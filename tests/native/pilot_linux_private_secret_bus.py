"""Hosted disposable Ubuntu prerequisite only; never access a collection or secret."""
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

from gi.repository import Gio, GLib

BROKER = "/usr/bin/dbus-daemon"
DBUS = "org.freedesktop.DBus"
SERVICE = "org.freedesktop.secrets"
BASE_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
# No includes, service discovery, systemd activation, or inherited policy.
BUS_CONFIG = """<busconfig>
<type>session</type><listen>unix:path={}</listen><auth>EXTERNAL</auth>
<policy context="default">
<allow user="{}"/><allow own="org.freedesktop.secrets"/>
<allow send_destination="org.freedesktop.DBus"/>
<allow receive_sender="org.freedesktop.DBus"/>
{}
</policy></busconfig>"""

# Both sides of delivery need policy. send_destination matches the owner of
# the well-known name even though the client addresses its checked unique name.
# The admission rule still blocks all other client->provider method calls.
# Reply sends are limited by the broker's pending-call record, which only
# the addressed recipient can complete; receive rules pin that provider.
SESSION_POLICY = """
<allow send_destination="org.freedesktop.secrets" send_interface="org.freedesktop.Secret.Service"
       send_member="OpenSession" send_path="/org/freedesktop/secrets" send_type="method_call" max_fds="0"/>
<allow receive_interface="org.freedesktop.Secret.Service" receive_member="OpenSession"
       receive_path="/org/freedesktop/secrets" receive_type="method_call" max_fds="0"/>
<allow send_type="method_return" send_requested_reply="true" max_fds="0"/>
<allow send_type="error" send_requested_reply="true" max_fds="0"/>
<allow receive_sender="org.freedesktop.secrets" receive_type="method_return"
       receive_requested_reply="true" max_fds="0"/>
<allow receive_sender="org.freedesktop.secrets" receive_type="error"
       receive_requested_reply="true" max_fds="0"/>
"""

# Separate unattended offer-only fixture. Deliberately does not allow Prompt,
# Dismiss, prompter activation, alias access, or any collection/item operations.
COLLECTION_OFFER_POLICY = """
<allow send_destination="org.freedesktop.secrets" send_interface="org.freedesktop.Secret.Service"
       send_member="CreateCollection" send_path="/org/freedesktop/secrets" send_type="method_call" max_fds="0"/>
<allow receive_interface="org.freedesktop.Secret.Service" receive_member="CreateCollection"
       receive_path="/org/freedesktop/secrets" receive_type="method_call" max_fds="0"/>
"""
PROMPTER = "org.gnome.keyring.SystemPrompter"
FIXTURE_CLIENT = "org.agentkeychain.PromptFixture"
FIRST_PROMPT = "/org/freedesktop/secrets/prompt/p1"
PROMPT_IFACE = "org.freedesktop.Secret.Prompt"


# dbus-daemon omits message paths from rejection diagnostics but reports
# the number of matched rules. Add DENY-only diagnostic rules *before* the
# existing allow rules. Last-match semantics keep every decision unchanged.
# Encode only exact p0/p1, expected destination and zero FD matches.
def prompt_ready_deny_markers():
    base = ('send_interface="org.gnome.keyring.internal.Prompter.Callback" '
            'send_member="PromptReady" send_type="method_call"')
    known = (("", 1), ('send_path="/org/gnome/keyring/Prompt/p0"', 1),
             ('send_path="/org/gnome/keyring/Prompt/p1"', 2),
             (f'send_destination="{SERVICE}"', 4), ('max_fds="0"', 8))
    return [f"<deny {base} {attributes}/>" for attributes, count in known for _ in range(count)]


def prompt_ready_denial_shape(raw):
    if b' type="method_call"' not in raw:
        return "other-type"
    if b' interface="org.gnome.keyring.internal.Prompter.Callback"' not in raw:
        return "other-interface"
    shape = re.search(rb"Rejected send message, ([0-9]{1,2}) matched rules;", raw)
    if shape is None:
        return "unclassified"
    score = int(shape[1]) - 1
    if not 0 <= score <= 14 or score & 3 == 3:
        return "unclassified"
    path = {0: "other-path", 1: "callback-p0", 2: "callback-p1"}[score & 3]
    role = "expected-destination" if score & 4 else "other-destination"
    fds = "zero-fds" if score & 8 else "has-fds"
    return "-".join((path, role, fds, "expected-interface"))


def prompt_cancel_policy():
    rules = prompt_ready_deny_markers() + [f'<allow own="{PROMPTER}"/>', f'<allow own="{FIXTURE_CLIENT}"/>']
    routes = (
        (FIXTURE_CLIENT, SERVICE, FIRST_PROMPT, PROMPT_IFACE, ("Prompt", "Dismiss")),
        (SERVICE, PROMPTER, "/org/gnome/keyring/Prompter", "org.gnome.keyring.internal.Prompter",
         ("BeginPrompting", "PerformPrompt", "StopPrompting")),
        (PROMPTER, SERVICE, "/org/gnome/keyring/Prompt/p0", "org.gnome.keyring.internal.Prompter.Callback",
         ("PromptReady", "PromptDone")),
    )
    for sender, destination, path, interface, members in routes:
        for method in members:
            rules += [
                f'<allow send_destination="{destination}" send_path="{path}" send_interface="{interface}" '
                f'send_member="{method}" send_type="method_call" max_fds="0"/>',
                f'<allow receive_sender="{sender}" receive_path="{path}" receive_interface="{interface}" '
                f'receive_member="{method}" receive_type="method_call" max_fds="0"/>',
            ]
    rules += [
        f'<allow send_destination="{FIXTURE_CLIENT}" send_path="{FIRST_PROMPT}" send_interface="{PROMPT_IFACE}" '
        'send_member="Completed" send_type="signal" send_broadcast="false" max_fds="0"/>',
        f'<allow receive_sender="{SERVICE}" receive_path="{FIRST_PROMPT}" receive_interface="{PROMPT_IFACE}" '
        'receive_member="Completed" receive_type="signal" max_fds="0"/>',
    ]
    # The existing requested-reply send rules apply; do not add any general
    # methods. Only the official prompter and the exact fixture requester may
    # receive the requested returns/errors needed for this one choreography.
    for sender in (PROMPTER, FIXTURE_CLIENT):
        for kind in ("method_return", "error"):
            rules.append(f'<allow receive_sender="{sender}" receive_type="{kind}" '
                         'receive_requested_reply="true" max_fds="0"/>')
    return "\n".join(rules)


def prompter_timeout_class(conn, process):
    """Classify only the disposable broker's small authenticated connection set."""
    try:
        reply = conn.call_sync(DBUS, "/org/freedesktop/DBus", DBUS, "ListNames", GLib.Variant("()", ()),
                               GLib.VariantType.new("(as)"), Gio.DBusCallFlags.NO_AUTO_START, 1000, None)
        names = reply.unpack()[0]
        if len(names) > 12:
            return "prompter-owner-timeout-bus-inventory-unexpected"
        for name in names:
            if not re.fullmatch(r":[0-9]+\.[0-9]+", name):
                continue
            credentials = call(conn, "GetConnectionCredentials", name, "(a{sv})")
            if credentials.get("UnixUserID") == os.getuid() and credentials.get("ProcessID") == process.pid:
                return "prompter-owner-timeout-connected-to-private-bus"
    except GLib.Error:
        return "prompter-owner-timeout-bus-inventory-unavailable"
    return "prompter-owner-timeout-not-connected-to-private-bus"


def wait_owner(conn, name, process, image, snapshot):
    global phase
    # GCR initializes GTK before requesting its bus name. Allow bounded
    # startup jitter but never start another prompter or accept a late owner.
    expires = time.monotonic() + 6
    while time.monotonic() < expires:
        phase = "prompter-process"
        exit_code = process.poll()
        if exit_code is not None:
            phase = {
                0: "prompter-exited-normally",
                1: "prompter-exited-status-one",
                127: "prompter-exited-status-127",
            }.get(exit_code, "prompter-exited-signal" if exit_code < 0 else "prompter-exited-other")
            raise RuntimeError("fixture prompter no longer running")
        phase = "prompter-process-image"
        owned_image(process, image, snapshot)
        phase = "prompter-owner-rpc"
        try:
            owner = call(conn, "GetNameOwner", name, "(s)")
        except GLib.Error as error:
            if Gio.DBusError.get_remote_error(error) != DBUS + ".Error.NameHasNoOwner":
                phase = "prompter-owner-rpc-" + session_rpc_failure(error)
                raise
        else:
            phase = "prompter-owner-shape"
            need(isinstance(owner, str) and re.fullmatch(r":[0-9]+\.[0-9]+", owner))
            phase = "prompter-credentials-rpc"
            try:
                credentials = call(conn, "GetConnectionCredentials", owner, "(a{sv})")
            except GLib.Error as error:
                phase = "prompter-credentials-rpc-" + session_rpc_failure(error)
                raise
            phase = "prompter-credentials-uid"
            need(credentials.get("UnixUserID") == os.getuid())
            phase = "prompter-credentials-pid"
            need(credentials.get("ProcessID") == process.pid)
            phase = "prompter-process-image-recheck"
            owned_image(process, image, snapshot)
            if time.monotonic() >= expires:
                phase = "prompter-owner-timeout-late"
                raise RuntimeError("fixture role owner arrived after deadline")
            return owner
        phase = "prompter-owner-pending"
        time.sleep(0.05)
    phase = "prompter-owner-timeout"
    owned_image(process, image, snapshot)
    phase = prompter_timeout_class(conn, process)
    raise RuntimeError("fixture role owner unavailable")


def show_then_cancel(bus, owner, offer, prompter_pid, windows, liveness):
    global phase
    need(offer == FIRST_PROMPT)
    def observed(step):
        def mark(stage):
            global phase
            phase = "prompt-" + step + "-" + stage
        return windows(mark)

    need(not observed("clean-screen"))
    context = GLib.MainContext.default()
    completed = []

    def completion(_bus, sender, path, interface, signal_name, parameters, _data):
        if (sender, path, interface, signal_name) == (owner, offer, PROMPT_IFACE, "Completed"):
            completed.append(parameters)

    subscription = bus.signal_subscribe(owner, PROMPT_IFACE, "Completed", offer, None,
                                        Gio.DBusSignalFlags.NONE, completion, None)
    try:
        phase = "public-prompt-rpc"
        bus.call_sync(owner, offer, PROMPT_IFACE, "Prompt", GLib.Variant("(s)", ("",)),
                      GLib.VariantType.new("()"), Gio.DBusCallFlags.NO_AUTO_START, 2000, None)
        for attempt in range(60):
            context.iteration(False)
            if completed:
                phase = "prompt-completed-before-visible"
                need(len(completed) == 1 and completed[0].get_type_string() == "(bv)")
                phase += "-dismissed" if completed[0].get_child_value(0).get_boolean() else "-accepted"
                raise RuntimeError("fixture completed before visible")
            liveness(attempt)
            visible = observed("visible")
            if visible:
                phase = "prompt-visible-foreign-pid"
                need(visible == {prompter_pid})
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("authenticated dialog not observed")
        phase = "public-dismiss-rpc"
        bus.call_sync(owner, offer, PROMPT_IFACE, "Dismiss", GLib.Variant("()", ()),
                      GLib.VariantType.new("()"), Gio.DBusCallFlags.NO_AUTO_START, 2000, None)
        phase = "prompt-cancel-result"
        for _ in range(60):
            context.iteration(False)
            if completed:
                break
            time.sleep(0.05)
        need(len(completed) == 1 and completed[0].get_type_string() == "(bv)")
        variant = completed[0].get_child_value(1).get_variant()
        need(completed[0].get_child_value(0).get_boolean() and
             variant.get_type_string() == "o" and variant.get_string() == "/")
        phase = "prompt-closed-screen"
        for _ in range(60):
            if not observed("closed-screen"):
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("fixture window still visible")
    finally:
        bus.signal_unsubscribe(subscription)

COLLECTION_LABEL = "AgentKeychain disposable offer only"


def validate_collection_offer(reply):
    need(reply is not None and reply.get_type_string() == "(oo)")
    collection, prompt = reply.unpack()
    need(collection == "/")
    # GNOME 46.1 gkd_secret_prompt_constructed uses SECRET_PROMPT_PREFIX "/p%d".
    need(re.fullmatch(r"/org/freedesktop/secrets/prompt/p[1-9][0-9]{0,9}", prompt))
    return prompt


def verify_collection_offer(bus, unique_owner):
    global phase
    phase = "collection-offer-rpc"
    properties = {"org.freedesktop.Secret.Collection.Label": GLib.Variant("s", COLLECTION_LABEL)}
    try:
        reply = bus.call_sync(unique_owner, "/org/freedesktop/secrets", "org.freedesktop.Secret.Service",
                             "CreateCollection", GLib.Variant("(a{sv}s)", (properties, "")), None,
                             Gio.DBusCallFlags.NO_AUTO_START, 2000, None)
    except GLib.Error as error:
        phase = "collection-offer-rpc-" + session_rpc_failure(error)
        raise
    phase = "collection-offer-shape"
    return validate_collection_offer(reply)


def require_no_fixture_keyring_files(data_home):
    keyrings = Path(data_home) / "keyrings"
    try:
        row = keyrings.lstat()
    except FileNotFoundError:
        return
    need(stat.S_ISDIR(row.st_mode) and row.st_uid == os.getuid())
    need(next(keyrings.iterdir(), None) is None)

ALGORITHM = "dh-ietf1024-sha256-aes128-cbc-pkcs7"
# RFC 2409 Section 6.2, 1024-bit MODP group. Protocol compatibility test only;
# not a general encryption recommendation.
MODP = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42"
    "E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B"
    "1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16
)
SUBGROUP = (MODP - 1) // 2


def validate_session_reply(reply):
    global phase
    phase = "encrypted-session-reply-signature"
    need(reply is not None and reply.get_type_string() == "(vo)")
    result = reply.get_child_value(0).get_variant()
    phase = "encrypted-session-peer-type"
    need(result.get_type_string() == "ay")
    phase = "encrypted-session-peer-length"
    size = result.n_children()
    need(0 < size <= 128)
    peer = int.from_bytes(bytes(result.unpack()), "big")
    phase = "encrypted-session-peer-range"
    need(2 <= peer <= MODP - 2)
    phase = "encrypted-session-peer-subgroup"
    need(pow(peer, SUBGROUP, MODP) == 1)
    phase = "encrypted-session-object"
    path = reply.get_child_value(1).get_string()
    # GNOME 46.1 gkd_secret_session_constructor: SECRET_SESSION_PREFIX "/s%d".
    need(re.fullmatch(r"/org/freedesktop/secrets/session/s[1-9][0-9]{0,9}", path))
    return peer


def session_rpc_failure(error):
    remote = Gio.DBusError.get_remote_error(error)
    known = {
        DBUS + ".Error.AccessDenied": "access-denied",
        DBUS + ".Error.AuthFailed": "auth-failed",
        DBUS + ".Error.NoReply": "no-reply",
        DBUS + ".Error.Timeout": "no-reply",
        DBUS + ".Error.NameHasNoOwner": "owner-lost",
        DBUS + ".Error.ServiceUnknown": "owner-lost",
        DBUS + ".Error.Disconnected": "disconnected",
        DBUS + ".Error.NotSupported": "unsupported",
        DBUS + ".Error.InvalidArgs": "invalid-input",
        DBUS + ".Error.UnknownMethod": "unknown-method",
        DBUS + ".Error.Failed": "provider-failed",
    }
    if remote == DBUS + ".Error.AccessDenied":
        # dbus-daemon prefixes its English diagnostic with these fixed labels
        # under LC_ALL=C. Never expose any other content from the remote body.
        if error.message.startswith("GDBus.Error:" + remote + ": Rejected send message"):
            return "access-denied-send"
        if error.message.startswith("GDBus.Error:" + remote + ": Rejected receive message"):
            return "access-denied-receive"
    if remote:
        return known.get(remote, "other-remote-error")
    if error.matches(Gio.io_error_quark(), Gio.IOErrorEnum.TIMED_OUT):
        return "no-reply"
    if error.matches(Gio.io_error_quark(), Gio.IOErrorEnum.CLOSED):
        return "disconnected"
    return "other-local-error"


def verify_encrypted_negotiation(bus, unique_owner):
    global phase
    phase = "encrypted-session-input"
    private = 2 + secrets.randbelow(SUBGROUP - 2)
    public = pow(2, private, MODP)
    wire = public.to_bytes((public.bit_length() + 7) // 8, "big")
    parameters = GLib.Variant("(sv)", (ALGORITHM, GLib.Variant("ay", wire)))
    phase = "encrypted-session-rpc"
    try:
        # Check the exact reply signature ourselves to separate wrong shape from transport denial.
        reply = bus.call_sync(unique_owner, "/org/freedesktop/secrets", "org.freedesktop.Secret.Service",
                             "OpenSession", parameters, None, Gio.DBusCallFlags.NO_AUTO_START, 2000, None)
    except GLib.Error as error:
        phase = "encrypted-session-rpc-" + session_rpc_failure(error)
        raise
    peer = validate_session_reply(reply)
    phase = "encrypted-session-derived-range"
    need(2 <= pow(peer, private, MODP) <= MODP - 2)
    # Only negotiation is tested. No key is serialized, no secret is
    # transferred, and disconnect cleans up this connection-bound session.


def need(condition):
    if not condition:
        raise RuntimeError("denied")


def owned_image(process, path, staged=None):
    need(process.poll() is None)
    current = os.stat(f"/proc/{process.pid}/exe")
    expected = os.stat(path, follow_symlinks=False)
    need(stat.S_ISREG(expected.st_mode))
    if staged is None:
        need(expected.st_uid == 0 and not expected.st_mode & 0o022)
    else:
        need(expected.st_uid == os.getuid() and stat.S_IMODE(expected.st_mode) == 0o500)
        need((expected.st_dev, expected.st_ino) == (staged.st_dev, staged.st_ino))
    need((current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino))


def verify_mapped_libraries(process, staged_libraries):
    maps = Path(f"/proc/{process.pid}/maps").read_text(encoding="ascii")
    for path, expected in staged_libraries.items():
        current = path.lstat()
        need(stat.S_ISREG(current.st_mode) and current.st_uid == os.getuid() and
             stat.S_IMODE(current.st_mode) == 0o400 and
             (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino))
        identity = (os.major(expected.st_dev), os.minor(expected.st_dev), expected.st_ino)
        rows = [line.split(maxsplit=5) for line in maps.splitlines()]
        need(any(len(row) == 6 and row[5] == str(path) and
                 (*[int(v, 16) for v in row[3].split(":")], int(row[4])) == identity
                 for row in rows))


def call(bus, method, name, reply):
    return bus.call_sync(DBUS, "/org/freedesktop/DBus", DBUS, method,
                         GLib.Variant("(s)", (name,)), GLib.VariantType.new(reply),
                         Gio.DBusCallFlags.NO_AUTO_START, 2000, None).unpack()[0]


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)


# Capture only these fixed private child roles in the prompt test. Never enable
# GLib debug (GCR could log exchange payload), expose original stderr, or write
# diagnostics to disk. Classification is bounded and content-free.
PROMPT_METHODS = {
    b"BeginPrompting": "begin", b"PerformPrompt": "perform", b"StopPrompting": "stop",
    b"PromptReady": "ready", b"PromptDone": "done", b"Prompt": "public-prompt",
    b"Dismiss": "dismiss", b"Completed": "completed", b"Ping": "expected-ping",
    b"RequestName": "name-request",
}


def prompt_child_label(role, raw):
    line = raw.lower()
    if role == "bus":
        direction = next((label for prefix, label in ((b"Rejected send message", "send"),
                            (b"Rejected receive message", "receive")) if prefix in raw), None)
        if direction is not None:
            member = re.search(rb' member="([A-Za-z]{1,32})"', raw)
            method = PROMPT_METHODS.get(member[1], "other") if member else "other"
            if direction == "send" and method == "ready":
                method += "-" + prompt_ready_denial_shape(raw)
            return "bus-rejected-" + direction + "-" + method
        return "bus-stderr-other"
    if b"cannot open display" in line or b"failed to open display" in line:
        return role + "-gtk-display-unavailable"
    if b"couldn't initialize prompt" in line or b"could not initialize prompt" in line:
        if b"accessdenied" in line or b"access denied" in line:
            return role + "-prompt-init-access-denied"
        if b"unknownmethod" in line or b"unknown method" in line:
            return role + "-prompt-init-unknown-method"
        return role + "-prompt-init-failed"
    if b"couldn't connect to session bus" in line:
        return role + "-session-bus-unavailable"
    if b"error while loading shared libraries" in line:
        return role + "-missing-library"
    if b"gtk-critical" in line or b"gtk-warning" in line or b"gdk-critical" in line:
        return role + "-gtk-warning"
    return role + "-stderr-other"


class PromptChildDiagnostics:
    def __init__(self, role, stream):
        self.role = role
        self.stream = stream
        self.labels = set()
        self.reader = threading.Thread(target=self._drain, daemon=True)
        self.reader.start()

    def _drain(self):
        limit = 2048
        try:
            with self.stream:
                while True:
                    raw = self.stream.readline(limit + 1)
                    if not raw:
                        break
                    if len(raw) > limit:
                        self.labels.add(self.role + "-stderr-line-omitted")
                        while raw and not raw.endswith(b"\n"):
                            raw = self.stream.readline(limit + 1)
                    elif raw.strip():
                        self.labels.add(prompt_child_label(self.role, raw))
        except OSError:
            self.labels.add(self.role + "-stderr-pipe-error")

    def summary_after_exit(self):
        self.reader.join(0.25)
        if self.reader.is_alive():
            return (self.role + "-stderr-incomplete",)
        return tuple(sorted(self.labels)) or (self.role + "-stderr-empty",)


phase = "environment"


def interrupted(_signum, _frame):
    raise RuntimeError("interrupted")


def verify_private_provider(provider_path, staged_provider, library_dir, staged_libraries, encrypted=False,
                            collection_offer=False, prompt=None):
    global phase
    need(sys.platform == "linux" and os.getuid() == os.geteuid() != 0)
    os.umask(0o077)
    signal.signal(signal.SIGALRM, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    signal.alarm(20)
    children = []
    diagnostics = []
    conn = None
    try:
        phase = "unix-capability"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        with sock, tempfile.TemporaryDirectory(prefix="akc-linux-bus-", dir="/tmp") as scratch:
            root = Path(scratch)
            row = root.lstat()
            need(stat.S_ISDIR(row.st_mode) and row.st_uid == os.getuid() and stat.S_IMODE(row.st_mode) == 0o700)
            env = dict(BASE_ENV)
            for key in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"):
                directory = root / key.lower()
                directory.mkdir(mode=0o700)
                env[key] = str(directory)
            env["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=" + str(root / "no-system-bus")
            control = root / "control"
            control.mkdir(mode=0o700)
            endpoint = root / "broker"
            phase = "broker"
            conf = root / "bus.xml"
            need(not collection_offer or encrypted)
            policy = SESSION_POLICY if encrypted else ""
            if collection_offer:
                policy += COLLECTION_OFFER_POLICY
            if prompt:
                need(collection_offer)
                policy += prompt_cancel_policy()
            conf.write_text(BUS_CONFIG.format(endpoint, os.getuid(), policy), encoding="ascii")
            def start(argv, environment, role):
                child = subprocess.Popen(argv, env=environment, cwd=root, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE if prompt else subprocess.DEVNULL)
                children.append(child)
                if prompt:
                    diagnostics.append(PromptChildDiagnostics(role, child.stderr))
                return child
            prompt_failed = False
            try:
                broker = start([BROKER, "--nofork", "--nopidfile", "--nosyslog", "--config-file=" + str(conf)], env, "bus")
                for _ in range(60):
                    if endpoint.exists() or broker.poll() is not None:
                        break
                    time.sleep(0.05)
                pinned = endpoint.lstat()
                need(stat.S_ISSOCK(pinned.st_mode) and pinned.st_uid == os.getuid())
                owned_image(broker, BROKER)
                sock.connect(str(endpoint))
                pid, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                need((pid, uid) == (broker.pid, os.getuid()))
                latest = endpoint.lstat()
                need((pinned.st_dev, pinned.st_ino) == (latest.st_dev, latest.st_ino))
                # Transfer the exact tested socket; do not open a new or ambient connection.
                fd = sock.detach()
                try:
                    gsocket = Gio.Socket.new_from_fd(fd)
                except GLib.Error:
                    os.close(fd)
                    raise
                observer = Gio.DBusAuthObserver.new()
                observer.connect("allow-mechanism", lambda _observer, name: name == "EXTERNAL")
                conn = Gio.DBusConnection.new_sync(gsocket.connection_factory_create_connection(), None,
                    Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
                    observer, None)
                conn.set_exit_on_close(False)
                phase = "provider-owner"
                provider = start([str(provider_path), "--foreground", "--components=secrets", "--control-directory=" + str(control)],
                                 {**env, "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + str(endpoint),
                                  "LD_LIBRARY_PATH": str(library_dir)}, "provider")
                owner = None
                for _ in range(80):
                    owned_image(provider, provider_path, staged_provider)
                    try:
                        owner = call(conn, "GetNameOwner", SERVICE, "(s)")
                    except GLib.Error as error:
                        if Gio.DBusError.get_remote_error(error) != DBUS + ".Error.NameHasNoOwner":
                            raise
                    else:
                        break
                    time.sleep(0.05)
                need(isinstance(owner, str) and re.fullmatch(r":[0-9]+\.[0-9]+", owner))
                credentials = call(conn, "GetConnectionCredentials", owner, "(a{sv})")
                need(credentials.get("UnixUserID") == os.getuid() and credentials.get("ProcessID") == provider.pid)
                owned_image(provider, provider_path, staged_provider)
                phase = "provider-library-identity"
                verify_mapped_libraries(provider, {path: row for path, row in staged_libraries.items()
                                                   if path.name != "libgcr-ui-3.so.1"})
                phase = "provider-owner-final"
                owned_image(broker, BROKER)
                need(call(conn, "GetNameOwner", SERVICE, "(s)") == owner)
                if encrypted:
                    phase = "encrypted-session"
                    verify_encrypted_negotiation(conn, owner)
                    phase = "encrypted-session-capability-denial"
                    try:
                        conn.call_sync(owner, "/org/freedesktop/secrets", "org.freedesktop.DBus.Peer",
                                       "Ping", GLib.Variant("()", ()), GLib.VariantType.new("()"),
                                       Gio.DBusCallFlags.NO_AUTO_START, 2000, None)
                    except GLib.Error as error:
                        need(Gio.DBusError.get_remote_error(error) == DBUS + ".Error.AccessDenied")
                    else:
                        raise RuntimeError("unexpected provider capability")
                    phase = "encrypted-session-owner"
                    owned_image(provider, provider_path, staged_provider)
                    owned_image(broker, BROKER)
                    need(call(conn, "GetNameOwner", SERVICE, "(s)") == owner)
                    credentials = call(conn, "GetConnectionCredentials", owner, "(a{sv})")
                    need(credentials.get("UnixUserID") == os.getuid() and credentials.get("ProcessID") == provider.pid)
                if collection_offer:
                    phase = "collection-offer-fresh-data"
                    require_no_fixture_keyring_files(env["XDG_DATA_HOME"])
                    need(call(conn, "GetNameOwner", SERVICE, "(s)") == owner)
                    if prompt:
                        phase = "prompt-requester-role"
                        result = conn.call_sync(DBUS, "/org/freedesktop/DBus", DBUS, "RequestName",
                                               GLib.Variant("(su)", (FIXTURE_CLIENT, 4)), GLib.VariantType.new("(u)"),
                                               Gio.DBusCallFlags.NO_AUTO_START, 2000, None)
                        need(result.unpack() == (1,) and call(conn, "GetNameOwner", FIXTURE_CLIENT, "(s)") == conn.get_unique_name())
                        phase = "prompter-start"
                        image, snapshot, display_env, windows = prompt
                        prompter = start([str(image)], {**env, **display_env, "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + str(endpoint),
                                                         "LD_LIBRARY_PATH": str(library_dir)}, "gcr")
                        prompt_owner = wait_owner(conn, PROMPTER, prompter, image, snapshot)
                        phase = "prompter-role-collision"
                        need(prompt_owner not in (owner, conn.get_unique_name()))
                        phase = "prompter-library-identity"
                        verify_mapped_libraries(prompter, staged_libraries)
                    offer = verify_collection_offer(conn, owner)
                    if prompt:
                        def prompt_liveness(attempt):
                            global phase
                            phase = "prompt-provider-process"
                            owned_image(provider, provider_path, staged_provider)
                            phase = "prompt-gcr-process"
                            owned_image(prompter, image, snapshot)
                            if attempt in (0, 59):
                                phase = "prompt-provider-owner-live"
                                need(call(conn, "GetNameOwner", SERVICE, "(s)") == owner)
                                phase = "prompt-gcr-owner-live"
                                need(call(conn, "GetNameOwner", PROMPTER, "(s)") == prompt_owner)

                        show_then_cancel(conn, owner, offer, prompter.pid, windows, prompt_liveness)
                        owner_after = wait_owner(conn, PROMPTER, prompter, image, snapshot)
                        phase = "prompter-owner-changed"
                        need(owner_after == prompt_owner)
                    phase = "collection-offer-owner"
                    owned_image(provider, provider_path, staged_provider)
                    owned_image(broker, BROKER)
                    need(call(conn, "GetNameOwner", SERVICE, "(s)") == owner)
                    credentials = call(conn, "GetConnectionCredentials", owner, "(a{sv})")
                    need(credentials.get("UnixUserID") == os.getuid() and credentials.get("ProcessID") == provider.pid)
                    phase = "collection-offer-no-fixture-files"
                    require_no_fixture_keyring_files(env["XDG_DATA_HOME"])
            except Exception:
                # Cleanup below stops only our children; classify buffered output
                # afterwards. Preserve the original phase and raise again.
                prompt_failed = True
                raise
            finally:
                signal.alarm(0)
                try:
                    if conn is not None and not conn.is_closed():
                        conn.close_sync(None)
                finally:
                    cleanup_failed = False
                    for child in reversed(children):
                        try:
                            stop(child)
                        except (OSError, subprocess.SubprocessError):
                            cleanup_failed = True
                    if prompt and (prompt_failed or cleanup_failed):
                        for record in diagnostics:
                            for label in record.summary_after_exit():
                                print("linux_private_prompt_child=" + label, file=sys.stderr)
                    need(not cleanup_failed)
    finally:
        signal.alarm(0)
