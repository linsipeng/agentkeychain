"""Exercise X11 authorization against one owned Xvfb; no graphical input."""
from contextlib import contextmanager
import os
from pathlib import Path
import platform
import secrets
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

AUTH = b"MIT-MAGIC-COOKIE-1"
XVFB = Path("/usr/bin/Xvfb")
phase = "display-environment"


def need(value):
    if not value:
        raise ValueError("private display denied")


def identity(row):
    return row.st_dev, row.st_ino


def padded(value):
    return value + bytes((-len(value)) % 4)


def authorization_record(display, cookie):
    # Xauthority on-disk record: FamilyLocal followed by length-prefixed fields.
    return struct.pack(">H", 256) + b"".join(
        struct.pack(">H", len(part)) + part
        for part in (os.uname().nodename.encode("ascii"), str(display).encode("ascii"), AUTH, cookie)
    )


def x11_setup(cookie):
    return struct.pack("<BBHHHHH", ord("l"), 0, 11, 0, len(AUTH), len(cookie), 0) + padded(AUTH) + padded(cookie)


def connect_own_display(process, executable, endpoint, endpoint_identity, cookie):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(2)
        need(process.poll() is None and identity(os.stat(f"/proc/{process.pid}/exe")) == executable)
        need(identity(endpoint.lstat()) == endpoint_identity)
        conn.connect(str(endpoint))
        pid, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need((pid, uid) == (process.pid, os.getuid()) and identity(endpoint.lstat()) == endpoint_identity)
        conn.sendall(x11_setup(cookie))
        with conn.makefile("rb", buffering=0) as wire:
            head = b""
            while len(head) < 8:
                fragment = wire.read(8 - len(head))
                need(fragment)
                head += fragment
        status, _, major, minor, _ = struct.unpack("<BBHHH", head)
        need((major, minor) == (11, 0))
        return status


@contextmanager
def owned_private_display(prompt=False):
    global phase
    need(platform.system() == "Linux" and platform.machine() == "x86_64" and os.getuid() == os.geteuid() != 0)
    need(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
         and os.environ.get("AKC_UBUNTU_PROVIDER_STAGE") in
         (("prompt-cancel-v1", "named-write-v1") if prompt else ("private-display-v1",)))
    os.umask(0o077)
    phase = "display-unix-capability"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM):
        pass
    phase = "display-image"
    for parent in reversed(XVFB.parents):
        row = parent.lstat()
        need(stat.S_ISDIR(row.st_mode) and row.st_uid == 0 and not row.st_mode & 0o022)
    image = XVFB.lstat()
    need(stat.S_ISREG(image.st_mode) and image.st_uid == 0 and not image.st_mode & 0o6022)
    with tempfile.TemporaryDirectory(prefix="akc-noble-display-", dir="/tmp") as directory:
        root = Path(directory)
        phase = "display-slot"
        number = 200 + secrets.randbelow(400)
        phase = "display-socket-directory"
        shared = Path("/tmp/.X11-unix")
        def shared_identity():
            for base in (Path("/tmp"), shared):
                row = base.lstat()
                need(stat.S_ISDIR(row.st_mode) and row.st_uid == 0 and bool(row.st_mode & stat.S_ISVTX))
            return identity(shared.lstat())
        expected_shared = shared_identity()
        endpoint = shared / ("X" + str(number))
        lock = Path("/tmp") / (".X" + str(number) + "-lock")
        need(not os.path.lexists(endpoint) and not os.path.lexists(lock))
        cookie = secrets.token_bytes(16)
        wrong = bytes([cookie[0] ^ 1]) + cookie[1:]
        authority = root / "Xauthority"
        with authority.open("xb") as file:
            file.write(authorization_record(number, cookie))
        need(stat.S_IMODE(authority.lstat().st_mode) == 0o600)
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(root), "XAUTHORITY": str(authority)}
        phase = "display-launch"
        child = subprocess.Popen([str(XVFB), ":" + str(number), "-auth", str(authority), "-nolisten", "tcp",
                                  "-noreset", "-screen", "0", "640x480x24"],
                                 env=env, cwd=root, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(60):
                if os.path.lexists(endpoint) or child.poll() is not None:
                    break
                time.sleep(0.05)
            need(shared_identity() == expected_shared)
            endpoint_row = endpoint.lstat()
            need(stat.S_ISSOCK(endpoint_row.st_mode) and endpoint_row.st_uid == os.getuid())
            peer = identity(endpoint_row)
            phase = "display-reject-wrong-cookie"
            need(connect_own_display(child, identity(image), endpoint, peer, wrong) == 0)
            phase = "display-authorized"
            need(connect_own_display(child, identity(image), endpoint, peer, cookie) == 1)
            phase = "display-reject-empty-cookie"
            need(connect_own_display(child, identity(image), endpoint, peer, b"") == 0)
            yield ({"DISPLAY": ":" + str(number), "XAUTHORITY": str(authority), "GDK_BACKEND": "x11",
                    "NO_AT_BRIDGE": "1", "GSETTINGS_BACKEND": "memory"},
                   (child, identity(image), endpoint, peer, cookie))
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
            need(shared_identity() == expected_shared)
            need(not os.path.lexists(endpoint) and not os.path.lexists(lock))


def verify_private_display():
    with owned_private_display():
        pass


def x11_input_event(frame):
    """Classify only fixed core wire event categories, never payload."""
    code = frame[0]
    if code & 0x80:
        return "send-event"
    if code == 34:
        # X11 core protocol sets request at offset four (octet immediately
        # after the sequence number), not the second byte.
        return {0: "mapping-modifier", 1: "mapping-keyboard", 2: "mapping-pointer"}.get(frame[4], "mapping-unknown")
    return {9: "focus-in", 10: "focus-out", 11: "keymap-notify", 28: "property-notify",
            35: "extension-event"}.get(code, "other-event")


def screen_windows(display, mark, input_scope=None):
    # Read only normal X11/XRes metadata over a strictly pinned socket, without
    # trusting client-controlled _NET_WM_PID or screenshot/title matches.
    child, executable, endpoint, endpoint_identity, cookie = display
    mark("unix-peer")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(2)
        need(child.poll() is None and identity(os.stat(f"/proc/{child.pid}/exe")) == executable)
        need(identity(endpoint.lstat()) == endpoint_identity)
        conn.connect(str(endpoint))
        pid, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need((pid, uid) == (child.pid, os.getuid()) and identity(endpoint.lstat()) == endpoint_identity)

        def read(amount):
            need(0 <= amount <= 65536)
            result = bytearray()
            while len(result) < amount:
                data = conn.recv(amount - len(result))
                need(data)
                result.extend(data)
            return result

        mark("x11-setup")
        conn.sendall(x11_setup(cookie))
        status, _, major, minor, length = struct.unpack("<BBHHH", read(8))
        need((status, major, minor) == (1, 11, 0))
        mark("x11-setup-frame")
        setup = read(length * 4)
        need(len(setup) >= 32)
        vendor, = struct.unpack_from("<H", setup, 16)
        need(setup[20] == 1)
        screen = 32 + ((vendor + 3) & ~3) + setup[21] * 8
        root, = struct.unpack_from("<I", setup, screen)
        sequence = 0

        def request(opcode, data=b"", minor=0):
            nonlocal sequence
            sequence += 1
            need(len(data) % 4 == 0)
            conn.sendall(struct.pack("<BBH", opcode, minor, 1 + len(data) // 4) + data)

        def reply(label, opcode, data=b"", minor=0):
            mark(label + "-rpc")
            request(opcode, data, minor)
            header = read(32)
            # MappingNotify is server-originated and unrequested (core X11).
            # It can interleave between a query and its reply. No other event
            # or send-event form is accepted, and the burst is bounded.
            if label.startswith("input-"):
                # Core server MappingNotify goes to every client. Keyboard
                # and modifier changes may drain only before the map snapshot;
                # pointer-only changes cannot invalidate the key map.
                before_map = (label.startswith("input-dialog-") or
                              label in ("input-xtest-extension", "input-focus-setup"))
                for _ in range(4):
                    if header[0] in (0, 1):
                        break
                    event = x11_input_event(header)
                    mark(label + "-event-" + event)
                    if event != "mapping-pointer":
                        need(before_map and event in ("mapping-modifier", "mapping-keyboard"))
                    header = read(32)
                if header[0] == 0:
                    # Core error code 3=BadWindow, 5=BadAtom, 8=BadMatch.
                    mark(label + "-error-" + {3: "window", 5: "atom", 8: "match"}.get(header[1], "other"))
                    need(False)
                if header[0] != 1:
                    mark(label + "-event-limit-" + x11_input_event(header))
                    need(False)
                mark(label + "-sequence")
                need(struct.unpack_from("<H", header, 2)[0] == sequence)
                mark(label + "-body-bound")
            else:
                mark(label + "-frame")
                need(header[0] == 1 and struct.unpack_from("<H", header, 2)[0] == sequence)
            return header, read(struct.unpack_from("<I", header, 4)[0] * 4)

        query = b"X-Resource"
        extension, _ = reply("xres-extension", 98, struct.pack("<H2x", len(query)) + padded(query))
        mark("xres-extension-unavailable")
        need(extension[8] == 1 and extension[9] >= 128)
        opcode = extension[9]
        tree, children = reply("x11-tree", 15, struct.pack("<I", root))
        count, = struct.unpack_from("<H", tree, 16)
        mark("x11-tree-shape")
        need(count <= 32 and len(children) == count * 4)
        result = []
        for (window,) in struct.iter_unpack("<I", children):
            attr_head, attributes = reply("x11-attributes", 3, struct.pack("<I", window))
            mark("x11-attributes-shape")
            need(len(attributes) == 12)
            if attr_head[26] != 2:  # IsViewable
                continue
            result.append(window)
        def local_pid_for_window(window):
            head, body = reply("xres-client-id", opcode, struct.pack("<III", 1, window, 2), minor=4)
            ids, = struct.unpack_from("<I", head, 8)
            mark("xres-client-id-shape")
            need(ids == 1 and len(body) == 16)
            resource, mask, length, local_pid = struct.unpack("<IIII", body)
            # Xorg returns the owning client's resource base, not the queried XID.
            mark("xres-local-pid")
            need(resource != 0 and mask == 2 and length == 4 and local_pid > 0)
            return local_pid

        resolved = {window: local_pid_for_window(window) for window in result}
        if input_scope is not None:
            need(os.environ.get("AKC_UBUNTU_PROVIDER_STAGE") == "named-write-v1")
            expected_pid, password = input_scope
            mark("input-pinned-window")
            need(len(resolved) == 1 and tuple(resolved.values()) == (expected_pid,))
            window = next(iter(resolved))
            authenticate_named_dialog(reply, mark, window, allow_pinned_empty=True)
            enter_fixture_password(reply, request, mark, setup, root, window, password,
                                   lambda focus: authenticate_gdk_focus_child(
                                       reply, mark, root, window, focus, expected_pid, local_pid_for_window))
        mark("mapped" if resolved else "no-viewable-top-level" if count else "no-top-level")
        return set(resolved.values())


def authenticate_named_dialog(reply, mark, window, *, allow_pinned_empty=False):
    # The window ID and owner were checked on this exact authenticated X11
    # connection. Resolve only the fixed EWMH title and its UTF-8 type with
    # InternAtom(only-if-exists); never create atoms or accept a caller name.
    def known_atom(label, name):
        header, body = reply("input-dialog-atom-" + label, 16, struct.pack("<H2x", len(name)) + padded(name), minor=1)
        mark("input-dialog-atom-" + label + "-shape")
        need(not body)
        return struct.unpack_from("<I", header, 8)[0]

    expected = b"New Keyring Password"

    def require_named_prompter_class():
        # GTK 3 window init: instance=g_get_prgname(), class=GDK program
        # fallback (same basename with first byte uppercased). GLib takes
        # the basename of argv[0]; the pinned fixture directly launches the
        # official basename with no --name/--class override. ICCCM's
        # XA_WM_CLASS=67 is two NUL-terminated 8-bit XA_STRING fields.
        expected_class = b"gcr-prompter\0Gcr-prompter\0"
        header, body = reply("input-dialog-wm-class", 20, struct.pack("<IIIII", window, 67, 31, 0, 16))
        typ, remaining, count = struct.unpack_from("<III", header, 8)
        mark("input-dialog-wm-class-encoding")
        need(typ == 31 and header[1] == 8)
        mark("input-dialog-wm-class-length")
        need(remaining == 0 and count == len(expected_class) and len(body) == ((count + 3) & ~3))
        mark("input-dialog-wm-class-value")
        need(body[:count] == expected_class)

    def title(kind, prop, expected_type):
        header, body = reply("input-dialog-title-" + kind, 20, struct.pack("<IIIII", window, prop, 0, 0, 16))
        typ, remaining, count = struct.unpack_from("<III", header, 8)
        if typ == 0:
            mark("input-dialog-title-" + kind + "-absent")
            need(header[1] == count == remaining == 0 and not body)
            return False
        mark("input-dialog-title-" + kind + "-encoding")
        need(typ == expected_type and header[1] == 8)
        mark("input-dialog-title-" + kind + "-wire-length")
        need(0 <= count <= 64 and remaining == 0 and len(body) == ((count + 3) & ~3))
        value = body[:count]
        if kind == "modern" and count == 0 and allow_pinned_empty:
            # This branch is reached only after the named-write workflow
            # observed an empty screen before its exact public Prompt call
            # and the verified Xvfb returned a singleton mapped GCR PID.
            require_named_prompter_class()
            return True
        if value != expected:
            # Static diagnostics only; neither GTK's fallback nor a source
            # string used for an on-screen label grants input authority.
            observed = {
                b"": "empty",
                b"gcr-prompter": "program-default",
                b"Choose password for new keyring": "provider-message",
            }.get(bytes(value), "other-same-length" if count == len(expected) else "other-length")
            mark("input-dialog-title-" + kind + "-" + observed)
            need(False)
        return True

    modern = known_atom("net-wm-name", b"_NET_WM_NAME")
    if modern:
        utf8 = known_atom("utf8", b"UTF8_STRING")
        mark("input-dialog-title-utf8-atom")
        need(utf8 != 0)
        if title("modern", modern, utf8):
            return
    # Legacy XA_WM_NAME=39, XA_STRING=31. Use only if the modern property is
    # absent, never after a contradictory title or malformed modern reply.
    need(title("legacy", 39, 31))


def authenticate_gdk_focus_child(reply, mark, root, window, focus, expected_pid, local_pid_for_window):
    # GTK 3.24 GDK-X11 setup_toplevel_window installs the special focus
    # target in _NET_WM_USER_TIME_WINDOW (type XA_WINDOW), and creates it as
    # a direct mapped 1x1 InputOnly child at (-1,-1). An X11 client property
    # alone is insufficient: prove ancestry and server-attested PID too.
    mark("input-focus-child-nonreserved")
    need(focus > 1 and focus not in (root, window))
    name = b"_NET_WM_USER_TIME_WINDOW"
    header, body = reply("input-focus-child-atom", 16, struct.pack("<H2x", len(name)) + padded(name), minor=1)
    atom, = struct.unpack_from("<I", header, 8)
    mark("input-focus-child-atom-shape")
    need(atom != 0 and not body)
    header, body = reply("input-focus-child-property", 20, struct.pack("<IIIII", window, atom, 33, 0, 1))
    mark("input-focus-child-property-shape")
    need(header[1] == 32 and struct.unpack_from("<III", header, 8) == (33, 0, 1) and len(body) == 4)
    mark("input-focus-child-property-id")
    need(struct.unpack("<I", body)[0] == focus)
    header, _ = reply("input-focus-child-tree", 15, struct.pack("<I", focus))
    mark("input-focus-child-ancestry")
    need(struct.unpack_from("<II", header, 8) == (root, window))
    header, body = reply("input-focus-child-attributes", 3, struct.pack("<I", focus))
    mark("input-focus-child-attributes-shape")
    need(len(body) == 12 and struct.unpack_from("<H", header, 12)[0] == 2 and header[26] == 2)
    header, body = reply("input-focus-child-geometry", 14, struct.pack("<I", focus))
    mark("input-focus-child-geometry-shape")
    need(not body and struct.unpack_from("<IhhHHH", header, 8) == (root, -1, -1, 1, 1, 0))
    owner = local_pid_for_window(focus)
    mark("input-focus-child-owner")
    need(owner == expected_pid)


def enter_fixture_password(reply, request, mark, setup, root, window, password, check_child):
    need(isinstance(password, bytearray) and len(password) == 40 and
         all(48 <= number <= 57 for number in password))
    query = b"XTEST"
    extension, _ = reply("input-xtest-extension", 98, struct.pack("<H2x", len(query)) + padded(query))
    need(extension[8] == 1 and extension[9] >= 128)
    def exact_focus(stage):
        header, body = reply("input-focus-" + stage, 43)
        mark("input-focus-" + stage + "-reply-shape")
        need(not body)
        focus, = struct.unpack_from("<I", header, 8)
        if focus != window:
            check_child(focus)

    # Fix focus before fetching the keyboard map so any initial server
    # MappingNotify from GTK/Xvfb startup cannot stale the snapshot we use.
    request(42, struct.pack("<II", window, 0))
    exact_focus("setup")

    first, last = setup[26:28]
    need(8 <= first < last and last - first <= 247)
    count = last - first + 1
    header, body = reply("input-keymap", 101, struct.pack("<BB2x", first, count))
    stride = header[1]
    need(0 < stride <= 16 and len(body) == count * stride * 4)
    symbols = (*range(48, 58), 0xff09, 0xff0d)
    keys = {}
    for symbol in symbols:
        candidates = [first + i for i in range(count)
                      if struct.unpack_from("<I", body, i * stride * 4)[0] == symbol]
        need(len(candidates) == 1)
        keys[symbol] = candidates[0]

    keymap, keymap_body = reply("input-no-held-keys", 44)
    # QueryKeymap reply is 40 bytes: eight framing bytes and 32 key bytes.
    mark("input-no-held-keys-reply-shape")
    need(len(keymap_body) == 8)
    mark("input-held-keys-present")
    need(not any(keymap[8:32] + keymap_body))
    for stage, group in (("before-password", password), ("after-password", (0xff09,)),
                         ("after-tab", password), ("after-confirmation", (0xff0d,))):
        exact_focus(stage)
        for symbol in group:
            for event in (2, 3):  # core KeyPress/KeyRelease; standard XTEST only.
                request(extension[9], struct.pack("<BB2xII20x", event, keys[symbol], 0, root), minor=2)
    mark("input-submitted")


if __name__ == "__main__":
    try:
        need(len(sys.argv) == 1)
        verify_private_display()
    except (OSError, ValueError, subprocess.SubprocessError):
        print("linux_private_display_denied phase=" + phase, file=sys.stderr)
        sys.exit(1)
    print("linux_private_xvfb_peer_and_authentication_verified_not_prompt")
