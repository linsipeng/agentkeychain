"""Hosted disposable Ubuntu prerequisite only; never access a collection or secret."""
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
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
</policy></busconfig>"""


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


phase = "environment"


def interrupted(_signum, _frame):
    raise RuntimeError("interrupted")


def verify_private_provider(provider_path, staged_provider, library_dir, staged_libraries):
    global phase
    need(sys.platform == "linux" and os.getuid() == os.geteuid() != 0)
    os.umask(0o077)
    signal.signal(signal.SIGALRM, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    signal.alarm(20)
    children = []
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
            conf.write_text(BUS_CONFIG.format(endpoint, os.getuid()), encoding="ascii")
            def start(argv, environment):
                child = subprocess.Popen(argv, env=environment, cwd=root, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                children.append(child)
                return child
            try:
                broker = start([BROKER, "--nofork", "--nopidfile", "--config-file=" + str(conf)], env)
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
                                  "LD_LIBRARY_PATH": str(library_dir)})
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
                maps = Path(f"/proc/{provider.pid}/maps").read_text(encoding="ascii")
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
                phase = "provider-owner-final"
                owned_image(broker, BROKER)
                need(call(conn, "GetNameOwner", SERVICE, "(s)") == owner)
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
                    need(not cleanup_failed)
    finally:
        signal.alarm(0)
