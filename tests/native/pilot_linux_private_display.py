"""Exercise X11 authorization against one owned Xvfb; no graphical input."""
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


def verify_private_display():
    global phase
    need(platform.system() == "Linux" and platform.machine() == "x86_64" and os.getuid() == os.geteuid() != 0)
    need(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
         and os.environ.get("AKC_UBUNTU_PROVIDER_STAGE") == "private-display-v1")
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


if __name__ == "__main__":
    try:
        need(len(sys.argv) == 1)
        verify_private_display()
    except (OSError, ValueError, subprocess.SubprocessError):
        print("linux_private_display_denied phase=" + phase, file=sys.stderr)
        sys.exit(1)
    print("linux_private_xvfb_peer_and_authentication_verified_not_prompt")
