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
         and os.environ.get("AKC_UBUNTU_PROVIDER_STAGE") == ("prompt-cancel-v1" if prompt else "private-display-v1"))
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


def screen_windows(display):
    # Read only normal X11/XRes metadata over a strictly pinned socket, without
    # trusting client-controlled _NET_WM_PID or screenshot/title matches.
    child, executable, endpoint, endpoint_identity, cookie = display
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

        conn.sendall(x11_setup(cookie))
        status, _, major, minor, length = struct.unpack("<BBHHH", read(8))
        need((status, major, minor) == (1, 11, 0))
        setup = read(length * 4)
        vendor, = struct.unpack_from("<H", setup, 16)
        need(setup[20] == 1)
        screen = 32 + ((vendor + 3) & ~3) + setup[21] * 8
        root, = struct.unpack_from("<I", setup, screen)
        sequence = 0

        def reply(opcode, data=b"", minor=0):
            nonlocal sequence
            sequence += 1
            need(len(data) % 4 == 0)
            conn.sendall(struct.pack("<BBH", opcode, minor, 1 + len(data) // 4) + data)
            header = read(32)
            need(header[0] == 1 and struct.unpack_from("<H", header, 2)[0] == sequence)
            return header, read(struct.unpack_from("<I", header, 4)[0] * 4)

        query = b"X-Resource"
        extension, _ = reply(98, struct.pack("<H2x", len(query)) + padded(query))
        need(extension[8] == 1 and extension[9] >= 128)
        opcode = extension[9]
        tree, children = reply(15, struct.pack("<I", root))
        count, = struct.unpack_from("<H", tree, 16)
        need(count <= 32 and len(children) == count * 4)
        result = []
        for (window,) in struct.iter_unpack("<I", children):
            attr_head, attributes = reply(3, struct.pack("<I", window))
            need(len(attributes) == 12)
            if attr_head[26] != 2:  # IsViewable
                continue
            result.append(window)
        resolved = set()
        for window in result:
            head, body = reply(opcode, struct.pack("<III", 1, window, 2), minor=4)
            ids, = struct.unpack_from("<I", head, 8)
            need(ids == 1 and len(body) == 16)
            resource, mask, length, local_pid = struct.unpack("<IIII", body)
            # Xorg ConstructClientIdValue reports the client's resource base,
            # not the queried window XID. The checked X server resolves the
            # exact request to a single local PID; reject missing/extra IDs.
            need(resource != 0 and mask == 2 and length == 4 and local_pid > 0)
            resolved.add(local_pid)
        return resolved


if __name__ == "__main__":
    try:
        need(len(sys.argv) == 1)
        verify_private_display()
    except (OSError, ValueError, subprocess.SubprocessError):
        print("linux_private_display_denied phase=" + phase, file=sys.stderr)
        sys.exit(1)
    print("linux_private_xvfb_peer_and_authentication_verified_not_prompt")
