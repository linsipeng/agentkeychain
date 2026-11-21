"""Fixture-only crypto and independently held named store checks. No reads via Secret Service."""
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat

LABEL = "AKCPilotPrimary"
COLLECTION = "/org/freedesktop/secrets/collection/" + LABEL
LEAF = LABEL + ".keyring"
GNOME_BINARY = b"GnomeKeyring\n\r\0\n"


def require(ok):
    if not ok:
        raise ValueError("named write denied")


def encrypted_fixture_secret(shared, marker):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    require(isinstance(shared, int) and 2 <= shared < (1 << 1024) and len(marker) == 32)
    # GNOME 46.1 CKM_DH_PKCS_DERIVE defaults to the full prime length
    # and zero-pads the leading edge (gkm-dh-mechanism.c). Its HKDF uses
    # SHA-256 with NULL salt and empty info (gkd-secret-session.c).
    prk = hmac.digest(bytes(32), shared.to_bytes(128, "big"), "sha256")
    key = hmac.digest(prk, b"\x01", "sha256")[:16]
    iv = secrets.token_bytes(16)
    padding = PKCS7(128).padder()
    padded = padding.update(marker) + padding.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv, cipher.update(padded) + cipher.finalize()


def verify_encrypted_fixture_secret(shared, iv, ciphertext, marker):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    require(isinstance(shared, int) and 2 <= shared < (1 << 1024) and
            len(marker) == 32 and len(iv) == 16 and len(ciphertext) == 48)
    prk = hmac.digest(bytes(32), shared.to_bytes(128, "big"), "sha256")
    key = hmac.digest(prk, b"\x01", "sha256")[:16]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    try:
        unpad = PKCS7(128).unpadder()
        plaintext = unpad.update(decryptor.update(ciphertext) + decryptor.finalize()) + unpad.finalize()
        require(hmac.compare_digest(plaintext, marker))
    except ValueError:
        raise ValueError("fixture marker denied") from None


class RestartFixture:
    """One disposable data directory and RAM-only continuity."""
    def __init__(self, home):
        self.home = home
        self.home.mkdir(mode=0o700)
        self.held = HeldKeyrings(home)
        try:
            self.password = bytearray(48 + secrets.randbelow(10) for _ in range(40))
            self.marker = bytearray(secrets.token_bytes(32))
            self.item = None
            self.snapshot = None
            self.stopped_broker = None
            self.stopped_roles = None
            self.stopped_display = None
            self.readback = False
        except BaseException:
            self.close()
            raise

    def close(self):
        for name in ("password", "marker"):
            value = getattr(self, name, None)
            if value is not None:
                value[:] = bytes(len(value))
        self.held.close()


class HeldKeyrings:
    def __init__(self, data_home):
        self.path = Path(data_home) / "keyrings"
        self.path.mkdir(mode=0o700)
        self.dirfd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.identity = self._row()
            require(not os.listdir(self.dirfd))
        except BaseException:
            os.close(self.dirfd)
            raise

    def _row(self):
        row = os.fstat(self.dirfd)
        visible = self.path.lstat()
        require(row.st_uid == os.getuid() and stat.S_IMODE(row.st_mode) == 0o700 and
                stat.S_ISDIR(visible.st_mode) and (row.st_dev, row.st_ino) == (visible.st_dev, visible.st_ino))
        return row.st_dev, row.st_ino

    def read_exact(self, absent_marker=None, mark=lambda _: None):
        mark("directory-identity")
        require(self._row() == self.identity)
        mark("leaf-inventory")
        leaves = os.listdir(self.dirfd)
        if leaves != [LEAF]:
            if "default" in leaves:
                mark("unexpected-default-alias")
            elif "login.keyring" in leaves:
                mark("unexpected-login-leaf")
            elif LEAF not in leaves:
                mark("expected-leaf-missing")
            else:
                mark("unexpected-extra-leaf")
            require(False)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        mark("exact-leaf-open")
        fd = os.open(LEAF, flags, dir_fd=self.dirfd)
        try:
            row = os.fstat(fd)
            mark("leaf-metadata-type-owner")
            require(stat.S_ISREG(row.st_mode) and row.st_uid == os.getuid())
            mark("leaf-metadata-mode")
            require(stat.S_IMODE(row.st_mode) == 0o600)
            mark("leaf-metadata-link")
            require(row.st_nlink == 1)
            mark("leaf-size-bound")
            require(len(GNOME_BINARY) < row.st_size <= 1024 * 1024)
            mark("leaf-read-bound")
            chunks = bytearray()
            while len(chunks) < row.st_size:
                block = os.read(fd, row.st_size - len(chunks))
                require(block)
                chunks.extend(block)
            require(not os.read(fd, 1))
            mark("leaf-binary-header")
            require(chunks.startswith(GNOME_BINARY))
            if absent_marker is not None:
                mark("leaf-plaintext-marker-denied")
                require(absent_marker not in chunks)
            mark("leaf-identity-stable")
            visible = os.stat(LEAF, dir_fd=self.dirfd, follow_symlinks=False)
            require(self._row() == self.identity and
                    (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns) ==
                    (visible.st_dev, visible.st_ino, visible.st_size, visible.st_mtime_ns))
            return row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, hashlib.sha256(chunks).digest()
        finally:
            os.close(fd)

    def close(self):
        os.close(self.dirfd)
