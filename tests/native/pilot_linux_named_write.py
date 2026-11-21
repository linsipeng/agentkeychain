"""Fixture-only crypto and independently held named store checks. No reads via Secret Service."""
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import stat

LABEL = "AKCPilotPrimary"
COLLECTION = "/org/freedesktop/secrets/collection/" + LABEL
LEAF = LABEL + ".keyring"
EMPTY_PROVIDER_SIDECAR = "user.keystore"
GNOME_BINARY = b"GnomeKeyring\n\r\0\n"


def require(ok):
    if not ok:
        raise ValueError("named write denied")


def encrypted_fixture_secret(shared, marker):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    require(isinstance(shared, int) and 2 <= shared < (1 << 1024) and len(marker) == 32)
    # GNOME 46.1 CKM_DH_PKCS_DERIVE defaults to the full prime length
    # and zero-pads the leading edge (gkm-dh-mechanism.c). Its HKDF uses
    # SHA-256 with NULL salt and empty info (gkd-secret-session.c).
    prk = hmac.digest(bytes(32), shared.to_bytes(128, "big"), "sha256")
    key = hmac.digest(prk, b"\x01", "sha256")[:16]
    iv = secrets.token_bytes(16)
    padded = bytearray(48)
    padded[:32] = marker
    padded[32:] = bytes([16]) * 16
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return iv, cipher.update(padded) + cipher.finalize()
    finally:
        padded[:] = bytes(len(padded))


def with_reopened_seed(shared, iv, ciphertext, consume):
    """Consume one fixed 32-byte secret; never return plaintext."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    require(isinstance(shared, int) and 2 <= shared < (1 << 1024) and
            len(iv) == 16 and len(ciphertext) == 48)
    prk = hmac.digest(bytes(32), shared.to_bytes(128, "big"), "sha256")
    key = hmac.digest(prk, b"\x01", "sha256")[:16]
    decoder = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    clear = bytearray(63)  # update_into needs ciphertext length plus block size minus one.
    view = memoryview(clear)
    try:
        require(decoder.update_into(ciphertext, clear) == 48 and decoder.finalize() == b"")
        require(hmac.compare_digest(view[32:48], bytes([16]) * 16))
        consume(view[:32])
    finally:
        clear[:] = bytes(len(clear))


def fixture_public(seed):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def verify_reopened_signing_once(pinned_public, signed_context, seed):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

    require(len(pinned_public) == 32 and len(signed_context) == 32 and len(seed) == 32)
    challenge = b"AgentKeychain-disposable-provider-reopen-signing-v1\0" + signed_context + secrets.token_bytes(32)
    require(hmac.compare_digest(fixture_public(seed), pinned_public))
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(challenge)
    Ed25519PublicKey.from_public_bytes(pinned_public).verify(signature, challenge)


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
    def __init__(self, home, protected_signer=False):
        self.home = home
        self.home.mkdir(mode=0o700)
        self.held = HeldKeyrings(home)
        try:
            self.password = bytearray(48 + secrets.randbelow(10) for _ in range(40))
            self.marker = bytearray(secrets.token_bytes(32))
            self.signer_pin = fixture_public(self.marker) if protected_signer else None
            self.signer_verified = False
            self.item = None
            self.snapshot = None
            self.stopped_broker = None
            self.stopped_roles = None
            self.stopped_display = None
            self.readback = False
        except BaseException:
            self.close()
            raise

    def drop_original_seed(self):
        require(self.signer_pin is not None and self.marker is not None and not self.readback and
                not self.signer_verified and self.snapshot is not None)
        self.marker[:] = bytes(len(self.marker))
        self.marker = None

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
        self._sidecar = None
        self._before_unlock = None
        self._after_unlock = None
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

    @staticmethod
    def _sidecar_identity(row):
        return (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_nlink,
                row.st_size, row.st_mtime_ns, row.st_ctime_ns)

    def _read_empty_sidecar(self, fd, mark):
        mark("sidecar-directory-identity")
        require(self._row() == self.identity)
        leaves = os.listdir(self.dirfd)
        mark("sidecar-inventory")
        require(len(leaves) == 2 and set(leaves) == {LEAF, EMPTY_PROVIDER_SIDECAR})
        row = os.fstat(fd)
        mark("sidecar-scoped-metadata")
        require(stat.S_ISREG(row.st_mode) and row.st_uid == os.getuid() and
                stat.S_IMODE(row.st_mode) == 0o600 and row.st_nlink == 1)
        mark("sidecar-nonempty")
        require(row.st_size == 0 and os.pread(fd, 1, 0) == b"")
        seen = self._sidecar_identity(row)
        mark("sidecar-stable-identity")
        require(seen == self._sidecar_identity(os.fstat(fd)) ==
                self._sidecar_identity(os.stat(EMPTY_PROVIDER_SIDECAR, dir_fd=self.dirfd, follow_symlinks=False)))
        return seen

    def pin_empty_unlocked_sidecar(self, mark):
        # Only the exact reopened fixture unlock calls this. GNOME's pinned
        # PKCS#11 provider opens the auxiliary store with O_RDONLY | O_CREAT.
        # Opening alone can make an empty file, never a persisted credential.
        require(self._sidecar is None)
        mark("sidecar-open")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(EMPTY_PROVIDER_SIDECAR, flags, dir_fd=self.dirfd)
        try:
            seen = self._read_empty_sidecar(fd, mark)
        except BaseException:
            os.close(fd)
            raise
        self._sidecar = fd, seen

    def _check_pinned_sidecar(self, mark):
        fd, expected = self._sidecar
        seen = self._read_empty_sidecar(fd, mark)
        mark("sidecar-pinned-identity")
        require(seen == expected)

    def read_exact(self, absent_marker=None, mark=lambda _: None):
        mark("directory-identity")
        require(self._row() == self.identity)
        mark("leaf-inventory")
        leaves = os.listdir(self.dirfd)
        if self._sidecar is not None:
            self._check_pinned_sidecar(mark)
        elif leaves != [LEAF]:
            if "default" in leaves:
                mark("unexpected-default-alias")
            elif "login.keyring" in leaves:
                mark("unexpected-login-leaf")
            elif LEAF not in leaves:
                mark("expected-leaf-missing")
            else:
                extras = set(leaves) - {LEAF}
                if extras == {"user.keystore"}:
                    mark("unexpected-pkcs11-store")
                elif extras == {"user.keystore.lock"}:
                    mark("unexpected-pkcs11-store-lock")
                elif len(extras) == 1:
                    # The pinned provider names transaction staging files with
                    # these two shapes. Classify only; every extra is denied.
                    extra = next(iter(extras))
                    if re.fullmatch(r"\.temp-[A-Za-z0-9]{6}", extra):
                        mark("unexpected-provider-temp-leaf")
                    elif re.fullmatch(re.escape(LEAF) + r"\.temp-[0-9]{1,10}", extra):
                        mark("unexpected-collection-temp-leaf")
                    else:
                        mark("unexpected-extra-leaf")
                else:
                    mark("unexpected-multiple-extra-leaves")
            require(False)
        mark("exact-leaf-open")
        fd = self._open_named()
        try:
            seen = self._snapshot_named(fd, absent_marker, mark, 1)
            self._assert_named_visible(fd, mark)
            if self._sidecar is not None:
                self._check_pinned_sidecar(mark)
            if self._after_unlock is not None:
                self._verify_unlock_files(seen, absent_marker, mark)
            return seen
        finally:
            os.close(fd)

    def _open_named(self):
        return os.open(LEAF, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.dirfd)

    def _snapshot_named(self, fd, absent_marker, mark, links):
        row = os.fstat(fd)
        mark("leaf-metadata-type-owner")
        require(stat.S_ISREG(row.st_mode) and row.st_uid == os.getuid())
        mark("leaf-metadata-mode")
        require(stat.S_IMODE(row.st_mode) == 0o600)
        mark("leaf-metadata-link")
        require(row.st_nlink == links)
        mark("leaf-size-bound")
        require(len(GNOME_BINARY) < row.st_size <= 1024 * 1024)
        mark("leaf-read-bound")
        chunks = bytearray()
        while len(chunks) < row.st_size:
            block = os.pread(fd, row.st_size - len(chunks), len(chunks))
            require(block)
            chunks.extend(block)
        require(not os.pread(fd, 1, len(chunks)))
        mark("leaf-binary-header")
        require(chunks.startswith(GNOME_BINARY))
        if absent_marker is not None:
            mark("leaf-plaintext-marker-denied")
            if isinstance(absent_marker, memoryview):
                view = memoryview(chunks)
                require(not any(hmac.compare_digest(view[i:i + len(absent_marker)], absent_marker)
                                for i in range(len(view) - len(absent_marker) + 1)))
            else:
                require(absent_marker not in chunks)
        mark("leaf-stable-read")
        require(self._sidecar_identity(row) == self._sidecar_identity(os.fstat(fd)))
        return row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, hashlib.sha256(chunks).digest()

    def _assert_named_visible(self, fd, mark):
        mark("leaf-identity-stable")
        row = os.fstat(fd)
        visible = os.stat(LEAF, dir_fd=self.dirfd, follow_symlinks=False)
        require(self._row() == self.identity and self._sidecar_identity(row) == self._sidecar_identity(visible))

    def pin_locked_original(self, expected, marker, mark):
        mark("one-original-before-unlock")
        require(self._sidecar is None and self._before_unlock is None and
                self._after_unlock is None and os.listdir(self.dirfd) == [LEAF])
        fd = self._open_named()
        try:
            require(self._snapshot_named(fd, marker, mark, 1) == expected)
            self._assert_named_visible(fd, mark)
        except BaseException:
            os.close(fd)
            raise
        self._before_unlock = fd, expected

    def pin_authenticated_unlock_replacement(self, marker, mark):
        mark("one-replacement-after-unlock")
        require(self._before_unlock is not None and self._after_unlock is None and self._sidecar is not None)
        old_fd, original = self._before_unlock
        # GNOME 46.1 explicitly persists the collection credential options
        # after the public unlock. Its transaction atomically replaces the
        # file and the binary serializer chooses fresh encryption parameters.
        mark("original-detached")
        require(os.fstat(old_fd).st_nlink == 0 and self._snapshot_named(old_fd, marker, mark, 0) == original)
        fd = self._open_named()
        try:
            new = self._snapshot_named(fd, marker, mark, 1)
            self._assert_named_visible(fd, mark)
            self._check_pinned_sidecar(mark)
            mark("single-same-size-encrypted-replacement")
            require(new[0] == original[0] and new[1] != original[1] and
                    new[2] == original[2] and new[4] != original[4])
            recorded = new, self._sidecar_identity(os.fstat(fd))
        except BaseException:
            os.close(fd)
            raise
        self._after_unlock = fd, recorded
        return new

    def _verify_unlock_files(self, observed, marker, mark):
        old_fd, original = self._before_unlock
        new_fd, (expected, metadata) = self._after_unlock
        mark("original-still-detached")
        require(self._snapshot_named(old_fd, marker, mark, 0) == original)
        current = self._snapshot_named(new_fd, marker, mark, 1)
        self._assert_named_visible(new_fd, mark)
        mark("replacement-still-pinned")
        require(current == observed == expected and self._sidecar_identity(os.fstat(new_fd)) == metadata)

    def close(self):
        def drop(field):
            value = getattr(self, field)
            if value is not None:
                try:
                    os.close(value[0])
                finally:
                    setattr(self, field, None)
        try:
            drop("_after_unlock")
        finally:
            try:
                drop("_before_unlock")
            finally:
                try:
                    drop("_sidecar")
                finally:
                    os.close(self.dirfd)
