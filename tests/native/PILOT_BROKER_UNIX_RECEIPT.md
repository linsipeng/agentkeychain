# Combined native peer and SQLite receipt fixture (not installed)

Compile `pilot_broker_unix_receipt.c` as one fixture translation unit against
the previously pinned SQLite amalgamation and an explicitly provisioned OpenSSL
libcrypto with EVP Ed25519 support (OpenSSL 1.1.1 or 3.x). Use the existing
writer setup and add `-lcrypto` (and explicit include/library paths if needed).
Do not make this an installed requirement or auto-install dependencies.
An AF_UNIX sandbox denial exits 77, not PASS. Darwin requires a separately
verified OpenSSL build; this is not a claim about Darwin's system libcrypto.

The retained operation is exactly the existing hard-coded handoff golden.
The broker keeps held directory handles and uses the already-pinned VFS and
lease. Its two forked clients close inherited directory and listener FDs,
verify the listener's PID/UID/GID, generate separate throwaway keys after fork,
and pass only their public key on a dedicated inherited bootstrap pipe. The
broker checks the exact accepted PID/UID/GID before reading application bytes.
Neither the pipe nor the kernel check is installed executable/code-signer
attestation. The child inherits a copy of the fixture broker's address space
at fork; this is not a key custody/process isolation claim.

The socket carries bounded expected-byte messages plus detached Ed25519
signatures and then a write-half EOF in each direction. The fixture checks
exact canonical ASCII byte count and content, which denies extra/alternate
shapes without a generic parser. Requests have a random run scope and an
attempt discriminator. Responses contain the exact request SHA-256 digest
and the unchanged immutable receipt; identities use different role keys.
The broker authenticates before opening a mutation connection; its first
client gets the exact newly committed receipt and exits. A fresh client
and fresh database connection exercise exact persisted replay, never a
second receipt. A final read-only reopen checks tuple count, integrity and
absence of the journal. Existing separate crash fixture still exercises
SIGKILL and lost response. This combined fixture does not simulate host power
loss, check an installed process image, dispatch variable operations, or
implement product wire authorization/AEAD.
