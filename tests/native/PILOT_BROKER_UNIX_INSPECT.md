# Canonical native inspect socket acceptance (fixture only)

Build `pilot_broker_unix_inspect.c` against the same pinned SQLite amalgamation
and Ed25519-capable OpenSSL as the combined receipt fixture, including
`-lcrypto`. No installed entrypoints, public endpoint, real vault, or
native keychain/secret service. The test prepares one committed synthetic row
via the existing receipt fixture; only the preparation has write access.

Each peer exchange uses a fresh independently forked client, verified
mutual kernel PID/UID/GID, the fixture's distinct Ed25519 client and server
keys and a per-run nonce. This is not identity pinning of an installed
executable. The inner `wire` field is the v1 canonical inspect request from
`src/cloud/pilot-broker-wire.ts`, with the existing fixed receipt-fixture
profile. A valid signed `seed-pending` wire request never reaches a transaction
or receives an application reply. In the positive case the server uses
`SQLITE_OPEN_READONLY` and the pinned held-dirfd VFS/lease, joins the current
snapshot and immutable receipt on generation and operation, and serializes the
**read SQLite values** to the canonical v1 `snapshot` wire shape. It validates
against the fixed stage-one fixture, signs a response correlated to the exact
signed request digest, and sends only that response. Read-only reopen checks
the original one-row state and absence of rollback journal.

This is deliberately a fixed exact-ASCII fixture for one scope and generation,
not a general wire decoder, installed process executable attestation, or
authorization policy. The profile digest is the test golden, not a user
install or owner assertion. To enable product dispatch, still independently
verify the signed installation and native executable under an owned descriptor,
derive the profile from its held directory, and implement general authenticated
strict wire and sealed state validation before any transaction. No active
enrollment or cloud endpoint is exercised. Exit 77 means local read-only
SQLite verification passed but the sandbox denied AF_UNIX; run on the hosted
native runner for actual transport verification.
