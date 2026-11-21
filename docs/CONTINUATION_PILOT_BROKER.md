# Native pilot broker journal v1 (unwired)

Candidate for a separately installed and verified pilot broker in a disposable
profile. Not a process, endpoint, store backend or activation command. The
installed CLI still only checks installation; no fallback to Bun, ambient
paths or ordinary vault/credential state.

One bounded canonical UTF-8 JSON request per length-delimited frame over an
authenticated private inherited OS channel, not a network listener. Requests
have no SQL, path, arbitrary table/key, native slot, plaintext keys or token.
The record is a single opaque AEAD frame. Size/shape validation is not proof
of authorization or authentication. AEAD associated data must bind purpose,
profile digest, step, generation and previous digest (or bootstrap sentinel).
The broker derives profile digest from verified installation, signed dirfd
identity and protocol, not caller-controlled configuration. It must verify
the exact installed executable and peer, exercise writer isolation, and use
the validated held dirfds and cooperative OS lease. The storage broker has
no access to native secrets or signing keys.

| Wire operation | Required eventual behavior |
| --- | --- |
| Inspect | Read one scoped profile snapshot, not an entire vault. Return absent or exact current step, generation, operation digest and sealed frame. Do not create data. |
| Seed-pending | Generation 1 from a separately authorized first-device bootstrap in an exact new empty pilot profile. Bind original grant/request, approved scope, exact signed roster and encrypted package. Do not import ordinary profiles or overwrite. |
| Advance | Compare prior generation and operation digest together, then atomically write one exact next phase, new AEAD frame and durable receipt under the same lease. Identical replay returns stored receipt; conflicts/phase skips deny. |
| Recover | Read back an exact committed operation digest in this profile, not reconstruct or automatically retry any HTTP call. Missing/ambiguous proof stays closed. |

Fixed phases are pending, handoff-recorded, handoff-published, approval-recorded,
preflight-recorded and owner-proof-recorded. That maps to the required
pending/pending-approved/pending-self-roster/pending-package scope in
continuation-handoff and enrollment-intent; to the journaled browser material
before publishing and the separate durable publish marker in
continuation-machine; and to the nonce, exact fresh proof and Main receipt in
installed-pilot-commit-round-v1. Do not print codes through broker IPC logs.
Owner-proof-recorded is not local activation. Canonical replies are scoped
empty, latest snapshot (receipt plus sealed frame), or immutable receipt only.
The pure reference in pilot-broker-wire models this one sequence; it is not a
second runtime state machine. Mutation receipt and new row commit in one
native SQLite transaction, after which exact historical replays return that
receipt even when the CAS generation is stale. Recover returns a retained
receipt only, never stale sealed frames. Advance CAS checks exact prior digest
and generation so conflicting records do not overwrite. Digests are public
correlators, not authentication; authenticate the retained ledger and
monotonic anchor in the native design. The reference is not persistence, peer
authentication, or proof that native IPC validated raw fatal UTF-8.

## Activation is a separate gate

Current code depends on direct Bun CloudStore SQL for leases and operations;
the native broker cannot be a drop-in db object. The activation path validates
fresh post-commit Custody evidence, initializes protected roster-anchor and
checkpoint-anchor, commits SQLite roster/history/pins and then the
enrollment/cursor/health/commit marker/pending purge, and finally removes
protected enrollment-intent. A new pilot adapter needs explicit first-roster
semantics, not clear-and-replace generic history/pins or a DB-only commit.

Separate audited protected provider, not a database operation: in the exact
pilot namespace, scope access only to csk, signing-private, wrapping-private,
protected enrollment-intent, roster-anchor and checkpoint-anchor. Current
VDK is inside protected intent / authenticated encrypted profile, not a
broker-readable native slot. No generic native get/put/remove, default
keychain/collection or ordinary namespace. To activate, independently design
cross-store staged/committed/retry markers bound to the same proof and
profile generation, authenticated monotonic rollback protection, native
intent-clear policy and prevention of stale/replayed Custody evidence. Until
that protected identity, packaging and two-store durability is proven, the
V1 verbs remain unavailable in an installed CLI.

## Minimum installed acceptance before wiring

- Exact independently verified installed CLI and helper on non-root Linux
  and both macOS architectures, over a private authenticated channel; wrong
  executable/installation/dirfd, ordinary vault or unapproved profile denies.
- New profile needs scoped bootstrap. Inspect/recover do not mutate. Wrong
  version, injected path/slot, concurrent broker, stale generation/rollback,
  altered ciphertext, interrupted reply and exact idempotent replay each
  verified on the actual installed pair, without real credentials.
- Kill each native mutation at rollback/post-commit fences and reopen under
  the pinned identity. Inspect exact local operation/receipt; never retry a
  remote commit or activate. Assert ordinary vault and native slots untouched.
- Later activation needs cross-store crash/retry tests plus lost or revoked
  Auth/Main/Custody proof cases. This is not power-loss acceptance.
