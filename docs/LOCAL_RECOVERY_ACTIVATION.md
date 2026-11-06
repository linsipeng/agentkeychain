# Local recovery activation — implementation and acceptance

2026-11-06. Uncommitted synthetic development only. No deployment, production
endpoint, real vault, real secure store, or release was used.

## Native recovery

`agentkeychain cloud recover <packageId>` creates independent signing/wrapping keys
and a CSK in the isolated secure-store recovery journal. The locally generated
requestRef is journaled before HTTP and signed together with the exact target.
The HTTP possession challenge proves the wrapping key; retries retain the original
reference and keys. `cloud recover` without a package resumes the journal. The
verification URL uses a fragment, not a query carrying key material; the Web form
accepts that fragment. `--no-open` prints the safe URL without opening a browser.
Only status and that URL are emitted. Local vault initialization remains the
existing private-password CLI boundary; recovery never chooses a master password.

The target polls signed native-only status/evidence/delivery/finish/trust/readback
contracts. Email verification remains in the public restricted browser flow.
An enrolled device can submit an exact signed case confirmation through
`recovery-confirm`. The private account attester signs the verified account's
case for the 24-hour path; both operators independently verify the assertion.
Missing release, authority, service or account-attester provisioning fails closed.

## Authority trust and refresh

The Custodian issues trust only after its own durable completed decision and
current recovery-package epoch check. Its independent authority signs an encrypted
bundle containing the exact case and target keys, package/VDK-envelope digest and
key epoch, release-manifest canonical bytes, the signed roster chain, checkpoint,
and target-only refresh credential. During trust delivery the API receives only
its digest. The native refresh endpoint verifies the credential presented with a
target signature and never persists its plaintext. The authority's package-signature check anchors the submitted
roster chain to independently stored recovery enrollment, rather than accepting
an arbitrary self-signed chain. Historical revocation checkpoints are preserved.

The client authenticates the built-in signed release first, then matches the exact
manifest, authority key ID/signature, case/target/epoch, roster chain and checkpoint
pins. Decryption is local. Wrong keys, substituted release/package/authority/roster,
rollback anchors and cross-case replay fail closed. An exact committed retry is a
receipt, not a second activation. The Custodian retains one immutable encrypted
trust receipt per case; the API atomically records its roster and refresh digest.

`recovery-refresh` is a real native, target-signed session contract. It checks the
credential digest and current device/membership/vault authorization. The client
uses a domain-separated deterministic session identifier derived from the protected
credential; retries/restarts converge to one session row. Only an expired session
is renewed; replay does not extend a live session. Device revocation denies refresh.
Original enrolled clients retain the existing challenge-based session flow.

## Durable activation and cleanup

The journal stages are `created`, `awaiting_verification`, `waiting_for_release`,
`released`, `reconstructed`, `activating`, `server_completed`, `local_committed`,
and `active`, with `cancelled`, `expired` and `conflict` terminal receipts.
A secure-store journal write is the stage commit point. SQLite is a CSK-encrypted
mirror; restart repairs a stale mirror from the same secure record. Fenced leases
exclude concurrent recovery writers. No replacement keys are generated on resume.

The client verifies both independently signed releases before opening either share,
reconstructs the recovery key and unwraps the VDK locally, and proves signing and
wrapping possession before server completion. Mutable shares, reconstruction keys,
PKCS8 imports and temporary plaintext buffers are erased on all ordinary exit paths.
JavaScript strings and opaque WebCrypto objects do not provide guaranteed erasure.

Activation stages the CSK, target private keys, refresh credential, roster anchor,
and independently retained recovery checkpoint in secure storage, then commits the
cloud profile/VDK/cursor in one SQLite transaction. A secure-store intent gate keeps
ordinary cloud runtime access closed during partial publication. Final activation
requires server completion/readback, matching refresh and roster digests, and local
key/profile/anchor readback. This provides atomic visibility through a recoverable
protocol, not an impossible cross-Keychain/SQLite transaction.

The initial sync cursor starts at genesis with a required checkpoint floor. The
separate secure recovery anchor binds that floor's root; sync verifies history
through it before applying buffered credentials. Recovery acceptance includes
subsequent actual encrypted sync and exact payload decryption.

Cancellation/expiry before a durable server activation erases isolated intent keys,
shares and VDK, leaving a key-free terminal receipt. Pre-activation binding conflicts
also erase the isolated intent. `cloud recover <packageId> --restart` explicitly
clears only a key-free terminal receipt; it cannot discard a live recovery. Once the
server has committed activation, expiry cannot strand completion/readback. Invalid
post-completion trust keeps the target isolated and resumable, without publishing
local credentials or falsely declaring it active.

## Validation (original recovery activation run)

Root: **158 passed**, **854 assertions**, **42 files**. Backend: **280 passed**,
**9 files**. Web: **90 passed**, **3 files**. Compiled recovery: **51 scenarios**
(48 main cases, two activation/expiry boundaries and live epoch invalidation). Resource diagnostics:
**8 passed**, no undisposed-RPC warning. Generated-bundle acceptance passed.
Machine-readable results: [LOCAL_RECOVERY_AUDIT.json](LOCAL_RECOVERY_AUDIT.json).

- Root tests include existing roster, export, reconciler, issuer and compiled
  enrollment regressions, plus recovery trust, journal, refresh and cleanup tests.
- Backend tests execute the two Workers and independent D1 databases, including
  authority trust issuance, repeat delivery, refresh renewal/replay/revocation,
  browser isolation and completion readback.
- `npm run test:recovery-process` builds the actual CLI with compile-time synthetic
  composition, two local Workers, temporary D1/SQLite and an in-memory fake secure
  store. No production environment variable selects those adapters.
- The compiled matrix covers requestRef request/response loss; share opening and
  reconstruction; activation request/response loss; secure-store writes before and
  after commit for every recovery slot; SQLite commit before/after; and final readback.
  It also rejects cancellation, expiry, wrong target/epoch, authority signature/key ID,
  roster public-key, checkpoint-pin and replay substitution. A real new-package
  epoch invalidates the waiting case and erases its isolated intent. The delayed flow advances a test clock across both Worker
  decisions and D1 time predicates, while process leases use elapsed test time.
- Successful scenarios assert exact device/session/receipt counts, resume, sync an
  encrypted synthetic credential, decrypt it, retry refresh, logout and relogin.
  Database/WAL and captured recovery output checks exclude plaintext VDK, recovery
  key, shares, target private keys, CSK and refresh credential.
- Lint, root/backend/Web typechecks and builds, generated bundle acceptance,
  resource diagnostics and dependency audits passed. npm full/runtime and Bun
  audits report zero vulnerabilities. A bounded scan of **106** changed/untracked source
  and document files found **zero** high-confidence embedded key/token patterns;
  it is not a comprehensive audit.
- An initial failing synthetic test assertion printed ephemeral test-key fields.
  The assertion now reports only booleans/stages, and that temporary diagnostic
  file was removed. No real keys were used. Final recovery-output and artifact
  checks pass without key/share/refresh plaintext.

## External gates

Production domain, signed release root/manifest, independent operator keys and
trusted identity/service bindings have not been provisioned or deployed. The
unprovisioned production CLI remains fail-closed. Native OS credential-store
integration is built; synthetic recovery uses the fake store and never the user's
Keychain. Built-in Chrome/DevTools is unavailable in this session; Web/HTTP and
compiled-process coverage was used, with no external Chrome takeover or Hermes
browser adapter. No commit, deployment or real-data access occurred.

Later export/enrollment/reconciliation changes and current gate evidence are recorded
in [PHASE45_FINAL_CONTINUATION.md](PHASE45_FINAL_CONTINUATION.md).

## Final local continuation

The final issuer/daemon, protected enrollment-anchor and directory-relative export
gaps are locally complete. See [current acceptance](PHASE45_FINAL_CONTINUATION.md)
for the latest full gates and external provisioning/native-platform/browser/deployment
boundaries. The 51 compiled recovery scenarios were rerun successfully.

Final recovery trust issuance is gated by the independent Custodian witness. Changed retries conflict; pre-activation refresh creates a new immutable version and target-signed activation freezes its accepted history. See [FINAL_SECURITY_REPAIR.md](FINAL_SECURITY_REPAIR.md).
