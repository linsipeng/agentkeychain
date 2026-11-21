# Managed Cloud v0.7 production and release runbook

This runbook is preparation, not permission to deploy, publish a release or change cloud credentials. The existing [v0.7 acceptance matrix](MANAGED_CLOUD_V07_ACCEPTANCE.md) still controls product readiness. Production rollout and GitHub Release are additional delivery stages.

## 1. Build and prove the candidate

- Keep one reviewed Git commit as the candidate. Record its tree, required CI, Worker-build evidence, native macOS helper/build evidence, and product and independent security review. Treat missing proof as not passed.
- Exercise the real built service graph with isolated synthetic data. First-device admission must prove independent Auth approval and atomic Custody admission. For an already-approved device, continue the original identity only with a fresh, exact, separately verified authorization. Do not mint a new identity to make activation pass.
- Require both compiled clients to complete onboarding, sync/restart, scope approval and denial, offline retry, revocation, and recovery without exposing credential material. Verify cookie behavior in a disposable real-browser session and keep actual passkey user verification intact.
- Use [the candidate packaging workflow](RELEASE_PACKAGING.md) to produce binaries for supported Darwin and Linux architectures and checksum-verified Darwin secure-store helpers. Verify file architecture, release input manifest, install/upgrade and rollback with isolated home and secure-store fixtures. Do not tag a candidate merely to produce test artifacts: the current repository treats version tags as a release trigger.

### Same-device continuation release gate

For the first package-only continuation, verify the original approval and the
exact still-active genesis device, use a fresh Auth-origin passkey assertion,
and pin the distinct continuation authority. Until the client can prove
checkpoint ancestry, require the pristine Custody head: first witness event,
first roster revision, sync sequence zero and the canonical genesis root.
Do not refresh the original expired grant or relax its existing activation
check.

Before activation, require separate evidence of the exact package commit and
of current independent Custody state. The transaction owner can attest only to
the committed package joined to its continuation record. Custody independently
checks current state against the same commitment and a fresh client challenge;
a Custody signature over a Main claim alone is not independent evidence of
Main storage. If independent durable package authority is a product
requirement, prove that authority separately before release.

Exercise loss before the commit and loss of the success response after it.
The first must leave no effective package; the second must recover the same
commit with a read-only proof, never a second approval or mutation. With a
committed row inside the approval window, a later readback can use fresh,
device-bound proof without extending the approval. Revocation, epoch change,
nonce mismatch, a missing or different package, or stale Custody state must
not activate the CLI. Repeat process termination before and after secure
staging, local database commit, and secure cleanup: the persisted intent must
resume one profile, one roster anchor and the same device and vault data key.
Do not unlock sync from that intent without a valid live head and revocation
check. Unwired fixtures and unsigned projections do not meet this release gate.
The experimental Auth issuer's provider returns a raw signed witness; before
enabling it, require nonce-bound current Custody state and revocation checks at
approval finalization and again during consumption. The experimental Auth
readback can return a byte-identical committed approval to a current session
with an exact ceremony/credential-bound read grant. Its isolated Auth
transport grants that scope atomically with a successful passkey ceremony;
the independently hosted browser origin, production transport and policy
are not wired. Do not reapprove or expose general decision lookup.

The internal Main proof binds one currently valid approval, exact durable
package and scoped device request to a nonce and a separately signed Custody
assertion. The separate experimental post-commit Custody check then
authenticates the exact Main claim before independently reading the latest
state, using a new activation nonce. It does not prove independent package
storage. Production transport and the normal CLI need to enforce this order
and recheck revocation before activation and unlock. This revision fails closed
after the short approval window; safely recovering an older committed
decision requires a separate time-of-commit contract, not replaying an
expired approval.

## 2. Rehearse the rollout in disposable staging

1. Identify and verify the distinct API and Web origins, Auth origin and RP, authority and witness ownership, Worker and D1 resources, manifest signers, current versions and deploy permissions. Main API must not hold Auth approval or Custody witness signing keys or control their authoritative state.
2. Use non-production account names, isolated databases and independently generated test material. Test migrations on fresh and upgrade-shaped synthetic databases, especially retention and witness invariants; validate a rollback-compatible Worker and matching static assets before rollout.
3. Confirm the cookie namespace rollout and real browsers on matched assets. Confirm new independent first-device approvals and continuity of existing witnessed heads. Do not infer provenance from Main-owned credentials; old production credentials or enrollment must not be moved or reset as a rehearsal step.
4. Record tested commit, bundle digests, safe diagnostics, D1 migration versions and a rollback decision point. Do not collect actual session cookies, private keys, recovery codes or credential values in the evidence.

## 3. Obtain release-time approval

Send one proposed production change to the owner. It must identify the exact candidate SHA and version, target origins and resources, what will be migrated or left unchanged, approval and maintenance implications, the rollback action, and the GitHub tag and release visibility. Give any real user-verification gate only when it is necessary and ready. Do not merge, change production, push the release tag or publish until the owner confirms the concrete scope and all prior gates pass.

## 4. Execute and verify only the approved sequence

- Verify the candidate, target account and approvals immediately before acting. Stop if remote HEAD, environment, migration, live owner or risk materially changed.
- Apply the approved compatible database and Worker/asset changes in the rehearsed dependency order. Independently read back the expected versions and safe service health. Validate a designated isolated account; never test by modifying someone's existing Vault.
- Only after production checks pass, create the approved version tag from the exact candidate and verify the GitHub release and exact asset checksums, including both Darwin helpers. Link the release and the tested rollback path.
- If any stop condition is reached, do not publish or quietly weaken a trust boundary. Use only the preapproved rollback if applicable and clearly report which stage actually took effect.

The isolated CLI staging slice records `genesis-package-continuation-v1` in
the existing protected intent only after validating both proofs. The Main
commit-key appendix and Auth approval-key appendix have distinct domains,
verify under the same signed release root and are tied to the exact release
manifest. The signed Main commit links the exact Auth approval and fresh
Custody evidence by digest; the three keys must differ. A dropped local
acknowledgment may be recovered by read-only validation of the protected
historical record at its accepted time. That record never grants activation,
does not renew authorization, and must not be used to unlock synchronization.
Production integration still needs a fresh revocation/head check and an
exclusive cross-process enrollment lease before any local write that activates
the profile. The native secure store does not expose compare-and-swap.

The isolated local-finalization slice additionally requests a new Custody
challenge after acquiring an enrolled-database lease. It verifies the current
post-commit signature over the exact staged Main receipt, device, witness and
package. Scope is the unchanged genesis head only. The same secure intent owns
partial roster/checkpoint writes; the profile and its exact intent digest
marker commit atomically. As long as protected intent cleanup is pending the
runtime will not open, even with a written profile. Retrying cleanup still
requires a new live Custody proof in the supported window. This slice is not
called by the shipping CLI and other enrollment writers do not yet share its
lease; do not enable it until all writers use a compatible exclusive guard.

The local process regression `bun test tests/cloud-continuation-process.test.ts`
builds a nonshipping Bun client with a signed isolated release fixture, then
runs the actual CLI staging/finalization and runtime checks in distinct OS
processes against a disposable SQLite file. The fixture controller calls the actual Main
transaction and proof reader; a token-protected localhost shim calls the actual
post-commit proof function against a separate SQLite Custody ledger. The test
injects secure-store and Auth/signing fixtures, and emulates stale lease expiry
only after observing an exited process. It verifies both sides of the local
profile commit and that an unavailable Custody proof leaves sync locked. This
is not a production route, native OS keychain, deployment or cross-operator
staging check. Auth credential enrollment and the Cloudflare Worker routing
remain covered or gated separately.
