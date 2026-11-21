# Managed Cloud support Workers and staging configuration

This implementation starts at `afc0186` on `feat/managed-cloud-v0.7`. It does not
provision resources, deploy, send real email, access Cloudflare accounts, create
credentials, commit, or change the pinned public installation release.

## Deployable artifacts

`managed-cloud/provisioning/plan.json` records the nonsecret staging topology:

| Component | Worker | Database / ingress |
| --- | --- | --- |
| API and Web assets | agentkeychain-cloud-api | agentkeychain-cloud-main; agentkeychain.soupsam.com and api.agentkeychain.soupsam.com |
| Custodian | agentkeychain-cloud-custodian | agentkeychain-cloud-custodian; private |
| Auth Trust | agentkeychain-cloud-auth-trust | agentkeychain-cloud-auth; private |
| API Trust | agentkeychain-cloud-api-trust | Main metadata; private |
| Custody Trust | agentkeychain-cloud-custody-trust | Custodian metadata; private |

The Web origin and Passkey RP ID are `https://agentkeychain.soupsam.com` and
`agentkeychain.soupsam.com`. Browser calls remain same-origin. Device clients use
the separately pinned API origin. Only the API Worker has custom-domain routes.
All Workers disable workers.dev, preview URLs and observability. Support Workers
return HTTP 404, including their named RPC entrypoints. Custody secrets and
resource administration must have separate operator ownership and permissions;
separate Worker names do not establish that administrative boundary by themselves.

Checked-in `provisioning/examples/*.json.example` contain no real resource IDs or
secrets and cannot be deployed as rendered manifests. Each Worker also has a
local-only `wrangler.toml`, with the actual production entrypoint names and
synthetic local D1 IDs. Never deploy these local manifests.

`node managed-cloud/provisioning/render.mjs` reads runtime environment supplied by
a protected operator process. Required inputs are `AKC_MAIN_D1_ID`,
`AKC_CUSTODIAN_D1_ID`, `AKC_AUTH_D1_ID`, `AKC_EMAIL_FROM`, `AKC_PUBLIC_PINS` and
`AKC_OPERATOR_PUBLIC_KEYS`. Optional `AKC_WEB_DOMAIN` and `AKC_API_DOMAIN` override
the recommended domains together. IDs must be distinct canonical UUIDs. Domains,
service names, compatibility flags, public pin hashes and cross-operator key
separation are validated before any file is written. Missing inputs fail closed.
No network, shell command, resource creation or deployment occurs in the renderer.

`AKC_PUBLIC_PINS` is a JSON object with `releaseId`, `checkpointKeys`, `witnessKeys`,
`recoveryAuthorities` and `recoveryServices` (`api` and `custodian`). Each pin is
`{keyId,publicKey}`, where keyId is lowercase SHA-256 of the canonical base64
32-byte public key. `AKC_OPERATOR_PUBLIC_KEYS` has `api` and `custodian` arrays
containing **all** active and retained public keys, including wrapping and account
attestation keys. Release pins must belong to the correct operator's array:
`checkpointKeys` and `recoveryServices.api` are API-owned; `witnessKeys`,
`recoveryAuthorities` and `recoveryServices.custodian` are Custody-owned. The renderer
and Custody runtime both enforce this mapping.
Collect these actual public values after operator provisioning; never substitute
synthetic test pins into release artifacts.

The renderer produces five mode-0600 Wrangler JSON files and
`release-manifest.unsigned.json` in ignored `provisioning/generated/` (directory
mode 0700). Paths resolve to the actual source, migrations and built Web assets.
The unsigned manifest is a candidate for the existing separately authorized
release signing/build process, not a signed release and not an activated client
configuration. No fallback release origin or pin is installed.

## Secret and metadata provisioning contract

All business credentials remain in AgentKeychain. An authorized, restricted
loader must pass the following values to the appropriate Worker secret bindings;
never persist them in manifests or committed files:

| Worker | Required secret bindings |
| --- | --- |
| API | AUTH_BOOTSTRAP_KEY, AUTH_EMAIL_KEY, AUTH_LOOKUP_KEY (distinct 32-byte canonical base64url) |
| Auth Trust | EMAIL_HASH_KEY, CODE_HASH_KEY, SOURCE_HASH_KEY (distinct 32-byte canonical base64) |
| API Trust | CHECKPOINT_KEYRING, ACCOUNT_KEYRING, WRAP_KEYRING, RELEASE_KEYRING |
| Custody Trust | WITNESS_KEYRING, TRUST_KEYRING, WRAP_KEYRING, RELEASE_KEYRING |

Keyring JSON has `{activeId,keys:[{keyId,publicKey,privateKey}]}`. Private material
is canonical base64 PKCS#8 (48 bytes); public material is canonical base64 raw
32-byte Ed25519, or X25519 for WRAP_KEYRING. Keys are pair-checked on import,
nonextractable private CryptoKeys are used, and duplicate public keys or private
seeds across purposes are rejected. The active ID must name a private key.
Retained signing keys may omit `privateKey` and are verification-only; retained
wrapping keys require their old private key to decrypt old packages. At most 16
keys per purpose are supported. Only the active key signs. No private material
is returned by any RPC; public signing metadata is available from `key()` and
`publicKeys()`. Helper functions are module-private, not merely TypeScript-private.

Both operators require `PEER_PUBLIC_KEYS` covering the other operator's entire
keyring. Custody also requires `RELEASE_POLICY` matching its provisioned witness,
trust and release keys. The renderer supplies these public variables. Failures
return fixed errors without serializing secret configuration or caller payloads.

Additive Main `0023_operator_trust.sql`, Custodian `0008_operator_trust.sql` and
Auth `0001_email.sql` supply the new tables. The independent operator control
plane must review and provision metadata in `trust_devices` (initial Custody
anchors and explicit revocation vetoes), `trust_accounts` (account-verifier pins)
and `trust_revocations` (exact approved canonical revocation digests). There is
no public or API RPC that grants these permissions. No default allow entry exists.
Custody follows its independently witnessed roster after genesis and rechecks
revocation, while API checks live membership and device records. For genesis,
`GENESIS_AUTH` connects the Custodian to the API Trust Worker's dedicated
`RosterGenesisAuthority` RPC, which only validates the initial roster against
active API Main enrollment. It does not expose general recovery authorization
or establish independent genesis evidence. Independent first-device approval
remains a release gate; account-verifier enrollment and last-device revocation
also require their separately provisioned trust metadata.

`RecoveryAuthority.authorize` stores a 60-second exact-case authorization only
after verifying evidence. `RecoveryKeys.rewrap` rechecks that evidence against
current trust, requires an active exact persisted saga and latest package epoch,
and matches the stored encrypted share and package context. It then binds output
to the case's target key and operator. Arbitrary contexts, changed targets,
unauthorized cases, cancelled cases and revoked confirmers fail closed. Neither
operator receives a reconstructed recovery key or Vault key.

Signing domains are restricted to canonical sync/activity checkpoints; the
operator's authenticated recovery releases; account-verification attestations;
independent roster/revocation witnesses; or Custody recovery completion, roster
and trust receipts. CheckpointSigner supports the existing sync object and
`AgentKeychain-activity-checkpoint-v2` array contracts. Activity rotation retains
and verifies the original independently stored public anchor and all historical
checkpoint pins; dropping an anchored pin fails verification.

## Email and trusted ingress

Auth Trust owns a separate D1. Codes are unbiased six-digit CSPRNG values with a
600-second lifetime, five attempts, one atomic consume, a 60-second resend limit
and five deliveries per email per hour across purposes/contexts. D1 contains only
keyed email/code hashes, context digests, counters and generic audit events.
Sender failures invalidate the attempted code and expose no provider diagnostic.
Expired rows are removed on calls and by an hourly scheduled cleanup; rate rows
and audit events have bounded retention. No email, code or raw IP is logged.

The production EMAIL binding is the typed Cloudflare SendEmail adapter. It must
be provisioned with a verified sender and a provider capability that can deliver
to the intended invitation/recovery recipients. Missing delivery capability fails
closed; there is no fetch-based provider or test sender fallback in production.
Real delivery, recipient policy and sender-domain verification remain external
gates. Tests replace only this external sender with an in-memory mailbox whose
inspection interface returns masked recipient metadata, never verification codes.

`POST /v1/auth/email/request` accepts exactly `{email,purpose,context}` after
bootstrap/session, strict Origin, JSON, CSRF, source and identity rates. Purpose
is `invitation` or `recovery`; context is the exact invitation token or prepared
43-character requestRef. It does no existence lookup, always returns generic
`{accepted:true,retryAfter:60}` on accepted requests, and never returns the code.
The API constructs verification proof envelopes with purpose and the digest of
the same context; a browser cannot substitute a proof's context. Existing
verification endpoints keep their browser-facing request format.

TrustedAuthSource accepts only the API ingress Request with Cloudflare `cf`
metadata and a single valid `CF-Connecting-IP`. This header is overwritten by
Cloudflare at the public ingress. Private binding callers are trusted ingress
components; they must never manufacture Requests from client-supplied metadata.
No X-Forwarded-For/X-Real-IP fallback exists. IPv6 is normalized and only a keyed
pseudonym is returned. Tests explicitly supply synthetic edge metadata.

The invitation and recovery forms include an accessible bilingual send-code
button. It obtains a bootstrap before sending; a successful response starts a
60-second resend cooldown from receipt time. Failures show generic retryable
status and do not start a false timer. This is a resend limit, not progress.

## Verification and external gates

Run `npm run test:support-bundle --prefix managed-cloud` for deterministic
provisioning negatives and the actual five generated bundles, exact staging
service graph and three D1s. The mailbox is in-memory and all outbound HTTP is
denied. It exercises invitation/recovery email request/verify/replay, private
HTTP, signing metadata, signing-domain denial, hidden helper methods, independent
release authorization, target-bound rewrap, revocation and cancellation.
Existing process fault fixtures remain synthetic and run separately.

Measured local acceptance: root **190 tests / 1,804 assertions / 46 files**
(including the compiled process test); backend **316 tests / 11 files**; Web
**95 tests / 4 files**; compiled recovery **52 scenarios**; resource diagnostics
**8 tests / no undisposed-resource warnings**. The final stricter-email change
also passed the focused **147-test** auth/browser suite. Both generated-bundle
harnesses passed; provisioning covered five configurations and eight rejection
cases. Lint, root/backend/Web typechecks, client/native/Worker/Web builds and
whitespace checks passed. Root and managed Bun audits plus full/runtime npm
audits returned zero advisories. Existing 190/291/93 baseline tests were retained.

The machine-readable acceptance record is `MANAGED_CLOUD_SUPPORT_WORKERS_AUDIT.json`.
Remaining external gates: actual Cloudflare resources and resource IDs; independent
operator permissions and metadata approvals; AgentKeychain-managed key generation
and secret installation; actual public pin collection and release signing; sender
verification and real delivery; remote migrations; DNS/custom-domain ownership;
real Passkey and delayed-recovery staging rehearsal; browser/Chrome accessibility
and visual acceptance; explicit deployment/release approval. No built-in Codex
Chrome interface was available in this session; no external Chrome or Hermes
browser adapter was used. These gates are not claimed as completed by local tests.


The signed release contract requires both `apiOrigin` and `webOrigin`: canonical
HTTPS origins without credentials, paths, queries or fragments. They must differ,
and the API hostname must be a strict subdomain of the Web hostname. Device HTTP
uses `apiOrigin`; login browser/verification URLs and device management use
`webOrigin`. Neither role can be replaced by environment variables. Provisioning
renders both from `apiDomain`/`webDomain`; Custody validates the same origin rules
while retaining independent API/Custody key ownership checks.

The 2026-11-06 dual-origin repair regenerates only the ignored unsigned staging
candidate and Custody `RELEASE_POLICY`. The existing single-origin signed artifact
is preserved and fails closed under the new contract. The controller must review
and sign the new canonical bytes with the offline root, rebuild the client, and
coordinate deployment separately. No signing or deployment is part of this repair.
