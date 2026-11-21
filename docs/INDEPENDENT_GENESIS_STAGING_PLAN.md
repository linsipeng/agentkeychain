# AgentKeychain v0.7: disposable independent-genesis staging

Review base: `c70306cfb0446f1550587a64fcd8bf161ed031bf`. This is a staged
provisioning and acceptance plan, not a generated Wrangler configuration or
authorization to touch Cloudflare. No target account, zone, domain, credential,
or signed release is assumed. Every account, database, key and browser identity
used here is disposable and distinct from production.

## Decision and honest status

Private Worker Service Binding RPC is same-account only:
[Cloudflare RPC](https://developers.cloudflare.com/workers/runtime-apis/rpc/).
The existing Miniflare fixture independently verifies Auth and Custody data and
signatures, but it does not prove separate Cloudflare account control. Shared
super-admin, team-wide deployment credentials, or the ability to replace bindings
are common control roots even when there are multiple workers and databases.

Use two stages, with different claims:

- **Disposable staging A:** one new nonproduction account/namespace for the
  current private RPC topology, named narrowly scoped role owners, and synthetic
  accounts only. This proves product flow, origin handling, persistence, and
  per-worker runtime isolation. Do not call it independent operator or account
  acceptance. An account super-admin exists and must remain out of application
  CI. Cloudflare states editing a Worker with a resource binding does not
  necessarily require direct permission to that resource; denying direct D1
  access while permitting arbitrary deployments/binding changes is not proof
  against indirect access. See [Workers roles and permissions](https://developers.cloudflare.com/workers/authorization/workers/).
- **Independent staging B:** separate control domains, with no shared owner or
  deploy principal who can change Auth proof issuance and Custody's verifier/pin.
  Prefer separately administered accounts; explicitly review every cross-account
  API/Auth/Custody edge. Private service bindings cannot cross this boundary.
  A reviewed service-authenticated transport must precede remote provisioning; it
  must retain strict method/body limits, scoped routing, pinned peers, the exact
  signed envelope end-to-end, and closed general HTTP. An exact approval is
  evidence, not transport authorization. Naming a separate DB or staging token
  does not solve this. Do not render account-B Wrangler files for the existing
  RPC graph.

The real Auth-managed Passkey registration, scoped session/approval HTTP and
device handoff are not wired at this revision. `tests/genesis-transport-fixture.ts`
uses a synthetic Auth front door and runtime-scoped fixtures to exercise the
experimental issuer plus readback. The normal `auth-trust-worker/index.ts`
is not that ingress. No deployable config should point production traffic at a
fixture, or claim that independently authorized onboarding works for users yet.

## Required ownership inputs (metadata only)

1. Staging account and zone chosen by Sam; reviewed owner/team for API
   deployment, Auth verifier/approval origin and Auth D1, and Custody verifier,
   witness signer and Custody D1. Include whether an independent second account
   and administrator are available, and document any shared break-glass admin.
   Use private review material for account/resource IDs. Never send tokens or
   operator recovery credentials by chat.
2. One fresh staging hostname triplet: site, API, independent Auth. DNS/zone
   owner separately approves route creation. An unrelated new Auth origin and
   RP do not inherit Main Passkeys. Stage only new synthetic registrations;
   don't copy credential records, counters, browser sessions or user data.
3. Stage-specific offline release root and bound public keys only: API
   checkpoint/release, Custody witness/recovery/release, separate Auth approval
   attester. Approval key ownership is Auth; accepted public pin ownership is
   Custody. Provision exact key ID and public key to Custody after offline review
   plus out-of-band fingerprint comparison. The app, Main D1 and API deployer
   cannot provide or override it.
4. Pin evidence: verify the current versioned signed release artifact against
   the separately held staging root. For the extra approval key, use a
   separately signed and reviewed staging deployment descriptor (proposed,
   not the current client manifest): scope/design version, exact staging
   account identifiers and origins, release/artifact digest, pin role/key
   ID/public key, validity, and intended operator. Custody checks the
   descriptor out of band and provisions the exact JSON
   `{keyId,publicKey}` to `GENESIS_APPROVAL_PIN`. Current code does not
   understand that descriptor; it reads the operator-configured pin. Don't add
   unsigned keys to the existing release artifact, copy a production root or
   claim the app verifies the new descriptor. Require a key rotation and
   rollback plan before crossing into real acceptance.
5. Auth/Custody credentials are entered by the designated owners through their
   own secure control plane or user-approved credential store. Use narrowly
   scoped, short-lived bootstrap access for approved resource creation, then
   individual-Worker deploy privileges. Verify no API deploy principal can
   replace Auth or Custody code, route, secret, or binding; verify resource
   authorizations and owners independently. No ambient account token or
   fixture private key in a manifest, source, CI logs, artifact, or caller input.

## Exact application bindings and policy

- Main/API has only its Main D1 and its pre-existing log/recovery dependencies.
  No Auth D1 or Custody D1 handle, approval secret, approval pin authority, or
  direct first-witness write capability. Main may eventually relay opaque,
  tightly scoped signed evidence via the approved transport; it does not
  authenticate email/Passkey state to Auth or decide whether evidence is valid.
- Auth ingress needs its own browser RP/origin, independently registered
  credentials, verified account/tenant/vault mapping, own Auth D1, and
  approval-signing authority. It must serve the exact displayed decision
  details, perform WebAuthn verification, enforce scoped readback and CSRF,
  and return the proof only under its own current session exact-intent grant.
  Main cannot seed Auth pins. Existing email/source services are not a source of
  independent approval.
- The trusted staging transport has one narrow
  `GenesisAdmission.admit({proof,grant,roster,checkpoint})` capability.
  The target uses only the private Custody entrypoint (closed HTTP), Custody
  D1, scoped witness signer and exact recovery policy. No general recovery
  authority is granted to this caller. The approval proof is not a recovery
  credential. A signed checkpoint zero and one-device genesis roster still
  require their own exact verification.
- Custody's admission owner controls `GENESIS_APPROVAL_PIN` and
  `GENESIS_ADMISSION_MODE=independent-v1`. No Auth key or private key belongs
  in Custody app configuration. Do not activate until the normal Auth ingress
  and transport pass acceptance; coordinate both mode/pin and removal of the
  old `GENESIS_AUTH` binding in the *independent* graph. Any partial independent
  configuration must refuse unwitnessed legacy admission; never restore that
  fallback just to recover an outage. Existing witnessed heads are preserved.

## Execution gates

1. Offline: review the code SHA, artifact digest, route and database matrix,
   separate ownership, exact public pin descriptors and named reviewers.
   Compile actual worker bundles and rerun
   `npm run test:support-bundle --prefix managed-cloud` in an isolated shell.
   Local success demonstrates neither a live gateway nor account ownership.
2. Before any remote action, obtain separate concrete approval for the
   disposable account/zone, resources, origin names, test identities and
   approved deployment principals. Rotation, IAM changes, DNS changes,
   provisioning, external communication and deployment have their own action
   boundaries. The recommendation is to start from fresh staging resources,
   not to repurpose production's linked account, domains, D1, release root,
   vault, credentials or screenshots.
3. Remote staging acceptance once approved: prove independent browser
   registration/approval and existing-state isolation; use test accounts and
   synthetic Vault only. Exercise pending and approved retry, lost response
   before and after commit, expired unused grants, restart, second device,
   encrypted sync, recovery and revocation. Record new and retained witness
   identities as redacted digests. A legacy prior witness may continue; a fresh
   unwitnessed genesis must not fall back under incomplete configuration.
4. Pause on a misbound service, unmatched pin, unavailable Auth, or unclear
   admin ownership. Do not weaken approval / expose services to recover.
   Preserve signed receipts/witnesses and report sanitized evidence. Prefer
   pausing new staging enrollment rather than rolling back through a legacy
   admission mode. No production migration or release is covered by this plan.

**Next decision:** Which disposable Cloudflare account/zone may be used, who
controls Auth and Custody there, and is the goal staging A (functional rehearsal)
or staging B (independent account acceptance)? Recommend staging A first while
implementing and reviewing the production Auth ingress and cross-account
transport; both are prerequisites before claiming staging B or production
independence.

## Continuation configuration preview

`managed-cloud/provisioning/continuation-preview.ts` accepts a signed synthetic
release and separately signed, purpose-bound appendices for Auth approval,
Main commit evidence and the rollout role. It takes the trusted *public* root
separately. It rejects non-fixture origins, wrong/missing signatures, wrong
appendix purposes and signer reuse. Output is a review matrix only: no
Wrangler config, account/resource identifiers, open route, private key, or
signed runtime rollout permit. It does not activate an installed client.

```sh
node --experimental-transform-types --test managed-cloud/tests/continuation-preview.test.mjs
```

Hosting a disposable HTTPS rehearsal in an existing account is an option only
if Sam explicitly names the owned account/zone, confirms isolated fresh
staging resources, and approves the exact role owners and changes. That
rehearsal demonstrates functional routing, not independent control if the
account shares a super-admin. The current synthetic client gate deliberately
rejects hosted origins; real Auth ingress, trusted transport and a separately
reviewed installed-client staging policy are prerequisites. Cross-account
acceptance additionally needs a reviewed authenticated transport across the
account boundary. Do not change hostnames to evade a synthetic guard.
