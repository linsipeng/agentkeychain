# Managed Cloud: independent first-device approval

Status: proposed design; not implemented, staged or approved for release.
Reviewed base: PR #10, commit `7d808ba72e0475c3dec6f46104842a976b8d9302`.

## What exists and what it proves

- `managed-cloud/shared/trust-runtime.ts:26–35,52–55`: the dedicated API Trust
  RPC verifies the first roster signature and looks up its active device key in
  Main D1. It does not independently verify how the binding was approved. The
  RPC split reduced capability, not the trust required of Main.
- `managed-cloud/api-worker/browser-auth.ts:183–225` and
  `browser-repository.ts:77–114`: Web Step-up binds its challenge to the
  session/account and exact action digest. The browser, challenge state, passkey
  public key, current account/vault mapping and result are still under API/Main.
- `managed-cloud/api-worker/device-repository.ts:63–100` resolves an exact
  enrollment grant; the first grant has no existing device issuer. The browser
  pairing UI ultimately calls that repository (`web-repository.ts:164–170`).
- `managed-cloud/auth-trust-worker/index.ts:1–17`: Auth Trust currently performs
  private email verification and trusted ingress identity, not Passkey
  registration or first-device approval. API Trust's existing recovery account
  attestation checks Main-owned inputs; do not reuse it as a separate trust root.
  The configured Web/RP origin is routed to the API Worker
  (`managed-cloud/provisioning/render.mjs`).
- `managed-cloud/recovery-worker/index.ts:105–113` and
  `managed-cloud/shared/roster-witness.ts:23–55`: Custodian owns the witness
  database and signer. Genesis is the branch where no previous witness exists;
  later exact retries and witness continuity use the persisted Custody record.

Therefore a signed Main assertion, a copied Main WebAuthn row, an email
verification flag, or a second RPC backed by Main cannot establish independent
user approval. A Custody pre-pin can work for an independently administered
bootstrap, but is not the self-service default.

## Recommended trust contract

1. Make the independently administered Auth verifier authoritative for its
   credential enrollment, RP/origin, challenge state, verified account-to-vault
   mapping, and enrollment decisions. Main must not have write access, signing
   keys, or code deployment rights over it. Auth's credential pin is created
   only by its own registration flow after independently established account
   identity; no generic API action may seed or replace that pin.
2. Make the approval interaction run under an independently controlled HTTPS
   origin (or an independently controlled ingress giving Auth exclusive custody
   of the same credential RP and approval surface). Serve the exact action
   summary and CLI pairing phrase from that authority; do not trust a display
   controlled by Main. Resolve the request via an opaque, bounded reference.
   Require fresh user verification and authenticate the new device's signing key
   possession. Bind both to the same canonical enrollment attempt. Browser
   verification remains a user action; it is not automated or bypassed.
3. Auth reserves one decision for the immutable enrollment. The signed,
   canonical, versioned receipt binds: a purpose and audience, authority key
   identity, unique decision ID, account/tenant/vault/device, signing and wrapping
   public keys, original request and exact approved grant digest, intended epoch
   and policy, issuance and expiration. Bind exact genesis roster digest where
   feasible; if approval precedes roster construction, Custody must instead
   enforce a deterministic one-device, one-epoch initial roster constrained by
   the approved grant and policy. No signatures, identity records, or codes go
   to operational logs.
4. Keep Main as a transport and consistency check, never an evidence issuer.
   Custodian verifies the authority from a Custody-controlled pin/policy, validates
   the exact roster and freshness, and atomically binds the decision to the first
   witness insert in Custody D1. Enforce uniqueness of decision ID and of the
   first witness. Same roster/decision and immutable checkpoint with a lost reply
   returns the recorded receipt, including after the unused approval window
   closes; no second decision is consumed. If the window closes before commit,
   prompt only for authorization of the same immutable attempt, keeping local
   device identity and intent; never issue a replacement silently. If Auth
   rotation or revocation is necessary, define admission-time checks explicitly.
5. Keep later-device authorization, recovery, revocation, witness-chain rules
   and signing domains unchanged. First approval is not a general permission
   credential and grants neither rewrap nor recovery authorization.

A locally configured Custody-controlled attester pin minimizes client format
changes. If clients must verify this new evidence, publish a versioned signed
release contract with reviewed key rotation, downgrade and rollback rules.
Do not add unsigned fields to the existing contract or treat fresh custody
configuration as independent if the API operator can edit it.

## Upgrade decision required

Recommended for new enrollments: establish an Auth-operated credential and approval
origin before mandatory genesis admission, then require fresh independent approval
for any **new or unwitnessed** genesis. If keeping the current RP origin, route its
authentication/approval surface to independently operated components and establish
provenance for existing credential pins without trusting a Main export. If assigning
a new RP, existing RP-scoped credentials cannot be reused on an unrelated RP:
plan separately approved enrollment or device-assisted re-anchoring, with a modern
browser/CLI handoff and account recovery that does not rely on Main alone.

Existing verified Custody heads keep continuity; a new policy is not evidence
that an old genesis was independently approved. Treat existing roots as legacy
until reviewed or re-anchored through a separately approved process. Do not erase
Vaults, credential records or witnesses. Do not silently grandfather unwitnessed
pending requests, fill Auth D1 from Main, redefine an existing witness, switch
production origins, or activate an emergency fail-open flag. This design does not
authorize any migration, access changes or deployment.

## Synthetic acceptance criteria

- Approved first device receives a usable witness with a legitimate signed
  roster and independently verified approval. Assert the same request and
  evidence survive transport/response loss and restart; a repeated successful
  request returns the same witness without a second independent authorization.
- The new defense fails closed for absent, expired before initial commit, or
  non-matching approval; separately verify axis-by-axis binding to account,
  tenant, vault, request, device/keys, policy/epoch and issuer. Assert denial
  creates no witness or independent admission.
- Concurrent attempts produce one initial witness; startup without authority
  binding or pin can't admit an unwitnessed vault. Existing recognized heads
  retain the same continuity/revocation gates. Assert malformed but bounded
  inputs do not change rollout state.
- Independently check actual Worker service bindings, isolated D1 account and
  Custody ownership, and scoped deployment permissions, not only TypeScript
  interfaces. Verify a real production bundle under local synthetic fixtures,
  with no real Vault or user credentials. Separately report native and remote
  acceptance when appropriately authorized.

## Isolated verifier slice

`managed-cloud/shared/genesis-approval.ts` implements the exact-roster option
only. Version 1 signs a separate domain and canonical decision containing the
exact signed roster digest and canonical grant digest; these bind request and
identity fields without duplicating them. The verifier checks a separate explicit
Custody pin and configured policy, requires a current first-device grant, and
does not authorize general recovery. The ten-minute approval window is bounded
by the grant expiry. If the grant itself expires before any witness commits,
renewal of the same device attempt requires a separately designed and freshly
approved grant; this slice deliberately does not renew it or bypass expiry.

This verifier is not wired to a Worker ingress, credential source, storage, or
production call path. Integration requires independent Auth issuance after
registration and approval, proof transport pinned to the authenticated session,
Custody runtime pin provisioning, and one atomic database transaction for
first witness plus admission consumption. A caller receiving a valid result
from this verifier must not assume consumption occurred.
