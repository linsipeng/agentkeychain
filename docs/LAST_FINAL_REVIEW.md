# Last final-review repair

2026-11-06. The requested local repairs and proportional verification are complete
in the dirty working tree. This record supersedes earlier completeness claims. No commit, deployment, production migration, real
credential retrieval or host secure-store operation is part of this work.

## Exact activation version

`TrustActivationBinding` is constructed canonically from the exact immutable receipt.
It contains case ID, signed receipt version, signed and sealed bundle digests, refresh
credential digest, checkpoint digest/root/key/sequence, witness receipt digest/event/
revision, roster digest/revision, target signing/wrapping keys, key epoch and expiry.
The authority-signed encrypted bundle contains its receipt version. Target signatures
use the v2 activation domain and this entire binding. Main and Custodian reconstruct
and compare all fields before commit; the client reconstructs and compares the same
binding before publishing any recovered secure-store slots or SQLite enrollment.
Existing recovery-intent/journal writes used to request recovery are not activation.

The regression matrix changes every binding field. Backend tests advance a real
checkpoint and independent witness while retaining the roster, obtain a new refresh
credential/version, reject a signature for the substituted old binding on both Main
and Custodian, and confirm zero activation commits. The compiled proxy performs an
actual signed sync operation, obtains a real newer receipt with the same roster and
changed checkpoint/refresh/witness, substitutes the original sealed payload, and
checks that no Custodian activation or local credential-slot publication occurred.
Changed retries conflict; an uncommitted target can obtain a new version after an
independently authorized issuer revocation, with a recovery-authority successor even
when no other issuer has published it. Committed activation history is immutable.

## Last-device safety

Main 0022 counts active issuers per affected vault in the revocation transaction.
A missing, expired, revoked or stale-epoch recovery readiness record aborts the whole
action, preserving device, session, vault and boundary state. The last-device action
has a distinct action digest and explicit “Access will require recovery” confirmation;
the immutable record retains that warning and the selected package. Expiry/revocation
between display and execution is rechecked in the same transaction. Existing packages
are preserved and are not silently assigned readiness during upgrade.

The Web safe view exposes no signing/wrapping keys. It gives a null `removeRef` when
recovery is not ready, explains how to retain access, and shows the stronger warning
before Passkey step-up. Readback distinguishes immediate enforcement from independently
confirmed revocation. Custodian records only separately authorized exact revocation
events, validates package/scope/keys/checkpoint, and fences activation whose roster
still contains an independently revoked device. Recovery must include every such
record. The end-to-end backend test removes the sole device, verifies independent
authorization, uses aged account-attested cooldown recovery, and activates a new target
with a witnessed roster containing the old device's immutable boundary.

## Incremental independent witness

Each request contains at most 128 rosters and 128 checkpoints, including the exact
stored anchors and prior independent receipt. Custodian verifies contiguous revisions,
signatures, checkpoint roots and historical revocation boundaries; its append CAS
advances the independently retained roster/checkpoint heads and signs the receipt.
Bounded checkpoint suffixes are retained to authenticate later revocation boundaries.
Main reads the independent head, requests bounded pages, catches up checkpoints before
rosters, and retries bounded concurrent-head conflicts. Response loss resumes from the
independent anchors. It never copies a Main head into Custodian.

Tests cross 258 roster revisions and 10,001 checkpoints with no full-history request,
reconstruct the witness service between pages, replay lost responses, reject gaps,
forks, stale checkpoints and missing/hidden roster history, and test concurrent writers.
A separate Main pagination test crosses 258 revisions and 260 checkpoints, asserts
page limits and resumes a committed response loss. Recovery no longer requests or
seals the entire roster history: Main selects the latest head, Custodian checks it
against its independent anchor, and the authority seals that head plus a successor
when one is needed. A backend regression refreshes and activates after 258 revisions
with at most two rosters in the bundle. The client requires both the pinned recovery
authority and independent witness for compact delivery; an existing local roster
anchor must still match included evidence, and a missing anchor bridge fails closed.
Current-roster inventory and packet-size limits remain; these are not revision or
checkpoint lifetime ceilings. Genesis remains independently
provisioned. Missing historical upgrade-boundary evidence fails closed; the
[migration runbook](SECURITY_REPAIR_MIGRATION_RUNBOOK.md) retains the independent
upgrade-anchor requirement.

## Acceptance

Root **190 tests / 1,804 assertions / 46 files**, backend **291 tests**, Web
**93 tests**, compiled process **695 assertions**, compiled recovery **52 scenarios**,
and resource diagnostics **8 tests / zero undisposed-resource warnings** passed.
The original gates and assertions were retained. A focused final run additionally
passed **27 tests / 294 assertions** for recovery bindings, long witness histories,
Main pagination and migration preservation. The genuine compiled version-substitution
scenario was rerun against the final source and passed.

Root/backend/Web typechecks, lint, client/native helper/Worker/Web builds, generated
bundle acceptance, whitespace checks and changed-source scans passed. Both Bun audits
and full/runtime npm audits reported zero vulnerabilities. The production binary
contains no tested fault selectors. Windows x86-64 PE compilation and header validation
passed; native Windows execution remains external. Source and artifact digests,
commands and coverage are in [machine-readable evidence](LAST_FINAL_REVIEW_AUDIT.json).
One full backend run encountered the existing cookie lifetime test at a one-second
boundary (43199 instead of 43200); its assertion was unchanged and the complete rerun
passed all 290 tests. The TDD regressions were observed failing before the respective fixes: missing
activation-binding module/acceptance, missing prior-witness enforcement, last-device
revocation succeeding without readiness, and pending revocation refresh returning the
old receipt version. The long-history recovery regression initially returned 258
rosters and now returns at most two. Existing process assertions were preserved when updating the
synthetic witness service to the new migration and head interface.

## External gates

- Independently provisioned production roots, witness/recovery services and exact
  revocation authorization registry; separately reviewed genesis/upgrade anchors.
- Native OS secure-store/service and platform packaging acceptance, including native
  Windows execution. Managed Windows entrypoints remain intentionally fail-closed.
- Built-in Chrome/DevTools and native Passkey acceptance. No supported browser tools
  were available; the disabled external Chrome extension was not changed or used.
- Explicit release/deployment approval and production rollout acceptance.
