# Signed dual-origin repair — 2026-11-06

The first-device failure was a client contract mismatch: the signed manifest pinned
only the API origin, while the backend correctly returned browser and verification
URLs at AUTH_ORIGIN (the Web origin).

The manifest now requires both origins in its exact schema, canonical bytes and
signature. A shared validator used by the client, renderer and Custody accepts only
canonical HTTPS origins without credentials/path/query/fragment, with distinct
origins and an API hostname strictly beneath the Web hostname. Empty hostname
labels and same-host/different-port substitutes are rejected. Custody retains all
existing independent signer-purpose and API/Custody ownership checks.

Device transport remains pinned to apiOrigin. Login browserUri and verificationUri,
recovery browser handoff and revoke-device browser navigation use webOrigin.
Synthetic clients and local backend adapters exercise the same distinct roles.
Environment overrides cannot replace either signed origin. Negative tests cover
unsigned substitutions, missing origins, malformed origins, browser/verification
substitution and runtime key-role swaps.

## Local validation

- Root suite: 193 passed, zero failed, including compiled first-device enrollment,
  approval, restart and sync; final focused origin suites: 7 passed.
- Backend: 316 passed; Web: 95 passed.
- Compiled recovery: 49 scenarios passed, including crash/resume and delayed release.
- Root lint; root, backend and Web typechecks; root/native, backend and Web builds passed.
- Generated API bundle, provisioning and five-Worker support bundle passed.
- `git diff --check` passed.
- Initial sandbox test runs could not bind localhost; successful runs used approved
  local test-server access and isolated synthetic stores. No real Vault/Keychain or
  remote services were accessed.
- Built-in Chrome/DevTools was unavailable in this session. No external browser was
  controlled; automated Web and local bundle tests supplied the available coverage.

## Controller handoff

The ignored `managed-cloud/provisioning/generated/release-manifest.unsigned.json`
and `custody-trust-worker.json` RELEASE_POLICY were regenerated from the existing
public pins and configured ingress domains:

- apiOrigin: `https://api.agentkeychain.soupsam.com`
- webOrigin: `https://agentkeychain.soupsam.com`

Verified the candidate equals canonicalManifest byte-for-byte (excluding its file
newline), is unsigned, and matches Custody RELEASE_POLICY exactly. Existing public
pins and key ownership were preserved. The old signed `src/cloud/release.generated.ts`
is unchanged and fails closed because it lacks webOrigin; it must not be edited to
add an unsigned field. The controller must sign the replacement canonical bytes
with the offline root and rebuild/deploy separately. No signing, deployment, commit,
Vault/Keychain access or remote access was performed by this repair.
