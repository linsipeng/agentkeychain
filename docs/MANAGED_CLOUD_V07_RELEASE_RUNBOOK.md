# Managed Cloud v0.7 production and release runbook

This runbook is preparation, not permission to deploy, publish a release or change cloud credentials. The existing [v0.7 acceptance matrix](MANAGED_CLOUD_V07_ACCEPTANCE.md) still controls product readiness. Production rollout and GitHub Release are additional delivery stages.

## 1. Build and prove the candidate

- Keep one reviewed Git commit as the candidate. Record its tree, required CI, Worker-build evidence, native macOS helper/build evidence, and product and independent security review. Treat missing proof as not passed.
- Exercise the real built service graph with isolated synthetic data. First-device admission must prove independent Auth approval and atomic Custody admission. For an already-approved device, continue the original identity only with a fresh, exact, separately verified authorization. Do not mint a new identity to make activation pass.
- Require both compiled clients to complete onboarding, sync/restart, scope approval and denial, offline retry, revocation, and recovery without exposing credential material. Verify cookie behavior in a disposable real-browser session and keep actual passkey user verification intact.
- Use [the candidate packaging workflow](RELEASE_PACKAGING.md) to produce binaries for supported Darwin and Linux architectures and checksum-verified Darwin secure-store helpers. Verify file architecture, release input manifest, install/upgrade and rollback with isolated home and secure-store fixtures. Do not tag a candidate merely to produce test artifacts: the current repository treats version tags as a release trigger.

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
