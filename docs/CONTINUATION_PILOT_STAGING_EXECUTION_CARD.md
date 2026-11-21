# Continuation pilot: disposable hosted staging execution card

Offline review only. This card is not deployment authority or proof of account ownership. A same-account pilot can exercise product behavior and binding isolation, not prove that administrators are independent.

## Prepare the review packet offline

- Record the candidate commit, artifact and bundle digests, target, signed installation and expiry, and separate public Auth approval, Main commit and Custody witness pins. Keep control-plane identifiers and operator names in a private packet. Never include tokens, private keys, cookies, passkey assertions, or Vault data.
- Name one disposable account and zone and a unique 4–24 character lowercase namespace (letters, digits, single hyphens between segments). Derive `https://web-pilot-<namespace>.<zone>`, `https://api.web-pilot-<namespace>.<zone>`, and `https://auth-pilot-<namespace>.<zone>`. Bind the WebAuthn RP ID to the exact Auth host. Do not reuse a production origin or a shared preview domain.
- List three fresh distinct D1 databases and Workers named `akc-pilot-<namespace>-<role>`. Verify account/zone authority and absence of name/route collisions before provisioning. Compare actual fresh D1 IDs with the independently maintained protected inventory before signing the target. Record migration files, hashes, order, and both clean and upgrade-shaped rehearsals.
- Preserve role boundaries. Auth owns registration/approval and only the `PilotCustodyReadiness` Custody binding; Main owns commit/readback and only `PilotCustodyFresh` and `PilotCustodyPost` bindings. Custody owns admission and live witness and has no public route or generic signer. Record who can deploy, rebind, or inject keys into each role.

Use [the reviewed target renderer](../managed-cloud/provisioning/continuation-pilot-review.ts) to verify the signed target's installation, expiry, origins, database exclusions, and role projections. It deliberately emits `ownershipVerified: false`, `deployable: false`, and `ingress: unbound`; public previews and `workers.dev` are disabled. Do not deploy those fragments. Finalize the signed target only after verifying ownership and exact fresh D1 IDs.

## Ask once when the runtime is ready

First review the actual hosted entrypoints, Auth bootstrap, independent Custody admission, route allowlist, separately scoped installed-client policy, and rollback. Rehearse the built graph and teardown with disposable data. Do not rename a fixture host to bypass installed-client guards.

Then ask the owner for one concrete scope authorization: the named disposable account and zone; creation and teardown of three named Workers and three fresh D1 databases, and the exact new HTTPS hosts; fixed candidate commit, synthetic data only, and no existing resources touched. Use a secure control-plane handoff if access is missing, never chat credentials. Prior staging cleanup approval does not carry forward. Stop for changed target, access, affected resources, or rollback scope.

## Verify and close

1. Verify deployed digests, HTTPS/RP, role bindings, migration versions and absent public Custody ingress. Physical passkey registration and explicit approval of the displayed action are separate ceremonies. Present each only when the exact isolated Auth page is ready; do not automate user verification or reuse production sessions.
2. From the isolated installed candidate verify first-device admission, original-device continuation, lost-response recovery, restart, sync, revocation, and recovery with fresh Custody proof. Report pass/fail/not run tied to exact SHA/digests. Browser-only success proves neither installed activation nor independent admin control.
3. On failure or expiry, disable pilot ingress and enrollment first. Preserve only redacted evidence. Revoke pilot access and remove only authorized disposable routes, Workers, and databases; verify the routes no longer serve, and existing resources are unchanged. Do not restore a legacy approval path.

Apple Developer ID signing and notarization, public asset signing, GitHub publication, and production changes are separate gates. Do not request those to run the hosted browser pilot. See [independent genesis staging](INDEPENDENT_GENESIS_STAGING_PLAN.md), [release runbook](MANAGED_CLOUD_V07_RELEASE_RUNBOOK.md), and [release packaging](RELEASE_PACKAGING.md).
