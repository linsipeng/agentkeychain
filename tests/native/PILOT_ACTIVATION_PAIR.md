# Pilot-only activation pairing (inert model)

Current `finalizeGenesisContinuationLocked` reads the protected continuation
intent, obtains fresh Custody post-commit proof, calls `RosterStore.initialize`
and `CloudStore.checkAnchor`, and writes enrollment/cursor/marker in a SQLite
transaction. The last step deletes `enrollment-intent`; the normal runtime
uses its absence as one gate. The SQLite marker includes only `stageDigest`.
There is no positive, retained, independently protected activation receipt.
The expiring SQLite enrollment row lease is also not the protected native
broker's real process lease. Neither an old marker nor an absent intent can
be interpreted as the new receipt.

The proposed gate is only for a separate pilot profile, before any "active"
return or pilot runtime open. Never change the ordinary Vault or historical
grant/approval timestamps. Use one exclusive verified native lease for all
reads and local CAS effects. Observe and act in this order:

1. Verify immutable pilot install/profile/device and the exact historical
   intent, existing stored package and signed roster. Derive versioned,
   domain-separated digests: `profileDigest` over the verified install/profile
   identity, `stageDigest` over exact validated protected continuation bytes,
   `commitDigest` over the exact enrollment/cursor/roster/pins/completion
   projection, and `slotDigest` over the independently observed native key
   identities, protected roster reference and genesis anchor. Never export
   secret bytes as receipt fields, accept caller digests as observations, or
   equate read failure with absence. A real adapter must derive the common
   basis from authenticated typed data, not accept a third identical copy.
2. Establish exact native `prepared` with CAS from the same authenticated
   intent, including the expected anchor and roster under protection. It is
   not active. Do not adopt extra/foreign material from either store. SQLite
   `empty` means precisely no activation projection, not merely no marker;
   preexisting partial roster/anchor state from today's implementation must
   deny unless a later exact migration handles it. Move pilot DB roster/pins
   writes into the single local commit, not today's earlier implicit write.
3. Recheck the fenced, live nonce-bound Custody proof/rollout; transactionally
   commit the exact DB projection and positive immutable receipt together;
   re-read an authenticated projection and verify receipt equality from
   committed storage. If intent is prepared but exact DB commit exists,
   never repeat or reseal it. If a live reread cannot be obtained under
   current lifetime limits, leave it pending; do not refresh/rewrite the
   original grant, infer historical freshness or delete any intent.
4. With the same lease and current verification, CAS that exact protected
   `prepared` record to `finalized`, retaining a positive receipt rather
   than deleting it. Read both stores again (same lease, exact expected
   profile and basis) before returning the local-active-recorded result (not runtime authorization). A replay with two already
   finalized equal records may report the completed **local** activation
   idempotently; subsequent trust/revocation checks remain separate.
5. Missing, unreadable, replaced, foreign, or divergent state is closed.
   Never recreate the other half from a finalized receipt. A native
   durable intent/finalized receipt and DB receipt need actual installed
   adapter tests, including resource-loss or rewind and CAS/crash cuts.
   This model assumes trusted fenced observations and does not protect
   against restoring both independent stores as one coordinated rollback.

The test-only reducer names the two allowed recovery actions; it never performs
them, grants authorization, opens an active Vault, or bypasses proof expiry.
