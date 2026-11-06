# Disposable upgrade and rollback procedure

No production migration, restore, deployment, credential access or key provisioning was
performed for this repair. Treat live migration as a separately authorized operation.

Before an authorized upgrade, stop writers and record the release, applied migration
names, per-vault accepted sequence, device states, pending approvals and recovery saga
states. Export a consistent Main D1 backup and a separate Custodian D1 backup. Retain
checksums and the corresponding schema/migration inventory. Backups contain sensitive
user data and belong in approved encrypted backup storage, never this repository.
Prove restoration on disposable databases before proceeding. Do not copy production
backups into developer tests.

0017 creates exactly one immutable boundary for each device already revoked globally or in the specific
vault membership, even when its global device remains active. Its sequence is the vault's latest accepted sequence at
migration time, including zero for an empty vault. This preserves all previously
accepted history through that conservative boundary. It does **not** claim to recover
the original revocation time or retroactively invalidate already accepted operations.
Later changes to the vault sequence do not move the boundary. New revocations record
the sequence at their transition. The migration must run with writers quiesced.

A migrated first roster includes all historical active and revoked identities and
their exact keys, with `revokedRevision: 1` for pre-roster revocations. Main verifies
its complete registered inventory. The independent Custodian genesis authorization
provider must be provisioned from the separately reviewed migration snapshot; a Main
request is not sufficient to establish that anchor. This is an external provisioning
gate, including empty-vault genesis or the complete signed checkpoint chain for a
nonempty vault. Do not discard revoked identities to make a roster pass validation.

Apply Main 0017–0019 before 0020–0021, and Custodian 0004–0005 before enabling the new
protocol. 0020 retains pending witness acknowledgments; it does not claim cross-D1
atomicity. 0021 retains immutable credential versions and activation commitments.
Custodian history, pending trust intents and receipts are independently durable.
Reconcile pending operations by resending their exact signed inputs. Never set a
witness head from Main, copy Main's sequence over Custodian, or delete a witness row.
Verify foreign keys, boundary counts, retained approvals/recovery states and complete
signed roster acceptance before resuming writers. Then verify the release-pinned
witness receipt and recover/retry a synthetic interrupted saga.

On a failed migration, keep writers stopped. Record which migration actually committed
in each database; a network error is not proof of rollback. Inspect schema and migration
inventory read-only. If only uncommitted transactional work occurred, roll back that
transaction and retry against a disposable restored copy first. For an authorized
restore, restore the paired pre-upgrade backups into isolated replacement databases,
validate the inventory and switch bindings only after acceptance. Never downgrade a
live database by dropping immutable revocations, roster history, receipts or approvals.
If either database accepted post-backup writes, retain it and reconcile/roll forward;
restoring an older backup would lose accepted history and cannot be called safe rollback.

`tests/cloud-migration-upgrade.test.ts` creates/restores in-memory backups at every
0001–0016 prefix, preserves active/revoked devices and approval states, tests a failed
0017–0019 transaction, preserves recovery states, and accepts a complete signed roster.
These fixtures contain generated synthetic values only.

## Last final-review protocol upgrade

Stop writers and back up both databases before Main 0022 and Custodian 0006–0007.
0022 preserves legacy recovery package bytes and creates no readiness records for
them. Re-confirm a package through the two-service enrollment flow before enabling
last-device removal. Readiness expires in 30 days; revocation and expiry are checked
inside the same transaction as device/session enforcement and the warning record.
Provision the independent `rosterRevocation` authorizer with exact, separately
verified action events. It must not accept an event merely because Main supplied it.

0006 preserves independently authorized revocation events and their checkpoint
boundaries. Recovery must carry every such event. 0007 retains bounded checkpoint
suffixes beside existing independent heads. Existing heads remain untouched;
unavailable historical boundary evidence fails closed. The independently reviewed
upgrade snapshot must establish any required historical boundary; do not synthesize
or silently reset a head to make a suffix pass. Validate exact old head equality,
consecutive suffixes, response-loss retries and pending revocation fences on a restored
disposable copy before enabling writers.

Trust activation v2 includes the receipt version inside the authority-signed sealed
bundle and signs the complete binding. Do not mix older activation clients with this
protocol. Preserve committed activation records exactly; resolve any pre-v2 pending
cases under an explicitly reviewed upgrade plan rather than rewriting immutable
receipts. Nothing in these migrations authorizes production deployment or migration.
