-- Opt-in pilot storage only. No read/write path is enabled by the standard API.
-- Keep historical staged receipts after ordinary pending-request expiry cleanup;
-- a stage is never token eligibility and does not retain a live FK to that row.
CREATE TABLE pilot_genesis_main_binding_stage (
 tenant_id TEXT PRIMARY KEY, vault_id TEXT NOT NULL, account_id TEXT NOT NULL,
 request_id TEXT NOT NULL UNIQUE, device_id TEXT NOT NULL UNIQUE,
 attempt_digest TEXT NOT NULL UNIQUE, grant TEXT NOT NULL, custody_receipt TEXT NOT NULL,
 staged_at INTEGER NOT NULL DEFAULT(unixepoch())
);
CREATE TRIGGER pilot_genesis_bind_no_replace BEFORE INSERT ON pilot_genesis_main_binding_stage
WHEN EXISTS(SELECT 1 FROM pilot_genesis_main_binding_stage p WHERE p.tenant_id=NEW.tenant_id
 OR p.request_id=NEW.request_id OR p.device_id=NEW.device_id OR p.attempt_digest=NEW.attempt_digest)
BEGIN SELECT RAISE(ABORT,'pilot_genesis_binding_immutable'); END;
CREATE TRIGGER pilot_genesis_bind_no_update BEFORE UPDATE ON pilot_genesis_main_binding_stage
BEGIN SELECT RAISE(ABORT,'pilot_genesis_binding_immutable'); END;
CREATE TRIGGER pilot_genesis_bind_no_delete BEFORE DELETE ON pilot_genesis_main_binding_stage
BEGIN SELECT RAISE(ABORT,'pilot_genesis_binding_immutable'); END;

CREATE VIEW pilot_genesis_main_binding_eligible AS
 SELECT q.id,q.account_id,q.tenant_id,q.vault_id,q.device_id,q.signing_key,q.wrapping_key,q.key_epoch,q.expires_at
 FROM device_requests q JOIN memberships m ON m.tenant_id=q.tenant_id AND m.account_id=q.account_id AND m.active=1
 JOIN vaults v ON v.tenant_id=q.tenant_id AND v.id=q.vault_id
 WHERE q.state='bound' AND q.key_epoch=1 AND q.expires_at>unixepoch() AND v.sequence=0
  AND (SELECT count(*) FROM vaults vv WHERE vv.tenant_id=q.tenant_id)=1
  AND NOT EXISTS(SELECT 1 FROM devices d WHERE d.tenant_id=q.tenant_id OR d.id=q.device_id)
  AND NOT EXISTS(SELECT 1 FROM vault_devices vd WHERE vd.tenant_id=q.tenant_id)
  AND NOT EXISTS(SELECT 1 FROM enrollment_grants g WHERE g.id=q.id OR g.tenant_id=q.tenant_id)
  AND NOT EXISTS(SELECT 1 FROM signed_rosters r WHERE r.tenant_id=q.tenant_id)
  AND NOT EXISTS(SELECT 1 FROM device_revocation_boundaries r WHERE r.tenant_id=q.tenant_id)
  AND NOT EXISTS(SELECT 1 FROM enrollment_retirements r WHERE r.request_id=q.id)
  AND NOT EXISTS(SELECT 1 FROM recovery_sagas s WHERE s.tenant_id=q.tenant_id
     OR json_extract(s.canonical,'$.targetDeviceId')=q.device_id);
