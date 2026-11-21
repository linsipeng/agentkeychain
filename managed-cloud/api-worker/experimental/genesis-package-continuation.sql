-- This table is written only by the internal verifier, not by legacy /enroll.
-- Insert and key-package effects are atomic. Old enrollment grants stay immutable.
CREATE TABLE genesis_package_continuations (
 id TEXT PRIMARY KEY,
 request_id TEXT NOT NULL UNIQUE REFERENCES enrollment_grants(id),
 account_id TEXT NOT NULL,
 tenant_id TEXT NOT NULL,
 vault_id TEXT NOT NULL,
 device_id TEXT NOT NULL,
 key_epoch INTEGER NOT NULL,
 old_grant TEXT NOT NULL,
 signed_intent TEXT NOT NULL,
 signed_approval TEXT NOT NULL,
 roster_digest TEXT NOT NULL,
 roster_canonical TEXT NOT NULL,
 roster_signature TEXT NOT NULL,
 witness TEXT NOT NULL,
 package_canonical TEXT NOT NULL,
 package_signature TEXT NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE TRIGGER genesis_package_continuation_admit BEFORE INSERT ON genesis_package_continuations BEGIN
 SELECT CASE WHEN EXISTS(SELECT 1 FROM genesis_package_continuations WHERE id=NEW.id OR request_id=NEW.request_id)
  THEN RAISE(ABORT,'idempotency_conflict') END;
 SELECT CASE WHEN NEW.expires_at<=unixepoch() OR NOT EXISTS(
  SELECT 1 FROM enrollment_grants g
  JOIN device_requests q ON q.id=g.id AND q.account_id=NEW.account_id AND q.tenant_id=g.tenant_id AND q.vault_id=g.vault_id AND q.device_id=g.device_id
  JOIN memberships m ON m.tenant_id=g.tenant_id AND m.account_id=q.account_id AND m.active=1
  JOIN devices d ON d.tenant_id=g.tenant_id AND d.account_id=q.account_id AND d.id=g.device_id AND d.active=1 AND d.public_key=q.signing_key
  JOIN device_keys k ON k.tenant_id=d.tenant_id AND k.device_id=d.id AND k.wrapping_key=q.wrapping_key
  JOIN vault_devices v ON v.tenant_id=g.tenant_id AND v.vault_id=g.vault_id AND v.device_id=d.id AND v.active=1
  JOIN signed_rosters r ON r.tenant_id=g.tenant_id AND r.vault_id=g.vault_id AND r.account_id=q.account_id AND r.revision=1 AND r.digest=NEW.roster_digest AND r.canonical=NEW.roster_canonical AND r.signature=NEW.roster_signature
  JOIN roster_witness_sagas w ON w.tenant_id=r.tenant_id AND w.vault_id=r.vault_id AND w.revision=r.revision AND w.digest=r.digest AND w.state='acknowledged' AND w.receipt=NEW.witness
  WHERE g.id=NEW.request_id AND g.canonical=NEW.old_grant AND g.tenant_id=NEW.tenant_id AND g.vault_id=NEW.vault_id
   AND g.device_id=NEW.device_id AND g.key_epoch=NEW.key_epoch AND g.issuer_device_id IS NULL
   AND q.state IN('approved','delivered') AND q.expires_at<=unixepoch()
   AND json_extract(r.canonical,'$.keyEpoch')=g.key_epoch
   AND json_array_length(r.canonical,'$.active')=1 AND json_array_length(r.canonical,'$.revoked')=0
   AND json_extract(r.canonical,'$.active[0].deviceId')=d.id
   AND json_extract(r.canonical,'$.active[0].signingKey')=q.signing_key
   AND json_extract(r.canonical,'$.active[0].wrappingKey')=q.wrapping_key
   AND NOT EXISTS(SELECT 1 FROM signed_rosters later WHERE later.tenant_id=r.tenant_id AND later.vault_id=r.vault_id AND later.revision>r.revision)
   AND NOT EXISTS(SELECT 1 FROM device_key_packages p WHERE p.tenant_id=g.tenant_id AND p.vault_id=g.vault_id AND p.target_device_id=d.id AND p.key_epoch=g.key_epoch)
 ) THEN RAISE(ABORT,'approval_required') END;
END;
DROP TRIGGER package_expiry;
CREATE TRIGGER package_expiry BEFORE INSERT ON device_key_packages BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM enrollment_grants WHERE id=NEW.grant_id AND json_extract(canonical,'$.expiresAt')>unixepoch())
  AND NOT EXISTS(SELECT 1 FROM genesis_package_continuations c WHERE c.request_id=NEW.grant_id AND c.expires_at>unixepoch()
   AND c.tenant_id=NEW.tenant_id AND c.vault_id=NEW.vault_id AND c.device_id=NEW.target_device_id
   AND c.device_id=NEW.issuer_device_id AND c.key_epoch=NEW.key_epoch
   AND c.package_canonical=NEW.canonical AND c.package_signature=NEW.signature)
 THEN RAISE(ABORT,'not_found') END;
END;
CREATE TRIGGER genesis_package_continuation_apply AFTER INSERT ON genesis_package_continuations BEGIN
 INSERT INTO device_key_packages VALUES(NEW.tenant_id,NEW.vault_id,NEW.device_id,NEW.key_epoch,NEW.device_id,NEW.request_id,NEW.package_canonical,NEW.package_signature);
END;
CREATE TRIGGER genesis_package_continuation_pin BEFORE UPDATE ON genesis_package_continuations BEGIN SELECT RAISE(ABORT,'immutable_continuation'); END;
CREATE TRIGGER genesis_package_continuation_retain BEFORE DELETE ON genesis_package_continuations BEGIN SELECT RAISE(ABORT,'immutable_continuation'); END;
