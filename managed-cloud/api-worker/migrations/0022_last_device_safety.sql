-- Readiness is time bounded and rechecked inside the revocation transaction.
-- Existing packages are deliberately not grandfathered into destructive readiness.
CREATE TABLE recovery_readiness(package_id TEXT PRIMARY KEY REFERENCES recovery_packages_v1(id),valid_until INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1)));
CREATE VIEW last_device_vaults AS
 SELECT d.tenant_id,d.account_id,d.id device_id,v.vault_id,
 (SELECT p.id FROM recovery_packages_v1 p JOIN recovery_readiness r ON r.package_id=p.id
 WHERE p.tenant_id=d.tenant_id AND p.account_id=d.account_id AND p.vault_id=v.vault_id AND p.ready=1 AND r.revoked=0 AND r.valid_until>unixepoch()
 AND p.key_epoch=(SELECT max(key_epoch) FROM recovery_packages_v1 WHERE tenant_id=d.tenant_id AND vault_id=v.vault_id)
 AND p.key_epoch>=COALESCE((SELECT max(key_epoch) FROM device_key_packages WHERE tenant_id=d.tenant_id AND vault_id=v.vault_id),1)) package_id
 FROM devices d JOIN vault_devices v ON v.tenant_id=d.tenant_id AND v.device_id=d.id
 WHERE d.active=1 AND v.active=1 AND NOT EXISTS(SELECT 1 FROM devices other JOIN vault_devices ov ON ov.tenant_id=other.tenant_id AND ov.device_id=other.id WHERE ov.tenant_id=v.tenant_id AND ov.vault_id=v.vault_id AND ov.active=1 AND other.active=1 AND other.id<>d.id);
CREATE TABLE last_device_revocations(action_id TEXT NOT NULL REFERENCES device_actions(id),vault_id TEXT NOT NULL,package_id TEXT NOT NULL,warning TEXT NOT NULL,PRIMARY KEY(action_id,vault_id));
CREATE TRIGGER last_device_guard BEFORE INSERT ON device_actions WHEN NEW.action='revoke' BEGIN
 SELECT CASE WHEN EXISTS(SELECT 1 FROM last_device_vaults WHERE tenant_id=NEW.tenant_id AND device_id=NEW.target AND package_id IS NULL) THEN RAISE(ABORT,'recovery_required') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM last_device_vaults WHERE tenant_id=NEW.tenant_id AND device_id=NEW.target) AND COALESCE(json_extract(NEW.canonical,'$[5]'),'')<>'Access will require recovery' THEN RAISE(ABORT,'approval_required') END;
 INSERT INTO last_device_revocations SELECT NEW.id,vault_id,package_id,'Access will require recovery' FROM last_device_vaults WHERE tenant_id=NEW.tenant_id AND device_id=NEW.target;
END;
CREATE TRIGGER last_device_record_update BEFORE UPDATE ON last_device_revocations BEGIN SELECT RAISE(ABORT,'immutable_revocation'); END;
CREATE TRIGGER last_device_record_delete BEFORE DELETE ON last_device_revocations BEGIN SELECT RAISE(ABORT,'immutable_revocation'); END;
CREATE TRIGGER trust_request_pin BEFORE UPDATE ON recovery_trust_requests WHEN NEW.case_id<>OLD.case_id OR NEW.version<>OLD.version OR NEW.request<>OLD.request OR (OLD.result IS NOT NULL AND (NEW.result IS NULL OR NEW.result<>OLD.result)) BEGIN SELECT RAISE(ABORT,'immutable_trust'); END;
CREATE TRIGGER trust_request_delete BEFORE DELETE ON recovery_trust_requests BEGIN SELECT RAISE(ABORT,'immutable_trust'); END;
