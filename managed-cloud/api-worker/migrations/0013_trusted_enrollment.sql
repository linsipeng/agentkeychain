-- The service stores only a target-sealed, issuer-signed trust bundle. It cannot anchor trust.
CREATE TABLE trusted_enrollment_bundles (
 request_id TEXT PRIMARY KEY REFERENCES enrollment_grants(id),
 tenant_id TEXT NOT NULL, vault_id TEXT NOT NULL, target_device_id TEXT NOT NULL,
 issuer_device_id TEXT NOT NULL, sealed TEXT NOT NULL,
 FOREIGN KEY(tenant_id,vault_id,target_device_id) REFERENCES vault_devices(tenant_id,vault_id,device_id)
);
CREATE TRIGGER trusted_bundle_immutable BEFORE UPDATE ON trusted_enrollment_bundles BEGIN SELECT RAISE(ABORT,'immutable_trust_bundle'); END;
CREATE TRIGGER trusted_bundle_retain BEFORE DELETE ON trusted_enrollment_bundles BEGIN SELECT RAISE(ABORT,'immutable_trust_bundle'); END;
CREATE TRIGGER trusted_bundle_insert BEFORE INSERT ON trusted_enrollment_bundles BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM enrollment_grants g JOIN devices d ON d.tenant_id=g.tenant_id AND d.id=g.issuer_device_id JOIN vault_devices v ON v.tenant_id=g.tenant_id AND v.vault_id=g.vault_id AND v.device_id=g.issuer_device_id JOIN devices t ON t.tenant_id=g.tenant_id AND t.id=g.device_id WHERE g.id=NEW.request_id AND g.tenant_id=NEW.tenant_id AND g.vault_id=NEW.vault_id AND g.device_id=NEW.target_device_id AND g.issuer_device_id=NEW.issuer_device_id AND d.active=1 AND v.active=1 AND t.active=1 AND d.account_id=t.account_id) THEN RAISE(ABORT,'not_found') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM trusted_enrollment_bundles WHERE request_id=NEW.request_id AND sealed<>NEW.sealed) THEN RAISE(ABORT,'idempotency_conflict') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM trusted_enrollment_bundles WHERE request_id=NEW.request_id) THEN RAISE(IGNORE) END;
END;
