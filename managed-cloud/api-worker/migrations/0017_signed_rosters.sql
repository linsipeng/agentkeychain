CREATE TABLE signed_rosters (
 tenant_id TEXT NOT NULL, vault_id TEXT NOT NULL, account_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0), digest TEXT NOT NULL, previous_digest TEXT,
 issuer_device_id TEXT, canonical TEXT NOT NULL, signature TEXT NOT NULL,
 PRIMARY KEY(tenant_id,vault_id,revision), UNIQUE(tenant_id,vault_id,digest)
);
CREATE TRIGGER roster_update BEFORE UPDATE ON signed_rosters BEGIN SELECT RAISE(ABORT,'immutable_roster'); END;
CREATE TRIGGER roster_delete BEFORE DELETE ON signed_rosters BEGIN SELECT RAISE(ABORT,'immutable_roster'); END;
CREATE TRIGGER roster_insert BEFORE INSERT ON signed_rosters BEGIN
 SELECT CASE WHEN EXISTS(SELECT 1 FROM signed_rosters WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id AND revision=NEW.revision AND canonical=NEW.canonical AND signature=NEW.signature AND digest=NEW.digest) THEN RAISE(IGNORE) END;
 SELECT CASE WHEN NEW.revision<>COALESCE((SELECT max(revision)+1 FROM signed_rosters WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id),1) OR (NEW.revision>1 AND NOT EXISTS(SELECT 1 FROM signed_rosters WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id AND revision=NEW.revision-1 AND digest=NEW.previous_digest)) THEN RAISE(ABORT,'roster_conflict') END;
 SELECT CASE WHEN NEW.issuer_device_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM devices d JOIN vault_devices v ON v.tenant_id=d.tenant_id AND v.device_id=d.id WHERE d.tenant_id=NEW.tenant_id AND d.account_id=NEW.account_id AND d.id=NEW.issuer_device_id AND v.vault_id=NEW.vault_id AND d.active=1 AND v.active=1) THEN RAISE(ABORT,'revoked') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM json_each(NEW.canonical,'$.active') j LEFT JOIN devices d ON d.tenant_id=NEW.tenant_id AND d.id=json_extract(j.value,'$.deviceId') WHERE d.id IS NULL OR d.active<>1 OR NOT EXISTS(SELECT 1 FROM vault_devices v WHERE v.tenant_id=NEW.tenant_id AND v.vault_id=NEW.vault_id AND v.device_id=d.id AND v.active=1) OR d.public_key<>json_extract(j.value,'$.signingKey')) THEN RAISE(ABORT,'roster_conflict') END;

 SELECT CASE WHEN (SELECT count(*) FROM devices d JOIN vault_devices v ON v.tenant_id=d.tenant_id AND v.device_id=d.id WHERE d.tenant_id=NEW.tenant_id AND d.account_id=NEW.account_id AND v.vault_id=NEW.vault_id)<>json_array_length(NEW.canonical,'$.active')+json_array_length(NEW.canonical,'$.revoked') THEN RAISE(ABORT,'roster_conflict') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM json_each(NEW.canonical,'$.revoked') j LEFT JOIN devices d ON d.tenant_id=NEW.tenant_id AND d.id=json_extract(j.value,'$.deviceId') LEFT JOIN device_revocation_boundaries b ON b.tenant_id=NEW.tenant_id AND b.vault_id=NEW.vault_id AND b.device_id=d.id WHERE d.id IS NULL OR (d.active<>0 AND NOT EXISTS(SELECT 1 FROM vault_devices v WHERE v.tenant_id=NEW.tenant_id AND v.vault_id=NEW.vault_id AND v.device_id=d.id AND v.active=0)) OR b.sequence IS NULL OR b.sequence<>json_extract(json_extract(j.value,'$.acceptedThrough.canonical'),'$.sequence')) THEN RAISE(ABORT,'roster_conflict') END;
 SELECT CASE WHEN NEW.issuer_device_id IS NULL AND NOT EXISTS(SELECT 1 FROM recovery_sagas WHERE id=json_extract(json_extract(NEW.canonical,'$.recovery.canonical'),'$.caseId') AND tenant_id=NEW.tenant_id AND account_id=NEW.account_id AND vault_id=NEW.vault_id AND state='completed') THEN RAISE(ABORT,'approval_required') END;
END;
CREATE TABLE device_revocation_boundaries (
 tenant_id TEXT NOT NULL,vault_id TEXT NOT NULL,device_id TEXT NOT NULL,sequence INTEGER NOT NULL,
 PRIMARY KEY(tenant_id,vault_id,device_id)
);
-- Pre-0017 revocation times are not recoverable. Preserve all accepted history
-- through the vault's migration-time sequence; never infer an earlier boundary.
INSERT INTO device_revocation_boundaries(tenant_id,vault_id,device_id,sequence)
 SELECT v.tenant_id,v.vault_id,v.device_id,c.sequence
 FROM vault_devices v JOIN devices d ON d.tenant_id=v.tenant_id AND d.id=v.device_id
 JOIN vaults c ON c.tenant_id=v.tenant_id AND c.id=v.vault_id
 WHERE d.active=0 OR v.active=0;
CREATE TRIGGER roster_revocation_boundary AFTER UPDATE OF active ON devices WHEN OLD.active=1 AND NEW.active=0 BEGIN
 INSERT OR IGNORE INTO device_revocation_boundaries SELECT v.tenant_id,v.vault_id,v.device_id,c.sequence FROM vault_devices v JOIN vaults c ON c.tenant_id=v.tenant_id AND c.id=v.vault_id WHERE v.tenant_id=NEW.tenant_id AND v.device_id=NEW.id;
END;
CREATE TRIGGER roster_vault_revocation_boundary AFTER UPDATE OF active ON vault_devices WHEN OLD.active=1 AND NEW.active=0 BEGIN
 INSERT OR IGNORE INTO device_revocation_boundaries SELECT NEW.tenant_id,NEW.vault_id,NEW.device_id,sequence FROM vaults WHERE tenant_id=NEW.tenant_id AND id=NEW.vault_id;
END;
CREATE TRIGGER roster_boundary_update BEFORE UPDATE ON device_revocation_boundaries BEGIN SELECT RAISE(ABORT,'immutable_revocation'); END;
CREATE TRIGGER roster_boundary_delete BEFORE DELETE ON device_revocation_boundaries BEGIN SELECT RAISE(ABORT,'immutable_revocation'); END;
CREATE TRIGGER roster_audit AFTER INSERT ON signed_rosters BEGIN INSERT INTO device_audit(event,account_id,tenant_id,device_id,vault_id,sequence) VALUES('checkpoint',NEW.account_id,NEW.tenant_id,NEW.issuer_device_id,NEW.vault_id,NEW.revision); END;
