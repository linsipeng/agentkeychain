CREATE TABLE recovery_trust_requests(case_id TEXT NOT NULL REFERENCES recovery_sagas(id),version INTEGER NOT NULL,request TEXT NOT NULL,result TEXT,PRIMARY KEY(case_id,version));
ALTER TABLE recovery_refresh RENAME TO recovery_refresh_legacy;
CREATE TABLE recovery_refresh_versions(case_id TEXT NOT NULL REFERENCES recovery_sagas(id),version INTEGER NOT NULL,device_id TEXT NOT NULL,digest TEXT NOT NULL UNIQUE,PRIMARY KEY(case_id,version));
INSERT INTO recovery_refresh_versions SELECT case_id,1,device_id,digest FROM recovery_refresh_legacy;
CREATE VIEW recovery_refresh AS SELECT case_id,device_id,digest FROM recovery_refresh_versions f WHERE version=COALESCE((SELECT version FROM recovery_activation WHERE case_id=f.case_id),(SELECT max(version) FROM recovery_refresh_versions WHERE case_id=f.case_id));
CREATE TRIGGER refresh_version_update BEFORE UPDATE ON recovery_refresh_versions BEGIN SELECT RAISE(ABORT,'immutable_refresh'); END;
CREATE TRIGGER refresh_version_delete BEFORE DELETE ON recovery_refresh_versions BEGIN SELECT RAISE(ABORT,'immutable_refresh'); END;
CREATE TABLE recovery_activation(case_id TEXT PRIMARY KEY REFERENCES recovery_sagas(id),version INTEGER NOT NULL,digest TEXT NOT NULL);
CREATE TRIGGER activation_update BEFORE UPDATE ON recovery_activation BEGIN SELECT RAISE(ABORT,'immutable_activation'); END;
CREATE TRIGGER activation_delete BEFORE DELETE ON recovery_activation BEGIN SELECT RAISE(ABORT,'immutable_activation'); END;
-- Reserve an initial recovery roster revision before crossing the D1 boundary.
-- Other writers must retry while the exact recovery saga owns that revision.
CREATE TABLE recovery_roster_reservations(tenant_id TEXT NOT NULL,vault_id TEXT NOT NULL,revision INTEGER NOT NULL,case_id TEXT NOT NULL,PRIMARY KEY(tenant_id,vault_id,revision));
CREATE TRIGGER recovery_roster_reserve BEFORE INSERT ON recovery_roster_reservations BEGIN
 SELECT CASE WHEN EXISTS(SELECT 1 FROM recovery_roster_reservations r WHERE r.tenant_id=NEW.tenant_id AND r.vault_id=NEW.vault_id AND r.revision=NEW.revision AND r.case_id<>NEW.case_id) THEN RAISE(ABORT,'witness_pending') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM signed_rosters r WHERE r.tenant_id=NEW.tenant_id AND r.vault_id=NEW.vault_id AND r.revision=NEW.revision AND COALESCE(json_extract(json_extract(r.canonical,'$.recovery.canonical'),'$.caseId'),'')<>NEW.case_id) THEN RAISE(ABORT,'witness_pending') END;
END;
CREATE TRIGGER recovery_roster_reserved BEFORE INSERT ON signed_rosters BEGIN
 SELECT CASE WHEN EXISTS(SELECT 1 FROM recovery_roster_reservations r WHERE r.tenant_id=NEW.tenant_id AND r.vault_id=NEW.vault_id AND r.revision=NEW.revision AND r.case_id<>COALESCE(json_extract(json_extract(NEW.canonical,'$.recovery.canonical'),'$.caseId'),'')) THEN RAISE(ABORT,'witness_pending') END;
END;
CREATE TRIGGER recovery_reservation_update BEFORE UPDATE ON recovery_roster_reservations BEGIN SELECT RAISE(ABORT,'immutable_reservation'); END;
CREATE TRIGGER recovery_reservation_delete BEFORE DELETE ON recovery_roster_reservations BEGIN SELECT RAISE(ABORT,'immutable_reservation'); END;
CREATE TABLE recovery_trust_superseded(case_id TEXT NOT NULL,version INTEGER NOT NULL,PRIMARY KEY(case_id,version),FOREIGN KEY(case_id,version) REFERENCES recovery_trust_requests(case_id,version));
CREATE TRIGGER trust_superseded_update BEFORE UPDATE ON recovery_trust_superseded BEGIN SELECT RAISE(ABORT,'immutable_trust_history'); END;
CREATE TRIGGER trust_superseded_delete BEFORE DELETE ON recovery_trust_superseded BEGIN SELECT RAISE(ABORT,'immutable_trust_history'); END;
