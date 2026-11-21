-- Custody records a decision only in the same batch as its initial witness.
-- Historic witness heads receive no synthesized admission record.
CREATE TABLE genesis_admissions (
 decision_id TEXT NOT NULL PRIMARY KEY,
 authority_key_id TEXT NOT NULL,
 tenant_id TEXT NOT NULL,
 vault_id TEXT NOT NULL,
 witness_event INTEGER NOT NULL CHECK(witness_event=1),
 witness_digest TEXT NOT NULL,
 attempt_digest TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 UNIQUE (tenant_id,vault_id),
 FOREIGN KEY (tenant_id,vault_id,witness_event) REFERENCES roster_witness(tenant_id,vault_id,event)
);
CREATE TRIGGER genesis_admission_insert BEFORE INSERT ON genesis_admissions BEGIN
 SELECT CASE WHEN NEW.expires_at<=unixepoch() THEN RAISE(ABORT,'genesis_approval_expired') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM genesis_admissions WHERE decision_id=NEW.decision_id OR (tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id)) THEN RAISE(ABORT,'genesis_already_admitted') END;
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM roster_witness WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id AND event=1 AND revision=1 AND sequence=0 AND digest=NEW.witness_digest AND request_digest=NEW.attempt_digest) THEN RAISE(ABORT,'genesis_witness_missing') END;
END;
CREATE TRIGGER genesis_admission_update BEFORE UPDATE ON genesis_admissions BEGIN SELECT RAISE(ABORT,'immutable_genesis_admission'); END;
CREATE TRIGGER genesis_admission_delete BEFORE DELETE ON genesis_admissions BEGIN SELECT RAISE(ABORT,'immutable_genesis_admission'); END;
