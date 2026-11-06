-- Custodian-owned append-only witness log. Main has no binding to this database.
CREATE TABLE roster_witness (
 tenant_id TEXT NOT NULL, vault_id TEXT NOT NULL, event INTEGER NOT NULL,
 revision INTEGER NOT NULL, digest TEXT NOT NULL, sequence INTEGER NOT NULL, root TEXT NOT NULL,
 request_digest TEXT NOT NULL, roster TEXT NOT NULL, checkpoint TEXT NOT NULL, receipt TEXT NOT NULL,
 PRIMARY KEY(tenant_id,vault_id,event)
);
CREATE TRIGGER witness_insert BEFORE INSERT ON roster_witness BEGIN
 SELECT CASE WHEN NEW.event<>COALESCE((SELECT max(event)+1 FROM roster_witness WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id),1) THEN RAISE(ABORT,'witness_conflict') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM roster_witness WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id AND (revision>NEW.revision OR sequence>NEW.sequence OR (revision=NEW.revision AND digest<>NEW.digest) OR (sequence=NEW.sequence AND root<>NEW.root))) THEN RAISE(ABORT,'witness_rollback') END;
END;
CREATE TRIGGER witness_update BEFORE UPDATE ON roster_witness BEGIN SELECT RAISE(ABORT,'immutable_witness'); END;
CREATE TRIGGER witness_delete BEFORE DELETE ON roster_witness BEGIN SELECT RAISE(ABORT,'immutable_witness'); END;
