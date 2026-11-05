CREATE TABLE checkpoint_key (
 slot INTEGER PRIMARY KEY CHECK(slot=1), key_id TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL
);
CREATE TRIGGER checkpoint_key_update BEFORE UPDATE ON checkpoint_key BEGIN SELECT RAISE(ABORT,'immutable_checkpoint_key'); END;
CREATE TRIGGER checkpoint_key_delete BEFORE DELETE ON checkpoint_key BEGIN SELECT RAISE(ABORT,'immutable_checkpoint_key'); END;
CREATE TRIGGER checkpoint_key_replace BEFORE INSERT ON checkpoint_key WHEN EXISTS(SELECT 1 FROM checkpoint_key WHERE slot=NEW.slot) BEGIN SELECT RAISE(ABORT,'immutable_checkpoint_key'); END;
CREATE TABLE sync_checkpoints (
 tenant_id TEXT NOT NULL, vault_id TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>=0),
 root TEXT NOT NULL, previous_root TEXT, operation_digest TEXT, key_id TEXT NOT NULL REFERENCES checkpoint_key(key_id),
 canonical TEXT NOT NULL, signature TEXT NOT NULL,
 PRIMARY KEY(tenant_id,vault_id,sequence), FOREIGN KEY(tenant_id,vault_id) REFERENCES vaults(tenant_id,id)
);
CREATE TRIGGER sync_checkpoint_accept BEFORE INSERT ON sync_checkpoints BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM vaults WHERE tenant_id=NEW.tenant_id AND id=NEW.vault_id AND sequence=NEW.sequence) THEN RAISE(ABORT,'checkpoint_conflict') END;
 SELECT CASE WHEN NEW.sequence>0 AND NOT EXISTS(SELECT 1 FROM sync_checkpoints WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id AND sequence=NEW.sequence-1 AND root=NEW.previous_root) THEN RAISE(ABORT,'checkpoint_conflict') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM sync_checkpoints WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id AND sequence=NEW.sequence) THEN RAISE(ABORT,'checkpoint_conflict') END;
END;
CREATE TRIGGER sync_checkpoint_update BEFORE UPDATE ON sync_checkpoints BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER sync_checkpoint_delete BEFORE DELETE ON sync_checkpoints BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER sync_checkpoint_audit AFTER INSERT ON sync_checkpoints BEGIN INSERT INTO device_audit(event,tenant_id,vault_id,sequence) VALUES('checkpoint',NEW.tenant_id,NEW.vault_id,NEW.sequence); END;
