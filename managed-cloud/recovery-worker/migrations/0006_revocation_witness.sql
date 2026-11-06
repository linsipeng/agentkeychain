CREATE TABLE recovery_revocation_witness(tenant_id TEXT NOT NULL,vault_id TEXT NOT NULL,device_id TEXT NOT NULL,package_id TEXT NOT NULL,checkpoint TEXT NOT NULL,canonical TEXT NOT NULL,receipt TEXT NOT NULL,PRIMARY KEY(tenant_id,vault_id,device_id));
CREATE TRIGGER recovery_revocation_update BEFORE UPDATE ON recovery_revocation_witness BEGIN SELECT RAISE(ABORT,'immutable_revocation'); END;
CREATE TRIGGER recovery_revocation_delete BEFORE DELETE ON recovery_revocation_witness BEGIN SELECT RAISE(ABORT,'immutable_revocation'); END;
