-- Explicit cross-D1 saga: local acceptance is pending until Custodian ACK.
CREATE TABLE roster_witness_sagas (
 tenant_id TEXT NOT NULL, vault_id TEXT NOT NULL, revision INTEGER NOT NULL,
 digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','acknowledged')),
 receipt TEXT, PRIMARY KEY(tenant_id,vault_id,revision),
 FOREIGN KEY(tenant_id,vault_id,revision) REFERENCES signed_rosters(tenant_id,vault_id,revision)
);
INSERT INTO roster_witness_sagas SELECT tenant_id,vault_id,revision,digest,'pending',NULL FROM signed_rosters;
CREATE TRIGGER roster_pending_witness AFTER INSERT ON signed_rosters BEGIN
 INSERT INTO roster_witness_sagas VALUES(NEW.tenant_id,NEW.vault_id,NEW.revision,NEW.digest,'pending',NULL);
END;
