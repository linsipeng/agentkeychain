-- Deliberately metadata only. No key shares or release capability in Phase 2A.
CREATE TABLE custodian_cases (
  tenant_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending','cancelled')),
  PRIMARY KEY(tenant_id,vault_id,id)
);
CREATE TABLE release_evidence (
  tenant_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  evidence_digest TEXT NOT NULL,
  PRIMARY KEY(tenant_id,vault_id,case_id,event_id),
  FOREIGN KEY(tenant_id,vault_id,case_id) REFERENCES custodian_cases(tenant_id,vault_id,id)
);
CREATE TRIGGER evidence_no_update BEFORE UPDATE ON release_evidence BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER evidence_no_delete BEFORE DELETE ON release_evidence BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER evidence_no_replace BEFORE INSERT ON release_evidence WHEN EXISTS(SELECT 1
  FROM release_evidence
  WHERE tenant_id=NEW.tenant_id
  AND vault_id=NEW.vault_id
  AND case_id=NEW.case_id
  AND event_id=NEW.event_id)
  BEGIN
  SELECT RAISE(ABORT,'append_only');
  END;
