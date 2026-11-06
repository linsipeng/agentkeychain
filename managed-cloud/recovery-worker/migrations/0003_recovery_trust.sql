CREATE TABLE recovery_trust_receipts(case_id TEXT PRIMARY KEY REFERENCES recovery_sagas(id), request_digest TEXT NOT NULL, result TEXT NOT NULL);
CREATE TRIGGER recovery_trust_update BEFORE UPDATE ON recovery_trust_receipts BEGIN SELECT RAISE(ABORT,'immutable_trust'); END;
CREATE TRIGGER recovery_trust_delete BEFORE DELETE ON recovery_trust_receipts BEGIN SELECT RAISE(ABORT,'immutable_trust'); END;
