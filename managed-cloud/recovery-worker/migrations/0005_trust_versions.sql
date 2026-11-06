CREATE TABLE recovery_trust_versions(case_id TEXT NOT NULL REFERENCES recovery_sagas(id),version INTEGER NOT NULL,request_digest TEXT NOT NULL,result TEXT NOT NULL,PRIMARY KEY(case_id,version));
INSERT INTO recovery_trust_versions SELECT case_id,1,request_digest,result FROM recovery_trust_receipts;
CREATE TRIGGER trust_version_insert BEFORE INSERT ON recovery_trust_versions BEGIN
 SELECT CASE WHEN EXISTS(SELECT 1 FROM recovery_trust_versions WHERE case_id=NEW.case_id AND version=NEW.version AND request_digest=NEW.request_digest) THEN RAISE(IGNORE) END;
 SELECT CASE WHEN NEW.version<=COALESCE((SELECT max(version) FROM recovery_trust_versions WHERE case_id=NEW.case_id),0) THEN RAISE(ABORT,'idempotency_conflict') END;
END;
CREATE TRIGGER trust_version_update BEFORE UPDATE ON recovery_trust_versions BEGIN SELECT RAISE(ABORT,'immutable_trust'); END;
CREATE TRIGGER trust_version_delete BEFORE DELETE ON recovery_trust_versions BEGIN SELECT RAISE(ABORT,'immutable_trust'); END;
CREATE TABLE recovery_trust_commits(case_id TEXT PRIMARY KEY REFERENCES recovery_sagas(id),version INTEGER NOT NULL,digest TEXT NOT NULL,signature TEXT NOT NULL);
CREATE TRIGGER trust_commit_update BEFORE UPDATE ON recovery_trust_commits BEGIN SELECT RAISE(ABORT,'immutable_activation'); END;
CREATE TRIGGER trust_commit_delete BEFORE DELETE ON recovery_trust_commits BEGIN SELECT RAISE(ABORT,'immutable_activation'); END;
CREATE TRIGGER trust_version_committed BEFORE INSERT ON recovery_trust_versions WHEN EXISTS(SELECT 1 FROM recovery_trust_commits WHERE case_id=NEW.case_id) BEGIN SELECT RAISE(ABORT,'activation_committed'); END;
CREATE TABLE recovery_trust_intents(case_id TEXT NOT NULL REFERENCES recovery_sagas(id),version INTEGER NOT NULL,request_digest TEXT NOT NULL,PRIMARY KEY(case_id,version));
CREATE TRIGGER trust_intent_update BEFORE UPDATE ON recovery_trust_intents BEGIN SELECT RAISE(ABORT,'immutable_trust_intent'); END;
CREATE TRIGGER trust_intent_delete BEFORE DELETE ON recovery_trust_intents BEGIN SELECT RAISE(ABORT,'immutable_trust_intent'); END;
