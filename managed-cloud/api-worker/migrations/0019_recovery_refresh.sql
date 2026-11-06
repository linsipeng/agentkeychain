CREATE TABLE recovery_refresh(case_id TEXT PRIMARY KEY REFERENCES recovery_sagas(id),device_id TEXT NOT NULL UNIQUE,digest TEXT NOT NULL UNIQUE);
CREATE TRIGGER recovery_refresh_update BEFORE UPDATE ON recovery_refresh BEGIN SELECT RAISE(ABORT,'immutable_refresh'); END;
CREATE TRIGGER recovery_refresh_delete BEFORE DELETE ON recovery_refresh BEGIN SELECT RAISE(ABORT,'immutable_refresh'); END;
