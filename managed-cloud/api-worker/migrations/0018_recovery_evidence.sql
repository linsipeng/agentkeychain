CREATE TABLE recovery_authorizations(case_id TEXT PRIMARY KEY REFERENCES recovery_sagas(id), evidence TEXT NOT NULL);
