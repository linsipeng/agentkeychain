CREATE TABLE web_actions(ref TEXT PRIMARY KEY,account_id TEXT NOT NULL,tenant_id TEXT NOT NULL,kind TEXT NOT NULL,target TEXT NOT NULL,action_digest TEXT NOT NULL,context TEXT,expires_at INTEGER NOT NULL);
CREATE INDEX web_actions_expiry ON web_actions(expires_at);
CREATE TABLE recovery_targets(digest TEXT PRIMARY KEY,target TEXT NOT NULL,expires_at INTEGER NOT NULL);
CREATE TABLE pairing_confirmations(request_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,account_id TEXT NOT NULL,issuer_device_id TEXT NOT NULL,canonical TEXT NOT NULL,signature TEXT NOT NULL);
CREATE TABLE recovery_cancel_confirmations(digest TEXT PRIMARY KEY,case_id TEXT NOT NULL,account_id TEXT NOT NULL,tenant_id TEXT NOT NULL,authorization TEXT NOT NULL,expires_at INTEGER NOT NULL);
