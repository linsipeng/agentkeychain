-- Independent operator-reviewed trust metadata; no public mutation endpoint.
CREATE TABLE trust_devices(account_id TEXT NOT NULL,tenant_id TEXT NOT NULL,vault_id TEXT NOT NULL,device_id TEXT NOT NULL,signing_key TEXT NOT NULL,revoked INTEGER NOT NULL CHECK(revoked IN(0,1)),expires_at INTEGER NOT NULL,PRIMARY KEY(account_id,tenant_id,vault_id,device_id));
CREATE TABLE trust_accounts(account_id TEXT PRIMARY KEY,public_key TEXT NOT NULL,revoked INTEGER NOT NULL CHECK(revoked IN(0,1)),expires_at INTEGER NOT NULL);
CREATE TABLE trust_revocations(digest TEXT PRIMARY KEY,expires_at INTEGER NOT NULL);
CREATE TABLE trust_authorizations(digest TEXT PRIMARY KEY,evidence TEXT NOT NULL,expires_at INTEGER NOT NULL);
