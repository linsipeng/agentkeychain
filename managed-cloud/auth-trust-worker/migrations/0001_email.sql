CREATE TABLE email_codes (
 email_hash TEXT NOT NULL, purpose TEXT NOT NULL CHECK(purpose IN ('invitation','recovery')),
 context_digest TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, consumed INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(email_hash,purpose,context_digest)
);
CREATE TABLE email_rates (identity TEXT PRIMARY KEY, window INTEGER NOT NULL, count INTEGER NOT NULL, last_sent INTEGER NOT NULL);
CREATE TABLE email_audit (id INTEGER PRIMARY KEY, event TEXT NOT NULL CHECK(event IN ('requested','verified','rejected')), at INTEGER NOT NULL);
CREATE INDEX email_codes_expiry ON email_codes(expires_at);
CREATE INDEX email_audit_retention ON email_audit(at);
