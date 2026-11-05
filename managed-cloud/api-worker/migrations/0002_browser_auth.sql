-- Additive: Phase 2A account rows and device authentication remain unchanged.
CREATE TABLE account_emails (
 account_id TEXT PRIMARY KEY REFERENCES accounts(id),
 encrypted_email TEXT NOT NULL, lookup_hash TEXT NOT NULL UNIQUE,
 verified INTEGER NOT NULL CHECK(verified=1)
);
CREATE TABLE invitations (
 digest TEXT PRIMARY KEY, email_lookup TEXT NOT NULL,
 expires_at INTEGER NOT NULL, consumed_at INTEGER
);
CREATE TABLE account_verifications (
 id TEXT PRIMARY KEY, invitation_digest TEXT NOT NULL REFERENCES invitations(digest),
 session_digest TEXT NOT NULL, email_lookup TEXT NOT NULL, encrypted_email TEXT NOT NULL,
 expires_at INTEGER NOT NULL, consumed_at INTEGER
);
CREATE TABLE passkeys (
 id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
 public_key TEXT NOT NULL, counter INTEGER NOT NULL CHECK(counter BETWEEN 0 AND 4294967295),
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN(0,1))
);
CREATE TABLE browser_sessions (
 digest TEXT PRIMARY KEY, csrf_digest TEXT NOT NULL, account_id TEXT NOT NULL,
 tenant_id TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT(unixepoch()),
 last_seen INTEGER NOT NULL DEFAULT(unixepoch()), absolute_expires INTEGER NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1)),
 step_up_digest TEXT, step_up_expires INTEGER,
 FOREIGN KEY(tenant_id,account_id) REFERENCES memberships(tenant_id,account_id)
);
CREATE TABLE consumed_bootstraps (digest TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
CREATE TABLE webauthn_challenges (
 id TEXT PRIMARY KEY, challenge_digest TEXT NOT NULL,
 purpose TEXT NOT NULL CHECK(purpose IN('registration','authentication','step-up','recovery')),
 session_digest TEXT NOT NULL, identity_hash TEXT NOT NULL, account_id TEXT REFERENCES accounts(id),
 verification_id TEXT REFERENCES account_verifications(id), request_digest TEXT NOT NULL,
 auth_expires INTEGER NOT NULL,
 expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
 consumed_at INTEGER
);
CREATE INDEX challenge_expiry ON webauthn_challenges(expires_at);
CREATE TABLE auth_rate_windows (
 kind TEXT NOT NULL CHECK(kind IN('source','identity')), digest TEXT NOT NULL,
 window INTEGER NOT NULL, hits INTEGER NOT NULL CHECK(hits BETWEEN 1 AND 1001),
 PRIMARY KEY(kind,digest,window)
);
CREATE INDEX rate_expiry ON auth_rate_windows(window);
CREATE TABLE auth_audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 event TEXT NOT NULL CHECK(event IN('registered','authenticated','step_up','logout','counter_risk','privilege_revoked','rejected')),
 created_at INTEGER NOT NULL DEFAULT(unixepoch())
);
CREATE TRIGGER auth_audit_no_update BEFORE UPDATE ON auth_audit BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER auth_audit_no_delete BEFORE DELETE ON auth_audit BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER auth_audit_no_replace BEFORE INSERT ON auth_audit WHEN EXISTS(SELECT 1 FROM auth_audit WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER passkey_pin BEFORE UPDATE OF id,account_id,public_key ON passkeys BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER passkey_retain BEFORE DELETE ON passkeys BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER passkey_no_replace BEFORE INSERT ON passkeys WHEN EXISTS(SELECT 1 FROM passkeys WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER browser_session_pin BEFORE UPDATE OF digest,csrf_digest,account_id,tenant_id,created_at,absolute_expires ON browser_sessions BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER browser_session_no_replace BEFORE INSERT ON browser_sessions WHEN EXISTS(SELECT 1 FROM browser_sessions WHERE digest=NEW.digest) BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER browser_session_no_unrevoke BEFORE UPDATE OF revoked ON browser_sessions WHEN OLD.revoked=1 AND NEW.revoked<>1 BEGIN SELECT RAISE(ABORT,'revoked'); END;
CREATE TRIGGER privilege_browser_revoke AFTER UPDATE OF active ON memberships WHEN OLD.active<>NEW.active BEGIN
 UPDATE browser_sessions SET revoked=1 WHERE account_id=NEW.account_id;
 INSERT INTO auth_audit(event) VALUES('privilege_revoked');
END;
CREATE TRIGGER passkey_browser_revoke AFTER UPDATE OF active ON passkeys WHEN OLD.active<>NEW.active BEGIN
 UPDATE browser_sessions SET revoked=1 WHERE account_id=NEW.account_id;
 INSERT INTO auth_audit(event) VALUES('privilege_revoked');
END;
-- Acceptance is the first statement of the atomic business batch. No JavaScript
-- transaction callback or read-before-write race is relied upon.
CREATE TABLE auth_acceptances (challenge_id TEXT PRIMARY KEY REFERENCES webauthn_challenges(id));
CREATE VIEW accept_browser_auth AS SELECT '' AS challenge_id,'' AS session_digest,'' AS purpose,'' AS request_digest,'' AS credential_id,'' AS account_id WHERE 0;
CREATE TRIGGER accept_browser_auth_insert INSTEAD OF INSERT ON accept_browser_auth BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM webauthn_challenges c WHERE c.id=NEW.challenge_id AND c.session_digest=NEW.session_digest AND c.purpose=NEW.purpose AND c.request_digest=NEW.request_digest AND c.expires_at>unixepoch() AND c.auth_expires>unixepoch() AND c.consumed_at IS NULL AND c.attempts BETWEEN 1 AND 5) THEN RAISE(ABORT,'unauthorized') END;
 SELECT CASE WHEN NEW.purpose='registration' AND NOT EXISTS(
  SELECT 1 FROM webauthn_challenges c JOIN account_verifications v ON v.id=c.verification_id JOIN invitations i ON i.digest=v.invitation_digest
  WHERE c.id=NEW.challenge_id AND v.session_digest=NEW.session_digest AND v.email_lookup=c.identity_hash AND i.email_lookup=c.identity_hash AND v.expires_at>unixepoch() AND i.expires_at>unixepoch() AND v.consumed_at IS NULL AND i.consumed_at IS NULL
 ) THEN RAISE(ABORT,'unauthorized') END;
 SELECT CASE WHEN NEW.purpose<>'registration' AND NOT EXISTS(
  SELECT 1 FROM passkeys p JOIN account_emails e ON e.account_id=p.account_id JOIN webauthn_challenges c ON c.identity_hash=e.lookup_hash
  WHERE c.id=NEW.challenge_id AND p.id=NEW.credential_id AND p.account_id=NEW.account_id AND p.active=1 AND e.verified=1
 ) THEN RAISE(ABORT,'unauthorized') END;
 SELECT CASE WHEN NEW.purpose='step-up' AND NOT EXISTS(
  SELECT 1 FROM browser_sessions s JOIN memberships m ON m.account_id=s.account_id AND m.tenant_id=s.tenant_id
  WHERE s.digest=NEW.session_digest AND s.account_id=NEW.account_id AND s.revoked=0 AND s.last_seen>unixepoch()-1800 AND s.absolute_expires>unixepoch() AND m.active=1
 ) THEN RAISE(ABORT,'unauthorized') END;
 INSERT INTO auth_acceptances VALUES(NEW.challenge_id);
 INSERT INTO consumed_bootstraps SELECT NEW.session_digest,unixepoch()+300 WHERE NEW.purpose IN('registration','authentication');
 UPDATE webauthn_challenges SET consumed_at=unixepoch() WHERE id=NEW.challenge_id;
 UPDATE invitations SET consumed_at=unixepoch() WHERE digest=(SELECT v.invitation_digest FROM account_verifications v JOIN webauthn_challenges c ON c.verification_id=v.id WHERE c.id=NEW.challenge_id) AND NEW.purpose='registration';
 UPDATE account_verifications SET consumed_at=unixepoch() WHERE id=(SELECT verification_id FROM webauthn_challenges WHERE id=NEW.challenge_id) AND NEW.purpose='registration';
END;
CREATE TRIGGER invite_no_reuse BEFORE UPDATE ON invitations WHEN OLD.consumed_at IS NOT NULL BEGIN SELECT RAISE(ABORT,'consumed'); END;
CREATE TRIGGER challenge_no_reuse BEFORE UPDATE ON webauthn_challenges WHEN OLD.consumed_at IS NOT NULL BEGIN SELECT RAISE(ABORT,'consumed'); END;
CREATE TRIGGER session_authorize BEFORE INSERT ON browser_sessions BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM memberships WHERE account_id=NEW.account_id AND tenant_id=NEW.tenant_id AND active=1) THEN RAISE(ABORT,'unauthorized') END;
END;
