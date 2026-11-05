-- Local-only Phase 3 additive migration. Legacy hash-only invites fail display closed.
ALTER TABLE invitations ADD COLUMN encrypted_email TEXT;
CREATE TABLE recovery_sessions (
 digest TEXT PRIMARY KEY, csrf_digest TEXT NOT NULL, bootstrap_digest TEXT NOT NULL UNIQUE,
 proof_digest TEXT NOT NULL UNIQUE, account_id TEXT, tenant_id TEXT, vault_id TEXT,
 case_id TEXT NOT NULL, request_digest TEXT NOT NULL, target TEXT, expires_at INTEGER NOT NULL,
 cancel_digest TEXT, started INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TRIGGER recovery_session_pin BEFORE UPDATE OF digest,csrf_digest,bootstrap_digest,proof_digest,account_id,tenant_id,vault_id,case_id,request_digest,target,expires_at ON recovery_sessions BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER recovery_session_no_replace BEFORE INSERT ON recovery_sessions WHEN EXISTS(SELECT 1 FROM recovery_sessions WHERE digest=NEW.digest OR bootstrap_digest=NEW.bootstrap_digest OR proof_digest=NEW.proof_digest) BEGIN SELECT RAISE(ABORT,'unauthorized'); END;
CREATE TRIGGER recovery_session_no_unrevoke BEFORE UPDATE OF revoked ON recovery_sessions WHEN OLD.revoked=1 AND NEW.revoked<>1 BEGIN SELECT RAISE(ABORT,'revoked'); END;
CREATE TRIGGER recovery_restricted_complete AFTER UPDATE OF state ON recovery_sagas WHEN NEW.state='completed' BEGIN UPDATE recovery_sessions SET revoked=1 WHERE account_id=NEW.account_id; END;
CREATE TRIGGER recovery_restricted_membership AFTER UPDATE OF active ON memberships WHEN NEW.active=0 BEGIN UPDATE recovery_sessions SET revoked=1 WHERE account_id=NEW.account_id; END;
DROP TRIGGER recovery_browser_authorize;
CREATE TRIGGER recovery_browser_authorize BEFORE INSERT ON recovery_browser_actions BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM browser_sessions s JOIN memberships m ON m.tenant_id=s.tenant_id AND m.account_id=s.account_id WHERE s.digest=NEW.session_digest AND s.tenant_id=NEW.tenant_id AND s.account_id=NEW.account_id AND s.revoked=0 AND s.absolute_expires>unixepoch() AND s.last_seen>unixepoch()-1800 AND s.step_up_expires>unixepoch() AND s.step_up_digest=NEW.action_digest AND m.active=1)
 AND NOT EXISTS(SELECT 1 FROM recovery_sessions s JOIN memberships m ON m.tenant_id=s.tenant_id AND m.account_id=s.account_id WHERE s.digest=NEW.session_digest AND s.tenant_id=NEW.tenant_id AND s.account_id=NEW.account_id AND s.revoked=0 AND s.expires_at>unixepoch() AND ((s.started=0 AND s.request_digest=NEW.action_digest) OR (s.started=1 AND s.cancel_digest=NEW.action_digest AND EXISTS(SELECT 1 FROM recovery_sagas c WHERE c.id=s.case_id AND c.session_digest=s.digest AND c.account_id=s.account_id AND c.tenant_id=s.tenant_id AND c.vault_id=s.vault_id AND c.state IN('prepared','confirmed','released','proven')))) AND m.active=1)
 THEN RAISE(ABORT,'approval_required') END;
 UPDATE browser_sessions SET step_up_digest=NULL,step_up_expires=NULL WHERE digest=NEW.session_digest;
 UPDATE recovery_sessions SET started=1 WHERE digest=NEW.session_digest;
END;

CREATE INDEX recovery_session_expiry ON recovery_sessions(expires_at);
