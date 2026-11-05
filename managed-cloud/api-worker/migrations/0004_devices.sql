-- Additive control-plane state. Public key extensions preserve historical keys.
CREATE TABLE device_keys (
 tenant_id TEXT NOT NULL, device_id TEXT NOT NULL, wrapping_key TEXT NOT NULL,
 PRIMARY KEY(tenant_id,device_id), FOREIGN KEY(tenant_id,device_id) REFERENCES devices(tenant_id,id)
);
CREATE TRIGGER device_keys_pin BEFORE UPDATE ON device_keys BEGIN SELECT RAISE(ABORT,'immutable_device'); END;
CREATE TRIGGER device_keys_retain BEFORE DELETE ON device_keys BEGIN SELECT RAISE(ABORT,'immutable_device'); END;
CREATE TRIGGER device_keys_replace BEFORE INSERT ON device_keys WHEN EXISTS(SELECT 1 FROM device_keys WHERE tenant_id=NEW.tenant_id AND device_id=NEW.device_id) BEGIN SELECT RAISE(ABORT,'immutable_device'); END;
CREATE TABLE device_requests (
 id TEXT PRIMARY KEY, code_digest TEXT NOT NULL UNIQUE, verification_digest TEXT NOT NULL UNIQUE,
 phrase TEXT NOT NULL, device_id TEXT NOT NULL UNIQUE, signing_key TEXT NOT NULL, wrapping_key TEXT NOT NULL,
 platform TEXT NOT NULL CHECK(platform IN('macos','linux','windows','other')),
 expires_at INTEGER NOT NULL, poll_after INTEGER NOT NULL DEFAULT 0,
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN('pending','bound','approved','denied','delivered')),
 account_id TEXT, tenant_id TEXT, vault_id TEXT, key_epoch INTEGER NOT NULL DEFAULT 1 CHECK(key_epoch>0),
 FOREIGN KEY(tenant_id,account_id) REFERENCES memberships(tenant_id,account_id),
 FOREIGN KEY(tenant_id,vault_id) REFERENCES vaults(tenant_id,id)
);
CREATE INDEX device_requests_expiry ON device_requests(expires_at);
CREATE TRIGGER device_request_pin BEFORE UPDATE OF id,code_digest,verification_digest,phrase,device_id,signing_key,wrapping_key,platform,expires_at,key_epoch ON device_requests BEGIN SELECT RAISE(ABORT,'immutable_request'); END;
CREATE TRIGGER device_request_binding BEFORE UPDATE OF account_id,tenant_id,vault_id ON device_requests WHEN OLD.account_id IS NOT NULL BEGIN SELECT RAISE(ABORT,'immutable_request'); END;
CREATE TRIGGER device_request_replace BEFORE INSERT ON device_requests WHEN EXISTS(SELECT 1 FROM device_requests WHERE id=NEW.id OR code_digest=NEW.code_digest OR verification_digest=NEW.verification_digest OR device_id=NEW.device_id) BEGIN SELECT RAISE(ABORT,'immutable_request'); END;
CREATE TABLE enrollment_grants (
 id TEXT PRIMARY KEY REFERENCES device_requests(id), tenant_id TEXT NOT NULL, vault_id TEXT NOT NULL,
 device_id TEXT NOT NULL, issuer_device_id TEXT, key_epoch INTEGER NOT NULL, canonical TEXT NOT NULL, signature TEXT,
 FOREIGN KEY(tenant_id,vault_id,device_id) REFERENCES vault_devices(tenant_id,vault_id,device_id),
 FOREIGN KEY(tenant_id,vault_id,issuer_device_id) REFERENCES vault_devices(tenant_id,vault_id,device_id)
);
CREATE TRIGGER enrollment_grants_update BEFORE UPDATE ON enrollment_grants BEGIN SELECT RAISE(ABORT,'immutable_grant'); END;
CREATE TRIGGER enrollment_grants_delete BEFORE DELETE ON enrollment_grants BEGIN SELECT RAISE(ABORT,'immutable_grant'); END;
CREATE TRIGGER enrollment_grants_replace BEFORE INSERT ON enrollment_grants WHEN EXISTS(SELECT 1 FROM enrollment_grants WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'immutable_grant'); END;
CREATE TABLE device_actions (
 id TEXT PRIMARY KEY, session_digest TEXT NOT NULL, account_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN('approve','deny','revoke')), target TEXT NOT NULL,
 action_digest TEXT NOT NULL, canonical TEXT NOT NULL, signature TEXT, issuer_device_id TEXT,
 created_at INTEGER NOT NULL DEFAULT(unixepoch()),
 UNIQUE(session_digest,action_digest), FOREIGN KEY(tenant_id,account_id) REFERENCES memberships(tenant_id,account_id)
);
CREATE TABLE device_audit (
 id INTEGER PRIMARY KEY, event TEXT NOT NULL CHECK(event IN('requested','bound','approved','denied','challenge','session','package','package_fetched','revoked','rejected','checkpoint','delivered')),
 account_id TEXT, tenant_id TEXT, device_id TEXT, vault_id TEXT, sequence INTEGER, created_at INTEGER NOT NULL DEFAULT(unixepoch())
);
CREATE TRIGGER device_audit_update BEFORE UPDATE ON device_audit BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER device_audit_delete BEFORE DELETE ON device_audit BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER device_audit_replace BEFORE INSERT ON device_audit WHEN EXISTS(SELECT 1 FROM device_audit WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER device_action_authorize BEFORE INSERT ON device_actions BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM browser_sessions s JOIN memberships m ON m.tenant_id=s.tenant_id AND m.account_id=s.account_id WHERE s.digest=NEW.session_digest AND s.account_id=NEW.account_id AND s.tenant_id=NEW.tenant_id AND s.revoked=0 AND s.absolute_expires>unixepoch() AND s.last_seen>unixepoch()-1800 AND s.step_up_digest=NEW.action_digest AND s.step_up_expires>unixepoch() AND m.active=1) THEN RAISE(ABORT,'approval_required') END;
 SELECT CASE WHEN NEW.action IN('approve','deny') AND NOT EXISTS(SELECT 1 FROM device_requests r WHERE r.id=NEW.target AND r.account_id=NEW.account_id AND r.tenant_id=NEW.tenant_id AND r.state='bound' AND r.expires_at>unixepoch()) THEN RAISE(ABORT,'not_found') END;
 SELECT CASE WHEN NEW.action='approve' AND NEW.issuer_device_id IS NULL AND EXISTS(SELECT 1 FROM devices WHERE tenant_id=NEW.tenant_id) THEN RAISE(ABORT,'approval_required') END;
 SELECT CASE WHEN NEW.action='approve' AND NEW.issuer_device_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM devices d JOIN vault_devices v ON v.tenant_id=d.tenant_id AND v.device_id=d.id JOIN device_requests r ON r.tenant_id=v.tenant_id AND r.vault_id=v.vault_id WHERE r.id=NEW.target AND d.id=NEW.issuer_device_id AND d.account_id=NEW.account_id AND d.active=1 AND v.active=1) THEN RAISE(ABORT,'approval_required') END;
 SELECT CASE WHEN NEW.action='revoke' AND NOT EXISTS(SELECT 1 FROM devices WHERE tenant_id=NEW.tenant_id AND account_id=NEW.account_id AND id=NEW.target AND active=1) THEN RAISE(ABORT,'not_found') END;
END;
CREATE TRIGGER device_action_accept AFTER INSERT ON device_actions BEGIN
 INSERT INTO devices(tenant_id,id,account_id,public_key,active) SELECT tenant_id,device_id,account_id,signing_key,1 FROM device_requests WHERE id=NEW.target AND NEW.action='approve';
 INSERT INTO device_keys SELECT tenant_id,device_id,wrapping_key FROM device_requests WHERE id=NEW.target AND NEW.action='approve';
 INSERT INTO vault_devices SELECT tenant_id,vault_id,device_id,1 FROM device_requests WHERE id=NEW.target AND NEW.action='approve';
 INSERT INTO enrollment_grants SELECT id,tenant_id,vault_id,device_id,NEW.issuer_device_id,key_epoch,NEW.canonical,NEW.signature FROM device_requests WHERE id=NEW.target AND NEW.action='approve';
 UPDATE device_requests SET state=CASE NEW.action WHEN 'approve' THEN 'approved' ELSE 'denied' END WHERE id=NEW.target AND NEW.action IN('approve','deny');
 UPDATE devices SET active=0 WHERE tenant_id=NEW.tenant_id AND account_id=NEW.account_id AND id=NEW.target AND NEW.action='revoke';
 UPDATE browser_sessions SET step_up_digest=NULL,step_up_expires=NULL WHERE digest=NEW.session_digest;
 INSERT INTO device_audit(event,account_id,tenant_id,device_id) VALUES(CASE NEW.action WHEN 'approve' THEN 'approved' WHEN 'deny' THEN 'denied' ELSE 'revoked' END,NEW.account_id,NEW.tenant_id,CASE WHEN NEW.action='revoke' THEN NEW.target ELSE (SELECT device_id FROM device_requests WHERE id=NEW.target) END);
END;
CREATE TRIGGER revoke_device_sessions AFTER UPDATE OF active ON devices WHEN NEW.active=0 BEGIN
 UPDATE device_sessions SET active=0 WHERE tenant_id=NEW.tenant_id AND device_id=NEW.id;
 UPDATE vault_devices SET active=0 WHERE tenant_id=NEW.tenant_id AND device_id=NEW.id;
END;
CREATE TRIGGER device_no_reactivate BEFORE UPDATE OF active ON devices WHEN OLD.active=0 AND NEW.active<>0 BEGIN SELECT RAISE(ABORT,'revoked_device'); END;
CREATE TABLE device_challenges (
 id TEXT PRIMARY KEY, challenge_digest TEXT NOT NULL UNIQUE, request_id TEXT NOT NULL REFERENCES device_requests(id),
 expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN(0,1))
);
CREATE INDEX device_challenges_expiry ON device_challenges(expires_at);
CREATE TABLE device_session_issues (
 challenge_id TEXT PRIMARY KEY REFERENCES device_challenges(id), digest TEXT NOT NULL UNIQUE,
 created_at INTEGER NOT NULL DEFAULT(unixepoch())
);
CREATE TRIGGER device_session_issue BEFORE INSERT ON device_session_issues BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM device_challenges c JOIN device_requests r ON r.id=c.request_id JOIN devices d ON d.tenant_id=r.tenant_id AND d.id=r.device_id JOIN memberships m ON m.tenant_id=r.tenant_id AND m.account_id=r.account_id JOIN vault_devices v ON v.tenant_id=r.tenant_id AND v.vault_id=r.vault_id AND v.device_id=r.device_id WHERE c.id=NEW.challenge_id AND c.consumed=0 AND c.expires_at>unixepoch() AND c.attempts BETWEEN 1 AND 5 AND r.state IN('approved','delivered') AND d.active=1 AND m.active=1 AND v.active=1) THEN RAISE(ABORT,'unauthorized') END;
 UPDATE device_challenges SET consumed=1 WHERE id=NEW.challenge_id;
 INSERT INTO device_sessions SELECT NEW.digest,r.tenant_id,r.vault_id,r.device_id,r.account_id,unixepoch()+900,1 FROM device_requests r JOIN device_challenges c ON c.request_id=r.id WHERE c.id=NEW.challenge_id;
 INSERT INTO device_audit(event,account_id,tenant_id,device_id) SELECT 'session',r.account_id,r.tenant_id,r.device_id FROM device_requests r JOIN device_challenges c ON c.request_id=r.id WHERE c.id=NEW.challenge_id;
END;
CREATE INDEX device_sessions_expiry ON device_sessions(expires_at);
CREATE TABLE device_key_packages (
 tenant_id TEXT NOT NULL, vault_id TEXT NOT NULL, target_device_id TEXT NOT NULL, key_epoch INTEGER NOT NULL,
 issuer_device_id TEXT NOT NULL, grant_id TEXT NOT NULL REFERENCES enrollment_grants(id), canonical TEXT NOT NULL, signature TEXT NOT NULL,
 PRIMARY KEY(tenant_id,vault_id,target_device_id,key_epoch),
 FOREIGN KEY(tenant_id,vault_id,target_device_id) REFERENCES vault_devices(tenant_id,vault_id,device_id),
 FOREIGN KEY(tenant_id,vault_id,issuer_device_id) REFERENCES vault_devices(tenant_id,vault_id,device_id)
);
CREATE TRIGGER package_accept BEFORE INSERT ON device_key_packages BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM enrollment_grants g JOIN devices d ON d.tenant_id=g.tenant_id AND d.id=NEW.issuer_device_id JOIN devices target ON target.tenant_id=g.tenant_id AND target.id=g.device_id JOIN vault_devices v ON v.tenant_id=d.tenant_id AND v.vault_id=g.vault_id AND v.device_id=d.id WHERE g.id=NEW.grant_id AND g.tenant_id=NEW.tenant_id AND g.vault_id=NEW.vault_id AND g.device_id=NEW.target_device_id AND g.key_epoch=NEW.key_epoch AND (g.issuer_device_id=NEW.issuer_device_id OR (g.issuer_device_id IS NULL AND g.device_id=NEW.issuer_device_id)) AND d.active=1 AND target.active=1 AND v.active=1 AND d.account_id=target.account_id) THEN RAISE(ABORT,'not_found') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM device_key_packages WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id AND target_device_id=NEW.target_device_id AND key_epoch=NEW.key_epoch AND (canonical<>NEW.canonical OR signature<>NEW.signature OR issuer_device_id<>NEW.issuer_device_id OR grant_id<>NEW.grant_id)) THEN RAISE(ABORT,'idempotency_conflict') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM device_key_packages WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id AND target_device_id=NEW.target_device_id AND key_epoch=NEW.key_epoch) THEN RAISE(IGNORE) END;
END;
CREATE TRIGGER package_update BEFORE UPDATE ON device_key_packages BEGIN SELECT RAISE(ABORT,'immutable_package'); END;
CREATE TRIGGER package_delete BEFORE DELETE ON device_key_packages BEGIN SELECT RAISE(ABORT,'immutable_package'); END;
CREATE TRIGGER package_audit AFTER INSERT ON device_key_packages BEGIN INSERT INTO device_audit(event,tenant_id,device_id) VALUES('package',NEW.tenant_id,NEW.target_device_id); END;
CREATE VIEW accept_device_nonce AS SELECT *,0 AS timestamp FROM device_nonces WHERE 0;
CREATE TRIGGER accept_device_nonce_insert INSTEAD OF INSERT ON accept_device_nonce BEGIN
 SELECT CASE WHEN abs(unixepoch()-NEW.timestamp)>300 THEN RAISE(ABORT,'unauthorized') END;
 INSERT INTO device_nonces VALUES(NEW.session_digest,NEW.tenant_id,NEW.vault_id,NEW.device_id,NEW.account_id,NEW.nonce);
END;
CREATE TRIGGER device_actions_update BEFORE UPDATE ON device_actions BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER device_actions_delete BEFORE DELETE ON device_actions BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER device_actions_replace BEFORE INSERT ON device_actions WHEN EXISTS(SELECT 1 FROM device_actions WHERE id=NEW.id OR (session_digest=NEW.session_digest AND action_digest=NEW.action_digest)) BEGIN SELECT RAISE(ABORT,'replayed_request'); END;
