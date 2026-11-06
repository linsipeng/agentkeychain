CREATE TABLE export_requests (
 ordinal INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL,vault_id TEXT NOT NULL,id TEXT NOT NULL,account_id TEXT NOT NULL,device_id TEXT NOT NULL,
 canonical TEXT NOT NULL,signature TEXT NOT NULL,request_digest TEXT NOT NULL,created_at INTEGER NOT NULL DEFAULT(unixepoch()),expires_at INTEGER NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN('pending','approved','denied','cancelled')),decided_at INTEGER,consumed_at INTEGER,
 UNIQUE(tenant_id,account_id,id),FOREIGN KEY(tenant_id,device_id,account_id) REFERENCES devices(tenant_id,id,account_id)
);
CREATE TRIGGER export_request_immutable BEFORE UPDATE OF ordinal,tenant_id,vault_id,id,account_id,device_id,canonical,signature,request_digest,created_at,expires_at ON export_requests BEGIN SELECT RAISE(ABORT,'immutable_request'); END;
CREATE TRIGGER export_request_retain BEFORE DELETE ON export_requests BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER export_terminal BEFORE UPDATE OF state ON export_requests WHEN OLD.state<>'pending' BEGIN SELECT RAISE(ABORT,'approval_required'); END;
CREATE TRIGGER export_consume BEFORE UPDATE OF consumed_at ON export_requests WHEN OLD.consumed_at IS NOT NULL OR OLD.state<>'approved' OR OLD.expires_at<=unixepoch() BEGIN SELECT RAISE(ABORT,'approval_required'); END;
CREATE TABLE export_decisions(id TEXT PRIMARY KEY,session_digest TEXT NOT NULL,tenant_id TEXT NOT NULL,account_id TEXT NOT NULL,request_id TEXT NOT NULL,decision TEXT NOT NULL CHECK(decision IN('approve','deny','cancel')),action_digest TEXT NOT NULL);
CREATE TRIGGER export_decide BEFORE INSERT ON export_decisions BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM browser_sessions s JOIN memberships m ON m.tenant_id=s.tenant_id AND m.account_id=s.account_id JOIN export_requests r ON r.id=NEW.request_id AND r.tenant_id=s.tenant_id AND r.account_id=s.account_id JOIN devices d ON d.tenant_id=r.tenant_id AND d.id=r.device_id WHERE s.digest=NEW.session_digest AND s.account_id=NEW.account_id AND s.tenant_id=NEW.tenant_id AND r.state='pending' AND r.expires_at>unixepoch() AND s.revoked=0 AND s.absolute_expires>unixepoch() AND s.last_seen>unixepoch()-1800 AND s.step_up_digest=NEW.action_digest AND s.step_up_expires>unixepoch() AND m.active=1 AND d.active=1) THEN RAISE(ABORT,'approval_required') END;
END;
CREATE TRIGGER export_decided AFTER INSERT ON export_decisions BEGIN
 UPDATE export_requests SET state=CASE NEW.decision WHEN 'approve' THEN 'approved' WHEN 'deny' THEN 'denied' ELSE 'cancelled' END,decided_at=unixepoch() WHERE tenant_id=NEW.tenant_id AND account_id=NEW.account_id AND id=NEW.request_id;
 UPDATE browser_sessions SET step_up_digest=NULL,step_up_expires=NULL WHERE digest=NEW.session_digest;
END;
CREATE TABLE approval_order(ordinal INTEGER PRIMARY KEY AUTOINCREMENT,tenant_id TEXT NOT NULL,account_id TEXT NOT NULL,request_id TEXT NOT NULL,kind TEXT NOT NULL,UNIQUE(tenant_id,account_id,request_id));
INSERT INTO approval_order(tenant_id,account_id,request_id,kind) SELECT tenant_id,account_id,id,'mutation' FROM approval_requests ORDER BY ordinal;
CREATE TRIGGER approval_order_mutation AFTER INSERT ON approval_requests BEGIN INSERT INTO approval_order(tenant_id,account_id,request_id,kind) VALUES(NEW.tenant_id,NEW.account_id,NEW.id,'mutation'); END;
CREATE TRIGGER approval_order_export AFTER INSERT ON export_requests BEGIN INSERT INTO approval_order(tenant_id,account_id,request_id,kind) VALUES(NEW.tenant_id,NEW.account_id,NEW.id,'export'); END;
CREATE TRIGGER export_decisions_update BEFORE UPDATE ON export_decisions BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER export_decisions_delete BEFORE DELETE ON export_decisions BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER export_replace BEFORE INSERT ON export_requests WHEN EXISTS(SELECT 1 FROM export_requests WHERE (tenant_id=NEW.tenant_id AND account_id=NEW.account_id AND id=NEW.id) AND (canonical<>NEW.canonical OR signature<>NEW.signature)) BEGIN SELECT RAISE(ABORT,'idempotency_conflict'); END;
