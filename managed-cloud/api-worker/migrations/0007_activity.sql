CREATE TABLE activity (
 id INTEGER PRIMARY KEY AUTOINCREMENT, public_id TEXT NOT NULL UNIQUE DEFAULT(lower(hex(randomblob(16)))), tenant_id TEXT, account_id TEXT, device_id TEXT, vault_id TEXT,
 event TEXT NOT NULL CHECK(event IN('account.created','browser.session','browser.revoked','browser.registered','browser.authenticated','browser.step_up','browser.logout','browser.counter_risk','browser.privilege_revoked','browser.rejected','device.requested','device.bound','device.approved','device.denied','device.challenge','device.session','device.package','device.package_fetched','device.revoked','device.rejected','device.checkpoint','device.delivered','sync.put','sync.delete','sync.restore','approval.pending','approval.approved','approval.denied','approval.cancelled','recovery.prepared','recovery.confirmed','recovery.released','recovery.cancelled','recovery.completed','recovery.proven','recovery.activating','recovery.reviewed')),
 reference TEXT, created_at INTEGER NOT NULL DEFAULT(unixepoch())
);
CREATE INDEX activity_scope ON activity(tenant_id,account_id,id);
CREATE TRIGGER activity_update BEFORE UPDATE ON activity BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER activity_delete BEFORE DELETE ON activity BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER activity_replace BEFORE INSERT ON activity WHEN EXISTS(SELECT 1 FROM activity WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER activity_sync AFTER INSERT ON audit BEGIN INSERT INTO activity(tenant_id,account_id,device_id,vault_id,event,reference) VALUES(NEW.tenant_id,NEW.account_id,NEW.device_id,NEW.vault_id,'sync.'||NEW.action,CAST(NEW.sequence AS TEXT)); END;
CREATE TRIGGER activity_device AFTER INSERT ON device_audit BEGIN INSERT INTO activity(tenant_id,account_id,device_id,vault_id,event) VALUES(NEW.tenant_id,NEW.account_id,NEW.device_id,NEW.vault_id,'device.'||NEW.event); END;
CREATE TRIGGER activity_browser AFTER INSERT ON browser_sessions BEGIN INSERT INTO activity(tenant_id,account_id,event) VALUES(NEW.tenant_id,NEW.account_id,'browser.session'); END;
CREATE TRIGGER activity_browser_revoke AFTER UPDATE OF revoked ON browser_sessions WHEN OLD.revoked=0 AND NEW.revoked=1 BEGIN INSERT INTO activity(tenant_id,account_id,event) VALUES(NEW.tenant_id,NEW.account_id,'browser.revoked'); END;
CREATE TRIGGER activity_account AFTER INSERT ON memberships BEGIN INSERT INTO activity(tenant_id,account_id,event) VALUES(NEW.tenant_id,NEW.account_id,'account.created'); END;
CREATE TRIGGER activity_approval AFTER INSERT ON approval_requests BEGIN INSERT INTO activity(tenant_id,account_id,device_id,vault_id,event,reference) VALUES(NEW.tenant_id,NEW.account_id,NEW.device_id,NEW.vault_id,'approval.pending',NEW.id); END;
CREATE TRIGGER activity_decision AFTER UPDATE OF state ON approval_requests BEGIN INSERT INTO activity(tenant_id,account_id,device_id,vault_id,event,reference) VALUES(NEW.tenant_id,NEW.account_id,NEW.device_id,NEW.vault_id,'approval.'||NEW.state,NEW.id); END;
CREATE TABLE activity_key (slot INTEGER PRIMARY KEY CHECK(slot=1),key_id TEXT NOT NULL,public_key TEXT NOT NULL);
CREATE TABLE activity_checkpoints (
 tenant_id TEXT NOT NULL, account_id TEXT NOT NULL, through_id INTEGER NOT NULL, count INTEGER NOT NULL, root TEXT NOT NULL,
 previous_id INTEGER NOT NULL, key_id TEXT NOT NULL, canonical TEXT NOT NULL, signature TEXT NOT NULL,
 PRIMARY KEY(tenant_id,account_id,through_id)
);
CREATE TRIGGER activity_cp_update BEFORE UPDATE ON activity_checkpoints BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER activity_cp_delete BEFORE DELETE ON activity_checkpoints BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER activity_cp_replace BEFORE INSERT ON activity_checkpoints WHEN EXISTS(SELECT 1 FROM activity_checkpoints WHERE tenant_id=NEW.tenant_id AND account_id=NEW.account_id AND through_id=NEW.through_id) BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER activity_key_update BEFORE UPDATE ON activity_key BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER activity_key_delete BEFORE DELETE ON activity_key BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER activity_key_replace BEFORE INSERT ON activity_key WHEN EXISTS(SELECT 1 FROM activity_key) BEGIN SELECT RAISE(ABORT,'append_only'); END;

ALTER TABLE auth_audit ADD COLUMN account_id TEXT;
ALTER TABLE auth_audit ADD COLUMN tenant_id TEXT;
CREATE TRIGGER activity_auth AFTER INSERT ON auth_audit BEGIN INSERT INTO activity(tenant_id,account_id,event) VALUES(NEW.tenant_id,NEW.account_id,'browser.'||NEW.event); END;
CREATE TRIGGER activity_redaction BEFORE INSERT ON activity WHEN
 COALESCE(NEW.reference,'') GLOB '*[^A-Za-z0-9_-]*' OR length(COALESCE(NEW.reference,''))>128 OR
 COALESCE(NEW.reference,'') GLOB 'sk-*' OR COALESCE(NEW.reference,'') GLOB 'AKIA*' OR COALESCE(NEW.reference,'') GLOB 'eyJ*'
BEGIN SELECT RAISE(ABORT,'invalid_audit'); END;

CREATE TRIGGER activity_cp_chain BEFORE INSERT ON activity_checkpoints WHEN NEW.previous_id<>COALESCE((SELECT max(through_id) FROM activity_checkpoints WHERE tenant_id=NEW.tenant_id AND account_id=NEW.account_id),0) BEGIN SELECT RAISE(ABORT,'invalid_audit_chain'); END;
