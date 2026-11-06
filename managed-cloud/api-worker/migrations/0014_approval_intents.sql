CREATE TABLE approval_intents (
 tenant_id TEXT NOT NULL, vault_id TEXT NOT NULL, request_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN('rotate','scope')), signature TEXT NOT NULL,
 PRIMARY KEY(tenant_id,vault_id,request_id),
 FOREIGN KEY(tenant_id,vault_id,request_id) REFERENCES approval_requests(tenant_id,vault_id,id)
);
CREATE TRIGGER approval_intent_update BEFORE UPDATE ON approval_intents BEGIN SELECT RAISE(ABORT,'immutable_intent'); END;
CREATE TRIGGER approval_intent_delete BEFORE DELETE ON approval_intents BEGIN SELECT RAISE(ABORT,'immutable_intent'); END;
CREATE TRIGGER approval_intent_replace BEFORE INSERT ON approval_intents WHEN EXISTS(SELECT 1 FROM approval_intents WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id AND request_id=NEW.request_id) BEGIN SELECT RAISE(ABORT,'immutable_intent'); END;
