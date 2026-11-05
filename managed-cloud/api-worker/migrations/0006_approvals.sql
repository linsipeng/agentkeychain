DROP TRIGGER accept_operation_insert;
CREATE TABLE approvals_next (
  tenant_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('put','delete','restore')),
  object_id TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_sequence INTEGER,
  PRIMARY KEY(tenant_id,vault_id,id),
  FOREIGN KEY(tenant_id,device_id,account_id) REFERENCES devices(tenant_id,id,account_id),
  FOREIGN KEY(tenant_id,vault_id,device_id) REFERENCES vault_devices(tenant_id,vault_id,device_id),
  FOREIGN KEY(tenant_id,vault_id,consumed_sequence) REFERENCES versions(tenant_id,vault_id,sequence)
);
INSERT INTO approvals_next SELECT * FROM approvals;
DROP TABLE approvals;
ALTER TABLE approvals_next RENAME TO approvals;
CREATE TRIGGER approvals_no_reuse BEFORE UPDATE OF consumed_sequence ON approvals WHEN OLD.consumed_sequence IS NOT NULL BEGIN SELECT RAISE(ABORT,'approval_required'); END;
CREATE TRIGGER approvals_no_replace BEFORE INSERT ON approvals WHEN EXISTS(SELECT 1
  FROM approvals
  WHERE tenant_id=NEW.tenant_id
  AND vault_id=NEW.vault_id
  AND id=NEW.id)
  BEGIN
  SELECT RAISE(ABORT,'approval_required');
  END;
CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals BEGIN SELECT RAISE(ABORT,'append_only'); END;

CREATE TRIGGER accept_operation_insert INSTEAD OF INSERT ON accept_operation BEGIN

  SELECT CASE WHEN EXISTS(SELECT 1
  FROM versions
  WHERE tenant_id=NEW.tenant_id
  AND vault_id=NEW.vault_id
  AND device_id=NEW.device_id
  AND operation_id=json_extract(NEW.canonical,'$.operationId')
  AND (canonical<>NEW.canonical OR signature<>NEW.signature))
  THEN RAISE(ABORT,'idempotency_conflict')
  END;

  SELECT CASE WHEN EXISTS(SELECT 1
  FROM versions
  WHERE tenant_id=NEW.tenant_id
  AND vault_id=NEW.vault_id
  AND device_id=NEW.device_id
  AND operation_id=json_extract(NEW.canonical,'$.operationId'))
  THEN RAISE(IGNORE)
  END;

  SELECT CASE WHEN NOT EXISTS(SELECT 1
  FROM heads
  WHERE tenant_id=NEW.tenant_id
  AND vault_id=NEW.vault_id
  AND object_id=json_extract(NEW.canonical,'$.objectId'))
  AND (json_extract(NEW.canonical,'$.kind')<>'put' OR json_extract(NEW.canonical,'$.generation')<>1)
  THEN RAISE(ABORT,'invalid_transition')
  END;

  SELECT CASE WHEN EXISTS(SELECT 1
  FROM heads h
  JOIN versions v ON v.tenant_id=h.tenant_id
  AND v.vault_id=h.vault_id
  AND v.sequence=h.sequence
  WHERE h.tenant_id=NEW.tenant_id
  AND h.vault_id=NEW.vault_id
  AND h.object_id=json_extract(NEW.canonical,'$.objectId')
  AND (json_extract(NEW.canonical,'$.keyEpoch')<v.key_epoch OR (json_extract(NEW.canonical,'$.kind')='restore'
  AND json_extract(NEW.canonical,'$.generation')<=v.generation) OR (json_extract(NEW.canonical,'$.kind')<>'restore'
  AND (v.kind='delete' OR json_extract(NEW.canonical,'$.generation')<>v.generation))))
  THEN RAISE(ABORT,'invalid_transition')
  END;
 SELECT CASE WHEN json_extract(NEW.canonical,'$.kind')='put' AND NOT EXISTS(SELECT 1 FROM heads WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id AND object_id=json_extract(NEW.canonical,'$.objectId')) AND json_extract(NEW.canonical,'$.approvalRef') IS NOT NULL THEN RAISE(ABORT,'approval_required') END;

  SELECT CASE WHEN (json_extract(NEW.canonical,'$.kind')<>'put' OR EXISTS(SELECT 1 FROM heads WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id AND object_id=json_extract(NEW.canonical,'$.objectId')))
  AND NOT EXISTS(SELECT 1
  FROM approvals
  WHERE tenant_id=NEW.tenant_id
  AND vault_id=NEW.vault_id
  AND id=json_extract(NEW.canonical,'$.approvalRef')
  AND account_id=NEW.account_id
  AND device_id=NEW.device_id
  AND action=json_extract(NEW.canonical,'$.kind')
  AND object_id=json_extract(NEW.canonical,'$.objectId')
  AND request_digest=NEW.request_digest
  AND expires_at>unixepoch()
  AND consumed_sequence IS NULL)
  THEN RAISE(ABORT,'approval_required')
  END;
 UPDATE vaults SET sequence=sequence+1 WHERE tenant_id=NEW.tenant_id AND id=NEW.vault_id;
 INSERT INTO versions
  SELECT NEW.tenant_id,NEW.vault_id,sequence,NEW.device_id,json_extract(NEW.canonical,'$.operationId'),json_extract(NEW.canonical,'$.objectId'),json_extract(NEW.canonical,'$.kind'),json_extract(NEW.canonical,'$.generation'),json_extract(NEW.canonical,'$.keyEpoch'),NEW.canonical,NEW.signature
  FROM vaults
  WHERE tenant_id=NEW.tenant_id
  AND id=NEW.vault_id;
 INSERT INTO heads
  SELECT NEW.tenant_id,NEW.vault_id,json_extract(NEW.canonical,'$.objectId'),sequence
  FROM vaults
  WHERE tenant_id=NEW.tenant_id
  AND id=NEW.vault_id ON CONFLICT(tenant_id,vault_id,object_id) DO UPDATE SET sequence=excluded.sequence;
 UPDATE approvals SET consumed_sequence=(SELECT sequence
  FROM vaults
  WHERE tenant_id=NEW.tenant_id
  AND id=NEW.vault_id)
  WHERE tenant_id=NEW.tenant_id
  AND vault_id=NEW.vault_id
  AND id=json_extract(NEW.canonical,'$.approvalRef');
 INSERT INTO idempotency
  SELECT NEW.tenant_id,NEW.vault_id,NEW.device_id,json_extract(NEW.canonical,'$.operationId'),sequence,json_object('vaultId',NEW.vault_id,'deviceId',NEW.device_id,'operationId',json_extract(NEW.canonical,'$.operationId'),'serverSequence',sequence)
  FROM vaults
  WHERE tenant_id=NEW.tenant_id
  AND id=NEW.vault_id;
 INSERT INTO audit
  SELECT NEW.tenant_id,NEW.vault_id,sequence,NEW.account_id,NEW.device_id,json_extract(NEW.canonical,'$.kind')
  FROM vaults
  WHERE tenant_id=NEW.tenant_id
  AND id=NEW.vault_id;
END;
CREATE TABLE approval_requests (
 ordinal INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, vault_id TEXT NOT NULL, id TEXT NOT NULL,
 account_id TEXT NOT NULL, device_id TEXT NOT NULL, action TEXT NOT NULL CHECK(action IN('put','delete','restore')),
 object_id TEXT NOT NULL, request_digest TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT(unixepoch()),
 expires_at INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN('pending','approved','denied','cancelled')),
 decided_at INTEGER, UNIQUE(tenant_id,vault_id,id), UNIQUE(tenant_id,vault_id,device_id,request_digest),
 FOREIGN KEY(tenant_id,device_id,account_id) REFERENCES devices(tenant_id,id,account_id)
);
CREATE TABLE approval_decisions (
 id TEXT PRIMARY KEY, session_digest TEXT NOT NULL, tenant_id TEXT NOT NULL, account_id TEXT NOT NULL,
 request_ordinal INTEGER NOT NULL REFERENCES approval_requests(ordinal), decision TEXT NOT NULL CHECK(decision IN('approve','deny','cancel')),
 action_digest TEXT NOT NULL
);
CREATE TRIGGER approval_decide BEFORE INSERT ON approval_decisions BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM browser_sessions s JOIN memberships m ON m.tenant_id=s.tenant_id AND m.account_id=s.account_id JOIN approval_requests r ON r.ordinal=NEW.request_ordinal WHERE s.digest=NEW.session_digest AND s.account_id=NEW.account_id AND s.tenant_id=NEW.tenant_id AND r.account_id=s.account_id AND r.tenant_id=s.tenant_id AND r.state='pending' AND r.expires_at>unixepoch() AND s.revoked=0 AND s.absolute_expires>unixepoch() AND s.last_seen>unixepoch()-1800 AND s.step_up_digest=NEW.action_digest AND s.step_up_expires>unixepoch() AND m.active=1) THEN RAISE(ABORT,'approval_required') END;
END;
CREATE TRIGGER approval_decided AFTER INSERT ON approval_decisions BEGIN
 UPDATE approval_requests SET state=CASE NEW.decision WHEN 'approve' THEN 'approved' WHEN 'deny' THEN 'denied' ELSE 'cancelled' END,decided_at=unixepoch() WHERE ordinal=NEW.request_ordinal;
 INSERT INTO approvals SELECT tenant_id,vault_id,id,account_id,device_id,action,object_id,request_digest,expires_at,NULL FROM approval_requests WHERE ordinal=NEW.request_ordinal AND NEW.decision='approve';
 UPDATE browser_sessions SET step_up_digest=NULL,step_up_expires=NULL WHERE digest=NEW.session_digest;
END;
CREATE TRIGGER approval_request_pin BEFORE UPDATE OF ordinal,tenant_id,vault_id,id,account_id,device_id,action,object_id,request_digest,created_at,expires_at ON approval_requests BEGIN SELECT RAISE(ABORT,'immutable_request'); END;
CREATE TRIGGER approval_request_terminal BEFORE UPDATE OF state ON approval_requests WHEN OLD.state<>'pending' BEGIN SELECT RAISE(ABORT,'approval_required'); END;
CREATE TRIGGER approval_request_delete BEFORE DELETE ON approval_requests BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER approval_request_replace BEFORE INSERT ON approval_requests WHEN EXISTS(SELECT 1 FROM approval_requests WHERE ordinal=NEW.ordinal OR (tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id AND id=NEW.id)) BEGIN SELECT RAISE(ABORT,'idempotency_conflict'); END;
CREATE TRIGGER approval_grant_pin BEFORE UPDATE OF tenant_id,vault_id,id,account_id,device_id,action,object_id,request_digest,expires_at ON approvals BEGIN SELECT RAISE(ABORT,'immutable_request'); END;
CREATE TRIGGER approval_decisions_update BEFORE UPDATE ON approval_decisions BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER approval_decisions_delete BEFORE DELETE ON approval_decisions BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER approval_decisions_replace BEFORE INSERT ON approval_decisions WHEN EXISTS(SELECT 1 FROM approval_decisions WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE UNIQUE INDEX approval_account_request_id ON approval_requests(tenant_id,account_id,id);
-- Optional human-readable summary is encrypted by the requesting device. It is
-- never selected by browser APIs; browser labels derive only from action enums.
CREATE TABLE approval_summaries (tenant_id TEXT NOT NULL,vault_id TEXT NOT NULL,request_id TEXT NOT NULL,digest TEXT NOT NULL,encrypted_summary TEXT NOT NULL,signature TEXT NOT NULL,PRIMARY KEY(tenant_id,vault_id,request_id),FOREIGN KEY(tenant_id,vault_id,request_id) REFERENCES approval_requests(tenant_id,vault_id,id));
CREATE TRIGGER approval_summary_update BEFORE UPDATE ON approval_summaries BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER approval_summary_delete BEFORE DELETE ON approval_summaries BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER approval_summary_replace BEFORE INSERT ON approval_summaries WHEN EXISTS(SELECT 1 FROM approval_summaries WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id AND request_id=NEW.request_id) BEGIN SELECT RAISE(ABORT,'append_only'); END;

ALTER TABLE approval_requests ADD COLUMN creation_digest TEXT;
CREATE TRIGGER approval_creation_pin BEFORE UPDATE OF creation_digest ON approval_requests BEGIN SELECT RAISE(ABORT,'immutable_request'); END;
