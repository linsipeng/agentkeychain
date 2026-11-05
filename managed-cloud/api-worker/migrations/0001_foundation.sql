PRAGMA foreign_keys = ON;
CREATE TABLE accounts (
  id TEXT PRIMARY KEY
);
CREATE TABLE tenants (
  id TEXT PRIMARY KEY
);
CREATE TABLE memberships (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  account_id TEXT NOT NULL REFERENCES accounts(id),
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  PRIMARY KEY(tenant_id,account_id)
);
CREATE TABLE vaults (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  id TEXT NOT NULL,
  sequence INTEGER NOT NULL DEFAULT 0 CHECK(sequence BETWEEN 0 AND 9007199254740991),
  PRIMARY KEY(tenant_id,id)
);
CREATE TABLE devices (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  PRIMARY KEY(tenant_id,id),
  UNIQUE(tenant_id,id,account_id),
  FOREIGN KEY(tenant_id,account_id) REFERENCES memberships(tenant_id,account_id)
);
CREATE TRIGGER pin_device BEFORE UPDATE OF public_key,tenant_id,id,account_id ON devices BEGIN SELECT RAISE(ABORT,'immutable_device'); END;
CREATE TRIGGER retain_device BEFORE DELETE ON devices BEGIN SELECT RAISE(ABORT,'immutable_device'); END;
CREATE TABLE vault_devices (
  tenant_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  PRIMARY KEY(tenant_id,vault_id,device_id),
  FOREIGN KEY(tenant_id,vault_id) REFERENCES vaults(tenant_id,id),
  FOREIGN KEY(tenant_id,device_id) REFERENCES devices(tenant_id,id)
);
CREATE TABLE device_sessions (
  digest TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  UNIQUE(digest,tenant_id,vault_id,device_id,account_id),
  FOREIGN KEY(tenant_id,vault_id,device_id) REFERENCES vault_devices(tenant_id,vault_id,device_id),
  FOREIGN KEY(tenant_id,device_id,account_id) REFERENCES devices(tenant_id,id,account_id)
);
CREATE TABLE device_nonces (
  session_digest TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  PRIMARY KEY(session_digest,nonce),
  FOREIGN KEY(session_digest,tenant_id,vault_id,device_id,account_id) REFERENCES device_sessions(digest,tenant_id,vault_id,device_id,account_id)
);
CREATE TRIGGER authorize_nonce BEFORE INSERT ON device_nonces BEGIN

  SELECT CASE WHEN NOT EXISTS(SELECT 1
  FROM device_sessions s
  JOIN memberships m ON m.tenant_id=s.tenant_id
  AND m.account_id=s.account_id
  JOIN devices d ON d.tenant_id=s.tenant_id
  AND d.id=s.device_id
  JOIN vault_devices v ON v.tenant_id=s.tenant_id
  AND v.vault_id=s.vault_id
  AND v.device_id=s.device_id
  WHERE s.digest=NEW.session_digest
  AND s.tenant_id=NEW.tenant_id
  AND s.vault_id=NEW.vault_id
  AND s.device_id=NEW.device_id
  AND s.account_id=NEW.account_id
  AND s.active=1
  AND s.expires_at>unixepoch()
  AND m.active=1
  AND d.active=1
  AND v.active=1)
  THEN RAISE(ABORT,'not_found')
  END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM device_nonces WHERE session_digest=NEW.session_digest AND nonce=NEW.nonce) THEN RAISE(ABORT,'replayed_request') END;
END;
CREATE TABLE versions (
  tenant_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence>0),
  device_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  object_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('put','delete','restore')),
  generation INTEGER NOT NULL CHECK(generation>0),
  key_epoch INTEGER NOT NULL CHECK(key_epoch>0),
  canonical TEXT NOT NULL,
  signature TEXT NOT NULL,
  PRIMARY KEY(tenant_id,vault_id,sequence),
  UNIQUE(tenant_id,vault_id,device_id,operation_id),
  FOREIGN KEY(tenant_id,vault_id,device_id) REFERENCES vault_devices(tenant_id,vault_id,device_id)
);
CREATE TABLE heads (
  tenant_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  object_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  PRIMARY KEY(tenant_id,vault_id,object_id),
  FOREIGN KEY(tenant_id,vault_id,sequence) REFERENCES versions(tenant_id,vault_id,sequence)
);
CREATE TABLE idempotency (
  tenant_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  receipt TEXT NOT NULL,
  PRIMARY KEY(tenant_id,vault_id,device_id,operation_id),
  FOREIGN KEY(tenant_id,vault_id,device_id,operation_id) REFERENCES versions(tenant_id,vault_id,device_id,operation_id),
  FOREIGN KEY(tenant_id,vault_id,sequence) REFERENCES versions(tenant_id,vault_id,sequence)
);
CREATE TABLE approvals (
  tenant_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('delete','restore')),
  object_id TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_sequence INTEGER,
  PRIMARY KEY(tenant_id,vault_id,id),
  FOREIGN KEY(tenant_id,device_id,account_id) REFERENCES devices(tenant_id,id,account_id),
  FOREIGN KEY(tenant_id,vault_id,device_id) REFERENCES vault_devices(tenant_id,vault_id,device_id),
  FOREIGN KEY(tenant_id,vault_id,consumed_sequence) REFERENCES versions(tenant_id,vault_id,sequence)
);
CREATE TABLE audit (
  tenant_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  account_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('put','delete','restore')),
  PRIMARY KEY(tenant_id,vault_id,sequence),
  FOREIGN KEY(tenant_id,vault_id,sequence) REFERENCES versions(tenant_id,vault_id,sequence),
  FOREIGN KEY(tenant_id,account_id) REFERENCES memberships(tenant_id,account_id)
);
CREATE TABLE checkpoints (
  tenant_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  digest TEXT NOT NULL,
  previous_digest TEXT,
  signature TEXT NOT NULL,
  PRIMARY KEY(tenant_id,vault_id,sequence),
  FOREIGN KEY(tenant_id,vault_id,sequence) REFERENCES audit(tenant_id,vault_id,sequence)
);
CREATE TABLE recovery_cases (
  tenant_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  target_device_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending','cancelled','completed')),
  not_before INTEGER NOT NULL,
  PRIMARY KEY(tenant_id,vault_id,id),
  FOREIGN KEY(tenant_id,account_id) REFERENCES memberships(tenant_id,account_id),
  FOREIGN KEY(tenant_id,vault_id,target_device_id) REFERENCES vault_devices(tenant_id,vault_id,device_id)
);
CREATE TABLE recovery_events (
  tenant_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending','cancelled','completed')),
  PRIMARY KEY(tenant_id,vault_id,case_id,event_id),
  FOREIGN KEY(tenant_id,vault_id,case_id) REFERENCES recovery_cases(tenant_id,vault_id,id)
);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER versions_no_update BEFORE UPDATE ON versions BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER versions_no_delete BEFORE DELETE ON versions BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER receipts_no_update BEFORE UPDATE ON idempotency BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER receipts_no_delete BEFORE DELETE ON idempotency BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER checkpoint_no_update BEFORE UPDATE ON checkpoints BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER checkpoint_no_delete BEFORE DELETE ON checkpoints BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER recovery_events_no_update BEFORE UPDATE ON recovery_events BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER recovery_events_no_delete BEFORE DELETE ON recovery_events BEGIN SELECT RAISE(ABORT,'append_only'); END;
-- A write-only command view: no command row survives acceptance. All expressions
-- execute inside the containing D1 batch transaction, not a JS read/write loop.
CREATE VIEW accept_operation AS SELECT tenant_id,vault_id,account_id,device_id,'' AS canonical,'' AS signature,'' AS request_digest FROM device_sessions WHERE 0;
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
 SELECT CASE WHEN json_extract(NEW.canonical,'$.kind')='put' AND json_extract(NEW.canonical,'$.approvalRef') IS NOT NULL THEN RAISE(ABORT,'approval_required') END;

  SELECT CASE WHEN json_extract(NEW.canonical,'$.kind')<>'put'
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
CREATE TRIGGER devices_no_replace BEFORE INSERT ON devices WHEN EXISTS(SELECT 1
  FROM devices
  WHERE tenant_id=NEW.tenant_id
  AND id=NEW.id)
  BEGIN
  SELECT RAISE(ABORT,'immutable_record');
  END;
CREATE TRIGGER versions_no_replace BEFORE INSERT ON versions WHEN EXISTS(SELECT 1
  FROM versions
  WHERE tenant_id=NEW.tenant_id
  AND vault_id=NEW.vault_id
  AND sequence=NEW.sequence)
  BEGIN
  SELECT RAISE(ABORT,'immutable_record');
  END;
CREATE TRIGGER idempotency_no_replace BEFORE INSERT ON idempotency WHEN EXISTS(SELECT 1
  FROM idempotency
  WHERE tenant_id=NEW.tenant_id
  AND vault_id=NEW.vault_id
  AND device_id=NEW.device_id
  AND operation_id=NEW.operation_id)
  BEGIN
  SELECT RAISE(ABORT,'immutable_record');
  END;
CREATE TRIGGER audit_no_replace BEFORE INSERT ON audit WHEN EXISTS(SELECT 1
  FROM audit
  WHERE tenant_id=NEW.tenant_id
  AND vault_id=NEW.vault_id
  AND sequence=NEW.sequence)
  BEGIN
  SELECT RAISE(ABORT,'immutable_record');
  END;
CREATE TRIGGER checkpoints_no_replace BEFORE INSERT ON checkpoints WHEN EXISTS(SELECT 1
  FROM checkpoints
  WHERE tenant_id=NEW.tenant_id
  AND vault_id=NEW.vault_id
  AND sequence=NEW.sequence)
  BEGIN
  SELECT RAISE(ABORT,'immutable_record');
  END;
CREATE TRIGGER recovery_events_no_replace BEFORE INSERT ON recovery_events WHEN EXISTS(SELECT 1
  FROM recovery_events
  WHERE tenant_id=NEW.tenant_id
  AND vault_id=NEW.vault_id
  AND case_id=NEW.case_id
  AND event_id=NEW.event_id)
  BEGIN
  SELECT RAISE(ABORT,'immutable_record');
  END;
CREATE TRIGGER device_sessions_no_replace BEFORE INSERT ON device_sessions WHEN EXISTS(SELECT 1
  FROM device_sessions
  WHERE digest=NEW.digest)
  BEGIN
  SELECT RAISE(ABORT,'immutable_record');
  END;
CREATE TRIGGER sessions_pin BEFORE UPDATE OF digest,tenant_id,vault_id,device_id,account_id ON device_sessions BEGIN SELECT RAISE(ABORT,'immutable_session'); END;
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
