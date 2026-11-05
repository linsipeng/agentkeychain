CREATE TABLE recovery_packages_v1 (id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,vault_id TEXT NOT NULL,account_id TEXT NOT NULL,key_epoch INTEGER NOT NULL,canonical TEXT NOT NULL,signature TEXT NOT NULL,ready INTEGER NOT NULL DEFAULT 0,UNIQUE(tenant_id,vault_id,key_epoch));
CREATE TABLE recovery_sagas (
 id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,vault_id TEXT NOT NULL,account_id TEXT NOT NULL,package_id TEXT NOT NULL REFERENCES recovery_packages_v1(id),
 canonical TEXT NOT NULL,request_digest TEXT NOT NULL,session_digest TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('prepared','confirmed','released','proven','activating','cancelled','completed')),
 not_before INTEGER NOT NULL,expires_at INTEGER NOT NULL,proof_digest TEXT NOT NULL,challenge TEXT NOT NULL,
 api_release TEXT,custodian_release TEXT,confirmer_id TEXT,review_required INTEGER NOT NULL DEFAULT 1,cancel_authorization TEXT
);
CREATE TABLE recovery_browser_actions(id TEXT PRIMARY KEY,session_digest TEXT NOT NULL,tenant_id TEXT NOT NULL,account_id TEXT NOT NULL,action_digest TEXT NOT NULL);
CREATE TRIGGER recovery_browser_authorize BEFORE INSERT ON recovery_browser_actions BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM browser_sessions s JOIN memberships m ON m.tenant_id=s.tenant_id AND m.account_id=s.account_id WHERE s.digest=NEW.session_digest AND s.tenant_id=NEW.tenant_id AND s.account_id=NEW.account_id AND s.revoked=0 AND s.absolute_expires>unixepoch() AND s.last_seen>unixepoch()-1800 AND s.step_up_expires>unixepoch() AND s.step_up_digest=NEW.action_digest AND m.active=1) THEN RAISE(ABORT,'approval_required') END;
 UPDATE browser_sessions SET step_up_digest=NULL,step_up_expires=NULL WHERE digest=NEW.session_digest;
END;
CREATE TABLE recovery_notifications(id INTEGER PRIMARY KEY AUTOINCREMENT,case_id TEXT NOT NULL REFERENCES recovery_sagas(id),tenant_id TEXT NOT NULL,account_id TEXT NOT NULL,device_id TEXT,event TEXT NOT NULL CHECK(event IN('started','cancelled','completed')),created_at INTEGER NOT NULL DEFAULT(unixepoch()));
CREATE TRIGGER recovery_started AFTER INSERT ON recovery_sagas BEGIN
 INSERT INTO activity(tenant_id,account_id,vault_id,event,reference) VALUES(NEW.tenant_id,NEW.account_id,NEW.vault_id,'recovery.prepared',NEW.id);
 INSERT INTO recovery_notifications(case_id,tenant_id,account_id,device_id,event) SELECT NEW.id,NEW.tenant_id,NEW.account_id,id,'started' FROM devices WHERE tenant_id=NEW.tenant_id AND account_id=NEW.account_id AND active=1;
 INSERT INTO recovery_notifications(case_id,tenant_id,account_id,event) VALUES(NEW.id,NEW.tenant_id,NEW.account_id,'started');
END;
CREATE TRIGGER recovery_changed AFTER UPDATE OF state ON recovery_sagas WHEN OLD.state<>NEW.state BEGIN
 INSERT INTO activity(tenant_id,account_id,vault_id,event,reference) VALUES(NEW.tenant_id,NEW.account_id,NEW.vault_id,'recovery.'||NEW.state,NEW.id);
 INSERT INTO recovery_notifications(case_id,tenant_id,account_id,event) SELECT NEW.id,NEW.tenant_id,NEW.account_id,NEW.state WHERE NEW.state IN('cancelled','completed');
END;
CREATE TRIGGER recovery_activate BEFORE UPDATE OF state ON recovery_sagas WHEN NEW.state='activating' AND OLD.state<>'activating' BEGIN
 SELECT CASE WHEN OLD.state NOT IN('released','proven') OR NEW.expires_at<=unixepoch() OR NEW.api_release IS NULL OR NEW.custodian_release IS NULL OR NOT EXISTS(SELECT 1 FROM memberships WHERE tenant_id=NEW.tenant_id AND account_id=NEW.account_id AND active=1) OR NOT EXISTS(SELECT 1 FROM recovery_packages_v1 p WHERE p.id=NEW.package_id AND p.key_epoch=(SELECT max(key_epoch) FROM recovery_packages_v1 WHERE tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id)) OR (NEW.confirmer_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM devices WHERE tenant_id=NEW.tenant_id AND id=NEW.confirmer_id AND account_id=NEW.account_id AND active=1)) THEN RAISE(ABORT,'invalid_transition') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM devices WHERE id=json_extract(NEW.canonical,'$.targetDeviceId')) OR EXISTS(SELECT 1 FROM device_keys WHERE device_id=json_extract(NEW.canonical,'$.targetDeviceId')) OR EXISTS(SELECT 1 FROM vault_devices WHERE device_id=json_extract(NEW.canonical,'$.targetDeviceId')) OR EXISTS(SELECT 1 FROM device_requests WHERE device_id=json_extract(NEW.canonical,'$.targetDeviceId') OR id=NEW.id) OR EXISTS(SELECT 1 FROM recovery_cases WHERE target_device_id=json_extract(NEW.canonical,'$.targetDeviceId')) OR EXISTS(SELECT 1 FROM recovery_sagas WHERE id<>NEW.id AND json_extract(canonical,'$.targetDeviceId')=json_extract(NEW.canonical,'$.targetDeviceId')) THEN RAISE(ABORT,'idempotency_conflict') END;
 INSERT INTO devices VALUES(NEW.tenant_id,json_extract(NEW.canonical,'$.targetDeviceId'),NEW.account_id,json_extract(NEW.canonical,'$.signingKey'),1);
 INSERT INTO device_keys VALUES(NEW.tenant_id,json_extract(NEW.canonical,'$.targetDeviceId'),json_extract(NEW.canonical,'$.wrappingKey'));
 INSERT INTO vault_devices VALUES(NEW.tenant_id,NEW.vault_id,json_extract(NEW.canonical,'$.targetDeviceId'),1);
 INSERT INTO device_requests(id,code_digest,verification_digest,phrase,device_id,signing_key,wrapping_key,platform,expires_at,state,account_id,tenant_id,vault_id,key_epoch) VALUES(NEW.id,NEW.proof_digest,NEW.request_digest,'Recovered device',json_extract(NEW.canonical,'$.targetDeviceId'),json_extract(NEW.canonical,'$.signingKey'),json_extract(NEW.canonical,'$.wrappingKey'),'other',unixepoch()+600,'approved',NEW.account_id,NEW.tenant_id,NEW.vault_id,json_extract(NEW.canonical,'$.keyEpoch'));

END;
CREATE TRIGGER recovery_terminal BEFORE UPDATE OF state,api_release,custodian_release,confirmer_id ON recovery_sagas WHEN OLD.state IN('cancelled','completed') BEGIN SELECT RAISE(ABORT,'terminal_case'); END;
CREATE TRIGGER recovery_case_pin BEFORE UPDATE OF id,tenant_id,vault_id,account_id,package_id,canonical,request_digest,session_digest,not_before,expires_at,proof_digest,challenge ON recovery_sagas BEGIN SELECT RAISE(ABORT,'immutable_case'); END;
CREATE TRIGGER recovery_case_replace BEFORE INSERT ON recovery_sagas WHEN EXISTS(SELECT 1 FROM recovery_sagas WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'immutable_case'); END;
CREATE TRIGGER recovery_case_delete BEFORE DELETE ON recovery_sagas BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER recovery_package_pin BEFORE UPDATE OF id,tenant_id,vault_id,account_id,key_epoch,canonical,signature ON recovery_packages_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER recovery_package_replace BEFORE INSERT ON recovery_packages_v1 WHEN EXISTS(SELECT 1 FROM recovery_packages_v1 WHERE id=NEW.id OR (tenant_id=NEW.tenant_id AND vault_id=NEW.vault_id AND key_epoch=NEW.key_epoch)) BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER recovery_package_delete BEFORE DELETE ON recovery_packages_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE UNIQUE INDEX recovery_nonce ON recovery_sagas(tenant_id,account_id,json_extract(canonical,'$.nonce'));
CREATE TRIGGER recovery_action_update BEFORE UPDATE ON recovery_browser_actions BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER recovery_action_delete BEFORE DELETE ON recovery_browser_actions BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER recovery_action_replace BEFORE INSERT ON recovery_browser_actions WHEN EXISTS(SELECT 1 FROM recovery_browser_actions WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER recovery_notification_update BEFORE UPDATE ON recovery_notifications BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER recovery_notification_delete BEFORE DELETE ON recovery_notifications BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE TRIGGER recovery_notification_replace BEFORE INSERT ON recovery_notifications WHEN EXISTS(SELECT 1 FROM recovery_notifications WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'append_only'); END;

CREATE TRIGGER recovery_reviewed AFTER UPDATE OF review_required ON recovery_sagas WHEN OLD.review_required=1 AND NEW.review_required=0 BEGIN INSERT INTO activity(tenant_id,account_id,vault_id,event,reference) VALUES(NEW.tenant_id,NEW.account_id,NEW.vault_id,'recovery.reviewed',NEW.id); END;

CREATE TRIGGER recovery_unique_target BEFORE INSERT ON recovery_sagas BEGIN SELECT CASE WHEN EXISTS(SELECT 1 FROM devices WHERE id=json_extract(NEW.canonical,'$.targetDeviceId')) OR EXISTS(SELECT 1 FROM device_keys WHERE device_id=json_extract(NEW.canonical,'$.targetDeviceId')) OR EXISTS(SELECT 1 FROM vault_devices WHERE device_id=json_extract(NEW.canonical,'$.targetDeviceId')) OR EXISTS(SELECT 1 FROM device_requests WHERE device_id=json_extract(NEW.canonical,'$.targetDeviceId') OR id=NEW.id) OR EXISTS(SELECT 1 FROM recovery_cases WHERE target_device_id=json_extract(NEW.canonical,'$.targetDeviceId')) OR EXISTS(SELECT 1 FROM recovery_sagas WHERE id<>NEW.id AND json_extract(canonical,'$.targetDeviceId')=json_extract(NEW.canonical,'$.targetDeviceId')) THEN RAISE(ABORT,'idempotency_conflict') END; END;

CREATE TRIGGER recovery_activation_lock BEFORE UPDATE OF state ON recovery_sagas WHEN OLD.state='activating' AND NEW.state<>'completed' BEGIN SELECT RAISE(ABORT,'invalid_transition'); END;
CREATE TRIGGER recovery_complete BEFORE UPDATE OF state ON recovery_sagas WHEN NEW.state='completed' BEGIN
 SELECT CASE WHEN OLD.state<>'activating' THEN RAISE(ABORT,'invalid_transition') END;
 UPDATE browser_sessions SET revoked=1 WHERE account_id=NEW.account_id;
END;
