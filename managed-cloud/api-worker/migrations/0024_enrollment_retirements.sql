-- A signed retirement is permanent evidence about exactly one previously
-- unapproved request. It is not a grant or permission to create a successor.
CREATE TABLE enrollment_retirements (
 request_id TEXT PRIMARY KEY REFERENCES device_requests(id) ON DELETE RESTRICT,
 retired_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE VIEW retirable_expired_device_requests AS
 SELECT r.id
 FROM device_requests r
 WHERE r.expires_at<=unixepoch() AND r.state IN('pending','bound','denied')
   AND NOT EXISTS(SELECT 1 FROM enrollment_grants g WHERE g.id=r.id OR g.device_id=r.device_id)
   AND NOT EXISTS(SELECT 1 FROM devices d WHERE d.id=r.device_id)
   AND NOT EXISTS(SELECT 1 FROM device_keys k WHERE k.device_id=r.device_id)
   AND NOT EXISTS(SELECT 1 FROM vault_devices v WHERE v.device_id=r.device_id)
   AND NOT EXISTS(SELECT 1 FROM device_actions a WHERE a.action='approve' AND a.target=r.id);
CREATE TRIGGER enrollment_retirement_authorize BEFORE INSERT ON enrollment_retirements BEGIN
 SELECT CASE WHEN EXISTS(SELECT 1 FROM enrollment_retirements WHERE request_id=NEW.request_id)
   OR NOT EXISTS(SELECT 1 FROM retirable_expired_device_requests WHERE id=NEW.request_id)
  THEN RAISE(ABORT,'not_found') END;
END;
CREATE TRIGGER enrollment_retirement_accept AFTER INSERT ON enrollment_retirements BEGIN
 UPDATE device_requests SET state='denied' WHERE id=NEW.request_id;
END;
CREATE TRIGGER enrollment_retirement_retain BEFORE DELETE ON enrollment_retirements BEGIN SELECT RAISE(ABORT,'immutable_retirement'); END;
CREATE TRIGGER enrollment_retirement_pin BEFORE UPDATE ON enrollment_retirements BEGIN SELECT RAISE(ABORT,'immutable_retirement'); END;
CREATE TRIGGER enrollment_retired_state_pin BEFORE UPDATE OF state ON device_requests
 WHEN NEW.state<>'denied' AND EXISTS(SELECT 1 FROM enrollment_retirements WHERE request_id=OLD.id)
 BEGIN SELECT RAISE(ABORT,'immutable_retirement'); END;
CREATE TRIGGER enrollment_retired_request_retain BEFORE DELETE ON device_requests
 WHEN EXISTS(SELECT 1 FROM enrollment_retirements WHERE request_id=OLD.id)
 BEGIN SELECT RAISE(ABORT,'immutable_retirement'); END;
