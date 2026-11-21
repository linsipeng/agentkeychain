-- A successor is a fresh, unapproved request, never an extension of a grant.
CREATE TABLE enrollment_successors (
 predecessor_id TEXT PRIMARY KEY REFERENCES enrollment_retirements(request_id),
 successor_id TEXT NOT NULL UNIQUE REFERENCES device_requests(id)
);
CREATE TRIGGER enrollment_successor_authorize BEFORE INSERT ON enrollment_successors BEGIN
 SELECT CASE WHEN EXISTS(SELECT 1 FROM enrollment_successors WHERE predecessor_id=NEW.predecessor_id OR successor_id=NEW.successor_id)
   OR NOT EXISTS(SELECT 1 FROM enrollment_retirements e
    JOIN device_requests a ON a.id=e.request_id AND a.state='denied'
    JOIN device_requests b ON b.id=NEW.successor_id AND b.id<>a.id AND b.device_id<>a.device_id
    WHERE e.request_id=NEW.predecessor_id AND b.state='pending' AND b.account_id IS NULL AND b.tenant_id IS NULL AND b.vault_id IS NULL
      AND b.signing_key=a.signing_key AND b.wrapping_key=a.wrapping_key AND b.platform=a.platform)
 THEN RAISE(ABORT,'idempotency_conflict') END;
END;
CREATE TRIGGER enrollment_successor_pin BEFORE UPDATE ON enrollment_successors BEGIN SELECT RAISE(ABORT,'immutable_successor'); END;
CREATE TRIGGER enrollment_successor_retain BEFORE DELETE ON enrollment_successors BEGIN SELECT RAISE(ABORT,'immutable_successor'); END;
CREATE TRIGGER enrollment_successor_request_retain BEFORE DELETE ON device_requests
 WHEN EXISTS(SELECT 1 FROM enrollment_successors WHERE successor_id=OLD.id)
 BEGIN SELECT RAISE(ABORT,'immutable_successor'); END;
