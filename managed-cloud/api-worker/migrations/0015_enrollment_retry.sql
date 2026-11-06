CREATE TRIGGER pairing_confirmation_retry BEFORE INSERT ON pairing_confirmations BEGIN
 SELECT CASE WHEN EXISTS(SELECT 1 FROM pairing_confirmations WHERE request_id=NEW.request_id AND (canonical<>NEW.canonical OR signature<>NEW.signature OR issuer_device_id<>NEW.issuer_device_id)) THEN RAISE(ABORT,'idempotency_conflict') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM pairing_confirmations WHERE request_id=NEW.request_id) THEN RAISE(IGNORE) END;
END;
CREATE TRIGGER trusted_bundle_expiry BEFORE INSERT ON trusted_enrollment_bundles BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM enrollment_grants WHERE id=NEW.request_id AND json_extract(canonical,'$.expiresAt')>unixepoch()) THEN RAISE(ABORT,'not_found') END;
END;
CREATE TRIGGER package_expiry BEFORE INSERT ON device_key_packages BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM enrollment_grants WHERE id=NEW.grant_id AND json_extract(canonical,'$.expiresAt')>unixepoch()) THEN RAISE(ABORT,'not_found') END;
END;
