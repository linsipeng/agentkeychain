-- Authentication artifacts: 24 hours after expiry, maximum 32/table/sweep.
-- Only rejected events may expire, after 30 days. All successful/security events
-- remain append-only indefinitely pending the Phase 2D archival design.
DROP TRIGGER auth_audit_no_delete;
CREATE TRIGGER auth_audit_no_delete BEFORE DELETE ON auth_audit
WHEN OLD.event<>'rejected' OR OLD.created_at>=unixepoch()-2592000
BEGIN SELECT RAISE(ABORT,'append_only'); END;
CREATE INDEX verification_expiry ON account_verifications(expires_at,id);
CREATE INDEX challenge_verification ON webauthn_challenges(verification_id);
CREATE INDEX browser_absolute_expiry ON browser_sessions(absolute_expires,digest);
CREATE INDEX browser_idle_expiry ON browser_sessions(last_seen,digest);
CREATE INDEX bootstrap_expiry ON consumed_bootstraps(expires_at,digest);
CREATE INDEX rejected_audit_expiry ON auth_audit(created_at,id) WHERE event='rejected';
