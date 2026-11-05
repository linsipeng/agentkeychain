-- A requestRef is issued only after signature verification and wrapping-key possession.
CREATE TABLE recovery_target_challenges (
    digest TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    proof_digest TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX recovery_target_challenge_expiry ON recovery_target_challenges(expires_at);
-- Earlier local handoffs did not prove wrapping-key possession; fail them closed.
DELETE FROM recovery_targets;
-- Direct-target bootstrap credentials issued by the previous implementation
-- must not survive the stronger handoff contract. Normal sessions are preserved.
UPDATE recovery_sessions SET revoked=1;
