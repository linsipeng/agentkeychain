-- Synthetic Auth state; never apply to production. No credential/key plaintext.
CREATE TABLE auth_continuation_handoffs (
 locator TEXT PRIMARY KEY, intent_digest TEXT NOT NULL UNIQUE, exact_digest TEXT NOT NULL,
 code_mac TEXT NOT NULL, stage_json TEXT NOT NULL, expires INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5), claimed_session TEXT
) STRICT;
CREATE TABLE auth_continuation_handoff_browsers (
 session_digest TEXT PRIMARY KEY, csrf_digest TEXT NOT NULL,
 locator TEXT NOT NULL REFERENCES auth_continuation_handoffs(locator), expires INTEGER NOT NULL
) STRICT;
CREATE TRIGGER auth_continuation_handoff_pin BEFORE UPDATE OF locator,intent_digest,exact_digest,code_mac,stage_json,expires ON auth_continuation_handoffs
 BEGIN SELECT RAISE(ABORT,'immutable_handoff'); END;
CREATE TRIGGER auth_continuation_handoff_claim_pin BEFORE UPDATE OF claimed_session ON auth_continuation_handoffs
 WHEN OLD.claimed_session IS NOT NULL
 BEGIN SELECT RAISE(ABORT,'immutable_handoff'); END;
