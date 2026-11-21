-- Staged browser capabilities are not authenticated sessions. Only a
-- successful exact Passkey completion can promote them into readback scope.
CREATE TABLE auth_continuation_browser_stages (
 challenge_id TEXT PRIMARY KEY REFERENCES auth_continuation_challenges(id),
 session_digest TEXT NOT NULL UNIQUE,
 csrf_digest TEXT NOT NULL
) STRICT;
