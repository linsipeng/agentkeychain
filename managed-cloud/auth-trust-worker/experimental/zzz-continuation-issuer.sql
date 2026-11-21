-- Local integration only. Never import device registration or sessions from Main.
CREATE TABLE auth_continuation_challenges (
 id TEXT PRIMARY KEY, challenge_digest TEXT NOT NULL,
 account TEXT NOT NULL, tenant TEXT NOT NULL, vault TEXT NOT NULL, credential TEXT NOT NULL,
 prior_decision_id TEXT NOT NULL REFERENCES auth_genesis_decisions(id),
 intent_digest TEXT NOT NULL, expires INTEGER NOT NULL
) STRICT;
CREATE TABLE auth_continuation_decisions (
 id TEXT PRIMARY KEY REFERENCES auth_continuation_challenges(id),
 intent_digest TEXT NOT NULL UNIQUE, canonical TEXT NOT NULL, signature TEXT NOT NULL
) STRICT;
