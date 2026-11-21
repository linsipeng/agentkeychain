-- Local integration only, intentionally not in the deployed Auth migration set.
-- No API/Main data import and no application-facing credential pin setter.
CREATE TABLE auth_genesis_pins (
 account TEXT NOT NULL, tenant TEXT NOT NULL, vault TEXT NOT NULL,
 handle TEXT NOT NULL, credential TEXT NOT NULL UNIQUE,
 cose_key TEXT NOT NULL, counter INTEGER NOT NULL CHECK(counter>=0),
 active INTEGER NOT NULL CHECK(active IN(0,1)),
 PRIMARY KEY(account,tenant,vault)
) STRICT;
CREATE TABLE auth_genesis_challenges (
 id TEXT PRIMARY KEY, challenge_digest TEXT NOT NULL,
 account TEXT NOT NULL, tenant TEXT NOT NULL, vault TEXT NOT NULL,
 credential TEXT NOT NULL, grant_digest TEXT NOT NULL, roster_digest TEXT NOT NULL, expires INTEGER NOT NULL
) STRICT;
CREATE TABLE auth_genesis_decisions (
 id TEXT PRIMARY KEY REFERENCES auth_genesis_challenges(id),
 grant_digest TEXT NOT NULL UNIQUE, canonical TEXT NOT NULL, signature TEXT NOT NULL
) STRICT;
