-- Experimental, excluded from deployed Auth schema; never materialize from Main.
-- This slice reads Auth-owned sessions and grants; it does not create them.
CREATE TABLE auth_genesis_view_sessions (
 session_digest TEXT PRIMARY KEY, csrf_digest TEXT NOT NULL,
 account TEXT NOT NULL, tenant TEXT NOT NULL, vault TEXT NOT NULL,
 approval_reader INTEGER NOT NULL CHECK(approval_reader IN(0,1)),
 revoked INTEGER NOT NULL CHECK(revoked IN(0,1)),
 expires INTEGER NOT NULL
) STRICT;
CREATE TABLE auth_genesis_view_grants (
 session_digest TEXT NOT NULL REFERENCES auth_genesis_view_sessions(session_digest),
 intent_digest TEXT NOT NULL,
 issued INTEGER NOT NULL, expires INTEGER NOT NULL CHECK(expires>issued AND expires-issued<=120),
 PRIMARY KEY(session_digest,intent_digest)
) STRICT;
