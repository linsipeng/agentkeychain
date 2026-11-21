-- Auth-owned grants, never provisioned by Main. Scope is one exact receipt.
CREATE TABLE auth_continuation_view_grants (
 session_digest TEXT NOT NULL REFERENCES auth_genesis_view_sessions(session_digest),
 intent_digest TEXT NOT NULL,
 credential TEXT NOT NULL REFERENCES auth_genesis_pins(credential),
 issued INTEGER NOT NULL,
 expires INTEGER NOT NULL CHECK(expires>issued AND expires-issued<=120),
 PRIMARY KEY(session_digest,intent_digest)
) STRICT;
