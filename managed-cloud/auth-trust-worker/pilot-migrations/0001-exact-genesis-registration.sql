-- Separate pilot migration only; never apply to normal Auth.
CREATE TABLE pilot_genesis_registration (
 id TEXT PRIMARY KEY, account TEXT NOT NULL, tenant TEXT NOT NULL, vault TEXT NOT NULL,
 grant_digest TEXT NOT NULL, roster_digest TEXT NOT NULL, browser_digest TEXT NOT NULL,
 handle TEXT NOT NULL, challenge_digest TEXT NOT NULL, expires INTEGER NOT NULL,
 credential TEXT UNIQUE, cose_key TEXT, counter INTEGER,
 CHECK ((credential IS NULL AND cose_key IS NULL AND counter IS NULL) OR
        (credential IS NOT NULL AND cose_key IS NOT NULL AND counter>=0))
) STRICT;

CREATE TRIGGER pilot_genesis_registration_pin AFTER UPDATE OF credential ON pilot_genesis_registration
WHEN OLD.credential IS NULL AND NEW.credential IS NOT NULL
BEGIN
 INSERT INTO auth_genesis_pins VALUES
 (NEW.account,NEW.tenant,NEW.vault,NEW.handle,NEW.credential,NEW.cose_key,NEW.counter,1);
END;

CREATE TABLE pilot_genesis_browser_guard (
 challenge_id TEXT PRIMARY KEY,
 browser_digest TEXT NOT NULL,
 finalize INTEGER NOT NULL DEFAULT 0 CHECK(finalize IN(0,1))
) STRICT;

CREATE TRIGGER pilot_genesis_challenge_exact BEFORE INSERT ON auth_genesis_challenges
WHEN NOT EXISTS (
 SELECT 1 FROM pilot_genesis_registration r JOIN pilot_genesis_browser_guard b
 ON b.browser_digest=r.browser_digest AND b.challenge_id=NEW.id AND b.finalize=0
 WHERE r.account=NEW.account AND r.tenant=NEW.tenant
 AND r.vault=NEW.vault AND r.credential=NEW.credential AND r.grant_digest=NEW.grant_digest
 AND r.roster_digest=NEW.roster_digest AND NEW.expires<=r.expires AND r.expires>unixepoch()
)
BEGIN SELECT RAISE(ABORT,'pilot_genesis_intent_required'); END;

CREATE TRIGGER pilot_genesis_decision_exact BEFORE INSERT ON auth_genesis_decisions
WHEN NOT EXISTS (
 SELECT 1 FROM auth_genesis_challenges c JOIN pilot_genesis_registration r
 ON r.account=c.account AND r.tenant=c.tenant AND r.vault=c.vault AND r.credential=c.credential
 AND r.grant_digest=c.grant_digest AND r.roster_digest=c.roster_digest
 JOIN pilot_genesis_browser_guard b ON b.challenge_id=c.id AND b.browser_digest=r.browser_digest AND b.finalize=1
 WHERE c.id=NEW.id AND c.grant_digest=NEW.grant_digest AND r.expires>unixepoch()
)
BEGIN SELECT RAISE(ABORT,'pilot_genesis_intent_required'); END;
