/**
 * Vault database schema.
 *
 * 4 tables per PRD Section 6:
 *   - identities: Agent identities (Ed25519 keypair + scopes)
 *   - secrets:    Encrypted credentials
 *   - audit_log:  Append-only audit trail with Ed25519 signatures
 *   - kek_meta:   KEK metadata (1 row only)
 */
export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS kek_meta (
  id            INTEGER PRIMARY KEY DEFAULT 1,
  argon2_salt   BLOB NOT NULL,
  argon2_params TEXT NOT NULL,
  kek_hash      BLOB NOT NULL,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  CHECK (id = 1)
);

CREATE TABLE IF NOT EXISTS identities (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL UNIQUE,
  public_key      BLOB NOT NULL,
  encrypted_priv  BLOB NOT NULL,
  priv_nonce      BLOB NOT NULL,
  scopes          TEXT NOT NULL,
  parent_id       TEXT,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER,
  revoked_at      INTEGER
);

CREATE TABLE IF NOT EXISTS secrets (
  name          TEXT PRIMARY KEY,
  ciphertext    BLOB NOT NULL,
  nonce         BLOB NOT NULL,
  scopes        TEXT NOT NULL,
  metadata      TEXT,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  version       INTEGER NOT NULL DEFAULT 1,
  deleted_at    INTEGER
);

CREATE TABLE IF NOT EXISTS audit_log (
  seq           INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            INTEGER NOT NULL,
  agent_id      TEXT NOT NULL,
  action        TEXT NOT NULL,
  target        TEXT,
  success       INTEGER NOT NULL,
  prev_hash     BLOB,
  sig           BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);
`;
