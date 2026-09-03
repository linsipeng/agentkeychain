-- agentkeychain sync — D1 schema (v1)
CREATE TABLE IF NOT EXISTS rows (
  name_hint    TEXT PRIMARY KEY,  -- BLAKE2b-256 keyed hash of the real name (irreversible)
  envelope     TEXT NOT NULL,     -- base64(nonce:salt:ciphertext), decryptable only with master password
  updated_at   INTEGER NOT NULL,  -- unix seconds, source of truth for LWW
  deleted      INTEGER NOT NULL DEFAULT 0,
  graveyard_at INTEGER            -- set when a live row is overwritten by a tombstone (purged after 30d)
);
CREATE INDEX IF NOT EXISTS idx_rows_updated ON rows(updated_at);

CREATE TABLE IF NOT EXISTS sync_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
  device_id  TEXT NOT NULL,
  action     TEXT NOT NULL,       -- push | pull | delete
  row_count  INTEGER NOT NULL
);
