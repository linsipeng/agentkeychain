/**
 * Run vault schema migration. Idempotent — safe to call repeatedly.
 */
import { Database } from "bun:sqlite";
import { SCHEMA_SQL } from "./schema.ts";

export function migrate(db: Database): void {
  db.exec(SCHEMA_SQL);
}
