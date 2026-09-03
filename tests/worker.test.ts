/**
 * Worker tests — run against an in-memory D1 shim (no network, no CF account).
 * Covers: auth, upsert LWW, tombstone graveyard stamping, pull since, delete.
 */
import { test, expect, beforeEach } from "bun:test";
import worker from "../worker/src/index.ts";

const TOKEN = "test-sync-token-0123456789abcdef";

// ---- Minimal D1 in-memory shim -------------------------------------------
class FakeD1 {
  rows = new Map<string, { name_hint: string; envelope: string; updated_at: number; deleted: number; graveyard_at: number | null }>();
  log: Array<{ ts: number; device_id: string; action: string; row_count: number }> = [];

  prepare(sql: string) {
    const db = this;
    return {
      sql,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      _args: [] as any[],
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      bind(...args: any[]) {
        this._args = args;
        return this;
      },
      async run() {
        if (this.sql.includes("INSERT INTO rows")) {
          const [hint, envelope, updatedAt, deleted] = this._args;
          const existing = db.rows.get(hint);
          if (existing && updatedAt <= existing.updated_at) {
            return { meta: { changes: 0 } }; // LWW: older write is a no-op
          }
          const graveyardAt =
            existing && existing.deleted === 0 && deleted === 1 && updatedAt > existing.updated_at
              ? Math.floor(Date.now() / 1000)
              : (existing?.graveyard_at ?? null);
          db.rows.set(hint, {
            name_hint: hint,
            envelope,
            updated_at: updatedAt,
            deleted,
            graveyard_at: graveyardAt,
          });
          return { meta: { changes: 1 } };
        }
        if (this.sql.includes("UPDATE rows SET deleted = 1")) {
          const [now, hint] = this._args;
          const existing = db.rows.get(hint);
          if (!existing || existing.deleted === 1) return { meta: { changes: 0 } };
          existing.deleted = 1;
          existing.updated_at = now;
          existing.graveyard_at = Math.floor(Date.now() / 1000);
          return { meta: { changes: 1 } };
        }
        return { meta: { changes: 0 } };
      },
      async all<T>(): Promise<{ results: T[] }> {
        if (this.sql.includes("WHERE updated_at > ?")) {
          const [since, limit] = this._args;
          const rows = [...db.rows.values()]
            .filter((r) => r.updated_at > since)
            .sort((a, b) => a.updated_at - b.updated_at)
            .slice(0, limit);
          return { results: rows as T[] };
        }
        return { results: [] };
      },
    };
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function makeEnv(): any {
  return { DB: new FakeD1(), SYNC_TOKEN: TOKEN };
}

function req(
  method: string,
  path: string,
  body?: unknown,
  opts: { noAuth?: boolean; rawAuth?: string } = {}
): Request {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.rawAuth !== undefined) headers["authorization"] = opts.rawAuth;
  else if (!opts.noAuth) headers["authorization"] = `Bearer ${TOKEN}`;
  return new Request(`https://sync.example.test${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

let env: ReturnType<typeof makeEnv>;

beforeEach(() => {
  env = makeEnv();
});

const HINT_A = "a".repeat(64);
const HINT_B = "b".repeat(64);

test("health endpoint: no auth required, no data returned", async () => {
  const res = await worker.fetch(req("GET", "/v1/health", undefined, { noAuth: true }), env);
  expect(res.status).toBe(200);
  const body = (await res.json()) as { ok: boolean };
  expect(body.ok).toBe(true);
});

test("401 without / wrong token", async () => {
  const r1 = await worker.fetch(req("GET", "/v1/rows", undefined, { noAuth: true }), env);
  expect(r1.status).toBe(401);
  const r2 = await worker.fetch(req("GET", "/v1/rows", undefined, { rawAuth: "Bearer wrong" }), env);
  expect(r2.status).toBe(401);
  const r3 = await worker.fetch(req("POST", "/v1/rows", { rows: [] }, { rawAuth: "Bearer wrong" }), env);
  expect(r3.status).toBe(401);
});

test("upsert + pull roundtrip", async () => {
  const res = await worker.fetch(
    req("POST", "/v1/rows", {
      rows: [
        { name_hint: HINT_A, envelope: "nonce:salt:ct1", updated_at: 100, deleted: 0 },
        { name_hint: HINT_B, envelope: "nonce:salt:ct2", updated_at: 101, deleted: 0 },
      ],
    }),
    env
  );
  expect(res.status).toBe(200);
  const written = ((await res.json()) as { written: number }).written;
  expect(written).toBe(2);

  const pull = await worker.fetch(req("GET", "/v1/rows?since=0"), env);
  const { rows } = (await pull.json()) as { rows: Array<{ name_hint: string; updated_at: number }> };
  expect(rows.length).toBe(2);
  expect(rows[0]?.name_hint).toBe(HINT_A);

  const pull2 = await worker.fetch(req("GET", "/v1/rows?since=100"), env);
  const { rows: rows2 } = (await pull2.json()) as { rows: Array<{ name_hint: string }> };
  expect(rows2.length).toBe(1);
  expect(rows2[0]?.name_hint).toBe(HINT_B);
});

test("LWW: older push does not overwrite newer", async () => {
  await worker.fetch(
    req("POST", "/v1/rows", {
      rows: [{ name_hint: HINT_A, envelope: "newer", updated_at: 200, deleted: 0 }],
    }),
    env
  );
  await worker.fetch(
    req("POST", "/v1/rows", {
      rows: [{ name_hint: HINT_A, envelope: "older", updated_at: 100, deleted: 0 }],
    }),
    env
  );
  const pull = await worker.fetch(req("GET", "/v1/rows?since=0"), env);
  const { rows } = (await pull.json()) as { rows: Array<{ envelope: string }> };
  expect(rows[0]?.envelope).toBe("newer");
});

test("tombstone over live row stamps graveyard; delete endpoint works", async () => {
  await worker.fetch(
    req("POST", "/v1/rows", {
      rows: [{ name_hint: HINT_A, envelope: "live", updated_at: 100, deleted: 0 }],
    }),
    env
  );
  const del = await worker.fetch(req("DELETE", `/v1/rows/${HINT_A}`), env);
  const { deleted } = (await del.json()) as { deleted: boolean };
  expect(deleted).toBe(true);

  const db = env.DB as FakeD1;
  const row = db.rows.get(HINT_A);
  expect(row?.deleted).toBe(1);
  expect(row?.graveyard_at).not.toBeNull();
});

test("invalid name_hint rejected", async () => {
  const res = await worker.fetch(
    req("POST", "/v1/rows", {
      rows: [{ name_hint: "openai-key-plaintext!", envelope: "x", updated_at: 1, deleted: 0 }],
    }),
    env
  );
  expect(res.status).toBe(400);
});
