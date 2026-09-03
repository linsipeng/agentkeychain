/**
 * agentkeychain sync worker — BYO Cloudflare ciphertext sync endpoint.
 *
 * Deployed into the USER'S OWN Cloudflare account via `agentkeychain sync init`
 * (wrangler). Stores ONLY ciphertext envelopes + irreversible name hints.
 * Zero-knowledge: the worker never sees plaintext names or values.
 *
 * Auth: single bearer token (SYNC_TOKEN secret), 256-bit random, set at deploy.
 */
export interface Env {
  DB: D1Database;
  SYNC_TOKEN: string;
}

interface RowUpsert {
  name_hint: string;
  envelope: string; // base64(nonce:salt:ciphertext) — self-contained, decryptable only with master password
  updated_at: number;
  deleted: 0 | 1;
}

const NAME_HINT_RE = /^[0-9a-f]{64}$/; // BLAKE2b-256 hex

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function err(message: string, status: number): Response {
  return json({ error: message }, status);
}

async function checkAuth(request: Request, env: Env): Promise<boolean> {
  const header = request.headers.get("authorization") ?? "";
  const expected = `Bearer ${env.SYNC_TOKEN}`;
  // Timing-safe-ish compare (lengths differ → reject fast; equal length → compare bytes)
  if (header.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= (header.charCodeAt(i) ?? 0) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/v1/health") {
      return json({ ok: true, service: "agentkeychain-sync", version: 1 });
    }

    if (!(await checkAuth(request, env))) {
      return err("unauthorized", 401);
    }

    if (url.pathname === "/v1/rows" && request.method === "POST") {
      let body: { rows?: RowUpsert[] };
      try {
        body = (await request.json()) as { rows?: RowUpsert[] };
      } catch {
        return err("invalid json body", 400);
      }
      const rows = body.rows;
      if (!Array.isArray(rows) || rows.length === 0) {
        return err("rows[] required", 400);
      }
      if (rows.length > 500) {
        return err("max 500 rows per request", 400);
      }
      for (const row of rows) {
        if (typeof row.name_hint !== "string" || !NAME_HINT_RE.test(row.name_hint)) {
          return err("name_hint must be 64-char hex", 400);
        }
        if (typeof row.envelope !== "string" || row.envelope.length === 0 || row.envelope.length > 64_000) {
          return err("envelope must be non-empty (<64KB)", 400);
        }
        if (typeof row.updated_at !== "number" || !Number.isFinite(row.updated_at)) {
          return err("updated_at must be a number", 400);
        }
      }

      const stmt = env.DB.prepare(
        `INSERT INTO rows (name_hint, envelope, updated_at, deleted, graveyard_at)
         VALUES (?, ?, ?, ?, NULL)
         ON CONFLICT(name_hint) DO UPDATE SET
           envelope = excluded.envelope,
           updated_at = excluded.updated_at,
           deleted = excluded.deleted,
           graveyard_at = CASE
             WHEN excluded.updated_at > rows.updated_at AND rows.deleted = 0 AND excluded.deleted = 1
             THEN unixepoch()
             ELSE rows.graveyard_at
           END
         WHERE excluded.updated_at > rows.updated_at`
      );
      // LWW: the WHERE clause makes older writes no-ops. Graveyard: when a live
      // row is overwritten by a tombstone, stamp graveyard_at (purged after 30d).
      const results = await Promise.all(
        rows.map((r) => stmt.bind(r.name_hint, r.envelope, Math.floor(r.updated_at), r.deleted).run())
      );
      const written = results.reduce<number>((acc, r) => acc + (r.meta.changes ?? 0), 0);
      return json({ ok: true, received: rows.length, written });
    }

    if (url.pathname === "/v1/rows" && request.method === "GET") {
      const sinceRaw = url.searchParams.get("since") ?? "0";
      const since = Number(sinceRaw);
      if (!Number.isFinite(since) || since < 0) {
        return err("since must be a non-negative number", 400);
      }
      const limit = Math.min(Number(url.searchParams.get("limit") ?? 500), 500);
      const { results } = await env.DB.prepare(
        `SELECT name_hint, envelope, updated_at, deleted FROM rows
         WHERE updated_at > ? ORDER BY updated_at ASC LIMIT ?`
      )
        .bind(Math.floor(since), limit)
        .all<RowUpsert>();
      return json({ rows: results ?? [] });
    }

    const deleteMatch = /^\/v1\/rows\/([0-9a-f]{64})$/.exec(url.pathname);
    if (deleteMatch && request.method === "DELETE") {
      const now = Math.floor(Date.now() / 1000);
      const result = await env.DB.prepare(
        `UPDATE rows SET deleted = 1, updated_at = ?, graveyard_at = unixepoch()
         WHERE name_hint = ? AND deleted = 0`
      )
        .bind(now, deleteMatch[1])
        .run();
      return json({ ok: true, deleted: (result.meta.changes ?? 0) > 0 });
    }

    return err("not found", 404);
  },
} satisfies ExportedHandler<Env>;
