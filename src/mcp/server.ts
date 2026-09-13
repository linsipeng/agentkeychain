/**
 * MCP server for agentkeychain.
 *
 * Exposes 5 tools over Model Context Protocol (stdio transport):
 *   - akc_store: encrypt + persist a secret
 *   - akc_get:   decrypt + return a secret (scope-checked)
 *   - akc_list:  list secret names (no values)
 *   - akc_delete: remove a secret
 *   - akc_audit: read audit log (no secret material)
 *
 * The MCP server runs in the same process as the agent.
 * It uses the agent's own identity and the OS-keychain-backed password chain
 * to decrypt secrets on demand. Sub-agents presenting a delegate token
 * (Ed25519-signed) are verified against the issuer's public key without
 * touching the DB.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { timingSafeEqual } from "node:crypto";
import type { Database } from "bun:sqlite";

import { getSecret, storeSecret, listSecrets, deleteSecret } from "../secrets.js";
import { query as queryAuditLog } from "../audit.js";
import { checkScope as hasScope } from "../auth/scope.js";
import type { DelegateToken } from "../auth/delegate.js";
import { verifyDelegateToken } from "../auth/delegate.js";
import { loadIdentityByName, type Identity } from "../identity.js";
import { openDb } from "../vault.js";
import { resolvePassword } from "../util/keychain.js";
import { deriveKEK, hashKEK } from "../crypto/argon2.js";

const IDENTITY_NAME = "default";

/** Resolve and verify the vault KEK without exposing password or KEK material. */
export async function resolveMcpKek(db: Database): Promise<Uint8Array> {
  const password = await resolvePassword();
  if (!password) {
    throw new Error(
      "vault locked — run `agentkeychain setup` so the OS keychain can unlock MCP"
    );
  }

  const meta = db.prepare(
    `SELECT argon2_salt, kek_hash FROM kek_meta WHERE id = 1`
  ).get() as { argon2_salt: Uint8Array; kek_hash: Uint8Array } | undefined;
  if (!meta) throw new Error("vault not initialized — run `agentkeychain init` first");

  const kek = await deriveKEK(password, meta.argon2_salt);
  const actualHash = await hashKEK(kek);
  const expected = Buffer.from(meta.kek_hash);
  const actual = Buffer.from(actualHash);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    kek.fill(0);
    actualHash.fill(0);
    throw new Error("vault unlock failed — OS keychain password does not match this vault");
  }
  actualHash.fill(0);
  return kek;
}

function toolErr(msg: string): { isError: true; content: [{ type: "text"; text: string }] } {
  return {
    isError: true,
    content: [{ type: "text", text: msg }],
  };
}

function toolOk(text: string): { content: [{ type: "text"; text: string }] } {
  return {
    content: [{ type: "text", text }],
  };
}

function _resolveContext(): void {
  // Reserved for future context resolution logic (currently inlined in handlers).
}
void _resolveContext;

export function createServer(): Server {
  const server = new Server(
    { name: "agentkeychain", version: "0.1.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "akc_store",
        description: "Encrypt and store a secret. Returns the secret id, never the value.",
        inputSchema: {
          type: "object",
          properties: {
            name: { type: "string", description: "Secret name (e.g. 'openai-api-key')" },
            value: { type: "string", description: "Secret value (NEVER logged or returned)" },
            scope: {
              type: "array",
              items: { type: "string" },
              description: "Scope tags (e.g. ['openai:write'])",
            },
            tags: {
              type: "array",
              items: { type: "string" },
              description: "Optional free-form tags",
            },
          },
          required: ["name", "value", "scope"],
        },
      },
      {
        name: "akc_get",
        description: "Decrypt and return a secret by name. Scope-checked.",
        inputSchema: {
          type: "object",
          properties: {
            name: { type: "string" },
            delegate_token: {
              type: "string",
              description: "Optional delegate token from another agent",
            },
          },
          required: ["name"],
        },
      },
      {
        name: "akc_list",
        description: "List secret names (never values).",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "akc_delete",
        description: "Remove a secret by name.",
        inputSchema: {
          type: "object",
          properties: { name: { type: "string" } },
          required: ["name"],
        },
      },
      {
        name: "akc_audit",
        description: "Read the audit log (no secret material).",
        inputSchema: {
          type: "object",
          properties: {
            limit: { type: "number", description: "Max entries to return (default 100)" },
          },
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const a = (args ?? {}) as Record<string, unknown>;

    // Resolve the password through the standard chain: AKC_PASSWORD for CI,
    // otherwise the OS keychain populated by init/setup. Raw KEKs are never
    // accepted through environment variables.
    const db = openDb();
    const identity = loadIdentityByName(db, IDENTITY_NAME);
    if (!identity) return toolErr("identity 'default' not found — run `agentkeychain init` first");
    const agent: Identity = identity;

    try {
      const kek = await resolveMcpKek(db);
      try {
        switch (name) {
        case "akc_store": {
          const secretName = String(a["name"] ?? "");
          const value = String(a["value"] ?? "");
          const scope = (a["scope"] as string[] | undefined) ?? [];
          const tags = (a["tags"] as string[] | undefined) ?? [];
          if (!secretName || !value) return toolErr("name and value required");
          const id = await storeSecret(db, {
            name: secretName,
            value,
            scopes: scope,
            metadata: { tags },
            kek,
            agent,
          });
          return toolOk(JSON.stringify({ id, name: secretName }));
        }

        case "akc_get": {
          const secretName = String(a["name"] ?? "");
          if (!secretName) return toolErr("name required");

          // Resolve scopes: self = full, delegated = from token
          let scopes: string[];
          if (typeof a["delegate_token"] === "string") {
            let tok: DelegateToken;
            try {
              tok = JSON.parse(Buffer.from(a["delegate_token"], "base64url").toString("utf8")) as DelegateToken;
            } catch {
              return toolErr("delegate_token is not valid base64url JSON");
            }
            const payload = await verifyDelegateToken(tok, identity.publicKey);
            if (!payload) return toolErr("delegate_token signature invalid or expired");
            scopes = payload.scopes;
          } else {
            scopes = ["*"];
          }

          if (!hasScope(scopes, ["read"])) return toolErr("scope 'read' not granted");

          const meta = listSecrets(db).find((s) => s.name === secretName);
          if (!meta) return toolErr(`secret '${secretName}' not found`);
          if (!hasScope(scopes, meta.scopes)) {
            return toolErr(`scope mismatch: secret requires [${meta.scopes.join(",")}], caller has [${scopes.join(",")}]`);
          }
          const value = await getSecret(db, { name: secretName, kek, agent });
          return toolOk(JSON.stringify({ name: secretName, value }));
        }

        case "akc_list": {
          const items = listSecrets(db);
          return toolOk(JSON.stringify(items.map((s) => ({ name: s.name, scopes: s.scopes }))));
        }

        case "akc_delete": {
          const secretName = String(a["name"] ?? "");
          if (!secretName) return toolErr("name required");
          const ok = deleteSecret(db, { name: secretName, agent, kek });
          return toolOk(JSON.stringify({ deleted: ok, name: secretName }));
        }

        case "akc_audit": {
          const limit = Number(a["limit"] ?? 100);
          const entries = queryAuditLog(db, { limit });
          return toolOk(JSON.stringify(entries));
        }

        default:
          return toolErr(`unknown tool: ${name}`);
        }
      } finally {
        kek.fill(0);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // Do NOT echo back secret material even on error
      return toolErr(`error: ${msg.replace(/sk-[A-Za-z0-9_-]+/g, "[REDACTED]")}`);
    }
  });

  return server;
}

export async function runServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Keep process alive — stdio transport reads from stdin forever
  await new Promise<void>(() => {});
}