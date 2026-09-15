/**
 * MCP server for agentkeychain.
 *
 * Exposes 7 tools over Model Context Protocol (stdio transport):
 *   - akc_request_store: open a local secure-entry form + infer scope
 *   - akc_request_password_check: privately verify one remembered master password
 *   - akc_store: advanced compatibility path for trusted clients
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
import type { Database } from "bun:sqlite";

import { getSecret, storeSecret, listSecrets, deleteSecret } from "../secrets.js";
import { query as queryAuditLog } from "../audit.js";
import { checkScope as hasScope } from "../auth/scope.js";
import type { DelegateToken } from "../auth/delegate.js";
import { verifyDelegateToken } from "../auth/delegate.js";
import { loadIdentityByName, type Identity } from "../identity.js";
import { openDb } from "../vault.js";
import { resolveVaultKek } from "../unlock.js";
import { requestSecureStore } from "../capture/store.js";
import { requestMasterPasswordCheck } from "../password-check/check.js";
import type { PasswordCheckHandle } from "../password-check/server.js";
import { VERSION } from "../index.js";

const IDENTITY_NAME = "default";

/** Backward-compatible export for callers/tests that used the MCP-specific name. */
export const resolveMcpKek = resolveVaultKek;

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

/** Run one MCP operation with a database handle that always closes. */
export async function withVaultDatabase<T>(
  // Function-type parameters are declarations; ESLint still treats the name as unused.
  // eslint-disable-next-line no-unused-vars
  operation: (db: Database) => Promise<T>,
  open: () => Database = openDb
): Promise<T> {
  const db = open();
  try {
    return await operation(db);
  } finally {
    db.close();
  }
}

function _resolveContext(): void {
  // Reserved for future context resolution logic (currently inlined in handlers).
}
void _resolveContext;

export interface McpServerOptions {
  requestPasswordCheck?: () => Promise<PasswordCheckHandle>;
}

export function createServer(options: McpServerOptions = {}): Server {
  const requestPasswordCheck = options.requestPasswordCheck ?? requestMasterPasswordCheck;
  const server = new Server(
    { name: "agentkeychain", version: VERSION },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "akc_request_store",
        description: "Open a one-time local secure-entry form. Use this by default so credential values never enter chat or MCP arguments. Scope is inferred automatically.",
        inputSchema: {
          type: "object",
          properties: {
            name: { type: "string", description: "Human-readable credential name" },
            purpose: { type: "string", description: "Natural-language intended use" },
          },
          required: ["name", "purpose"],
        },
      },
      {
        name: "akc_request_password_check",
        description: "Open a one-time local form that checks a remembered master password without sending it through chat or MCP arguments and without changing the vault or OS keychain.",
        inputSchema: { type: "object", properties: {}, additionalProperties: false },
      },
      {
        name: "akc_store",
        description: "Advanced compatibility tool that accepts a secret value in MCP arguments. Prefer akc_request_store for human input.",
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

    if (name === "akc_request_password_check") {
      if (Object.keys(a).length > 0) return toolErr("this tool accepts no arguments");
      try {
        const check = await requestPasswordCheck();
        const result = await check.done;
        return toolOk(JSON.stringify({
          status: result,
          matches: result === "correct" ? true : result === "incorrect" ? false : null,
          message: result === "correct"
            ? "The remembered master password is correct."
            : result === "incorrect"
              ? "The remembered master password is incorrect. The vault and OS keychain were not changed."
              : "The local password check did not complete.",
        }));
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return toolErr(`error: ${msg.replace(/sk-[A-Za-z0-9_-]+/g, "[REDACTED]")}`);
      }
    }

    return withVaultDatabase(async (db) => {

    // Resolve the password through the standard chain: AKC_PASSWORD for CI,
    // otherwise the OS keychain populated by init/setup. Raw KEKs are never
    // accepted through environment variables.
    const identity = loadIdentityByName(db, IDENTITY_NAME);
    if (!identity) return toolErr("identity 'default' not found — run `agentkeychain init` first");
    const agent: Identity = identity;

    try {
      const kek = await resolveMcpKek(db);
      try {
        switch (name) {
        case "akc_request_store": {
          const secretName = String(a["name"] ?? "").trim();
          const purpose = String(a["purpose"] ?? "").trim();
          if (!secretName || !purpose) return toolErr("name and purpose required");
          const capture = await requestSecureStore({ name: secretName, purpose });
          return toolOk(JSON.stringify({
            status: "waiting_for_local_input",
            name: secretName,
            permission: capture.permission,
            message: "A one-time secure form was opened locally. The credential value will not be returned to MCP.",
          }));
        }

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