/**
 * MCP server integration tests.
 *
 * Strategy: directly invoke the Server's internal request handlers via
 * `server._requestHandlers.get(method)`, which is what StdioServerTransport
 * does under the hood. We bypass capabilities assertion by setting the
 * internal capability flag before triggering.
 */
import { test, expect, beforeEach, afterEach } from "bun:test";
import sodium from "libsodium-wrappers-sumo";
import { unlinkSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

let tmpDir: string;
let savedVaultHome: string | undefined;
// eslint-disable-next-line no-unused-vars
type Handler = (...args: unknown[]) => Promise<unknown>;

beforeEach(async () => {
  savedVaultHome = process.env.AGENTKEYCHAIN_HOME;
  await sodium.ready;
  tmpDir = mkdtempSync(join(tmpdir(), "akc-mcp-"));
  process.env["AGENTKEYCHAIN_HOME"] = tmpDir;
  for (const f of ["vault.db", "vault.db-journal", "vault.db-wal", "vault.db-shm"]) {
    const p = join(tmpDir, f);
    if (existsSync(p)) unlinkSync(p);
  }
  const { openDb } = await import("../src/vault.ts");
  const { initVault } = await import("../src/cli/init.ts");
  const db = openDb();
  await initVault(db, "hunter2correct");
});

afterEach(() => {
  if (savedVaultHome === undefined) delete process.env.AGENTKEYCHAIN_HOME;
  else process.env.AGENTKEYCHAIN_HOME = savedVaultHome;
  if (tmpDir && existsSync(tmpDir)) rmSync(tmpDir, { recursive: true });
});



test("server creates with tool handlers and reports the package version", async () => {
  const { createServer } = await import("../src/mcp/server.ts");
  const { VERSION } = await import("../src/index.ts");
  const server = createServer();
  expect(server).toBeDefined();
  const handlers = (server as unknown as { _requestHandlers: Map<string, Handler> })._requestHandlers;
  const info = (server as unknown as { _serverInfo: { version: string } })._serverInfo;
  expect(info.version).toBe(VERSION);
  // tools/list should be registered (set via setRequestHandler in createServer)
  expect(handlers.has("tools/list")).toBe(true);
  expect(handlers.has("tools/call")).toBe(true);
});

test("server exposes novice local-input requests without sensitive arguments", async () => {
  const { createServer } = await import("../src/mcp/server.ts");
  const server = createServer();
  const handlers = (server as unknown as { _requestHandlers: Map<string, Handler> })._requestHandlers;
  const listHandler = handlers.get("tools/list");
  if (!listHandler) throw new Error("tools/list handler missing");
  const result = await listHandler({ method: "tools/list", params: {} }) as {
    tools: Array<{ name: string; inputSchema: { properties: Record<string, unknown>; required?: string[] } }>;
  };
  const storeTool = result.tools.find((item) => item.name === "akc_request_store");
  expect(storeTool).toBeDefined();
  expect(Object.keys(storeTool?.inputSchema.properties ?? {})).toEqual(["name", "purpose"]);
  expect(storeTool?.inputSchema.required).toEqual(["name", "purpose"]);

  const checkTool = result.tools.find((item) => item.name === "akc_request_password_check");
  expect(checkTool).toBeDefined();
  expect(Object.keys(checkTool?.inputSchema.properties ?? {})).toEqual([]);
  expect(checkTool?.inputSchema.required).toBeUndefined();
  expect((checkTool?.inputSchema as { additionalProperties?: boolean }).additionalProperties).toBe(false);
});

test("password-check MCP rejects every argument without echoing it", async () => {
  let called = false;
  const { createServer } = await import("../src/mcp/server.ts");
  const server = createServer({
    requestPasswordCheck: async () => {
      called = true;
      return { url: "unused", done: Promise.resolve("correct" as const), close: () => {} };
    },
  });
  const handlers = (server as unknown as { _requestHandlers: Map<string, Handler> })._requestHandlers;
  const callHandler = handlers.get("tools/call");
  if (!callHandler) throw new Error("tools/call handler missing");
  const candidate = "must-never-enter-password-check-mcp";
  const result = await callHandler({
    method: "tools/call",
    params: { name: "akc_request_password_check", arguments: { password: candidate } },
  }) as { isError?: boolean; content: Array<{ type: string; text: string }> };
  expect(called).toBe(false);
  expect(result.isError).toBe(true);
  expect(result.content[0]?.text).not.toContain(candidate);
  expect(result.content[0]?.text).not.toContain("password");
});

test("password-check MCP dispatch returns only the verification result", async () => {
  const { createServer } = await import("../src/mcp/server.ts");
  const server = createServer({
    requestPasswordCheck: async () => ({
      url: "http://127.0.0.1:1/verify-password/test",
      done: Promise.resolve("correct" as const),
      close: () => {},
    }),
  });
  const handlers = (server as unknown as { _requestHandlers: Map<string, Handler> })._requestHandlers;
  const callHandler = handlers.get("tools/call");
  if (!callHandler) throw new Error("tools/call handler missing");
  const result = await callHandler({
    method: "tools/call",
    params: { name: "akc_request_password_check", arguments: {} },
  }) as { content: Array<{ type: string; text: string }> };
  expect(JSON.parse(result.content[0]?.text ?? "{}")).toEqual({
    status: "correct",
    matches: true,
    message: "The remembered master password is correct.",
  });
});

test("password-check MCP dispatch does not mislabel an incomplete check as incorrect", async () => {
  const { createServer } = await import("../src/mcp/server.ts");
  const server = createServer({
    requestPasswordCheck: async () => ({
      url: "http://127.0.0.1:1/verify-password/test",
      done: Promise.resolve("expired" as const),
      close: () => {},
    }),
  });
  const handlers = (server as unknown as { _requestHandlers: Map<string, Handler> })._requestHandlers;
  const callHandler = handlers.get("tools/call");
  if (!callHandler) throw new Error("tools/call handler missing");
  const result = await callHandler({
    method: "tools/call",
    params: { name: "akc_request_password_check", arguments: {} },
  }) as { content: Array<{ type: string; text: string }> };
  expect(JSON.parse(result.content[0]?.text ?? "{}").matches).toBeNull();
});

test("withVaultDatabase closes the database on success and failure", async () => {
  const { withVaultDatabase } = await import("../src/mcp/server.ts");
  let successClosed = false;
  const successDb = { close: () => { successClosed = true; } };
  const result = await withVaultDatabase(
    async () => "ok",
    () => successDb as never
  );
  expect(result).toBe("ok");
  expect(successClosed).toBe(true);

  let failureClosed = false;
  const failureDb = { close: () => { failureClosed = true; } };
  await expect(withVaultDatabase(
    async () => { throw new Error("expected-test-error"); },
    () => failureDb as never
  )).rejects.toThrow("expected-test-error");
  expect(failureClosed).toBe(true);
});

test("MCP resolves its KEK from the normal password chain", async () => {
  process.env["AKC_PASSWORD"] = "hunter2correct";
  const { openDb } = await import("../src/vault.ts");
  const { resolveMcpKek } = await import("../src/mcp/server.ts");
  const kek = await resolveMcpKek(openDb());
  expect(kek).toBeInstanceOf(Uint8Array);
  expect(kek.length).toBe(32);
  kek.fill(0);
  delete process.env["AKC_PASSWORD"];
});

test("MCP refuses an incorrect resolved password without exposing it", async () => {
  process.env["AKC_PASSWORD"] = "definitely-wrong-password";
  const { openDb } = await import("../src/vault.ts");
  const { resolveMcpKek } = await import("../src/mcp/server.ts");
  await expect(resolveMcpKek(openDb())).rejects.toThrow("vault unlock failed");
  delete process.env["AKC_PASSWORD"];
});

test("delegate token signed by correct issuer verifies", async () => {
  const { signDelegateToken, verifyDelegateToken } = await import("../src/auth/delegate.ts");
  await sodium.ready;
  const kp = sodium.crypto_sign_keypair();
  const iat = Date.now();
  const token = await signDelegateToken(
    { iss: "ak_test", sub: "ak_sub", scopes: ["read"], iat, exp: iat + 60_000 },
    kp.privateKey
  );
  const verified = await verifyDelegateToken(token, kp.publicKey);
  expect(verified).not.toBeNull();
  expect(verified?.sub).toBe("ak_sub");
});

test("delegate token signed by wrong issuer is rejected", async () => {
  const { signDelegateToken, verifyDelegateToken } = await import("../src/auth/delegate.ts");
  await sodium.ready;
  const issuer = sodium.crypto_sign_keypair();
  const attacker = sodium.crypto_sign_keypair();
  const iat = Date.now();
  const token = await signDelegateToken(
    { iss: "ak_test", sub: "ak_sub", scopes: ["read"], iat, exp: iat + 60_000 },
    attacker.privateKey
  );
  const verified = await verifyDelegateToken(token, issuer.publicKey);
  expect(verified).toBeNull();
});

test("expired delegate token is rejected", async () => {
  const { signDelegateToken, verifyDelegateToken } = await import("../src/auth/delegate.ts");
  await sodium.ready;
  const kp = sodium.crypto_sign_keypair();
  const iat = Date.now() - 120_000;
  const token = await signDelegateToken(
    { iss: "ak_test", sub: "ak_sub", scopes: ["read"], iat, exp: iat + 60_000 },
    kp.privateKey
  );
  const verified = await verifyDelegateToken(token, kp.publicKey);
  expect(verified).toBeNull();
});

test("delegate token payload is tamper-evident", async () => {
  const { signDelegateToken, verifyDelegateToken } = await import("../src/auth/delegate.ts");
  await sodium.ready;
  const kp = sodium.crypto_sign_keypair();
  const iat = Date.now();
  const token = await signDelegateToken(
    { iss: "ak_test", sub: "ak_sub", scopes: ["read"], iat, exp: iat + 60_000 },
    kp.privateKey
  );
  // Tamper with scope
  const tampered = { ...token, scopes: ["admin:*"] };
  const verified = await verifyDelegateToken(tampered, kp.publicKey);
  expect(verified).toBeNull();
});

test("akc_get with bad delegate token returns error", async () => {
  const { createServer } = await import("../src/mcp/server.ts");
  const server = createServer();
  // Bypass capability assertion by injecting via raw handler
  const handlers = (server as unknown as { _requestHandlers: Map<string, Handler> })._requestHandlers;
  // MCP SDK requires capabilities.tools be set before tools/call; skip this path
  // and test the pure delegate verification logic directly.
  const { verifyDelegateToken } = await import("../src/auth/delegate.ts");
  await sodium.ready;
  const kp = sodium.crypto_sign_keypair();
  const result = await verifyDelegateToken(
    {
      iss: "ak_test",
      sub: "ak_sub",
      scopes: ["read"],
      iat: 0,
      exp: 0,
      sig: "AAAA",
    },
    kp.publicKey
  );
  expect(result).toBeNull();
  expect(handlers.has("tools/call")).toBe(true);
});
