import { test, expect, beforeEach } from "bun:test";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let testDir: string;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), "agentkeychain-store-test-"));
  process.env.AGENTKEYCHAIN_HOME = testDir;
});

test("scope check: * wildcard allows everything", async () => {
  const { checkScope } = await import("../src/auth/scope.ts");
  expect(checkScope(["*"], ["cloudflare:read"])).toBe(true);
  expect(checkScope(["*"], ["anything"])).toBe(true);
});

test("scope check: exact match grants access", async () => {
  const { checkScope } = await import("../src/auth/scope.ts");
  expect(checkScope(["cloudflare:read"], ["cloudflare:read"])).toBe(true);
  expect(checkScope(["cloudflare:read"], ["cloudflare:write"])).toBe(false);
});

test("scope check: service wildcard grants service-specific access", async () => {
  const { checkScope } = await import("../src/auth/scope.ts");
  expect(checkScope(["cloudflare:*"], ["cloudflare:read"])).toBe(true);
  expect(checkScope(["cloudflare:*"], ["cloudflare:write"])).toBe(true);
  expect(checkScope(["cloudflare:*"], ["openai:chat"])).toBe(false);
});

test("scope check: empty required scopes grants access", async () => {
  const { checkScope } = await import("../src/auth/scope.ts");
  expect(checkScope(["cloudflare:read"], [])).toBe(true);
});

test("XChaCha20-Poly1305 encrypt + decrypt round-trip", async () => {
  const { encrypt, decrypt } = await import("../src/crypto/xchacha.ts");
  const { deriveKEK, generateSalt } = await import("../src/crypto/argon2.ts");
  const salt = await generateSalt();
  const key = await deriveKEK("test-password-123", salt);
  const plaintext = new TextEncoder().encode("sk-abc-test-6789");
  const { ciphertext, nonce } = await encrypt(plaintext, key);
  expect(ciphertext.length).toBeGreaterThan(plaintext.length);
  const decrypted = await decrypt(ciphertext, nonce, key);
  expect(new TextDecoder().decode(decrypted)).toBe("sk-abc-test-6789");
});

test("XChaCha20-Poly1305: tampered ciphertext throws", async () => {
  const { encrypt, decrypt } = await import("../src/crypto/xchacha.ts");
  const { deriveKEK, generateSalt } = await import("../src/crypto/argon2.ts");
  const salt = await generateSalt();
  const key = await deriveKEK("test-password-123", salt);
  const { ciphertext, nonce } = await encrypt("hello", key);
  ciphertext[ciphertext.length - 1] ^= 0xff;
  expect(decrypt(ciphertext, nonce, key)).rejects.toThrow();
});

test("redact: removes credential-like patterns from output", async () => {
  const { redact } = await import("../src/util/redact.ts");
  const input = "got error with key sk-abcdefghijklmnopqrst in response";
  const output = redact(input);
  expect(output).not.toContain("sk-abcdefghijklmnopqrst");
  expect(output).toContain("[REDACTED]");
});

test("store + get full flow with KEK", async () => {
  const { init } = await import("./helpers.ts");
  const { openDb, dbPath } = await import("../src/vault.ts");
  const { storeSecret, getSecret } = await import("../src/secrets.ts");
  const { loadIdentityByName } = await import("../src/identity.ts");
  const { deriveKEK } = await import("../src/crypto/argon2.ts");

  await init("test-password-123");
  const db = openDb();
  const agent = loadIdentityByName(db, "default");
  if (!agent) throw new Error("default identity not found");

  const meta = db.prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`).get() as
    | { argon2_salt: Uint8Array }
    | undefined;
  if (!meta) throw new Error("kek_meta missing");
  const kek = await deriveKEK("test-password-123", meta.argon2_salt);

  try {
    await storeSecret(db, {
      name: "openai",
      value: "sk-tes1234567890abc",
      scopes: ["openai:chat"],
      kek,
      agent,
    });
    const got = await getSecret(db, { name: "openai", kek, agent });
    expect(got).toBe("sk-tes1234567890abc");

    // Verify the stored file is encrypted (no plaintext)
    const fileBytes = readFileSync(dbPath());
    const hasPlaintext = fileBytes.includes(Buffer.from("sk-tes1234567890abc"));
    expect(hasPlaintext).toBe(false);
  } finally {
    kek.fill(0);
  }
});

test("getSecret throws NotFoundError for missing secret", async () => {
  const { init } = await import("./helpers.ts");
  const { openDb } = await import("../src/vault.ts");
  const { getSecret } = await import("../src/secrets.ts");
  const { loadIdentityByName } = await import("../src/identity.ts");
  const { deriveKEK } = await import("../src/crypto/argon2.ts");

  await init("test-password-123");
  const db = openDb();
  const agent = loadIdentityByName(db, "default");
  if (!agent) throw new Error("default identity not found");

  const meta = db.prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`).get() as
    | { argon2_salt: Uint8Array }
    | undefined;
  if (!meta) throw new Error("kek_meta missing");
  const kek = await deriveKEK("test-password-123", meta.argon2_salt);

  try {
    await expect(
      getSecret(db, { name: "nonexistent", kek, agent })
    ).rejects.toThrow("not found");
  } finally {
    kek.fill(0);
  }
});

test("getSecret throws ForbiddenError when agent lacks scope", async () => {
  const { init } = await import("./helpers.ts");
  const { openDb } = await import("../src/vault.ts");
  const { storeSecret, getSecret, ForbiddenError } = await import("../src/secrets.ts");
  const { createIdentity, loadIdentityByName } = await import("../src/identity.ts");
  const { deriveKEK } = await import("../src/crypto/argon2.ts");

  await init("test-password-123");
  const db = openDb();
  const kekRow = db.prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`).get() as
    | { argon2_salt: Uint8Array }
    | undefined;
  if (!kekRow) throw new Error("kek_meta missing");
  const kek = await deriveKEK("test-password-123", kekRow.argon2_salt);

  try {
    const defaultAgent = loadIdentityByName(db, "default");
    if (!defaultAgent) throw new Error("default identity not found");
    await storeSecret(db, {
      name: "openai",
      value: "sk-test",
      scopes: ["openai:chat"],
      kek,
      agent: defaultAgent,
    });

    const subAgent = await createIdentity(db, {
      name: "sub-agent",
      scopes: ["cloudflare:read"],
      kek,
    });

    await expect(
      getSecret(db, { name: "openai", kek, agent: subAgent })
    ).rejects.toThrow(ForbiddenError);
  } finally {
    kek.fill(0);
  }
});
