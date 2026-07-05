import { test, expect, beforeEach } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let testDir: string;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), "agentkeychain-test-"));
  process.env.AGENTKEYCHAIN_HOME = testDir;
});

test("argon2 KEK derivation is deterministic given same salt+password", async () => {
  const { deriveKEK, generateSalt } = await import("../src/crypto/argon2.ts");
  const salt = await generateSalt();
  const kek1 = await deriveKEK("password123", salt);
  const kek2 = await deriveKEK("password123", salt);
  expect(kek1.length).toBe(32);
  expect(kek1).toEqual(kek2);
});

test("argon2 KEK differs for different passwords", async () => {
  const { deriveKEK, generateSalt } = await import("../src/crypto/argon2.ts");
  const salt = await generateSalt();
  const kek1 = await deriveKEK("password123", salt);
  const kek2 = await deriveKEK("password456", salt);
  expect(kek1).not.toEqual(kek2);
});

test("Ed25519 keypair generation produces correct sizes", async () => {
  const { generateKeypair, PUB_BYTES, PRIV_BYTES } = await import(
    "../src/crypto/keys.ts"
  );
  const kp = await generateKeypair();
  expect(kp.publicKey.length).toBe(PUB_BYTES);
  expect(kp.privateKey.length).toBe(PRIV_BYTES);
});

test("encrypt + decrypt private key round-trips", async () => {
  const { generateKeypair, encryptPrivKey, decryptPrivKey } = await import(
    "../src/crypto/keys.ts"
  );
  const { deriveKEK, generateSalt } = await import("../src/crypto/argon2.ts");
  const salt = await generateSalt();
  const kek = await deriveKEK("password123", salt);
  const kp = await generateKeypair();
  const enc = await encryptPrivKey(kp.privateKey, kek);
  const dec = await decryptPrivKey(enc.ciphertext, enc.nonce, kek);
  expect(dec).toEqual(kp.privateKey);
});

test("vault db schema migration creates 4 tables", () => {
  const { openDb } = require("../src/vault.ts");
  const db = openDb();
  const tables = db
    .query<{ name: string }, []>(
      "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    .all()
    .map((r: { name: string }) => r.name);
  expect(tables).toContain("kek_meta");
  expect(tables).toContain("identities");
  expect(tables).toContain("secrets");
  expect(tables).toContain("audit_log");
  db.close();
});
