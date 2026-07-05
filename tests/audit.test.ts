import { test, expect, beforeEach } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let testDir: string;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), "agentkeychain-audit-test-"));
  process.env.AGENTKEYCHAIN_HOME = testDir;
});

test("audit chain verify: empty log passes", async () => {
  const { init } = await import("./helpers.ts");
  const { openDb } = await import("../src/vault.ts");
  const { verifyChain } = await import("../src/audit.ts");

  await init("test-password");
  const db = openDb();
  const result = await verifyChain(db);
  expect(result.ok).toBe(true);
  expect(result.total).toBe(0);
});

test("audit chain verify: signed entries pass verification", async () => {
  const { init } = await import("./helpers.ts");
  const { openDb } = await import("../src/vault.ts");
  const { append } = await import("../src/audit.ts");
  const { verifyChain } = await import("../src/audit.ts");
  const { deriveKEK } = await import("../src/crypto/argon2.ts");

  await init("test-password");
  const db = openDb();
  const meta = db.prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`).get() as
    | { argon2_salt: Uint8Array }
    | undefined;
  if (!meta) throw new Error("kek_meta missing");
  const kek = await deriveKEK("test-password", meta.argon2_salt);

  try {
    // Unlock default agent
    const { loadIdentityByName } = await import("../src/identity.ts");
    const identity = loadIdentityByName(db, "default");
    if (!identity) throw new Error("default identity not found");
    const { decryptPrivKey } = await import("../src/crypto/keys.ts");
    const idRow = db
      .prepare(`SELECT encrypted_priv, priv_nonce FROM identities WHERE id = ?`)
      .get(identity.id) as { encrypted_priv: Uint8Array; priv_nonce: Uint8Array };
    const privateKey = await decryptPrivKey(idRow.encrypted_priv, idRow.priv_nonce, kek);

    await append(db, {
      agent: { identity, privateKey },
      action: "store",
      target: "test-secret",
      success: true,
      kek,
    });
    await append(db, {
      agent: { identity, privateKey },
      action: "get",
      target: "test-secret",
      success: true,
      kek,
    });

    const result = await verifyChain(db);
    if (!result.ok) {
      console.error("DEBUG chain verify failed:", JSON.stringify(result));
    }
    expect(result.ok).toBe(true);
    expect(result.total).toBeGreaterThanOrEqual(2);
  } finally {
    kek.fill(0);
  }
});

test("audit chain verify: tampered signature fails verification", async () => {
  const { init } = await import("./helpers.ts");
  const { openDb } = await import("../src/vault.ts");
  const { append } = await import("../src/audit.ts");
  const { verifyChain } = await import("../src/audit.ts");
  const { deriveKEK } = await import("../src/crypto/argon2.ts");

  await init("test-password");
  const db = openDb();
  const meta = db.prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`).get() as
    | { argon2_salt: Uint8Array }
    | undefined;
  if (!meta) throw new Error("kek_meta missing");
  const kek = await deriveKEK("test-password", meta.argon2_salt);

  try {
    const { loadIdentityByName } = await import("../src/identity.ts");
    const identity = loadIdentityByName(db, "default");
    if (!identity) throw new Error("default identity not found");
    const { decryptPrivKey } = await import("../src/crypto/keys.ts");
    const idRow = db
      .prepare(`SELECT encrypted_priv, priv_nonce FROM identities WHERE id = ?`)
      .get(identity.id) as { encrypted_priv: Uint8Array; priv_nonce: Uint8Array };
    const privateKey = await decryptPrivKey(idRow.encrypted_priv, idRow.priv_nonce, kek);

    await append(db, {
      agent: { identity, privateKey },
      action: "store",
      target: "test",
      success: true,
      kek,
    });

    // Tamper with the audit row
    const row = db.prepare(`SELECT seq, sig FROM audit_log LIMIT 1`).get() as
      | { seq: number; sig: Uint8Array }
      | undefined;
    if (!row) throw new Error("no audit row");
    // Flip a byte in the signature
    const tamperedSig = new Uint8Array(row.sig);
    tamperedSig[0] ^= 0xff;
    db.prepare(`UPDATE audit_log SET sig = ? WHERE seq = ?`).run(tamperedSig, row.seq);

    const result = await verifyChain(db);
    expect(result.ok).toBe(false);
    expect(result.brokenAtSeq).toBeDefined();
  } finally {
    kek.fill(0);
  }
});
