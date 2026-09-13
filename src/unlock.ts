import { timingSafeEqual } from "node:crypto";
import type { Database } from "bun:sqlite";
import { resolvePassword } from "./util/keychain.ts";
import { deriveKEK, hashKEK } from "./crypto/argon2.ts";

export async function resolveVaultKek(db: Database): Promise<Uint8Array> {
  const password = await resolvePassword();
  if (!password) throw new Error("vault locked — run `agentkeychain setup` so the OS keychain can unlock AgentKeychain");
  const meta = db.prepare(`SELECT argon2_salt, kek_hash FROM kek_meta WHERE id = 1`).get() as
    | { argon2_salt: Uint8Array; kek_hash: Uint8Array }
    | undefined;
  if (!meta) throw new Error("vault not initialized — run `agentkeychain init` first");
  const kek = await deriveKEK(password, meta.argon2_salt);
  let actualHash: Uint8Array | null = null;
  try {
    actualHash = await hashKEK(kek);
    const expected = Buffer.from(meta.kek_hash);
    const actual = Buffer.from(actualHash);
    const valid = expected.length === actual.length && timingSafeEqual(expected, actual);
    expected.fill(0);
    actual.fill(0);
    if (!valid) throw new Error("vault unlock failed — OS keychain password does not match this vault");
    return kek;
  } catch (error) {
    kek.fill(0);
    throw error;
  } finally {
    actualHash?.fill(0);
  }
}
