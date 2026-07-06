/**
 * `agentkeychain issue-token` — issue a cross-agent delegate token.
 *
 *   agentkeychain issue-token --sub ak_xxx --scopes "read,write" --ttl 1h
 *
 * Output: base64url-encoded JSON token to stdout.
 * Pipe into another process or set as AKC_DELEGATE_TOKEN env var.
 */
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import sodium from "libsodium-wrappers-sumo";
import type { Database } from "bun:sqlite";

import { loadIdentityByName, unlockIdentityPrivateKey } from "../identity.ts";
import { openDb } from "../vault.ts";
import { deriveKEK } from "../crypto/argon2.ts";
import { signDelegateToken } from "../auth/delegate.ts";
import { resolvePassword } from "../util/keychain.ts";

function parseTtl(s: string): number {
  const m = /^(\d+)(s|m|h|d)$/.exec(s);
  if (!m) throw new Error(`invalid ttl: ${s} (use e.g. 30s, 5m, 1h, 7d)`);
  const n = Number(m[1]);
  switch (m[2]) {
    case "s": return n * 1000;
    case "m": return n * 60_000;
    case "h": return n * 3_600_000;
    case "d": return n * 86_400_000;
    default: throw new Error(`unknown unit: ${m[2]}`);
  }
}

async function promptUnlock(): Promise<string> {
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    process.stdout.write("Master password: ");
    return await new Promise<string>((resolve, reject) => {
      rl.once("line", (line) => resolve(line));
      rl.once("close", () => reject(new Error("stdin closed before password")));
    });
  } finally {
    rl.close();
  }
}

/**
 * Sign a delegate token given an unlocked issuer private key.
 * Pure function — caller controls password / KEK derivation.
 */
export async function issueDelegateToken(
  db: Database,
  issuer: { id: string; publicKey: Uint8Array },
  issuerPrivateKey: Uint8Array,
  args: { sub: string; scopes: string[]; ttlMs: number }
): Promise<string> {
  const iat = Date.now();
  const token = await signDelegateToken(
    { iss: issuer.id, sub: args.sub, scopes: args.scopes, iat, exp: iat + args.ttlMs },
    issuerPrivateKey
  );
  return Buffer.from(JSON.stringify(token)).toString("base64url");
}

export async function runIssueToken(args: string[]): Promise<number> {
  await sodium.ready;

  let sub = "";
  let scopes: string[] = ["read"];
  let ttlMs = 3_600_000;
  let issuerName = "default";

  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    switch (a) {
      case "--sub": sub = args[++i] ?? ""; break;
      case "--scopes": scopes = (args[++i] ?? "").split(",").map((s) => s.trim()).filter(Boolean); break;
      case "--ttl": ttlMs = parseTtl(args[++i] ?? "1h"); break;
      case "--issuer": issuerName = args[++i] ?? "default"; break;
      case "--help": case "-h":
        process.stdout.write(
          `Usage: agentkeychain issue-token --sub <agent_id> --scopes "read,write" [--ttl 1h]\n\n` +
          `Options:\n` +
          `  --sub <id>        Subject agent id (the sub-agent receiving the token)\n` +
          `  --scopes <list>   Comma-separated scope tags (default: "read")\n` +
          `  --ttl <duration>  Token lifetime: 30s, 5m, 1h, 7d (default: 1h)\n` +
          `  --issuer <name>   Issuing agent name (default: "default")\n` +
          `  --help, -h        Show this help\n\n` +
          `Output: base64url-encoded delegate token to stdout.\n`
        );
        return 0;
      default:
        process.stderr.write(`unknown flag: ${a}\n`);
        return 1;
    }
  }

  if (!sub) {
    process.stderr.write(`error: --sub is required\n`);
    return 1;
  }
  if (scopes.length === 0) {
    process.stderr.write(`error: --scopes cannot be empty\n`);
    return 1;
  }

  const db = openDb();
  const issuer = loadIdentityByName(db, issuerName);
  if (!issuer) {
    process.stderr.write(`error: issuer identity '${issuerName}' not found\n`);
    return 1;
  }

  const meta = db.prepare(`SELECT argon2_salt FROM kek_meta WHERE id = 1`).get() as
    | { argon2_salt: Uint8Array }
    | undefined;
  if (!meta) {
    process.stderr.write("vault corrupted: no kek_meta\n");
    return 4;
  }

  const password = (await resolvePassword()) ?? (await promptUnlock());
  const kek = await deriveKEK(password, meta.argon2_salt);

  try {
    const privateKey = await unlockIdentityPrivateKey(db, issuer, kek);
    const iat = Date.now();
    const token = await signDelegateToken(
      { iss: issuer.id, sub, scopes, iat, exp: iat + ttlMs },
      privateKey
    );
    privateKey.fill(0);

    const b64 = Buffer.from(JSON.stringify(token)).toString("base64url");
    process.stdout.write(b64 + "\n");
    return 0;
  } finally {
    kek.fill(0);
  }
}