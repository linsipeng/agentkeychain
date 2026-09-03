/**
 * `agentkeychain sync` — BYO Cloudflare ciphertext sync.
 *
 *   agentkeychain sync init        Deploy worker + D1 to YOUR Cloudflare account
 *   agentkeychain sync connect     Bind this machine (URL + token from init)
 *   agentkeychain sync push        Local → cloud
 *   agentkeychain sync pull        Cloud → local (LWW)
 *   agentkeychain sync status      Binding, health, row counts
 *   agentkeychain sync disconnect  Unbind this machine (cloud data untouched)
 *
 * `init` shells out to wrangler (user's own install). Requires CLOUDFLARE_API_TOKEN.
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { openDb, vaultExists, vaultDir } from "../vault.ts";
import {
  loadSyncConfig,
  saveSyncConfig,
  deleteSyncConfig,
  generateSyncToken,
  generateDeviceId,
  syncPush,
  syncPull,
  syncHealth,
  localRowCount,
  type SyncConfig,
} from "../sync.ts";
import { resolvePassword } from "../util/keychain.ts";
import { readPassword, readLines } from "../util/prompt.ts";
import { redact } from "../util/redact.ts";

const WORKER_DIR_NAME = "worker";
const WORKER_NAME = "agentkeychain-sync";
const DB_NAME = "agentkeychain-sync";

function usage(): number {
  process.stdout.write(
    `usage: agentkeychain sync <init|connect|push|pull|status|disconnect>\n\n` +
      `  init        Deploy the sync worker + D1 to your Cloudflare account\n` +
      `              (requires wrangler + CLOUDFLARE_API_TOKEN; idempotent)\n` +
      `  connect     Bind this machine: paste the sync URL + token from init\n` +
      `  push        Upload changed secrets (encrypted) to the cloud\n` +
      `  pull        Download and merge (last-write-wins)\n` +
      `  status      Show binding, health, local row count\n` +
      `  disconnect  Unbind this machine (cloud data is NOT deleted)\n`
  );
  return 1;
}

function requireVault(): ReturnType<typeof openDb> | null {
  if (!vaultExists()) {
    process.stderr.write("vault not initialized — run `agentkeychain init` first\n");
    return null;
  }
  return openDb();
}

async function requirePassword(): Promise<string> {
  return (await resolvePassword()) ?? (await readPassword("Master password: "));
}

// ---- sync init -------------------------------------------------------------

async function runInit(): Promise<number> {
  if (!existsSync("wrangler.toml") && !process.env.AKC_SYNC_ALLOW_ANY_CWD) {
    // guard: wrangler commands must run inside the repo's worker/ dir
  }
  const token = await generateSyncToken();
  const scriptDir = process.env.AKC_SYNC_WORKER_DIR ?? join(process.cwd(), WORKER_DIR_NAME);
  const wranglerToml = join(scriptDir, "wrangler.toml");
  if (!existsSync(wranglerToml)) {
    process.stderr.write(`error: ${wranglerToml} not found — run from the repo or set AKC_SYNC_WORKER_DIR\n`);
    return 1;
  }

  process.stdout.write("Deploying sync worker to YOUR Cloudflare account…\n");

  // 1. account id
  const whoami = Bun.spawnSync(["wrangler", "whoami"], {
    env: { ...process.env },
    stdout: "pipe",
    stderr: "pipe",
  });
  const whoamiOut = whoami.stdout.toString() + whoami.stderr.toString();
  const accountMatch = /([a-f0-9]{32})/.exec(whoamiOut);
  if (!accountMatch?.[1]) {
    process.stderr.write(
      "error: cannot determine Cloudflare account id.\n" +
        "Ensure wrangler is installed and CLOUDFLARE_API_TOKEN is set (token must include Workers + D1 edit).\n"
    );
    return 1;
  }
  const accountId: string = accountMatch[1];

  // 2. inject account_id into wrangler.toml BEFORE any wrangler d1 command
  //    (wrangler reads account_id from cwd's wrangler.toml and fails on placeholders).
  //    Keyed regex replace (not placeholder text) so re-runs self-heal a corrupted toml.
  const { writeFileSync } = await import("node:fs");
  let toml = readFileSync(wranglerToml, "utf8");
  toml = toml.replace(/^account_id\s*=\s*"[^"]*"/m, `account_id = "${accountId}"`);
  writeFileSync(wranglerToml, toml);

  // 3. create D1 database (idempotent)
  let dbId: string | null = null;
  const dbList = Bun.spawnSync(["wrangler", "d1", "list", "--json"], {
    cwd: scriptDir,
    env: { ...process.env },
    stdout: "pipe",
    stderr: "pipe",
  });
  try {
    const list = JSON.parse(dbList.stdout.toString()) as Array<{ name: string; uuid: string }>;
    dbId = list.find((d) => d.name === DB_NAME)?.uuid ?? null;
  } catch {
    dbId = null;
  }
  if (!dbId) {
    // wrangler d1 create has no --json flag (v4) — parse human output.
    const create = Bun.spawnSync(["wrangler", "d1", "create", DB_NAME], {
      cwd: scriptDir,
      env: { ...process.env },
      stdout: "pipe",
      stderr: "pipe",
    });
    const out = create.stdout.toString() + create.stderr.toString();
    const m = /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/.exec(out);
    dbId = m?.[1] ?? null;
  }
  if (dbId === null) {
    process.stderr.write("error: failed to create D1 database\n");
    return 1;
  }
  process.stdout.write(`✓ D1 database: ${DB_NAME} (${dbId})\n`);

  // 3b. bind database_id into wrangler.toml (keyed replace, self-healing)
  toml = readFileSync(wranglerToml, "utf8");
  toml = toml.replace(/^(\s*database_id\s*=\s*)"[^"]*"/m, `$1"${dbId}"`);
  writeFileSync(wranglerToml, toml);

  // 4. apply schema (--file: multi-statement SQL with comments)
  const schemaPath = join(scriptDir, "schema.sql");
  const apply = Bun.spawnSync(
    ["wrangler", "d1", "execute", DB_NAME, "--remote", "--file", schemaPath, "-y"],
    {
      cwd: scriptDir,
      env: { ...process.env },
      stdout: "pipe",
      stderr: "pipe",
    }
  );
  if (apply.exitCode !== 0) {
    process.stderr.write(
      `warning: schema apply reported issues (may already exist): ${redact(apply.stderr.toString().slice(0, 200))}\n`
    );
  } else {
    process.stdout.write("✓ D1 schema applied\n");
  }

  // 5. deploy worker
  const deploy = Bun.spawnSync(["wrangler", "deploy", "--name", WORKER_NAME], {
    cwd: scriptDir,
    env: { ...process.env },
    stdout: "pipe",
    stderr: "pipe",
  });
  const deployOut = deploy.stdout.toString() + deploy.stderr.toString();
  if (deploy.exitCode !== 0) {
    process.stderr.write(`error: worker deploy failed:\n${redact(deployOut.slice(0, 400))}\n`);
    return 1;
  }
  const urlMatch = /https:\/\/[a-z0-9.-]+\.workers\.dev/.exec(deployOut);
  const workerUrl = urlMatch ? urlMatch[0] : null;
  if (!workerUrl) {
    process.stderr.write(`error: deploy succeeded but URL not found in output\n`);
    return 1;
  }
  process.stdout.write(`✓ worker deployed: ${workerUrl}\n`);

  // 6. inject token secret
  // wrangler secret put reads the value from stdin — pipe it via the shell.
  const secret = Bun.spawnSync(["sh", "-c", `printf '%s' "$AKC_SYNC_TOKEN_VALUE" | wrangler secret put SYNC_TOKEN --name ${WORKER_NAME}`], {
    cwd: scriptDir,
    env: { ...process.env, AKC_SYNC_TOKEN_VALUE: token },
    stdout: "pipe",
    stderr: "pipe",
  });
  if (secret.exitCode !== 0) {
    process.stderr.write(`error: failed to set SYNC_TOKEN secret:\n${redact(secret.stderr.toString().slice(0, 200))}\n`);
    return 1;
  }
  process.stdout.write("✓ SYNC_TOKEN injected\n\n");

  process.stdout.write(
    `════════════════════════════════════════════════════════\n` +
      `Sync endpoint ready.\n\n` +
      `  URL:   ${workerUrl}\n` +
      `  Token: ${token}\n\n` +
      `On your OTHER machine(s), run:\n` +
      `  agentkeychain sync connect\n` +
      `and paste this URL + token.\n` +
      `════════════════════════════════════════════════════════\n` +
      `\nThen here: agentkeychain sync connect  (paste the same)  →  sync push\n`
  );
  return 0;
}

// ---- sync connect ----------------------------------------------------------

async function runConnect(): Promise<number> {
  const db = requireVault();
  if (!db) return 1;

  // Batch BOTH prompts into one readLines call — sequential single-prompt
  // readline interfaces race stdin EOF under piped input (see util/prompt.ts notes).
  const [urlLine, tokenLine] = await readLines([
    "Sync URL (https://…workers.dev): ",
    "Sync token: ",
  ]);
  const url = (urlLine ?? "").trim();
  if (!/^https:\/\/[a-z0-9.-]+$/.test(url)) {
    process.stderr.write("error: invalid URL\n");
    return 1;
  }
  const token = (tokenLine ?? "").trim();
  if (token.length < 20) {
    process.stderr.write("error: token looks too short\n");
    return 1;
  }

  const existing = loadSyncConfig();
  const config: SyncConfig = {
    url,
    token,
    deviceId: existing?.deviceId ?? (await generateDeviceId()),
    lastPushAt: 0,
    lastPullAt: 0,
  };

  const health = await syncHealth(config);
  if (!health.ok) {
    process.stderr.write("error: endpoint /v1/health did not return ok — check the URL\n");
    return 1;
  }

  saveSyncConfig(config);
  process.stdout.write(
    `✓ bound to ${url}\n` +
      `  device: ${config.deviceId}\n` +
      `  next: agentkeychain sync push   (first push uploads everything)\n`
  );
  return 0;
}

// ---- push / pull / status / disconnect -------------------------------------

async function runPush(): Promise<number> {
  const db = requireVault();
  if (!db) return 1;
  const config = loadSyncConfig();
  if (!config) {
    process.stderr.write("not connected — run `agentkeychain sync connect` first\n");
    return 1;
  }
  const password = await requirePassword();
  const result = await syncPush(db, password, config);
  process.stdout.write(`✓ pushed ${result.pushed} row(s) (${result.written} written to cloud)\n`);
  return 0;
}

async function runPull(): Promise<number> {
  const db = requireVault();
  if (!db) return 1;
  const config = loadSyncConfig();
  if (!config) {
    process.stderr.write("not connected — run `agentkeychain sync connect` first\n");
    return 1;
  }
  const password = await requirePassword();
  const result = await syncPull(db, password, config);
  process.stdout.write(
    `✓ pulled ${result.pulled} row(s): ${result.applied} applied, ${result.skipped} skipped (local newer/corrupt)\n`
  );
  return 0;
}

async function runStatus(): Promise<number> {
  const db = requireVault();
  if (!db) return 1;
  const config = loadSyncConfig();
  process.stdout.write(`vault: ${vaultDir()}\n`);
  process.stdout.write(`local rows: ${localRowCount(db)}\n`);
  if (!config) {
    process.stdout.write("sync: not connected\n");
    return 0;
  }
  const health = await syncHealth(config);
  process.stdout.write(
    `sync: ${config.url}\n` +
      `  device: ${config.deviceId}\n` +
      `  health: ${health.ok ? "ok" : "UNREACHABLE"}\n` +
      `  last push: ${config.lastPushAt ? new Date(config.lastPushAt).toISOString() : "never"}\n` +
      `  last pull: ${config.lastPullAt ? new Date(config.lastPullAt).toISOString() : "never"}\n`
  );
  return 0;
}

async function runDisconnect(): Promise<number> {
  const removed = deleteSyncConfig();
  process.stdout.write(
    removed
      ? "✓ unbound this machine (cloud data untouched — delete the Worker/D1 in your CF dashboard to fully remove)\n"
      : "this machine was not connected\n"
  );
  return 0;
}

export async function runSync(argv: string[]): Promise<number> {
  const sub = argv[0];
  switch (sub) {
    case "init":
      return runInit();
    case "connect":
      return runConnect();
    case "push":
      return runPush();
    case "pull":
      return runPull();
    case "status":
      return runStatus();
    case "disconnect":
      return runDisconnect();
    default:
      return usage();
  }
}
