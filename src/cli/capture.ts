import { requestSecureStore } from "../capture/store.ts";

export interface CaptureArgs {
  name: string;
  purpose: string;
  openBrowser: boolean;
  json: boolean;
}

export function parseCaptureArgs(argv: string[]): CaptureArgs {
  let name = "";
  let purpose = "";
  let openBrowser = true;
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? "";
    if (arg === "--purpose" || arg === "-p") purpose = argv[++i] ?? "";
    else if (arg === "--no-open") openBrowser = false;
    else if (arg === "--json") json = true;
    else if (!arg.startsWith("-") && !name) name = arg;
  }
  if (!name.trim()) throw new Error("secret name is required");
  if (!purpose.trim()) throw new Error("credential purpose is required; use --purpose <text>");
  return { name: name.trim(), purpose: purpose.trim(), openBrowser, json };
}

export async function runCapture(argv: string[]): Promise<number> {
  const args = parseCaptureArgs(argv);
  const handle = await requestSecureStore({
    name: args.name,
    purpose: args.purpose,
    openBrowser: args.openBrowser,
  });
  if (args.json) {
    process.stdout.write(JSON.stringify({
      status: "waiting_for_local_input",
      name: args.name,
      permission: handle.permission,
      ...(args.openBrowser ? {} : { localUrl: handle.url }),
    }) + "\n");
  } else if (args.openBrowser) {
    process.stdout.write(`Secure local entry opened for '${args.name}'. Waiting up to 5 minutes…\n`);
  } else {
    process.stdout.write(`Open this local one-time URL: ${handle.url}\n`);
  }

  const result = await handle.done;
  if (result === "stored") {
    process.stdout.write(`✓ encrypted and stored: ${args.name}\n`);
    return 0;
  }
  process.stderr.write(result === "expired" ? "secure entry expired\n" : "secure entry cancelled\n");
  return 1;
}
