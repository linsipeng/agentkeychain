import { randomBytes } from "node:crypto";
import { URL, URLSearchParams } from "node:url";

export type PasswordCheckResult = "correct" | "incorrect" | "expired" | "cancelled";

export interface PasswordCheckHandle {
  url: string;
  done: Promise<PasswordCheckResult>;
  close: () => void;
}

export interface PasswordCheckOptions {
  openBrowser?: boolean;
  timeoutMs?: number;
  // eslint-disable-next-line no-unused-vars
  onVerify: (password: string) => Promise<boolean>;
}

const MAX_BODY_BYTES = 16_384;

function securityHeaders(contentType: string): Record<string, string> {
  return {
    "content-type": contentType,
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  };
}

function formPage(): string {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>验证主密码</title><style>body{font-family:system-ui,sans-serif;background:#f6f7f9;color:#172033;margin:0}.card{max-width:520px;margin:8vh auto;background:white;padding:32px;border-radius:18px;box-shadow:0 10px 35px #16213a1a}h1{font-size:24px}.safe{background:#eef8f1;padding:14px;border-radius:12px;color:#255b35;margin:18px 0}input{box-sizing:border-box;width:100%;font-size:18px;padding:14px;border:1px solid #aab4c5;border-radius:10px}button{width:100%;margin-top:16px;padding:14px;border:0;border-radius:10px;background:#2457e6;color:#fff;font-size:16px;font-weight:700}.note{font-size:13px;color:#60708d;margin-top:14px}</style></head><body><main class="card"><h1>验证主密码</h1><div class="safe">只做只读校验，不会修改 Vault，也不会更新 macOS 钥匙串。</div><form method="post" autocomplete="off"><label for="password">你记住的主密码</label><input id="password" name="password" type="password" required autofocus autocomplete="off" maxlength="12000"><button type="submit">只读验证</button></form><p class="note">密码仅提交到本机 127.0.0.1，不会进入聊天、MCP 参数或远程服务器。此页面验证一次后立即失效。</p></main></body></html>`;
}

function resultPage(correct: boolean): string {
  const title = correct ? "主密码正确" : "主密码不正确";
  const detail = correct
    ? "你记住的密码可以解锁当前 Vault。"
    : "当前输入无法解锁 Vault。Vault 和钥匙串均未被修改。";
  return `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><body style="font-family:system-ui,sans-serif;max-width:520px;margin:10vh auto;padding:24px"><h1>${title}</h1><p>${detail}</p><p>可以关闭此页面。</p></body></html>`;
}

async function openLocalPage(url: string): Promise<void> {
  const command = process.platform === "darwin"
    ? ["open", url]
    : process.platform === "win32"
      ? ["cmd", "/c", "start", "", url]
      : ["xdg-open", url];
  const child = Bun.spawn(command, { stdout: "ignore", stderr: "ignore" });
  if (await child.exited !== 0) throw new Error("could not open the local password-check page");
}

export async function startPasswordCheck(options: PasswordCheckOptions): Promise<PasswordCheckHandle> {
  const token = randomBytes(32).toString("hex");
  const path = `/verify-password/${token}`;
  let settled = false;
  let inFlight = false;
  // eslint-disable-next-line no-unused-vars
  let resolveDone: (result: PasswordCheckResult) => void = () => {};
  const done = new Promise<PasswordCheckResult>((resolve) => { resolveDone = resolve; });

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      if (url.pathname !== path) return new Response("Not found", { status: 404, headers: securityHeaders("text/plain; charset=utf-8") });
      if (settled || inFlight) return new Response("This request is no longer active", { status: 410, headers: securityHeaders("text/plain; charset=utf-8") });
      if (request.method === "GET") return new Response(formPage(), { headers: securityHeaders("text/html; charset=utf-8") });
      if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: securityHeaders("text/plain; charset=utf-8") });
      const contentType = request.headers.get("content-type") ?? "";
      if (!contentType.toLowerCase().startsWith("application/x-www-form-urlencoded")) return new Response("Form submission required", { status: 415, headers: securityHeaders("text/plain; charset=utf-8") });
      const declaredLength = Number(request.headers.get("content-length") ?? "0");
      if (declaredLength > MAX_BODY_BYTES) return new Response("Password is too large", { status: 413, headers: securityHeaders("text/plain; charset=utf-8") });
      const body = await request.text();
      if (Buffer.byteLength(body) > MAX_BODY_BYTES) return new Response("Password is too large", { status: 413, headers: securityHeaders("text/plain; charset=utf-8") });
      const password = new URLSearchParams(body).get("password") ?? "";
      if (!password) return new Response("Password is required", { status: 400, headers: securityHeaders("text/plain; charset=utf-8") });
      if (settled || inFlight) return new Response("This request is no longer active", { status: 410, headers: securityHeaders("text/plain; charset=utf-8") });
      inFlight = true;

      let correct: boolean;
      try {
        correct = await options.onVerify(password);
      } catch {
        inFlight = false;
        return new Response("Could not verify the password", { status: 500, headers: securityHeaders("text/plain; charset=utf-8") });
      }
      settled = true;
      const result: PasswordCheckResult = correct ? "correct" : "incorrect";
      resolveDone(result);
      clearTimeout(timer);
      setTimeout(() => server.stop(true), 10);
      return new Response(resultPage(correct), { headers: securityHeaders("text/html; charset=utf-8") });
    },
  });

  const url = `http://127.0.0.1:${server.port}${path}`;
  const close = (): void => {
    if (!settled) {
      settled = true;
      resolveDone("cancelled");
    }
    clearTimeout(timer);
    server.stop(true);
  };
  const timer = setTimeout(() => {
    if (!settled) {
      settled = true;
      resolveDone("expired");
      server.stop(true);
    }
  }, options.timeoutMs ?? 300_000);

  if (options.openBrowser !== false) {
    try {
      await openLocalPage(url);
    } catch (error) {
      close();
      throw error;
    }
  }

  return { url, done, close };
}
