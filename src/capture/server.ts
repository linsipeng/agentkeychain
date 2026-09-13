import { randomBytes } from "node:crypto";
import { URL, URLSearchParams } from "node:url";
import { escapeHTML } from "bun";

export type CaptureResult = "stored" | "expired" | "cancelled";

export interface SecureCaptureHandle {
  url: string;
  permission: string;
  done: Promise<CaptureResult>;
  close: () => void;
}

export interface SecureCaptureOptions {
  name: string;
  purpose: string;
  scope: string;
  permission: string;
  openBrowser?: boolean;
  timeoutMs?: number;
  // eslint-disable-next-line no-unused-vars
  onSubmit: (value: string) => Promise<void>;
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

function page(name: string, purpose: string, permission: string): string {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>安全保存凭证</title><style>body{font-family:system-ui,sans-serif;background:#f6f7f9;color:#172033;margin:0}.card{max-width:520px;margin:8vh auto;background:white;padding:32px;border-radius:18px;box-shadow:0 10px 35px #16213a1a}h1{font-size:24px}.meta{background:#f0f4ff;padding:16px;border-radius:12px;margin:20px 0}.label{font-size:12px;color:#60708d;margin-top:10px}.value{font-weight:650}input{box-sizing:border-box;width:100%;font-size:18px;padding:14px;border:1px solid #aab4c5;border-radius:10px}button{width:100%;margin-top:16px;padding:14px;border:0;border-radius:10px;background:#2457e6;color:#fff;font-size:16px;font-weight:700}.note{font-size:13px;color:#60708d;margin-top:14px}</style></head><body><main class="card"><h1>安全保存凭证</h1><div class="meta"><div class="label">名称</div><div class="value">${escapeHTML(name)}</div><div class="label">用途</div><div class="value">${escapeHTML(purpose)}</div><div class="label">权限</div><div class="value">${escapeHTML(permission)}</div></div><form method="post" autocomplete="off"><label for="value">密钥或 Token</label><input id="value" name="value" type="password" required autofocus autocomplete="off" maxlength="12000"><button type="submit">加密并保存</button></form><p class="note">内容仅提交到本机 127.0.0.1，不会发送到聊天或远程服务器。页面将在保存后失效。</p></main></body></html>`;
}

function successPage(): string {
  return `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>已保存</title><body><h1>已加密保存</h1><p>可以关闭此页面。</p></body></html>`;
}

async function openLocalPage(url: string): Promise<void> {
  const command = process.platform === "darwin"
    ? ["open", url]
    : process.platform === "win32"
      ? ["cmd", "/c", "start", "", url]
      : ["xdg-open", url];
  const child = Bun.spawn(command, { stdout: "ignore", stderr: "ignore" });
  if (await child.exited !== 0) throw new Error("could not open the local secure-entry page");
}

export async function startSecureCapture(options: SecureCaptureOptions): Promise<SecureCaptureHandle> {
  const token = randomBytes(32).toString("hex");
  const path = `/capture/${token}`;
  let settled = false;
  // eslint-disable-next-line no-unused-vars
  let resolveDone: (result: CaptureResult) => void = () => {};
  const done = new Promise<CaptureResult>((resolve) => { resolveDone = resolve; });

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      if (url.pathname !== path) return new Response("Not found", { status: 404, headers: securityHeaders("text/plain; charset=utf-8") });
      if (settled) return new Response("This request is no longer active", { status: 410, headers: securityHeaders("text/plain; charset=utf-8") });
      if (request.method === "GET") return new Response(page(options.name, options.purpose, options.permission), { headers: securityHeaders("text/html; charset=utf-8") });
      if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: securityHeaders("text/plain; charset=utf-8") });
      const contentType = request.headers.get("content-type") ?? "";
      if (!contentType.toLowerCase().startsWith("application/x-www-form-urlencoded")) return new Response("Form submission required", { status: 415, headers: securityHeaders("text/plain; charset=utf-8") });
      const declaredLength = Number(request.headers.get("content-length") ?? "0");
      if (declaredLength > MAX_BODY_BYTES) return new Response("Value is too large", { status: 413, headers: securityHeaders("text/plain; charset=utf-8") });
      const body = await request.text();
      if (Buffer.byteLength(body) > MAX_BODY_BYTES) return new Response("Value is too large", { status: 413, headers: securityHeaders("text/plain; charset=utf-8") });
      const value = new URLSearchParams(body).get("value") ?? "";
      if (!value) return new Response("Value is required", { status: 400, headers: securityHeaders("text/plain; charset=utf-8") });
      try {
        await options.onSubmit(value);
      } catch {
        return new Response("Could not save the credential", { status: 500, headers: securityHeaders("text/plain; charset=utf-8") });
      }
      settled = true;
      resolveDone("stored");
      clearTimeout(timer);
      setTimeout(() => server.stop(true), 10);
      return new Response(successPage(), { headers: securityHeaders("text/html; charset=utf-8") });
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

  return { url, permission: options.permission, done, close };
}
