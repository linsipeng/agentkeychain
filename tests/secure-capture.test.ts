import { afterEach, describe, expect, test } from "bun:test";
import { URL, URLSearchParams } from "node:url";
import { startSecureCapture, type SecureCaptureHandle } from "../src/capture/server.ts";

const handles: SecureCaptureHandle[] = [];
afterEach(() => {
  for (const handle of handles.splice(0)) handle.close();
});

describe("secure loopback capture", () => {
  test("serves a no-store form without exposing raw scope", async () => {
    const handle = await startSecureCapture({
      name: "openai-prod",
      purpose: "用于聊天",
      scope: "openai:chat",
      permission: "仅允许用于 OpenAI 模型调用",
      openBrowser: false,
      onSubmit: async () => {},
    });
    handles.push(handle);

    const response = await fetch(handle.url);
    const html = await response.text();
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(html).toContain("仅允许用于 OpenAI 模型调用");
    expect(html).not.toContain("openai:chat");
  });

  test("rejects wrong paths and non-form submissions", async () => {
    const handle = await startSecureCapture({
      name: "x",
      purpose: "use x",
      scope: "x:use",
      permission: "Only use X",
      openBrowser: false,
      onSubmit: async () => {},
    });
    handles.push(handle);
    const wrong = new URL(handle.url);
    wrong.pathname = "/capture/wrong-token";
    expect((await fetch(wrong)).status).toBe(404);
    expect((await fetch(handle.url, { method: "POST", body: "value=secret" })).status).toBe(415);
  });

  test("accepts one local value and never returns it", async () => {
    let submitted = "";
    const handle = await startSecureCapture({
      name: "x",
      purpose: "use x",
      scope: "x:use",
      permission: "Only use X",
      openBrowser: false,
      onSubmit: async (value) => { submitted = value; },
    });
    handles.push(handle);
    const synthetic = "test-secret-value-never-return";
    const response = await fetch(handle.url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ value: synthetic }),
    });
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(submitted).toBe(synthetic);
    expect(body).not.toContain(synthetic);
    expect(await handle.done).toBe("stored");
  });

  test("rejects empty and oversized values", async () => {
    const handle = await startSecureCapture({
      name: "x",
      purpose: "use x",
      scope: "x:use",
      permission: "Only use X",
      openBrowser: false,
      onSubmit: async () => {},
    });
    handles.push(handle);
    const empty = await fetch(handle.url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "value=",
    });
    expect(empty.status).toBe(400);
    const oversized = await fetch(handle.url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "content-length": "20000" },
      body: `value=${"a".repeat(20_000)}`,
    });
    expect(oversized.status).toBe(413);
  });
});
