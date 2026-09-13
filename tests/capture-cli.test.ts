import { expect, test } from "bun:test";
import { parseCaptureArgs } from "../src/cli/capture.ts";

test("capture CLI requires a name and natural-language purpose", () => {
  expect(parseCaptureArgs(["openai-prod", "--purpose", "用于聊天", "--no-open", "--json"])).toEqual({
    name: "openai-prod",
    purpose: "用于聊天",
    openBrowser: false,
    json: true,
  });
  expect(() => parseCaptureArgs([])).toThrow("name");
  expect(() => parseCaptureArgs(["openai-prod"])).toThrow("purpose");
});