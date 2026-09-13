import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dir, "..");
const read = (path: string): string => readFileSync(join(root, path), "utf8");

describe("AI-native installation contract", () => {
  test("repository ships an agent entrypoint and a public Hermes skill", () => {
    expect(existsSync(join(root, "AGENTS.md"))).toBe(true);
    expect(existsSync(join(root, "skills/agentkeychain/SKILL.md"))).toBe(true);
  });

  test("skill triggers broadly for credentials and routes through AgentKeychain", () => {
    const skill = read("skills/agentkeychain/SKILL.md");
    expect(skill.startsWith("---\n")).toBe(true);
    expect(skill).toContain("name: agentkeychain");
    expect(skill).toMatch(/API key/i);
    expect(skill).toMatch(/token/i);
    expect(skill).toMatch(/password/i);
    expect(skill).toMatch(/private key/i);
    expect(skill).toMatch(/connection string/i);
    expect(skill).toContain("agentkeychain list");
    expect(skill).toContain("Never print");
  });

  test("agent protocol pins release artifacts, preserves collisions, registers MCP, and documents trust", () => {
    const protocol = read("AGENTS.md");
    expect(protocol).toContain("v0.5.0/install.sh");
    expect(protocol).toContain("--version v0.5.0");
    expect(protocol).toContain("v0.5.0/skills/agentkeychain/SKILL.md");
    expect(protocol).toContain("hermes skills install --yes");
    expect(protocol).toContain("printf 'y\\n' | hermes mcp add");
    expect(protocol).toContain("hermes mcp test");
    expect(protocol).toMatch(/do not overwrite/i);
    expect(protocol).toMatch(/trusted\s+local clients/i);
  });

  test("English and Chinese AI installation guides are both present", () => {
    expect(existsSync(join(root, "docs/AI_INSTALL.md"))).toBe(true);
    expect(existsSync(join(root, "docs/AI_INSTALL.zh-CN.md"))).toBe(true);
    expect(read("README.md")).toContain("Install with your AI agent");
    expect(read("README.zh-CN.md")).toContain("把链接发给你的 AI");
  });
});
