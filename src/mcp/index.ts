/**
 * MCP server entry point.
 *
 * Usage:
 *   agentkeychain serve         # start stdio MCP server
 *
 * Configure in any MCP client (Claude Desktop, Codex, Hermes) by pointing
 * the MCP stdio command at the compiled binary with the `serve` subcommand.
 */
import { runServer } from "./server.js";

runServer().catch((err) => {
  // MCP clients should never see stack traces — print minimal info to stderr
  process.stderr.write(`agentkeychain MCP server failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});