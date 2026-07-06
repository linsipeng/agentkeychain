/**
 * `agentkeychain serve` — start MCP stdio server.
 *
 * The server speaks Model Context Protocol over stdin/stdout.
 * Any MCP-compatible client (Claude Desktop, Hermes, Codex, IDE plugins)
 * can launch the binary with the `serve` subcommand to get the 5 akc_* tools.
 */
export async function runServe(_args: string[]): Promise<number> {
  void _args;
  const { runServer } = await import("../mcp/server.js");
  await runServer();
  // runServer blocks indefinitely on stdio; never returns
  return 0;
}