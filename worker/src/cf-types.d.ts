/**
 * Minimal Cloudflare Workers type declarations (subset used by this worker).
 * Kept inline so the repo needs no extra devDependency.
 */
declare interface D1Database {
  prepare(query: string): D1PreparedStatement;
}
declare interface D1PreparedStatement {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  bind(...values: unknown[]): D1PreparedStatement;
  run(): Promise<{ meta: { changes?: number } }>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  all<T>(): Promise<{ results: T[] }>;
}
declare interface ExportedHandler<Env = unknown> {
  fetch(request: Request, env: Env, ctx: unknown): Response | Promise<Response>;
}
