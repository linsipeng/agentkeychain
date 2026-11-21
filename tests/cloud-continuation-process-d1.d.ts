/* eslint-disable no-unused-vars -- declaration argument names */
// Root tsc has a minimal Worker surface. The managed-cloud project checks these
// imported production helpers against the full Cloudflare types separately.
declare interface D1Database {
  batch<T>(statements: D1PreparedStatement[]): Promise<{results:T[]}[]>;
}
declare interface D1PreparedStatement {
  first<T>(): Promise<T|null>;
  first<T>(column: string): Promise<T|null>;
}
