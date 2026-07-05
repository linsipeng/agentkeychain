/**
 * Scope parsing + matching.
 */
export function parseScopes(raw: string): string[] {
  if (raw.trim() === "") return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Check if `agentScopes` permits accessing a secret requiring `requiredScopes`.
 */
export function checkScope(agentScopes: string[], requiredScopes: string[]): boolean {
  if (requiredScopes.length === 0) return true;
  if (agentScopes.includes("*")) return true;

  for (const required of requiredScopes) {
    if (agentScopes.includes(required)) return true;
    const [service] = required.split(":");
    if (service && agentScopes.includes(`${service}:*`)) return true;
  }

  return false;
}
