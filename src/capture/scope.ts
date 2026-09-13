export interface ScopeDecision {
  service: string;
  scope: string;
  permission: string;
}

interface ProviderRule {
  service: string;
  display: string;
  aliases: string[];
  kind: "model" | "infrastructure" | "inference" | "generic";
}

const PROVIDERS: ProviderRule[] = [
  { service: "openai", display: "OpenAI", aliases: ["openai", "chatgpt"], kind: "model" },
  { service: "anthropic", display: "Anthropic", aliases: ["anthropic", "claude"], kind: "model" },
  { service: "cloudflare", display: "Cloudflare", aliases: ["cloudflare", "wrangler"], kind: "infrastructure" },
  { service: "fal", display: "Fal", aliases: ["fal.ai", "fal-api", "fal_"], kind: "inference" },
  { service: "github", display: "GitHub", aliases: ["github", "gh-"], kind: "generic" },
  { service: "stripe", display: "Stripe", aliases: ["stripe"], kind: "generic" },
];

const READ_WORDS = /(?:read|query|list|status|inspect|只读|查询|读取|查看|状态)/i;
const WRITE_WORDS = /(?:write|deploy|publish|create|update|modify|delete|manage|部署|发布|创建|更新|修改|删除|管理)/i;

function titleCase(slug: string): string {
  return slug.split("-").filter(Boolean).map((part) => part[0]?.toUpperCase() + part.slice(1)).join(" ");
}

function fallbackService(name: string): string {
  const normalized = name.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  const stripped = normalized.replace(/-(?:api-)?(?:key|token|secret)$/g, "").replace(/-(?:prod|production|dev|test)$/g, "");
  return stripped || "credential";
}

export function inferCredentialScope(name: string, purpose: string): ScopeDecision {
  const haystack = `${name} ${purpose}`.toLowerCase();
  const provider = PROVIDERS.find((rule) => rule.aliases.some((alias) => haystack.includes(alias)));
  const service = provider?.service ?? fallbackService(name);
  const display = provider?.display ?? titleCase(service);
  let action = "use";

  if (provider?.kind === "model") action = "chat";
  else if (provider?.kind === "inference") action = "inference";
  else if (provider?.kind === "infrastructure") {
    action = WRITE_WORDS.test(purpose) ? "write" : READ_WORDS.test(purpose) ? "read" : "use";
  }

  const permission = provider?.kind === "model"
    ? `仅允许用于 ${display} 模型调用`
    : action === "read"
      ? `仅允许读取 ${display} 数据`
      : action === "write"
        ? `允许管理 ${display} 资源`
        : `仅允许用于 ${display}`;

  return { service, scope: `${service}:${action}`, permission };
}
