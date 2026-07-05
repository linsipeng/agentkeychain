/**
 * Safe error formatter — never includes credential material in error messages.
 */
const REDACT_PATTERNS = [
  /sk-[A-Za-z0-9_-]{20,}/g,
  /ghp_[A-Za-z0-9]{20,}/g,
  /xoxb-[A-Za-z0-9-]{20,}/g,
  /Bearer\s+[A-Za-z0-9_-]{20,}/g,
];

export function redact(text: string): string {
  let out = text;
  for (const pat of REDACT_PATTERNS) {
    out = out.replace(pat, "[REDACTED]");
  }
  return out;
}
