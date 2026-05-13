/**
 * Egress policy evaluation.
 *
 * Default-deny: a host:port is allowed only if it matches an entry in the
 * allowlist. Wildcard "*" allows all (audit-only mode). Subdomain matching
 * uses literal suffix-with-dot (no glob).
 *
 * Pre-Publish-Audit F7: host strings on both sides of the match are first
 * NFKC + zero-width-strip + bidi-block normalized via Pillar-8 normalize.ts
 * and lowercased, so a fullwidth-unicode hostname (e.g. `ｅｘａｍｐｌｅ.com`)
 * cannot smuggle past an allowlist that lists the ASCII form.
 */

import { normalizeArg } from "../normalize.js";

export interface EgressDecision {
  allowed: boolean;
  reason: string;
}

/**
 * Canonicalize a host string: NFKC + invisible-codepoint strip via the
 * shared normalize pipeline, then lowercase. Used on both allowlist entries
 * and the candidate host so matching is locale-stable and unicode-safe.
 */
function canonicalHost(host: string): string {
  return normalizeArg(host).toLowerCase();
}

/**
 * Evaluate whether a host:port pair is allowed by the allowlist.
 *
 * Allowlist entry forms:
 *   - "*"               → allow all (used in audit-only mode)
 *   - "example.com:443" → exact host:port match
 *   - ".example.com:443"→ suffix match (any subdomain)
 *   - "example.com:*"   → host match, any port
 */
export function evaluateEgress(
  host: string,
  port: number,
  allowlist: readonly string[]
): EgressDecision {
  if (!host || !Number.isFinite(port) || port < 0 || port > 65535) {
    return { allowed: false, reason: "invalid host or port" };
  }
  if (allowlist.includes("*")) {
    return { allowed: true, reason: "wildcard allow" };
  }
  const candidate = canonicalHost(host);
  for (const entry of allowlist) {
    if (matches(candidate, port, entry)) {
      return { allowed: true, reason: `match: ${entry}` };
    }
  }
  return { allowed: false, reason: "default-deny: no allowlist match" };
}

function matches(host: string, port: number, entry: string): boolean {
  const colonIdx = entry.lastIndexOf(":");
  if (colonIdx < 0) return false;
  const entryHost = canonicalHost(entry.slice(0, colonIdx));
  const entryPort = entry.slice(colonIdx + 1);

  // Port match
  if (entryPort !== "*" && entryPort !== String(port)) {
    return false;
  }

  // Host match (both sides already canonicalized).
  if (entryHost.startsWith(".")) {
    return host.endsWith(entryHost) || host === entryHost.slice(1);
  }
  return host === entryHost;
}
