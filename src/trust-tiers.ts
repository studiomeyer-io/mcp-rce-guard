/**
 * Trust-Tier defaults for register_subprocess.
 *
 * Each tier defines a sensible isolation profile so callers can register
 * a subprocess with minimal config. Profiles are intentionally conservative
 * — escalation requires explicit per-field overrides.
 *
 * Anti-Pattern provenance: Nginx-MCP RCE CVSS 9.8 (subprocess inheritert
 * volle parent-permissions weil keine Profile-Defaults existieren).
 */

import type { IsolationProfile } from "./types.js";

export type TrustTier = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export const TRUST_TIER_DEFAULTS: Record<TrustTier, IsolationProfile> = {
  /**
   * LOW = highest isolation. For unverified third-party MCP tools.
   * Read-only fs, tiny scratch, no egress, hard CPU/mem caps.
   */
  LOW: {
    fsReadOnly: ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"],
    fsWritable: [],
    cpuMs: 5_000,
    memMB: 128,
    pidMax: 32,
    egressAllowlist: []
  },
  /**
   * MEDIUM = medium isolation. For first-party tools that need light egress.
   */
  MEDIUM: {
    fsReadOnly: ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"],
    fsWritable: [],
    cpuMs: 30_000,
    memMB: 512,
    pidMax: 128,
    egressAllowlist: ["api.anthropic.com:443", "api.openai.com:443"]
  },
  /**
   * HIGH = relaxed isolation. For tools that need broader egress + larger budgets.
   */
  HIGH: {
    fsReadOnly: ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"],
    fsWritable: [],
    cpuMs: 120_000,
    memMB: 2048,
    pidMax: 512,
    egressAllowlist: ["api.anthropic.com:443", "api.openai.com:443", "github.com:443"]
  },
  /**
   * CRITICAL = minimum isolation. Audit-only egress (still default-deny on caps).
   * Use only for fully-trusted first-party tools that need broad system access.
   */
  CRITICAL: {
    fsReadOnly: [],
    fsWritable: [],
    cpuMs: 600_000,
    memMB: 8192,
    pidMax: 2048,
    egressAllowlist: ["*"]
  }
};

/**
 * Merge a partial profile onto a tier default. Caller-supplied fields win.
 */
export function resolveProfile(
  tier: TrustTier,
  override: Partial<IsolationProfile>
): IsolationProfile {
  const base = TRUST_TIER_DEFAULTS[tier];
  return {
    fsReadOnly: override.fsReadOnly ?? base.fsReadOnly,
    fsWritable: override.fsWritable ?? base.fsWritable,
    cpuMs: override.cpuMs ?? base.cpuMs,
    memMB: override.memMB ?? base.memMB,
    pidMax: override.pidMax ?? base.pidMax,
    egressAllowlist: override.egressAllowlist ?? base.egressAllowlist
  };
}
