/**
 * In-memory subprocess registry + canary chain registry.
 *
 * Process-local state. The persistent audit-log lives in audit/log.ts (NDJSON).
 *
 * v0.1 trade-off: registry is in-memory and resets on server restart. v0.2 will
 * persist to ~/.mcp-rce-guard/registry.json with optional Pillar-1 signing.
 */

import { createHash, randomBytes } from "node:crypto";
import type {
  EgressMode,
  IsolationProfile,
  RegisteredSubprocess
} from "./types.js";

const subprocesses = new Map<string, RegisteredSubprocess>();

interface CanaryChain {
  chainId: string;
  sourceServerId: string;
  downstreamServerIds: string[];
  canaryToken: string;
  canaryPattern: string;
  createdAt: string;
}

const canaryChains = new Map<string, CanaryChain>();

/**
 * Compute a stable fingerprint for a profile. Two registrations with the
 * same effective profile must produce the same fingerprint.
 */
export function profileFingerprint(profile: IsolationProfile): string {
  const canonical = JSON.stringify({
    fsReadOnly: [...profile.fsReadOnly].sort(),
    fsWritable: [...profile.fsWritable].sort(),
    cpuMs: profile.cpuMs ?? null,
    memMB: profile.memMB ?? null,
    pidMax: profile.pidMax ?? null,
    egressAllowlist: [...profile.egressAllowlist].sort()
  });
  return createHash("sha256").update(canonical).digest("hex").slice(0, 32);
}

export function generateHandle(prefix = "sp"): string {
  return `${prefix}_${randomBytes(12).toString("hex")}`;
}

export function registerSubprocess(
  serverId: string,
  binary: string,
  args: string[],
  trustTier: RegisteredSubprocess["trustTier"],
  profile: IsolationProfile
): RegisteredSubprocess {
  const subprocessHandle = generateHandle();
  const now = new Date().toISOString();
  const record: RegisteredSubprocess = {
    subprocessHandle,
    serverId,
    binary,
    args: [...args],
    trustTier,
    profile,
    profileFingerprint: profileFingerprint(profile),
    egressMode: "default-deny",
    egressModeSetAt: now,
    blockedEgressAttempts: 0,
    registeredAt: now
  };
  subprocesses.set(subprocessHandle, record);
  return record;
}

export function getSubprocess(handle: string): RegisteredSubprocess | undefined {
  return subprocesses.get(handle);
}

export function listSubprocesses(): readonly RegisteredSubprocess[] {
  return Array.from(subprocesses.values());
}

export function updateEgressPolicy(
  handle: string,
  allowlist: string[],
  mode: EgressMode
): RegisteredSubprocess | undefined {
  const record = subprocesses.get(handle);
  if (!record) return undefined;
  record.profile = {
    ...record.profile,
    egressAllowlist: [...allowlist]
  };
  record.profileFingerprint = profileFingerprint(record.profile);
  // Only bump egressModeSetAt when the mode actually transitions. Pure
  // allowlist edits without mode-change keep the original timestamp so the
  // staleness WARN measures actual mode-dwell time, not edit churn.
  if (record.egressMode !== mode) {
    record.egressMode = mode;
    record.egressModeSetAt = new Date().toISOString();
  }
  return record;
}

export function bumpBlockedEgress(handle: string, by = 1): void {
  const record = subprocesses.get(handle);
  if (!record) return;
  record.blockedEgressAttempts += by;
}

export function clearRegistry(): void {
  subprocesses.clear();
  canaryChains.clear();
}

/* canary chains */

export function generateCanaryToken(): string {
  // 32-byte high-entropy hex; prefix marks it as a canary so legitimate
  // tools can detect + redact in their logs.
  return `__MCP_CANARY_${randomBytes(32).toString("hex")}__`;
}

export function registerCanaryChain(
  chainId: string,
  sourceServerId: string,
  downstreamServerIds: string[],
  canaryPattern: string,
  canaryToken: string
): CanaryChain {
  const chain: CanaryChain = {
    chainId,
    sourceServerId,
    downstreamServerIds: [...downstreamServerIds],
    canaryToken,
    canaryPattern,
    createdAt: new Date().toISOString()
  };
  canaryChains.set(chainId, chain);
  return chain;
}

export function getCanaryChain(chainId: string): CanaryChain | undefined {
  return canaryChains.get(chainId);
}
