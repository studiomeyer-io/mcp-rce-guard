/**
 * Shared types + Zod schemas for mcp-rce-guard tools.
 */

import { z } from "zod";

/**
 * Isolation profile applied to a subprocess at register_subprocess time.
 * Field semantics are platform-dependent — see src/isolation/{landlock,sandbox-exec,cgroups}.ts
 * for how each field is realized on Linux + macOS.
 */
export interface IsolationProfile {
  /** Read-only filesystem roots the subprocess may traverse. */
  fsReadOnly: string[];
  /** Writable scratch directories (typically per-spawn ephemeral). */
  fsWritable: string[];
  /** CPU time cap in milliseconds. Soft cap, enforced via cgroups-v2 cpu.max on Linux. */
  cpuMs?: number;
  /** RSS cap in megabytes. Hard cap, enforced via cgroups-v2 memory.max on Linux. */
  memMB?: number;
  /** Max child PIDs. Hard cap, enforced via cgroups-v2 pids.max on Linux. */
  pidMax?: number;
  /**
   * Network egress allowlist as host:port pairs. "*" allows all (audit-only).
   * Default-deny: empty array blocks all egress.
   */
  egressAllowlist: string[];
}

export const IsolationProfileSchema = z.object({
  fsReadOnly: z.array(z.string()).default([]),
  fsWritable: z.array(z.string()).default([]),
  cpuMs: z.number().int().positive().optional(),
  memMB: z.number().int().positive().optional(),
  pidMax: z.number().int().positive().optional(),
  egressAllowlist: z.array(z.string()).default([])
});

export const TrustTierSchema = z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);

/**
 * Args for register_subprocess.
 */
export const RegisterSubprocessArgsSchema = z.object({
  serverId: z.string().min(1).max(200),
  binary: z.string().min(1).max(1000),
  args: z.array(z.string().max(4000)).max(256).default([]),
  trustTier: TrustTierSchema,
  isolationProfile: IsolationProfileSchema.partial().default({})
});
export type RegisterSubprocessArgs = z.infer<typeof RegisterSubprocessArgsSchema>;

/**
 * Args for audit_subprocess.
 */
export const AuditSubprocessArgsSchema = z.object({
  subprocessHandle: z.string().min(1),
  requestedArgs: z.array(z.string().max(4000)).max(256)
});
export type AuditSubprocessArgs = z.infer<typeof AuditSubprocessArgsSchema>;

export const AuditVerdict = z.enum(["approve", "block", "quarantine"]);
export type AuditVerdictType = z.infer<typeof AuditVerdict>;

/**
 * Args for scan_cve_replay.
 */
export const CveIdSchema = z.enum([
  "mcp-sdk-rce-2026-04-22",
  "cve-2026-27124",
  "nginx-mcp-rce-9.8"
]);
export type CveId = z.infer<typeof CveIdSchema>;

export const ScanCveReplayArgsSchema = z.object({
  targetServerCommand: z.string().min(1).max(2000),
  cveSet: z.array(CveIdSchema).min(1).max(16).optional(),
  timeoutMs: z.number().int().positive().max(300_000).default(30_000)
});
export type ScanCveReplayArgs = z.infer<typeof ScanCveReplayArgsSchema>;

/**
 * Args for track_canary.
 */
export const TrackCanaryArgsSchema = z.object({
  chainId: z.string().min(1).max(200),
  sourceServerId: z.string().min(1).max(200),
  downstreamServerIds: z.array(z.string().min(1).max(200)).min(1).max(32),
  canaryPattern: z.string().min(8).max(256).optional()
});
export type TrackCanaryArgs = z.infer<typeof TrackCanaryArgsSchema>;

/**
 * Args for inject_egress_policy.
 */
export const EgressModeSchema = z.enum(["default-deny", "audit-only"]);
export type EgressMode = z.infer<typeof EgressModeSchema>;

export const InjectEgressPolicyArgsSchema = z.object({
  subprocessHandle: z.string().min(1),
  allowlist: z.array(z.string().min(1).max(500)).max(256),
  mode: EgressModeSchema
});
export type InjectEgressPolicyArgs = z.infer<typeof InjectEgressPolicyArgsSchema>;

/**
 * Args for get_audit_log.
 *
 * `staleEgressModeThresholdDays` (default 7) drives the audit-only-staleness
 * WARN list — see PLAN.md §Predicted-Impact §inject_egress_policy
 * at-risk-regression-mitigation. Operators can lower the threshold for
 * stricter staleness or set it to 0 to disable the check.
 */
export const GetAuditLogArgsSchema = z.object({
  subprocessHandle: z.string().min(1).optional(),
  since: z.string().datetime().optional(),
  limit: z.number().int().positive().max(10_000).default(100),
  staleEgressModeThresholdDays: z
    .number()
    .int()
    .min(0)
    .max(365)
    .default(7)
});
export type GetAuditLogArgs = z.infer<typeof GetAuditLogArgsSchema>;

/**
 * One entry in the get_audit_log staleness-WARN list. Emitted when a
 * registered subprocess has been left in egressMode="audit-only" longer
 * than `staleEgressModeThresholdDays`. See PLAN.md §Predicted-Impact
 * §inject_egress_policy.
 */
export interface StaleEgressModeWarning {
  subprocessHandle: string;
  serverId: string;
  egressMode: EgressMode;
  egressModeSetAt: string;
  ageDays: number;
}

/**
 * Audit-log entry shape (NDJSON line in ~/.mcp-rce-guard/audit.log).
 */
export interface AuditLogEntry {
  ts: string;
  subprocessHandle: string;
  action: string;
  verdict: string;
  serverId?: string;
  reason?: string;
  meta?: Record<string, unknown>;
}

/**
 * Internal subprocess registry record.
 */
export interface RegisteredSubprocess {
  subprocessHandle: string;
  serverId: string;
  binary: string;
  args: string[];
  trustTier: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  profile: IsolationProfile;
  profileFingerprint: string;
  /** Active egress mode after inject_egress_policy. Defaults to default-deny. */
  egressMode: EgressMode;
  /**
   * ISO timestamp of the last egress-mode transition. Initialised to
   * registeredAt and bumped on every inject_egress_policy that successfully
   * applies. Drives the audit-only-staleness WARN in get_audit_log.
   */
  egressModeSetAt: string;
  /** Tracked blocked-egress attempts since policy injection. */
  blockedEgressAttempts: number;
  registeredAt: string;
}
