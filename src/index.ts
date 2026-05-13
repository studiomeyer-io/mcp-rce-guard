/**
 * mcp-rce-guard — public library entrypoint.
 *
 * This module re-exports the building blocks for callers that want to
 * embed mcp-rce-guard in their own MCP server / CLI tool.
 */

export { NAME, VERSION } from "./version.js";

// Types + schemas
export {
  IsolationProfileSchema,
  RegisterSubprocessArgsSchema,
  AuditSubprocessArgsSchema,
  ScanCveReplayArgsSchema,
  TrackCanaryArgsSchema,
  InjectEgressPolicyArgsSchema,
  GetAuditLogArgsSchema,
  TrustTierSchema,
  CveIdSchema,
  EgressModeSchema,
  AuditVerdict,
  type IsolationProfile,
  type RegisterSubprocessArgs,
  type AuditSubprocessArgs,
  type ScanCveReplayArgs,
  type TrackCanaryArgs,
  type InjectEgressPolicyArgs,
  type GetAuditLogArgs,
  type AuditLogEntry,
  type RegisteredSubprocess,
  type AuditVerdictType,
  type CveId,
  type EgressMode
} from "./types.js";

// Normalize (Pillar-8-shared)
export { normalizeArg, normalizeArgs, hasInvisibleCodepoints } from "./normalize.js";

// Trust tiers
export {
  TRUST_TIER_DEFAULTS,
  resolveProfile,
  type TrustTier
} from "./trust-tiers.js";

// Isolation backends
export {
  detectPlatform,
  type PlatformInfo,
  type IsolationBackend
} from "./isolation/platform.js";
export { buildLandlockPolicy, policyAllowsExec } from "./isolation/landlock.js";
export type { LandlockPolicyDescriptor } from "./isolation/landlock.js";
export { buildSandboxProfile } from "./isolation/sandbox-exec.js";
export { buildCgroupSpec, type CgroupSpec } from "./isolation/cgroups.js";

// Canary
export {
  makeCanary,
  detectLeaks,
  type LeakChannel,
  type LeakLocation,
  type CorpusEntry
} from "./canary/tracker.js";

// CVE replay
export {
  runReplay,
  BUILT_IN_FIXTURES,
  getFixture,
  type CveFixture,
  type ReplayResult,
  type ReplayPerCve
} from "./cve/replay.js";

// Egress
export { evaluateEgress, type EgressDecision } from "./egress/policy.js";

// Audit log
// Note: `clearAuditLog` is intentionally NOT re-exported here (Pre-Publish-Audit F9).
// It is a @internal test helper; tests import it directly from "./audit/log.js".
export { appendAudit, readAudit, auditLogPath } from "./audit/log.js";

// Tools (programmatic access — same handlers the MCP server registers)
export {
  registerSubprocessTool,
  type RegisterSubprocessResult
} from "./tools/register.js";
export {
  auditSubprocessTool,
  type AuditSubprocessResult
} from "./tools/audit.js";
export { scanCveReplayTool } from "./tools/scanCve.js";
export {
  trackCanaryTool,
  type TrackCanaryResult
} from "./tools/trackCanary.js";
export {
  injectEgressPolicyTool,
  type InjectEgressPolicyResult
} from "./tools/injectEgress.js";
export {
  getAuditLogTool,
  type GetAuditLogResult
} from "./tools/getAuditLog.js";

// State (test-only escape hatch — guarded by name)
export { clearRegistry } from "./state.js";
