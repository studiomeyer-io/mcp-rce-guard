/**
 * Tool: get_audit_log
 *
 * Read-only access to the NDJSON audit log. Filterable by subprocessHandle,
 * since-timestamp, and limit.
 *
 * Additionally emits a `staleEgressModeWarnings` array: every currently-
 * registered subprocess that has been left in egressMode="audit-only" longer
 * than `staleEgressModeThresholdDays` (default 7) is surfaced as a WARN.
 * This implements the PLAN.md §Predicted-Impact §inject_egress_policy
 * at-risk-regression-mitigation ("Reviewer-Pass im Pillar-9-Audit-Tool
 * flaggt 'Mode: audit-only seit >7d' als WARN") so operators do not
 * silently sit on a soft policy.
 *
 * Log rotation lives in audit/log.ts (auto-rotate on 100MB threshold,
 * 10 backups, `mcp-rce-guard cleanup` CLI for manual purge).
 */

import {
  GetAuditLogArgsSchema,
  type GetAuditLogArgs,
  type AuditLogEntry,
  type StaleEgressModeWarning
} from "../types.js";
import { readAudit } from "../audit/log.js";
import { listSubprocesses } from "../state.js";

export interface GetAuditLogResult {
  entries: AuditLogEntry[];
  staleEgressModeWarnings: StaleEgressModeWarning[];
}

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * Build the staleness-WARN list. A subprocess is stale if:
 *   - egressMode === "audit-only", AND
 *   - now() - egressModeSetAt > thresholdDays
 *
 * Threshold 0 disables the check (returns empty array). Subprocesses with
 * an unparseable egressModeSetAt are skipped silently — better to under-warn
 * than to false-positive on a malformed timestamp.
 */
export function computeStaleEgressModeWarnings(
  thresholdDays: number,
  now: Date = new Date()
): StaleEgressModeWarning[] {
  if (thresholdDays <= 0) return [];
  const warnings: StaleEgressModeWarning[] = [];
  for (const sp of listSubprocesses()) {
    if (sp.egressMode !== "audit-only") continue;
    const setAt = Date.parse(sp.egressModeSetAt);
    if (!Number.isFinite(setAt)) continue;
    const ageDays = (now.getTime() - setAt) / MS_PER_DAY;
    if (ageDays > thresholdDays) {
      warnings.push({
        subprocessHandle: sp.subprocessHandle,
        serverId: sp.serverId,
        egressMode: sp.egressMode,
        egressModeSetAt: sp.egressModeSetAt,
        ageDays: Math.round(ageDays * 100) / 100
      });
    }
  }
  return warnings;
}

export async function getAuditLogTool(rawArgs: unknown): Promise<GetAuditLogResult> {
  const args: GetAuditLogArgs = GetAuditLogArgsSchema.parse(rawArgs);

  const filter: {
    subprocessHandle?: string;
    since?: string;
    limit?: number;
  } = { limit: args.limit };
  if (args.subprocessHandle !== undefined) filter.subprocessHandle = args.subprocessHandle;
  if (args.since !== undefined) filter.since = args.since;

  const entries = await readAudit(filter);
  const staleEgressModeWarnings = computeStaleEgressModeWarnings(
    args.staleEgressModeThresholdDays
  );

  return { entries, staleEgressModeWarnings };
}
