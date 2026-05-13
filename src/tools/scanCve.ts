/**
 * Tool: scan_cve_replay
 *
 * Runs the built-in CVE replay fixtures against a target server command.
 * Returns overall pass/fail + per-CVE detail.
 *
 * Anti-Pattern provenance: alle 3 frischen 2026-CVEs (MCP-SDK-RCE
 * 22.04.2026, CVE-2026-27124 FastMCP Confused Deputy, Nginx-MCP RCE
 * CVSS 9.8). Predicates leben in src/cve/replay.ts und sind als
 * behavioral predicates designed (kein exploit payload).
 */

import {
  ScanCveReplayArgsSchema,
  type ScanCveReplayArgs
} from "../types.js";
import { runReplay, type ReplayResult } from "../cve/replay.js";
import { appendAudit } from "../audit/log.js";

export async function scanCveReplayTool(rawArgs: unknown): Promise<ReplayResult> {
  const args: ScanCveReplayArgs = ScanCveReplayArgsSchema.parse(rawArgs);

  const result = runReplay(args.targetServerCommand, args.cveSet, args.timeoutMs);

  await appendAudit({
    subprocessHandle: "n/a",
    action: "scan_cve_replay",
    verdict: result.overall,
    meta: {
      targetServerCommand: args.targetServerCommand,
      perCve: result.perCve.map((r) => ({ id: r.id, status: r.status }))
    }
  });

  return result;
}
