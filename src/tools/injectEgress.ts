/**
 * Tool: inject_egress_policy
 *
 * Updates a registered subprocess's egress allowlist + mode. Destructive:
 * modifies runtime policy. Returns applied + cumulative blocked-attempts
 * counter (since registration).
 *
 * Anti-Pattern provenance: Nginx-MCP RCE CVSS 9.8 (subprocess kann beliebig
 * egress → exfiltration via curl/wget/raw-socket vom kompromittierten
 * subprocess).
 *
 * Mode trade-off: audit-only erlaubt Operators die Policy zu bauen ohne
 * Production-Traffic zu brechen, aber ist eine "soft policy" — get_audit_log
 * markiert mode prominent damit Operator nicht in audit-only haengen bleiben.
 */

import {
  InjectEgressPolicyArgsSchema,
  type InjectEgressPolicyArgs
} from "../types.js";
import { updateEgressPolicy, getSubprocess } from "../state.js";
import { appendAudit } from "../audit/log.js";

export interface InjectEgressPolicyResult {
  applied: boolean;
  blockedAttempts: number;
}

export async function injectEgressPolicyTool(
  rawArgs: unknown
): Promise<InjectEgressPolicyResult> {
  const args: InjectEgressPolicyArgs = InjectEgressPolicyArgsSchema.parse(rawArgs);

  const updated = updateEgressPolicy(args.subprocessHandle, args.allowlist, args.mode);
  if (!updated) {
    await appendAudit({
      subprocessHandle: args.subprocessHandle,
      action: "inject_egress_policy",
      verdict: "block",
      reason: "unknown subprocess handle"
    });
    return { applied: false, blockedAttempts: 0 };
  }

  await appendAudit({
    subprocessHandle: updated.subprocessHandle,
    serverId: updated.serverId,
    action: "inject_egress_policy",
    verdict: "approve",
    meta: {
      mode: updated.egressMode,
      allowlistSize: args.allowlist.length,
      profileFingerprint: updated.profileFingerprint
    }
  });

  // Re-read counter (could have been bumped by a concurrent egress evaluator).
  const fresh = getSubprocess(updated.subprocessHandle);
  return {
    applied: true,
    blockedAttempts: fresh?.blockedEgressAttempts ?? 0
  };
}
