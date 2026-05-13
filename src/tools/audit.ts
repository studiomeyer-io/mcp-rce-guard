/**
 * Tool: audit_subprocess
 *
 * Verifies a candidate args set against the registered subprocess profile.
 * Returns approve | block | quarantine + reason.
 *
 * Layer-2 (Pillar 8) interaction: args are normalized via the shared
 * normalize.ts pipeline (NFKC + ZWC + Bidi) before any comparison.
 *
 * Layer-1 (Pillar 1) interaction: when MCP_RCE_GUARD_PILLAR1_FINGERPRINT is
 * set in the environment, the tool reflects that into pillar1Fingerprint
 * for cross-pillar audit traceability. v0.1 trust-on-first-use, v0.2 will
 * verify against a Sigstore key.
 *
 * Anti-Pattern provenance: MCP-SDK-RCE 22.04.2026 (Tool-Args ungesanitized
 * in subprocess command-strings).
 */

import {
  AuditSubprocessArgsSchema,
  type AuditSubprocessArgs,
  type AuditVerdictType
} from "../types.js";
import { getSubprocess } from "../state.js";
import { normalizeArgs, hasInvisibleCodepoints } from "../normalize.js";
import { appendAudit } from "../audit/log.js";

export interface AuditSubprocessResult {
  verdict: AuditVerdictType;
  reason: string;
  pillar1Fingerprint?: string;
  pillar8Allowlist: "pass" | "fail";
}

export async function auditSubprocessTool(
  rawArgs: unknown
): Promise<AuditSubprocessResult> {
  const args: AuditSubprocessArgs = AuditSubprocessArgsSchema.parse(rawArgs);

  const record = getSubprocess(args.subprocessHandle);
  if (!record) {
    const result: AuditSubprocessResult = {
      verdict: "block",
      reason: `unknown subprocess handle: ${args.subprocessHandle}`,
      pillar8Allowlist: "fail"
    };
    await appendAudit({
      subprocessHandle: args.subprocessHandle,
      action: "audit_subprocess",
      verdict: "block",
      reason: result.reason
    });
    return result;
  }

  // Pillar 8: normalize + allowlist check.
  const normalizedRequested = normalizeArgs(args.requestedArgs);
  const normalizedRegistered = normalizeArgs(record.args);

  // Detection signal: any invisible codepoint in requested args raises
  // suspicion even if normalization makes the args comparable.
  const suspicious = args.requestedArgs.some(hasInvisibleCodepoints);

  // Allowlist semantics: requested args must be a prefix/exact-match of
  // registered args (the registered args are the *trusted invocation*).
  let pillar8: "pass" | "fail" = "pass";
  let mismatchReason = "";
  if (normalizedRequested.length !== normalizedRegistered.length) {
    pillar8 = "fail";
    mismatchReason = `arg-count mismatch: requested=${normalizedRequested.length}, registered=${normalizedRegistered.length}`;
  } else {
    for (let i = 0; i < normalizedRequested.length; i++) {
      if (normalizedRequested[i] !== normalizedRegistered[i]) {
        pillar8 = "fail";
        mismatchReason = `arg[${i}] mismatch: requested=${JSON.stringify(normalizedRequested[i])}, registered=${JSON.stringify(normalizedRegistered[i])}`;
        break;
      }
    }
  }

  let verdict: AuditVerdictType;
  let reason: string;
  if (pillar8 === "fail") {
    verdict = "block";
    reason = `Pillar-8 allowlist fail: ${mismatchReason}`;
  } else if (suspicious) {
    verdict = "quarantine";
    reason = "args contain invisible/bidi codepoints; quarantine for human review";
  } else {
    verdict = "approve";
    reason = "Pillar-8 allowlist pass + no suspicious codepoints";
  }

  const pillar1 = process.env["MCP_RCE_GUARD_PILLAR1_FINGERPRINT"];

  const result: AuditSubprocessResult = {
    verdict,
    reason,
    pillar8Allowlist: pillar8,
    ...(pillar1 ? { pillar1Fingerprint: pillar1 } : {})
  };

  await appendAudit({
    subprocessHandle: record.subprocessHandle,
    serverId: record.serverId,
    action: "audit_subprocess",
    verdict,
    reason,
    meta: {
      pillar8: pillar8,
      suspicious,
      profileFingerprint: record.profileFingerprint
    }
  });

  return result;
}
