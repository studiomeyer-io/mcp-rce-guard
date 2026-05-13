/**
 * Tool: register_subprocess
 *
 * Registers a subprocess spec + isolation profile and returns a handle.
 * Profile defaults are filled in from the trust tier; caller-supplied
 * fields override the tier defaults.
 *
 * Anti-Pattern provenance: Nginx-MCP RCE CVSS 9.8 (subprocess inheritert
 * volle parent-permissions weil keine Profile-Defaults existieren).
 */

import {
  RegisterSubprocessArgsSchema,
  type RegisterSubprocessArgs
} from "../types.js";
import { resolveProfile } from "../trust-tiers.js";
import { registerSubprocess } from "../state.js";
import { appendAudit } from "../audit/log.js";
import { normalizeArg, normalizeArgs } from "../normalize.js";

export interface RegisterSubprocessResult {
  subprocessHandle: string;
  profileFingerprint: string;
}

export async function registerSubprocessTool(
  rawArgs: unknown
): Promise<RegisterSubprocessResult> {
  const args: RegisterSubprocessArgs = RegisterSubprocessArgsSchema.parse(rawArgs);

  // Pre-Publish-Audit F6: NFKC + ZWC-strip + Bidi-block on binary + args at
  // registration time so the stored allowlist is already in canonical form.
  // audit_subprocess normalizes the candidate args the same way; storing the
  // canonical form here removes a fullwidth-unicode bypass class where an
  // attacker registers a "binary" that includes invisible codepoints and
  // later spawns a normalized lookalike that compares equal.
  const normalizedBinary = normalizeArg(args.binary);
  const normalizedArgs = normalizeArgs(args.args);

  const profile = resolveProfile(args.trustTier, args.isolationProfile);
  const record = registerSubprocess(
    args.serverId,
    normalizedBinary,
    normalizedArgs,
    args.trustTier,
    profile
  );

  await appendAudit({
    subprocessHandle: record.subprocessHandle,
    serverId: record.serverId,
    action: "register_subprocess",
    verdict: "approve",
    meta: {
      binary: record.binary,
      trustTier: record.trustTier,
      profileFingerprint: record.profileFingerprint
    }
  });

  return {
    subprocessHandle: record.subprocessHandle,
    profileFingerprint: record.profileFingerprint
  };
}
