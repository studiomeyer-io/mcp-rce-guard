/**
 * Linux landlock policy synthesis.
 *
 * v0.1 emits a *policy descriptor* — a serializable representation of the
 * landlock ruleset — but does NOT directly invoke the prctl/landlock_create_ruleset
 * syscalls. Reason: the landlock syscall interface requires either a tiny native
 * addon or a `libc.dlopen` dance, both of which add binary-distribution complexity.
 *
 * The actual enforcement contract is: the spawning helper uses the `landlock-restrict`
 * tool (bundled in `mcp-rce-fixtures` for v0.1; will become its own bin in v0.2)
 * to apply the policy descriptor before exec'ing the target binary. Same pattern
 * as `firejail` or `bubblewrap` — split policy-eval from enforcement.
 *
 * Anti-Pattern provenance: Nginx-MCP RCE CVSS 9.8 (subprocess inheritert volle
 * parent-permissions). Defense: explicit policy descriptor that lists every
 * allowed fs path + access flag.
 */

import type { IsolationProfile } from "../types.js";

export interface LandlockPolicyDescriptor {
  version: 1;
  ruleset: {
    handledAccessFs: string[];
    rules: Array<{
      path: string;
      access: ("read" | "execute" | "write")[];
    }>;
  };
}

/**
 * Build a landlock policy descriptor from an isolation profile.
 *
 * - fsReadOnly entries → read+execute access.
 * - fsWritable entries → read+execute+write access.
 * - Everything else: implicit deny.
 */
export function buildLandlockPolicy(profile: IsolationProfile): LandlockPolicyDescriptor {
  const rules: LandlockPolicyDescriptor["ruleset"]["rules"] = [];

  for (const path of profile.fsReadOnly) {
    rules.push({ path, access: ["read", "execute"] });
  }
  for (const path of profile.fsWritable) {
    rules.push({ path, access: ["read", "execute", "write"] });
  }

  return {
    version: 1,
    ruleset: {
      handledAccessFs: [
        "execute",
        "write_file",
        "read_file",
        "read_dir",
        "remove_dir",
        "remove_file",
        "make_char",
        "make_dir",
        "make_reg",
        "make_sock",
        "make_fifo",
        "make_block",
        "make_sym"
      ],
      rules
    }
  };
}

/**
 * Validate that a path appears in the policy. Used by audit_subprocess to
 * detect when the requested binary lives outside the read-only roots.
 */
export function policyAllowsExec(
  policy: LandlockPolicyDescriptor,
  binaryPath: string
): boolean {
  for (const rule of policy.ruleset.rules) {
    if (binaryPath.startsWith(rule.path) && rule.access.includes("execute")) {
      return true;
    }
  }
  return false;
}
