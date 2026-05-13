/**
 * macOS sandbox-exec policy synthesis.
 *
 * Emits a Scheme-syntax sandbox profile (.sb) that can be passed to
 * `/usr/bin/sandbox-exec -p` before the target binary. Apple's sandbox-exec
 * is non-public-API but stable since 10.5; v0.1 ships it, v0.2 evaluates
 * App Sandbox via Entitlements as fallback (per Architect-Empfehlung).
 */

import type { IsolationProfile } from "../types.js";

/**
 * Build a sandbox-exec profile string from an isolation profile.
 *
 * Default-deny + per-rule allow. The sandbox profile language is Scheme-derived,
 * see `man sandbox-exec` and `/usr/share/sandbox/`.
 */
export function buildSandboxProfile(profile: IsolationProfile): string {
  const lines: string[] = [
    "(version 1)",
    "(deny default)",
    "(allow process-fork)",
    "(allow process-exec self)",
    "(allow signal (target self))",
    "(allow sysctl-read)",
    "(allow mach-lookup)",
    "(allow ipc-posix-shm)",
    "(allow file-read-metadata)"
  ];

  for (const path of profile.fsReadOnly) {
    lines.push(`(allow file-read* (subpath "${escapeSchemeString(path)}"))`);
    lines.push(`(allow process-exec (subpath "${escapeSchemeString(path)}"))`);
  }
  for (const path of profile.fsWritable) {
    lines.push(`(allow file-read* file-write* (subpath "${escapeSchemeString(path)}"))`);
  }

  // Network egress: default-deny. Allowlist entries are emitted as remote-host
  // matchers. Wildcard "*" permits all (audit-only mode).
  if (profile.egressAllowlist.includes("*")) {
    lines.push("(allow network-outbound)");
  } else {
    for (const entry of profile.egressAllowlist) {
      const [host, port] = parseHostPort(entry);
      if (host && port) {
        lines.push(
          `(allow network-outbound (remote ip "${escapeSchemeString(host)}:${port}"))`
        );
      }
    }
  }

  return lines.join("\n") + "\n";
}

function parseHostPort(entry: string): [string | null, string | null] {
  const m = entry.match(/^([^:]+):(\d+)$/);
  if (!m || !m[1] || !m[2]) return [null, null];
  return [m[1], m[2]];
}

function escapeSchemeString(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}
