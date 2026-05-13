/**
 * cgroups-v2 resource cap synthesis.
 *
 * v0.1 emits a *spec* listing the files-to-write and values. The actual
 * write happens in the spawning helper (separation-of-concerns: we don't
 * want to write to /sys/fs/cgroup from inside a tool handler — that needs
 * elevated privileges that the MCP server typically lacks).
 */

import type { IsolationProfile } from "../types.js";

export interface CgroupSpec {
  /** cgroup v2 path under /sys/fs/cgroup. The spawner creates it. */
  cgroupPath: string;
  /** key/value writes the spawner must perform. */
  writes: Array<{ file: string; value: string }>;
}

export function buildCgroupSpec(
  cgroupName: string,
  profile: IsolationProfile
): CgroupSpec {
  const cgroupPath = `/sys/fs/cgroup/${cgroupName}`;
  const writes: CgroupSpec["writes"] = [];

  if (profile.memMB !== undefined) {
    // memory.max accepts bytes.
    const bytes = profile.memMB * 1024 * 1024;
    writes.push({ file: `${cgroupPath}/memory.max`, value: String(bytes) });
  }
  if (profile.pidMax !== undefined) {
    writes.push({ file: `${cgroupPath}/pids.max`, value: String(profile.pidMax) });
  }
  if (profile.cpuMs !== undefined) {
    // cpu.max format: "<quota> <period>". 100ms period; quota = cpuMs * 1000 / period_count.
    // Simplified: derive quota_us = cpuMs * 1000 spread over a 100_000us period.
    // For caps on TOTAL CPU time the spawner uses RLIMIT_CPU instead — see spec.
    const periodUs = 100_000;
    const quotaUs = Math.max(1000, Math.min(periodUs, profile.cpuMs * 1000));
    writes.push({
      file: `${cgroupPath}/cpu.max`,
      value: `${quotaUs} ${periodUs}`
    });
  }

  return { cgroupPath, writes };
}
