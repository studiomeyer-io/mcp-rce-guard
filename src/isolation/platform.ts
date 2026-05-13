/**
 * Platform detection for isolation backends.
 *
 * v0.1 supports Linux (landlock + cgroups-v2) and macOS (sandbox-exec).
 * Windows is v0.2 backlog (AppContainer + Win Sandbox-API).
 */

import { existsSync, readFileSync } from "node:fs";
import { platform } from "node:process";

export type IsolationBackend = "landlock" | "sandbox-exec" | "unsupported";

export interface PlatformInfo {
  os: NodeJS.Platform;
  backend: IsolationBackend;
  /** Linux kernel version, e.g. "5.15.0". Empty on non-Linux. */
  kernelVersion: string;
  /** True if cgroups-v2 unified hierarchy is mounted at /sys/fs/cgroup. */
  hasCgroupsV2: boolean;
  /** True if the running kernel exposes landlock syscalls (kernel >=5.13). */
  hasLandlock: boolean;
  /** True if /usr/bin/sandbox-exec is present (macOS only). */
  hasSandboxExec: boolean;
  /** Human-readable reason if backend is "unsupported". */
  reason?: string;
}

let cached: PlatformInfo | null = null;

export function detectPlatform(): PlatformInfo {
  if (cached) return cached;

  const os = platform;
  let backend: IsolationBackend = "unsupported";
  let kernelVersion = "";
  let hasCgroupsV2 = false;
  let hasLandlock = false;
  let hasSandboxExec = false;
  let reason: string | undefined;

  if (os === "linux") {
    kernelVersion = readKernelVersion();
    hasLandlock = kernelMeetsMin(kernelVersion, 5, 13);
    hasCgroupsV2 = isCgroupsV2();
    if (hasLandlock) {
      backend = "landlock";
    } else {
      reason = `Linux kernel ${kernelVersion} does not support landlock (need >=5.13)`;
    }
  } else if (os === "darwin") {
    hasSandboxExec = existsSync("/usr/bin/sandbox-exec");
    if (hasSandboxExec) {
      backend = "sandbox-exec";
    } else {
      reason = "macOS sandbox-exec binary not found at /usr/bin/sandbox-exec";
    }
  } else {
    reason = `Platform ${os} is not supported in v0.1 (Windows is v0.2 backlog)`;
  }

  const info: PlatformInfo = {
    os,
    backend,
    kernelVersion,
    hasCgroupsV2,
    hasLandlock,
    hasSandboxExec,
    ...(reason !== undefined ? { reason } : {})
  };
  cached = info;
  return info;
}

/**
 * Test helper: reset the cache. Required because detection uses fs reads.
 */
export function _resetPlatformCache(): void {
  cached = null;
}

function readKernelVersion(): string {
  try {
    const raw = readFileSync("/proc/version", "utf8");
    const m = raw.match(/Linux version (\d+\.\d+\.\d+)/);
    return m?.[1] ?? "";
  } catch {
    return "";
  }
}

function kernelMeetsMin(version: string, minMajor: number, minMinor: number): boolean {
  const parts = version.split(".").map((p) => parseInt(p, 10));
  const major = parts[0];
  const minor = parts[1];
  if (major === undefined || minor === undefined || Number.isNaN(major) || Number.isNaN(minor)) {
    return false;
  }
  if (major > minMajor) return true;
  if (major < minMajor) return false;
  return minor >= minMinor;
}

function isCgroupsV2(): boolean {
  try {
    const mounts = readFileSync("/proc/mounts", "utf8");
    return mounts.split("\n").some((line) => {
      const fields = line.split(/\s+/);
      return fields[2] === "cgroup2";
    });
  } catch {
    return false;
  }
}
