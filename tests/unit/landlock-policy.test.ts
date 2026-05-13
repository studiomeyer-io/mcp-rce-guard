import { describe, it, expect } from "vitest";
import {
  buildLandlockPolicy,
  policyAllowsExec
} from "../../src/isolation/landlock.js";
import { buildSandboxProfile } from "../../src/isolation/sandbox-exec.js";
import { buildCgroupSpec } from "../../src/isolation/cgroups.js";

describe("buildLandlockPolicy", () => {
  it("emits read+execute for fsReadOnly entries", () => {
    const p = buildLandlockPolicy({
      fsReadOnly: ["/usr"],
      fsWritable: [],
      egressAllowlist: []
    });
    const rule = p.ruleset.rules.find((r) => r.path === "/usr");
    expect(rule).toBeDefined();
    expect(rule?.access).toContain("read");
    expect(rule?.access).toContain("execute");
    expect(rule?.access).not.toContain("write");
  });

  it("emits read+execute+write for fsWritable entries", () => {
    const p = buildLandlockPolicy({
      fsReadOnly: [],
      fsWritable: ["/tmp/scratch"],
      egressAllowlist: []
    });
    const rule = p.ruleset.rules.find((r) => r.path === "/tmp/scratch");
    expect(rule?.access).toContain("write");
  });

  it("policyAllowsExec returns true for binary inside read-only root", () => {
    const p = buildLandlockPolicy({
      fsReadOnly: ["/usr/bin"],
      fsWritable: [],
      egressAllowlist: []
    });
    expect(policyAllowsExec(p, "/usr/bin/node")).toBe(true);
  });

  it("policyAllowsExec returns false for binary outside policy", () => {
    const p = buildLandlockPolicy({
      fsReadOnly: ["/usr/bin"],
      fsWritable: [],
      egressAllowlist: []
    });
    expect(policyAllowsExec(p, "/opt/evil/bin/x")).toBe(false);
  });
});

describe("buildSandboxProfile", () => {
  it("emits version + deny default", () => {
    const out = buildSandboxProfile({
      fsReadOnly: ["/usr"],
      fsWritable: [],
      egressAllowlist: []
    });
    expect(out).toMatch(/\(version 1\)/);
    expect(out).toMatch(/\(deny default\)/);
    expect(out).toMatch(/\(allow file-read.*\/usr/);
  });

  it("emits allow network-outbound on wildcard", () => {
    const out = buildSandboxProfile({
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: ["*"]
    });
    expect(out).toMatch(/\(allow network-outbound\)/);
  });

  it("emits per-host network-outbound rules", () => {
    const out = buildSandboxProfile({
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: ["api.example.com:443"]
    });
    expect(out).toMatch(/\(allow network-outbound \(remote ip "api.example.com:443"\)\)/);
  });
});

describe("buildCgroupSpec", () => {
  it("emits memory.max + pids.max + cpu.max writes", () => {
    const spec = buildCgroupSpec("test", {
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: [],
      memMB: 64,
      pidMax: 16,
      cpuMs: 5000
    });
    const memWrite = spec.writes.find((w) => w.file.endsWith("memory.max"));
    expect(memWrite?.value).toBe(String(64 * 1024 * 1024));

    const pidsWrite = spec.writes.find((w) => w.file.endsWith("pids.max"));
    expect(pidsWrite?.value).toBe("16");

    const cpuWrite = spec.writes.find((w) => w.file.endsWith("cpu.max"));
    expect(cpuWrite).toBeDefined();
  });

  it("omits writes for unset caps", () => {
    const spec = buildCgroupSpec("test", {
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: []
    });
    expect(spec.writes).toHaveLength(0);
  });
});
