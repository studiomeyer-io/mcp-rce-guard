/**
 * Regression tests for Reviewer R3 F5 (audit-only-mode staleness WARN).
 *
 * Verifies:
 *   - computeStaleEgressModeWarnings only flags egressMode==="audit-only"
 *   - threshold=0 disables the check entirely
 *   - fresh audit-only entries (within threshold) are NOT flagged
 *   - stale audit-only entries (over threshold) ARE flagged
 *   - subprocesses with unparseable egressModeSetAt are skipped silently
 *   - updateEgressPolicy bumps egressModeSetAt ONLY on mode-transition
 *     (pure allowlist edits keep the original timestamp — Reviewer's intent
 *     is to flag long-running soft policy, not list churn)
 *
 * See PLAN.md §Predicted-Impact §inject_egress_policy
 * at-risk-regression-mitigation.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { computeStaleEgressModeWarnings } from "../../src/tools/getAuditLog.js";
import {
  clearRegistry,
  registerSubprocess,
  updateEgressPolicy,
  listSubprocesses
} from "../../src/state.js";

const MS_PER_DAY = 24 * 60 * 60 * 1000;

describe("computeStaleEgressModeWarnings (R3 F5)", () => {
  beforeEach(() => {
    clearRegistry();
  });

  it("returns empty array when threshold is 0 (disabled)", () => {
    const r = registerSubprocess("svc", "/bin/x", [], "LOW", {
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: []
    });
    // Move it into audit-only with a known-stale timestamp
    updateEgressPolicy(r.subprocessHandle, ["*"], "audit-only");
    // Manually back-date so it would normally be stale
    const sp = listSubprocesses().find(
      (s) => s.subprocessHandle === r.subprocessHandle
    )!;
    (sp as { egressModeSetAt: string }).egressModeSetAt = new Date(
      Date.now() - 30 * MS_PER_DAY
    ).toISOString();

    const w = computeStaleEgressModeWarnings(0);
    expect(w).toEqual([]);
  });

  it("ignores subprocesses NOT in audit-only mode", () => {
    // Fresh register → default-deny, never transitioned
    registerSubprocess("svc", "/bin/x", [], "LOW", {
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: []
    });
    const w = computeStaleEgressModeWarnings(7);
    expect(w).toEqual([]);
  });

  it("does NOT flag fresh audit-only (within threshold)", () => {
    const r = registerSubprocess("svc", "/bin/x", [], "LOW", {
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: []
    });
    updateEgressPolicy(r.subprocessHandle, ["*"], "audit-only");
    // Default egressModeSetAt is just-now → ageDays ≈ 0 → not stale
    const w = computeStaleEgressModeWarnings(7);
    expect(w).toEqual([]);
  });

  it("flags stale audit-only beyond threshold", () => {
    const r = registerSubprocess("svc-stale", "/bin/x", [], "LOW", {
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: []
    });
    updateEgressPolicy(r.subprocessHandle, ["*"], "audit-only");
    // Back-date 10 days ago
    const sp = listSubprocesses().find(
      (s) => s.subprocessHandle === r.subprocessHandle
    )!;
    (sp as { egressModeSetAt: string }).egressModeSetAt = new Date(
      Date.now() - 10 * MS_PER_DAY
    ).toISOString();

    const w = computeStaleEgressModeWarnings(7);
    expect(w).toHaveLength(1);
    expect(w[0]?.subprocessHandle).toBe(r.subprocessHandle);
    expect(w[0]?.serverId).toBe("svc-stale");
    expect(w[0]?.egressMode).toBe("audit-only");
    expect(w[0]?.ageDays).toBeGreaterThanOrEqual(10);
    expect(w[0]?.ageDays).toBeLessThan(10.1);
  });

  it("skips subprocesses with unparseable egressModeSetAt (under-warn)", () => {
    const r = registerSubprocess("svc", "/bin/x", [], "LOW", {
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: []
    });
    updateEgressPolicy(r.subprocessHandle, ["*"], "audit-only");
    const sp = listSubprocesses().find(
      (s) => s.subprocessHandle === r.subprocessHandle
    )!;
    (sp as { egressModeSetAt: string }).egressModeSetAt = "not-a-timestamp";

    const w = computeStaleEgressModeWarnings(7);
    expect(w).toEqual([]);
  });

  it("flags multiple stale subprocesses correctly", () => {
    const r1 = registerSubprocess("s1", "/bin/x", [], "LOW", {
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: []
    });
    const r2 = registerSubprocess("s2", "/bin/y", [], "LOW", {
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: []
    });
    const r3 = registerSubprocess("s3-fresh", "/bin/z", [], "LOW", {
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: []
    });

    updateEgressPolicy(r1.subprocessHandle, ["*"], "audit-only");
    updateEgressPolicy(r2.subprocessHandle, ["*"], "audit-only");
    updateEgressPolicy(r3.subprocessHandle, ["*"], "audit-only");

    const stale1 = listSubprocesses().find(
      (s) => s.subprocessHandle === r1.subprocessHandle
    )!;
    const stale2 = listSubprocesses().find(
      (s) => s.subprocessHandle === r2.subprocessHandle
    )!;
    (stale1 as { egressModeSetAt: string }).egressModeSetAt = new Date(
      Date.now() - 8 * MS_PER_DAY
    ).toISOString();
    (stale2 as { egressModeSetAt: string }).egressModeSetAt = new Date(
      Date.now() - 14 * MS_PER_DAY
    ).toISOString();
    // r3 stays fresh

    const w = computeStaleEgressModeWarnings(7);
    expect(w).toHaveLength(2);
    const ids = w.map((e) => e.serverId).sort();
    expect(ids).toEqual(["s1", "s2"]);
  });
});

describe("updateEgressPolicy egressModeSetAt semantics (R3 F5)", () => {
  beforeEach(() => {
    clearRegistry();
  });

  it("initialises egressModeSetAt at register time", () => {
    const before = Date.now();
    const r = registerSubprocess("svc", "/bin/x", [], "LOW", {
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: []
    });
    const after = Date.now();
    const t = Date.parse(r.egressModeSetAt);
    expect(t).toBeGreaterThanOrEqual(before);
    expect(t).toBeLessThanOrEqual(after);
  });

  it("bumps egressModeSetAt on mode-transition", async () => {
    const r = registerSubprocess("svc", "/bin/x", [], "LOW", {
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: []
    });
    const initial = r.egressModeSetAt;
    // Tiny sleep so the new timestamp is strictly greater
    await new Promise((res) => setTimeout(res, 10));
    const updated = updateEgressPolicy(
      r.subprocessHandle,
      ["*"],
      "audit-only"
    );
    expect(updated).toBeDefined();
    expect(updated!.egressModeSetAt).not.toBe(initial);
    expect(Date.parse(updated!.egressModeSetAt)).toBeGreaterThan(
      Date.parse(initial)
    );
  });

  it("does NOT bump egressModeSetAt on pure allowlist edit (same mode)", async () => {
    const r = registerSubprocess("svc", "/bin/x", [], "LOW", {
      fsReadOnly: [],
      fsWritable: [],
      egressAllowlist: []
    });
    // Transition into audit-only once
    const first = updateEgressPolicy(
      r.subprocessHandle,
      ["api.a.com:443"],
      "audit-only"
    )!;
    const t1 = first.egressModeSetAt;
    await new Promise((res) => setTimeout(res, 10));
    // Pure allowlist edit, same mode
    const second = updateEgressPolicy(
      r.subprocessHandle,
      ["api.a.com:443", "api.b.com:443"],
      "audit-only"
    )!;
    expect(second.egressModeSetAt).toBe(t1);
  });
});
