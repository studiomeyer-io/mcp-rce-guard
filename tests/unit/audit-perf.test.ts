/**
 * Performance regression for audit_subprocess hot-path (Reviewer S1024 F5).
 *
 * PLAN.md §Performance commits to "audit_subprocess p95 <200ms" as a hard
 * v0.1 gate. This test runs 10_000 audits against a registered subprocess
 * and asserts the 95th-percentile latency stays under that threshold on the
 * CI runner.
 *
 * The cap is generous on purpose: in-memory state + a single fs.appendFile
 * per call is the hot-path, and we want to catch regressions from
 * accidentally-quadratic allowlist checks or extra fs round-trips.
 */

import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import { registerSubprocessTool } from "../../src/tools/register.js";
import { auditSubprocessTool } from "../../src/tools/audit.js";
import { clearAuditLog } from "../../src/audit/log.js";
import { clearRegistry } from "../../src/state.js";

const SAMPLES = 10_000;
const P95_BUDGET_MS = 200;

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx] ?? 0;
}

describe("audit_subprocess perf gate (Reviewer S1024 F5)", () => {
  let handle = "";

  beforeAll(async () => {
    await clearAuditLog();
  });

  beforeEach(() => {
    clearRegistry();
  });

  it(`registers a subprocess and runs ${SAMPLES} audits under p95=${P95_BUDGET_MS}ms`, async () => {
    const reg = await registerSubprocessTool({
      serverId: "perf-test",
      binary: "/usr/bin/node",
      args: ["server.js", "--port", "9999"],
      trustTier: "MEDIUM"
    });
    handle = reg.subprocessHandle;
    expect(handle).toMatch(/^sp_/);

    const durations: number[] = new Array(SAMPLES);
    for (let i = 0; i < SAMPLES; i++) {
      const start = process.hrtime.bigint();
      await auditSubprocessTool({
        subprocessHandle: handle,
        requestedArgs: ["server.js", "--port", "9999"]
      });
      const end = process.hrtime.bigint();
      durations[i] = Number(end - start) / 1_000_000; // ns → ms
    }
    durations.sort((a, b) => a - b);
    const p50 = percentile(durations, 50);
    const p95 = percentile(durations, 95);
    const p99 = percentile(durations, 99);
    const last = durations[durations.length - 1] ?? 0;

    // Surface the numbers in the test output so a regression is debuggable.
    // eslint-disable-next-line no-console
    console.log(
      `[audit_subprocess perf] N=${SAMPLES} p50=${p50.toFixed(3)}ms p95=${p95.toFixed(3)}ms p99=${p99.toFixed(3)}ms max=${last.toFixed(3)}ms`
    );

    expect(p95).toBeLessThan(P95_BUDGET_MS);
  }, 60_000);
});
