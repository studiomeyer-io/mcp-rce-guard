import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync } from "node:fs";
import {
  appendAudit,
  readAudit,
  clearAuditLog,
  auditLogPath,
  rotateAuditLog
} from "../../src/audit/log.js";

describe("audit log", () => {
  beforeEach(async () => {
    await clearAuditLog();
  });

  it("appendAudit + readAudit round-trip", async () => {
    await appendAudit({
      subprocessHandle: "sp_test_1",
      action: "register_subprocess",
      verdict: "approve",
      serverId: "demo"
    });
    const entries = await readAudit({});
    expect(entries).toHaveLength(1);
    expect(entries[0]?.subprocessHandle).toBe("sp_test_1");
    expect(entries[0]?.serverId).toBe("demo");
    expect(entries[0]?.ts).toMatch(/\d{4}-\d{2}-\d{2}T/);
  });

  it("filter by subprocessHandle", async () => {
    await appendAudit({
      subprocessHandle: "sp_a",
      action: "x",
      verdict: "approve"
    });
    await appendAudit({
      subprocessHandle: "sp_b",
      action: "x",
      verdict: "approve"
    });
    const entries = await readAudit({ subprocessHandle: "sp_b" });
    expect(entries).toHaveLength(1);
    expect(entries[0]?.subprocessHandle).toBe("sp_b");
  });

  it("filter by since-timestamp", async () => {
    const before = new Date().toISOString();
    await appendAudit({
      subprocessHandle: "sp_old",
      action: "x",
      verdict: "approve",
      ts: "2020-01-01T00:00:00.000Z"
    });
    await appendAudit({ subprocessHandle: "sp_new", action: "x", verdict: "approve" });
    const entries = await readAudit({ since: before });
    expect(entries.find((e) => e.subprocessHandle === "sp_old")).toBeUndefined();
    expect(entries.find((e) => e.subprocessHandle === "sp_new")).toBeDefined();
  });

  it("limit caps the result count", async () => {
    for (let i = 0; i < 5; i++) {
      await appendAudit({
        subprocessHandle: `sp_${i}`,
        action: "x",
        verdict: "approve"
      });
    }
    const entries = await readAudit({ limit: 3 });
    expect(entries).toHaveLength(3);
    // last 3 (slice(-3))
    expect(entries.map((e) => e.subprocessHandle)).toEqual([
      "sp_2",
      "sp_3",
      "sp_4"
    ]);
  });

  it("auditLogPath is under MCP_RCE_GUARD_HOME", () => {
    const home = process.env["MCP_RCE_GUARD_HOME"];
    expect(home).toBeTruthy();
    expect(auditLogPath().startsWith(home ?? "")).toBe(true);
  });

  it("Pre-Publish-Audit F3: literal tab in meta survives round-trip", async () => {
    // Old implementation split on the last \t (HMAC suffix carve-out) and
    // silently dropped any entry whose body contained a tab. Regression
    // assertion: a tab inside meta.binary makes it through readAudit intact.
    await appendAudit({
      subprocessHandle: "sp_tab_1",
      action: "register_subprocess",
      verdict: "approve",
      meta: { binary: "/usr/bin/tool\twith-tab", args: ["a\tb", "c"] }
    });
    const entries = await readAudit({});
    expect(entries).toHaveLength(1);
    expect(entries[0]?.meta).toBeDefined();
    const meta = entries[0]?.meta as { binary: string; args: string[] };
    expect(meta.binary).toBe("/usr/bin/tool\twith-tab");
    expect(meta.args).toEqual(["a\tb", "c"]);
  });

  it("Pre-Publish-Audit F3: multiple tab-bearing entries all parse", async () => {
    for (let i = 0; i < 3; i++) {
      await appendAudit({
        subprocessHandle: `sp_tabs_${i}`,
        action: "x",
        verdict: "approve",
        reason: `tab-\t-${i}-\t-end`
      });
    }
    const entries = await readAudit({});
    expect(entries).toHaveLength(3);
    for (let i = 0; i < 3; i++) {
      expect(entries[i]?.reason).toBe(`tab-\t-${i}-\t-end`);
    }
  });

  it("Pre-Publish-Audit F3: embedded JSON-ish strings do not break parse", async () => {
    // JSON.stringify escapes inner quotes; the read path must survive
    // a reason that looks like JSON itself.
    await appendAudit({
      subprocessHandle: "sp_json",
      action: "x",
      verdict: "approve",
      reason: '{"nested":"value","ts":"2020-01-01T00:00:00Z"}'
    });
    const entries = await readAudit({});
    expect(entries).toHaveLength(1);
    expect(entries[0]?.reason).toBe(
      '{"nested":"value","ts":"2020-01-01T00:00:00Z"}'
    );
  });
});

describe("audit log rotation (Reviewer S1024 F6)", () => {
  const originalMaxBytes = process.env["MCP_RCE_GUARD_AUDIT_MAX_BYTES"];

  beforeEach(async () => {
    await clearAuditLog();
  });

  afterEach(() => {
    if (originalMaxBytes === undefined) {
      delete process.env["MCP_RCE_GUARD_AUDIT_MAX_BYTES"];
    } else {
      process.env["MCP_RCE_GUARD_AUDIT_MAX_BYTES"] = originalMaxBytes;
    }
  });

  it("rotateAuditLog returns no-op when no active log exists", async () => {
    const r = await rotateAuditLog();
    expect(r.rotated).toBe(false);
  });

  it("explicit rotate moves active → .1", async () => {
    await appendAudit({
      subprocessHandle: "sp_rotate",
      action: "register_subprocess",
      verdict: "approve"
    });
    expect(existsSync(auditLogPath())).toBe(true);
    const r = await rotateAuditLog();
    expect(r.rotated).toBe(true);
    expect(existsSync(auditLogPath())).toBe(false);
    expect(existsSync(`${auditLogPath()}.1`)).toBe(true);
  });

  it("rotation shifts existing .1 → .2", async () => {
    await appendAudit({ subprocessHandle: "first", action: "x", verdict: "approve" });
    await rotateAuditLog();
    await appendAudit({ subprocessHandle: "second", action: "x", verdict: "approve" });
    await rotateAuditLog();
    expect(existsSync(`${auditLogPath()}.1`)).toBe(true);
    expect(existsSync(`${auditLogPath()}.2`)).toBe(true);
  });

  it("appendAudit auto-rotates when size threshold exceeded", async () => {
    // Force a tiny threshold so a single entry triggers rotation on the
    // second append.
    process.env["MCP_RCE_GUARD_AUDIT_MAX_BYTES"] = "50";
    await appendAudit({
      subprocessHandle: "sp_big_1",
      action: "register_subprocess",
      verdict: "approve",
      reason: "padding-padding-padding-padding-padding-padding"
    });
    await appendAudit({
      subprocessHandle: "sp_big_2",
      action: "register_subprocess",
      verdict: "approve"
    });
    // After the second append the active log is the second entry, and .1
    // holds the first.
    expect(existsSync(`${auditLogPath()}.1`)).toBe(true);
    const entries = await readAudit({});
    expect(entries).toHaveLength(1);
    expect(entries[0]?.subprocessHandle).toBe("sp_big_2");
  });
});
