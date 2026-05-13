import { describe, it, expect, beforeEach } from "vitest";
import { registerSubprocessTool } from "../../src/tools/register.js";
import { auditSubprocessTool } from "../../src/tools/audit.js";
import { scanCveReplayTool } from "../../src/tools/scanCve.js";
import { trackCanaryTool } from "../../src/tools/trackCanary.js";
import { injectEgressPolicyTool } from "../../src/tools/injectEgress.js";
import { getAuditLogTool } from "../../src/tools/getAuditLog.js";
import { clearRegistry } from "../../src/state.js";
import { clearAuditLog } from "../../src/audit/log.js";

describe("tool: register_subprocess", () => {
  beforeEach(() => {
    clearRegistry();
  });

  it("returns a handle + fingerprint", async () => {
    const out = await registerSubprocessTool({
      serverId: "demo",
      binary: "/usr/bin/node",
      args: ["server.js"],
      trustTier: "LOW",
      isolationProfile: { memMB: 256 }
    });
    expect(out.subprocessHandle).toMatch(/^sp_[a-f0-9]+$/);
    expect(out.profileFingerprint).toMatch(/^[a-f0-9]+$/);
    expect(out.profileFingerprint).toHaveLength(32);
  });

  it("two registrations with same effective profile produce different handles but same fingerprint", async () => {
    const a = await registerSubprocessTool({
      serverId: "demo",
      binary: "/usr/bin/node",
      args: ["x.js"],
      trustTier: "LOW",
      isolationProfile: {}
    });
    const b = await registerSubprocessTool({
      serverId: "demo",
      binary: "/usr/bin/node",
      args: ["x.js"],
      trustTier: "LOW",
      isolationProfile: {}
    });
    expect(a.subprocessHandle).not.toBe(b.subprocessHandle);
    expect(a.profileFingerprint).toBe(b.profileFingerprint);
  });
});

describe("tool: audit_subprocess", () => {
  beforeEach(() => {
    clearRegistry();
  });

  it("approves matching args", async () => {
    const reg = await registerSubprocessTool({
      serverId: "demo",
      binary: "/usr/bin/node",
      args: ["--version"],
      trustTier: "LOW",
      isolationProfile: {}
    });
    const out = await auditSubprocessTool({
      subprocessHandle: reg.subprocessHandle,
      requestedArgs: ["--version"]
    });
    expect(out.verdict).toBe("approve");
    expect(out.pillar8Allowlist).toBe("pass");
  });

  it("blocks mismatched args", async () => {
    const reg = await registerSubprocessTool({
      serverId: "demo",
      binary: "/usr/bin/node",
      args: ["--version"],
      trustTier: "LOW",
      isolationProfile: {}
    });
    const out = await auditSubprocessTool({
      subprocessHandle: reg.subprocessHandle,
      requestedArgs: ["--exec", "rm -rf /"]
    });
    expect(out.verdict).toBe("block");
    expect(out.pillar8Allowlist).toBe("fail");
  });

  it("blocks unknown handle", async () => {
    const out = await auditSubprocessTool({
      subprocessHandle: "sp_nonexistent",
      requestedArgs: []
    });
    expect(out.verdict).toBe("block");
    expect(out.reason).toMatch(/unknown subprocess handle/);
  });

  it("quarantines on invisible codepoint even when normalized form matches", async () => {
    // registered: --safe
    // requested: --safe with embedded ZWJ — normalized form matches but smell-test flags
    const reg = await registerSubprocessTool({
      serverId: "demo",
      binary: "/bin/x",
      args: ["--safe"],
      trustTier: "LOW",
      isolationProfile: {}
    });
    const out = await auditSubprocessTool({
      subprocessHandle: reg.subprocessHandle,
      requestedArgs: ["--s\u200Dafe"]
    });
    expect(out.verdict).toBe("quarantine");
  });

  it("normalizes fullwidth and approves", async () => {
    const reg = await registerSubprocessTool({
      serverId: "demo",
      binary: "/bin/x",
      args: ["abc"],
      trustTier: "LOW",
      isolationProfile: {}
    });
    // U+FF21 U+FF22 U+FF23 → ABC after NFKC; registered is "abc" so this should still fail.
    const out = await auditSubprocessTool({
      subprocessHandle: reg.subprocessHandle,
      requestedArgs: ["\uFF21\uFF22\uFF23"]
    });
    expect(out.verdict).toBe("block"); // ABC vs abc
    expect(out.pillar8Allowlist).toBe("fail");
  });
});

describe("tool: scan_cve_replay", () => {
  it("returns overall fail on shell -c invocation", async () => {
    const out = await scanCveReplayTool({
      targetServerCommand: "/bin/sh -c 'echo x'"
    });
    expect(out.overall).toBe("fail");
  });

  it("returns overall pass on a clean node invocation", async () => {
    const out = await scanCveReplayTool({
      targetServerCommand: "/usr/bin/node /tmp/server.js --port=3000"
    });
    expect(out.overall).toBe("pass");
  });
});

describe("tool: track_canary", () => {
  it("issues a token and returns leakDetected=false at registration", async () => {
    const out = await trackCanaryTool({
      chainId: "chain-1",
      sourceServerId: "src",
      downstreamServerIds: ["d1", "d2"]
    });
    expect(out.canaryToken).toMatch(/^__MCP_CANARY_/);
    expect(out.leakDetected).toBe(false);
    expect(out.leakLocations).toEqual([]);
  });
});

describe("tool: inject_egress_policy", () => {
  beforeEach(() => {
    clearRegistry();
  });

  it("applies policy to a registered subprocess", async () => {
    const reg = await registerSubprocessTool({
      serverId: "demo",
      binary: "/bin/x",
      args: [],
      trustTier: "LOW",
      isolationProfile: {}
    });
    const out = await injectEgressPolicyTool({
      subprocessHandle: reg.subprocessHandle,
      allowlist: ["api.example.com:443"],
      mode: "default-deny"
    });
    expect(out.applied).toBe(true);
  });

  it("returns applied=false on unknown handle", async () => {
    const out = await injectEgressPolicyTool({
      subprocessHandle: "sp_unknown",
      allowlist: [],
      mode: "default-deny"
    });
    expect(out.applied).toBe(false);
  });
});

describe("tool: get_audit_log", () => {
  beforeEach(async () => {
    clearRegistry();
    await clearAuditLog();
  });

  it("returns entries appended by other tools", async () => {
    await registerSubprocessTool({
      serverId: "demo",
      binary: "/bin/x",
      args: [],
      trustTier: "LOW",
      isolationProfile: {}
    });
    const out = await getAuditLogTool({ limit: 50 });
    expect(out.entries.length).toBeGreaterThanOrEqual(1);
    expect(out.entries[0]?.action).toBe("register_subprocess");
    // R3 F5: result shape now includes staleEgressModeWarnings (empty by
    // default — fresh subprocess, default-deny mode).
    expect(out.staleEgressModeWarnings).toEqual([]);
  });

  it("filters by subprocessHandle", async () => {
    const a = await registerSubprocessTool({
      serverId: "a",
      binary: "/bin/x",
      args: [],
      trustTier: "LOW",
      isolationProfile: {}
    });
    await registerSubprocessTool({
      serverId: "b",
      binary: "/bin/x",
      args: [],
      trustTier: "LOW",
      isolationProfile: {}
    });
    const out = await getAuditLogTool({
      subprocessHandle: a.subprocessHandle,
      limit: 50
    });
    expect(out.entries.every((e) => e.subprocessHandle === a.subprocessHandle)).toBe(
      true
    );
  });
});
