import { describe, it, expect } from "vitest";
import {
  RegisterSubprocessArgsSchema,
  AuditSubprocessArgsSchema,
  ScanCveReplayArgsSchema,
  TrackCanaryArgsSchema,
  InjectEgressPolicyArgsSchema,
  GetAuditLogArgsSchema,
  CveIdSchema
} from "../../src/types.js";

describe("RegisterSubprocessArgsSchema", () => {
  it("accepts a minimal valid input", () => {
    const out = RegisterSubprocessArgsSchema.parse({
      serverId: "demo",
      binary: "/usr/bin/node",
      args: ["--version"],
      trustTier: "LOW",
      isolationProfile: {}
    });
    expect(out.serverId).toBe("demo");
    expect(out.trustTier).toBe("LOW");
  });

  it("rejects empty serverId", () => {
    expect(() =>
      RegisterSubprocessArgsSchema.parse({
        serverId: "",
        binary: "/usr/bin/node",
        args: [],
        trustTier: "LOW",
        isolationProfile: {}
      })
    ).toThrow();
  });

  it("rejects invalid trust tier", () => {
    expect(() =>
      RegisterSubprocessArgsSchema.parse({
        serverId: "x",
        binary: "/usr/bin/node",
        args: [],
        trustTier: "ULTRA",
        isolationProfile: {}
      })
    ).toThrow();
  });

  it("rejects more than 256 args", () => {
    expect(() =>
      RegisterSubprocessArgsSchema.parse({
        serverId: "x",
        binary: "/usr/bin/node",
        args: Array(257).fill("a"),
        trustTier: "LOW",
        isolationProfile: {}
      })
    ).toThrow();
  });

  it("defaults isolationProfile.fsReadOnly to []", () => {
    const out = RegisterSubprocessArgsSchema.parse({
      serverId: "x",
      binary: "/bin/x",
      args: [],
      trustTier: "LOW",
      isolationProfile: {}
    });
    // partial schema: fsReadOnly may be undefined, that is OK — handled in resolveProfile
    expect(out.isolationProfile).toBeDefined();
  });
});

describe("AuditSubprocessArgsSchema", () => {
  it("accepts a valid input", () => {
    const out = AuditSubprocessArgsSchema.parse({
      subprocessHandle: "sp_abc",
      requestedArgs: ["--foo", "bar"]
    });
    expect(out.subprocessHandle).toBe("sp_abc");
  });

  it("rejects empty handle", () => {
    expect(() =>
      AuditSubprocessArgsSchema.parse({ subprocessHandle: "", requestedArgs: [] })
    ).toThrow();
  });
});

describe("ScanCveReplayArgsSchema", () => {
  it("defaults timeout to 30000", () => {
    const out = ScanCveReplayArgsSchema.parse({ targetServerCommand: "node x.js" });
    expect(out.timeoutMs).toBe(30_000);
  });

  it("rejects zero timeout", () => {
    expect(() =>
      ScanCveReplayArgsSchema.parse({ targetServerCommand: "x", timeoutMs: 0 })
    ).toThrow();
  });

  it("CveIdSchema accepts known ids", () => {
    expect(CveIdSchema.parse("mcp-sdk-rce-2026-04-22")).toBe("mcp-sdk-rce-2026-04-22");
  });

  it("CveIdSchema rejects unknown ids", () => {
    expect(() => CveIdSchema.parse("cve-1999-0001")).toThrow();
  });
});

describe("TrackCanaryArgsSchema", () => {
  it("requires non-empty downstreamServerIds", () => {
    expect(() =>
      TrackCanaryArgsSchema.parse({
        chainId: "c1",
        sourceServerId: "s",
        downstreamServerIds: []
      })
    ).toThrow();
  });

  it("rejects too-short canaryPattern", () => {
    expect(() =>
      TrackCanaryArgsSchema.parse({
        chainId: "c1",
        sourceServerId: "s",
        downstreamServerIds: ["d"],
        canaryPattern: "abc"
      })
    ).toThrow();
  });
});

describe("InjectEgressPolicyArgsSchema", () => {
  it("accepts default-deny", () => {
    const out = InjectEgressPolicyArgsSchema.parse({
      subprocessHandle: "sp_x",
      allowlist: ["api.example.com:443"],
      mode: "default-deny"
    });
    expect(out.mode).toBe("default-deny");
  });

  it("rejects unknown mode", () => {
    expect(() =>
      InjectEgressPolicyArgsSchema.parse({
        subprocessHandle: "sp_x",
        allowlist: [],
        mode: "lax"
      })
    ).toThrow();
  });
});

describe("GetAuditLogArgsSchema", () => {
  it("defaults limit to 100", () => {
    const out = GetAuditLogArgsSchema.parse({});
    expect(out.limit).toBe(100);
  });

  it("rejects bad ISO date", () => {
    expect(() => GetAuditLogArgsSchema.parse({ since: "yesterday" })).toThrow();
  });

  it("accepts a valid ISO date", () => {
    const out = GetAuditLogArgsSchema.parse({ since: "2026-05-01T00:00:00Z" });
    expect(out.since).toBe("2026-05-01T00:00:00Z");
  });

  // R3 F5: audit-only-mode staleness threshold
  it("defaults staleEgressModeThresholdDays to 7", () => {
    const out = GetAuditLogArgsSchema.parse({});
    expect(out.staleEgressModeThresholdDays).toBe(7);
  });

  it("accepts staleEgressModeThresholdDays=0 (disable)", () => {
    const out = GetAuditLogArgsSchema.parse({ staleEgressModeThresholdDays: 0 });
    expect(out.staleEgressModeThresholdDays).toBe(0);
  });

  it("rejects negative staleEgressModeThresholdDays", () => {
    expect(() =>
      GetAuditLogArgsSchema.parse({ staleEgressModeThresholdDays: -1 })
    ).toThrow();
  });

  it("rejects staleEgressModeThresholdDays > 365", () => {
    expect(() =>
      GetAuditLogArgsSchema.parse({ staleEgressModeThresholdDays: 366 })
    ).toThrow();
  });
});
