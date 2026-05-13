import { describe, it, expect } from "vitest";
import {
  TRUST_TIER_DEFAULTS,
  resolveProfile
} from "../../src/trust-tiers.js";

describe("TRUST_TIER_DEFAULTS", () => {
  it("LOW has empty egress", () => {
    expect(TRUST_TIER_DEFAULTS.LOW.egressAllowlist).toEqual([]);
  });

  it("CRITICAL has wildcard egress", () => {
    expect(TRUST_TIER_DEFAULTS.CRITICAL.egressAllowlist).toEqual(["*"]);
  });

  it("LOW has tighter cap than CRITICAL", () => {
    expect(TRUST_TIER_DEFAULTS.LOW.memMB).toBeLessThan(
      TRUST_TIER_DEFAULTS.CRITICAL.memMB ?? Infinity
    );
    expect(TRUST_TIER_DEFAULTS.LOW.cpuMs).toBeLessThan(
      TRUST_TIER_DEFAULTS.CRITICAL.cpuMs ?? Infinity
    );
  });

  it("each tier has read-only roots filled or empty (CRITICAL)", () => {
    expect(TRUST_TIER_DEFAULTS.LOW.fsReadOnly.length).toBeGreaterThan(0);
    expect(TRUST_TIER_DEFAULTS.MEDIUM.fsReadOnly.length).toBeGreaterThan(0);
    expect(TRUST_TIER_DEFAULTS.HIGH.fsReadOnly.length).toBeGreaterThan(0);
    expect(TRUST_TIER_DEFAULTS.CRITICAL.fsReadOnly).toEqual([]);
  });
});

describe("resolveProfile", () => {
  it("returns tier defaults when override is empty", () => {
    const out = resolveProfile("LOW", {});
    expect(out.egressAllowlist).toEqual([]);
    expect(out.memMB).toBe(128);
  });

  it("override fields win", () => {
    const out = resolveProfile("LOW", { memMB: 256, egressAllowlist: ["x:443"] });
    expect(out.memMB).toBe(256);
    expect(out.egressAllowlist).toEqual(["x:443"]);
    // unchanged from default:
    expect(out.cpuMs).toBe(5000);
  });
});
