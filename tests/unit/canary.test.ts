import { describe, it, expect } from "vitest";
import { makeCanary, detectLeaks } from "../../src/canary/tracker.js";

describe("makeCanary", () => {
  it("returns a token with the expected prefix + suffix", () => {
    const { token, pattern } = makeCanary();
    expect(token).toMatch(/^__MCP_CANARY_[a-f0-9]{64}__$/);
    expect(pattern).toBe(token);
  });

  it("uses caller-provided pattern when given", () => {
    const { token, pattern } = makeCanary("__test_pattern_xxxxxxxxxxxxxxxx__");
    expect(token).toMatch(/^__MCP_CANARY_/);
    expect(pattern).toBe("__test_pattern_xxxxxxxxxxxxxxxx__");
  });
});

describe("detectLeaks", () => {
  it("finds the pattern in stdout entries", () => {
    const corpus = [
      { serverId: "down1", channel: "stdout" as const, content: "ok ABC123 done" }
    ];
    const leaks = detectLeaks(corpus, "ABC123");
    expect(leaks).toEqual([{ serverId: "down1", channel: "stdout" }]);
  });

  it("returns empty when pattern not found", () => {
    const corpus = [{ serverId: "x", channel: "stdout" as const, content: "no leak" }];
    const leaks = detectLeaks(corpus, "ABC123");
    expect(leaks).toEqual([]);
  });

  it("flags multiple channels", () => {
    const pattern = "p_unique_1234";
    const corpus = [
      { serverId: "down1", channel: "stdout" as const, content: pattern },
      { serverId: "down2", channel: "network-egress" as const, content: pattern },
      { serverId: "down3", channel: "fs-write" as const, content: "no" }
    ];
    const leaks = detectLeaks(corpus, pattern);
    expect(leaks).toHaveLength(2);
    expect(leaks.map((l) => l.channel)).toEqual(["stdout", "network-egress"]);
  });
});
