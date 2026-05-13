import { describe, it, expect } from "vitest";
import { evaluateEgress } from "../../src/egress/policy.js";

describe("evaluateEgress", () => {
  it("denies on empty allowlist", () => {
    const d = evaluateEgress("api.example.com", 443, []);
    expect(d.allowed).toBe(false);
  });

  it("allows on wildcard", () => {
    const d = evaluateEgress("anything.tld", 80, ["*"]);
    expect(d.allowed).toBe(true);
  });

  it("allows exact host:port match", () => {
    const d = evaluateEgress("api.example.com", 443, ["api.example.com:443"]);
    expect(d.allowed).toBe(true);
  });

  it("denies different port", () => {
    const d = evaluateEgress("api.example.com", 80, ["api.example.com:443"]);
    expect(d.allowed).toBe(false);
  });

  it("allows host:* port wildcard", () => {
    const d = evaluateEgress("api.example.com", 8080, ["api.example.com:*"]);
    expect(d.allowed).toBe(true);
  });

  it("allows .domain suffix subdomain match", () => {
    const d = evaluateEgress("foo.example.com", 443, [".example.com:443"]);
    expect(d.allowed).toBe(true);
  });

  it("allows .domain suffix exact base match", () => {
    const d = evaluateEgress("example.com", 443, [".example.com:443"]);
    expect(d.allowed).toBe(true);
  });

  it("denies sibling domain on suffix", () => {
    const d = evaluateEgress("example.org", 443, [".example.com:443"]);
    expect(d.allowed).toBe(false);
  });

  it("denies invalid port", () => {
    const d = evaluateEgress("x", 99999, ["*"]);
    expect(d.allowed).toBe(false);
  });
});
