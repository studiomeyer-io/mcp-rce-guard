import { describe, it, expect } from "vitest";
import {
  normalizeArg,
  normalizeArgs,
  hasInvisibleCodepoints
} from "../../src/normalize.js";

describe("normalizeArg", () => {
  it("returns identity for ASCII", () => {
    expect(normalizeArg("hello world")).toBe("hello world");
  });

  it("collapses fullwidth to halfwidth via NFKC", () => {
    // U+FF21 = fullwidth A → 'A'
    const fullwidth = "\uFF21\uFF22\uFF23";
    expect(normalizeArg(fullwidth)).toBe("ABC");
  });

  it("strips zero-width joiner", () => {
    // U+200D ZWJ between letters
    expect(normalizeArg("h\u200De\u200Dllo")).toBe("hello");
  });

  it("strips bidi control codepoints", () => {
    // U+202E RIGHT-TO-LEFT OVERRIDE
    expect(normalizeArg("safe\u202Edangerous")).toBe("safedangerous");
  });

  it("rejects non-string input", () => {
    expect(() => normalizeArg(42 as unknown as string)).toThrow(TypeError);
  });

  it("normalizeArgs returns new array (no mutation)", () => {
    const input = ["a", "\uFF21"];
    const out = normalizeArgs(input);
    expect(out).toEqual(["a", "A"]);
    expect(input).toEqual(["a", "\uFF21"]);
  });
});

describe("hasInvisibleCodepoints", () => {
  it("flags zero-width joiner", () => {
    expect(hasInvisibleCodepoints("a\u200Db")).toBe(true);
  });

  it("flags bidi control", () => {
    expect(hasInvisibleCodepoints("a\u202Eb")).toBe(true);
  });

  it("does not flag normal text", () => {
    expect(hasInvisibleCodepoints("hello world")).toBe(false);
  });

  // Reviewer S1024 F3 regression: previously /g-flagged RegExps were used for
  // both .replace() and .test(). The .test() path consults+mutates lastIndex,
  // so two back-to-back calls on identical ZWC input flipped between true
  // and false. Both calls must now return true.
  it("returns stable true across repeated calls on ZWC input (F3 regression)", () => {
    const sample = "h\u200De\u200Dllo";
    expect(hasInvisibleCodepoints(sample)).toBe(true);
    expect(hasInvisibleCodepoints(sample)).toBe(true);
    expect(hasInvisibleCodepoints(sample)).toBe(true);
    expect(hasInvisibleCodepoints(sample)).toBe(true);
  });

  it("returns stable true across repeated calls on bidi input (F3 regression)", () => {
    const sample = "safe\u202Edanger";
    expect(hasInvisibleCodepoints(sample)).toBe(true);
    expect(hasInvisibleCodepoints(sample)).toBe(true);
    expect(hasInvisibleCodepoints(sample)).toBe(true);
    expect(hasInvisibleCodepoints(sample)).toBe(true);
  });

  it("returns stable false across repeated calls on clean input (F3 regression)", () => {
    const sample = "plain ascii text";
    expect(hasInvisibleCodepoints(sample)).toBe(false);
    expect(hasInvisibleCodepoints(sample)).toBe(false);
    expect(hasInvisibleCodepoints(sample)).toBe(false);
  });
});
