/**
 * Argument normalization for subprocess audit.
 *
 * Provenance: shared with Pillar 8 (mcp-stdio-shellguard) — same NFKC + Zero-Width-Char-Strip
 * + Bidi-Block pipeline. Wiederverwendung garantiert dass Layer-2 Allowlist und Layer-3
 * Sandbox-Audit auf identischer canonical form arbeiten.
 *
 * Anti-Pattern provenance: Fullwidth-Unicode-Bypass (mcp-server-attestation R3, S912),
 * Zero-Width-Joiner-Smuggling (ai-shield Round-2 Finding F2).
 */

/**
 * Two distinct regex objects per pattern to avoid the V8 well-known footgun
 * where a `/g`-flagged RegExp carries mutable `lastIndex`. The `_STRIP` form
 * (with `/g`) is used by `.replace()` to remove all occurrences. The `_TEST`
 * form (without `/g`) is used by `.test()` for stateless boolean checks.
 *
 * Bug context: a single `/g` regex used for both `.replace()` (mutates state)
 * AND `.test()` (consults state) makes the test result flip on alternating
 * calls. Reviewer S1024 F3 documented this; regression test in
 * `tests/unit/normalize.test.ts` covers it.
 */
const ZERO_WIDTH_STRIP = /[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF]/g;
const ZERO_WIDTH_TEST = /[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF]/;

/**
 * Bidi control codepoints: U+2066..U+2069 (LRI/RLI/FSI/PDI), U+202A..U+202E (LRE/RLE/PDF/LRO/RLO).
 * These are weaponized in trojan-source attacks (CVE-2021-42574).
 */
const BIDI_CONTROL_STRIP = /[\u202A-\u202E\u2066-\u2069]/g;
const BIDI_CONTROL_TEST = /[\u202A-\u202E\u2066-\u2069]/;

/**
 * Normalize a single argument string for safe comparison against an allowlist.
 *
 * Applies in order:
 *   1. NFKC unicode normalization (collapses fullwidth/halfwidth + compat chars).
 *   2. Strip zero-width / format-control codepoints.
 *   3. Strip bidi-control codepoints.
 *
 * Returns the canonical form. Comparison MUST always go through this function.
 */
export function normalizeArg(input: string): string {
  if (typeof input !== "string") {
    throw new TypeError(`normalizeArg expects string, got ${typeof input}`);
  }
  let s = input.normalize("NFKC");
  s = s.replace(ZERO_WIDTH_STRIP, "");
  s = s.replace(BIDI_CONTROL_STRIP, "");
  return s;
}

/**
 * Normalize an entire args array. Returns a new array (never mutates input).
 */
export function normalizeArgs(args: readonly string[]): string[] {
  return args.map(normalizeArg);
}

/**
 * Quick smell-test: does an input contain any zero-width or bidi codepoint?
 * Used by the audit-log to mark suspicious args even when normalization
 * makes them comparable.
 */
export function hasInvisibleCodepoints(input: string): boolean {
  // IMPORTANT: use the non-/g regex variants. `.test()` on a /g-flagged
  // RegExp consults+mutates `lastIndex`, which makes the result flip on
  // alternating calls with the same input (Reviewer S1024 F3).
  return ZERO_WIDTH_TEST.test(input) || BIDI_CONTROL_TEST.test(input);
}
