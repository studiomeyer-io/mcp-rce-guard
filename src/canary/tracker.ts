/**
 * Canary token tracking for cross-server credential leak detection.
 *
 * Pattern provenance: arXiv 2604.27819 (MCPHunt, April 2026) — taint tracking
 * via canary-token injection across MCP server boundaries. If a token leaves
 * the chain via stdout/network/fs, the controller flags the leak channel.
 *
 * v0.1 ist scanner-only: detect_leaks scant a corpus of textual outputs for
 * the canary token. The actual injection happens at the calling MCP server's
 * tool boundary via track_canary which returns the token + downstream IDs.
 */

import { generateCanaryToken } from "../state.js";

export type LeakChannel = "stdout" | "network-egress" | "fs-write";

export interface LeakLocation {
  serverId: string;
  channel: LeakChannel;
}

export interface CorpusEntry {
  serverId: string;
  channel: LeakChannel;
  content: string;
}

/**
 * Build a canary token + pattern. Caller may supply a fixed pattern (for
 * tests) or accept the high-entropy default.
 */
export function makeCanary(pattern?: string): { token: string; pattern: string } {
  const token = generateCanaryToken();
  return {
    token,
    pattern: pattern ?? token
  };
}

/**
 * Scan a corpus for canary leaks. Returns one LeakLocation per matching entry.
 *
 * False-positive note: a tool that legitimately echoes a canary in its own
 * structured output would be flagged. Mitigation: callers should redact the
 * token from logs they emit, or pass a unique pattern per chain.
 */
export function detectLeaks(
  corpus: readonly CorpusEntry[],
  pattern: string
): LeakLocation[] {
  const out: LeakLocation[] = [];
  for (const entry of corpus) {
    if (entry.content.includes(pattern)) {
      out.push({ serverId: entry.serverId, channel: entry.channel });
    }
  }
  return out;
}
