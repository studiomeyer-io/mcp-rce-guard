/**
 * Tool: track_canary
 *
 * Issues a canary token + registers a chain. v0.1 returns the token + a
 * pre-evaluated leakDetected=false because actual leak detection requires
 * the calling MCP-aware controller to feed downstream-server output back
 * via a corpus parameter (added in v0.2).
 *
 * Pattern provenance: arXiv 2604.27819 (MCPHunt, April 2026) — taint
 * tracking via canary-token injection across MCP server boundaries.
 *
 * Confused-Deputy defense (CVE-2026-27124): if the chain controller pipes
 * downstream output back to detect_leaks, a leak via egress channel will
 * be flagged.
 */

import {
  TrackCanaryArgsSchema,
  type TrackCanaryArgs
} from "../types.js";
import { registerCanaryChain } from "../state.js";
import { makeCanary, type LeakLocation } from "../canary/tracker.js";
import { appendAudit } from "../audit/log.js";

export interface TrackCanaryResult {
  canaryToken: string;
  leakDetected: boolean;
  leakLocations: LeakLocation[];
}

export async function trackCanaryTool(rawArgs: unknown): Promise<TrackCanaryResult> {
  const args: TrackCanaryArgs = TrackCanaryArgsSchema.parse(rawArgs);

  const { token, pattern } = makeCanary(args.canaryPattern);
  registerCanaryChain(
    args.chainId,
    args.sourceServerId,
    args.downstreamServerIds,
    pattern,
    token
  );

  // v0.1: leak detection requires a separate corpus feed; here we always
  // return false at registration time. The library export `detectLeaks`
  // is the entry-point for callers that want to scan their own corpus.
  await appendAudit({
    subprocessHandle: "n/a",
    action: "track_canary",
    verdict: "approve",
    serverId: args.sourceServerId,
    meta: {
      chainId: args.chainId,
      downstreamServerIds: args.downstreamServerIds,
      tokenPrefix: token.slice(0, 24)
    }
  });

  return {
    canaryToken: token,
    leakDetected: false,
    leakLocations: []
  };
}
