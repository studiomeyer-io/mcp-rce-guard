/**
 * mcp-rce-guard MCP stdio server (entry-point).
 *
 * Spec: MCP 2025-06-18.
 * Transport: stdio (consistent with Pillar 1 + Pillar 8).
 * Tools: 6 (register_subprocess, audit_subprocess, scan_cve_replay,
 *           track_canary, inject_egress_policy, get_audit_log).
 *
 * The server is a thin wrapper around the programmatic tool handlers in
 * src/tools/*.ts — same handlers the library exports.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import {
  RegisterSubprocessArgsSchema,
  AuditSubprocessArgsSchema,
  ScanCveReplayArgsSchema,
  TrackCanaryArgsSchema,
  InjectEgressPolicyArgsSchema,
  GetAuditLogArgsSchema
} from "./types.js";
import { registerSubprocessTool } from "./tools/register.js";
import { auditSubprocessTool } from "./tools/audit.js";
import { scanCveReplayTool } from "./tools/scanCve.js";
import { trackCanaryTool } from "./tools/trackCanary.js";
import { injectEgressPolicyTool } from "./tools/injectEgress.js";
import { getAuditLogTool } from "./tools/getAuditLog.js";
import { NAME, VERSION } from "./version.js";

interface ToolResult {
  [x: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

function ok(result: unknown): ToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
  };
}

function err(message: string): ToolResult {
  return {
    content: [{ type: "text", text: message }],
    isError: true
  };
}

async function safe<T>(fn: () => Promise<T>): Promise<ToolResult> {
  try {
    return ok(await fn());
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return err(`mcp-rce-guard error: ${msg}`);
  }
}

export function createServer(): McpServer {
  const server = new McpServer(
    { name: NAME, version: VERSION },
    {
      capabilities: {
        tools: {}
      },
      instructions:
        "v0.1 policy-synthesis library for MCP subprocess isolation. Emits landlock / sandbox-exec / cgroups-v2 policy descriptors + runs behavioral CVE-replay predicates + tracks cross-server canary leaks + appends NDJSON audit log. Does NOT call landlock/sandbox-exec/cgroups syscalls in v0.1 — the host spawner translates descriptors into platform syscalls. Native enforcement is v0.2. Use register_subprocess + audit_subprocess to synthesize + validate spawn-specs, scan_cve_replay before connecting to unknown servers, track_canary in multi-server chains, inject_egress_policy for descriptor-only egress policy, get_audit_log for forensic review."
    }
  );

  server.registerTool(
    "register_subprocess",
    {
      title: "Synthesize isolation policy descriptors",
      description:
        "Register a subprocess spec (binary + args) under a trust tier with an isolation profile. Returns a stable handle + profile fingerprint + policyDescriptor (landlockRuleset, sandboxExecProfile, cgroupsV2Limits). v0.1 emits descriptors only — the host spawner is responsible for translating them into platform syscalls. Native enforcement is v0.2.",
      inputSchema: RegisterSubprocessArgsSchema.shape,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    async (args) => safe(() => registerSubprocessTool(args))
  );

  server.registerTool(
    "audit_subprocess",
    {
      title: "Audit a candidate args set",
      description:
        "Verify candidate args against the registered subprocess. Runs Pillar-8 (NFKC + ZWC + Bidi) normalize + allowlist check. Returns approve / block / quarantine.",
      inputSchema: AuditSubprocessArgsSchema.shape,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (args) => safe(() => auditSubprocessTool(args))
  );

  server.registerTool(
    "scan_cve_replay",
    {
      title: "Run CVE replay fixtures",
      description:
        "Replay 2026 MCP CVE fixtures (mcp-sdk-rce-2026-04-22, cve-2026-27124, nginx-mcp-rce-9.8, mcp-interpreter-eval-rce) against a candidate command. Returns overall + per-CVE pass/fail.",
      inputSchema: ScanCveReplayArgsSchema.shape,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (args) => safe(() => scanCveReplayTool(args))
  );

  server.registerTool(
    "track_canary",
    {
      title: "Issue canary token + register chain",
      description:
        "Register a multi-server canary chain. Returns a high-entropy token to inject into the source server's outbound flow. Cross-boundary leaks are detectable via the library detectLeaks() helper. State change is limited to the in-memory chain registry; no subprocess is mutated.",
      inputSchema: TrackCanaryArgsSchema.shape,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false
      }
    },
    async (args) => safe(() => trackCanaryTool(args))
  );

  server.registerTool(
    "inject_egress_policy",
    {
      title: "Emit egress policy descriptor",
      description:
        "Update the egress allowlist + mode (default-deny / audit-only) on a registered subprocess. v0.1 emits a descriptor only — no subprocess state, nftables, or packet-filter is modified by this call. The host spawner translates the descriptor into platform-specific enforcement. v0.2 will flip destructiveHint=true once native enforcement is wired.",
      inputSchema: InjectEgressPolicyArgsSchema.shape,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (args) => safe(() => injectEgressPolicyTool(args))
  );

  server.registerTool(
    "get_audit_log",
    {
      title: "Read audit log",
      description:
        "Read the append-only NDJSON audit log. Filter by subprocessHandle, since-timestamp, and limit.",
      inputSchema: GetAuditLogArgsSchema.shape,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (args) => safe(() => getAuditLogTool(args))
  );

  return server;
}

export async function main(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();

  // Graceful shutdown: SIGTERM + SIGINT close transport + flush stderr.
  const shutdown = async (signal: string): Promise<void> => {
    try {
      await server.close();
    } catch {
      // best-effort
    }
    process.stderr.write(`[mcp-rce-guard] received ${signal}, exiting\n`);
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));

  await server.connect(transport);
  process.stderr.write(
    `[mcp-rce-guard] ${VERSION} listening on stdio (6 tools)\n`
  );
}

const isDirect = (() => {
  try {
    const argvUrl = `file://${process.argv[1]}`;
    return argvUrl === import.meta.url || process.argv[1]?.endsWith("server.js");
  } catch {
    return false;
  }
})();

if (isDirect) {
  main().catch((e) => {
    process.stderr.write(`[mcp-rce-guard] fatal: ${(e as Error).message}\n`);
    process.exit(1);
  });
}
