/**
 * mcp-rce-guard CLI.
 *
 * Subcommands:
 *   serve                       — run the stdio MCP server (same as mcp-rce-guard-server bin)
 *   platform                    — print detected isolation backend + capabilities
 *   scan-cve <command...>       — run CVE replay fixtures against a candidate command
 *   audit-log [--since=..]      — print recent audit-log entries
 *   policy <profile.json>       — emit landlock + sandbox-exec + cgroups specs from a profile
 */

import { Command } from "commander";
import { readFileSync } from "node:fs";
import { detectPlatform } from "./isolation/platform.js";
import { runReplay } from "./cve/replay.js";
import { readAudit, rotateAuditLog, auditLogPath } from "./audit/log.js";
import { buildLandlockPolicy } from "./isolation/landlock.js";
import { buildSandboxProfile } from "./isolation/sandbox-exec.js";
import { buildCgroupSpec } from "./isolation/cgroups.js";
import { IsolationProfileSchema } from "./types.js";
import { resolveProfile } from "./trust-tiers.js";
import { NAME, VERSION } from "./version.js";
import type { CveId } from "./types.js";
import { main as serverMain } from "./server.js";

const program = new Command();
program
  .name(NAME)
  .description("Layer-3 RCE defense for MCP servers")
  .version(VERSION);

program
  .command("serve")
  .description("Run the stdio MCP server")
  .action(async () => {
    await serverMain();
  });

program
  .command("platform")
  .description("Print detected isolation backend + capabilities")
  .action(() => {
    const info = detectPlatform();
    process.stdout.write(JSON.stringify(info, null, 2) + "\n");
  });

program
  .command("scan-cve")
  .description("Run CVE replay fixtures against a candidate command")
  .argument("<command...>", "command tokens (joined with spaces)")
  .option("--cve <ids...>", "CVE IDs to run (default: all)")
  .option("--timeout <ms>", "timeout in milliseconds", "30000")
  .action((cmdTokens: string[], opts: { cve?: string[]; timeout: string }) => {
    const command = cmdTokens.join(" ");
    const cveSet = opts.cve as CveId[] | undefined;
    const timeoutMs = parseInt(opts.timeout, 10) || 30_000;
    const result = runReplay(command, cveSet, timeoutMs);
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    process.exit(result.overall === "pass" ? 0 : 2);
  });

program
  .command("audit-log")
  .description("Print recent audit-log entries")
  .option("--since <iso>", "only entries since this ISO timestamp")
  .option("--handle <h>", "filter by subprocess handle")
  .option("--limit <n>", "max entries", "100")
  .action(async (opts: { since?: string; handle?: string; limit: string }) => {
    const filter: { since?: string; subprocessHandle?: string; limit: number } = {
      limit: parseInt(opts.limit, 10) || 100
    };
    if (opts.since) filter.since = opts.since;
    if (opts.handle) filter.subprocessHandle = opts.handle;
    const entries = await readAudit(filter);
    for (const e of entries) {
      process.stdout.write(JSON.stringify(e) + "\n");
    }
  });

program
  .command("cleanup")
  .description("Force-rotate the audit log (audit.log → audit.log.1, shifting backups)")
  .action(async () => {
    const result = await rotateAuditLog();
    process.stdout.write(
      JSON.stringify({ ...result, path: auditLogPath() }, null, 2) + "\n"
    );
  });

program
  .command("policy")
  .description("Emit isolation specs from a profile JSON file")
  .argument("<file>", "path to profile JSON")
  .option("--tier <tier>", "trust tier base (LOW|MEDIUM|HIGH|CRITICAL)", "MEDIUM")
  .option("--cgroup-name <name>", "cgroup name for cgroups spec", "mcp-rce-guard-default")
  .action((file: string, opts: { tier: string; cgroupName: string }) => {
    const raw = readFileSync(file, "utf8");
    const overrides = IsolationProfileSchema.partial().parse(JSON.parse(raw));
    const tier = opts.tier as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    const profile = resolveProfile(tier, overrides);
    const out = {
      tier,
      profile,
      landlock: buildLandlockPolicy(profile),
      sandboxExec: buildSandboxProfile(profile),
      cgroups: buildCgroupSpec(opts.cgroupName, profile)
    };
    process.stdout.write(JSON.stringify(out, null, 2) + "\n");
  });

const isDirect = (() => {
  try {
    return process.argv[1]?.endsWith("cli.js") ?? false;
  } catch {
    return false;
  }
})();

if (isDirect) {
  // No args → serve. Matches the behavior of `mcp-rce-guard-server` bin.
  if (process.argv.length <= 2) {
    serverMain().catch((e: unknown) => {
      const msg = e instanceof Error ? e.message : String(e);
      process.stderr.write(`[mcp-rce-guard] fatal: ${msg}\n`);
      process.exit(1);
    });
  } else {
    program.parseAsync(process.argv).catch((e: unknown) => {
      const msg = e instanceof Error ? e.message : String(e);
      process.stderr.write(`[mcp-rce-guard cli] error: ${msg}\n`);
      process.exit(1);
    });
  }
}

export { program };
