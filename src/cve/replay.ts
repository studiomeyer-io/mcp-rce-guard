/**
 * CVE replay engine.
 *
 * v0.1 ships built-in replay logic for three 2026-CVEs. Each fixture is a
 * deterministic predicate that examines the candidate `targetServerCommand`
 * + the registered subprocess profile and decides if the configuration
 * would be vulnerable. A `pass` verdict means the configuration BLOCKS the
 * vuln class; `fail` means the configuration is still vulnerable.
 *
 * The fixtures are *behavioral predicates*, not exploit payloads, so this
 * package can ship without security-distribution-hygiene flags. The
 * separate `mcp-rce-fixtures` package contains additional offline replay
 * suites for CI use; v0.1 inlines just enough to make the tool useful
 * without requiring the fixtures package.
 *
 * Sources:
 *   - MCP-SDK-RCE 22.04.2026 (Cloudflare patch in createMcpHandler)
 *   - CVE-2026-27124 (FastMCP Confused Deputy)
 *   - Nginx-MCP RCE CVSS 9.8
 */

import type { CveId } from "../types.js";
import { normalizeArg } from "../normalize.js";

export interface CveFixture {
  id: CveId;
  description: string;
  predicate: (cmd: string) => CveFixtureResult;
}

export interface CveFixtureResult {
  status: "pass" | "fail";
  evidence: string;
}

/**
 * Allowlist of variable names that are considered safe to embed verbatim in
 * a target command. Anything outside this allowlist gets flagged as
 * potential confused-deputy material by the cve-2026-27124 fixture.
 *
 * Reviewer S1024 F4-Sub-b: previous code used a narrow blocklist
 * (`API_KEY|SECRET|TOKEN|PASSWORD|BEARER`) and missed obvious credentials
 * like `AUTH_HEADER`, `COOKIE`, `SESSION_ID`, `PRIVATE_KEY`, `REFRESH_TOKEN`.
 * Inverting to allowlist closes the entire credential-name surface.
 */
const SAFE_ENV_VARS: ReadonlySet<string> = new Set([
  "HOME",
  "USER",
  "USERNAME",
  "LOGNAME",
  "SHELL",
  "PATH",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TZ",
  "TERM",
  "TMPDIR",
  "TEMP",
  "TMP",
  "PWD",
  "OLDPWD",
  "HOSTNAME",
  "DISPLAY",
  "EDITOR",
  "PAGER",
  "NODE_ENV",
  "DEBUG",
  "CI"
]);

/**
 * Shell binaries that are commonly used to wrap a subprocess and grant it the
 * full inheritance surface that Nginx-MCP RCE (CVSS 9.8) exploits. Broadened
 * per Reviewer S1024 F4-Sub-c — busybox/dash/csh/ksh/fish/tcsh now covered,
 * arbitrary absolute paths covered, indirect invocation (`exec`, `nice`, `env`)
 * covered.
 */
const SHELL_BINARIES: readonly string[] = [
  "sh",
  "bash",
  "zsh",
  "dash",
  "ksh",
  "csh",
  "tcsh",
  "fish",
  "ash",
  "busybox"
];

/**
 * Detect any unquoted shell metacharacter or substitution form anywhere in
 * the command. Covers (Reviewer S1024 F4-Sub-a evidence):
 *   - Standalone metachars: `;`, `|`, `&` (single + double), `>`, `<`
 *   - Command substitution: backticks `` `cmd` ``
 *   - `$(cmd)` substitution
 *   - `<<<` here-strings
 *   - `${VAR}` and `$VAR` variable expansions adjacent to metachars
 */
const SHELL_METACHAR_PATTERNS: readonly { pattern: RegExp; name: string }[] = [
  { pattern: /`[^`]*`/, name: "backtick command substitution" },
  { pattern: /\$\([^)]*\)/, name: "$(...) command substitution" },
  { pattern: /<<</, name: "here-string redirect (<<<)" },
  { pattern: /(^|[^\\])[;]/, name: "unescaped semicolon" },
  { pattern: /(^|[^\\|])\|(?!\|)/, name: "unescaped pipe" },
  { pattern: /(^|[^\\&])&(?!&)/, name: "unescaped background ampersand" },
  { pattern: /(^|[^\\])&&/, name: "logical-and operator" },
  { pattern: /(^|[^\\])\|\|/, name: "logical-or operator" },
  { pattern: /(^|[^\\])>(?!>)/, name: "stdout redirect" },
  { pattern: /(^|[^\\])>>/, name: "append redirect" },
  { pattern: /(^|[^\\])<(?![<])/, name: "stdin redirect" },
  { pattern: /\$\{[^}]+\}/, name: "${VAR} expansion" },
  { pattern: /\$[A-Za-z_][A-Za-z0-9_]*/, name: "$VAR expansion" }
];

function findShellInvocation(cmd: string): string | null {
  // Tokenize on whitespace + simple separators so we can spot a shell
  // binary anywhere in the command (not just anchored at the start).
  const tokens = cmd
    .split(/[\s;|&]+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
  for (const token of tokens) {
    // Strip absolute-path prefix to compare just the basename.
    const basename = token.split("/").pop() ?? token;
    if (SHELL_BINARIES.includes(basename)) {
      return token;
    }
  }
  return null;
}

export const BUILT_IN_FIXTURES: readonly CveFixture[] = [
  {
    id: "mcp-sdk-rce-2026-04-22",
    description:
      "MCP-SDK ungesanitized Tool-Args fed into shell command. Predicate: command must NOT contain ANY shell metacharacters or substitution forms (broadened per Reviewer S1024 F4-Sub-a — covers ;, |, &, &&, ||, backticks, $(), <<<, redirects, ${VAR}, $VAR).",
    predicate: (cmd) => {
      for (const { pattern, name } of SHELL_METACHAR_PATTERNS) {
        if (pattern.test(cmd)) {
          return {
            status: "fail",
            evidence: `command contains ${name} (${cmd}) — shell-injection class`
          };
        }
      }
      return {
        status: "pass",
        evidence: "no shell metacharacters or substitution forms detected"
      };
    }
  },
  {
    id: "cve-2026-27124",
    description:
      "FastMCP Confused Deputy — server forwards caller-controlled token to downstream. Predicate: any embedded `${VAR}` or `$VAR` must be in the SAFE_ENV_VARS allowlist (Reviewer S1024 F4-Sub-b — invert to allowlist).",
    predicate: (cmd) => {
      // Match both ${VAR_NAME} and $VAR_NAME forms.
      const bracedRe = /\$\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}/g;
      const bareRe = /\$([A-Za-z_][A-Za-z0-9_]*)\b/g;
      const flagged: string[] = [];
      for (const re of [bracedRe, bareRe]) {
        let m: RegExpExecArray | null;
        while ((m = re.exec(cmd)) !== null) {
          const name = m[1];
          if (name && !SAFE_ENV_VARS.has(name)) {
            flagged.push(name);
          }
        }
      }
      if (flagged.length > 0) {
        const list = Array.from(new Set(flagged)).join(", ");
        return {
          status: "fail",
          evidence: `command embeds non-allowlisted env-var(s): ${list} — potential confused-deputy class`
        };
      }
      return {
        status: "pass",
        evidence: "no non-allowlisted env-vars embedded in command"
      };
    }
  },
  {
    id: "nginx-mcp-rce-9.8",
    description:
      "Nginx-MCP RCE CVSS 9.8 — bridge-server spawns subprocess inheriting full parent permissions. Predicate: no shell binary may appear anywhere in the command, regardless of path/invocation form (broadened per Reviewer S1024 F4-Sub-c — busybox/dash/csh/ksh/fish/tcsh covered, arbitrary paths covered, indirect invocation covered).",
    predicate: (cmd) => {
      const found = findShellInvocation(cmd);
      if (found !== null) {
        return {
          status: "fail",
          evidence: `command invokes shell binary "${found}" — RCE-bridge class`
        };
      }
      return {
        status: "pass",
        evidence: "no shell binary invocation detected"
      };
    }
  }
];

export function getFixture(id: CveId): CveFixture | undefined {
  return BUILT_IN_FIXTURES.find((f) => f.id === id);
}

export interface ReplayPerCve {
  id: CveId;
  status: "pass" | "fail" | "skipped";
  durationMs: number;
  evidence?: string;
}

export interface ReplayResult {
  overall: "pass" | "fail";
  perCve: ReplayPerCve[];
}

export function runReplay(
  targetCommand: string,
  cveSet?: CveId[],
  timeoutMs = 30_000
): ReplayResult {
  // Reviewer F3 (Session post-S1056): pre-normalize the target command before
  // feeding it to predicates. NFKC + ZWC-strip + Bidi-block ensures
  // Fullwidth-Unicode-Bypass payloads like `＄（rm -rf /）` collapse to
  // `$(rm -rf /)` and trigger SHELL_METACHAR_PATTERNS. Without this step,
  // `scan_cve_replay` returned false-negatives on the simulate_attacker_input
  // fullwidth-unicode corpus that README §13 explicitly claims to cover.
  // The audit_subprocess path already normalizes via Pillar-8 shared normalize.ts;
  // this aligns scan_cve_replay with the same canonical form.
  const normalizedCommand = normalizeArg(targetCommand);

  const ids = cveSet ?? BUILT_IN_FIXTURES.map((f) => f.id);
  const perCve: ReplayPerCve[] = [];
  const startAll = Date.now();

  for (const id of ids) {
    const fixture = getFixture(id);
    if (!fixture) {
      perCve.push({ id, status: "skipped", durationMs: 0, evidence: "unknown fixture id" });
      continue;
    }
    if (Date.now() - startAll > timeoutMs) {
      perCve.push({ id, status: "skipped", durationMs: 0, evidence: "timeout" });
      continue;
    }
    const start = Date.now();
    const result = fixture.predicate(normalizedCommand);
    perCve.push({
      id,
      status: result.status,
      durationMs: Date.now() - start,
      evidence: result.evidence
    });
  }

  const overall: "pass" | "fail" = perCve.every((r) => r.status !== "fail") ? "pass" : "fail";
  return { overall, perCve };
}
