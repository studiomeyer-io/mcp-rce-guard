/**
 * Append-only NDJSON audit log.
 *
 * Path: ${MCP_RCE_GUARD_HOME:-~/.mcp-rce-guard}/audit.log
 *
 * Each line is a JSON-serialized AuditLogEntry. The log is append-only with
 * size-based rotation (Reviewer S1024 F6): when the active log exceeds
 * `MCP_RCE_GUARD_AUDIT_MAX_BYTES` (default 100MB), it is atomically renamed
 * to `audit.log.1`, the previous .1 becomes .2, etc., up to .10. Anything
 * beyond .10 is dropped to bound disk usage.
 *
 * Pre-Publish-Audit (2026-05-13 F1/F3/F5):
 *   - HMAC-SHA256 signing path removed: the v0.1 implementation lacked a
 *     verifier, key-validation and rotation-safety, making it security
 *     theatre per Acra-pattern (industry baseline for HMAC audit-log chains).
 *     v0.2 will reintroduce a verified Acra-style signed chain.
 *   - NDJSON reader now uses `JSON.parse(line.trim())` per line; the previous
 *     tab-splitting scheme silently dropped entries whose arg strings
 *     contained a literal tab character.
 */

import { promises as fs } from "node:fs";
import { existsSync, mkdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import type { AuditLogEntry } from "../types.js";

/**
 * Reviewer S1024 F6: cap on active log size before rotation. Default 100MB.
 * Configurable via env so ops can tune for high-volume tenants.
 */
const DEFAULT_MAX_BYTES = 100 * 1024 * 1024;
const MAX_ROTATED_BACKUPS = 10;

function homeDir(): string {
  return process.env["MCP_RCE_GUARD_HOME"] ?? join(homedir(), ".mcp-rce-guard");
}

export function auditLogPath(): string {
  return join(homeDir(), "audit.log");
}

function maxBytes(): number {
  const raw = process.env["MCP_RCE_GUARD_AUDIT_MAX_BYTES"];
  if (!raw) return DEFAULT_MAX_BYTES;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_MAX_BYTES;
  return parsed;
}

function ensureDir(path: string): void {
  const dir = dirname(path);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}

/**
 * Rotate the active log: rename audit.log → audit.log.1 (shifting existing
 * .1 → .2 etc., up to .MAX_ROTATED_BACKUPS). Anything beyond .10 is unlinked.
 * Atomic via fs.rename, which is atomic on the same filesystem on POSIX.
 *
 * Known Issue v0.1 (Pre-Publish-Audit F2): TOCTOU race window between the
 * size-check and the rename. In multi-process / high-concurrency setups, two
 * appenders may both observe "needs rotation" and both attempt the rename;
 * the loser's append lands in the freshly-created empty active log. v0.2
 * will gate rotation behind `proper-lockfile` or an equivalent advisory
 * lockfile. v0.1 callers should serialize writes or accept the race.
 */
export async function rotateAuditLog(): Promise<{ rotated: boolean; reason?: string }> {
  const active = auditLogPath();
  if (!existsSync(active)) {
    return { rotated: false, reason: "no active log" };
  }
  // Shift backups: .9 → .10, .8 → .9, ..., .1 → .2
  for (let i = MAX_ROTATED_BACKUPS; i >= 2; i--) {
    const from = `${active}.${i - 1}`;
    const to = `${active}.${i}`;
    if (existsSync(from)) {
      // If destination exists (overflow at .10), drop it first.
      if (existsSync(to)) {
        await fs.unlink(to);
      }
      await fs.rename(from, to);
    }
  }
  // Move active → .1
  const dotOne = `${active}.1`;
  if (existsSync(dotOne)) {
    await fs.unlink(dotOne);
  }
  await fs.rename(active, dotOne);
  return { rotated: true };
}

function shouldRotate(path: string): boolean {
  if (!existsSync(path)) return false;
  try {
    const st = statSync(path);
    return st.size >= maxBytes();
  } catch {
    return false;
  }
}

/**
 * Append a single audit-log entry. Idempotent against duplicate calls — every
 * call writes a distinct line because `ts` is auto-stamped if missing.
 *
 * Triggers rotation BEFORE writing if the active log already exceeds the
 * configured cap. This is a best-effort guard; under heavy concurrency the
 * log may briefly exceed the cap by one batch (acceptable for audit
 * semantics).
 */
export async function appendAudit(
  entry: Omit<AuditLogEntry, "ts"> & { ts?: string }
): Promise<void> {
  const finalEntry: AuditLogEntry = {
    ts: entry.ts ?? new Date().toISOString(),
    subprocessHandle: entry.subprocessHandle,
    action: entry.action,
    verdict: entry.verdict,
    ...(entry.serverId !== undefined ? { serverId: entry.serverId } : {}),
    ...(entry.reason !== undefined ? { reason: entry.reason } : {}),
    ...(entry.meta !== undefined ? { meta: entry.meta } : {})
  };
  const path = auditLogPath();
  ensureDir(path);
  if (shouldRotate(path)) {
    await rotateAuditLog();
  }
  // JSON.stringify never emits a literal newline inside the string (all
  // control chars are escaped). One entry == one NDJSON line.
  const line = JSON.stringify(finalEntry);
  await fs.appendFile(path, line + "\n", { mode: 0o600 });
}

/**
 * Read entries with optional filters.
 *
 * Pre-Publish-Audit F3: each line is parsed as a single JSON document. The
 * earlier implementation split on the last tab character (legacy HMAC suffix
 * carve-out); arg strings containing a literal tab were silently truncated
 * and the surviving prefix failed JSON.parse, dropping the entry. The
 * NDJSON-standard read path used here is robust to any byte content the
 * JSON encoder produced.
 */
export async function readAudit(filter?: {
  subprocessHandle?: string;
  since?: string;
  limit?: number;
}): Promise<AuditLogEntry[]> {
  const path = auditLogPath();
  if (!existsSync(path)) return [];
  const raw = await fs.readFile(path, "utf8");
  // Splitting on \n is safe: JSON.stringify escapes embedded newlines as \n
  // (literal two-character sequence) so a real newline only appears at the
  // entry boundary written by appendAudit.
  const lines = raw.split("\n").filter((l) => l.length > 0);
  const entries: AuditLogEntry[] = [];
  for (const rawLine of lines) {
    try {
      const parsed = JSON.parse(rawLine.trim()) as AuditLogEntry;
      if (filter?.subprocessHandle && parsed.subprocessHandle !== filter.subprocessHandle) {
        continue;
      }
      if (filter?.since && parsed.ts < filter.since) {
        continue;
      }
      entries.push(parsed);
    } catch {
      // Skip malformed lines; production: add a counter + WARN log.
      continue;
    }
  }
  if (filter?.limit && entries.length > filter.limit) {
    return entries.slice(-filter.limit);
  }
  return entries;
}

/**
 * Test helper: clear the log file. NOT a public API — imported directly
 * from this module by tests; intentionally absent from `src/index.ts`
 * re-exports so external consumers cannot accidentally drop their
 * audit trail (Pre-Publish-Audit F9).
 *
 * @internal
 */
export async function clearAuditLog(): Promise<void> {
  const path = auditLogPath();
  if (existsSync(path)) {
    await fs.unlink(path);
  }
  // Also clear any rotated backups so test runs start clean.
  for (let i = 1; i <= MAX_ROTATED_BACKUPS; i++) {
    const backup = `${path}.${i}`;
    if (existsSync(backup)) {
      await fs.unlink(backup);
    }
  }
}
