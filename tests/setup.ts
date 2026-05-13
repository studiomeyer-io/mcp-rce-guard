/**
 * Vitest setup: redirect MCP_RCE_GUARD_HOME to a per-run temp dir so the
 * audit log never writes to ~/.mcp-rce-guard during tests.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "mcp-rce-guard-test-"));
process.env["MCP_RCE_GUARD_HOME"] = dir;
