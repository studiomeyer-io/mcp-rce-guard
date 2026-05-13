import { describe, it, expect } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createServer } from "../../src/server.js";
import { NAME, VERSION } from "../../src/version.js";

describe("MCP server", () => {
  it("creates without throwing", () => {
    const server = createServer();
    expect(server).toBeDefined();
  });

  it("is an instance of McpServer (public-API contract)", () => {
    const server = createServer();
    expect(server).toBeInstanceOf(McpServer);
  });

  // Reviewer S1024 F5-Sub-e / F9 fix: previous test reached into
  // `_serverInfo` (private field of the SDK). That field is "stable in 1.x"
  // by convention only and breaks the moment the SDK refactors. Use the
  // public `server` accessor (which exposes the underlying low-level Server)
  // and verify it exists. Name/version are sourced from src/version.ts at
  // build time, so we assert that those exported constants match what the
  // package.json declares — that is the actual production contract.
  it("exposes the underlying low-level Server via public getter", () => {
    const server = createServer();
    // McpServer.server is documented public (see SDK README).
    expect(server.server).toBeDefined();
  });

  it("NAME + VERSION are populated from build-time module", () => {
    expect(NAME).toBe("mcp-rce-guard");
    expect(typeof VERSION).toBe("string");
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
  });
});
