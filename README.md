# mcp-rce-guard

Policy-synthesis + behavioral CVE-replay + canary-tracking library for MCP servers. Foundation Pillar 9.

## v0.1 Scope: Policy-Synthesizer, Not Kernel-Level Sandbox

**Be precise about what this is and is not.** v0.1 is a building-block library that synthesizes isolation **policy descriptors** (landlock JSON profiles, sandbox-exec `.sb` scheme files, cgroups-v2 spec maps) and provides **behavioral predicates** that scan subprocess commands for known RCE-vulnerability shapes. It does **not** apply those policies to a running process. The host spawning the subprocess is responsible for translating a descriptor into the platform-specific syscall (Linux landlock, macOS sandbox-exec, cgroups-v2 fs write).

**Native enforcement** (NAPI-RS landlock binding, sandbox-exec execa wrap, cgroups-v2 file writes with cleanup-on-exit, cross-platform integration tests) is the **v0.2 tranche** and is not bundled with v0.1. Layered defense relies on the host wiring policy emission to actual enforcement; this library does the first half cleanly.

Use this library if you want:
- A typed, validated way to describe what an MCP subprocess is allowed to read, write, spawn, and talk to.
- A reproducible scanner for known RCE-vulnerability classes in subprocess commands (MCP-SDK-RCE-2026-04-22, CVE-2026-27124, Nginx-MCP RCE 9.8) plus 5 shell-injection + 3 fullwidth-unicode payload patterns from the simulate_attacker_input corpus.
- An append-only NDJSON audit log of every isolation decision. Verified tamper-evident signing (Acra-pattern key derivation + rotation + integrated verifier) is on the v0.2 roadmap; v0.1 ships the log unsigned and treats signing as a v0.2 deliverable.

Do **not** use v0.1 if you need a sandbox that actually contains a hostile subprocess at the kernel boundary. For that, the v0.1 descriptor needs to be paired with an enforcement helper. v0.2 ships that helper.

## What it does (v0.1)

- **Process isolation policy synthesis** — emits landlock (Linux >=5.13) policy descriptors, sandbox-exec (macOS) Scheme profiles, cgroups-v2 specs (memory.max, pids.max, cpu.max). Descriptors only; no syscalls are made.
- **Network egress allowlist** — default-deny policy with wildcard / exact / suffix / port:* matching. Descriptors only; no nftables / packet-filter integration.
- **CVE replay suite** — behavioral predicates for known MCP-server RCE vectors. Not exploit payloads — predicates that scan a target command for the vulnerable shape.
- **Cross-server canary tokens** — issue tokens, scan downstream stdout / fs-write / network-egress streams for leaks (MCPHunt arXiv 2604.27819 pattern).
- **NDJSON append-only audit log** — every tool call appended at `$MCP_RCE_GUARD_HOME/audit.log`. 100MB rotation with max 10 backups. v0.1 ships unsigned (no in-process verifier); v0.2 adds Acra-pattern HMAC chain with key derivation, rotation safety and an integrated verifier.
- **NFKC + zero-width strip + Bidi-block** normalization shared with Pillar 8 (mcp-stdio-shellguard).

## Install

```bash
npm install -g mcp-rce-guard
```

Or run via npx:

```bash
npx -y mcp-rce-guard serve
```

## Tools (MCP, Spec 2025-06-18)

| Tool | Purpose | readOnly | destructive |
|------|---------|----------|-------------|
| `register_subprocess` | Register a child MCP server with isolation profile, get back a handle + fingerprint + policy descriptor | yes | no |
| `audit_subprocess` | Verify requested args match registered allowlist (post-NFKC, smell-test for invisibles) | yes | no |
| `scan_cve_replay` | Run behavioral predicates against a target server command | yes | no |
| `track_canary` | Issue a canary token + scan downstream servers for leaks | yes | no |
| `inject_egress_policy` | Emit network-egress allowlist descriptor for a registered subprocess (v0.1 descriptor-only) | yes | no |
| `get_audit_log` | Read NDJSON audit log entries with filters | yes | no |

> **v0.1 Honesty Note:** all six tools are `readOnlyHint=true, destructiveHint=false` in v0.1 because they emit policy descriptors + append to the audit log but do not modify subprocess state. v0.2 will flip `inject_egress_policy` to `destructiveHint=true` when native enforcement is wired in.

## CLI

```bash
mcp-rce-guard serve            # start MCP server on stdio
mcp-rce-guard platform         # detect isolation backend (landlock/sandbox-exec/unsupported)
mcp-rce-guard scan-cve <cmd>   # one-shot CVE replay against a command
mcp-rce-guard audit-log        # tail the audit log
mcp-rce-guard policy <profile.json>  # synthesize landlock+cgroups+sandbox-exec from JSON
```

## Compatibility matrix

| Platform | Isolation backend | Network egress | cgroups |
|----------|-------------------|----------------|---------|
| Linux >= 5.13 | landlock | nftables hook (out-of-band) | cgroups-v2 |
| Linux < 5.13 | unsupported | unsupported | unsupported |
| macOS 11+ | sandbox-exec (.sb) | sandbox-exec network rules | n/a |
| Windows | unsupported (planned: AppContainer) | n/a | n/a |

## Layer architecture (v0.1)

```
Pillar 1 (mcp-protocol-conformance) — protocol input shape
        ↓
Pillar 8 (mcp-stdio-shellguard)     — argv allowlist + invisible-codepoint detection
        ↓
Pillar 9 (mcp-rce-guard, this lib)  — policy synthesis + CVE-replay scan + canary
        ↓
Host spawner (caller responsibility) — applies the policy descriptor via real syscalls
```

In v0.2 the bottom box collapses into Pillar 9 (NAPI-RS landlock binding, sandbox-exec exec wrap, cgroups-v2 fs writes with cleanup). Until then, the host has to bridge the descriptor to the platform.

## Trust tiers

| Tier | mem | pids | egress | use |
|------|-----|------|--------|-----|
| `LOW` | 256MB | 32 | none | untrusted MCP from registry |
| `MEDIUM` | 512MB | 64 | api-only | known vendor with limited scope |
| `HIGH` | 1024MB | 128 | broad | first-party MCP with reviewed source |
| `CRITICAL` | 2048MB | 256 | unrestricted | local OS-integrated MCP, you own the source |

## Audit log location

```
$MCP_RCE_GUARD_HOME/audit.log     # default: ~/.mcp-rce-guard/audit.log
```

Entries are written as one JSON document per line (NDJSON) and read back via
`JSON.parse` per line, so arbitrary characters inside `args` strings (tabs,
quotes, embedded escape sequences) round-trip safely. Rotation happens at
100MB; up to 10 backups (`audit.log.1` .. `audit.log.10`) are kept.

v0.1 does **not** sign entries. The previous `MCP_RCE_GUARD_SIGNING_KEY`
HMAC-SHA256 path was removed pre-publish: there was no in-process verifier,
no key-length validation, and no rotation strategy, which would have been
security theatre. v0.2 ships a verified Acra-pattern chain (`KDF(master) →
per-entry HMAC`, key rotation, an integrated `verify_audit_log` tool).

## Notes

- v0.1 emits **policy descriptors**. Actual landlock syscall application is the responsibility of the spawning helper (separation-of-concerns: policy synthesis is portable, syscall is platform-specific). A native bindings wrapper is planned for v0.2.
- CVE fixtures are **behavioral predicates**, not runnable exploits. They check: "does the target command match the shape known to be exploitable?" Not "can we trigger the exploit?"
- Canary tokens use crypto-random 64-hex bodies inside `__MCP_CANARY_<hex>__` markers. Pattern uniqueness is statistical, not crypto-guaranteed against an adversary that controls the generator.

## Known Issues v0.1

These are real but accepted limitations of the v0.1 line. They are tracked in
the v0.2 roadmap below; if any of them blocks your use case, pin to a future
v0.2.x release once it ships.

- **Audit-log rotation has a TOCTOU window** (`src/audit/log.ts`
  `rotateAuditLog`). The size check and the rename are not atomic. In
  multi-process / high-concurrency setups two appenders may both observe
  "needs rotation" and both attempt the rename; the loser's append lands in
  the freshly-created empty active log. Workaround: serialize writes or run
  one writer per process. v0.2 will gate rotation behind `proper-lockfile`.
- **In-memory state lost on restart** (`src/state.ts`). Registered
  subprocesses and canary chains live in process memory. A process restart
  empties the registry; the operator has to re-register. v0.2 plans a
  SQLite-backed store as an opt-in persistence layer.
- **`mcp-protocol-validator` CI step is not a hard gate**
  (`.github/workflows/ci.yml`). The validator runs with
  `continue-on-error: true` because the upstream tool is still stabilising;
  failures surface as CI annotations but do not block. v0.2 promotes it to a
  hard gate once upstream is stable.
- **Audit log is unsigned in v0.1**. See "Audit log location" above. v0.2
  adds a verified Acra-pattern signed chain.

## v0.2 Roadmap (parked, no commit date)

- pnpm-workspace mit `mcp-rce-guard` + `mcp-rce-demo` + `mcp-rce-fixtures` (Marketplace-Distribution-Hygiene: CVE-Fixtures separate distribution).
- NAPI-RS Landlock binding fuer Linux (kernel >=5.13). Plain `child_process.spawn` mit prctl + LANDLOCK_CREATE_RULESET ist nicht testbar ohne C-Bridge.
- macOS sandbox-exec execa wrap mit profile-file lifecycle (deny-network triggert connection-refused, deny-fs-read triggert EACCES).
- cgroups-v2 fs.writeFile mit Permission-Checks + cleanup-on-exit + signal handlers.
- Integration tests `tests/integration/linux-landlock.test.ts` + `tests/integration/macos-sandbox-exec.test.ts`.
- Reference server `mcp-rce-demo` mit 6 Tools die jede Capability live demonstrieren (read_isolated_file, attempt_egress_blocked, spawn_subprocess_audited, replay_cve_demo, inject_canary_demo, get_demo_audit).
- Latency test "subprocess-Spawn p95 <200ms" auf ubuntu-latest GitHub Actions runner.
- Sigstore Trusted Publishing OIDC fuer alle 3 npm-Packages.
- Verified Acra-pattern audit-log chain: KDF master-key → per-entry HMAC, key rotation with overlap window, integrated `verify_audit_log` tool. Replaces the v0.1 HMAC-SHA256 prototype that was removed pre-publish for lacking a verifier.

## License

MIT — Copyright (c) 2026 Matthias Meyer (StudioMeyer)
