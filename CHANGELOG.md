# Changelog

All notable changes to `mcp-rce-guard` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-06-21

### Security

- **New CVE-replay fixture `mcp-interpreter-eval-rce` — closes the
  interpreter inline-eval RCE class.** Before this release, a command that
  handed attacker-influenced source code to a language runtime via an
  inline-eval flag (`node -e` / `node --eval` / `node -p`, `python -c`,
  `perl -e`, `ruby -e`, `php -r`, `deno eval`, `bun -e`) was reported as
  `overall: pass` by `scan_cve_replay`. Such commands need **no** shell
  binary and **no** shell metacharacter, so they slipped past both the
  `nginx-mcp-rce-9.8` (shell-binary) and `mcp-sdk-rce-2026-04-22`
  (shell-metachar) predicates — a full arbitrary-code-execution hole in a
  guard whose entire purpose is to close tool-injection RCE. Detection is
  exact-token (post-NFKC) so benign launch flags such as
  `--experimental-vm-modules`, `--enable-source-maps`,
  `--max-old-space-size=512` and `--inspect` are **not** misclassified.
  (`src/cve/replay.ts`, `src/types.ts`).
- **`mcp-sdk-rce-2026-04-22` now flags newline / carriage-return command
  separators.** A literal `\n` / `\r` is a command separator in every POSIX
  shell, but the metacharacter pattern set previously omitted them, so
  `node tool.js\nrm -rf /` passed. (`src/cve/replay.ts`).
- **`policyAllowsExec` path-confusion fix.** The exported landlock predicate
  used a naive `startsWith`, so a rule for `/usr/bin` also authorized
  `execute` on sibling paths that merely share the textual prefix
  (`/usr/binary-evil/x`, `/usr/bin-backdoor`) — paths outside the allowed
  tree. Matching is now path-boundary aware (exact path or `/`-delimited
  descendant). (`src/isolation/landlock.ts`).

### Added

- Attack-blocked **and** benign-allowed test coverage for every detection
  change above (`tests/unit/cve-replay.test.ts`,
  `tests/unit/landlock-policy.test.ts`). Suite grows 142 → 179 tests.

### Notes

- All three fixes are additive and backward compatible. Existing `cveSet`
  arrays keep working; `BUILT_IN_FIXTURES` grows from 3 to 4. This stays in
  the v0.1 descriptor-only line — no native enforcement is introduced (that
  remains the v0.2 tranche). Hence a patch bump (0.1.0 → 0.1.1) rather than a
  minor, which the README reserves semantically for the native-enforcement
  release.

## [0.1.0] - 2026-05-13

- Initial public release. Policy-synthesis (landlock / sandbox-exec /
  cgroups-v2 descriptors), behavioral CVE-replay predicates
  (`mcp-sdk-rce-2026-04-22`, `cve-2026-27124`, `nginx-mcp-rce-9.8`),
  cross-server canary tracker, network-egress allowlist, append-only NDJSON
  audit log, NFKC + zero-width + Bidi normalization shared with Pillar 8.
