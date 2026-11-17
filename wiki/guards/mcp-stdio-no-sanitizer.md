---
type: Guard
title: "mcp-stdio-no-sanitizer"
description: "MCP server uses the SDK's STDIO transport with no argv sanitizer, allow-list, or opt-out anywhere in the repo."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "mcp-stdio-no-sanitizer"
checklist_section: ["4"]
standards: ["CWE-78", "OWASP-ASI:ASI04"]
---

# MCP server uses the SDK's STDIO transport with no argv sanitizer anywhere

_Author — 2026-09-26_

---

## The threat

Anthropic declined to CVE the MCP STDIO transport design itself (OX Security, 2026-04-15):
the upstream SDKs pass server configuration to the OS as command execution BY DESIGN — a
STDIO-transported MCP server IS a subprocess launch, not a bug in one. CWE-78 (OS Command
Injection), OWASP-ASI:ASI04 (Agentic Supply Chain Vulnerabilities). This leaves a structural
obligation on every downstream server that uses the SDK's STDIO primitives: add a
compensating control, because the SDK itself will not. Sourced from `agent-audit-kit`'s
`mcp_sdk_hardening.py` (AAK-ANTHROPIC-SDK-001), verified against the real repo source,
at research time.

## Why it's often introduced

STDIO is the simplest, most common MCP transport for a local-first server — it just works,
with no network config. Because the SDK handles the actual subprocess plumbing, a server
author reasonably assumes "the SDK must be validating this," when in fact the design
intentionally leaves that to the caller.

## Detection design

1. `applies()` gates on `"mcp" in profile.features`.
2. Project-wide, not per-file: first confirms the upstream MCP SDK is DECLARED in a manifest
   at any depth (a manifest under a test/example/fixture path is ignored;
   `pyproject.toml`/`requirements*.txt` for `mcp`/`modelcontextprotocol`; `package.json`
   for `@modelcontextprotocol/sdk`/`@anthropic-ai/mcp`/`@anthropic-ai/claude-agent-sdk`;
   `pom.xml`/`build.gradle(.kts)` for `io.modelcontextprotocol`; `Cargo.toml` for
   `mcp`/`modelcontextprotocol`). If no manifest declares it, the guard is silent
   immediately — this is not a generic "you spawn subprocesses" check.
3. Finds every file using a STDIO-transport API marker (`StdioServerTransport`,
   `StdioClientTransport`, `stdio_server`, `StdioServer`, `stdio_client`, `StdioClient`).
   If none, silent. It then requires LAUNCHER evidence in the project's product source: a
   client-side STDIO API (`StdioClientTransport`, `StdioTransport`, `stdio_client`,
   `StdioClient`, `StdioServerParameters`) or a process-spawn call (`subprocess.`,
   `child_process`, `spawn(`, `execFile(`, `Popen(`, `execSync(`). A server-only project reads
   JSON-RPC from stdin and builds no argv, so it is silent. Test and example paths do not count
   as launcher evidence: a test harness that starts the server under test is not the product
   launching a configured command.
4. Scans EVERY source file in the project (`.py .ts .tsx .js .mjs .java .kt .rs`, not just the
   STDIO-using ones, so a shared sanitizer helper module counts) for any of: a real
   sanitizer (`shlex.quote`/`shlex.split`, `execFile([...])` with a literal array,
   `ProcessBuilder(List.of(...)/Arrays.asList(...)/[...])`,
   `std::process::Command::new(...).arg(...)`), an allow-list identifier
   (`ALLOWED_*`/`WHITELIST_*`/`VALID_TOOLS`/`VALID_COMMANDS`), a config-level opt-out
   (`transports=['http'|'sse'|'streamable-http']`, `stdio_disabled: true`), or the inline
   pragma. If any is found anywhere in the project, the whole project is treated as covered.
   A "project" is the tree under a manifest that declares the SDK (step 2): for a
   single-package repo that is the whole repo; in a monorepo each declaring package is its
   own project (the deepest declaring manifest owns a STDIO file), so a sanitizer in one
   package does not vouch for another, and a manifest under a test/example/fixture path
   creates no project. Two further scoping rules: the pragma and the config opt-outs are also read from test/example paths and from
   YAML/TOML/JSON/INI config files (a user's own opt-out is honoured wherever it sits),
   while the sanitizer and allow-list identifiers count from PRODUCT source only (a
   `shlex.split` in a test does not vouch for production code); and web-server allow-lists
   (`ALLOWED_HOSTS`, `ALLOWED_ORIGINS`, CORS/redirect/extension/URL lists) are excluded from
   the `ALLOWED_*`/`WHITELIST_*` identifier, since they are not an argv control.
5. Only if the SDK is declared, STDIO is used, and NOTHING above is found anywhere does it
   fire — once per STDIO-using file, located at the first STDIO marker's line
   (`file.py:<line>`).
6. Inline opt-out (this project's substitute for the real source's bespoke
   `.agent-audit-kit.yml` risk-acceptance file, which agentsec has no equivalent
   convention for): a `# security: allow-mcp-stdio-no-sanitizer` comment (`// …` in JS/TS/Java/
   Kotlin) in any file of the project. A string literal or quoted config value carrying the phrase
   does not count (#424); a `.json` or `.rs` file has no comment dialect here, so there the raw
   text is matched.
7. Severity MEDIUM (a structural, repo-wide gap rather than a single provable bug — the
   same "surfacing a review" register other design-level guards in this codebase use),
   rule `mcp-stdio-no-sanitizer/no-sanitizer`, standards `["CWE-78", "OWASP-ASI:ASI04"]`.

## When NOT to flag

- The SDK is not declared at all, or STDIO transport is never used — a server that only
  uses HTTP/SSE transport is out of this guard's scope entirely (the risk is specific to
  the OS-command-execution nature of STDIO).
- Any real sanitizer, allow-list, or documented opt-out present anywhere in the project —
  deliberately project-wide, not per-file, since a shared sanitizer helper module is a normal
  and correct way to satisfy this.

## Tests

| Test | What it checks |
|---|---|
| `test_stdio_with_no_sanitizer_fires` | SDK declared + STDIO used + nothing else — fires |
| `test_shlex_sanitizer_present_is_safe` | A real `shlex.quote` call — silent |
| `test_allowlist_marker_present_is_safe` | An `ALLOWED_*` identifier — silent |
| `test_http_transport_optout_is_safe` | `transports=['http']` config opt-out — silent |
| `test_sdk_not_declared_is_safe` | STDIO-shaped identifier, no manifest declares the SDK — silent |
| `test_no_stdio_usage_is_safe` | SDK declared, only SSE transport used — silent |
| `test_sanitizer_in_a_different_file_than_the_stdio_server_clears_it` | Two-file: `shlex.quote` in `sanitize.py`, STDIO in `server.py` — silent |
| `test_without_the_helper_module_the_same_server_still_fires` | Same server without the helper — fires, with a line |
| `test_sanitizer_only_in_a_test_file_does_not_vouch_for_production` | A test-only `shlex.split` does not count |
| `test_web_allowlists_elsewhere_are_not_an_argv_control` | `ALLOWED_HOSTS` / `ALLOWED_ORIGINS` elsewhere do not count |
| `test_command_allowlist_in_another_file_clears_it`, `test_config_file_stdio_opt_out_clears_it`, `test_pragma_in_a_test_or_example_path_still_counts` | Cross-file allow-list, config opt-out and pragma clear it |
| `test_monorepo_sanitizer_in_one_package_does_not_vouch_for_another`, `test_manifest_under_a_test_path_does_not_create_a_project` | Project scoping in a monorepo |
| `test_finding_line_points_at_the_stdio_marker` | Findings carry the first STDIO marker's line |
| `test_pragma_suppresses_finding` | Inline pragma silences it |
| `test_mcp_stdio_no_sanitizer_pragma_quoted_in_a_string_does_not_suppress_py`, `test_mcp_stdio_no_sanitizer_pragma_quoted_in_a_string_does_not_suppress_yaml`, `test_mcp_stdio_no_sanitizer_pragma_quoted_in_a_string_does_not_suppress_toml`, `test_mcp_stdio_no_sanitizer_pragma_comment_suppresses_yaml`, `test_mcp_stdio_no_sanitizer_pragma_comment_suppresses_toml` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6) |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` gates correctly |

## Known bypasses

- The sanitizer/allow-list/opt-out check is project-wide presence, not scoped to whether it
  actually reaches the STDIO call site — a sanitizer used for an unrelated purpose
  elsewhere in the project silences a genuinely unprotected STDIO transport. (Import edges
  are not traced; the scope is the manifest's tree.)
- The SDK-name and marker vocabularies are fixed lists; a vendored/renamed copy of the SDK
  is invisible.
- Launcher evidence is read from product source only, using the same test/example path list as
  every other part of this guard. A server-only project whose only launcher lives under
  `examples/` (or `samples/`, `e2e/`, ...) is therefore silent, even though that example spawns
  a subprocess. This is deliberate: the finding is anchored on the product's STDIO server, which
  spawns nothing, and example code is out of scope for anchoring here and in the sanitizer search.

## What this guard does NOT prove

Silence does not prove the argv sanitizer is CORRECT or complete — only that some
recognized sanitizer/allow-list/opt-out marker exists somewhere in the repo. This is a
structural, repo-wide surfacing check (matching Anthropic's own framing of the underlying
design as an unpatchable-by-default risk class), not a proof that a specific code path is
safe.

# Citations

[1] agentsec checklist item `4-mcp-stdio-no-sanitizer` (§4)
[2] OX Security disclosure, 2026-04-15 — Anthropic declined to CVE the MCP STDIO design
[3] CWE-78, OWASP-ASI:ASI04
[4] agent-audit-kit `mcp_sdk_hardening.py`, rule AAK-ANTHROPIC-SDK-001
