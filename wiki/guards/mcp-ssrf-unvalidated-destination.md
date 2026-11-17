---
type: Guard
title: "mcp-ssrf-unvalidated-destination"
description: "MCP-reachable destination (a tool-handler URL argument, or an MCP-config server/webhook URL) reaches an outbound fetch with no host/scheme validation."
timestamp: "2026-09-22T11:30:00+08:00"
guard_id: "mcp-ssrf-unvalidated-destination"
checklist_section: ["4"]
standards: ["CWE-918", "OWASP:A10", "OWASP-ASI:ASI04"]
---

# MCP-reachable destination reaches an outbound fetch with no host/scheme validation

_Author — 2026-09-22_

---

## The threat

Two CVEs, two taint sources, one shared shape: a network destination the MCP server does not
choose itself reaches a server-side HTTP fetch, and nothing in the reachable code resolves or
range-checks it first. An attacker who controls the destination — a tool-call argument, or an
MCP server registration — gets the server to fetch on their behalf: internal services, cloud
metadata endpoints (`169.254.169.254`), or an attacker-controlled host for data exfiltration.

**Rule A — tool-argument SSRF (CVE-2026-14748, CVSS 6.3, CWE-918):** AIAnytime
Awesome-MCP-Server's `mcp-wiki/src/mcp_wiki/server.py` routes a tool parameter named `url`
straight into `requests.get(url)`. NVD verbatim: *"This manipulation of the argument url causes
server-side request forgery. The attack may be initiated remotely. The exploit has been
published."* WHO reaches it: any MCP client authorized to call the tool. WHAT privilege: an
outbound HTTP request issued with the server's own network position (past any perimeter
firewall). TO WHAT EFFECT: internal service reconnaissance, cloud metadata credential theft, or
using the server as an open relay.

**Rule B — MCP-config destination SSRF, two real CVEs sharing one shape:**
- **CVE-2026-85666** (OGX / ex-Llama Stack, HIGH 7.5): MCP tool definitions accept a
  `server_url` parameter that is fetched server-side without destination validation — *the
  existing `validate_url_not_private()` guard used for other URL inputs is not applied to
  `server_url` specifically*. The guard exists. It is called. It is simply not called on this
  one input — a within-file inconsistency, not an absent control.
- **CVE-2026-86122** (Rowboat, MEDIUM 5.0): NVD — Rowboat "fails to validate custom MCP server
  and webhook URLs." No guard exists anywhere for this destination.

WHO reaches Rule B: whoever can register or edit an MCP server/webhook entry. WHAT privilege:
same server-side-fetch primitive as Rule A, sourced from configuration instead of a live tool
call. TO WHAT EFFECT: identical — internal reconnaissance, metadata credential theft, exfil relay.
Standards: OWASP:A10 (SSRF), CWE-918, OWASP-ASI:ASI04 (Agentic Supply Chain Vulnerabilities — an
MCP config value an attacker can influence becomes an SSRF primitive).

## Why it's often introduced / Why this guard fits the stack

`ssrf-general` already catches the classic shapes (an f-string URL, string concatenation, a
`request.`-object argument) — but it deliberately does NOT fire on a bare-variable *whole* URL
argument (`requests.get(url)`), because in ordinary backend code that pattern is common and
mostly benign (a URL built and validated several lines earlier, then passed through). Confirmed
directly from `ssrf-general`'s own docstring before building this guard, per this project's
verification discipline — not assumed. MCP tool handlers are a narrower, higher-risk context
where that same bare-variable shape is exactly the vulnerable one: the "several lines earlier"
validation the general guard is being lenient about often simply doesn't exist, because the
parameter arrived straight from the MCP client with no intermediate processing at all.

```python
@mcp.tool()
def fetch_page(url: str) -> str:      # url is whatever the calling MCP client sent
    return requests.get(url).text     # no allow-list, no scheme/host check
```

The config-destination case (Rule B) is introduced differently: a developer builds a generic
`validate_url_not_private()` helper, applies it carefully to the URL inputs they were thinking
about when writing the function, and simply doesn't notice that `server_url` — often added later,
or handled by a different code path in the same module — never gets routed through it.

## Detection design

1. **`applies()` gate:** `"mcp" in profile.features`.
2. **File-level MCP-context gate (`_MCP_HINT_RE`):** the file must reference `@mcp.tool`,
   `FastMCP`, `McpServer`, `modelcontextprotocol`, a bare `@tool`, `from mcp`/`import mcp`, or
   `mcpServers` — verbatim from the real source. Keeps the guard from firing on unrelated
   general-purpose HTTP client code.
3. **Files scanned:** `python_scan_dirs(root, profile)` + `iter_files(d, (".py",))`, same as
   the guard's siblings. Python-only in v1 (see Known bypasses).
4. **AST parsing:** `safe_ast_parse()` (the project's shared total-parse helper); a file that
   fails to parse is skipped entirely, same fail-safe convention every AST-based guard follows.
5. **Rule A — `mcp-ssrf-unvalidated-destination/tool-arg-url` (HIGH):**
   - Walks every `FunctionDef`/`AsyncFunctionDef` whose decorator list matches
     `_is_mcp_tool_decorator` (`@mcp.tool`, `@server.tool`, `@app.tool`, `@fastmcp.tool`, the
     bare `@tool` name, or an `add_tool` attribute call — the same decorator-recognition helper
     the `code_injection_eval_exec.py` already carries, reused here).
   - Seeds taint from parameters whose name matches `_URL_ARG_RE` (`url`/`uri`/`endpoint`/
     `target`/`link`/`href`/`webhook`/`callback`, or a `*_url`/etc. variant, verbatim from the
     real source).
   - `_collect_tainted()` propagates the seed through simple same-function assignments (a
     bounded 6-pass fixed point, mirroring the real source's own taint-propagation loop) — a
     `resolved = url` alias is still recognized as tainted.
   - Fires if a tainted name reaches a fetch-sink call (`requests`/`httpx`/`urllib`/`aiohttp`,
     `_is_fetch_sink`) AND the function's own unparsed source does not match `_GUARD_RE`
     (allow-list/validation marker vocabulary — verbatim from the real source).
6. **Rule B — `mcp-ssrf-unvalidated-destination/config-destination` (HIGH):**
   - Walks every `Call` in the WHOLE module (not scoped to a tool handler — the config
     destination may be read anywhere) that is a fetch sink.
   - For each fetch call's arguments, walks the argument expression for a `Name` or
     `Attribute` whose identifier matches `_DEST_TOKENS` (`server_url`, `mcp_server_url`,
     `webhook_url`, `callback_url`, `endpoint_url`, `upstream_url`, `remote_url`, `target_url`,
     `server_uri`, `webhook_uri`, `endpoint_uri`, `sse_url` — verbatim from the real source).
   - Fires if the MODULE's own unparsed source does not match `_GUARD_RE` anywhere — a
     module-wide check, not scoped to the containing function, matching the real source's own
     "does this module guard ANYTHING" design.
7. **Guard-marker vocabulary (`_GUARD_RE`), shared by both rules:** `ALLOWED_HOSTS`/
   `allowed_hosts`/`allowlist`/`allow_list`/`urlparse`/`is_private`/`ip_address`/`ip_network`/a
   `scheme`/`netloc`/`hostname` membership check/`startswith("https`/`validate_url`/`ssrf`/
   `is_safe_url`/`check_url`/`deny` — verbatim from the real source.
8. **Inline opt-out pragma:** `# security: allow-mcp-ssrf-unvalidated-destination`, file-level.
9. **Severity/standards:** `high` (matching the real source's HIGH-severity precedent,
   CVE-2026-85666), `["OWASP:A10", "CWE-918", "OWASP-ASI:ASI04"]`.

## Deliberate simplification vs. the real source (disclosed)

The real `mcp_destination_guard.py` distinguishes **Arm A** (asymmetry — the module guards
*some* destinations but not this one, a stronger signal) from **Arm B** (absence — no guard
exists anywhere) by importing a shared guard-function-recognition helper (`_guard_functions`/
`_is_validator_name`) from a sibling scanner (`ssrf_toctou.py`) that has no equivalent in
agentsec. This guard collapses both sub-cases into one check — "does the module's own text match
`_GUARD_RE` anywhere" — rather than tracking which SPECIFIC identifiers are guarded vs. not. Both
real CVEs (85666's asymmetry, 86122's absence) still fire correctly under this simplification;
what's lost is the more precise "guarded-elsewhere-but-not-here" distinction in the finding
message. Disclosed rather than silently narrowed.

`base_url` is deliberately excluded from `_DEST_TOKENS`, per the real source's own documented
lesson: it fired on `tests/fixtures/cves/cve-2026-73498-mcp-atlassian/negative/attachments.py`
during the real source's own self-scan — a fixture whose whole job is to be clean — because
`base_url` in an API client is typically the service's own fixed address, configured once and
not steerable by a caller, the opposite of what this rule is about. Dropped rather than
special-cased, since the real source found every API client in its corpus has one.

## When NOT to flag

- **No MCP-context marker in the file** — the file-level gate exists exactly for this.
- **A non-URL-shaped tool parameter** (`query`, `text`, `path`) reaching a fetch sink — Rule A
  only seeds taint from URL-shaped parameter names.
- **A plain (non-`@mcp.tool`) function** with a `url` parameter reaching a fetch sink — Rule A
  is scoped to MCP tool handlers specifically; a generic internal helper is out of scope (closer
  general coverage is `ssrf-general`/`agent-tool-url-fetch-ssrf`).
- **A guard marker present anywhere in the relevant scope** (the function for Rule A, the whole
  module for Rule B) — `urlparse`/`ALLOWED_HOSTS`/`validate_url`/etc.
- **`base_url`** as a destination name — deliberately excluded (see above).
- An audited, intentional case suppressed with the inline pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_mcp_tool_url_param_to_requests_get` | Rule A fires on an `@mcp.tool` handler's `url` param → `requests.get()` — CVE-2026-14748's own shape |
| `test_fires_on_webhook_param_via_httpx` | Rule A fires on a `webhook`-shaped param via `httpx.post()` |
| `test_tool_arg_guarded_is_safe` | FP-bait: a handler that validates via `urlparse`/`ALLOWED_HOSTS` before fetching stays silent |
| `test_non_url_shaped_param_is_safe` | FP-bait: a non-URL-shaped param (`query`) reaching a fetch sink stays silent |
| `test_non_mcp_tool_function_is_safe` | FP-bait: a plain (non-decorated) function stays silent |
| `test_fires_on_server_url_config_destination` | Rule B fires on `cfg['server_url']` reaching `requests.get()` with no guard in the module |
| `test_fires_on_webhook_url_config_destination` | Rule B fires on `webhook_url` too |
| `test_config_destination_guarded_elsewhere_in_module_is_safe` | FP-bait: any recognized guard marker anywhere in the module silences Rule B |
| `test_base_url_config_destination_is_safe` | FP-bait: `base_url` is deliberately not a recognized destination token |
| `test_no_mcp_context_is_safe` | FP-bait: no MCP-context marker in the file stays silent |
| `test_pragma_suppresses_finding` | the inline pragma silences the finding |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` is False without the `mcp` feature |
| `test_guard_applicable_with_mcp_feature` | `applies()` is True with the `mcp` feature |
| `test_nonproduct_path_skipped` | files under `tests/fixtures/` are skipped |

## Known bypasses

- **Python-only in v1.** The real source's TS/JS/Rust regex-fallback arm (comment-stripped
  regex matching a URL-shaped argument passed to `fetch`/`axios`/`got`/`reqwest`) is not
  ported — a Node.js or Rust MCP server with either vulnerable shape gets no coverage from this
  guard.
- **Collapsed asymmetry/absence distinction (Rule B)** — see "Deliberate simplification" above;
  both real CVEs still fire, but the finding does not distinguish "guarded elsewhere, not here"
  from "no guard anywhere."
- **Module-wide guard recognition (Rule B) is a text-presence check, not a call-graph proof** —
  a `validate_url` FUNCTION DEFINITION that exists but is never actually called anywhere in the
  module still silences the finding, since the check is `_GUARD_RE.search()` on the whole
  unparsed module source, not a proof the guard is applied to the specific destination. Same
  known limitation the real source itself carries and the project's other allow-list-marker
  guards (`agent-tool-url-fetch-ssrf`) already document.
- **Unlisted destination/parameter names** — both `_URL_ARG_RE` and `_DEST_TOKENS` are curated;
  an unusually-named parameter or config key not matching either set gets no coverage.
- **Cross-function/cross-file taint** — Rule A's taint propagation is same-function only (a
  6-pass fixed point over direct assignments); a value passed through a helper function before
  reaching the fetch sink is not tracked.
- **Multi-language / dynamic dispatch** — an indirect call (`getattr(requests, "get")(url)`) is
  not recognized as a fetch sink.

## What this guard does NOT prove

- That a recognized guard marker actually validates the SPECIFIC destination this guard flagged
  — see the module-wide text-presence limitation above.
- That the destination, once allow-listed, is checked against RFC-1918/link-local/metadata IP
  ranges as well as hostname — this guard only proves a guard MARKER is present, not that it is
  a complete SSRF defense.
- That a destination arriving through a channel other than a decorated tool-handler parameter or
  a curated config-key name (e.g. a nested dict value under an unlisted key) is safe — absence of
  a finding is not proof of absence of the vulnerability.

# Citations

[1] agentsec checklist item `4-mcp-ssrf-unvalidated-destination` (§4)
[2] CWE-918
[3] OWASP:A10
[4] OWASP-ASI:ASI04
[5] CVE-2026-14748 (AIAnytime Awesome-MCP-Server, mcp-wiki tool-arg SSRF, CVSS 6.3)
[6] CVE-2026-85666 (OGX / ex-Llama Stack, MCP config-destination asymmetry, CVSS 7.5)
[7] CVE-2026-86122 (Rowboat, MCP/webhook URL validation absence, CVSS 5.0)
[8] agent-audit-kit (sattyamjjain/agent-audit-kit), `mcp_ssrf_toolarg.py` + `mcp_destination_guard.py`
