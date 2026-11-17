---
type: Guard
title: "mcp-transport-dns-rebinding"
description: "MCP StreamableHTTP transport exposed with no Host-header allow-list (DNS-rebinding protection)."
timestamp: "2026-09-21T18:00:00Z"
guard_id: "mcp-transport-dns-rebinding"
checklist_section: ["4"]
standards: ["OWASP:A01", "OWASP-ASI:ASI04"]
---

# MCP StreamableHTTP transport exposed with no DNS-rebinding Host-header allow-list

_Author — 2026-09-21_

---

## The threat

A malicious web page a victim visits in their browser can make the victim's own browser send a
request to a domain whose DNS record resolves to `127.0.0.1` — but only *after* the browser's
same-origin check already passed against the attacker's own domain (DNS rebinding). If a local MCP
server trusts whatever `Host` header that request carries, rather than validating it against an
allow-list, the request reaches the server indistinguishably from a legitimate local client —
CWE-350, practically a same-origin-policy bypass onto a loopback service with full tool access.

WHO reaches this: any web page the victim's browser visits, no MCP-level credential needed at all —
the attack lives entirely in DNS + browser same-origin timing.
WHAT privilege: every capability the server's tools expose.
TO WHAT EFFECT: unauthenticated (from the MCP server's point of view, "local," so often not gated by
`mcp-transport-no-auth`'s own concern at all) remote tool invocation from an attacker-controlled web
page. Standards: OWASP:A01 (Broken Access Control), OWASP-ASI:ASI04 (Agentic Supply Chain
Vulnerabilities).

Anchors a real CVE cluster found and verified during this project's own MCP-server research effort:
CVE-2025-66414 / CVE-2025-66416 (Python SDK `mcp` before 1.23.0), CVE-2026-35568 (Java
`io.modelcontextprotocol.sdk:mcp-core` before 0.11.0), CVE-2026-35577 (`@apollo/mcp-server` before
1.7.0), and **CVE-2026-81102** — the Dash MCP server, reached through the Python **FastMCP**
wrapper: it bound its listener to loopback and never checked the `Host` a request named, so a
rebound name still reached it. Binding to loopback was not the control — the Host allow-list is.

## Why it's often introduced / relationship to the sibling `mcp-transport-no-auth` guard

Checked agentsec's own coverage before building anything (per this project's own lesson).
Two things were already true:

1. `agentsec/guards/version_floors.json` already floors `mcp` (pip) at `>= 1.28.1`, well above the
   `1.23.0` DNS-rebinding fix (Batch 0/A of this same build queue) — so **upgrading the SDK is
   already checked** by the existing generic `dependency-version-floor` guard.
2. The sibling guard `mcp-transport-no-auth` already flags a missing authentication marker on the
   same class of transport.

Neither closes this gap. The SDK's 1.23.0 fix *added* an opt-in `TransportSecuritySettings`
allow-list — it did not turn protection on by default. An app can run the latest SDK version, have
solid bearer-token auth wired (satisfying the sibling guard), and still be reachable via DNS
rebinding if it never actually passes `allowed_hosts=`/wires `TrustedHostMiddleware`. Auth and
Host-header validation are different controls answering different questions ("who is asking" vs "is
this request's stated origin real"), and DNS rebinding specifically defeats the "it's local, no auth
needed" assumption *before* any auth check the app does run:

```python
# Upgraded the SDK, added bearer-token auth on every tool call -- looks fully hardened.
app = FastMCP("my-tools")

@app.middleware
def require_bearer(request, call_next):
    ...  # a real, working auth check

# But: never configured TransportSecuritySettings / TrustedHostMiddleware. A DNS-rebound
# request still reaches this line and still carries a *valid* bearer token, because the
# attacker's page relayed the victim's own already-authenticated session.
app.run(transport="streamable-http", host="127.0.0.1", port=8080)
```

## Detection design

Ported from `agent-audit-kit`'s `AAK-DNS-REBIND-001` pattern-check (fetched and read in full; its
sibling pin-check, `AAK-DNS-REBIND-002`, is deliberately not built here — already covered by
`dependency-version-floor`, see above).

1. **`applies()` gate:** `"mcp" in profile.features and "python" in profile.features`.
2. **Files scanned:** `python_scan_dirs(root, profile)` + `iter_files(d, (".py",))`. Every file
   is read for the allow-list marker (step 4); `is_nonproduct_path` only bounds which files can
   anchor a finding, per CLAUDE.md rule 4.
3. **Transport signal, per file:** the raw SDK classes (`StreamableHTTPSessionManager`,
   `StreamableHTTPServerTransport`), or a `FastMCP(` construction that also, anywhere in the same
   file, selects a network transport (`transport="streamable-http"`/`"sse"`/`"http"` — hyphenated,
   since FastMCP's own literal never uses the underscore form — or `.streamable_http_app(`/
   `.sse_app(`/`run_streamable_http_async(`/`run_sse_async(`). A bare `FastMCP(...)` with no network
   transport selected (stdio, the SDK's own default) does not fire. Matched on code only: comments
   are stripped and every string literal (triple-quoted and single-line) is blanked, so an import,
   a comment or a string that names the class does not fire. The one exception is the
   `transport="..."` selector, which needs its string value, so it reads the strings but its match
   must start in code.
4. **Suppression is PROJECT-WIDE, not per-file:** a Host-allow-list marker
   (`TrustedHostMiddleware`, `allowed_hosts=`, `ALLOWED_HOSTS`, `HostHeaderFilter`,
   `host_allow_list`) anywhere in the scanned tree suppresses every candidate file — real projects
   often wire the middleware in one place while the transport is constructed in another (mirrors the
   source's own documented design). The marker must be code: a string that only mentions it, such
   as `DOC = "see allowed_hosts= for config"`, does not suppress. Before the PR #917 re-review it
   did, and one incidental string anywhere in the project silenced every real CRITICAL. A string
   whose whole value names a marker still counts, because it is a reference rather than prose:
   a settings key (`{'ALLOWED_HOSTS': ...}`), a prefixed env-var name
   (`os.environ['MCP_ALLOWED_HOSTS']`) or a dotted middleware path
   (`'starlette.middleware.trustedhost.TrustedHostMiddleware'`). The marker must end the value:
   `'ALLOWED_HOSTS_NOT_SET'` (a log key warning that the allow-list is missing) does not count.
5. **Deliberately NOT an exemption:** an explicit loopback bind (`host="127.0.0.1"`). This is the
   one detail where this guard's behavior differs from its sibling `mcp-transport-no-auth`, which
   *does* treat loopback as safe — DNS rebinding is specifically the attack that defeats that
   assumption (CVE-2026-81102).
6. **Inline opt-out pragma:** `# security: allow-mcp-dns-rebinding`, checked per file.
7. **Severity/standards:** `critical`, `["OWASP:A01", "OWASP-ASI:ASI04"]`. Rule id:
   `mcp-transport-dns-rebinding/no-host-allowlist`.

## When NOT to flag

- **stdio-only servers** — no listener to rebind onto; a network transport must be selected
  explicitly.
- **A Host-allow-list marker anywhere in the scanned project** — even in a different file from the
  transport construction.
- **Python-only in this v1** — TS/Java/Rust SDKs use a structurally different code shape, not
  scanned here (matches every sibling MCP guard's own first-pass scope boundary).

Use the pragma `# security: allow-mcp-dns-rebinding` for an audited, intentional case (e.g. a
network-layer control this guard cannot see from source alone actually enforces the same property).

## Tests

| Test | What it checks |
|---|---|
| `test_flags_raw_streamable_http_transport_no_allowlist` | raw SDK `StreamableHTTPServerTransport`, no allow-list — fires |
| `test_flags_fastmcp_streamable_http_string_transport` | `FastMCP` + `transport='streamable-http'` — fires |
| `test_flags_fastmcp_even_with_explicit_loopback_bind` | `host='127.0.0.1'` present — still fires (CVE-2026-81102 shape, unlike the sibling guard) |
| `test_fastmcp_stdio_default_does_not_fire` | FP-bait: `FastMCP` constructed, `.run()` with no network transport — silent |
| `test_stays_silent_with_host_allowlist_in_same_file` | FP-bait: `TrustedHostMiddleware` present — silent |
| `test_stays_silent_with_host_allowlist_in_a_different_file` | FP-bait: project-wide suppression across 2 files — silent |
| `test_non_mcp_streamable_http_reference_does_not_fire` | FP-bait: `sse_app` mentioned only in a comment, no real FastMCP construction — silent |
| `test_stays_silent_with_host_allowlist_only_in_examples_dir` | FP-bait: the allow-list lives only in `examples/`, which the mitigation scan still reads: silent |
| `test_unmitigated_transport_inside_examples_dir_does_not_fire` | a transport inside `examples/` never anchors a finding: silent |
| `test_bare_import_of_streamable_transport_does_not_fire` | FP-bait: the class imported, never constructed: silent |
| `test_comment_mentioning_streamable_transport_with_call_syntax_does_not_fire` | FP-bait: `ClassName()` inside a `#` comment: silent |
| `test_docstring_mentioning_streamable_transport_does_not_fire` | FP-bait: `ClassName()` inside a docstring: silent |
| `test_allowlist_marker_only_in_a_string_does_not_suppress` | an allow-list marker only inside a string (prose, f-string, or a key that merely contains one, such as `'ALLOWED_HOSTS_NOT_SET'`) in another file: still fires |
| `test_allowlist_wired_through_a_string_key_still_suppresses` | FP-bait: an allow-list wired through a settings-dict key, a dotted middleware path, a prefixed env-var name, or a kwarg beside a string: silent |
| `test_single_line_string_mentioning_streamable_transport_does_not_fire` | FP-bait: `"StreamableHTTPServerTransport() was the old way"`: silent |
| `test_fastmcp_network_selector_only_in_a_string_does_not_fire` | FP-bait: real `FastMCP(`, but `transport='sse'` appears only in a help string: silent |
| `test_fastmcp_constructor_only_in_a_string_does_not_fire` | FP-bait: `FastMCP(` appears only in a string: silent |
| `test_real_transport_after_a_string_mention_anchors_on_the_real_line` | a string that spells the same text comes first; the finding anchors on the real call: fires |
| `test_pragma_suppresses_finding` | the inline pragma silences the finding |
| `test_applies_requires_mcp_and_python_features` | `applies()` gate — both `mcp` and `python` required |

## Known bypasses

- **JS/TS/Java/Rust SDK servers are not covered.** Python-only in this v1.
- **Whole-project marker check, not a real containment proof** — same limitation as the sibling
  `mcp-transport-no-auth` guard: a `TrustedHostMiddleware` import present but misconfigured (e.g.
  `allowed_hosts=["*"]`, which defeats the whole point) still silences this guard. The same holds
  for a string whose whole value names a marker: `{'ALLOWED_HOSTS': ...}` counts as a reference,
  so `getattr(settings, 'ALLOWED_HOSTS', None)`, or any `'ALLOWED_HOSTS'` string that wires
  nothing, also silences it (the same as a bare `settings.ALLOWED_HOSTS` in code). Prose that
  mentions a marker (`"see allowed_hosts= for config"`) and a key that merely contains one
  (`'ALLOWED_HOSTS_NOT_SET'`) do not.
- **`validate_host`/`validateHost` deliberately excluded from the marker vocabulary**, unlike the
  real source rule this was ported from — a demonstrated collision, not a hypothetical one:
  agentsec's own `ssrf_ipv6_bypass.py` canary plant defines an unrelated `validate_host(host: str)`
  function for a completely different purpose, which would have falsely suppressed this guard in the
  combined canary tree. A real project that names its own Host-validation function `validate_host`
  and nothing else gets no signal from this guard for that reason.

## What this guard does NOT prove

- That a present allow-list marker is *correctly configured* — `allowed_hosts=["*"]` or an empty/
  permissive `TrustedHostMiddleware` wiring silences this guard exactly like a real one would.
- That the underlying deployment has network-layer protections this guard cannot see from source
  alone (a firewall, a VPN) — legitimate reasons to use the pragma, not gaps this guard claims to
  close.

# Citations

[1] agentsec checklist item `4-mcp-transport-dns-rebinding` (§4)
[2] OWASP:A01, OWASP-ASI:ASI04, CWE-350
[3] CVE-2025-66414 / CVE-2025-66416 (Python SDK `mcp`)
[4] CVE-2026-35568 (Java `io.modelcontextprotocol.sdk:mcp-core`)
[5] CVE-2026-35577 (`@apollo/mcp-server`)
[6] CVE-2026-81102 (Dash MCP server, via the FastMCP wrapper)
[7] agent-audit-kit `AAK-DNS-REBIND-001` (sattyamjjain/agent-audit-kit)
