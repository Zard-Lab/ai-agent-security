---
type: Guard
title: "mcp-transport-session-unauth"
description: "An MCP HTTP transport authenticates its own outbound credential but never checks an inbound one."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "mcp-transport-session-unauth"
checklist_section: ["4"]
standards: ["OWASP:A07", "OWASP-ASI:ASI04"]
---

# MCP transport authenticates its outbound credential, not its inbound caller

_Author — 2026-09-26_

---

## The threat

CVE-2026-82456 (argocd-mcp, CVSS 10.0): the server reads an operator's Argo CD API token
from the environment and attaches it to requests it sends UPSTREAM to Argo CD. Every naive
reader — including `mcp-transport-no-auth`'s own coarse "any auth marker present" check —
sees `Authorization: Bearer ...` in the file and assumes the server is authenticated. It
is not: nothing there checks who is CALLING the MCP server itself. A caller who sends no
credential at all gets the full tool surface, executed with the operator's own privileges
(`create_application` against an attacker repo, then `sync_application` — arbitrary
manifests applied to the destination cluster). OWASP:A07 (Identification and
Authentication Failures), OWASP-ASI:ASI04 (Agentic Supply Chain Vulnerabilities — the
server's own privileged credential is what makes the missing inbound check exploitable at
all). Sourced from `agent-audit-kit`'s `mcp_transport_session_unauth.py`
(AAK-MCP-TRANSPORT-SESSION-UNAUTH-001), verified against the real repo source.

## Why it's often introduced

An MCP server that proxies to a real backend service naturally needs a credential for
THAT backend — reading it from the environment is the normal, correct pattern. The bug is
never deciding that the MCP server's OWN front door needs a separate, independent check.
Because the environment credential is real and does get used (just outbound, not to gate
inbound callers), a code reviewer skimming for "is there auth here" sees `Authorization`
and moves on.

## Detection design

1. `applies()` gates on `"mcp" in profile.features`.
2. Scans every `.py`/`.ts`/`.tsx`/`.js`/`.mjs`/`.cjs` file (`iter_files`), skipping
   non-product paths; TS/JS comments are stripped before matching.
3. Fires when, in one file: (a) an MCP HTTP transport is present (a `/mcp` route literal,
   or the same `SSEServerTransport`/`StreamableHTTPServerTransport`/`.run(transport=...)`
   markers `mcp-transport-no-auth` recognizes); (b) the transport binds every interface —
   an explicit `0.0.0.0`/`::`/`[::]` literal, or (JS/TS only) a `.listen(port)` call with no
   host argument at all (Python web servers default to loopback, so this inference never
   applies there); and (c) either an inbound header read falls back to an environment
   credential (`req.headers[...] || process.env.X`), or an environment credential is
   demonstrably spent on an outbound `Authorization`/`Bearer` header with no inbound
   per-caller check anywhere in the file (`requireAuth(`, `passport.authenticate(`,
   `verify_jwt(`, `HTTPBearer(`, `Depends(...auth...)`, `enableDnsRebindingProtection: true`,
   ...).
3a. The finding is located at the credential site (`file.ts:<line>`): where the inbound header
   falls back to the environment credential, or where the environment credential is put on
   an outbound `Authorization` header. TS/JS comment stripping keeps newlines, so the line
   is the real one.
4. Inline opt-out: a `# security: allow-mcp-transport-session-unauth` comment (`// security: …` in
   JS/TS) anywhere in the file silences the file (a string literal quoting the phrase does not count, #424).
5. Severity CRITICAL, rule `mcp-transport-session-unauth/decorative-credential`, standards
   `["OWASP:A07", "OWASP-ASI:ASI04"]`.

## When NOT to flag

- A server with a real inbound check present anywhere in the file, even alongside an
  environment credential used outbound.
- A server bound to an explicit loopback host/argument.
- A server with no environment-credential-to-outbound-header pattern at all — that shape
  (no auth marker whatsoever) is `mcp-transport-no-auth`'s scope, not this guard's; the two
  are deliberately disjoint so one defect is reported once.

## Tests

| Test | What it checks |
|---|---|
| `test_decorative_outbound_credential_fires` | Env credential spent outbound, no inbound check — fires |
| `test_header_falls_back_to_env_credential_fires` | Inbound header optional, falls back to env — fires |
| `test_explicit_loopback_bind_is_safe` | Explicit `'localhost'` argument to `.listen()` — silent |
| `test_inbound_auth_marker_present_is_safe` | A real inbound check clears the finding |
| `test_no_env_credential_at_all_is_safe` | No env-credential fallback at all — out of this guard's scope |
| `test_not_an_mcp_http_server_is_safe` | No `/mcp` route or transport marker — irrelevant file |
| `test_outbound_credential_finding_points_at_the_authorization_header`, `test_fallback_finding_points_at_the_header_to_env_fallback_after_block_comments`, `test_two_files_each_report_their_own_line` | Findings carry the credential site's line |
| `test_pragma_suppresses_finding` | Inline pragma silences it |
| `test_mcp_transport_session_unauth_pragma_quoted_in_a_string_does_not_suppress`, `test_mcp_transport_session_unauth_pragma_comment_suppresses_py`, `test_mcp_transport_session_unauth_pragma_quoted_in_a_string_does_not_suppress_ts`, `test_mcp_transport_session_unauth_ts_slash_comment_pragma_suppresses` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6); a `//` comment now opts a JS/TS file out too, and a TS string quoting either form does not |
| `test_python_server_no_implicit_bind_inference` | Python never gets the implicit-bind inference |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` gates correctly |

## Known bypasses

- Single-file scope: an inbound check applied from a separate middleware module the
  transport file itself doesn't reference is invisible to this guard.
- The inbound-auth-marker list is a fixed vocabulary; a bespoke, unusually-named auth
  wrapper with none of the recognized markers would not suppress a genuinely-safe file.
- A credential fallback chain split across multiple statements/variables (rather than one
  `||` expression or one outbound header construction) is not traced.

## What this guard does NOT prove

Silence does not prove the inbound check is *correct* — only that some recognized marker
is present in the file. A broken or trivially-bypassable inbound check (e.g. one that
accepts any non-empty header value) stays silent here; that is a separate defect class.

# Citations

[1] agentsec checklist item `4-mcp-transport-session-unauth` (§4)
[2] CVE-2026-82456 (argocd-mcp, CVSS 10.0), GHSA-rp45-5x3v-48mr
[3] OWASP:A07 — Identification and Authentication Failures
[4] OWASP-ASI:ASI04 — Agentic Supply Chain Vulnerabilities
[5] agent-audit-kit `mcp_transport_session_unauth.py`, rule AAK-MCP-TRANSPORT-SESSION-UNAUTH-001
