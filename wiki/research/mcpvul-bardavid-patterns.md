---
type: Research
title: MCPVul — Tool-Poisoning and MCP Session/Auth-Flow Patterns
description: Statically-detectable MCP tool-description-poisoning, upstream-data-sanitization, session-identity, and OAuth-launch patterns distilled from a Python MCP static-analysis pipeline, mapped to agentsec coverage.
tags: [research, mcp, tool-poisoning, prompt-injection, session-security, oauth]
status: stable
generated: { by: agent:research-cycle, at: 2026-10-09T00:00:00Z }
stale_after: 2027-01-07
---

# MCPVul — Tool-Poisoning and MCP Session/Auth-Flow Patterns

## What this covers

A Python-based MCP static analysis pipeline (AST taint propagation, cross-file dataflow, a
declarative pattern catalog) contributed patterns across two existing agentsec detection
surfaces and two new ones: tool-description poisoning markers, non-JSON upstream-data
sanitization gaps, MCP session identifier weaknesses, and unsafe OAuth authorization-URL launch.
Pure reference — no tool-specific or process details.

## Tool-description poisoning: eight high-risk markers

Beyond plaintext directive language (which agentsec already detected across several categories
— role-redefinition, cross-tool directives, covert-transfer admissions), eight narrower
shapes. Two are structural carriers with no legitimate benign reading (CRITICAL). The other
six are keyword/phrase heuristics over free text, which keep a residual false-positive rate (for
example a legitimate "please run sudo -n to check permissions"), so agentsec reports them as
MEDIUM review signals rather than gating findings:

| Pattern | What it catches | Severity |
|---|---|---|
| Invisible/bidi Unicode in metadata | Zero-width/RTL-override control characters in a tool description — a steganographic carrier | CRITICAL |
| HTML-hidden instruction | A directive inside an HTML comment within the description (`<!-- ignore previous instructions -->`) | CRITICAL |
| Bracketed instruction marker | `[Important]`/`[System]`/`[Instruction]`/`[Hidden]`/`[Internal]` — makes injected text read as a privileged annotation | MEDIUM (surfacing) |
| Mandatory shell command | The description mandates execution of a literal shell command as a prerequisite/follow-up | MEDIUM (surfacing) |
| User-intent override | The description claims precedence over the user's own request ("regardless of the user's request") | MEDIUM (surfacing) |
| Quoted cross-tool prerequisite | A mandate naming a specific, quoted tool literal ("you must call 'read_file'") | MEDIUM (surfacing) |
| Forced argument change | The description coerces an automatic/silent change to an argument or request | MEDIUM (surfacing) |
| Preference manipulation | The description claims the tool should be preferred/prioritized over others | MEDIUM (surfacing) |

**Why these and not a broader vocabulary:** generic forms of several of these (bare "override"/
"ignore", any URL mention, any "execute the command" phrasing, any "tools" mention) were
deliberately excluded — they are strictly broader/noisier versions of patterns already covered
more precisely elsewhere, and several rounds of prior FP-narrowing on the sibling plaintext-
directive rules already established why the broad forms don't hold up.

## Confusable (homoglyph) tool-name detection: NFKC does not help

A duplicate MCP tool name declared in two different files is a known trust-boundary risk (a
second, compromised definition can shadow the trusted one). The natural extension — catching a
HOMOGLYPH-substituted duplicate, not just a byte-identical one — has a common implementation
mistake worth naming: **Unicode NFKC normalization does not merge cross-script confusables.**

```python
import unicodedata
unicodedata.normalize("NFKC", "sync_wоrkspace")  # Cyrillic о (U+043E)
# -> 'sync_wорkspace' (unchanged) -- NOT 'sync_workspace'
```

NFKC only merges *compatibility-equivalent* forms within a script (full-width variants,
ligatures, combining-mark compositions) — it was never designed to resolve visual confusables
across scripts. Detecting a Cyrillic/Greek lookalike requires either a Unicode confusables table
(IDN TR39's skeleton algorithm) or, more cheaply, a **structural skeleton-pair comparison**: two
strings of equal length that differ only at positions where one side is a plain ASCII Latin
letter and the other is a codepoint from a vetted confusable set. The latter avoids needing a
full confusables table while still being provably safe against false positives (two ordinary
ASCII names that happen to share a length never match, since neither side of an ASCII/ASCII
mismatch is ever in the confusable set).

## Non-JSON upstream-data sanitization gaps

A tool-function-scoped sink pattern distinct from `.json()`-chain validation: an LLM/agent tool
function (`@tool`-decorated) that returns raw external data through a non-JSON sink, with no
sanitization call anywhere in the function:

| Sink | Example |
|---|---|
| HTTP raw text/content | `requests.get(url).text` (no `.json()` — the existing JSON-chain check never anchors) |
| `urllib` raw read | `urllib.request.urlopen(url).read()` |
| File raw read | `open(path).read()` |
| Subprocess raw output | `subprocess.run(cmd, capture_output=True).stdout` |
| DB raw fetch | `cursor.fetchall()` |

**Why tool-scoped, not "anywhere in the codebase":** an ordinary backend helper that returns raw
file/HTTP/subprocess/DB content for conventional use is completely normal. The risk — poisoned
upstream content landing unsanitized in the model's tool-result context — only exists once that
raw value becomes an agent tool's return value. Gating on the tool-decorator shape keeps the
pattern precise.

## MCP session identifier weaknesses

Two session-identity failure modes, distinct from protocol-version compliance (whether code
still depends on the pre-stateless-spec session header):

1. **Predictable or client-supplied session IDs.** `uuid.uuid1()` derives its value from the
   host's MAC address and the current timestamp — not cryptographically random. A server that
   lets the client choose the ID of a new session is worse, but reading the client's ID back
   out of a request is the correct streamable-HTTP pattern and looks identical in source, so
   agentsec detects only the predictable-generation half.
2. **Session-ID possession as sole authorization.** `if session_id in sessions:` with no further
   check means stealing or guessing a session ID is a complete login bypass.

## Unsafe OAuth authorization-URL launch

MCP clients commonly open a browser at a dynamically-built OAuth authorization URL. Two launch-
time failure modes:

1. **No scheme validation.** `webbrowser.open(auth_url)`/`os.startfile(auth_url)` with no check
   that the URL is actually `https://` — if any part of the URL is attacker-influenced (a
   redirected discovery document, a malformed callback parameter), a `file://` or `javascript:`
   scheme reaches the OS opener unchecked.
2. **Opened through a shell.** `subprocess.run(f"open {auth_url}", shell=True)` re-invokes a
   shell with the URL embedded in the command line — shell metacharacters become OS command
   injection, not merely an unexpected browser tab.

## Coverage note

This pattern set turned out to overlap heavily with an MCP-security research paper agentsec had
already mined extensively in prior sessions (transport authentication, OAuth flow hardening,
protocol-version migration, session fixation, config-file hardening, supply-chain pinning, audit
logging, SSRF). Most of a larger candidate catalog mapped onto existing, often more rigorous,
coverage — the patterns above are the genuinely novel subset that survived that cross-check.
