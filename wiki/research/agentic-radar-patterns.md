---
type: Research
title: agentic-radar (SplxAI) — Agent Tool SSRF Patterns
description: A statically-detectable SSRF pattern sourced from agentic-radar's agent-tool vulnerability registry, covering WebBaseLoader wrapped as an agent-callable tool with a non-literal URL.
tags: [research, ssrf, agent-tools, langchain]
timestamp: "2026-07-12T00:00:00Z"
---

# agentic-radar (SplxAI) — Agent Tool SSRF Patterns

## What this covers

agentic-radar is an agent-framework static analyzer that maps agent architectures (LangChain,
CrewAI, and similar frameworks) and catalogues known-risky tool classes against a structured
vulnerability registry, keyed by exact tool name rather than a generic code pattern. The
pattern below is sourced directly from that registry's entry for `WebBaseLoader`.

## A safe ingestion tool becomes an SSRF primitive once the URL is agent-controlled

`WebBaseLoader` (LangChain's standard web-page loader for RAG pipelines) issues a server-side
HTTP GET against whatever URL it is constructed with. Used inside a fixed ingestion script
with a hardcoded URL, this is an ordinary, safe pattern — the developer chose the URL, once,
at write time. The risk appears the moment the same loader is wrapped as an agent-callable
tool (a `@tool`-decorated function, a `Tool(name=...)` registration, a `StructuredTool.
from_function(...)` call, or a `BaseTool` subclass) and the URL it fetches becomes a tool
parameter or any other value the LLM controls at call time — a prompt injection (from a
retrieved document, a user message, or a poisoned tool result) can then instruct the agent to
fetch an internal service, the cloud metadata endpoint (`http://169.254.169.254/`), or encode
sensitive data into an attacker-controlled host's URL for exfiltration. agentic-radar's own
vulnerability registry tags exactly this tool by name, with both "Unrestricted External Access
leading to SSRF" and "Data Exfiltration" categories.

## The same tool, two different risk profiles, indistinguishable by class alone

Because the risk lives entirely in *who controls the URL argument*, not in the tool class
itself, a detector must distinguish a literal-URL call (`WebBaseLoader("https://docs.example.
com/page")` — safe, regardless of whether it sits inside a tool wrapper) from a non-literal
one (a bare variable, an f-string interpolation, or any other value that isn't a pure string
literal). A detector that flags every `WebBaseLoader` construction inside a tool-registration
context, without checking whether the URL argument is actually dynamic, would over-fire on the
overwhelmingly common safe case of a tool that only ever loads a small, developer-chosen set
of known documentation pages.

## An allowlist marker is a real mitigating signal, with a real limit

A file containing an explicit domain allowlist/validation marker (`allowed_domains`,
`allowlist`, `ALLOWED_HOSTS`, `validate_url`, `urlparse`+`netloc` inspection, etc.) is a
meaningfully lower-risk case than one with no validation signal at all — a domain check may
gate the fetch before it reaches an internal host or the metadata endpoint. The limit worth
naming: a whole-file textual presence check for such a marker cannot prove the marker is
actually wired into the control flow that gates the specific fetch call — an unused allowlist
constant declared elsewhere in the same file would still read as "mitigated" under a
presence-only check. This is a known, accepted trade-off of static analysis without a real
data/control-flow graph, not a design flaw unique to this pattern.

## Citations

- [splx-ai/agentic-radar](https://github.com/splx-ai/agentic-radar) — `agentic_radar/mapper/vulnerabilities.json`'s `WebBaseLoader` entry (fetched and read directly).
