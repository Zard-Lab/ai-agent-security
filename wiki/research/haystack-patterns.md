---
type: Research
title: Haystack (deepset) Security Advisories — Agentic Security Patterns
description: Statically-detectable security patterns distilled from Haystack's published CVEs and security policy, extending two existing agentsec guards with precision fixes.
tags: [research, llm, rag, ssti, deserialization, jinja2]
timestamp: "2026-07-03T00:00:00Z"
---

# Haystack (deepset) Security Advisories — Agentic Security Patterns

## What this covers

Haystack is a widely used RAG/pipeline framework with an unusually candid security
policy — it names several behaviors as explicitly unsafe-by-design rather than leaving
them undocumented. This document distills two patterns that turned out to be genuine
precision gaps in *existing* agentsec guards, not new detection surfaces: the underlying
vulnerability classes (SSTI, unsafe deserialization) were already covered, but a
Haystack-specific call shape slipped past the existing detection logic.

## Server-side template injection beyond the Flask idiom

| Pattern | What it catches | Detection |
|---|---|---|
| Raw Jinja2 `Template()`/`.from_string()` construction | A Jinja2 template built directly from a non-literal string — not through Flask's `render_template_string()`, which most SSTI detection assumes is the only entry point. Any code that lets a caller supply and render an arbitrary template has the same RCE exposure. | A `Template(...)` constructor call, or a `.from_string(...)` call on an `Environment`, given a non-literal (f-string, concatenation, or bare variable) argument |

Haystack's own advisory for this pattern is unusually precise: components let a caller
"create and render that template on the client machine" with no framework wrapper in
sight — a reminder that SSTI detection scoped to one framework's helper function name
misses the same vulnerability reached through the underlying templating library
directly.

## Pipeline/config deserialization

| Pattern | What it catches | Detection |
|---|---|---|
| Framework pipeline config loaded from an untrusted source | A pipeline-definition loader that "intentionally supports dynamic imports at runtime" (by the framework's own documentation) executes arbitrary code when the definition comes from anywhere other than a trusted, version-controlled source — the same class of risk as `pickle.loads()` on untrusted bytes, reached through a completely different, framework-specific function name. | A pipeline-loading call (`Pipeline.load`/`.loads`/`.load_from_yaml`) |

This generalizes beyond Haystack: any agentic/RAG framework that supports declarative,
dynamically-importable pipeline or chain configuration (a common extensibility pattern)
likely has the same underlying risk under its own function names.

## What was excluded, and why

Haystack's security policy explicitly rules two other classes out of scope, with clear
reasoning: SSRF via URL-fetching components (intentional design, application/network-
layer responsibility) and prompt injection via document/metadata content (application
responsibility unless a specific defense is bypassed). Both are already agentsec's own
established territory under different, non-Haystack-specific guards, so no new pattern
was extracted from them.
