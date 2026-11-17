---
type: Research
title: Agentic AI Security Patterns — Medusa Reference Audit
description: Statically-detectable AI/agentic security patterns distilled from community open-source SAST research, mapped to agentsec coverage and guard candidates.
tags: [research, mcp, rag, multi-agent, tool-callbacks, dataset-injection, prompt-injection]
timestamp: "2026-06-28T00:00:00Z"
---

# Agentic AI Security Patterns — Medusa Reference Audit

## What this covers

Community SAST tools have published large corpora of AI-specific detection rules. This document
distills the patterns that are relevant to AI/agentic Python apps (FastAPI + LLM/RAG/MCP) and
maps each to agentsec coverage status. Pure reference — no tool-specific details.

## MCP Security Patterns

### Config-level (files: `mcp*.json`, `.mcp.json`, MCP server YAML/TOML)

| Pattern | What it catches | Detection |
|---|---|---|
| Hardcoded secrets in `env:` blocks | API keys in MCP server config | Regex: `"env":\s*\{[^}]*(?:KEY\|TOKEN\|SECRET)` |
| Wildcard filesystem paths | `**`, `/*`, `%SYSTEMROOT%` in `args` | String match in path values |
| HTTP transport without TLS | `"url": "http://` in SSE/WS transports | Scheme check on transport URL |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` | TLS validation disabled | Env var match |
| Untrusted server sources | `.onion`, `ngrok`, raw IP HTTP URLs | Hostname pattern match |
| Missing version pinning (npm) | Rug-pull risk for `@latest` | `"@latest"` in MCP package refs |
| **CVE-2025-6514 (mcp-remote RCE)** | OAuth URL injection in mcp-remote 0.0.5–0.1.15 | Version range check in package.json |
| Missing `destructiveHint`/`readOnlyHint` | Agent has no safe signal before calling tool | Absence check in tool schema `annotations` |

**CVE-2025-6514 detail:** CVSS 9.6 (Critical). The `mcp-remote` npm package versions 0.0.5 through
0.1.15 pass the server-provided `authorization_endpoint` value to the OS `open()` handler without
validation, so a malicious MCP server can achieve **OS command injection / full RCE** on the client
(the first documented RCE against an MCP client; the package has ~437k downloads). Fix: upgrade to
0.1.16+.

### Code-level MCP patterns

- OAuth server anti-patterns: MCP server acting as its own OAuth provider
- Non-localhost binding (`0.0.0.0`) without TLS
- SSE endpoint without TLS

## RAG Security Patterns (AIR-001 through AIR-016)

RAG pipeline security is the richest new category. These patterns apply to any app doing
retrieval-augmented generation.

### Source trust

| ID | Pattern | Detection approach |
|---|---|---|
| AIR-001 | Untrusted doc source — HTTP/FTP/tunnel | URL scheme check on retrieval source |
| AIR-002 | Sanitization disabled in loader | `sanitize=False`, `allow_dangerous_deserialization=True` |
| AIR-003 | Executable code enabled | `eval`/`exec` in document processing pipeline |
| AIR-004 | Mixed trust level documents | Different-origin docs in same retrieval context without isolation |
| AIR-005 | Missing source attribution | Retrieved content added to prompt without provenance tag |

### Embedding and storage

| ID | Pattern | Detection approach |
|---|---|---|
| AIR-006 | Insecure embedding service (HTTP) | HTTP endpoint in embedding config |
| AIR-007 | Vector DB credential exposure | Pinecone/Weaviate/Milvus keys in source |
| AIR-008 | Unsafe chunking | Unlimited chunk size — no `max_chunk_size` |
| AIR-009 | No retrieval filtering | `.similarity_search()` without `k=` limit or score threshold |
| AIR-015 | Multi-tenant isolation disabled | `tenant_isolation: false`; shared namespaces across tenants |

### Active injection patterns

| ID | Pattern | What it is | Detection |
|---|---|---|---|
| AIR-010 | **Knowledge base prompt injection** | `ignore previous instructions` in document being indexed | Regex on JSONL/Markdown content in `rag/`, `corpus/`, `knowledge/` dirs |
| AIR-013 | **Hidden text poisoning** | CSS white-on-white text in HTML docs; zero-width Unicode chars | CSS color match + `​‌‍‎‏﻿` |
| AIR-014 | **Adversarial suffix patterns** | Long Unicode combining mark sequences appended to prompt-injection text | Regex: `[̀-ͯ]{5,}` (Unicode combining range) |
| AIR-016 | **Code-level RAG injection** | User input flows into document ingestion paths | Dataflow pattern: user param → `add_documents()`/`ingest()` |

These three (AIR-010/013/014) are the highest-risk patterns — real attacks confirmed in
academic literature and in production RAG compromises.

## Tool Callback Enforcement (TC-001 through TC-010)

When an LLM calls a tool, the surrounding code must validate inputs, check permissions, and
log actions. Missing callbacks leave tool execution unchecked.

| Pattern | What's missing | Detection |
|---|---|---|
| TC-001 | `before_tool_callback` absent | `@tool`/`execute_tool()` present, no `before_tool_callback` nearby |
| TC-004 | Destructive op without confirmation | `delete`/`drop`/`truncate`/`destroy` + no confirmation wrapper |
| TC-005 | No argument validation | Tool execution without `validate_args()`/`has_permission()` |
| TC-007 | No rate limiting | Tool call loop without rate-limit/throttle |
| TC-010 | No audit logging | Tool execution without any logging of what was called and with what args |

Key FP exclusion: files named `*validator*`, `*permission*`, `*auth*` should be excluded as
they typically define the control itself, not a missing control.

## Prompt Injection Obfuscation

Beyond plain-text injection, attackers use encoding tricks to bypass naive filters:

| Pattern | What it is | Detection |
|---|---|---|
| **Zero-width chars** | `​ ‌ ‍ ‎ ‏ ﻿` in user input paths | Literal byte match in strings passed to LLM |
| **ChatML tokens** | `<|im_start|>` / `<|im_end|>` in user content | String match |
| **Llama control tokens** | `[INST]` / `[/INST]` / `<<SYS>>` in user content | String match |
| **HTML comment injection** | `<!-- ignore previous instructions -->` | HTML comment regex in user input |

These are high-confidence signals — legitimate user input never contains ChatML or Llama tokens.

## Multi-Agent Security (MAG-011 through MAG-015)

In multi-agent pipelines (LangGraph, CrewAI, AutoGen), each agent-to-agent message hop is
an injection risk if the receiving agent treats upstream content as trusted.

| ID | Pattern | Detection |
|---|---|---|
| MAG-011 | **No prompt origin tagging** | Agent output forwarded to next agent without `<from_agent:X>` wrapper or `role: "tool"` boundary |
| MAG-012 | **Cascading prompt without sanitization** | Agent A output directly concatenated into Agent B system prompt |
| MAG-015 | **No auth in agent handoff** | Agent-to-agent call without any identity/auth propagation |

Practical heuristic: in LangGraph, look for `.add_edge(A, B)` where the message passed from A
has no trust-boundary wrapper. In CrewAI, `agent.execute_task(task)` where task came directly
from another agent's `output`.

## Dataset Injection (DSI-001 through DSI-008)

Training datasets and RAG corpora stored as JSONL/CSV files can contain injected instructions
that survive into model fine-tuning or retrieval.

| Pattern | Examples | Where to scan |
|---|---|---|
| Instruction override | `ignore previous instructions`, `disregard your`, `your new instructions are` | JSONL/CSV in `rag/`, `training/`, `corpus/`, `knowledge/`, `documents/` |
| Role manipulation | `you are now`, `act as`, `pretend you are`, `forget you are` | Same dirs |
| Exfiltration directives | URLs in `output`/`response` fields pointing outside expected domains | JSON field values |
| Boundary injection | Strings containing `\n\nHuman:`, `\n\nAssistant:`, `[INST]` in training examples | JSONL training pairs |

Max file size to scan: 2MB per file (bound cost; very large files unlikely to be manually
injected, more likely generated data).

## ML Model RCE Vectors (MA-013/014)

These are code patterns — not config — that allow RCE when loading ML models:

| Pattern | Why it's RCE | Safe alternative |
|---|---|---|
| `torch.load(path)` without `weights_only=True` | Deserializes arbitrary pickle | `torch.load(path, weights_only=True)` |
| `from_pretrained(..., trust_remote_code=True)` | Downloads + executes arbitrary Python | Remove flag or pin to verified revision hash |
| `joblib.load(untrusted_path)` | Deserializes arbitrary pickle | Use safe format (numpy npz, safetensors) |

Note: `torch.load()` with `weights_only=True` is only safe on PyTorch 2.0+.
The `trust_remote_code=True` flag should never appear in production code loading user-controlled
model sources.

## Coverage Summary (agentsec as of 2026-07-03)

Refreshed after the 2026-06-28/29 guard batch merged — several categories that were gaps when this
page was first drafted are now covered.

| Category | agentsec coverage | Gap detail |
|---|---|---|
| MCP config security | Partial | MCP trust + description injection covered (`mcp-config-security`, `mcp-tool-description-injection`); CVE-2025-6514 version check + `destructiveHint`/`readOnlyHint` annotation checks still missing |
| RAG isolation | Partial | `rag-trust-boundary` + `rag-no-instruction-filter` + `rag-isolation` built; AIR-010 covered by `dataset-injection`, AIR-015 by `rag-isolation`; residual: AIR-013 (CSS text-hiding), AIR-014 (adversarial combining marks) |
| Tool callback enforcement | Partial | `tool-callback-enforcement` covers TC-001/004/005 (interrupt gate, destructive-op confirmation, credential-returning tool); residual: TC-007 (rate limit), TC-010 (audit logging) |
| Prompt injection obfuscation | Partial | zero-width chars (U+200B–200F, FEFF) covered by `invisible-unicode`; residual: ChatML (`<\|im_start\|>`) / Llama (`[INST]`) control tokens, HTML-comment injection |
| Multi-agent origin tagging | Partial | `multi-agent-prompt-origin` covers MAG-011 (untagged relay) + MAG-015 (unauth handoff); residual: MAG-012 (cascading concat), CrewAI `execute_task` chaining |
| Dataset injection | Covered | `dataset-injection` scans JSONL/CSV/JSON/TXT/MD in corpus dirs (DSI-001/008 override phrases, VIA-011 trigger-response, AIM009 payload markers) |
| ML model RCE (torch/HF) | Covered | `unsafe-deserialization` detects `torch.load` without `weights_only=True`, `from_pretrained(trust_remote_code=True)`, and `joblib.load` |

## Recommended guard roadmap (priority order)

The 2026-06-28/29 guard batch shipped most of the earlier candidates — `tool-callback-enforcement`,
`multi-agent-prompt-origin`, `dataset-injection`, `rag-isolation`, and the `unsafe-deserialization`
extension (`trust_remote_code` / `torch.load` / `joblib.load`). The remaining candidates:

1. **Extend the MCP guard** — CVE-2025-6514 `mcp-remote` version check + `destructiveHint`/`readOnlyHint` annotation-absence check (½ day)
2. **Extend prompt-injection coverage** — ChatML (`<\|im_start\|>`) / Llama (`[INST]`) control tokens + HTML-comment injection (zero-width chars are already covered by `invisible-unicode`) (½ day)
3. **Close the RAG hidden-text gaps** — AIR-013 (CSS white-on-white) + AIR-014 (adversarial combining-mark suffixes) (1 day)
4. **Extend `tool-callback-enforcement`** — TC-007 (rate limiting) + TC-010 (audit logging) (½ day)
