---
type: Research
title: LlamaIndex Security Advisories — Agentic Security Patterns
description: Statically-detectable security patterns distilled from LlamaIndex's published CVEs and security policy, mapped to agentsec coverage and guard candidates.
tags: [research, llm, rag, sql-injection, code-execution, tls, tempfile]
timestamp: "2026-07-03T00:00:00Z"
---

# LlamaIndex Security Advisories — Agentic Security Patterns

## What this covers

LlamaIndex is one of the most widely used RAG/agentic frameworks, and has a real
published CVE history. This document distills the patterns that generalize past
LlamaIndex's own codebase into detectable anti-patterns in the FastAPI/LLM-RAG
applications agentsec targets — separating them from bugs internal to LlamaIndex's own
reader/loader implementations, which aren't visible in application code that merely
uses the library.

## LLM-driven query engines that execute directly

| Pattern | What it catches | Detection |
|---|---|---|
| LLM-to-SQL query engine instantiated | A natural-language question is turned into SQL and executed directly against a live database — no traditional injection syntax needed, the LLM itself generates the query. "Drop the Students table" via English input is a real, documented exploit. | Instantiation of a known Text-to-SQL engine class (LlamaIndex's `NLSQLTableQueryEngine`, `SQLTableRetrieverQueryEngine`, `PGVectorSQLQueryEngine`, `JSONalyzeQueryEngine`; LangChain's `SQLDatabaseChain`, `create_sql_agent`) |
| LLM-to-code-execution query engine instantiated | A natural-language question is turned into Python/pandas code and executed directly against live data — arbitrary code execution with no traditional injection syntax. | Instantiation of a known code-execution engine class (LlamaIndex's `PandasQueryEngine`; LangChain's `create_pandas_dataframe_agent`, `PythonREPLTool`, `PALChain`) |

Both are **surfacing** patterns — the class name alone doesn't prove the connection is
unsafely scoped or the execution is unsandboxed, only that the architecture invites
exactly that failure mode if no safeguard is in place. A read-only DB role or a
sandboxed interpreter makes the same class construction safe.

## Outbound connection hygiene

| Pattern | What it catches | Detection |
|---|---|---|
| TLS certificate verification disabled | `requests.get(url, verify=False)` / `httpx.Client(verify=False)` trusts whatever server answers an outbound call with no certificate check — a man-in-the-middle setup on any network path between the app and the destination. | `verify=False` on a `requests`/`httpx` call or client constructor, or a `.verify = False` attribute assignment |
| Insecure temporary file creation | `tempfile.mktemp()` generates a filename without creating the file — a race window exists before the caller opens it, during which another process can create a file at that path first. The Python docs themselves call this a potential security hole. | Any call to the deprecated `tempfile.mktemp()` (the safe alternatives — `mkstemp()`, `NamedTemporaryFile()` — are unaffected) |

Neither pattern is LLM-specific — both are general Python application-security
anti-patterns that happen to show up in LlamaIndex's own documented vulnerability
history and security policy, and apply to any Python codebase making outbound HTTP
calls or creating temporary files.

## What was excluded, and why

Several LlamaIndex CVEs describe bugs internal to the library's own reader/loader
implementations (an unbounded-recursion DoS in a web crawler, a hash-collision data-loss
bug in a document reader, an insecure default cache directory) — these aren't visible or
actionable in *application* code that merely calls the library; a static guard scanning
a user's FastAPI app has no way to see inside LlamaIndex's own source. One advisory
(`eval()` on an LLM-hosting-provider's response) generalizes to a pattern agentsec
already detects independent of any specific framework: a bare `eval()`/`exec()` call fed
non-literal content.
