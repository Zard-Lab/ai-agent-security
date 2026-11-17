---
type: Guard
title: "langchain-serialization"
description: "LangChain unsafe serialization — secrets_from_env=True or langchain-core loads on dynamic content."
timestamp: "2026-06-28T11:57:06+08:00"
guard_id: "langchain-serialization"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM01", "OWASP:A08"]
---

# LangChain unsafe serialization — secrets_from_env=True or langchain-core loads on dynamic content

## Threat

**CVE-2025-68664 (LangGrinch, CVSS 9.3) — LangChain unsafe serialization.**

Two related patterns in the same CVE:

**`secrets_from_env=True`:** When loading a LangChain chain config (`LLMChain.load()`), this flag
tells LangChain to automatically inject environment variables referenced in the config at
deserialisation time. If an attacker can supply the config (e.g., from LLM output, user upload,
or an external data store), they can include references to arbitrary env vars (`$OPENAI_API_KEY`,
`$DATABASE_URL`, etc.) and exfiltrate them as part of normal chain execution.

**`langchain_core.load.loads()` on dynamic content:** This deserialiser reconstructs arbitrary
Python objects from JSON, including function references. Passing LLM output or user-controlled
JSON to `loads()` is equivalent to `pickle.loads()` on untrusted bytes — arbitrary code execution
if the input can be influenced by an attacker.

## Detection design

**Guard structure:** Single guard, two independent sub-rules detected per line:

1. **`secrets-from-env` rule:** detects `secrets_from_env=True` on any line in a file that
   imports from `langchain`. The check is line-level so the finding points directly at the
   offending assignment.

2. **`loads-dynamic-content` rule:** detects `langchain_core.load.loads(` or
   `from langchain_core.load import loads` usage. The import itself is flagged as a signal
   because any use of `loads()` warrants review.

**Import gate matches `langchain_core` too.** The file gate is `\b(?:import\s+langchain|from\s+langchain)`
with NO trailing `\b` — a trailing word boundary would fail between `langchain` and `_core` and gate
out the canonical modern import `from langchain_core.load import loads`, which is exactly the code the
`loads` rule targets. Dropping it was a PR #206 review fix; a `langchain_core`-only file now correctly
satisfies the gate.

**Docstring/comment carve-out.** Lines are scanned after `strip_python_strings()` blanks triple-quoted
strings (preserving line numbers), and comment-only lines (`line.lstrip().startswith("#")`) are skipped.
Without this, a docstring or comment that merely *mentions* `secrets_from_env=True` or `loads` would fire
a CRITICAL finding (which gates CI) — a false positive fixed in the PR #206 review.

**`applies()` gate:** requires `python` in `profile.features`. LangChain-specific gating is done
internally (files are skipped unless they import from `langchain`) — this avoids a false-skip when
`pydantic-ai` is detected first and wins the single `llm_framework` slot in the stack profile.

**Pragma:** `# security: allow-langchain-serialization` at file level suppresses both rules.

## Tests

| Test | Expected |
|---|---|
| `secrets_from_env=True` with langchain import | 1 finding, CRITICAL, secrets-from-env rule |
| `from langchain_core.load import loads` usage | 1 finding, CRITICAL, loads-dynamic-content rule |
| `langchain_core`-only import (no bare `langchain`) | fires — import gate matches `langchain_core` |
| `secrets_from_env=True` in a docstring/comment | silent — strings blanked, comments skipped |
| `secrets_from_env=False` | silent |
| `secrets_from_env=True` without any langchain import | silent |
| `# security: allow-langchain-serialization` pragma | silent |
| `python` not in profile features | `applies()` False |

## Known bypasses / limitations

- `secrets_from_env` set via environment variable or config file (not in code): will not fire.
- Custom deserialisers wrapping `langchain_core.load.loads` under a different name: will not fire.
- Does not detect whether the source of the chain config is actually attacker-controlled — it
  flags all uses of these patterns regardless of data source.

## What this guard does NOT prove

- That the LangChain version is patched (>= 0.3.81 / 1.2.5) — version floor checking is a
  separate concern for `DependencyVersionFloorGuard`.
- That `langchain_core.load.load` (not `loads`) is safe — it also deserialises Python objects.

# Citations

[1] agentsec checklist item `4-langchain-serialization-injection` (§4)
[2] OWASP-LLM:LLM01
[3] OWASP:A08
