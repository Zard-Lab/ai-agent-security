---
type: Guard
title: "agent-memory-retention"
description: "Persistent agent memory constructed without a retention TTL."
timestamp: "2026-07-13T02:56:39+02:00"
guard_id: "agent-memory-retention"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM01", "OWASP-LLM:LLM08", "OWASP:A09"]
---

# Persistent agent memory constructed without a retention TTL

_Author — 2026-07-12_

**Guard ID:** `agent-memory-retention`
**Checklist item:** `4-agent-memory-retention`
**Severity:** MEDIUM
**Standards:** OWASP-LLM:LLM01, OWASP-LLM:LLM08, OWASP:A09

---

## The threat

An agent that persists conversation/state memory in a durable store (LangChain
`RedisChatMessageHistory`, LangGraph Redis checkpoint savers) **with no retention TTL** keeps every
written entry forever. Anyone who can write to that memory — a user issuing an indirect
prompt-injection payload, or a compromised upstream document surfaced through RAG — plants content
that never expires. On every future session that draws on the store, the poisoned entry is retrieved
and re-injected into the agent's context: a *stored* prompt injection with unbounded blast radius
across time (OWASP-LLM:LLM01), amplified by the persistence layer (LLM08), and a logging/retention
control failure (OWASP:A09). The Zero-Trust-for-AI-Agents guidance (Phase 7) makes retention limits a
requirement precisely so a single poisoning attempt cannot persist indefinitely.

## Why it's often introduced / Why this guard fits the stack

LangChain's `RedisChatMessageHistory(session_id, url, ttl=None)` defaults `ttl` to `None` — "never
expire." The 9_Agent_SaaS shape (pydantic-ai/langchain agent + Redis-backed session memory) reaches
for the persistent store to survive restarts and share context across a session, and the TTL is easy
to omit because the app "works" without it. The gap is silent: nothing fails, memory just accumulates
forever.

```python
# Bad — keys live forever; a poisoned memory persists into every future session:
history = RedisChatMessageHistory(session_id=sid, url=REDIS_URL)   # ttl defaults to None
```

## Detection design

1. **applies() gate** — `"llm" in profile.features` (a pydantic-ai/langchain stack).
2. **Files scanned** — `python_scan_dirs(root, profile)` → `iter_files(d, (".py",))`, skipping
   `is_nonproduct_path` files. Strings blanked via `strip_python_strings` (docstring examples can't
   false-fire).
3. **Pattern** — `_MEM_CTOR` matches a persistent, TTL-capable memory constructor
   (`RedisChatMessageHistory`, `RedisSaver`, `AsyncRedisSaver`, `RedisStore`, and their `.from_*`
   factories). On a match, a `_WINDOW`=6-line span from the constructor is checked against `_TTL_OK`
   (a real, non-`None` `ttl=` / `ex=` / `px=`, a chained `.expire(...)`, or a named retention kwarg
   like `max_age`/`time_to_live`). Present → skip; absent (or `ttl=None`) → fire. One finding per file.
4. **Pragma** — a `# security: allow-no-memory-retention` comment anywhere in the file silences the file (a
   string literal quoting the phrase does not count, #424).
5. **Emits** — severity `medium`, rule `agent-memory-retention/persistent-memory-no-ttl`, standards
   `["OWASP-LLM:LLM01", "OWASP-LLM:LLM08", "OWASP:A09"]`.

This is a distinct axis from its two sibling guards: `agent-memory-security` keys on TLS /
unsanitized-write / memory→prompt / pickle-integrity; `agent-memory-user-scope` keys on per-user
isolation; this guard keys **only on the retention TTL**.

## When NOT to flag

An intentionally permanent store — a curated knowledge base whose entries should never expire — is a
legitimate no-TTL pattern. That is what the pragma is for. A store that already sets `ttl=<int>`, calls
`.expire(...)`, or writes with `ex=`/`px=` is correctly silent.

## Tests

| Test | What it checks |
|---|---|
| `test_agent_memory_retention_fires` | no-TTL `RedisChatMessageHistory` → one MEDIUM finding, correct rule/severity/standards/location |
| `test_agent_memory_retention_ttl_none_fires` | `ttl=None` (the "never expire" default) still fires |
| `test_agent_memory_retention_fires_once_per_file` | two no-TTL ctors in one file → a single finding |
| `test_agent_memory_retention_silent_with_ttl` | `ttl=86400` → silent |
| `test_agent_memory_retention_silent_ttl_multiline` | `ttl=` on a continuation line of a multi-line ctor → silent |
| `test_agent_memory_retention_silent_chained_expire` | a following `.expire(...)` within the window → silent |
| `test_agent_memory_retention_silent_non_persistent_ctor` | `ConversationBufferMemory()` (out of scope) → silent |
| `test_agent_memory_retention_silent_in_docstring` | ctor shown in a docstring example → silent (strings blanked) |
| `test_agent_memory_retention_trailing_comment_marker_still_fires` | a trailing `# ttl=3600` comment does NOT silence (the #386 fix) |
| `test_agent_memory_retention_following_comment_marker_still_fires` | a `# .expire(...)` comment in the window does NOT silence |
| `test_agent_memory_retention_ttl_var_and_zero_silent` | `ttl=<var>` and `ttl=0` read as configured → silent (mechanism, not value) |
| `test_agent_memory_retention_redis_write_expiry_silent` | a same-store `ex=` write expiry in the window → silent |
| `test_agent_memory_retention_aliased_import_bypass` | an aliased ctor (`RCMH`) is not matched → silent (documented bypass) |
| `test_agent_memory_retention_pragma_silences` | the pragma silences the file |
| `test_agent_memory_retention_applies_gate` | fires only when `llm` is a detected feature |

## Known bypasses

- **Out-of-band TTL** — a TTL applied far from the constructor (a `redis.expire()` beyond the
  `_WINDOW`, or an ops-level `maxmemory-policy` / key-eviction rule) reads as absent. Fail-safe
  direction (over-flags → escapable via the pragma).
- **Marker on an unrelated object** — `_TTL_OK` is not variable-scoped: a `.expire(...)` / `ex=` / `px=`
  belonging to a *different* store within the window silences the finding (e.g. an unrelated
  `cache.expire(60)` two lines below a misconfigured constructor). A false negative; accepted rather
  than tracking the constructor's assignment target across the window (fragile for a rare case).
- **TTL marker inside a single-line string** — `#` comments are stripped (the #386 fix), but a
  single-line string literal that happens to contain a marker (`log.warning("set ttl=3600")`) is NOT
  blanked by `strip_python_strings` and will silence a nearby finding. Rare; accepted residual.
- **Aliased / dynamic construction** — building the store through `RedisChatMessageHistory as RCMH`, a
  factory wrapper, a variable class reference, or `getattr` evades the literal-constructor regex.
- **A different persistent store** — an in-house Redis wrapper, or a store not in `_MEM_CTOR`'s set,
  is not matched.

## What this guard does NOT prove

That a *present* `ttl=` value is short enough to matter — `ttl=<var>` or a very large literal both read
as configured (the guard verifies the retention *mechanism* exists, not that its value is appropriate).
It also does not cover vector-store / DB-backed retention (Chroma, pgvector, Postgres savers), where
retention is a database-side eviction policy rather than a constructor argument — explicitly out of
scope, not silently handled.

# Citations

[1] agentsec checklist item `4-agent-memory-retention` (§4)
[2] OWASP-LLM:LLM01
[3] OWASP-LLM:LLM08
[4] OWASP:A09
