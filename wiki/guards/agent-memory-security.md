---
type: Guard
title: "agent-memory-security"
description: "AI agent long-term memory store is insecure or poisonable."
timestamp: "2026-06-28T20:01:01+08:00"
guard_id: "agent-memory-security"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM01", "OWASP-LLM:LLM03", "OWASP-LLM:LLM04", "OWASP-LLM:LLM08", "OWASP:A01", "OWASP:A02", "OWASP:A03", "OWASP:A08"]
---

# AI agent long-term memory store is insecure or poisonable

_Author — 2026-06-28_

---

## The threat

AI agents that persist conversation history, user context, and tool outputs to
long-term stores (Redis, vector databases, pickle checkpoints) create a durable
attack surface. Three concrete attack paths:

1. **Network interception (AIM002):** A Redis memory store without TLS transmits
   agent memory in plaintext. An attacker on the network path — or a compromised
   internal host — can read conversation history and inject poisoned data into
   the stream before it reaches the store. Privilege required: network adjacency.

2. **Stored prompt injection (AIM007 + AIM009):** An attacker submits crafted
   user input containing prompt injection payloads. If that input is written
   directly to memory (AIM007) and later retrieved and injected into the system
   prompt (AIM009), the payload executes in a future session — possibly for a
   different user. This is a stored, cross-session variant of OWASP-LLM:LLM01.
   Privilege required: ability to send any message to the agent.

3. **Arbitrary code execution via deserialization (AIM013):** Agent memory
   serialized with `pickle` without an HMAC can be swapped for a malicious
   pickle payload. On next load, `pickle.load()` executes arbitrary code.
   Privilege required: write access to the checkpoint file path.

Standards (per-rule, not uniform):
- `redis-no-tls` → **OWASP:A02** (Cryptographic Failures — unencrypted transport).
- `unsanitized-user-write` → **OWASP-LLM:LLM04** (Data and Model Poisoning), **OWASP:A03**.
- `memory-to-system-prompt` → **OWASP-LLM:LLM01** (Prompt Injection), **OWASP:A03**.
- `checkpoint-no-integrity` → **OWASP:A08** (Software/Data Integrity), **OWASP-LLM:LLM03**
  (Supply-Chain) — insecure pickle deserialisation, mirroring `unsafe-deserialization`.

(Note: OWASP-LLM **LLM08:2025** is "Vector and Embedding Weaknesses", not the retired
"Excessive Agency" — so the poisoning rules are tagged LLM04/LLM01, not LLM08.)

## Why it is often introduced / Why this guard fits the stack

In a FastAPI + LLM/RAG stack, developers frequently:

- Add Redis as a quick persistence layer for conversation history without
  enabling TLS, especially in early development where SSL setup feels like
  friction.
- Write raw user messages directly to a vector store or LangChain memory
  object to keep the code short, not recognizing the injection risk.
- Inject the full retrieved memory blob into the system prompt using an f-string
  for convenience, trusting the memory store as a safe source.
- Use `pickle` to serialize agent state because it handles complex Python objects
  without schema definition.

Example bad pattern (AIM007 + AIM009 chained):

```python
memories = store.get(user_id)                    # retrieval
system_prompt = f"Remember this: {memories}"     # injection
memory.add(user_message)                         # next turn writes raw input
```

## Detection design

1. **applies() gate:** `"llm" in profile.features` — fires only when the stack
   is detected as LLM/agent-enabled. Avoids noise on pure web apps.

2. **Files scanned:** `.py` files under `python_scan_dirs(root, profile)`.
   Non-product paths (tests, fixtures, examples) are skipped via
   `is_nonproduct_path(rel(root, f), profile.archive_segments)`.

3. **Patterns:**

   - **Rule AIM002 (rule: `agent-memory/redis-no-tls`, HIGH):**
     Phase 1: file contains a Redis import (`import redis`, `from redis import`,
     `StrictRedis`, `redis.Redis`).
     Phase 2: scan for `redis.Redis(...)` or `redis.StrictRedis(...)` calls — **and, in a file
     that imports the class from `redis` itself, the bare `Redis(...)` / `StrictRedis(...)`
     call with no receiver** (#422). `from redis import Redis` is the more common of the two
     import spellings and makes you write the bare call, which the dotted-receiver pattern could
     never match, so the whole rule was dead on it. The bare matcher is gated on
     `from redis ... import (Strict)Redis` specifically — a plain `import redis` is deliberately
     not enough, because under that import the call is spelled `redis.Redis(...)` and the dotted
     pattern already owns it. Two guards on the bare form: it is **case-sensitive** (with no
     `redis.` receiver to anchor on, a case-insensitive match would fire on any local helper named
     `redis(...)`), and it rejects a dotted receiver via lookbehind so the two patterns cannot both
     match one call. A same-named class from another library (`from fakeredis import Redis`) does
     not trip it.
     Phase 3: if the connection call does NOT contain `ssl=True`, `ssl_certfile`,
     `rediss://`, or `tls=True`, fire HIGH.
     Before matching, the line's trailing `#` comment is stripped (string-aware, so the
     `rediss://` TLS marker inside a literal survives). The bare matcher is gated only on a
     file-level import, so without the strip a **comment** describing the anti-pattern would raise
     a HIGH on documentation.

   - **Rule AIM007 (rule: `agent-memory/unsanitized-user-write`, HIGH):**
     Per-line scan for `.add(`, `.save(`, `.put(`, `.store(`, `.append(`,
     `.upsert(` followed by a variable whose name suggests raw user input
     (`user_*`, `*input*`, `*message*`, `query`, `prompt`). An FP filter
     skips lines where the argument name contains `sanitized`, `cleaned`,
     `normalized`, `validated`, `filtered`, `escaped`, `assistant`, `system`,
     or `safe`.

   - **Rule AIM009 (rule: `agent-memory/memory-to-system-prompt`, HIGH):**
     Phase 1: find all `var = <obj>.get/retrieve/search/recall/load/fetch(...)`
     assignments. Phase 2: for each retrieved variable, scan subsequent lines
     for `system_prompt += <var>` or `system_prompt = f"...{var}..."` patterns.
     Phase 3: skip if a sanitization marker (`sanitize`, `clean`, `strip`,
     `validate`, `escape`, `filter`) appears within 3 lines after the retrieval.

   - **Rule AIM013 (rule: `agent-memory/checkpoint-no-integrity`, MEDIUM):**
     Phase 1: detect `pickle.dump(...)` or `joblib.dump(...)`.
     Phase 2: check the 5-line context for `memory`, `state`, or `checkpoint`.
     Phase 3: skip if `hmac`, `hashlib`, `sha`, or `digest` appears in the
     surrounding 10-line window.

4. **Pragma:** `# security: allow-agent-memory-security` anywhere in the file
   suppresses all rules for that file.

5. **Standards:** per-rule (see the Standards list above) — A02 for redis-no-tls; LLM04/A03
   for unsanitized-user-write; LLM01/A03 for memory-to-system-prompt; A08/LLM03 for
   checkpoint-no-integrity. The earlier uniform `LLM08` set was corrected in PR #221 review
   (LLM08:2025 is Vector/Embedding Weaknesses, not the poisoning these rules target).

   Detection precision (PR #221 review): Rule 2 requires a memory-ish receiver (`memory`/
   `memstore`/`vectorstore`/`vector_db`/`docstore`/`retriever`/`knowledge_base`/`history`/
   `checkpoint`/`recall`/`redis`/`longterm` — see `_MEM_TOKENS`) so the chat-array
   idiom `messages.append(user_message)` does not false-fire; Rule 1 also matches
   `redis.Redis.from_url(...)` (a plaintext `redis://` URL was a silent miss); strings are
   blanked before the content rules so docstring examples don't fire; `strip` is no longer a
   Rule 3 trust marker.

## When NOT to flag

- **Redis with TLS:** `redis.Redis(host=..., ssl=True, ssl_ca_certs=...)` or a
  `rediss://` connection string is safe. The guard is silent.
- **Sanitized memory writes:** `memory.add(sanitized_output)` — a variable with
  a sanitized/cleaned/validated name prefix is assumed safe.
- **Sanitized system prompt injection:** if `strip_injection(memories)` or
  similar call appears within 3 lines between retrieval and system prompt use,
  the guard is silent.
- **Pickle with HMAC:** if `hmac` or `hashlib` appears in the surrounding
  10-line window, the guard assumes integrity is checked.
- **Non-memory pickle:** `pickle.dump(config, f)` without `memory`/`state`/
  `checkpoint` in context stays silent.
- Use `# security: allow-agent-memory-security` to suppress for intentional
  patterns (e.g. a Redis instance used only as a cache for public data, with
  TLS handled at the network/VPC layer).

## Tests

| Test | What it checks |
|---|---|
| `test_agent_memory_security_applies_gate` | Guard is silent when `llm` is absent from features |
| `test_agent_memory_security_applies_llm` | Guard applies when `llm` is present |
| `test_redis_no_tls_fires` | AIM002: Redis connection without ssl= fires HIGH |
| `test_redis_with_ssl_silent` | AIM002: ssl=True in connection args is clean |
| `test_redis_rediss_scheme_silent` | AIM002: rediss:// URL is clean |
| `test_unsanitized_user_write_fires` | AIM007: `memory.add(user_input)` fires HIGH |
| `test_unsanitized_message_write_fires` | AIM007: `memory.save({"content": user_message})` fires HIGH |
| `test_sanitized_output_silent` | AIM007: `memory.add(sanitized_output)` is clean |
| `test_assistant_response_silent` | AIM007: `memory.save(assistant_response)` is clean |
| `test_memory_to_system_prompt_fires` | AIM009: retrieval + unsanitized system_prompt f-string fires HIGH |
| `test_memory_to_system_prompt_with_sanitize_silent` | AIM009: sanitize() call between retrieval and use is clean |
| `test_pickle_memory_no_integrity_fires` | AIM013: pickle.dump(agent_memory) without hmac fires MEDIUM |
| `test_pickle_memory_with_hmac_silent` | AIM013: hmac.new() present in context is clean |
| `test_pickle_no_memory_context_silent` | AIM013: pickle.dump on non-memory object is clean |
| `test_pragma_suppresses_all_rules` | Pragma silences all rules file-wide |

## Known bypasses

- **Variable aliasing:** `data = user_message; memory.add(data)` — the aliased
  variable name (`data`) does not match the user-input name pattern, so AIM007
  is silent.
- **Multiline calls:** if the argument spans multiple lines (closing paren on a
  different line), the per-line regex may miss the match.
- **Indirect system prompt construction:** `parts = [memories]; system_prompt =
  "".join(parts)` — the join pattern is not detected by AIM009.
- **TLS at the infrastructure layer:** Redis with TLS terminated by a sidecar
  (e.g. Envoy proxy) appears unencrypted in the connection call, causing a FP.
  Use the pragma to suppress.
- **Custom integrity schemes:** using `cryptography.fernet` or similar instead
  of `hmac`/`hashlib` will not be recognized as an integrity check by AIM013.

## What this guard does NOT prove

- That TLS certificates are valid or that the Redis server is properly
  authenticated (only that TLS is enabled in the client config).
- That the sanitization function referenced in AIM009 context actually removes
  all injection vectors — only that some sanitization call exists.
- That pickle checkpoints are stored in a path with proper access controls.
- That memory retrieved via variable aliasing or indirect construction is safe.
- Runtime behavior: whether the agent actually uses the system prompt as
  constructed, or whether the memory store is reachable from the attack surface.

# Citations

[1] agentsec checklist item `4-agent-memory-write-validation` (§4)
[2] OWASP-LLM:LLM01
[3] OWASP-LLM:LLM03
[4] OWASP-LLM:LLM04
[5] OWASP-LLM:LLM08
[6] OWASP:A01
[7] OWASP:A02
[8] OWASP:A03
[9] OWASP:A08
