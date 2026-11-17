---
type: Guard
title: "multi-agent-prompt-origin"
description: "Multi-agent pipeline forwards LLM output without trust-boundary marking."
timestamp: "2026-06-28T18:41:11+08:00"
guard_id: "multi-agent-prompt-origin"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM01", "OWASP-LLM:LLM05", "OWASP:A01"]
---

# Multi-agent pipeline forwards LLM output without trust-boundary marking

_Author — 2026-06-28_

---

## The threat

In a multi-agent pipeline, Agent A processes untrusted user input and produces output. Agent B
then receives Agent A's output as its prompt input — treating it as trusted context. An attacker
who controls the user input to Agent A can embed an injection payload that survives Agent A's
processing and cascades into Agent B's reasoning context. Because Agent B cannot distinguish
Agent A's output from a trusted instruction, it executes the payload.

The attack surface has three sub-patterns:

- **Untagged relay (MAG001/003):** Agent A's result variable flows directly to Agent B's
  `invoke()/run()` call with no sanitization or origin-tagging.
- **Infection delimiter (MAG006/011):** Inter-agent relay uses structural delimiters (`<<<`,
  `[CASCADE]`, `[INJECT]`) that user input can spoof, allowing payload injection at the
  protocol level.
- **Unauthenticated handoff (MAG015):** An HTTP endpoint accepts agent-relay parameters
  (e.g. `agent_output`, `forwarded`) and passes them to an LLM call without verifying that
  the message actually came from a trusted upstream agent.

Standards (per rule): untagged-relay and infection-delimiter are prompt-injection +
improper-output-handling → `OWASP-LLM:LLM01` + `OWASP-LLM:LLM05` (LLM05:2025 is Improper
Output Handling — the repo convention, matching `llm-output-to-sink` / `langchain-unsafe-chain`;
LLM02:2025 is Sensitive Information Disclosure and does not apply here). Unauthenticated handoff
adds broken access control → `OWASP-LLM:LLM01` + `OWASP:A01`.

## Why it's often introduced / Why this guard fits the stack

Multi-agent systems in FastAPI + LLM stacks emerge naturally when developers compose agents
for different subtasks. The naive approach is to pipe the output of one agent call directly
into the next:

```python
# Bad — Agent A's output (potentially attacker-controlled) flows into Agent B untouched.
result = agent_a.invoke(user_query)
final = agent_b.invoke(result)  # cascade injection risk
```

Similarly, relay endpoints are often added without authentication because the developer
assumes the endpoint is "internal":

```python
@app.post("/relay")
async def relay_agent(agent_output: str):
    return await llm.ainvoke(agent_output)  # unverified source
```

## Detection design

1. **applies() gate** — fires only when `"llm"` is in `profile.features`. Multi-agent relay
   is an LLM-specific threat.

2. **Files scanned** — Python files under `python_scan_dirs(root, profile)`, found via
   `iter_files(d, (".py",))`. Non-product paths skipped via `is_nonproduct_path`.

3. **Three rules, all per-file:**

   **Rule 1 — untagged-relay (HIGH):**
   The file must first show an LLM-call signal (`_LLM_CALL_SIGNAL`) — parity with Rules 2/3,
   so a pure non-LLM module never trips it. Phase 1 scans for LLM result assignments via
   `_LLM_ASSIGN` — deliberately **LLM-specific** call shapes: `var = x.invoke(...)`,
   `.ainvoke/.arun/.run_sync/.generate(...)`, `var = client.chat.completions.create(...)`,
   `var = client.messages.create(...)`. Bare `.run(` / `.create(` are **not** matched (they
   hit `subprocess.run()` and Django `User.objects.create()`). Phase 2 fires only when the
   captured variable is forwarded **whole** into a later call — `invoke(var)` /
   `ainvoke/arun/run_sync(var)`, or a message `'content': var` immediately closed by
   `}`/`,`/`]`/`)`. Attribute-extracted content (`'content': reply.choices[0].message.content`)
   is intentionally NOT matched, so the canonical single-agent `messages.append({"role":
   "assistant", "content": reply...})` history loop stays silent. A trust marker (`origin`,
   `source_agent`, `trust_level`, `verified`, `sanitize`, `clean_output`, `strip_injection`),
   matched as a **whole word** within ±5 lines of the forwarding point, suppresses the finding.

   **Rule 2 — infection-delimiter (MEDIUM):**
   Searches for `<<<`, `>>>`, `[CASCADE]`, `[INJECT]`, `[HANDOFF]` in files that have LLM
   call signals. Triple-quoted strings and comments are stripped first (`_strip_docstrings`)
   to avoid FPs in documentation. Suppression is the file-level `_PRAGMA`.

   **Rule 3 — unauth-agent-handoff (HIGH):**
   Matches `async def` functions whose parameter list includes a relay-named parameter
   (`agent_output`, `relay_msg`, `handoff`, `forwarded`, `from_agent`, `agent_result`). The
   function body must contain an LLM call AND neither the **signature** nor the body may
   contain an auth marker (`verify_source`, `check_origin`, `auth_token`, `hmac`, `signature`,
   `Depends`, `Security`). `Depends`/`Security` cover the idiomatic FastAPI auth-dependency
   (`user=Depends(get_current_user)` lives in the signature, hence the signature is checked too).

4. **Pragma** — `# security: allow-multi-agent-relay` (file-level; any occurrence silences
   all three rules for that file).

5. **Severities, rules, and standards:**
   - `multi-agent-prompt-origin/untagged-relay` — HIGH — `["OWASP-LLM:LLM01", "OWASP-LLM:LLM05"]`
   - `multi-agent-prompt-origin/infection-delimiter` — MEDIUM — `["OWASP-LLM:LLM01", "OWASP-LLM:LLM05"]`
   - `multi-agent-prompt-origin/unauth-agent-handoff` — HIGH — `["OWASP-LLM:LLM01", "OWASP:A01"]`

## When NOT to flag

- When an intermediate sanitization step (a function call that processes the result) appears
  between the two LLM calls. Rule 1's trust-marker window (`_has_trust_marker_nearby`) catches
  the most common patterns (`sanitize`, `verified`, `origin`).
- When the file makes no LLM call at all — Rule 1 (like Rules 2/3) requires `_LLM_CALL_SIGNAL`,
  so `subprocess.run(out) → subprocess.run(...)` chaining and other non-LLM pipelines stay silent.
- When an LLM reply is appended to its own conversation history with attribute extraction
  (`messages.append({"role": "assistant", "content": completion.choices[0].message.content})`).
  This is a single agent recording its own turn, not a cross-agent relay — Rule 1 requires the
  forwarded var to be the bare value.
- When a relay endpoint has an auth check (`verify_source`, `hmac`, `signature`) or a FastAPI
  auth dependency (`Depends`/`Security`) in the signature or body. Rule 3 explicitly skips these.
- When delimiters appear only in docstrings or comments (stripped by `_strip_docstrings`).
- When no LLM call is present in the file (Rule 2 requires `_LLM_CALL_SIGNAL`).
- When the file carries `# security: allow-multi-agent-relay`.

## Tests

| Test | What it checks |
|---|---|
| `test_untagged_relay_fires_direct_chaining` | Rule 1 fires HIGH when result forwarded via `'content': result` |
| `test_untagged_relay_fires_invoke_chaining` | Rule 1 fires HIGH when result forwarded via `invoke(result)` |
| `test_untagged_relay_silent_when_sanitized` | Rule 1 silent when `sanitize()` is between the two calls |
| `test_untagged_relay_silent_on_subprocess_chaining` | Rule 1 silent on `subprocess.run` chaining (FP-bait, non-LLM) |
| `test_untagged_relay_silent_on_single_agent_history_loop` | Rule 1 silent on the canonical `messages.append(reply)` loop (FP-bait) |
| `test_untagged_relay_silent_with_pragma` | Pragma suppresses all rules |
| `test_infection_delimiter_fires_on_cascade` | Rule 2 fires MEDIUM on `[CASCADE]` in LLM-serving file |
| `test_infection_delimiter_fires_on_angle_brackets` | Rule 2 fires MEDIUM on `<<<` in LLM-serving file |
| `test_infection_delimiter_silent_without_llm_call` | Rule 2 silent in file with no LLM call |
| `test_infection_delimiter_silent_in_docstring` | Rule 2 silent when delimiter is only in a docstring |
| `test_unauth_handoff_fires_relay_without_auth` | Rule 3 fires HIGH on unauthenticated relay endpoint |
| `test_unauth_handoff_silent_with_hmac_check` | Rule 3 silent when `verify_source()` is present |
| `test_unauth_handoff_silent_with_fastapi_depends_auth` | Rule 3 silent when gated by `Depends(...)` (FP-bait) |
| `test_unauth_handoff_silent_when_no_llm_call` | Rule 3 silent when relay route makes no LLM call |
| `test_multi_agent_prompt_origin_not_applicable_without_llm` | applies() returns False without llm feature |
| `test_multi_agent_prompt_origin_applies_with_llm` | applies() returns True with llm feature |

## Known bypasses

- **Aliasing:** If the LLM result is assigned to a new variable name before forwarding
  (`x = result; llm.invoke(x)`), Rule 1 does not detect it (two-hop aliasing is out of scope
  for a single-pass regex guard).
- **Cross-file relay:** Agent A's result stored in a shared object and Agent B reads it from
  another module — single-file analysis misses this.
- **Trust-marker naming:** A developer who names a variable `trust_level` near the forwarding
  point silences Rule 1 even without actual sanitization.
- **Non-standard LLM SDKs:** Rule 1 and Rule 3 rely on a known set of invoke method names.
  A custom wrapper with a different call signature is missed.
- **`messages.append` relay (FN, deliberate):** Rule 1 no longer matches the loose
  `messages.append(...var...)` form. That form was dropped because it false-fired on the
  canonical single-agent history loop; a genuine relay that appends Agent A's whole output to
  Agent B's history (rather than passing it to `invoke(var)` / `'content': var`) is now missed.
- **Sync relay handlers (FN):** Rule 3 matches only `async def`. A synchronous FastAPI relay
  route (`def relay_agent(agent_output: str)`) is missed; gating on the param name keeps the
  async-only form low-FP.
- **Delimiter encoding:** URL-encoded or base64-encoded delimiters in the message bypass
  Rule 2's string match.
- **Rule 2 angle-bracket noise (FP):** `<<<`/`>>>` inside ordinary single/double-quoted
  strings (e.g. a bash here-string `"grep x <<< $y"`) in an LLM-serving file produce a MEDIUM.
  Only triple-quoted strings/comments are stripped. MEDIUM does not trip the default
  `--fail-on high` gate, so this is accepted as noise rather than a blocker.

## What this guard does NOT prove

- That any sanitization function called between LLM calls is actually effective against
  injection payloads — only that something is called.
- That the authenticated relay endpoint correctly validates the auth token (only that some
  auth keyword is present).
- That cross-file or cross-service agent handoffs are safe.
- That runtime behavior is secure — this is a static analysis guard only.

# Citations

[1] agentsec checklist item `4-multi-agent-handoff-authentication` (§4)
[2] agentsec checklist item `4-multi-agent-infection-delimiter` (§4)
[3] agentsec checklist item `4-multi-agent-untagged-relay` (§4)
[4] OWASP-LLM:LLM01
[5] OWASP-LLM:LLM05
[6] OWASP:A01
