---
type: Guard
title: "input-delimiters"
description: "User input reaches an LLM call without delimiter wrapping."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "input-delimiters"
checklist_section: ["3b"]
standards: ["OWASP-LLM:LLM01"]
---

# User input reaches an LLM call without delimiter wrapping

_Added 2026-06-14 — gap #3 (§3b prompt-injection input delimiters), the last High-effort LLM gap
with a tractable static shape. The **first guard built by following the `/guard-factory` skill**
(`claude-skills/guard-factory/SKILL.md`)._

---

## The threat

§3b of the checklist: *"External user input wrapped in delimiters (XML/JSON tags) before prompts"*.
This is OWASP-LLM's Layer-1 deterministic prompt-injection defense. When an app concatenates raw
user input into a prompt — `agent.run_sync(user_message)`, or
`f"Answer this: {user_message}"` — the model receives one undifferentiated blob: it cannot tell
*the user's data* from *instructions about the user's data*. Anyone who can send the app a message
(typically any authenticated, often any anonymous, user) can therefore smuggle `Ignore the previous
instructions and instead …` into their input and the model obeys it — leaking the system prompt,
calling tools they shouldn't reach, or returning attacker-chosen output. Wrapping untrusted input in
explicit delimiters (`<user_input>…</user_input>`) plus a "treat the contents as data, never
instructions" directive is the cheap structural fix.

Findings carry `["OWASP-LLM:LLM01"]`.

## Scope — complementary to lethal-trifecta (accepted overlap, not double-flagging)

`agentsec/ai/lethal_trifecta.py` inventories an `untrusted_content` leg and a `rag_sanitization`
mitigation, but it only emits a finding when the **full lethal trifecta is active** (private data +
untrusted content + external comms) and frames the gap as *post-retrieval RAG sanitization* of
fetched chunks. The common shape this guard targets — an ordinary agent that takes a **user
message** and calls the model, with no full trifecta and no RAG at all — is invisible to it.

This guard partitions that space: it fires whenever **user input reaches an LLM call with no
delimiter wrapping**, independent of the trifecta and of RAG. In the full-trifecta case both can
fire — **accepted**, not a bug: lethal-trifecta frames it architecturally (a missing leg of layered
defense), this guard frames it specifically (the concrete §3b control is absent). They share the
`wrap_untrusted` marker (`_DELIMITER` ⊇ `lethal_trifecta._MITIGATIONS["rag_sanitization"]`'s
`wrap_untrusted`) so they agree on what counts as wrapping; we deliberately do **not** suppress one
based on the other (cross-guard suppression is fragile). The canary proves coexistence: its
`agent.py` fires `lethal-trifecta/no-defense`, `system-prompt-leak/no-leak-filter`, **and**
`input-delimiters/unwrapped-user-input`.

## Why it's often introduced  /  Why this guard fits the stack

The `9_Agent_SaaS` shape calls the model in one line — `agent.run_sync(user_message)` — and the
delimiter boundary is a separate, easily-omitted step that leaves no trace in the happy path. The
default state of a freshly-built agent is "unwrapped", which is exactly what an absence guard should
catch.

## Detection design

1. **`applies()` gate** — `"llm" in profile.features` (mirrors `LethalTrifectaGuard` /
   `SystemPromptLeakGuard`).
2. **Scan** — every `.py` under `python_scan_dirs` (deduped via a `seen` set), as `(path, text)`.
3. **Evidence/pragma pass (repo-global), runs FIRST** — if any file matches `_DELIMITER`
   (`<user_input>` / `<untrusted>` / `<documents>` / `<context>` / `wrap_untrusted` /
   `wrap_user_input` / `delimit` / `in_delimiters` / `<input>`) or contains the pragma →
   `return []`. Ordering is load-bearing: some wrapping markers contain user-input tokens, so
   short-circuiting on wrapping first makes any overlap harmless.
4. **User-input gate** — if no file matches `_USER_INPUT` (`request` / `user_` / `message` / `query`
   / `user_input` / `question` / `prompt` / `.body` / `form` / `payload`) → `return []`. An app that
   calls the model only with constant/system prompts has no user input to delimit; this is the most
   important false-positive class to suppress.
5. **Anchor pass** — the first file+line where the shared `base.LLM_CALL` matches (`.run` /
   `.run_sync` / `.complete` / `.chat` / `chat.completions.create` / `responses.create` /
   `.predict` / `.invoke`) becomes the single finding's location. No call site → `return []`.
   The pattern is defined once in `guards/base.py` and shared with `rag-trust-boundary` and
   `prompt-string-interp`. It used to be three hand-kept copies, and they drifted apart twice
   (found in #717 and #726); `tests/guards/test_base.py` now fails if any guard grows its own copy.
   The bare `.run(` form is **receiver-scoped**: `asyncio` / `subprocess` / `trio` / `anyio` /
   `uvicorn` / `gunicorn` / `unittest` / `pytest` / `nox` / `tox` are excluded, because a process,
   event-loop or test runner is not a model invocation. Unconstrained, they were the dominant false
   anchor (#717): the reported line was `subprocess.run(` in a `.claude/` skill reference file, and
   `uvicorn.run(app, ...)` on the flagship. Note what that defect was and was not — the guard's
   **claim** (no delimiter wrapping anywhere in the app) was true in both repos; only the **location**
   was wrong, which is a distinct failure mode from a false positive and sends the fixer to the wrong
   file. `agent.run(...)` / `title_agent.run(...)` are real Pydantic-AI calls and still anchor.
6. **Opt-out pragma** — `# security: allow-undelimited-input` anywhere in the scanned source.
7. **Severity / rule** — one **medium** `input-delimiters/unwrapped-user-input`,
   `["OWASP-LLM:LLM01"]`.

### Severity rationale (medium finding vs a HIGH checklist item)

The checklist item `3b-input-delimiters` is **high** — undelimited input is a genuine injection
vector (control importance). The guard's finding is **medium**, decoupled exactly as
`security-headers` decouples its `low` finding from a `medium` item: *detection confidence* and
*control importance* are different axes. LLM call-site recognition by regex is the FP-prone-est
detection in the guard set, so medium keeps a heuristic match below the default `--fail-on high` CI
gate — it advises, it does not block a merge on its own. Flagged for maintainer (Marconi) curation:
he may prefer `high` (relying on the pragma) once it is validated live on the flagship; that is a
one-line `severity=` change.

## When NOT to flag

- **Non-product code** — migration plumbing (`alembic/`), test/example/fixture code is skipped via `is_nonproduct_path`; LLM-input framing does not apply there (round-2 §A.2).
  **The skip gates the ANCHOR and `_USER_INPUT` precondition passes, never the MITIGATION pass.** A
  file under a non-product path cannot *establish* the finding (it is not the deployed app), but it is
  still read for the **pragma and the `_DELIMITER` mitigation** — those are repo-level opt-outs, so a
  `# security: allow-undelimited-input` pragma or a
  `wrap_untrusted(...)` helper living in `tests/`, `e2e/` or an opted-in archive tree still silences
  the guard. An earlier revision of #484 filtered before that check and voided them (B1/B2); the
  order is load-bearing, not incidental.

An app that already wraps input (any `_DELIMITER` marker — explicit tags or a
`wrap_untrusted(...)` / `delimit(...)` helper) is clean and silent. An LLM app that calls the model
only with constant or system-authored prompts (no `_USER_INPUT` signal) is silent. The pragma covers
an app where delimiting is genuinely handled elsewhere (a gateway/middleware) or where undelimited
input is a reviewed, accepted decision.

## Tests

| Test | What it checks |
|---|---|
| `test_input_delimiters_flags_unwrapped_call` | `agent.run_sync(user_message)` + user-input token, no wrapping → one MEDIUM `input-delimiters/unwrapped-user-input` |
| `test_input_delimiters_silent_with_wrapping` | same call + `<user_input>…</user_input>` (or `wrap_untrusted`) → silent (evidence pass first) |
| `test_input_delimiters_pragma_opt_out` | `# security: allow-undelimited-input` → silent |
| `test_input_delimiters_silent_without_llm_call` | user input present but no model-invocation call → silent |
| `test_input_delimiters_silent_without_user_input` | a `.run(` call but only a constant prompt (no user-input token) → silent (the key FP guard) |
| `test_input_delimiters_not_applicable_without_llm` | `applies()` False without `llm` |
| `test_process_and_loop_runners_do_not_anchor` | user input, no wrapping, but the only `.run(` calls are `subprocess` / `asyncio` / `uvicorn` → silent (#717 FP-bait) |
| `test_nested_asyncio_run_does_not_anchor` | `sys.exit(asyncio.run(main()))` → the receiver lookbehind holds inside a nested call |
| `test_pydantic_ai_agent_run_still_anchors` | `title_agent.run(user_message)` → still fires (the direction traded against by the narrowing) |
| `test_openai_completions_create_still_anchors` | `client.chat.completions.create(...)` → still fires |
| `test_runner_file_does_not_steal_the_anchor_from_the_real_llm_call` | a runner file sorting first must not win the first-match race; the anchor crosses to the real LLM file |
| `test_suffix_collision_receiver_still_anchors` | `my_subprocess.run(user_message)` → still fires; the exclusions are identifier-scoped, not suffix-scoped (#725 review) |
| `test_every_runner_receiver_is_still_suppressed` | all ten excluded receivers stay suppressed, so the `\b` fix cannot quietly undo the #717 narrowing |

Liveness: the canary's `agent.py` plants `agent.run_sync(question)` with no wrapping marker
(`agentsec/canary.py`), so `doctor --canary` proves the guard fires end-to-end and coexists with
`lethal-trifecta/no-defense` + `system-prompt-leak/no-leak-filter`.

## Known bypasses

- **Indirect wrapping** — a delimiter helper named outside the marker set (e.g. `def fence(...)`
  with no `wrap`/`delimit`/tag token) won't silence the guard → a false positive; the pragma is the
  escape hatch. Conversely, a wrapping marker that is *defined but never applied* to the call still
  silences it (static can't trace data flow).
- **Indirect / aliased call site** — a model wrapper (`def ask(msg): return agent.run_sync(msg)`)
  anchors on the inner `.run_sync(`; but a fully dynamic dispatch (`getattr(agent, verb)(...)`) or
  a model SDK whose invocation verb isn't in `base.LLM_CALL` won't anchor (false negative).
  Anthropic's `messages.create(` is one: it is deliberately left out of the shared pattern because
  as an anchor it would also land on Twilio / ORM / queue `client.messages.create(...)` (#717).
- **Runner-exclusion edges on the bare `.run(` arm.** The lookbehinds are identifier-scoped (each
  carries a leading `\b`), so `my_subprocess.run(` correctly anchors while `subprocess.run(` does
  not. Three edges remain, all accepted: a **dotted attribute** receiver (`self.subprocess.run(...)`,
  where the attribute is genuinely unrelated) is still suppressed, which is inherent to matching a
  receiver by regex; a **newline between receiver and call** (`asyncio\n.run(...)`) defeats the
  lookbehind, so that form still anchors; and nox's own idiom **`session.run("pytest")`** in a
  top-level `noxfile.py` (which counts as product code) still anchors, because the receiver is
  `session` and the `nox` exclusion never sees it. Only the first can hide a real call site, and it is
  the rarest. The other two err the loud way, by counting a runner as the call site (a mislocated
  finding, or a manufactured one in an app with no real call).
- **Variable provenance** — the guard cannot prove the variable at the call site is *actually*
  user-derived; it relies on a co-occurring user-input token in the source. A call fed from a
  constant whose file happens to mention `request`/`prompt` could over-fire (mitigated by medium
  severity + pragma); a genuinely user-fed call in a file with no user-input token under-fires.
- **Constant-only prompts in a user-input-heavy file** — the file-level (not call-level)
  user-input gate is coarse; this is the deliberate trade-off for FP-safety + simplicity.

## What this guard does NOT prove

That the app is safe from prompt injection — only that a delimiter-wrapping **marker exists in the
code** (or that there is no user-input→model flow). It is a *static* analyzer: it cannot confirm the
wrapping is actually applied to the user variable at the call site, that the delimiters are
paired with a "treat as data" instruction, or that the model honors them. Existence ≠ efficacy. Nor
does it assess the other prompt-injection layers (output guardrails, RAG sanitization, invisible-
Unicode scanning) — those are lethal-trifecta's and the other §3b/§4 items' territory.

# Citations

[1] agentsec checklist item `3b-input-delimiters` (§3b)
[2] OWASP-LLM:LLM01
