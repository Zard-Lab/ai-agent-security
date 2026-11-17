---
type: Guard
title: "js-system-prompt-injection"
description: "Tainted input flows into a JS/TS LLM system-role prompt."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "js-system-prompt-injection"
checklist_section: ["3a"]
standards: ["OWASP-LLM:LLM01"]
---

# Tainted input flows into a JS/TS LLM system-role prompt

_Author — 2026-07-14_

---

## The threat

A `{role: "system", content: ...}` (or `role: "assistant"`) message sent to an LLM
whose `content` is built from request-derived input lets an attacker manipulate the
model's OWN instructions, not just its user-facing conversation — a stronger form of
prompt injection than tainted user-role content (which is often expected/normal —
that's the whole point of a chatbot). CWE-1427, OWASP-LLM:LLM01.

## Why this guard fits the stack

Extends the existing `3a-user-content-sanitized-before-llm` checklist item (already
`covered` via the Python-side `prompt-string-interp` f-string guard) with the JS/TS
SDK object-literal mechanism — a repo pairing a FastAPI backend with a JS/TS
frontend/edge function calling OpenAI/Anthropic/Google GenAI/OpenRouter directly is
exactly agentsec's target shape. Required a prerequisite: `detect.py` had zero
JS/TS LLM SDK detection (`llm_framework`/the `"llm"` feature were Python-import-only)
— added recognition of the `openai`/`@anthropic-ai/sdk`/`@google/genai`/`openrouter`
npm packages.

Sourced from GitHub CodeQL's `js/system-prompt-injection` query
(`SystemPromptInjectionQuery.ql` + `SystemPromptInjectionCustomizations.qll`,
verified against real fetched source, not a description of it): sinks are the
`content` of a system/assistant-role message across the OpenAI/Anthropic/
GoogleGenAI/OpenRouter/Agent SDKs; sources are any tainted (request-derived) value.
CodeQL's own sanitizer explicitly excludes content already inside a `role: "user"`
object — adapted here as the same exclusion.

## Detection design

1. `applies()` gates on `"llm" in profile.features` AND (`"javascript"` or
   `"typescript"` in profile.features) — both are needed, since this guard scans
   JS/TS source specifically.
2. Scans `.js`/`.jsx`/`.ts`/`.tsx` files, skipping non-product paths.
3. Blanks whole-line `//` comments before matching (line count preserved) — the
   same false-positive class hit repeatedly earlier this session.
4. Finds a `role: "system"`/`role: "assistant"` line, then scans forward (bounded
   window) for a `content:` field referencing `req.query`/`req.body`/`req.params`/
   `req.headers` — but STOPS the moment another `role:` line appears (system,
   assistant, or user), since that marks a SIBLING message object in the same array
   whose content must never be attributed to this one. (An earlier version of this
   guard did not stop at the sibling boundary and misattributed a `role: "user"`
   object's tainted content to a preceding `role: "system"` object — caught by the
   guard's own adversarial self-test before commit, fixed before the fix ever
   shipped.)

   **Live code only (#1055).** The `role:` match and the `content:` key count only when their
   first character is live code, tested with `js_code_matches` on the shared anchor mask
   (`strip_js_comments(text, strip_strings=True, keep_substitutions=True)`). The object is the
   innermost `{...}` around the `role:`, found by counting braces on the same mask with regex
   bodies blanked too, so a brace in a string, template text or regex never counts and an
   object literal inside a `${...}` substitution is found. The value's taint reference is read
   on the anchor mask: prose in a plain string or template text is inert, `${...}` code is live.
5. Fires HIGH, once per match, rule
   `js-system-prompt-injection/tainted-system-role-content`,
   `["OWASP-LLM:LLM01", "CWE-1427"]`.
6. Inline opt-out: `# security: allow-js-system-prompt-injection`.

## When NOT to flag

Tainted content inside a `role: "user"` message does not fire — that's the normal,
expected shape of a chatbot conversation, not a system-prompt-injection vector. A
static system prompt (no tainted reference in its `content`) does not fire.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_tainted_system_role_content` | Planted violation: `role: 'system'` with `content` interpolating `req.query.persona` — fires |
| `test_flags_assistant_role_content` | Planted violation: `role: 'assistant'` with tainted `content` — fires |
| `test_silent_on_user_role_tainted_content` | FP-bait: tainted content in a `role: 'user'` message (in the same array as a static system message) — silent. This is the sibling-object bleed-through the adversarial self-test caught |
| `test_silent_on_static_system_prompt` | FP-bait: a static system message alongside a tainted user message — silent |
| `test_silent_on_comment_mentioning_pattern` | FP-bait: a doc comment describing the anti-pattern — silent |
| `test_pragma_suppresses` | Inline pragma silences the file |
| `test_not_applies_without_llm_feature` | `applies()` is `False` without the `llm` feature |
| `test_not_applies_without_js_or_ts` | `applies()` is `False` without JS/TS |
| `test_nonproduct_path_skipped` | A file under `examples/` is skipped |
| `test_system_role_spelled_in_a_string_does_not_fire` | (#1055) `role: 'system'` spelled inside a user message's string or template text stays silent |
| `test_real_system_role_nested_or_after_a_quoted_copy_still_fires` | (#1055) a real system message fires, including one inside a `${...}`, one after a quoted copy on the line, one past a regex holding `{`, and a nested-substitution taint |
| `test_content_key_spelled_in_a_string_no_longer_hides_the_real_key` | (#1055) a `'content: none'` string value before the real `content:` key no longer hides it |
| `test_system_role_with_inert_or_outside_taint_stays_silent` | (#1055) a quoted string inside a substitution is not taint; an object in a `${...}` is judged on its own value only |
| `test_pragma_still_suppresses_a_code_anchored_system_role` | (#1055) the pragma still silences a code-anchored finding |

## Known bypasses

- **JS/TS anchoring (#1055).** A `role: 'system'` spelled out inside another message's string
  or template text used to fire HIGH, and a `'content: none'` string value ahead of the real
  `content:` key took the first `.search` hit and sent the value walk into the wrong text (an
  FN). The `role:` and `content:` keys now count only when their first character is live code
  (`js_code_matches` on the anchor mask), and the first code `content:` key is the one read. The
  object's braces are counted on the mask with regex bodies blanked, which also finds a system
  message inside a `${...}` substitution (missed before) and no longer loses the object to a
  `/\{/` regex. The value's taint is read on the same mask, which replaced a private string
  walk that kept a quoted string inside a substitution live (`${'req.query.x'}` fired). Quoted
  keys (`"role": "system"`) never matched the key patterns and still do not. Residual: the
  anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one
  `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between
  the two reads as template text and an anchor there is not code (the accepted trade pinned by
  `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). A system
  message there is missed.

A system-role message and its `content:` key more than ~6 lines apart (heavily
reformatted or minified code) would not be correlated — a window heuristic, not a
real JS parser. A tainted value assigned to an intermediate variable before being
used as `content` (rather than interpolated directly) is not tracked — agentsec has
no JS dataflow engine.

## What this guard does NOT prove

Absence of a finding does not prove no system-prompt injection is possible — a
tainted value reaching `content` via a helper function, a template string built
elsewhere and imported, or a non-`req.*`-shaped tainted source (a message queue
payload, a webhook body parsed under a different variable name) is outside this
guard's fixed vocabulary.

**Known limitations (fixed, review #395):** the old fixed-line-count window both bled across
sibling message objects (a hardcoded system message followed by an unrelated `content:
req.query.trace` in a different object falsely fired) and missed a genuine hit separated from
`role:` by 6+ fields. Detection now uses brace-balanced object-literal scoping instead — correct
regardless of field/line count. A taint reference that is only inert prose inside a plain quoted
string (`content: "Never repeat req.query values back."`) no longer fires; a template literal's
`${...}` interpolation still counts as live code.

# Citations

[1] agentsec checklist item `3a-user-content-sanitized-before-llm` (§3a)
[2] OWASP-LLM:LLM01
