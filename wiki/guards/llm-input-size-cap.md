---
type: Guard
title: "llm-input-size-cap"
description: "LLM call site has no max_tokens ceiling — economic DoS risk."
timestamp: "2026-10-08T12:00:00+08:00"
guard_id: "llm-input-size-cap"
checklist_section: ["3a", "4"]
standards: ["OWASP-LLM:LLM10"]
---

# LLM call site has no max_tokens ceiling — economic DoS risk

## What it detects

Direct LLM API calls (`chat.completions.create`, `completions.create`, `responses.create`,
`messages.create`) in Python files that either:

1. Have no `max_tokens` argument anywhere in the file — the cost ceiling is absent entirely.
2. Set `max_tokens` from a user-controlled value (`request.*` or `user_*`) — the caller controls
   their own cost ceiling.

## Why it matters

Without a `max_tokens` ceiling, an attacker can send a 100 k-token prompt and drain API credits
proportionally to the token length. This is the primary economic-denial-of-service (EDoS) vector for
LLM-backed services. A single overnight script can rack up hundreds of dollars in API cost before
anyone notices.

With a user-controlled ceiling (`max_tokens=request.max_tokens`), the attacker sets their own limit
to the provider maximum, bypassing any intended cap.

## Detection scope

- Language: Python
- Applies when: `"llm" in profile.features`
- Scanned files: all `.py` files under `python_scan_dirs`, excluding test/fixture/migration paths
- Precision gate: only files with a direct SDK call. The call SHAPE is the shared
  `base.LLM_SDK_CREATE` (a `.chat.completions` / `.completions` / `.responses` / `.messages` path,
  then `.create(`), and a candidate counts only when `base.is_llm_sdk_create_call` confirms one of
  its top-level arguments is `model=`, `messages=`, `prompt=`, `extra_body=` or a `**` spread (#561).
  The method path alone is shared by non-LLM APIs: a Twilio SMS
  (`client.messages.create(body=..., from_=..., to=...)`) and a Django reverse-relation create
  (`survey.responses.create(answer=q)`) both fired this HIGH, though neither has a token ceiling to
  set. Every OpenAI and Anthropic SDK `create` is keyword-only, so a real call spells its arguments
  the SDK's way. The gate fails open: an argument list it cannot split counts as a call.
- The finding anchors on the FIRST confirmed call in the file, not the first SDK-shaped one, so an
  SMS sent above the LLM call is not where the finding points.
- Until #561 this guard kept its own three-arm copy of the shape with a `\b\w+\.` receiver prefix.
  That prefix only looked stricter than guardrail-architecture's (`client.` and `survey.` satisfy it
  equally), and the two copies disagreed about `completions.create`. Both guards now import the one
  definition. Two widenings came with it: the legacy `completions.create` path, and a call result
  as the receiver (`get_client().messages.create(model=...)`). The gate covers both
  (`db.completions.create(body=q)` stays silent).
- Intentionally excluded: high-level wrappers (`agent.run_sync()`, `agent.invoke()`, LangChain
  chains) — these configure token limits at the model/agent level, not per-call
- Comments, docstrings and string literals are blanked before any matching (#563). Prose
  that quotes a call shape, such as `# TODO: switch to client.responses.create(...)`, is not a
  call. A `max_tokens` that appears only in prose, in a commented-out kwarg, or inside a one-line
  string (`log("no max_tokens set")`, #968 review) is not a ceiling, so it no longer masks a real
  unbounded call in the same file. The one string kept is a literal that is exactly the kwarg
  name, the dict-key form of a real ceiling: `**{"max_tokens": 512}`,
  `extra_body={"max_completion_tokens": 100}`. Disclosed cost: a ceiling carried inside a longer
  string, such as a JSON blob `json.loads('{"max_tokens": 512}')`, is blanked with the rest of the
  string, so that call reads as unbounded and fires (over-alerting, pinned by
  `test_llm_input_size_cap_json_blob_ceiling_fires_disclosed`). Line numbers are preserved.
- The argument gate reads a candidate's arguments from `router_code_view`, at the same row and
  column, not from the view above. That view pairs quotes line by line, so on the row that closes
  a multi-line triple-quoted argument (`instructions="""...""", model="gpt-4o", input=q)`) its
  leftover delimiter paired with `model=`'s own quote and blanked the keyword, and a real
  `responses.create` was dropped (#1050 review, pinned by
  `test_llm_input_size_cap_gate_reads_past_a_triple_quoted_argument`). `router_code_view` finds
  comments and literals with the tokenizer, so neither that row nor a `)` in a comment inside a
  multi-line call (a numbered note, `# 1) ...`) can hide a `model=`.
- The opt-out pragma is read from the raw text, because it is itself a comment.

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `llm-input-size-cap/no-max-tokens` | HIGH | Direct LLM call with no `max_tokens` in file |
| `llm-input-size-cap/user-controlled-max-tokens` | MEDIUM | `max_tokens=request.*` or `max_tokens=user_*` |

## Known residuals (over-alerting)

Both err towards firing, as the guard did before the #561 argument gate:

- `split_call_args` does not track `[]`/`{}` depth, so a `**` spread inside a dict-literal argument
  of a non-LLM create (`survey.responses.create(answers={"q": a, **rest})`) reads as a top-level
  spread and confirms the call.
- A lambda default (`key=lambda a, model=None: a`) surfaces a top-level `model=`.

## Known residuals (under-alerting)

- By design, a real SDK call that spells none of `model=`, `messages=`, `prompt=`, `extra_body=` or
  a `**` spread is not a call site. A wrapper forwarding only a positional `*args` is the shape
  that reaches this, and a keyword-only SDK `create` raises on it at runtime.

## Opt-out

`# security: allow-unbounded-llm-input` anywhere in a file silences all findings for that file.
Use only when the token ceiling is enforced at the proxy/gateway layer (e.g. an API gateway that
caps tokens per request before forwarding to the LLM provider).

## False-negative scope

- Multi-file patterns: `max_tokens` set in one module, call in another — not detected.
- An SDK call whose arguments carry none of `model=`, `messages=`, `prompt=`, `extra_body=` or a
  `**` spread does not count (#561). The only measured instance, the Azure AI Foundry agent
  reference, is covered by `extra_body=`. A wrapper forwarding only a positional `*args` is not, but
  a keyword-only SDK `create` would reject that call at runtime anyway.
- The OpenAI Assistants API's `beta.threads.messages.create(thread_id=..., role=..., content=...)`
  no longer counts. It adds a message to a thread and generates nothing; that API's model call is
  `runs.create`, which this guard has never matched. OpenAI has deprecated the Assistants API.
- Non-standard call signatures (e.g. SDK wrapper subclasses that rename the parameter) — not
  detected.
- High-level frameworks (pydantic-ai, LangChain, LlamaIndex) — intentionally excluded; those
  frameworks use their own token-limit mechanism.

## Checklist mapping

`4-llm-input-cap-all-endpoints` (MANUAL → partial via this guard)

## Standards

- OWASP-LLM:LLM04 (Model Denial of Service)
- CWE-400 (Uncontrolled Resource Consumption)

## Related guards

- `llm-rate-limit-absent`: rate limiting at the HTTP layer (different axis — requests/minute vs
  tokens/request)
- `prompt-string-interp`, `string-format-injection`: user input into prompt content

# Citations

[1] agentsec checklist item `3a-llm-input-size-cap` (§3a)
[2] agentsec checklist item `4-llm-input-cap-all-endpoints` (§4)
[3] agentsec checklist item `4-llm-output-truncation` (§4)
[4] OWASP-LLM:LLM10
