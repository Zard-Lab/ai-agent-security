---
type: Guard
title: "llm-json-output-unvalidated"
description: "LLM response text parsed as JSON without Pydantic schema validation."
timestamp: "2026-07-01T17:37:26+08:00"
guard_id: "llm-json-output-unvalidated"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM05", "OWASP:A03"]
---

# LLM response text parsed as JSON without Pydantic schema validation

_Author — 2026-07-01_

---

## The threat

A structured-output pipeline asks the model to return JSON, parses the response text
with `json.loads(...)`, and uses the resulting dict's fields directly in a decision — a
permission check, a payment amount, a routing choice. The model's output is attacker-
influenceable through prompt injection (an attacker can steer the model toward emitting
`{"is_admin": true}` or a manipulated numeric field) or simply non-deterministic. Without
schema validation, nothing constrains the keys, types, or ranges the calling code
assumes are present. OWASP-LLM:LLM05 (Improper Output Handling), OWASP:A03
(Injection — untrusted structured data flowing to a sink without validation).

A secondary, lower-severity risk: if the model doesn't return valid JSON at all, the bare
`json.loads(...)` call raises with no recovery path.

## Why it's often introduced

Prompt engineering makes the model return JSON reliably enough in testing that the
schema-validation step feels redundant — "the model already returns the right shape":

```python
def handle(prompt):
    response = llm.invoke(prompt)
    data = json.loads(response.content)      # trusted immediately
    if data["is_admin"]:
        grant_admin()
```

This mirrors `upstream-response-unvalidated`'s pattern for external HTTP API responses,
applied to the LLM's own output — llm-guard's `JSON` output scanner exists to close
exactly this gap.

## Detection design

1. **applies() gate:** `"llm" in profile.features` — only runs for detected LLM stacks.

2. **Files scanned:** All `.py` files via `iter_files(d, (".py",))` from
   `python_scan_dirs`. Non-product paths (tests, fixtures) skipped via
   `is_nonproduct_path`.

3. **Pattern (`no-schema-validation`, HIGH):**
   - For each `json.loads(...)`, collects LLM-result variable names assigned within the
     **enclosing function** (`_enclosing_def_span` — NOT file-wide, so a `response` from an
     LLM call in one function can't taint a same-named `response` in another; the review's
     reproduced FP). Unambiguous framework methods (`.invoke`/`.generate`/`.chat`/`.complete`/
     `.ainvoke`) always count; the overloaded `.create(` counts only when the file imports an
     LLM SDK (`_LLM_SDK_IMPORT`) — else it matches stripe/ORM/boto3. Module-level `json.loads`
     keeps file scope.
   - Checks whether the `json.loads` argument references any of those names (word-boundary match —
     covers `json.loads(response.content)`, `json.loads(response.choices[0].message.
     content)`, etc.).
   - If it does, checks the same line AND the next non-blank line for a schema-validation call
     whose OWN argument correlates with the value `json.loads(...)` just produced
     (`_validated_nearby` / `_validation_targets`) — **not just any validation-shaped call
     nearby**. The parsed value's own assignment target is captured by `_JSON_LOADS_ASSIGN`
     (`x = json.loads(...)` → `x`); a validation call (`.model_validate(`, `.parse_obj(`,
     `TypeAdapter(...).validate_python(`, or a `SomeModel(**x)` construction) silences the
     finding only when its argument references that captured name. One hop of plain
     reassignment between the parse and the validation call is tracked (`cleaned =
     strip_nulls(data)` then `Model.model_validate(cleaned)` — `_STRAIGHT_REASSIGN` widens the
     correlated-name set by one name for the line right after such a reassignment, mirroring how
     `_LLM_RESULT_VAR` tracking already widens the LLM-result-var set). When the `json.loads(...)`
     result isn't captured by a simple single-name assignment (no `_JSON_LOADS_ASSIGN` match —
     e.g. it's returned or used inline), there is no name to correlate against, so the check
     falls back to the original presence-only `_SCHEMA_VALIDATE` signal for that line pair.
     Absent (correlated or fallback) on both lines → fire.

   **2026-08-22 — correlation fix (checklist gap closed):** originally the same-line/next-line
   check only asked "does ANY schema-validation-shaped call appear here", never whether that
   call's argument was the value `json.loads(...)` actually produced. `data =
   json.loads(response.content)` immediately followed by an unrelated `other =
   SomeModel(**other_dict)` silenced the finding even though `data` — the value used in the
   decision — was never validated. Every existing FP-bait test happened to reuse the same
   variable name for both the parse and the validation call, so this correlation gap went
   unexercised. Closed by requiring the validation call's own argument to reference the parsed
   value's name (or a tracked one-hop alias of it), not just co-occur on the same/next line.

4. **Inline opt-out pragma:** `# security: allow-llm-json-unvalidated`

5. **Severity and rule:** `"high"`, rule
   `"llm-json-output-unvalidated/no-schema-validation"`, standards
   `["OWASP-LLM:LLM05", "OWASP:A03"]`.

## When NOT to flag

- `json.loads(...)` on something that isn't an LLM result at all (a request body, a
  config file) — the guard only fires when the parsed argument references a name
  collected from an LLM call in the same file.
- A schema-validation call on the same line (`Model.model_validate(json.loads(...))`) or
  the very next non-blank line (`raw = json.loads(...)` then `Model.model_validate(raw)`)
  **that validates the parsed value itself** — treated as validated. A validation call on
  those lines that targets a DIFFERENT variable no longer silences the finding. The tracked
  name can appear anywhere in the validation call's own argument list — a bare reference, a
  keyword argument (`Model.model_validate(obj=data)`), wrapped in another call
  (`Model.model_validate(dict(data))`), or as the iterable of a list-comprehension loop
  variable (`[Model.model_validate(x) for x in data]`) — not only immediately after the
  open paren.
- One hop of plain reassignment between the parse and the validation call (`data =
  json.loads(...)` → `cleaned = strip_nulls(data)` → `Model.model_validate(cleaned)`) is
  still recognized as validating the parsed value.
- **The SDK response *envelope*, rather than the model's text** (#715). Every LLM SDK
  checked (openai, anthropic, litellm, langchain-core, google-genai) builds its response
  types on `pydantic.BaseModel`, so `resp.json()`, `resp.model_dump_json()`,
  `resp.to_dict()` and friends re-serialize the SDK's OWN typed object. Its shape is the
  SDK's API contract, not something the model authored, so schema-validating it is not
  the app's job. The idiom that triggered this — "coerce an SDK object to a plain dict,
  robustly, across SDK versions" — reaches for several *envelope* accessors in a fallback
  chain, never a content accessor:

  ```python
  if hasattr(resp, "model_dump"):
      return resp.model_dump()
  return json.loads(resp.json()) if hasattr(resp, "json") else dict(resp)
  ```

  The discrimination is **accessor-based, and positional**: the guard silences only when an
  envelope serializer is the *terminal* call of the argument. The model's text is reached
  by a disjoint set of names (`.content`, `.text`, `.output_text`, `.arguments`), and code
  that indexes *through* a serializer into one of them still fires. See the pair
  `test_fp_bait_sdk_response_envelope_deserialization` /
  `test_fires_when_envelope_is_indexed_into_model_text`.

## Tests

| Test | What it checks |
|---|---|
| `test_applies_when_llm_feature_present` | Guard activates on `llm` feature |
| `test_not_applies_without_llm_feature` | Guard skips non-LLM stacks |
| `test_fires_on_unvalidated_json_parse` | Fires: `json.loads(response.content)`, no validation |
| `test_fp_bait_same_line_model_validate` | Silent: `Model.model_validate(json.loads(...))` same line |
| `test_fp_bait_next_line_model_validate` | Silent: `.model_validate(raw)` on the next line |
| `test_fp_bait_next_line_model_construct` | Silent: `Model(**raw)` construction on the next line |
| `test_fp_bait_json_loads_unrelated_to_llm` | Silent: `json.loads` on a non-LLM value |
| `test_fp_bait_when_pragma_present` | Silent: file-level pragma |
| `test_fires_when_validation_targets_unrelated_variable` | Fires: a validate-shaped call sits on the next line but validates an UNRELATED variable, not the parsed `data` (the checklist gap) |
| `test_fires_when_typeadapter_validates_unrelated_variable` | Fires: same gap, `TypeAdapter(...).validate_python(...)` flavor |
| `test_fp_bait_typeadapter_validates_parsed_var` | Silent: `TypeAdapter(...).validate_python(data)` correlated to the parsed var |
| `test_fp_bait_validation_after_one_hop_reassignment` | Silent: `cleaned = strip_nulls(data)` then `Model.model_validate(cleaned)` — one-hop alias correctly still counts as validated |
| `test_fp_bait_sdk_response_envelope_deserialization` | Silent: `json.loads(resp.json())`, the SDK envelope (#715) |
| `test_fp_bait_model_dump_json_envelope` | Silent: `json.loads(resp.model_dump_json(...))` |
| `test_fires_when_envelope_is_indexed_into_model_text` | Fires: serializer indexed through to `['content']` |
| `test_fires_on_tool_call_arguments` | Fires: `function.arguments`, model-generated JSON by OpenAI's own docs |
| `test_fires_when_content_accessor_ends_in_a_call` | Fires: `response.content.strip()` — a trailing call is not a serializer |
| `test_dump_then_extract_then_parse_is_a_known_limit` | Pins the documented FN: envelope dumped, text extracted, then parsed |
| `test_quoted_paren_in_argument_fails_toward_firing` | Pins the safe direction of the non-quote-aware scan |
| `test_fp_bait_model_validate_list_comprehension` | Silent: `[Model.model_validate(x) for x in data]` — H5 |
| `test_fp_bait_model_validate_keyword_argument` | Silent: `Model.model_validate(obj=data)` — H5 |
| `test_fp_bait_model_validate_wrapped_in_dict_call` | Silent: `Model.model_validate(dict(data))` — H5 |

## Known bypasses

- The LLM-result variable renamed via a plain reassignment before `json.loads` (e.g.
  `text = response.content` then `json.loads(text)`) is not tracked — the guard only
  recognizes the ORIGINAL variable name captured from the generation-call assignment.
- Validation more than one non-blank line after the `json.loads(...)` call (or more than
  one hop of straight reassignment past it) is not detected — the window is intentionally
  narrow to stay low-noise.
- When `json.loads(...)`'s result isn't captured by a simple `x = json.loads(...)`
  assignment (used inline, returned directly, tuple-unpacked), there is no single name to
  correlate a validation call against, so correlation falls back to the original
  presence-only check for that line pair — a validation call anywhere on those lines
  silences it regardless of what it validates.
- A validation call that exists and correlates but is a no-op (e.g. a schema with every
  field `Optional[Any]`) silences the rule without providing real protection.
- The LLM result assigned in an OUTER function and consumed by a `json.loads` inside a
  NESTED inner function is not tracked — variable scoping is to the innermost enclosing
  `def` (`_enclosing_def_span`), which deliberately does not walk into enclosing closures.
- The pragma `# security: allow-llm-json-unvalidated` silences the rule for the entire
  file.
- **Dump the envelope, extract the model's text, then parse THAT** is not tracked, and this
  is the largest gap in the guard:

  ```python
  data = json.loads(resp.model_dump_json())          # envelope, silenced (#715)
  content = data["choices"][0]["message"]["content"]  # the model's text, now a plain name
  parsed = json.loads(content)                        # THE THREAT -- and it is missed
  ```

  The last line is the shape the guard exists to catch, and it is missed because `content`
  is a derived name rather than one captured from the generation-call assignment. This is
  the one-hop derivation limit above, not a cost of the #715 envelope silence: **measured
  against the pre-#715 guard, that line is missed identically.** What the pre-#715 guard did
  emit was a finding on the *envelope* line, whose message ("nothing guarantees the parsed
  dict has the keys, types, or ranges") is untrue of an SDK envelope, so it was adjacency
  rather than coverage. Closing this properly means tracking one-hop derivation, which is a
  larger change than #715. Pinned by
  `test_dump_then_extract_then_parse_is_a_known_limit` so it cannot drift silently.
- An envelope serializer wrapped in another call, e.g.
  `json.loads(json.dumps(resp.model_dump()))`, still fires: the terminal call is
  `json.dumps(`, so the envelope test does not recognize it. A residual FALSE POSITIVE
  (#715), left documented rather than special-cased, because the shape is a contrived
  double round-trip and widening the test costs true positives.
- The argument-expression scan is capped at 400 characters
  (`_ARG_SCAN_LIMIT`); an envelope serializer that terminates past that cap is not
  recognized, so such a line keeps firing. The cap exists because the argument is walked
  per raw source line, and the `#676` hang was caused by exactly this path being
  unbounded.

## What this guard does NOT prove

- That the schema, if present, actually constrains the fields the code later trusts for
  a privileged decision (a permissive schema passes this check but provides no real
  protection).
- That a `try/except` around the parse (if present) is scoped correctly — this guard
  does not consider exception handling at all, only schema validation.
- Multi-file or multi-function dataflow: an LLM result stored, passed to another
  function, and parsed there is not tracked.

# Citations

[1] agentsec checklist item `4-llm-json-output-validated` (§4)
[2] OWASP-LLM:LLM05
[3] OWASP:A03
