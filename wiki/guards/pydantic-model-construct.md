---
type: Guard
title: "pydantic-model-construct"
description: "Pydantic model_construct() bypasses all field validators."
timestamp: "2026-08-19T00:00:00+08:00"
guard_id: "pydantic-model-construct"
checklist_section: ["3a"]
standards: ["OWASP:A03", "OWASP:A04"]
---

# Pydantic model_construct() bypasses all field validators

## Threat

Pydantic's `.model_construct()` (v2) and `.construct()` (v1) create model instances
without running any field validators, type coercions, or constraint checks. When a
developer passes untrusted external input — a request body, query parameter, or
third-party API payload — to these methods instead of the standard constructor or
`model_validate()`, the entire validation layer is silently skipped. Malformed,
out-of-range, or adversarially-crafted data reaches business logic and persistence
layers unchecked.

This is a variant of OWASP A03 (Injection / Improper Input Validation): the developer
believes Pydantic is guarding the boundary, but the guard has been bypassed by
construction API choice.

## Detection design

**Scope fix (corpus-scan precision pass, 2026-08-19).** Originally scanned every `.py` file
unconditionally and fired on every `.model_construct(`/`.construct(` call, one per matching
LINE (multi-line calls were only caught if the opening `(` line itself matched). A corpus scan
against real SDK repos (`openai-python`, `langchain`, the MCP Python SDK) surfaced 115+ findings,
all one shape: SDK-internal plumbing reconstructing its own typed request/response/control
objects — `FinalRequestOptions.construct(method="get", url=path, **options)`,
`Run.model_construct(**kwargs)` in a pydantic v1/v2 compat shim, `Response.model_construct(**resp)`
reconstructing an API response — none of them untrusted external input. Two independent fixes:

1. **`is_nonproduct_path` skip added.** Test fixtures deliberately exercising the unvalidated
   path (`SystemMessage.model_construct(content=[{"type": "text", "text": 42}])` in a real
   `test_codex.py`) were being scanned as if they were product code.
2. **Positive-evidence requirement.** The guard now scans the WHOLE file text (not per-line, so
   multi-line calls are caught via `split_call_args`) and only fires when the call's own argument
   text contains a substring matching `request|payload|body|input|data|params` (case-insensitive,
   plain substring — NOT `\b`-bounded, since Python treats `_` as a word character and `\brequest\b`
   would not match inside `request_data`, the guard's own canonical dangerous example).

```python
_CONSTRUCT_CALL = re.compile(r"\.model_construct\(|\.construct\(")
_UNTRUSTED_MARKER = re.compile(r"request|payload|body|input|data|params", re.I)
```

The leading `.` anchors `_CONSTRUCT_CALL` to a method call on an object, avoiding hypothetical
method names like `_reconstruct(`. No attempt is made to resolve whether the receiver is a
Pydantic model — the call site pattern plus the marker requirement is the signal; this is a
precision trade, not a data-flow proof (see "Known bypasses").

**Key-position fix (2026-08-26, #686 fix-commit round, High 1).** The 2026-08-22 fix (below)
blanked every quoted string in the call's argument text uniformly before the marker test, with
no distinction for WHERE a quote sits syntactically. That went too far the other direction:
`row["request_data"]`, `d["payload"]`, and `{"data": untrusted}` all name the untrusted field
via a quoted subscript/dict-literal KEY — the guard's own canonical shape one level removed —
and all three went silent, the exact false-negative regression the marker's whole design exists
to avoid. Fixed by only blanking a quoted string in a plain VALUE position; a string sitting in
a `[...]` subscript or immediately before a dict-literal `:` stays visible to the marker.

**Quoted-string-value fix (2026-08-22, Dean's review, High 1).** The marker was tested against
the call's whole argument text including quoted string LITERAL CONTENT, so
`model_construct(source="database_row")` fired on the substring "data" inside the label
`"database_row"`, with no untrusted-input-shaped identifier anywhere in the call. Fixed by
blanking ordinary (non-key-position, as of the 2026-08-26 refinement above) quoted string
content before the marker test.

## Severity rationale

**Medium.** The bypass itself is one factor removed from exploitation: the developer
must also pass untrusted data to the method. If internal/trusted data is always used
here the risk is low; however static analysis cannot confirm data provenance, so the
guard fires conservatively. The remediation (switch to `model_validate`) is low-effort
and non-breaking in well-structured code. Severity would rise to High if the call site
is directly processing a request body with no other validation layer present.

## Known bypasses / false negatives

| Scenario | Why missed | Risk |
|---|---|---|
| Variable aliased — `fn = SomeModel.model_construct; fn(**data)` | No `.model_construct(` literal call-site text | Low — unusual pattern |
| Dynamic dispatch via `getattr(Model, "model_construct")(**data)` | No literal method name in the text | Low — very uncommon |
| Custom class named `construct` unrelated to Pydantic | Flagged as false positive | Very low — name collision is rare |
| **Untrusted data under a name that doesn't match the marker** — `Model.model_construct(**x)` where `x` came from `await request.json()` two lines earlier | The call's own argument text has no `request`/`payload`/`body`/`input`/`data`/`params` substring | **Real recall loss, accepted deliberately** (2026-08-19 scope fix) — this guard does not trace where a spread variable's value originated, only what the call site's own text names it |

## False positive scenarios

| Scenario | Why it fires | Resolution |
|---|---|---|
| Rehydrating a fully-trusted DB row after schema migration into a variable still named `..._data`/`request_...` | Matches the untrusted-input marker | Confirm data is trusted; add `# security: allow-model-construct` |
| Non-Pydantic class with a `.construct(` method, called with a marker-matching arg name | Name collision | Add pragma if the class is not a Pydantic model |
| SDK-internal plumbing reconstructing a typed request/response/control object (`FinalRequestOptions.construct(method=..., **options)`) | **Largely fixed, not fully closed** (Dean's review, Medium 1, corrected 2026-08-22 — this row previously overclaimed "no longer fires"): re-measured against the same cached corpus the 2026-08-19 fix cites — openai-python 121→10, pydantic-ai 68→0, litellm 25→1, langchain 5→0, MCP SDK 1→1, fastapi 0→0. All 10 openai-python survivors are `FinalRequestOptions.construct(...)` sibling overloads that pass `json_data=body` — both `json_data` (contains "data") and `body` are themselves markers, so the kwarg NAME alone still satisfies the check regardless of what SDK-internal plumbing it carries. The MCP SDK's one finding is `model_construct(data=data)`, same shape. The name-based heuristic cannot distinguish these from a genuinely untrusted `data=` kwarg without deeper corpus-driven tuning (a follow-up, not part of this fix) | Real reduction (92%+ on the worst repo), residual FP class open |
| Test fixture deliberately exercising the unvalidated path | **No longer fires** — `is_nonproduct_path` skips it | N/A, fixed 2026-08-19 |

## Checklist items flipped

| ID | Status | Reason |
|---|---|---|
| 3a-no-pydantic-validation-bypass | `partial` | Guard detects `.model_construct()` and `.construct()` bypasses on the untrusted-input-shaped cases it can identify statically; test suite validates true-positive, silent, and pragma cases. (Corrected 2026-08-19: this table previously claimed `covered`, which never matched `checklist.json`'s actual `partial` status — left as `partial` here, not flipped, since fixing that mismatch wasn't in scope of this session's FP fix.) |

## Tests

| Test | Validates |
|---|---|
| `test_pydantic_model_construct_flags_model_construct` | True positive: `User.model_construct(**request_data)` fires a finding with the correct rule |
| `test_pydantic_model_construct_flags_construct_v1` | True positive: `.construct(name=data["name"])` (v1 API) also fires |
| `test_pydantic_model_construct_silent_safe_patterns` | False-positive guard: `User(**data)` and `User.model_validate(data)` stay silent |
| `test_pydantic_model_construct_pragma_silences_file` | Pragma: file containing `# security: allow-model-construct` produces no findings |
| `test_pydantic_model_construct_applies_gate` | Feature gate: guard applies when `python` in features; silent when not |
| `test_pydantic_model_construct_silent_sdk_options_reconstruction` | Real FP (corpus scan): `FinalRequestOptions.construct(method="get", url=path, **options)` stays silent |
| `test_pydantic_model_construct_silent_compat_shim_kwargs` | Real FP: `Run.model_construct(**kwargs)` in a compat shim stays silent |
| `test_pydantic_model_construct_silent_response_reconstruction` | Real FP: `Response.model_construct(**resp)` stays silent |
| `test_pydantic_model_construct_skips_nonproduct_path` | A marker-matching call inside `tests/` stays silent |
| `test_pydantic_model_construct_flags_multiline_call` | A `.model_construct(` call split across multiple lines is still caught, anchored to its opening line |
| `test_pydantic_model_construct_silent_on_docstring_example` | FP-bait (#424): a `.model_construct(`/`.construct(` example inside a docstring doesn't fire |

# Citations

[1] agentsec checklist item `3a-no-pydantic-validation-bypass` (§3a)
[2] OWASP:A03
[3] OWASP:A04
