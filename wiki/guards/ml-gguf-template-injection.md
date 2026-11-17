---
type: Guard
title: "ml-gguf-template-injection"
description: "Flags a committed GGUF model whose embedded Jinja chat template carries a sandbox-escape construct."
timestamp: "2026-10-08T00:00:00Z"
guard_id: "ml-gguf-template-injection"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM01", "OWASP:A03", "CWE-94"]
---

# Committed GGUF model's chat template carries a Jinja sandbox-escape construct

_Author — 2026-10-08_

---

## The threat

A GGUF model's chat template is a Jinja template that runs on **every**
inference request to format the conversation before it reaches the model —
"the template runs" is not an extra precondition, it is what using the model
means. A template carrying an attribute-traversal chain
(`__class__.__mro__[1].__subclasses__()`-style), the `|attr()` filter, or a
call to `eval`/`subprocess`/`importlib`/... is a documented Jinja
server-side-template-injection sandbox escape (CWE-94), and it travels
*inside the model file itself* — a code review of the app's own source never
sees it. Different renderers sandbox differently (llama.cpp's `minja` has no
Python objects to reach for; `transformers.apply_chat_template` uses Jinja's
sandboxed environment, against which sandbox escapes are still published;
plain `jinja2.Template` is unsandboxed SSTI outright), so the construct is
worth flagging regardless of which one eventually renders it.

## Why this guard fits the stack

A FastAPI + LLM/RAG app running a local/quantized model via `llama-cpp-python`
or similar is exactly the shape that pulls in `.gguf` files — and the chat
template is metadata the app's own code typically never inspects; it trusts
the model file to carry a safe one.

## Detection design

1. `applies()` gates on `"llm" in profile.features`.
2. Scans `.gguf` via `iter_files`, `is_nonproduct_path()`-filtered, bytes
   capped at `_MAX_READ_BYTES` (8 MiB).
3. Confirms the `GGUF` magic, then walks the binary key-value metadata block
   with stdlib `struct` only (no `gguf`/`llama-cpp-python` package) — every
   declared string length and array count is bounds-checked against the
   bytes actually present before being used; running out of buffer sets
   `truncated=True` rather than raising.
4. Extracts `tokenizer.chat_template` and any named variants
   (`tokenizer.chat_template.<name>`, llama.cpp's convention for a model
   shipping several templates, e.g. a `.tool_use` variant).
5. Each template is scanned as a plain STRING — never rendered, parsed, or
   compiled — for: an attribute-traversal/introspection token
   (`__class__`/`__mro__`/`__subclasses__`/...), the `|attr()` filter, a
   dangerous callable (`eval`/`subprocess`/`importlib`/...) used as a call
   (an attribute form must be CALLED, `x.system(`, since
   `messages[0].system` is just a field name; a subscript form
   `x['system'](` is matched in the raw text, since its name is a string
   literal; not merely mentioned: `{% if role == 'system' %}` is a string
   comparison, not a call to `os.system`, and literals/comments are stripped
   before the call check runs, by a hand-written single-pass scan that is
   linear in the template length; a lazy-regex version re-scanned to the end
   from every unterminated `{#` or quote and stalled for minutes on a ~100
   KB template), a context-leaking object
   (`self._TemplateReference__context`, or `lipsum`/`cycler`/`joiner` with
   an attribute or subscript traversed off them, e.g. `cycler.__init__` or
   `lipsum['__glo'~'bals__']`; a variable named `joiner` or a plain
   `joiner(...)` call is their designed use), or a template-inclusion tag
   (`include`/`extends`/`import`/`from`).
6. Suppression is owner-side only: an entry in the exceptions/baseline
   file (`agentsec-exceptions.json`), or the path in `.agentsec/config.json`
   (`nonproduct_paths` demotes, `archive_paths` drops). There is deliberately
   NO in-file marker. The artifact is the untrusted thing being judged, so a
   byte string inside it is attacker-controlled: an earlier draft honoured
   `security: allow-<id>` anywhere in the file, and a malicious model carried
   its own opt-out after STOP / in a spare member / in string metadata
   (PR #1049 review, H3).
7. Fires `ml-gguf-template-injection/sandbox-escape` (CRITICAL) when an
   escape/attr-filter/dangerous-call/context-leak is found; otherwise
   `ml-gguf-template-injection/metadata-incomplete` (HIGH) when the metadata
   block did not fit the read budget (a non-critical template-inclusion note
   does not hide the cut), so a model whose template simply was not reached
   is not reported as clean.

## When NOT to flag

A template comparing a message's role against the string `'system'`, or one
with no attribute-traversal/dangerous-call shape at all, stays silent — see
`test_scan_jinja_template_role_comparison_stays_silent`.

## Canary scope (disclosed limitation)

The canary plant is a REAL, minimal GGUF container — magic bytes, version,
zero tensors, one KV pair naming `tokenizer.chat_template` — built with a
`struct.pack`-based encoder and verified programmatically against this
guard's own `scan_gguf_bytes` before being embedded as the plant, not
hand-typed hex escapes (an earlier draft of this guard's canary had an
off-by-one length-prefix bug caught exactly this way). Unlike the Keras
guard's canary (which can only exercise its text-fallback path), a GGUF
container's binary key-value format happens to be representable as valid
UTF-8 text for small field values, so this canary proves the REAL parser,
not a fallback.

## Tests

| Test | What it checks |
|---|---|
| `test_scan_jinja_template_finds_sandbox_escape` | A `__class__.__mro__...` chain is detected. |
| `test_scan_jinja_template_role_comparison_stays_silent` | FP-bait: comparing a role to `'system'` is not a call. |
| `test_scan_gguf_bytes_finds_sandbox_escape` | The real GGUF KV walk extracts and scans the template. |
| `test_scan_gguf_bytes_ordinary_template_stays_silent` | FP-bait for the GGUF walk. |
| `test_scan_gguf_bytes_non_gguf_stays_silent` | A non-GGUF file is a no-op, not an error. |
| `test_scan_gguf_bytes_named_template_variant` | A multi-template model tags findings with the variant key. |
| `test_scan_gguf_bytes_truncated_metadata_reports_incomplete` | A cut-off metadata block is flagged incomplete, not clean. |
| `test_committed_gguf_sandbox_escape_fires_end_to_end` | End-to-end: a `.gguf` file in a repo fires. |
| `test_ordinary_gguf_stays_silent_end_to_end` | End-to-end FP-bait. |
| `test_truncated_gguf_fires_incomplete_high_end_to_end` | End-to-end incomplete-scan HIGH finding. |
| `test_in_file_pragma_bytes_do_not_suppress` | The old in-file marker bytes, placed where the format ignores them, no longer silence the finding. |
| `test_nonproduct_path_skipped` | A fixture under `tests/fixtures/` is skipped. |
| `test_does_not_apply_without_llm_feature` | `applies()` is False with no `llm` feature. |
| `test_garbage_file_does_not_raise` | A bogus kv_count never crashes the scan. |
| `test_template_comment_and_literal_strip_is_linear` | Growth class: `"{#" * n` and `"{{ " + "'a\\" * n` scan linearly (were quadratic). |
| `test_template_strip_keeps_literal_and_comment_semantics` | The linear strip keeps the regex semantics: literals/comments hide tokens, unterminated openers hide nothing. |
| `test_gguf_file_far_over_the_cap_is_not_loaded_whole` | A file far over the cap is read only up to it (tracemalloc peak bound), and still fires. |
| `test_an_unexpected_scanner_error_is_contained_per_file` | Any scanner exception is contained to its file (`metadata-incomplete`). |
| `test_benign_attribute_and_variable_names_stay_silent` | FP fix: `.system`/`.compile` field reads, a `joiner` variable, a `joiner()` call stay silent. |
| `test_real_escape_shapes_still_fire` | Still-fires: dunder traversal, a real `.system(`/`.popen(` call, traversal off `lipsum`/`cycler`/`joiner`. |
| `test_payload_past_256_kib_of_template_fires` | An escape after 300,000 chars of padding fires (the template was cut at 256 KiB). |
| `test_cut_metadata_with_only_non_critical_threats_is_reported_incomplete` | A cut read is `metadata-incomplete` even when a non-critical inclusion was found. |
| `test_subscript_and_filter_escape_forms_fire` | Still-fires: `lipsum['__glo'~'bals__']`, `cycler[...]`, `x['system'](`, `|attr(`. |
| `test_subscript_reads_and_benign_names_stay_silent` | FP-bait: a subscript READ of a sink-named key, and the `joiner` baits, stay silent. |
| `test_subscript_call_pattern_lists_every_dangerous_call` | `_SUBSCRIPT_CALL` stays equal to `_DANGEROUS_CALLS`. |
| `test_a_malicious_named_variant_next_to_a_benign_default_fires` | A malicious `tool_use` variant next to a benign default fires CRITICAL (the finding, not just a threat string). |
| `test_named_variant_tag_survives_a_key_containing_a_bracket` | The variant tag is a suffix, so a key with `]` cannot break the check. |
| `test_benign_named_variants_stay_silent` | FP-bait: benign variants produce nothing. |
| `test_every_duplicate_chat_template_key_is_judged` | Every copy of a repeated `tokenizer.chat_template` key is judged (evil first and evil last). |
| `test_the_incomplete_finding_names_the_owner_opt_outs` | The HIGH incomplete finding's remediation names the owner-side opt-outs. |
| `test_an_attr_filter_only_variant_next_to_a_benign_default_fires` | An attr-filter-only variant next to a benign default fires CRITICAL (an equality check missed the tag). |
| `test_every_critical_kind_stays_critical_when_tagged` | Each critical threat kind stays critical with a variant tag. |
| `test_many_distinct_template_keys_are_merged_in_linear_time` | Growth: merging threats from n distinct template keys is linear (it was quadratic). |

## What metadata-incomplete means for the gate

`ml-gguf-template-injection/metadata-incomplete` is **HIGH**, so it DOES
fail the default `--fail-on high` gate. That is deliberate: the guards fail
CLOSED on untrusted artifacts. The verdict for one file is CRITICAL if any
candidate in any view holds a dangerous construct; otherwise HIGH if any
candidate in any view could not be fully scanned; otherwise clean. Three
review rounds each found a mirror-image hole in guessing which entry or view
a loader would use, so the guard no longer guesses: whatever it cannot
inspect is reported, not assumed benign. An attacker can still turn a
CRITICAL into this HIGH (by pushing the chat template past the 8 MiB read
cap with a large vocabulary array or other metadata stored before it), but
the HIGH now blocks the merge just the same. It is declared a review signal
(`surfacing_rule_prefixes`), so it ranks below a proven finding of the same
severity. The owner-side opt-outs for an audited artifact are an
`agentsec-exceptions.json` entry or the path in `.agentsec/config.json`.

Measured noise (2026-10-18, benign files through the real pipeline): HIGH on
a GGUF whose tokenizer vocabulary array (900,000 entries, 15 MB) precedes
the template; clean on a small model. Real large-vocabulary models (a 128k
to 150k token vocabulary plus BPE merges) can approach the 8 MiB window
before the template; that was not measured on a real model here.

## Per-file cost (disclosed)

The whole chat template is scanned, bounded only by the 8 MiB read cap. Each
check is linear, but there are about 33 of them (escape tokens, dangerous
calls, context leaks, the attr filter, subscript calls, inclusion tags, and
the comment/literal strip), so a template that fills the read window costs
roughly 5 to 9 s per file on a loaded machine (measured 2026-10-18). There is
no cross-file budget: a repo that commits N such `.gguf` files costs N times
that, and the audit's per-guard budget (which preempts and discloses an
over-budget guard) is the backstop. Real chat templates are a few KB.

## Known bypasses

- Only `tokenizer.chat_template` and its `.{name}` variants are inspected —
  a template under a different key convention is not found.
- The escape-token list is fixed; a sandbox-escape primitive not on the list
  (a future Jinja gadget) would not be recognized.
- A model whose metadata exceeds `_MAX_READ_BYTES` (8 MiB) before reaching
  the chat template key reports `metadata-incomplete` rather than a
  (potentially false) clean result: disclosed as HIGH, not silently dropped.

## What this guard does NOT prove

A clean result proves no recognized escape construct was found in the
template(s) this guard could reach — it does not prove the template is safe
to render under every possible Jinja environment, nor does it evaluate
anything else in the GGUF file (architecture, quantization, tensor data).

`ml-artifact-committed` (MEDIUM, presence only) is the one signal that
remains when this content guard misses an artifact for a reason it cannot
detect (a sink outside the denylist, a format it does not parse): it fires on
every committed model file by extension, independent of what is inside.

# Citations

[1] agentsec checklist item `4-ml-gguf-template-injection` (§4)
[2] OWASP-LLM:LLM01 — Prompt Injection
[3] OWASP:A03 — Injection
[4] CWE-94 — Code Injection
[5] Lab700xOrg/aisbom, `aisbom/safety.py` + `aisbom/scanner.py` (Apache-2.0) —
    the source this guard's GGUF metadata walk and Jinja-escape detection
    were ported from
