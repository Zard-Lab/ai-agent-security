---
type: Guard
title: "ml-onnx-external-data"
description: "Flags a committed ONNX model declaring an external-data path that escapes its own directory, or an undisclosed custom operator."
timestamp: "2026-10-08T00:00:00Z"
guard_id: "ml-onnx-external-data"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM03", "OWASP:A01", "CWE-22"]
---

# Committed ONNX model declares an external-data path escape or a custom operator

_Author — 2026-10-08_

---

## The threat

ONNX stores tensor weights inline by default, but a tensor can instead point
at bytes in a SEPARATE file via an `external_data` location — a plain string
the model author chose, with no sandboxing. A location that walks out of the
model's own directory (`../../etc/passwd`, an absolute path, a UNC path, or a
URL) is the model declaring where to read from on disk the moment something
resolves it (CWE-22, Path Traversal). A custom operator (a domain outside
ONNX's standard set) is a separate signal: it cannot execute without a
matching native-code operator library being registered — a load the model's
consumer inherits sight-unseen from whoever built the model.

## Why this guard fits the stack

ONNX is one of the portable model-interchange formats a FastAPI + LLM/RAG
app's inference pipeline (ONNX Runtime) can load directly — `ml-artifact-
committed` already flags any `.onnx` file's mere presence; this guard looks
inside it.

## Detection design

1. `applies()` gates on `"llm" in profile.features`.
2. Scans `.onnx` via `iter_files`, `is_nonproduct_path()`-filtered, bytes
   capped at `_MAX_READ_BYTES` (8 MiB).
3. ONNX has no magic bytes — a `.onnx` file is a bare serialized
   `ModelProto` — so the file is walked directly as protobuf WIRE FORMAT
   with a minimal, schema-free reader (field numbers only; no `.proto`
   compiler, no `onnx`/`protobuf` package). Field numbers and declared
   lengths come from the file and are bounds-checked before use; a
   truncated message yields the fields wholly present rather than raising.
4. Walks the model's graph (field 7) recursively: every node's attributes
   are inspected for a NESTED subgraph (an `If`/`Loop`/`Scan` branch, fields
   6/11 of `AttributeProto`) and walked too (capped at `_MAX_GRAPH_DEPTH`),
   so a custom op or an escaping path hidden one branch down is still
   found, not just the top-level graph. Nesting past the cap is reported
   `scan-incomplete`, not silently dropped (PR #1049 review, M2).
5. For each node, the operator `domain` (field 7) is checked against the
   ONNX standard set (`""`, `ai.onnx`, `ai.onnx.ml`, `ai.onnx.training`,
   `ai.onnx.preview.training`) plus ONNX Runtime's own first-party domains
   from `include/onnxruntime/core/graph/constants.h` (`com.microsoft`,
   `com.microsoft.nchwc`, `com.microsoft.experimental`,
   `com.ms.internal.nhwc`, `com.microsoft.dml`, `org.pytorch.aten`), whose
   kernels ship inside ONNX Runtime; anything else is a custom operator,
   including `ai.onnx.contrib` (onnxruntime-extensions, a separately
   registered native library) and vendor execution-provider domains. A call
   to a function the model itself defines (a `functions` entry with that
   exact domain, field 10, and name, field 1; the dynamo exporter's local
   functions) is not a custom operator; field 9, the function's
   `opset_import`, lists domains it USES and is deliberately not exempted,
   and a dummy function cannot cover a different op in its domain. A
   function BODY's own nodes are judged like graph nodes, so a native custom
   op inside a local function still fires. Findings
   are one per custom domain (its first op types named), capped at
   `_MAX_REPORTED_DOMAINS`. The reader follows the protobuf semantics a
   runtime follows: a scalar or string field that repeats takes its LAST
   value (`data_location`, `domain`, `op_type`), and a singular message
   field that repeats (`graph`, an attribute's `g`/`t`) is MERGED, not read
   first-only. Every external-data tensor is checked as it is walked
   (initializers, `sparse_initializer`, attribute tensors and sparse
   tensors) in the main graph, in `training_info` graphs (ModelProto field
   20) and in local function bodies and default attributes (`functions`,
   field 25). For each tensor whose `data_location` (field 14) is `EXTERNAL`
   (1), EVERY `location` entry (not only the last one a loader uses; a
   benign model never carries an escaping one) is checked for a
   path-traversal/absolute/UNC/URL shape (`external_location_escapes`,
   textual resolution only: the point is judging what the file ASKS FOR,
   never touching the real filesystem). Distinct escaping locations are
   reported once each, capped at `_MAX_REPORTED_ESCAPES`.
6. Suppression is owner-side only: an entry in the exceptions/baseline
   file (`agentsec-exceptions.json`), or the path in `.agentsec/config.json`
   (`nonproduct_paths` demotes, `archive_paths` drops). There is deliberately
   NO in-file marker. The artifact is the untrusted thing being judged, so a
   byte string inside it is attacker-controlled: an earlier draft honoured
   `security: allow-<id>` anywhere in the file, and a malicious model carried
   its own opt-out after STOP / in a spare member / in string metadata
   (PR #1049 review, H3).
7. Fires `ml-onnx-external-data/path-escape` (CRITICAL) or
   `ml-onnx-external-data/custom-operator` (MEDIUM: a review signal, not
   proof of malice; some legitimate ONNX Runtime extensions use a custom
   op); and, when no path escape was found but the walk could not finish (a
   file larger than the read cap, a truncated or malformed protobuf, no
   graph at all, subgraphs nested past `_MAX_GRAPH_DEPTH`),
   `ml-onnx-external-data/scan-incomplete`, HIGH. A Git LFS pointer file is
   skipped.

## When NOT to flag

A standard-domain op (`Conv`, `Relu`, ..., or the default empty domain) and
an external-data location that stays within the model's own directory
(`weights/layer1.bin`, or `a/../b` which textually nets back to `b`) both
stay silent — see `test_scan_onnx_bytes_standard_domain_stays_silent` and
`test_external_location_escapes_stays_silent_on_benign_relative_path`.

## Tests

| Test | What it checks |
|---|---|
| `test_external_location_escapes_detects_traversal` | `../`, absolute, UNC, and URL-shaped locations are flagged. |
| `test_external_location_escapes_stays_silent_on_benign_relative_path` | FP-bait for the path-resolution logic. |
| `test_scan_onnx_bytes_finds_custom_operator` | A node with a non-standard domain is detected. |
| `test_scan_onnx_bytes_standard_domain_stays_silent` | FP-bait: `ai.onnx` domain stays silent. |
| `test_scan_onnx_bytes_default_empty_domain_stays_silent` | FP-bait: no domain (default) stays silent. |
| `test_scan_onnx_bytes_finds_external_data_escape` | An escaping external-data tensor is detected. |
| `test_scan_onnx_bytes_benign_external_data_stays_silent` | FP-bait: a same-directory external-data path stays silent. |
| `test_committed_onnx_custom_op_fires_end_to_end` | End-to-end: a `.onnx` file with a custom op fires MEDIUM. |
| `test_committed_onnx_path_escape_fires_critical_end_to_end` | End-to-end: a path-escaping tensor fires CRITICAL. |
| `test_ordinary_onnx_model_stays_silent_end_to_end` | End-to-end FP-bait. |
| `test_in_file_pragma_bytes_do_not_suppress` | The old in-file marker bytes, placed where the format ignores them, no longer silence the finding. |
| `test_nonproduct_path_skipped` | A fixture under `tests/fixtures/` is skipped. |
| `test_does_not_apply_without_llm_feature` | `applies()` is False with no `llm` feature. |
| `test_garbage_file_does_not_raise` | Garbage bytes never crash the scan, and are reported `scan-incomplete`, not clean. |
| `test_onnx_file_far_over_the_cap_is_not_loaded_whole` | A file far over the cap is read only up to it (tracemalloc peak bound), and still fires. |
| `test_model_cut_by_the_read_cap_is_reported_unscanned` | An escaping tensor pushed past the cap makes the result `scan-incomplete`, not clean. |
| `test_ordinary_onnx_model_is_not_reported_unscanned` | FP-bait: a complete model with inline and benign external data stays silent. |
| `test_onnx_git_lfs_pointer_is_not_scanned` | A Git LFS pointer is skipped. |
| `test_an_unexpected_scanner_error_is_contained_per_file` | Any scanner exception is contained to its file (`scan-incomplete`). |
| `test_onnx_runtime_first_party_domain_stays_silent` | FP fix: each ONNX Runtime first-party domain (`com.microsoft`, ...) stays silent. |
| `test_domains_outside_the_first_party_set_still_fire` | Still-fires: a lookalike, `ai.onnx.contrib` and a vendor EP domain stay flagged. |
| `test_custom_op_findings_are_one_per_domain` | 1,001 custom nodes in two domains give two findings, not 1,001. |
| `test_distinct_custom_domains_are_capped` | At most `_MAX_REPORTED_DOMAINS` findings, the last naming how many more. |
| `test_subgraphs_past_the_depth_cap_are_reported_unscanned` | A custom op nested past `_MAX_GRAPH_DEPTH` makes the result `scan-incomplete`. |
| `test_subgraphs_within_the_depth_cap_are_walked` | Still-fires: a custom op three subgraphs down is found. |
| `test_every_external_data_tensor_is_checked` | An escape in the 151st external tensor is found (entries were capped at 100). |
| `test_many_benign_external_tensors_stay_silent` | FP-bait: 300 benign external tensors stay silent. |
| `test_data_location_is_last_wins` | `data_location` DEFAULT then EXTERNAL is EXTERNAL (protobuf last-wins). |
| `test_node_domain_is_last_wins` | A custom LAST `domain` is reported. |
| `test_node_domain_last_wins_stays_silent_when_the_last_is_standard` | A standard LAST `domain` stays silent. |
| `test_a_repeated_graph_field_is_merged_not_first_only` | Two `graph` occurrences are merged, not first-only. |
| `test_sparse_initializer_external_data_is_checked` | `sparse_initializer` tensors are checked for external data. |
| `test_attribute_tensor_t_is_merged` | An attribute's `t` split across two occurrences is merged (first-wins and last-wins both miss it). |
| `test_sparse_tensor_parts_are_merged` | The same for sparse `values` and `indices`. |
| `test_attribute_sparse_tensors_are_checked` | Attribute `sparse_tensor` (22) / `sparse_tensors` (23) are checked. |
| `test_attribute_subgraph_g_is_merged_not_last_wins` | Evil-first `g` is merged, not last-wins. |
| `test_model_graph_is_merged_not_last_wins` | Evil-first ModelProto `graph` is merged, not last-wins. |
| `test_only_the_location_key_is_judged` | FP-bait: other `external_data` keys are not judged as paths. |
| `test_reported_escapes_are_capped_with_a_count_of_the_rest` | 25 escapes give 20 findings, the last naming the 5 more. |
| `test_any_escaping_location_entry_is_flagged` | An escaping `location` followed by a benign one is flagged. |
| `test_function_bodies_are_checked_for_external_data` | Local function body node attributes are checked. |
| `test_function_default_attributes_are_checked_for_external_data` | Function default attributes are checked. |
| `test_training_info_graphs_are_walked` | `training_info` initialization / algorithm graphs are walked. |
| `test_benign_functions_and_training_info_stay_silent` | FP-bait: benign external data in those sections stays silent. |
| `test_a_large_benign_onnx_model_is_high_incomplete_as_the_documented_cost` | Pins the documented cost: a benign model with 9 MiB of inline weights is HIGH incomplete. |
| `test_a_call_to_a_model_local_function_is_not_a_custom_operator` | FP fix: a graph call to a model-local function is not a custom op. |
| `test_a_local_function_call_inside_a_function_subgraph_is_not_custom` | FP fix: the same inside an If subgraph of a function body. |
| `test_an_undefined_op_in_a_local_function_domain_is_still_custom` | Still-fires: an op the model does not define stays custom even in a local-function domain. |
| `test_a_native_custom_op_inside_a_local_function_body_fires` | A native custom op in a local function's BODY fires (regression from the exemption). |
| `test_a_local_function_does_not_cover_the_same_name_in_another_domain` | Still-fires: function Dummy in domain A does not cover op Dummy in domain B (name-only mutant goes red). |
| `test_a_local_function_body_of_standard_ops_stays_silent` | FP-bait: a body of standard ops is clean. |
| `test_the_incomplete_finding_names_the_owner_opt_outs` | The HIGH incomplete finding's remediation names the owner-side opt-outs. |
| `test_a_capped_read_of_a_complete_looking_model_is_incomplete` | A capped read is incomplete even when the prefix parses completely. |

## What scan-incomplete means for the gate

**Expected noise: every ONNX model with more than 8 MiB of inline weights is
reported HIGH `scan-incomplete` and fails the default gate.** That is most
real ONNX models committed directly to git (LFS-tracked ones are pointer
files and are skipped). The seek-based walk that would step over inline
weights (aisbom's) is not ported, so the guard cannot see past the read cap,
and under fail-closed it says so instead of assuming the rest is benign. For
an audited model, opt out owner-side: an `agentsec-exceptions.json` entry
for that file, or its directory in `.agentsec/config.json`
`nonproduct_paths`.

`ml-onnx-external-data/scan-incomplete` is **HIGH**, so it DOES fail the
default `--fail-on high` gate. That is deliberate: the guards fail CLOSED on
untrusted artifacts. The verdict for one file is CRITICAL if any candidate
in any view holds a dangerous construct; otherwise HIGH if any candidate in
any view could not be fully scanned; otherwise clean. Three review rounds
each found a mirror-image hole in guessing which entry or view a loader
would use, so the guard no longer guesses: whatever it cannot inspect is
reported, not assumed benign. An attacker can still turn a CRITICAL into
this HIGH (by placing the escaping tensor or custom op after 8 MiB of inline
weights, nesting it past `_MAX_GRAPH_DEPTH` subgraphs, or breaking the
protobuf framing after the benign part), but the HIGH now blocks the merge
just the same. It is declared a review signal (`surfacing_rule_prefixes`),
so it ranks below a proven finding of the same severity. The owner-side
opt-outs for an audited artifact are an `agentsec-exceptions.json` entry or
the path in `.agentsec/config.json`.

Measured noise (2026-10-18, benign files through the real pipeline): HIGH on
a model with 20 MiB of inline weights; clean on a small model with inline
and benign external data.

## Known bypasses

Disclosed in the module docstring:

- A read is capped at `_MAX_READ_BYTES` (8 MiB) and parsed entirely in
  memory — aisbom's own streamed/seek-based walk for a multi-gigabyte file
  (stepping over inline weight data without buffering it) is not ported. A
  model larger than the read window is reported `scan-incomplete` (HIGH)
  rather than clean, so this is visible, not silent; the cost is a HIGH on
  every ordinary model with more than 8 MiB of inline weights until the
  streamed walk is ported.
- Memory amplification: the in-memory parse costs many times the bytes
  read. The final review measured 43x to 97x on dense shapes (flat varint
  fields, empty nodes, nodes with empty attributes), so one 8 MiB read can
  peak at about 818 MB; a weight-heavy file costs about 3x. A seek-based
  streaming walk would bound this and is not ported.
- The protobuf reader itself has no concept of ONNX's actual `.proto`
  schema beyond the field numbers used here — a future ONNX version that
  renumbers these fields would silently stop matching (mitigated by the
  field numbers being sourced from models serialized by the real `onnx`
  library, per aisbom's own sourcing note, not read off the spec by eye).

## What this guard does NOT prove

A clean result proves no recognized path escape or custom operator was
found in the graph structure this guard could reach within its read budget
— it does not prove the model's inline weight data (never inspected by this
or any guard here) is benign, nor that a custom operator it DOES flag is
actually malicious (it is a review signal).

`ml-artifact-committed` (MEDIUM, presence only) is the one signal that
remains when this content guard misses an artifact for a reason it cannot
detect (a sink outside the denylist, a format it does not parse): it fires on
every committed model file by extension, independent of what is inside.

# Citations

[1] agentsec checklist item `4-ml-onnx-external-data` (§4)
[2] OWASP-LLM:LLM03 — Supply Chain
[3] OWASP:A01 — Broken Access Control
[4] CWE-22 — Path Traversal
[5] Lab700xOrg/aisbom, `aisbom/protobuf_reader.py` + `aisbom/safety.py` +
    `aisbom/scanner.py` (Apache-2.0) — the source this guard's protobuf
    reader, field numbers, and detection signatures were ported from
