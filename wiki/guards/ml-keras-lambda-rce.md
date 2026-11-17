---
type: Guard
title: "ml-keras-lambda-rce"
description: "Flags a committed Keras model file (.keras/.h5/.hdf5) embedding a Lambda layer or a marshalled code object."
timestamp: "2026-10-08T00:00:00Z"
guard_id: "ml-keras-lambda-rce"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM03", "OWASP:A08", "CWE-502"]
---

# Committed Keras model file embeds a Lambda-layer code-execution vector

_Author — 2026-10-08_

---

## The threat

A Keras `Lambda` layer stores an arbitrary Python callable as part of the
model's own config — restoring the model calls that callable. This is an
actively exploited remote-code-execution vector in model-sharing pipelines
(the CVE-2025-1550 class), distinct from the pickle-opcode route
`ml-pickle-dangerous-global` already covers: a Keras container's config is
JSON (`.keras`) or bytes embedded in an HDF5 attribute (legacy `.h5`), and the
payload can be the Lambda layer itself or a `marshal`-encoded code object
nested inside one.

## Why this guard fits the stack

Keras is one of the two mainstream model-serialization ecosystems a FastAPI +
LLM/RAG app's own fine-tuning/caching step can produce alongside PyTorch —
`ml-artifact-committed` already flags any `.keras`/`.h5`/`.hdf5` file's mere
presence; this guard looks inside the ones it can.

## Detection design

1. `applies()` gates on `"llm" in profile.features`.
2. Scans `.keras .h5 .hdf5` via `iter_files`, `is_nonproduct_path()`-filtered,
   bytes capped at `_MAX_READ_BYTES` (8 MiB).
3. Every file gets BOTH views, whatever its extension and whichever comes
   first, and neither returns early. The zip view: the zip is found by its
   end-of-central-directory record wherever it starts (zipfile, and Keras
   through `zipfile.is_zipfile`, do the same), its declared directory size
   checked against `_MAX_ZIP_DIRECTORY_BYTES`, and EVERY root `config.json`
   entry (same-named duplicates included, the last one, which Keras loads,
   read first) is read through one shared decompressed-byte budget with
   `zip_member_prefix`, so a zip bomb is never inflated whole. A zip whose
   directory zipfile refuses is recovered from its local file headers
   (`_recover_zip_members`, stdlib `struct` + `zlib`, capped at 32 members
   and `_MAX_READ_BYTES` of output) for a signature scan, and reported
   incomplete if that finds nothing.
4. The HDF5 view (legacy `.h5`/`.hdf5`): no HDF5 structure (B-trees, heaps,
   object headers) is decoded. What is judged: (a) for each occurrence of
   the `model_config` attribute name in the read window, the first JSON
   object after it that parses (`_extract_h5_configs`, a string-aware
   brace-match), up to 16 occurrences with one shared 8 MiB brace-scan
   budget, more being `scan-incomplete`; (b) ALWAYS, the Lambda byte
   signatures over the whole window, because an h5py `str` attribute is only
   a variable-length reference whose JSON lives in a global heap elsewhere,
   so the first object after the name can be an unrelated attribute such as
   `{}`; (c) when the read was capped, the rest of the file streamed in 1
   MiB chunks (with overlap at the window end and every chunk boundary) for
   the same signatures, which are CRITICAL, and for the name, which alone is
   `scan-incomplete`. A config that is neither parsed nor carries a literal
   signature (an unusually spaced `"class_name"`) can still be missed. A
   file with no marker anywhere is weights-only or plain HDF5 data: no
   config to deserialize.
5. A recovered config is walked structurally (`scan_keras_config`,
   iterative, uncapped in depth, one iterator frame per level so memory
   follows depth, not width) for a `class_name` of `Lambda` or Keras 3's
   `__lambda__` serialized-callable tag, and for any string value that
   decodes as base64 with a CPython `marshal` code-object header
   (`TYPE_CODE`/`0x63` or the `FLAG_REF` variant `0xE3`, followed by three
   zero bytes); the payload is identified from this header alone and never
   unmarshalled, and `marshal` is not imported anywhere in this module (it
   is in `guard_sandbox.py`'s banned import list).
6. When no JSON can be recovered at all, falls back to a coarse byte-
   signature scan (`scan_keras_config_bytes`) for the literal
   `"class_name": "Lambda"` shape — less precise (can't name the layer), but
   still fires rather than reporting a damaged file as clean.
7. Suppression is owner-side only: an entry in the exceptions/baseline
   file (`agentsec-exceptions.json`), or the path in `.agentsec/config.json`
   (`nonproduct_paths` demotes, `archive_paths` drops). There is deliberately
   NO in-file marker. The artifact is the untrusted thing being judged, so a
   byte string inside it is attacker-controlled: an earlier draft honoured
   `security: allow-<id>` anywhere in the file, and a malicious model carried
   its own opt-out after STOP / in a spare member / in string metadata
   (PR #1049 review, H3).
8. Fires `ml-keras-lambda-rce/lambda-layer` or
   `ml-keras-lambda-rce/marshalled-code`, both CRITICAL, when any candidate
   in either view carries one; otherwise
   `ml-keras-lambda-rce/scan-incomplete`, HIGH, when any candidate could not
   be fully scanned (a `config.json` entry zipfile rejects, the member cap
   or shared budget hit, a config cut by the read cap or nested past the
   JSON parser's limit, a `model_config` that could not be recovered, a zip
   with no `config.json` and no HDF5 view, a file that is neither
   container). A Git LFS pointer file is skipped.

## When NOT to flag

An ordinary `Dense`/`Conv2D`/... layer config carries no `Lambda` class name
and no base64 string matching the marshal code-object header shape — see
`test_ordinary_keras_zip_stays_silent` / `test_ordinary_hdf5_shaped_file_stays_silent`.

## Canary scope (disclosed limitation)

`agentsec`'s canary-plant mechanism writes every guard's plant as UTF-8 TEXT
(`CanaryPlant.files: Mapping[str, str]`) — a genuine `.keras` zip or HDF5
file is binary and cannot be planted through it. This guard's canary plants a
plain-text byte-signature match (the same shape `scan_keras_config_bytes`'s
fallback path looks for) rather than a real container, so `agentsec doctor
--canary` proves the **fallback signature path** is wired end-to-end, not the
real zip/HDF5 parsers. Those are proven by the pytest suite instead, against
genuine binary fixtures (`_make_keras_zip`, `_make_hdf5_shaped`, and a
hand-built damaged-zip-with-local-headers-only fixture) — see the Tests
table below.

## Tests

| Test | What it checks |
|---|---|
| `test_lambda_layer_in_keras_zip_fires` | A real `.keras` zip's `config.json` with a `Lambda` layer is detected. |
| `test_ordinary_keras_zip_stays_silent` | FP-bait: a `Dense`-only `.keras` zip stays silent. |
| `test_lambda_layer_in_hdf5_shaped_file_fires` | The HDF5 attribute byte-scan recovers a `Lambda` layer. |
| `test_ordinary_hdf5_shaped_file_stays_silent` | FP-bait for the HDF5 path. |
| `test_damaged_zip_recovers_lambda_from_local_headers` | A zip with no central directory still yields its `Lambda` layer via local-header recovery. |
| `test_marshalled_code_object_fires` | A real `marshal.dumps()` code object, base64-embedded in a config string, is detected from its header alone. |
| `test_committed_keras_lambda_fires_end_to_end` | End-to-end: a `.keras` file in a repo fires. |
| `test_ordinary_checkpoint_stays_silent_end_to_end` | End-to-end FP-bait. |
| `test_in_file_pragma_bytes_do_not_suppress` | The old in-file marker bytes, placed where the format ignores them, no longer silence the finding. |
| `test_nonproduct_path_skipped` | A fixture under `tests/fixtures/` is skipped. |
| `test_does_not_apply_without_llm_feature` | `applies()` is False with no `llm` feature. |
| `test_garbage_file_does_not_raise` | Garbage bytes never crash the scan, and are reported `scan-incomplete`, not clean. |
| `test_config_member_far_over_the_cap_is_not_inflated_whole` | A deflate-bomb `config.json` is inflated only up to the cap (tracemalloc peak bound), and still fires. |
| `test_damaged_zip_salvage_does_not_inflate_a_bomb_whole` | The local-header salvage path bounds its inflate to the read budget. |
| `test_keras_file_far_over_the_cap_is_not_loaded_whole` | A file far over the cap is read only up to it (peak bound). |
| `test_keras_zip_larger_than_the_read_cap_still_fires` | A 9 MiB `.keras` zip with `config.json` past the cap still fires CRITICAL. |
| `test_keras_zip_without_config_is_reported_unscanned` | A zip with no `config.json` is `scan-incomplete`. |
| `test_h5_whose_model_config_cannot_be_recovered_is_reported_unscanned` | A `model_config` that cannot be recovered is `scan-incomplete`. |
| `test_weights_only_h5_and_ordinary_models_are_not_reported_unscanned` | FP-bait: weights-only HDF5 and ordinary models stay silent. |
| `test_keras_git_lfs_pointer_is_not_scanned` | A Git LFS pointer is skipped. |
| `test_deeply_nested_zip_config_does_not_raise` | A config nested past the interpreter's recursion limit (zip) does not raise. |
| `test_deeply_nested_h5_config_does_not_raise` | The same for the HDF5 `model_config` extraction. |
| `test_one_hostile_file_does_not_hide_the_others` | A hostile file is reported `scan-incomplete` and the next file is still judged. |
| `test_an_unexpected_scanner_error_is_contained_per_file` | Any scanner exception is contained to its file (`scan-incomplete`). |
| `test_duplicate_config_json_entries_are_all_scanned` | An evil-first duplicate `config.json` entry is scanned. |
| `test_lambda_under_deeply_nested_models_fires` | A Lambda under 80 nested Sequentials fires (the walk stopped at depth 200). |
| `test_deeply_nested_ordinary_model_stays_silent` | FP-bait: the same nesting with no Lambda stays silent. |
| `test_config_walk_path_label_stays_bounded_at_any_depth` | The walk's path label is capped, so a 5,000-deep config stays linear. |
| `test_keras_zip_with_prepended_bytes_is_still_read_as_a_zip` | A zip with bytes prepended is found by its end record and its Lambda fires CRITICAL. |
| `test_keras_zip_with_prepended_bytes_and_ordinary_config_stays_silent` | FP-bait: the same container with an ordinary model is clean, not incomplete. |
| `test_many_distinct_lambda_layers_are_merged_in_linear_time` | Growth: merging n distinct Lambda labels is linear (it was quadratic). |
| `test_a_corrupt_decoy_config_does_not_abort_the_real_scan` | A bad-CRC decoy `config.json` no longer hides the real one. |
| `test_the_last_config_entry_keras_loads_is_scanned_past_the_cap` | The last same-named `config.json` (the one Keras loads) is always scanned past the cap. |
| `test_hdf5_magic_zip_polyglot_is_read_as_a_zip` | An HDF5-magic + zip polyglot `.keras` fires CRITICAL (it read clean). |
| `test_hdf5_files_without_a_zip_are_unchanged` | FP-bait: weights-only HDF5 (even with a stray end-record signature) stays silent; an HDF5 Lambda still fires. |
| `test_all_config_entries_share_one_read_budget` | All `config.json` entries share ONE decompressed-byte budget. |
| `test_config_walk_memory_is_proportional_to_depth_not_width` | A 500,000-wide config walks under a 4 MiB tracemalloc peak (it was 109 MB). |
| `test_more_config_entries_than_the_cap_is_reported_unscanned` | More `config.json` entries than the cap is `scan-incomplete`. |
| `test_a_large_decoy_config_cannot_starve_the_config_keras_loads` | A 9 MiB decoy config first cannot starve the last one (Keras loads it): CRITICAL. |
| `test_hdf5_lambda_with_an_appended_benign_zip_fires` | An HDF5 Lambda behind an appended benign zip fires: both views are scanned. |
| `test_ordinary_keras_models_stay_silent_under_fail_closed` | FP-bait: ordinary `.keras`, `.h5` and weights-only files stay silent. |
| `test_a_decoy_model_config_cannot_hide_the_real_attribute` | A decoy `model_config` in a user block no longer hides the real Lambda attribute. |
| `test_hostile_repeated_model_config_markers_scan_linearly` | Growth: `model_config{` repeated scans linearly (it was quadratic). |
| `test_more_model_config_candidates_than_the_cap_is_high` | More candidates than the cap is `scan-incomplete`. |
| `test_a_model_config_past_the_read_window_is_high` | A marker past the read window is HIGH (it read clean). |
| `test_a_large_weights_only_hdf5_file_stays_silent` | FP-bait: a capped weights-only HDF5 file is clean. |
| `test_the_incomplete_finding_names_the_owner_opt_outs` | The HIGH incomplete finding's remediation names the owner-side opt-outs. |
| `test_a_vlen_heap_config_behind_a_junk_brace_attribute_fires` | An h5py vlen-heap config behind a junk `{}` attribute fires CRITICAL (it read clean). |
| `test_a_vlen_heap_config_past_the_read_window_fires` | The same with the heap past the read window fires CRITICAL. |
| `test_a_lambda_past_the_window_with_its_marker_is_critical_not_high` | A Lambda signature past the window is CRITICAL, not only HIGH. |
| `test_a_benign_vlen_heap_config_stays_silent` | FP-bait: ordinary vlen-heap configs, in and past the window, are clean. |
| `test_a_marker_straddling_the_window_end_is_found` | A marker straddling the read-window end is found (the seek-to-start mutant goes red). |
| `test_a_marker_straddling_a_chunk_boundary_is_found` | A marker straddling a 1 MiB chunk boundary is found (the drop-the-tail mutant goes red). |
| `test_a_lambda_signature_straddling_a_chunk_boundary_is_critical` | A Lambda signature straddling a chunk boundary is CRITICAL. |

## What scan-incomplete means for the gate

`ml-keras-lambda-rce/scan-incomplete` is **HIGH**, so it DOES fail the
default `--fail-on high` gate. That is deliberate: the guards fail CLOSED on
untrusted artifacts. The verdict for one file is CRITICAL if any candidate
in any view holds a dangerous construct; otherwise HIGH if any candidate in
any view could not be fully scanned; otherwise clean. Three review rounds
each found a mirror-image hole in guessing which entry or view a loader
would use, so the guard no longer guesses: whatever it cannot inspect is
reported, not assumed benign. An attacker can still turn a CRITICAL into
this HIGH (by making a config unreadable: a BZIP2/LZMA or corrupt
`config.json`, JSON nested past the parser's recursion limit, a damaged zip,
a config over the read cap, or more entries than the cap or budget), but the
HIGH now blocks the merge just the same. It is declared a review signal
(`surfacing_rule_prefixes`), so it ranks below a proven finding of the same
severity. The owner-side opt-outs for an audited artifact are an
`agentsec-exceptions.json` entry or the path in `.agentsec/config.json`.

Measured noise (2026-10-18, benign files through the real pipeline): clean
on an ordinary `.keras` with a 10 MiB weights member and on a 20 MiB
weights-only `.h5`. I/O cost: every HDF5 file over the 8 MiB cap with no
CRITICAL in its first 8 MiB (every large weights file and every large clean
model) is streamed to its end once, in 1 MiB chunks, for the `model_config`
marker and the Lambda signatures.

## Known false positive (a maintainer decision)

A benign large Keras `.h5` can draw HIGH `scan-incomplete` ("more
model_config candidates than the scan budget allows"): when the
variable-length reference stored after the `model_config` name happens to
contain a `{` byte and the weights are all zeros, the brace scan runs to the
end of the window and exhausts the budget. The final review measured this at
about 1% of such files. It is left as is (fail closed) for the maintainer to
decide; the owner-side opt-out applies.

## Known bypasses

- The byte-signature fallback only recognizes the literal
  `"class_name": "Lambda"` shape (four whitespace variants) — a config
  serialized with unusual spacing or by a non-standard JSON writer can evade
  it, though the structured JSON-walk path would still have caught the same
  model if the container parsed cleanly.
- `_recover_zip_members` caps recovery at 32 members; a `.keras` archive
  deliberately padded with more than that before its real `config.json`
  evades recovery (though not the fallback signature scan, which still runs
  against the full raw blob first).
- An `.h5` whose `model_config` attribute lies past the first
  `_MAX_READ_BYTES` (8 MiB) is not parsed, but it is no longer silent: the
  rest of a capped HDF5 file is streamed for the marker, and a marker found
  only there is `scan-incomplete` (HIGH). An earlier version let such a file
  read clean.

## What this guard does NOT prove

A clean result proves no recognized Lambda/marshalled-code signature was
found in the config this guard could recover — it does not prove the
artifact is safe to load. A custom Keras layer class that executes code
through a mechanism other than `Lambda`/`__lambda__` is outside this guard's
detection shape entirely.

`ml-artifact-committed` (MEDIUM, presence only) is the one signal that
remains when this content guard misses an artifact for a reason it cannot
detect (a sink outside the denylist, a format it does not parse): it fires on
every committed model file by extension, independent of what is inside.

# Citations

[1] agentsec checklist item `4-ml-keras-lambda-rce` (§4)
[2] OWASP-LLM:LLM03 — Supply Chain
[3] OWASP:A08 — Software and Data Integrity Failures
[4] CWE-502 — Deserialization of Untrusted Data
[5] Lab700xOrg/aisbom, `aisbom/safety.py` + `aisbom/scanner.py` (Apache-2.0) —
    the source this guard's Keras config walk, HDF5 byte-signature recovery,
    and damaged-zip local-header recovery were ported from
