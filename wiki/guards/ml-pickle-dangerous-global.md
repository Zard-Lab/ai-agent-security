---
type: Guard
title: "ml-pickle-dangerous-global"
description: "Flags a committed pickle-family model file whose opcode stream imports a dangerous global (os.system, subprocess.Popen, ...)."
timestamp: "2026-10-08T00:00:00Z"
guard_id: "ml-pickle-dangerous-global"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM03", "OWASP:A08", "CWE-502"]
---

# Committed pickle-family model file imports a dangerous global

_Author — 2026-10-08_

---

## The threat

`pickle.loads(data)` (and `torch.load`/`joblib.load`, both pickle underneath)
executes arbitrary code as a side effect of *loading* a stream whose
`GLOBAL`/`STACK_GLOBAL` opcode names a dangerous callable — not when the
loaded object is later used, but the instant it's deserialized (CWE-502). This
is the mechanism behind the malicious-Hugging-Face-pickle vector (MITRE ATLAS
T0004): an attacker who can get a backdoored `.pkl`/`.pt`/`.bin` file into a
repo (a compromised contributor, a lax PR merge gate, a supply-chain swap on a
dependency that ships a checkpoint) gets code execution the moment anything in
the app calls `torch.load`/`pickle.load` on it — independent of what that code
does with the result.

`agentsec/guards/unsafe_deserialization.py` already catches the SOURCE CODE
side of this (a bare `pickle.loads(...)` call site). This guard looks the
other direction: at the actual bytes of a committed artifact, to see whether
the payload itself is malicious regardless of whether this repo's own code
ever loads it.

## Why this guard fits the stack

A FastAPI + LLM/RAG app that fine-tunes or caches local models is exactly the
shape that accumulates `.pkl`/`.pt`/`.bin` checkpoints during development —
and `ml-artifact-committed` already flags their mere presence. This guard adds
the layer that actually looks inside the ones it can parse (pickle-family) and
tells the difference between an ordinary checkpoint (tensor data + structural
globals like `torch._utils._rebuild_tensor_v2`, `collections.OrderedDict`) and
one carrying a sink.

## Detection design

1. `applies()` gates on `"llm" in profile.features`.
2. Scans `.pkl .pickle .pt .pth .bin .joblib .dill` via `iter_files`,
   `is_nonproduct_path()`-filtered, bytes capped at `_MAX_READ_BYTES` (8 MiB).
3. A Git LFS pointer file (`is_git_lfs_pointer`, strict) is skipped: the
   artifact itself is not in the repo. A zip (local-file-header magic
   `PK\x03\x04`, a modern PyTorch >= 1.6 checkpoint) is opened from the
   FILE, since its central directory sits at the end, past any read cap; the
   directory's declared size is checked against `_MAX_ZIP_DIRECTORY_BYTES`
   first. EVERY `data.pkl` / `*/data.pkl` entry is a candidate: matched
   case-insensitively (as PyTorch's reader resolves names), each `ZipInfo`
   from `infolist()` so a same-named duplicate is read too, up to
   `_MAX_PICKLE_MEMBERS`, all sharing ONE decompressed-byte budget (the read
   cap) through `zip_member_prefix`, so a zip bomb is never inflated whole.
   The entry torch loads (`<directory of the first entry>/data.pkl`, its
   first and last occurrence) is read first; that ordering only finds a
   CRITICAL sooner, since a cap or budget that stops the rest is HIGH.
   Otherwise the file's own bytes are the stream, except that a recognized
   compressed container (gzip/zlib/bz2/xz/lz4/joblib `ZF`) or a legacy tar
   checkpoint (a valid tar header; torch.load unpickles its `pickle` member)
   is reported incomplete, and bytes whose FIRST byte is not a pickle opcode
   are not a
   candidate at all (every unpickler raises on that same byte, so nothing
   can execute: this keeps Chameleon `.pt` templates, `.pth` path files and
   translated `.pt` text files silent).
4. Disassembles that stream with stdlib `pickletools.genops` — a read-only
   opcode walk, never `pickle.loads`/`pickle.load` (both are in
   `agentsec/guard_sandbox.py`'s banned-import list for every guard module;
   `pickletools` is not, and unlike `pickle` it never executes, imports, or
   constructs anything the stream names — verified live against a real
   malicious protocol-4 pickle before this guard shipped). Tracks the last
   two pushed string literals (handling the memo `PUT`/`GET`/`MEMOIZE`
   opcodes, since a real `STACK_GLOBAL` commonly resolves one of its two
   operands through the memo table rather than a literal immediately before
   it) to resolve both the classic `GLOBAL` opcode and the modern
   `STACK_GLOBAL` form.
5. Each resolved `(module, name)` pair is checked against a dangerous-globals
   table ported near-verbatim from Lab700xOrg/aisbom's `safety.py`
   (Apache-2.0) — `os`/`subprocess`/`builtins` execution sinks, debugger and
   event-loop gadgets, import-mechanism abuse, `dill`'s code-reconstruction
   globals — plus a module-family generalization (`asyncio.*`,
   `importlib.*`, `pip.*`, `ctypes.*`, `multiprocessing.*`) that catches an
   unenumerated submodule carrying a known execution-attribute name.
6. Suppression is owner-side only: an entry in the exceptions/baseline
   file (`agentsec-exceptions.json`), or the path in `.agentsec/config.json`
   (`nonproduct_paths` demotes, `archive_paths` drops). There is deliberately
   NO in-file marker. The artifact is the untrusted thing being judged, so a
   byte string inside it is attacker-controlled: an earlier draft honoured
   `security: allow-<id>` anywhere in the file, and a malicious model carried
   its own opt-out after STOP / in a spare member / in string metadata
   (PR #1049 review, H3).
7. Fires `ml-pickle-dangerous-global/dangerous-import`, CRITICAL, when any
   candidate names a sink; otherwise
   `ml-pickle-dangerous-global/scan-incomplete`, HIGH, when any candidate
   could not be fully scanned (no `data.pkl`, a zip directory over budget,
   an entry zipfile rejects such as a bad CRC or a local/central name
   mismatch, the member cap or the shared budget hit, a stream that breaks
   or runs past the cap before STOP, a compressed container).

## When NOT to flag

An ordinary checkpoint's globals (`torch._utils._rebuild_tensor_v2`,
`numpy.core.multiarray._reconstruct`, `collections.OrderedDict`, ...) are not
in the dangerous-globals table and stay silent — see
`test_scan_pickle_stream_silent_on_ordinary_checkpoint` and
`test_ordinary_checkpoint_stays_silent`.

## Tests

| Test | What it checks |
|---|---|
| `test_scan_pickle_stream_finds_classic_global_opcode` | Protocol-0 `GLOBAL` opcode naming `os.system` is detected. |
| `test_scan_pickle_stream_finds_stack_global_opcode` | A real protocol-4 pickle (via `pickle.dumps`, never executed) using `STACK_GLOBAL` is detected. |
| `test_scan_pickle_stream_silent_on_ordinary_checkpoint` | A plain-data dict pickle stays silent. |
| `test_committed_malicious_pickle_fires` | End-to-end: a `.pkl` file in a repo fires the finding. |
| `test_ordinary_checkpoint_stays_silent` | End-to-end FP-bait: an ordinary `.pt` checkpoint stays silent. |
| `test_zip_wrapped_pytorch_checkpoint_fires` | A modern zip-wrapped `torch.save()`-shaped checkpoint is unwrapped and scanned. |
| `test_zip_wrapped_ordinary_checkpoint_stays_silent` | The zip-unwrap path's FP-bait counterpart. |
| `test_in_file_pragma_bytes_do_not_suppress` | The old in-file marker bytes, placed where the format ignores them, no longer silence the finding. |
| `test_nonproduct_path_skipped` | A fixture under `tests/fixtures/` is skipped. |
| `test_does_not_apply_without_llm_feature` | `applies()` is False with no `llm` feature. |
| `test_malformed_pickle_does_not_raise` | Garbage bytes never crash the scan; a first byte that is no pickle opcode is not a candidate. |
| `test_zip_member_far_over_the_cap_is_not_inflated_whole` | A kilobyte zip declaring a far larger `data.pkl` is read only up to the cap (tracemalloc peak bound), and still fires. |
| `test_file_far_over_the_cap_is_not_loaded_whole` | A file far over the cap is read only up to it (peak bound), and still fires. |
| `test_zip_checkpoint_larger_than_the_read_cap_still_fires` | A 9 MiB `.pt` zip (directory past the read cap) still fires CRITICAL. |
| `test_zip_without_a_data_pkl_member_is_reported_unscanned` | A zip with no `data.pkl` is `scan-incomplete`, not clean. |
| `test_zip_whose_directory_exceeds_the_budget_is_reported_unscanned` | A central directory over budget is `scan-incomplete`. |
| `test_stream_cut_before_stop_is_reported_unscanned` | A stream that breaks before STOP is `scan-incomplete`. |
| `test_stream_whose_stop_lies_past_the_read_cap_is_reported_unscanned` | A stream whose STOP is past the cap is `scan-incomplete`. |
| `test_ordinary_small_checkpoints_are_not_reported_unscanned` | FP-bait: complete plain, protocol-0 and zip checkpoints stay silent. |
| `test_generic_bin_that_is_not_a_pickle_stays_silent` | FP-bait: a generic `.bin` that is neither a pickle nor a torch zip stays silent. |
| `test_git_lfs_pointer_is_not_scanned` | A Git LFS pointer is skipped. |
| `test_an_unexpected_scanner_error_is_contained_per_file` | Any scanner exception is contained to its file (`scan-incomplete`). |
| `test_every_data_pkl_directory_is_scanned` | A benign `good/data.pkl` decoy no longer hides `evil/data.pkl`. |
| `test_duplicate_data_pkl_entries_are_all_scanned` | An evil-first duplicate `archive/data.pkl` entry is scanned. |
| `test_too_many_data_pkl_members_is_reported_unscanned` | More than `_MAX_PICKLE_MEMBERS` entries is `scan-incomplete`. |
| `test_several_benign_data_pkl_members_stay_silent` | FP-bait: several benign `data.pkl` entries stay silent. |
| `test_zip64_directory_over_the_budget_is_reported_unscanned` | A zip64 directory over budget is caught even when the classic end record claims a tiny one. |
| `test_many_distinct_sinks_are_merged_in_linear_time` | Growth: merging n distinct sinks across entries is linear (it was quadratic). |
| `test_a_corrupt_decoy_entry_does_not_abort_the_real_scan` | A bad-CRC decoy `data.pkl` no longer hides the real payload. |
| `test_a_corrupt_entry_alone_is_reported_unscanned` | A corrupt entry on its own is `scan-incomplete`. |
| `test_the_torch_resolved_entry_is_scanned_even_past_the_cap` | The entry torch loads (`<first dir>/data.pkl`) is scanned first, so 20 decoys cannot push it past the cap. |
| `test_the_last_duplicate_of_the_torch_entry_is_scanned_past_the_cap` | Its last duplicate is scanned first too. |
| `test_all_data_pkl_entries_share_one_read_budget` | All `data.pkl` entries share ONE decompressed-byte budget (bytes actually read are bounded). |
| `test_data_pkl_is_matched_case_insensitively` | `archive/DATA.PKL` in a generic `.bin` is scanned (it read as no data.pkl). |
| `test_a_bad_crc_data_pkl_is_high_not_medium` | A bad-CRC `data.pkl` (another reader may load it) fails closed at HIGH. |
| `test_a_local_central_name_mismatch_is_high_not_medium` | A local/central name mismatch fails closed at HIGH. |
| `test_the_first_occurrence_of_the_torch_entry_leads` | The torch target's FIRST occurrence leads (mutation `lead = hits[-1:]` goes red). |
| `test_text_files_with_pickle_extensions_are_not_pickle_candidates` | FP-bait: Chameleon `.pt`, `.pth` path and `.pt` text files stay silent. |
| `test_compressed_containers_are_high_incomplete` | gzip/zlib/bz2/xz/joblib-ZF containers are HIGH incomplete. |
| `test_a_stream_that_starts_as_a_pickle_and_breaks_is_high` | A protocol-0 stream that breaks before STOP is HIGH. |
| `test_a_payload_in_a_later_legacy_torch_stream_fires` | A payload in the 4th stream of a legacy torch.save file fires. |
| `test_a_legacy_torch_checkpoint_layout_stays_silent` | FP-bait: a benign legacy layout (five streams, raw storage starting with an opcode byte) is clean; a sixth walk turns it red. |
| `test_several_pickles_dumped_into_one_file_stay_silent` | FP-bait: several benign pickles in one file stay silent. |
| `test_a_legacy_tar_checkpoint_is_high` | A legacy tar checkpoint (first byte no opcode) is HIGH, not silent. |
| `test_long_text_files_with_pickle_extensions_are_not_tar_candidates` | FP-bait: long templates and path files are not tar headers (checksum fails). |
| `test_an_lz4_joblib_container_is_high` | An lz4 joblib container (frame magic 04 22 4D 18) is HIGH, not silent. |
| `test_stack_global_operands_pushed_as_byte_strings_fire` | STACK_GLOBAL operands pushed by STRING / SHORT_BINSTRING / BINSTRING fire. |
| `test_the_incomplete_finding_names_the_owner_opt_outs` | The HIGH incomplete finding's remediation names the owner-side opt-outs. |
| `test_trailing_opcode_bytes_after_a_benign_pickle_name_the_later_stream` | Trailing opcode-like bytes after a benign pickle are HIGH, and the reason names the later stream. |

## What scan-incomplete means for the gate

`ml-pickle-dangerous-global/scan-incomplete` is **HIGH**, so it DOES fail
the default `--fail-on high` gate. That is deliberate: the guards fail
CLOSED on untrusted artifacts. The verdict for one file is CRITICAL if any
candidate in any view holds a dangerous construct; otherwise HIGH if any
candidate in any view could not be fully scanned; otherwise clean. Three
review rounds each found a mirror-image hole in guessing which entry or view
a loader would use, so the guard no longer guesses: whatever it cannot
inspect is reported, not assumed benign. An attacker can still turn a
CRITICAL into this HIGH (by hiding the payload behind inline joblib array
bytes, in a compressed container, past the read cap, in an entry zipfile
rejects, or past the member cap or shared budget), but the HIGH now blocks
the merge just the same. It is declared a review signal
(`surfacing_rule_prefixes`), so it ranks below a proven finding of the same
severity. The owner-side opt-outs for an audited artifact are an
`agentsec-exceptions.json` entry or the path in `.agentsec/config.json`.

Measured noise (2026-10-18, benign files through the real pipeline): HIGH on
a gzip-compressed `.pkl` and on a joblib-style stream with inline array
bytes (an uncompressed joblib dump of numpy arrays); clean on protocol 0 and
4 pickles, a small and a 20 MiB torch zip checkpoint, a Chameleon `.pt`
template, a `.pth` path file and a translated `.pt` text file.

## Known bypasses

Disclosed in the module docstring, not discovered later:

- A legacy (pre-1.6) `torch.save` checkpoint is five pickles end to end
  (magic number, protocol, sys_info, the object, the storage keys) and
  torch.load runs each, so after a completed stream the next one is walked
  too, up to five (an earlier version judged only the first, and a payload
  in the 4th stream executed unseen). Pickles past the fifth are not walked;
  torch.load does not read them as pickles either.
- Accepted cost of that rule: a benign pickle followed by trailing bytes
  whose first byte happens to be a pickle opcode is walked as a second
  stream, and when those bytes are not a pickle the file is HIGH
  `scan-incomplete`, with a reason naming the later stream ("pickle stream
  2, after 1 complete one(s), broke before its STOP opcode"). The first
  stream was judged in full.
- A zip-wrapped checkpoint whose member naming doesn't match PyTorch's
  `*/data.pkl` convention is not unwrapped; it is reported
  `scan-incomplete` (HIGH) rather than clean.
- joblib's own compressed containers (zlib/gzip/bz2/lzma/the legacy `ZF`
  format) are not unwrapped; they are reported `scan-incomplete`. So is an
  uncompressed joblib dump with numpy arrays (joblib writes the array bytes
  inline, which stops the opcode walk before STOP): fail closed, so a HIGH on
  ordinary joblib array dumps.
- The dual-use-constructor check (`operator.methodcaller("system")` reaching
  a sink through an *argument* rather than a named global) is not ported.
- A stream whose STOP opcode lies beyond `_MAX_READ_BYTES` (8 MiB), or that
  breaks before STOP, is reported `scan-incomplete` (HIGH) instead of
  clean. An earlier draft read only an 8 MiB prefix of the FILE, so a real
  `.pt` checkpoint (whose zip directory is at the end) was silently unscanned
  (PR #1049 review, H4).
- A generic `.bin` is only reported `scan-incomplete` once identified as a
  pickle (PROTO header) or a torch zip (`data.pkl` member); a broken
  protocol-0/1 stream in a `.bin` stays silent.

## What this guard does NOT prove

A clean result proves the pickle streams it walked name no *known* sink from
this table; it does not prove the artifact is safe to load. A sink reached only
through a dual-use constructor's string argument, or in a stream past the
fifth, is invisible to this guard (a compressed joblib container is reported
`scan-incomplete`, so it is visible as unscanned, but its contents are not
inspected). This
guard is one layer; `ml-artifact-committed` (presence) and
`unsafe_deserialization` (source-code call sites) are the others.

Fail-closed covers CONTAINERS and STREAMS (anything the walk cannot reach is
HIGH), not the dangerous-globals table: a sink that is not on the denylist is
read clean. For example `pydoc.pipepager` (which runs a shell command) is not
flagged today; the denylist is ported from aisbom and is not exhaustive.

`ml-artifact-committed` (MEDIUM, presence only) is the one signal that
remains when this content guard misses an artifact for a reason it cannot
detect (a sink outside the denylist, a format it does not parse): it fires on
every committed model file by extension, independent of what is inside.

# Citations

[1] agentsec checklist item `4-ml-pickle-dangerous-global` (§4)
[2] OWASP-LLM:LLM03 — Supply Chain
[3] OWASP:A08 — Software and Data Integrity Failures
[4] CWE-502 — Deserialization of Untrusted Data
[5] MITRE ATLAS T0004 — ML Supply Chain Compromise
[6] Lab700xOrg/aisbom, `aisbom/safety.py` (Apache-2.0) — the source this guard's
    dangerous-globals table and opcode-walk design were ported from
