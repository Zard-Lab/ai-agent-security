---
type: Guard
title: "ml-artifact-committed"
description: "Flags a binary ML model artifact (.pkl/.pt/.h5/.gguf/.onnx/...) committed directly to source control."
timestamp: "2026-10-08T00:00:00Z"
guard_id: "ml-artifact-committed"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM03", "OWASP:A08", "CWE-506"]
---

# Binary ML model artifact committed directly to source control

_Author — 2026-10-08_

---

## The threat

A `.pkl`/`.pt`/`.h5`/`.gguf`/`.onnx`-style file in a repo is a binary blob that
every PR diff tool renders as "binary file changed" — nobody reads it the way
they read a code change. Several of these formats execute arbitrary code the
moment they are *loaded* (pickle-family and Keras's HDF5/zip containers, the
ATLAS T0004 malicious-model vector, CWE-502) — so an attacker who lands a PR,
compromises a contributor's machine, or exploits a lax merge gate gets a
code-execution path that a normal code review never inspects. Even for formats
that are safe-by-construction (SafeTensors), a committed weight file is still a
supply-chain liability: it has no independent provenance trail, no access
control, and git history keeps every version forever, including one an
attacker swapped in and a later commit silently reverted.

## Why this guard fits the stack

A FastAPI + LLM/RAG app almost always loads its model(s) from the Hugging Face
Hub, a model registry, or object storage at runtime — `agentsec`'s own
`ml-model-provenance` guard already assumes that shape (it checks the download
call site, not a local file). The moment a `.pkl`/`.gguf`/`.h5` file shows up
*inside the repo itself*, that assumption has been broken, and it's worth
flagging regardless of whether the file's content can be parsed (see
`ml-pickle-dangerous-global`, `ml-keras-lambda-rce`, `ml-gguf-template-injection`
and `ml-onnx-external-data` for the guards that actually disassemble pickle
opcodes / Keras configs / GGUF metadata / ONNX graphs — this guard exists for
the formats and cases those miss: SafeTensors, `.ckpt`, or simply "this
shouldn't be here regardless of what's inside it").

## Detection design

1. `applies()` gates on `"llm" in profile.features`.
2. Scans the whole repo via `iter_files(root, _EXTENSIONS)` for
   `.pkl .pickle .joblib .pt .pth .h5 .hdf5 .keras .gguf .onnx .safetensors .ckpt`
   — deliberately excludes `.bin` (too generic: firmware, lockfiles, arbitrary
   build output).
3. No content is parsed: this is a presence/extension-only check. At most
   1 KiB is read, only to recognize a Git LFS pointer file (the text stub
   committed in place of the binary, the recommended mitigation), which is
   not reported. The check is strict (`is_git_lfs_pointer`: under 1024
   bytes, the LFS version line first, only printable `key value` lines with
   `oid` and `size`), so a binary that merely starts with the version line
   still fires (PR #1049 review, M4).
4. `is_nonproduct_path()` drops test/fixture/example trees.
5. Suppression is owner-side only: an entry in the exceptions/baseline file
   (`agentsec-exceptions.json`, e.g. via `--write-baseline`), or the path in
   `.agentsec/config.json` (`nonproduct_paths` demotes, `archive_paths`
   drops). There is deliberately NO in-file marker: an earlier draft honoured
   `security: allow-ml-artifact-committed` anywhere in the file's bytes, but
   whoever can commit the binary can commit the marker inside it, which is no
   opt-out at all for a "this binary was never reviewed" signal (PR #1049
   review, H3).
6. Fires `ml-artifact-committed/binary-artifact`, MEDIUM, `surfacing = True`
   (a presence signal to confirm, not proof of malice).

## When NOT to flag

A tiny `.pkl`/`.npy` fixture under `tests/`/`fixtures/`/`examples/` is ordinary
test data — `is_nonproduct_path()` already excludes it. An artifact whose
provenance has been reviewed and accepted can be marked non-product in
`.agentsec/config.json` or accepted in the exceptions file.

## Tests

| Test | What it checks |
|---|---|
| `test_committed_pickle_file_fires` | A `.pkl` file in the repo root fires the finding. |
| `test_committed_gguf_file_fires` | A `.gguf` file fires, with the correct location. |
| `test_generic_bin_file_stays_silent` | `.bin` is deliberately excluded — stays silent. |
| `test_in_file_pragma_bytes_do_not_suppress` | The old in-file marker bytes no longer silence the finding. |
| `test_nonproduct_path_skipped` | A fixture under `tests/fixtures/` is skipped. |
| `test_does_not_apply_without_llm_feature` | `applies()` is False with no `llm` feature. |
| `test_git_lfs_pointer_is_not_a_committed_binary` | FP fix: a Git LFS pointer is not a committed binary. |
| `test_binary_starting_with_the_lfs_version_line_still_fires` | Still-fires: a binary opening with the LFS version line is still reported. |

## Known bypasses

A file renamed to an extension outside the tracked list (or with no extension
at all) is invisible to this guard — it is purely extension-based, not a magic-
byte sniff. An attacker who controls the filename trivially evades it; the
companion content-scanning guards (pickle/Keras/GGUF/ONNX) are the layer that
would still catch the content itself if the renamed file is later loaded by
name convention and actually parsed.

## What this guard does NOT prove

Presence alone proves nothing about whether the artifact is malicious — it is a
repo-hygiene/supply-chain flag, not a vulnerability finding. A clean result from
the content-scanning guards (pickle/Keras/GGUF/ONNX) plus a clean result here is
still not a guarantee: a format those guards don't parse at all (SafeTensors is
safe-by-construction, but a `.ckpt` could wrap arbitrary pickle content those
guards can fail to fully walk on a sufficiently obfuscated/truncated stream).

This guard is also the only signal left when a content guard
(`ml-pickle-dangerous-global`, `ml-keras-lambda-rce`,
`ml-gguf-template-injection`, `ml-onnx-external-data`) misses an artifact for
a reason it cannot detect, such as a sink outside its denylist: it fires on
every committed model file by extension, whatever is inside.

# Citations

[1] agentsec checklist item `4-ml-artifact-committed` (§4)
[2] OWASP-LLM:LLM03 — Supply Chain
[3] OWASP:A08 — Software and Data Integrity Failures
[4] CWE-506 — Embedded Malicious Code
[5] MITRE ATLAS T0004 — ML Supply Chain Compromise
