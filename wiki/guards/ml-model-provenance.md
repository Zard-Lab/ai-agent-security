---
type: Guard
title: "ml-model-provenance"
description: "ML model downloaded or loaded without provenance verification."
timestamp: "2026-06-28T20:31:10+08:00"
guard_id: "ml-model-provenance"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM03", "OWASP:A02", "OWASP:A06", "OWASP:A08"]
---

# ML model downloaded or loaded without provenance verification

_Author — 2026-06-28_

---

## The threat

An attacker who controls the network path between a developer's machine and a model
host (or who compromises the host itself) can substitute a backdoored model during
download. The model appears to load and run normally; the malicious payload executes
on every inference call. This is ATLAS AML.T0004 (Backdoor ML Model) realized at the
supply-chain layer.

A second vector: Hugging Face Hub repositories are mutable by default. A model owner
can push new weights to the same repo without changing the name — a "rug pull". A
project that calls `from_pretrained("org/repo")` without a revision hash will silently
load the new (potentially backdoored) weights on the next container rebuild or pip
install, without any alert or diff.

Standards: the transport rules (R1 HTTP, R2 verify=False) are TLS/integrity failures
— `OWASP:A02` (Cryptographic Failures) + `OWASP:A08` (Software and Data Integrity
Failures) + `OWASP-LLM:LLM03` (Supply Chain). The provenance rules (R3 no-hash, R4
no-revision) are supply-chain/integrity failures — `OWASP-LLM:LLM03` + `OWASP:A08`.

## Why it's often introduced / Why this guard fits the stack

FastAPI + LLM apps frequently download models at startup or via a helper script, and
the convenience path skips the "boring" provenance steps:

```python
# Fast to write; silently dangerous
resp = requests.get("http://huggingface-mirror.corp/llama.gguf")
with open("model.gguf", "wb") as f:
    f.write(resp.content)

# Also common in tutorials — no revision pin
model = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-2-7b")
```

Neither pattern is obviously wrong to an author focused on getting inference working,
yet both leave the project open to undetected substitution.

## Detection design

1. **applies() gate** — `"llm" in profile.features`. If the feature is not set, the
   guard still scans files that import `transformers`, `torch`, `tensorflow`, `keras`,
   `huggingface_hub`, `diffusers`, `llama_cpp`, or `ctransformers` (detected per-file
   in `run()`). (There is no `ml` feature in `KNOWN_FEATURES`; the import fallback is
   the actual non-`llm` entry point.)

2. **Files scanned** — all `.py` files found via `python_scan_dirs` + `iter_files`.
   Non-product paths (`is_nonproduct_path`) are skipped.

3. **Patterns (per rule)**:

   - **Rule 1 — http-model-download (CRITICAL)**:
     - `_HTTP_DOWNLOAD`: `requests.get` or `urllib.request.urlopen` with `http://`
       (excluding `localhost` / `127.0.0.1`).
     - Fires when the URL itself contains an ML extension keyword (`_ML_URL_KEYWORD`)
       OR when a file-write to an ML extension appears within 30 lines of the download
       call (`_ML_WRITE`).

   - **Rule 2 — tls-verification-disabled (CRITICAL)**:
     - `_VERIFY_FALSE`: `requests.get|post|Session(..., verify=False)`.
     - Fires only when (a) the file contains ML library imports (`_ML_IMPORTS`) **and**
       (b) model-download context (`_MODEL_CTX`: model / weights / a model extension /
       download / from_pretrained / hf_hub / huggingface / hub) appears within 10 lines
       of the call. The file-import gate alone fired on any `verify=False` in an
       ML-importing module (e.g. a telemetry POST); the proximity gate scopes it to the
       actual download path.

   - **Rule 3 — download-no-hash-verify (HIGH)**:
     - Combines `_DOWNLOAD_CALL` (any `requests.get` or `urllib.request.urlopen`) with
       an **ML artifact** — a write to a model extension (`_ML_WRITE`) or an ML
       extension in the URL (`_ML_URL_KEYWORD`) — within a 20-line window, and no hash
       verification indicator (`_HASH_VERIFY`: hashlib / sha256 / sha512 / hmac /
       checksum / verify_hash / compare_digest) in the same window. The earlier gate
       used any `open(..., "w")` write, so a generic download-to-disk (a report, a CSV)
       in an llm-flagged repo fired HIGH; requiring an ML artifact removes that. `md5`
       is deliberately **not** a hash-verify indicator — it is broken for integrity.

   - **Rule 4 — from-pretrained-no-revision (LOW)**:
     - `_FROM_PRETRAINED_HUB`: `.from_pretrained("org/repo")` where the first argument
       is a string containing a `/` (Hub org/repo format) and the call site does NOT
       contain `revision=` anywhere before the closing `)`.

4. **Pragma**: `# security: allow-ml-model-provenance` on the flagged line suppresses
   all rules for that line.

5. **Severity / rule ids / standards**:
   - `ml-model-provenance/http-model-download` — CRITICAL — `_STD_TRANSPORT`
   - `ml-model-provenance/tls-verification-disabled` — CRITICAL — `_STD_TRANSPORT`
   - `ml-model-provenance/download-no-hash-verify` — HIGH — `_STD_PROVENANCE`
   - `ml-model-provenance/from-pretrained-no-revision` — LOW — `_STD_PROVENANCE`
   - `_STD_TRANSPORT = ["OWASP:A02", "OWASP:A08", "OWASP-LLM:LLM03"]`
   - `_STD_PROVENANCE = ["OWASP-LLM:LLM03", "OWASP:A08"]`
   - R4 is LOW (not MEDIUM): the unpinned `org/repo` form is the documented-everywhere
     default, so it is a hygiene nudge rather than a likely live compromise.

## When NOT to flag

- HTTPS downloads (`https://`) are safe from transport-layer substitution — rule 1
  stays silent.
- `http://localhost` and `http://127.0.0.1` are dev-only loopbacks — rule 1 is
  exempted.
- `verify=False` in a file with no ML imports is likely a general API call, not a
  model download — rule 2 stays silent.
- `verify=False` in an ML-importing file but on an unrelated call (a telemetry/health
  POST with no model-download context within 10 lines) — rule 2 stays silent.
- `requests.get(url)` with no nearby file-write is typically a metadata or API call,
  not an artifact download — rule 3 stays silent.
- A download saved to a non-model file (`report.csv`, a cache blob) in an llm-flagged
  repo — rule 3 stays silent (it requires an ML artifact, not any disk write).
- `from_pretrained("/local/path")` uses a filesystem path (absolute or relative, no
  `org/repo` slash) — rule 4 stays silent.
- `from_pretrained("gpt2")` uses a short name with no slash — rule 4 stays silent.
- `from_pretrained("org/repo", revision="abc123")` is correctly pinned — rule 4
  stays silent.
- Any line with a `# security: allow-ml-model-provenance` comment is suppressed for all rules; the
  phrase quoted in a string on that line is not a comment and does not count (#1040).

## Tests

| Test | What it checks |
|---|---|
| `test_http_model_download_fires_on_gguf_url` | HTTP URL with .gguf → CRITICAL (rule 1) |
| `test_http_model_download_fires_on_ml_write_in_window` | HTTP URL + nearby .bin write → fires (rule 1) |
| `test_https_model_download_does_not_fire` | HTTPS URL → silent (FP-bait, rule 1) |
| `test_http_localhost_does_not_fire` | localhost exemption → silent (FP-bait, rule 1) |
| `test_http_no_ml_write_does_not_fire` | HTTP without ML context → silent (FP-bait, rule 1) |
| `test_http_model_download_suppressed_by_pragma` | pragma suppresses rule 1 |
| `test_verify_false_with_ml_import_fires` | verify=False + ML import + model context → CRITICAL (rule 2) |
| `test_verify_false_without_ml_import_does_not_fire` | verify=False without ML import → silent (FP-bait, rule 2) |
| `test_verify_false_without_model_context_does_not_fire` | verify=False + ML import but no model context → silent (FP-bait, rule 2) |
| `test_download_without_hash_fires` | download + ML write + no hash → HIGH (rule 3) |
| `test_download_with_hash_does_not_fire` | download + sha256 check → silent (FP-bait, rule 3) |
| `test_generic_download_to_disk_does_not_fire` | non-model download to disk in llm repo → silent (FP-bait, rule 3) |
| `test_from_pretrained_hub_no_revision_fires` | Hub ID without revision → LOW (rule 4) |
| `test_from_pretrained_with_revision_does_not_fire` | Hub ID with revision= → silent (FP-bait, rule 4) |
| `test_from_pretrained_local_path_does_not_fire` | local path → silent (FP-bait, rule 4) |
| `test_from_pretrained_short_name_does_not_fire` | short name (no slash) → silent (FP-bait, rule 4) |
| `test_applies_with_llm_feature` | applies() true for llm feature |
| `test_not_applies_without_ml_features` | no llm + no ML imports → no findings |

## Known bypasses

- **Indirect URL assignment**: `url = "http://..."; requests.get(url)` — the HTTP
  pattern only matches when the literal `http://` appears in the same call's argument.
  Aliased URLs evade rule 1.
- **Variable extension**: `ext = ".gguf"; open("model" + ext, "wb")` — `_ML_WRITE`
  matches only static open() call strings with the extension visible.
- **urllib3 directly**: `urllib3.PoolManager().request(...)` — not matched by
  `_HTTP_DOWNLOAD` (which targets `requests.get` and `urllib.request.urlopen`).
- **Long functions**: if the file-write is more than 30 lines from the download call,
  rule 1 misses it; rule 3's window is 20 lines.
- **Multiline from_pretrained**: if `revision=` appears on a line below the closing
  `)` (very unusual syntax), rule 4 may false-positive.
- **Aliased from_pretrained**: `load = AutoModel.from_pretrained; load("org/repo")` —
  not matched.

## What this guard does NOT prove

- That HTTPS downloads come from a trustworthy source (cert pinning is out of scope).
- That hash values are actually correct (the guard only checks for the presence of hash
  verification code, not its correctness).
- That `revision=` pins are to a known-good commit (any hash silences rule 4).
- That models loaded from local paths are themselves unmodified.
- That `trust_remote_code=True` is absent (covered by `unsafe-deserialization`).
- That pickle / joblib / torch unsafe loads are absent (covered by `unsafe-deserialization`).

# Citations

[1] agentsec checklist item `4-ml-model-provenance` (§4)
[2] OWASP-LLM:LLM03
[3] OWASP:A02
[4] OWASP:A06
[5] OWASP:A08
