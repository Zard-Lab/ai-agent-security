---
type: Guard
title: "ctypes-load-downloaded-library"
description: "No ctypes load of a native library downloaded earlier in the same scope — fetch-then-load-into-process with no review step."
timestamp: "2026-10-19T00:00:00Z"
guard_id: "ctypes-load-downloaded-library"
checklist_section: ["8"]
standards: ["OWASP:A08", "CWE-494"]
---

# No ctypes load of a native library downloaded earlier in the same scope

_Author — 2026-10-18_

---

## The threat

Loading a native library with `ctypes` runs unreviewed machine code IN-PROCESS — unlike a
subprocess, there is no boundary at all between the loaded code and the Python interpreter's
own memory. Fetching that library over the network moments earlier means the code that will be
mapped into the process was never reviewed, pinned, or checksum-verified.

WHO reaches this: any package install, AI-agent skill, or contribution that ships this code —
the native code runs the moment the ctypes load executes. WHAT privilege / TO WHAT EFFECT: full
arbitrary native-code execution with the privileges of the Python process, from whatever a
compromised download host, a poisoned DNS response, or an on-path attacker on a plain-HTTP
fetch served instead. Standards: OWASP:A08 (Software and Data Integrity Failures), CWE-494
(Download of Code Without Integrity Check).

## Why it's often introduced / why no existing agentsec guard covers this

Grepped every guard in this project for `ctypes` before building anything: the only hit was
`ml_pickle_dangerous_global.py`, which checks for `ctypes.CDLL`/etc. as a dangerous GLOBAL-
opcode target INSIDE a malicious pickle's own binary structure — a completely different scan
surface (pickle-file internals) from this guard's concern (a live source-code taint pattern: a
download call followed by a ctypes load). No guard anywhere checks for freshly-downloaded
native code being loaded into the process via ordinary Python source.

## Detection design

Ported from `rakshit-737/warden-supply-chain-security`'s `warden-python.yml` semgrep rule
(`warden.malicious_behavior.ctypes-load-downloaded-library`, fetched and read in full).

**`ctypes-load-after-download` (HIGH).**

1. **`applies()` gate:** `"python" in profile.features`.
2. **Files scanned:** `.py`/`.pyi` under `python_scan_dirs`, `is_nonproduct_path` filtered.
3. **Pattern:** a network-download call (`urllib.request.urlretrieve`, `requests.get`,
   `httpx.get`, or `urlopen`) appears within a 15-line window BEFORE a ctypes native-library-
   load call (`ctypes.CDLL`/`PyDLL`/`WinDLL`/`OleDLL`, or `ctypes.cdll`/`windll`/`pydll`/
   `oledll`.`LoadLibrary(`), AND the ctypes call's argument list references something the
   download produced. The link tokens, per download:
   - the variable its result was assigned to (`lib_path, _ = urlretrieve(url)`);
   - `urlretrieve`'s own destination, the second positional argument or `filename=`
     (`urlretrieve(url, path)`, `urlretrieve(url, "/tmp/lib.so")`);
   - the destination of an `open(dest, "wb")` / `dest.write_bytes(` write within 400
     characters after the download.

   An identifier token must be a whole word of the ctypes argument list; a path or expression
   token is matched as a substring (`"/tmp/lib.so"`, `os.path.join(d, "lib.so")`).
4. **Nested form:** a download nested inside the ctypes call's own argument list
   (`ctypes.CDLL(urlretrieve(url)[0])`) fires with no window.

Every call's matching `)` comes from one `close_paren_map` pass per file, and each download's
line and tokens are computed once, so a file full of unclosed or interleaved calls stays linear.

**Deliberately simpler than the source:** the source's semgrep rule threads a specific
metavariable (`$LIB`) from the download call through an intermediate `open(...).write(...)` or
`write_bytes(...)` step to the exact ctypes argument. This guard approximates that with the
token link above inside a 15-line window, rather than a second AST-threading implementation.
It started as a pure proximity window with no link at all, the approximation
`download-execute-chain`'s `python-download-run` rule uses, and fired HIGH on a healthcheck
`requests.get` sitting above an ordinary `ctypes.CDLL("libc.so.6")` (PR #1093 review, round 1).
The first link check then dropped the `urlretrieve(url, path)` destination and the nested form
(round 2); both are tested now.

**Inline opt-out pragma:** `# security: allow-ctypes-load-downloaded-library`.

## When NOT to flag

- **A ctypes load with no network-download call anywhere in the preceding 15 lines** — the
  overwhelmingly common case (loading a vendored/bundled native extension).
- **A download with no ctypes load nearby** — an ordinary asset/data fetch.
- **A download and a ctypes load that share nothing** — a healthcheck GET above a
  `ctypes.CDLL("libc.so.6")`, or a CSV downloaded next to the load of a bundled library.

Use the pragma `# security: allow-ctypes-load-downloaded-library` for a legitimate plugin
system with its own pinned-checksum verification this pattern cannot see.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_urlretrieve_then_cdll` | `urlretrieve` then `ctypes.CDLL(lib_path)` — fires HIGH |
| `test_fires_on_requests_get_then_windll_loadlibrary` | `requests.get` + file write then `ctypes.windll.LoadLibrary` — fires |
| `test_ctypes_load_without_prior_download_does_not_fire` | FP-bait: loading a vendored library, no download nearby — silent |
| `test_download_without_ctypes_load_does_not_fire` | FP-bait: a plain asset download, no ctypes load — silent |
| `test_ctypes_load_far_outside_window_does_not_fire` | FP-bait: an unrelated download and load separated past the 15-line window — silent |
| `test_healthcheck_get_then_unrelated_system_library_load_does_not_fire` | FP-bait: a healthcheck GET above `ctypes.CDLL("libc.so.6")` — silent |
| `test_fires_on_download_written_to_destination_then_loaded_by_same_path` | `requests.get`, `open("/tmp/lib.so", "wb").write(...)`, `CDLL("/tmp/lib.so")` — fires |
| `test_fires_on_urlretrieve_to_named_destination_then_cdll` | `urlretrieve(url, path)` then `CDLL(path)` — fires |
| `test_fires_on_urlretrieve_to_literal_and_keyword_destination` | a literal destination, and `filename=dest` with `windll.LoadLibrary(dest)` — fire |
| `test_fires_on_download_nested_inside_ctypes_call` | `ctypes.CDLL(urlretrieve(url)[0])` — fires |
| `test_urlretrieve_destination_unrelated_to_loaded_library_does_not_fire` | FP-bait: a CSV (and an empty destination) downloaded next to `CDLL("libc.so.6")` — silent |
| `test_scan_is_linear_on_unclosed_and_interleaved_calls` | (slow) unclosed and interleaved get/CDLL lines scan in linear time; a real fetch-then-load appended still fires |
| `test_scan_is_linear_on_a_long_line_before_a_download` | (slow) a long `a,a,...` line before a download scans in linear time; a real fetch-then-load appended still fires |
| `test_docstring_prose_alone_does_not_fire` | FP-bait: both trigger phrases mentioned only in a docstring — silent |
| `test_pragma_silences` | the inline pragma silences the rule |
| `test_applies_requires_python` | `applies()` gate |

## Known bypasses

- **One-hop token link, not dataflow.** A destination reassigned before the load
  (`p2 = p`), a `tempfile.NamedTemporaryFile` whose `.name` is loaded, a
  `Path(p).write_bytes(...)` destination, an `open(os.path.join(d, "lib.so"), "wb")` destination
  (only a bare name or a literal is read from the `open` write), and an
  `open(p, "wb", buffering=0)` (trailing arguments after the mode) are not linked.
- **Window-limited.** A download more than 15 lines before the ctypes load is not paired.
- **Size caps.** Only the first 4 KB of a ctypes call's argument list is searched for a link
  token, and a `urlretrieve` call longer than 4 KB yields no destination token, so a link placed
  after that much other text is missed (caps that keep a hostile file of nested calls bounded; #1112).
- **Fixed call vocabulary.** A download via a library not in the fixed list (`requests.post`,
  `requests.Session().get`, `aiohttp`, a raw `socket` download) is not recognized, and neither
  is `from ctypes import CDLL; CDLL(...)` or `from urllib.request import urlretrieve`.

## What this guard does NOT prove

- That a flagged pairing is actually malicious — a plugin system that downloads, verifies a
  checksum out-of-band (invisible to this pattern), and then loads is a legitimate design that
  still matches.
- That code WITHOUT a matching pairing never loads unreviewed native code — a download and
  load split across two files, or routed through an intermediate helper function, is not
  caught.

# Citations

[1] agentsec checklist item `8-ctypes-load-downloaded-library` (§8)
[2] OWASP:A08, CWE-494
[3] rakshit-737/warden-supply-chain-security `warden-python.yml` (`ctypes-load-downloaded-library`)
