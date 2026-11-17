---
type: Guard
title: "curl-pipe-to-shell"
description: "curl/wget output piped directly into an interpreter, unverified."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "curl-pipe-to-shell"
checklist_section: ["5"]
standards: ["CWE-829", "OWASP:A08"]
---

# curl/wget output piped directly into an interpreter, unverified

_Author — 2026-07-13_

---

## The threat

`curl <url> | bash` (or `wget ... | sh`, `| python`, `| perl`, `| ruby`) downloads a
script and pipes it directly into an interpreter with zero inspection: no file lands on
disk to diff, checksum, or signature-verify before it runs. Anyone who can influence
what the download host serves — a compromised install-script host, a poisoned DNS
response, or an on-path attacker on a plain-HTTP fetch — gets arbitrary code execution
with the privileges of whatever ran the pipeline. Inside a Dockerfile `RUN` instruction
that's the image build's privileges (frequently root); in a shell script it's whatever
ran the script. This is a software/data integrity failure: OWASP:A08 (Software and Data
Integrity Failures), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).

The pattern is sourced from a real external scanner, drogonsec's `SH-004` shell rule
(verified against the actual Go source, not a description):

```go
{
    ID: "SH-004", Language: config.LangShell, Severity: config.SeverityMedium,
    Title:       "curl/wget piped to bash (arbitrary code execution)",
    Pattern:     mustCompile(`(?i)(curl|wget).*\|\s*(bash|sh|python|perl|ruby)`),
    OWASP:       config.OWASP_A08_SoftwareDataIntegrityFailures, CWE: "CWE-829", CVSS: 8.8,
}
```

## Why this guard fits the stack

Docker-install one-liners of exactly this shape are everywhere in real-world
Dockerfiles and setup scripts (`curl -fsSL https://get.docker.com | bash` is the
canonical example from Docker's own install docs), and they show up unmodified in
agent-generated or copy-pasted setup instructions for a FastAPI + React + LLM/RAG stack
just as often as anywhere else. agentsec already scans Dockerfiles for the sibling
integrity concern in `docker_apt_update_not_alone.py` (stale-package-index layering) —
this guard closes the adjacent gap in the same file-type scope: an unverified remote
script executed at build/setup time. No existing agentsec guard covers this specific
pattern; `actions_script_injection.py` is unrelated (untrusted GitHub-Actions context
interpolation in `run:` steps, not curl-pipe-to-shell).

## Detection design

1. **`applies()` gate** — returns `True` unconditionally. The guard has three scan scopes
   with *different* gating rules (see point 2), and `applies()` can only express a
   single boolean for the whole guard — it cannot say "scope A only if feature X, scope
   B always." Since the `.sh` scope is universal, the guard is always at least partially
   relevant, so `applies()` returning `True` and pushing the Dockerfile-specific gate
   into `run()` is the only way to honor both halves of the intended behavior without
   either false-negative-ing every `.sh` file in a non-Docker repo (gating the whole
   guard on `"docker" in profile.features` would do that) or scanning Dockerfiles that
   don't exist (in practice a non-issue either way — `"docker" in profile.features` is
   only ever true when `has_docker` detected a real Dockerfile, so `iter_dockerfiles()`
   returns `[]` regardless when none exists; the in-`run()` gate is a defensive, explicit
   mirror of `docker_apt_update_not_alone.py`'s intent, not a behavior difference).
2. **What files are scanned:**
   - `.sh`/`.bash` files, via `iter_files(root, (".sh", ".bash"))` — **unconditional**,
     mirroring `untrusted_package_install_source.py`'s universal `.sh`/`.bash` scan (a shell
     script can exist in any repo regardless of detected stack).
   - Dockerfiles, via `iter_dockerfiles(root)` — only when `"docker" in
     profile.features`, mirroring `docker_apt_update_not_alone.py`'s gate exactly.
   - Python source (`.py`/`.pyi`) — only when `"python" in profile.features`. Scanned for the
     same pipeline hidden as ONE string literal passed to a shell-invoking sink:
     `subprocess.run`/`call`/`Popen`/`check_call`/`check_output`/`getoutput`/`getstatusoutput`
     or `os.system`/`popen` (from `rakshit-737/warden-supply-chain-security`'s
     `WX_DROP_Python_Shell_Download_Execute` YARA rule). The sink call's first string argument
     (plain or `f`-prefixed) is extracted, and the pattern in point 4 is matched against that
     text alone, so `subprocess.run("grep curl file | bash")` stays silent for the same reason
     the `.sh` form does. Fires MEDIUM as `curl-pipe-to-shell/python-subprocess-literal`.
   - All three file lists pass through `is_nonproduct_path()` first (test/fixture/example
     paths excluded).
3. **Line handling:** each file's text is joined with
   `join_dockerfile_continuations()` first (a generic backslash-line-continuation
   joiner, despite the name — reused as-is rather than duplicated) so a `RUN curl ... \`
   / `    | bash` pair, or the shell-script equivalent, is matched as one logical line
   with line numbers preserved. For a Dockerfile, only lines matching `^\s*RUN\s+(.+)$`
   are considered, and only the instruction's own command text is scanned (mirrors
   `docker_apt_update_not_alone.py`'s `_RUN_LINE`). For a `.sh` file every joined line is
   scanned directly. The pragma is read from the `hash` comment view of the joined text
   (before comment stripping, since the pragma itself lives inside a `#` comment), so a
   comment on a continuation line counts for its logical line and the phrase inside a
   quoted string does not (#1040); a `.py` file is read through the `python` view. The actual pattern
   match runs on the line after `strip_hash_comments()` (a whole-line or trailing `#`
   comment can never fire).
4. **The pattern:** `(?:^|[|&;(])\s*(?:sudo\s+)?(?:curl|wget)\b.*(?<!\|)\|(?!\|)\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|python3?|perl|ruby)\b`
   — `curl`/`wget` in **command position** (line start or right after a `|`/`&`/`;`/`(`
   separator, optionally via `sudo`), followed eventually by a **single** `|` piping into
   an interpreter (optionally via `sudo`). Tightened from drogonsec's source regex three ways:
   (a) word boundaries on both ends (so `sh` can't match inside `shellcheck`, and `curl`/`wget`
   can't match inside a longer identifier); (b) the command-position anchor, so `curl` as an
   *argument* (`grep curl file | sh`, `cat curl-notes.txt | sh`) no longer false-positives;
   (c) a single-pipe match `(?<!\|)\|(?!\|)`, so the OR-fallback idiom `curl -f url || bash x`
   (run bash only if curl fails) no longer false-positives. `.*` (not `[^|]*`) keeps the
   multi-stage `curl ... | grep ... | bash` true positive. `python3` alongside `python`;
   `zsh`/`dash` added as common POSIX-family shells.
5. **Inline opt-out pragma:** `# security: allow-curl-pipe-shell` on the offending line.
6. **Severity / rule / standards:** fires MEDIUM, one rule
   `curl-pipe-to-shell/unverified-pipe`, standards `["OWASP:A08", "CWE-829"]`.

## When NOT to flag

- A `curl`/`wget` that only downloads to a file (`curl -o install.sh https://...`, no
  `|` at all) is not flagged — the script lands on disk where it CAN be reviewed, even
  if the repo doesn't actually review it. That's a weaker, unproven claim this guard
  deliberately doesn't make.
- `curl ... | jq`, `curl ... | grep`, `curl ... | tee file` and any other non-interpreter
  pipe target are not flagged — piping into a data/text tool is not code execution.
- A commented-out example (`# curl ... | bash`, whole-line or trailing) is not flagged —
  `strip_hash_comments()` removes it before the pattern match runs.
- The pragma is for an audited, deliberate case — e.g. a script that's already
  checksum-verified upstream of the pipe by some other mechanism the guard can't see
  (a signed-URL CDN, an internal mirror with its own integrity gate), or a build step
  the team has explicitly accepted the risk on.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_curl_piped_to_bash_in_dockerfile` | `RUN curl ... \| bash` in a Dockerfile fires MEDIUM |
| `test_fires_on_wget_piped_to_sh_in_shell_script` | `wget -qO- ... \| sh` in a `.sh` file fires |
| `test_fires_on_dockerfile_line_continuation` | `RUN curl ... \` continued onto `    \| bash` still fires (continuations joined) |
| `test_silent_on_download_only_no_pipe` | `curl -o file url` (download only, no pipe) stays silent |
| `test_silent_on_commented_out_example` | A `#`-commented example line stays silent |
| `test_pragma_silences` | `# security: allow-curl-pipe-shell` on the line silences it |
| `test_dockerfile_not_scanned_without_docker_feature` | A Dockerfile present but `"docker"` not in `profile.features` is not scanned (the `.sh` scope stays unconditional) |
| `test_applies_gate_is_universal` | `applies()` returns `True` regardless of features |
| `test_silent_on_or_fallback_idiom` | `curl -f url \|\| bash restart.sh` (OR-fallback, not a pipe) stays silent — single-pipe match |
| `test_silent_on_curl_as_argument_not_command` | `grep curl file \| sh` / `cat curl-notes.txt \| sh` (curl is an argument) stays silent — command-position anchor |
| `test_fires_on_curl_after_shell_separator` | `set -e && curl ... \| bash` (curl after `&&`) fires |
| `test_fires_on_multi_stage_download_filter_execute` | `curl ... \| grep -v '#' \| bash` (multi-stage pipe) still fires |
| `test_fires_on_bash_extension_shell_script` | `curl ... \| bash` in a `.bash` file fires (`.sh`/`.bash` scope) |
| `test_fires_on_subprocess_run_with_curl_pipe_shell_string` | `subprocess.run("curl ... \| bash", shell=True)` fires (Python scope) |
| `test_fires_on_os_system_with_wget_pipe_sh_string` | `os.system("wget -qO- ... \| sh")` fires |
| `test_python_scan_not_run_without_python_feature` | the Python scope is gated on `"python"` |
| `test_silent_on_argv_list_form_no_literal_pipe` | the argv list form (no shell string) stays silent |
| `test_silent_on_curl_as_argument_not_command_inside_sink_string` | `grep curl file \| bash` inside a sink string stays silent |
| `test_silent_on_commented_out_sink_call_example` | a `#`-commented sink call stays silent |
| `test_pragma_silences_python_scope` | the pragma silences the Python scope |

## Known bypasses

- **Indirection through a variable/heredoc:** `URL=https://...; SCRIPT=$(curl -s "$URL"); echo "$SCRIPT" | bash`
  splits the download and the pipe across two commands/lines — the single-line regex
  never sees `curl` and the interpreter pipe on the same logical line.
- **A non-listed interpreter:** `curl ... | node`, `curl ... | php`, or a custom
  interpreter shim is not in the fixed alternation and is missed.
- **`eval "$(curl -s url)"`** — command substitution into `eval` achieves the same
  effect without a literal `|` pipe character at all; out of scope for this pattern
  (a different, `eval`-shaped guard would be needed).
- **A wrapper function:** `download_and_run() { curl -s "$1" | bash; }` followed by
  calls to the wrapper elsewhere would still be caught at the definition site (the
  pipe is still on one line), but a fully parameterized, multi-file indirection could
  obscure it further than this guard's single-line regex reasons about.
- **A command wrapper before `curl`/`wget`:** `time curl ... | bash`, `env FOO=bar curl ... |
  bash`, `nohup`/`exec`/`nice curl ... | bash` are NOT matched — the wrapper is neither a shell
  separator nor `sudo`, so `curl` is not in command position. This is the accepted flip side of
  not false-positiving on `curl` as an argument (`grep curl file | sh`): `time curl` and `grep
  curl` are structurally identical, so position alone cannot distinguish them. The removed FP is
  the more common case, so the anchor stays and this narrow miss is documented, not chased.
- **File types beyond `.sh`/`.bash`/Dockerfile/Python:** a `.zsh`, `.ps1`, Makefile recipe
  line, or CI YAML `run:` block containing the same pattern is not scanned by this guard (scope
  is deliberately narrow — `.sh`/`.bash` scripts, Dockerfile `RUN` when `docker` is detected,
  and Python shell-sink string literals when `python` is detected).
- **Python scope, per line and literal only.** The sink call and its whole string argument
  must sit on one line, so a multi-line call, a command built by concatenation or held in a
  variable, an aliased sink (`from subprocess import run`), a raw `r"..."` string, and the list
  form `["bash", "-c", "curl ... | sh"]` are all missed. The scan reads ordinary single-line
  string literals, so a docstring or `print(...)` that quotes a sink call as an EXAMPLE fires,
  and a pragma written inside the string literal itself silences the line.

## What this guard does NOT prove

A silent guard does not mean the repo is free of unverified remote-code execution — it
only means no `curl`/`wget` output is piped into a listed interpreter on a single
logical line in a `.sh` file, (when `docker` is detected) a Dockerfile `RUN`
instruction, or (when `python` is detected) a one-line Python shell-sink string literal. It
says nothing about: JS/TS/CI-YAML/Makefile equivalents of the same
pattern, multi-step indirection through variables or `eval`, or a script that IS piped
to a file first but then executed unreviewed by a subsequent line (`curl -o x.sh url &&
bash x.sh` is intentionally not flagged — it's a materially different, less severe
pattern than a direct pipe, since the file at least exists to be reviewed/diffed even if
nothing here proves anyone actually reviewed it).

## Checklist mapping

Not wired here — `agentsec/checklist/checklist.json` is a shared file updated in the
integration pass after all workers finish (see the build task's file-ownership rules).

## Standards

- OWASP:A08 (Software and Data Integrity Failures)
- CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)

## Related guards

- `docker-apt-update-not-alone`: the sibling Dockerfile integrity-adjacent guard (stale
  package index across layers) that this guard's file scope and shape were modeled on.
- `untrusted-package-install-source`: a different unverified-source concern (`pip`/`npm`
  installing directly from a URL/git ref instead of the registry) that established the
  precedent for an unconditional `.sh`/`.bash` scan this guard reuses.

# Citations

[1] agentsec checklist item `5-curl-pipe-to-shell` (§5)
[2] CWE-829
[3] OWASP:A08
