---
type: Guard
title: "skill-untrusted-exec-path"
description: "Install/skill-setup code resolves an executable from a workspace-controlled source with no absolute-path pin."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "skill-untrusted-exec-path"
checklist_section: ["8"]
standards: ["CWE-426", "OWASP-ASI:ASI04"]
---

# Install/skill-setup code resolves an executable from a workspace-controlled source

_Author — 2026-09-26_

---

## The threat

CVE-2026-53819 (CVSS 8.7): per NVD, "OpenClaw before 2026.5.27 contains an arbitrary code
execution vulnerability in skill install flows where workspace `.env` files can override
the Homebrew executable selection ... execute unintended Homebrew-compatible executables
during skill setup to compromise the system." CWE-426 (Untrusted Search Path),
OWASP-ASI:ASI04. Skill-install code that resolves "which binary to run" from
workspace-controlled input (a `.env` file, a tainted `PATH`) executes whatever the
workspace points at, not what the author intended — and a skill bundle is exactly the kind
of content that can arrive from an untrusted source. Sourced from `agent-audit-kit`'s
`skill_untrusted_exec_path.py` (AAK-SKILL-UNTRUSTED-EXEC-PATH), verified against the real
repo source.

## Why it's often introduced

Reading a tool's location from an environment variable or resolving it via `PATH` (rather
than hardcoding an absolute path) is normal, portable install-script practice — the bug is
specifically when that same workspace can ALSO control the `.env`/`PATH` value the
resolution reads from, collapsing "portable" into "attacker-directed."

## Detection design

1. `applies()` returns `True` unconditionally.
2. Scans `.py`/`.sh`/`.bash` files (`iter_files`), gated first by an install/skill-setup
   context signal (filename matching `install`/`setup`/`bootstrap`/`provision`/
   `postinstall`/`skill`, or content mentioning `SKILL.md`/`load_dotenv`/`homebrew`/`brew`)
   — this keeps the guard from firing on ordinary application code that happens to read an
   env var and spawn a subprocess.
3. Python, via `ast`: collects names bound to an env-sourced value (`os.environ.get(...)`/
   `os.getenv(...)`/`dotenv_values(...)[...]`) or a `shutil.which(...)` result (skipping
   any absolute-literal-pinned assignment), and whether `PATH` is tainted: `load_dotenv(
   override=True)` (a bare `load_dotenv()` uses `override=False`, which never replaces an
   existing `PATH`, so it does not taint), `os.environ.update(<dotenv_values>)`, or
   `os.environ["PATH"]` reassigned to something non-absolute or built from a name/call rather
   than a pure literal. An `env=` built from `dotenv_values(...)` passed to the spawn taints
   that spawn. Then finds an exec sink
   (`subprocess.run/Popen/call/check_call/check_output`, `os.system`/`os.popen`/
   `os.exec*`/`os.spawn*`) whose command expression: references an env-sourced name;
   references a `shutil.which` result (or calls it directly) while `PATH` is tainted; is
   itself an env read; or is a bare binary name (no path separator) while `PATH` is
   tainted.
4. Shell: a `PATH` prepend with a non-absolute element (a `$HOME/...` or `~/...` prepend, the
   standard uv/pipx/cargo install idiom, is per-user and benign), or a sourced `.env`,
   followed by a bare `brew`/`npm`/`node`/`pip`/`python`/`uv` invocation.
5. FP guards (both languages): an absolute-path-literal command, or an
   `os.path.isabs`/allowlist marker anywhere in the file.
6. Inline opt-out: a `# security: allow-skill-untrusted-exec-path` comment anywhere in the file
   (Python or shell) silences the file (a string literal quoting the phrase does not count, #424).
7. Rule `skill-untrusted-exec-path/untrusted-search-path`, standards
   `["CWE-426", "OWASP-ASI:ASI04"]`.

## When NOT to flag

- The resolved command is pinned to an absolute path literal.
- An `os.path.isabs`/allowlist check present anywhere in the file.
- The same code shape in a file with no install/skill-setup context at all.

## Tests

| Test | What it checks |
|---|---|
| `test_env_sourced_binary_fires` | `os.environ.get()` feeds an exec sink — fires |
| `test_which_over_tainted_path_fires` | `shutil.which()` over a `load_dotenv(override=True)`-tainted PATH — fires |
| `test_load_dotenv_without_env_read_does_not_taint_bare_spawn` | Bare `load_dotenv()` then `gh auth status` — silent |
| `test_load_dotenv_override_true_taints_bare_spawn` | `override=True` then a bare `brew` spawn — fires |
| `test_load_dotenv_override_false_is_not_tainted` | `override=False` — silent |
| `test_dotenv_values_env_passed_to_spawn_fires` | A dotenv-derived `env=` on a bare-name spawn — fires |
| `test_which_result_spawned_with_dotenv_env_fires` | `shutil.which` result spawned with a dotenv `env=` — fires |
| `test_shell_home_path_prepend_is_benign` | `export PATH="$HOME/.local/bin:$PATH"` — silent |
| `test_shell_relative_path_prepend_still_fires` | `export PATH="./bin:$PATH"` — fires |
| `test_absolute_path_pin_is_safe` | An absolute literal command — silent |
| `test_allowlist_marker_present_is_safe` | An `ALLOWED_BINARIES` marker — silent |
| `test_not_install_context_is_safe` | Same shape, no install context — out of scope |
| `test_shell_install_script_fires` | Shell `.env` source + bare `brew` — fires |
| `test_pragma_suppresses_finding` | Inline pragma silences it |
| `test_skill_untrusted_exec_path_pragma_quoted_in_a_string_does_not_suppress`, `test_skill_untrusted_exec_path_pragma_comment_suppresses_sh`, `test_skill_untrusted_exec_path_pragma_quoted_in_a_string_does_not_suppress_sh` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6) |
| `test_guard_applies_universally` | `applies()` is unconditionally `True` |

## Known bypasses

- Single-file, AST-scoped: taint tracked across an import boundary (a helper module that
  sets `PATH`, called from the file that spawns) is not traced.
- The install-context filename/content vocabulary is a fixed set; an install script with
  none of the recognized names/markers is invisible.
- The shell-side check is a narrower regex path than the Python AST analysis and only
  recognizes the specific `PATH=`/`source .env` + bare-tool-name shape.
- A `PATH` prepend that starts with `$HOME`/`~` but also carries a later relative element
  (`$HOME/bin:./bin:$PATH`) is treated as the benign per-user idiom.

## False-positive mechanisms that remain

- Taint is per file, not per call path: once the file has `load_dotenv(override=True)` or a
  dotenv `env=`, every bare-name spawn later in the file is flagged, including ones whose
  executable the `.env` cannot influence.
- In shell, `source .env` is treated as able to set `PATH` (a shell `.env` can assign it
  directly), so a sourced `.env` followed by any bare `npm`/`uv`/`python` matches whether or
  not that `.env` sets `PATH`.
- The env-read-to-executable check follows plain assignment, not data flow: a variable that
  only shares a name with an env-sourced one still matches.

## What this guard does NOT prove

Silence does not prove the resolved binary is safe at runtime — only that no code path this
guard recognizes reads the executable from a workspace-tainted `.env`/`PATH` source. A
taint path through a helper function or a language this guard doesn't scan is outside its
detection surface.

# Citations

[1] agentsec checklist item `8-skill-untrusted-exec-path` (§8)
[2] CVE-2026-53819 (OpenClaw < 2026.5.27, CVSS 8.7)
[3] CWE-426, OWASP-ASI:ASI04
[4] agent-audit-kit `skill_untrusted_exec_path.py`, rule AAK-SKILL-UNTRUSTED-EXEC-PATH
