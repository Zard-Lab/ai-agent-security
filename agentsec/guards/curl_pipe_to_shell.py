"""Guard: curl/wget output piped directly into an interpreter, unverified
(checklist §5-adjacent; drogonsec `SH-004`, verified against the real Go source).

    RUN curl -fsSL https://get.docker.com | bash
    wget -qO- https://example.com/install.sh | sh

Downloading a script and piping it straight into an interpreter (`bash`, `sh`, `python`,
`perl`, `ruby`, ...) executes it with zero inspection: no file lands on disk to diff,
review, or checksum/signature-verify before it runs. An attacker who compromises the
download host, poisons DNS, or sits on-path for a plain-HTTP fetch gets arbitrary code
execution with the privileges of whatever ran the pipeline — inside a Docker build this
is the image's build-time privileges (often root). This is a classic software/data
integrity failure: OWASP:A08 (Software and Data Integrity Failures), CWE-829 (Inclusion
of Functionality from Untrusted Control Sphere). The pattern is sourced from drogonsec's
`SH-004` shell rule (`(?i)(curl|wget).*\\|\\s*(bash|sh|python|perl|ruby)`), tightened here
with word boundaries (so `sh` doesn't match inside `shellcheck`) and an optional
`sudo`/`python3` before the interpreter.

Three scan scopes, one shared pattern:

  * **Dockerfiles** (`RUN` instructions, backslash line-continuations joined into one
    logical line first — a `RUN curl ... \\` / `    | bash` pair is a realistic
    real-world shape) — gated on `"docker" in profile.features` (mirrors
    `docker_apt_update_not_alone.py`'s gate exactly: a Dockerfile-only signal, on only
    when a Dockerfile was actually detected).
  * **Shell scripts** (`.sh`/`.bash` files, every line, continuations joined the same way) —
    scanned UNCONDITIONALLY. A shell script can exist in any repo regardless of detected
    stack (mirrors `untrusted_package_install_source.py`'s universal `.sh`/`.bash` scan).
  * **Python source, same pipeline hidden inside a `subprocess`/`os.system`/`os.popen` string
    argument** (mined from `rakshit-737/warden-supply-chain-security`'s
    `WX_DROP_Python_Shell_Download_Execute` YARA rule, fetched and read in full): a shell
    script lands this guard's existing scan; the exact same pipeline hidden as ONE Python
    string literal (`subprocess.run("curl https://x/y | bash", shell=True)`) did not, before
    this extension — gated on `"python" in profile.features`. **Reuses the existing,
    already-FP-hardened `_CURL_PIPE_SHELL` pattern verbatim** rather than writing a second,
    looser one: the sink-call string argument is extracted first, then `_CURL_PIPE_SHELL` is
    matched against just that extracted text (treated as its own "line", so the `^`/separator
    anchor still means "start of the command string"). A naive sink-call regex with no
    extraction step would refire the exact FP this guard's own H1 fix removed —
    `subprocess.run("grep curl file | bash")` has `curl` as a `grep` ARGUMENT, not in command
    position, and the extraction-then-reuse design keeps that fix intact rather than
    reintroducing it under a new scan scope.

Because these three scopes have different gating rules but share one `run()`, `applies()`
itself returns `True` unconditionally (the guard is always relevant — there is always at
least the `.sh` scope to check) and the Dockerfile-vs-`docker`-feature gate is applied
INSIDE `run()` instead of at the `applies()` level. `applies()` cannot express "scan
scope A only if feature X, scope B always" with a single boolean, so pushing the
Dockerfile conditional into `run()` is the only way to honor both halves of the intended
gating without either false-negative-ing every `.sh` file in a non-Docker repo or
false-positive-scanning Dockerfiles that don't exist (in practice `"docker" in
profile.features` is only ever true when a Dockerfile was actually detected, so this is
a defensive/explicit mirror of the sibling guard's intent, not a behavior difference —
`iter_dockerfiles()` returns `[]` regardless when no Dockerfile exists).

A `#` line comment (whole-line or trailing) never fires — a documented example like
`# curl ... | bash  (do not do this)` is inert. Suppress an audited exception with
`# security: allow-curl-pipe-shell` on the offending line.

Known false negative (accepted trade-off): the command-position anchor requires `curl`/`wget`
at the start of the command or right after a shell separator, so a `curl | sh` invoked behind a
command *wrapper* — `time curl ... | bash`, `env FOO=bar curl ... | bash`, `nohup`/`exec`/`nice
curl ... | bash` — is NOT matched (the wrapper is neither a separator nor `sudo`). This is the
inescapable flip side of not false-positiving on `curl` as an *argument* (`grep curl file | sh`,
`cat curl-notes.txt | sh`): `time curl` and `grep curl` are structurally identical (a bare word,
a space, then `curl`), so position alone cannot tell "curl is the command" from "curl is an
argument". The removed false positive is the more common case, so the anchor stays and this
narrow miss is documented rather than chased.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_dockerfiles,
    iter_files,
    join_dockerfile_continuations,
    pragma_line_set,
    read,
    rel,
    strip_hash_comments,
    strip_python_line_comment,
)

_RUN_LINE = re.compile(r"^\s*RUN\s+(?P<cmd>.+)$", re.IGNORECASE)
_PY_SUFFIXES = (".py", ".pyi")

# `curl`/`wget` (in command position) ... a single `|` ... an interpreter (optionally via
# `sudo`). Three tightenings over drogonsec's bare `(curl|wget).*\|\s*(bash|...)`:
#   * `curl`/`wget` must be in COMMAND position — at the start of the (trimmed) command or right
#     after a shell separator (`|`, `&`, `;`, `(`) — so `curl` as an ARGUMENT to another command
#     (`grep curl file | sh`, `cat curl-notes.txt | sh`) no longer false-positives (M1).
#   * a SINGLE pipe `(?<!\|)\|(?!\|)`, never a `||` — so the OR-fallback idiom
#     (`curl -f url || bash restart.sh`, run bash only if curl fails) no longer false-positives (H1).
#   * interpreter word-boundaried so `sh` can't match inside `shellcheck`; `python3`/`python` both
#     covered via the optional trailing `3?`. `.*` (not `[^|]*`) between them so a multi-stage
#     download-filter-execute pipe (`curl url | grep -v '#' | bash`) still fires.
_CURL_PIPE_SHELL = re.compile(
    r"(?:^|[|&;(])\s*(?:sudo\s+)?(?:curl|wget)\b.*(?<!\|)\|(?!\|)\s*(?:sudo\s+)?"
    r"(?:bash|sh|zsh|dash|python3?|perl|ruby)\b",
    re.IGNORECASE,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-curl-pipe-shell")

_STANDARDS = ["OWASP:A08", "CWE-829"]

# the same curl/wget-piped-to-shell pipeline, hidden as ONE Python string literal
# passed to a shell-invoking sink, instead of a .sh file line. Extracts the sink call's string
# argument first; `_CURL_PIPE_SHELL` (above) is then matched against just that extracted text,
# never against the raw Python source line — see the module docstring for why a naive
# sink-call-plus-pattern regex with no extraction step would refire the exact `grep curl file |
# bash` false positive this guard's own H1 fix already removed.
_PY_SHELL_SINK_STRING_ARG = re.compile(
    r"\b(?:subprocess\s*\.\s*(?:run|call|Popen|check_call|check_output|getoutput|getstatusoutput)"
    r"|os\s*\.\s*(?:system|popen))\s*\(\s*f?(['\"])(?P<cmd>(?:(?!\1).)*)\1",
    re.IGNORECASE,
)


class CurlPipeToShellGuard(Guard):
    id = "curl-pipe-to-shell"
    title = "curl/wget output piped directly into an interpreter, unverified"
    area = "Dependencies"

    # install.sh: curl output piped straight into bash -> fires
    # curl-pipe-to-shell/unverified-pipe.
    # Must NOT contain: allow-curl-pipe-shell pragma.
    canary_plant = CanaryPlant(
        files={
            "install.sh": "curl -fsSL https://example.com/install.sh | bash\n",
        },
        expects=frozenset({
            "curl-pipe-to-shell/unverified-pipe",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        # Always relevant: the .sh scope below is universal (a shell script can exist in any
        # repo regardless of detected stack), so this can't gate on a single feature the way
        # docker_apt_update_not_alone.py does. See the module docstring for the full rationale.
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        sh_files = iter_files(root, (".sh", ".bash"))
        dockerfiles = iter_dockerfiles(root) if "docker" in profile.features else []
        for f in sh_files + dockerfiles:
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f, is_dockerfile=f in dockerfiles))
        if "python" in profile.features:
            for f in iter_files(root, _PY_SUFFIXES):
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan_python(root, f))
        return out

    def _scan_python(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        pragma_lines = pragma_line_set(_PRAGMA, text, dialect="python")
        for lineno, raw_line in enumerate(text.splitlines(), start=1):
            if not raw_line.strip():
                continue
            if lineno in pragma_lines:
                continue
            code = strip_python_line_comment(raw_line)
            for m in _PY_SHELL_SINK_STRING_ARG.finditer(code):
                if _CURL_PIPE_SHELL.search(m.group("cmd")):
                    out.append(self._finding_python(root, f, lineno))
        return out

    def _scan(self, root: Path, f: Path, *, is_dockerfile: bool) -> list[Finding]:
        out: list[Finding] = []
        joined = join_dockerfile_continuations(read(f))
        # The view of the JOINED text (same line numbers): a comment on a continuation line is part
        # of its logical line, as in the raw check, and a quoted span is read across the join.
        pragma_lines = pragma_line_set(_PRAGMA, joined, dialect="hash")
        for lineno, raw_line in enumerate(joined.splitlines(), start=1):
            if not raw_line.strip():
                continue
            if lineno in pragma_lines:
                continue

            cmd = raw_line
            if is_dockerfile:
                m = _RUN_LINE.match(raw_line)
                if not m:
                    continue
                cmd = m.group("cmd")

            code = strip_hash_comments(cmd)
            if _CURL_PIPE_SHELL.search(code):
                out.append(self._finding(root, f, lineno))
        return out

    def _finding(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "This line downloads a script with curl/wget and pipes it directly into an "
                "interpreter. Nothing is inspected, checksummed, or signature-verified before "
                "it runs — a compromised download host, a poisoned DNS response, or an "
                "on-path attacker on a plain-HTTP fetch gets arbitrary code execution with "
                "the privileges of whatever ran the pipeline."
            ),
            remediation=(
                "Download the script to a file first, review it (or verify its checksum/"
                "signature against a value published out-of-band), and only then execute the "
                "local file: `curl -fsSL -o install.sh https://... && sha256sum install.sh "
                "&& bash install.sh`. Suppress an audited exception with `# security: allow-"
                "curl-pipe-shell` on the offending line."
            ),
            rule="curl-pipe-to-shell/unverified-pipe",
            standards=list(_STANDARDS),
        )

    def _finding_python(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "This line passes a curl/wget-piped-to-interpreter pipeline as a single string "
                "argument to `subprocess`/`os.system`/`os.popen` — the same unverified-pipe risk "
                "as a shell script, just hidden inside a Python string literal instead of a "
                "`.sh` file."
            ),
            remediation=(
                "Download the script to a file first, review it (or verify its checksum/"
                "signature against a value published out-of-band), and only then execute the "
                "local file — never build a `curl ... | sh` pipeline as a shell string. "
                "Suppress an audited exception with `# security: allow-curl-pipe-shell` on the "
                "offending line."
            ),
            rule="curl-pipe-to-shell/python-subprocess-literal",
            standards=list(_STANDARDS),
        )
