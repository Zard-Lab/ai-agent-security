"""Guard: PHP OS-command injection via a tainted shell sink (checklist §3b).

A shell sink that receives interpolated, concatenated, or variable input runs whatever the
attacker can steer that string to — `system($_GET['host'])` with `host = "8.8.8.8; rm -rf /"` is
remote code execution. This is the PHP sibling of the Python `command-injection` guard
(`3b-command-injection`), targeting PHP's own OS-shell surface.

Detection target verified against graudit's real signature dictionary (`wireghoul/graudit`,
`signatures/php.db`, which flags `system`/`exec`/`passthru`/`popen`/`shell_exec`/`proc_open` as PHP
command-execution sinks) — the function list is cited for provenance; the "argument must be
dynamic, not a sole string literal" detection logic here is original, developed independently, not
copied from graudit's own (POSIX ERE, presence-only) implementation.

Fires CRITICAL on one of the six shell-executing functions —

    system, exec, passthru, popen, shell_exec, proc_open

— called with a first argument that is **not a sole string literal**:

  * a bare variable or superglobal (`$cmd`, `$_GET[...]`, `$_POST[...]`, `$_REQUEST[...]`,
    `$_COOKIE[...]`, `$_ENV[...]`, `$_SERVER[...]`);
  * string concatenation with `.` (even of two literals — the *shape* is the risk signal, matching
    the Python sibling's stance on f-string/concat/`.format()`);
  * a function-call result (`getUserCommand()`);
  * a double-quoted string literal that itself contains a `$` — PHP interpolates variables inside
    `"..."` (unlike `'...'`), so `system("ping $host")` is exactly as tainted as `system($host)`.

A single-quoted string literal, or a double-quoted string literal with no `$` inside it (no
interpolation possible), is a fixed command and does NOT fire — `system('ls -la')` and
`system("ls -la")` are both silent.

A sink name that is merely quoted string DATA — e.g. a diagnostic message describing a command
that was attempted elsewhere (`'shell_exec(' . self::PS_COMMAND . '...'`) — does NOT fire either
(#848 corpus scan, matomo-org/matomo real-world case): the guard tracks PHP string-literal state
(including across lines, since a `.`-concatenated string can span a literal newline) and rejects a
sink match sitting inside an active string literal.

Suppress an audited case (e.g. the value is validated/allow-listed immediately above, or the call
is a deliberate, reviewed exception) with:

    exec($cmd); // security: allow-php-shell-exec
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    iter_files,
    php_scan_dirs,
    read,
    rel,
    strip_php_comments,
    strip_php_heredocs,
)

_STANDARDS = ["OWASP:A03", "OWASP-LLM:LLM05"]

# The six graudit-verified PHP shell-executing sinks. `\b` in front is safe against a longer
# identifier ending in one of these names (e.g. `myexec(`) because the character immediately
# before the boundary would be a word character (no boundary there); it is NOT fooled by
# `shell_exec(` matching bare `exec(` either, since `_` is a word character in regex and there is
# therefore no `\b` between `shell_` and `exec`.
_SHELL_SINK = re.compile(r"\b(?:system|exec|passthru|popen|shell_exec|proc_open)\s*\(")

# A trimmed argument that is exactly ONE quoted string literal (no leading/trailing junk, so a
# concatenation like `'a' . $b` does not match) — escape-aware for both quote kinds.
_SOLE_STRING_LITERAL = re.compile(r"""^(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")$""")

_PRAGMA = "security: allow-php-shell-exec"


def _first_arg(line: str, open_paren: int) -> str:
    """Return the text of the first (comma-separated, top-level) argument starting just after the
    `(` at index `open_paren`. Quote- and paren-depth-aware so a comma inside a nested call or a
    string literal doesn't end the argument early. Single-line only, matching every other guard in
    this codebase (no multi-line argument tracking)."""
    buf: list[str] = []
    i = open_paren + 1
    n = len(line)
    depth = 0
    quote = ""
    while i < n:
        c = line[i]
        if quote:
            if c == "\\" and i + 1 < n:
                buf.append(c)
                buf.append(line[i + 1])
                i += 2
                continue
            if c == quote:
                quote = ""
            buf.append(c)
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
            continue
        if c == "(":
            depth += 1
            buf.append(c)
            i += 1
            continue
        if c == ")":
            if depth == 0:
                break
            depth -= 1
            buf.append(c)
            i += 1
            continue
        if c == "," and depth == 0:
            break
        buf.append(c)
        i += 1
    return "".join(buf)


def _string_state_at(line: str, pos: int, open_quote: str) -> str:
    """The active PHP quote state (`""`, `"'"`, or `'"'`) right before `line[pos]`, given the state
    carried in from a PRIOR line (`open_quote`) — a `.`-concatenated string can legally contain a
    literal newline. Escape-aware for double-quoted strings; treating any `\\` as an escape char
    inside a single-quoted string too is a safe over-approximation for this narrow use.

    Used to reject a sink-name match that is merely quoted string DATA — e.g. a diagnostic message
    describing what command was attempted (`'shell_exec(' . self::PS_COMMAND . '...'`) — from being
    read as an actual call (#848 corpus scan: matomo-org/matomo's `core/CliMulti/Process.php:240`).
    A real call is never itself inside a string literal, so this costs nothing on the
    true-positive path."""
    quote = open_quote
    i = 0
    n = min(pos, len(line))
    while i < n:
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in ("'", '"'):
            quote = c
        i += 1
    return quote


def _is_dynamic(arg: str) -> bool:
    """True if `arg` is anything other than a fixed command: empty means "no argument at all"
    (not this guard's concern), a sole single-quoted literal or a sole `$`-free double-quoted
    literal is fixed/safe, everything else (bare variable, superglobal, concatenation, a
    function-call result, or a `$`-interpolated double-quoted literal) is tainted."""
    a = arg.strip()
    if not a:
        return False
    if _SOLE_STRING_LITERAL.fullmatch(a):
        return a[0] == '"' and "$" in a
    return True


class PhpCommandInjectionGuard(Guard):
    id = "php-command-injection"
    title = "No OS-command injection via a PHP shell sink"
    area = "Code safety"

    # CommandInjection.php: system($_GET['host']) -> php-command-injection/tainted-shell-sink.
    canary_plant = CanaryPlant(
        files={
            "CommandInjection.php": (
                "<?php\n"
                "function pingHost() {\n"
                "    return system($_GET['host']);\n"
                "}\n"
            ),
        },
        expects=frozenset({"php-command-injection/tainted-shell-sink"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "php" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in php_scan_dirs(root, profile):
            for f in iter_files(d, (".php",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # The pragma check runs on the COMMENT-ONLY view of the line — it IS the comment
        # `strip_php_comments` below would blank, and a string quoting it must not count (#424).
        view_lines = comment_view(text, "php").splitlines()  # same length: comments only (#424)
        # `strip_php_heredocs` runs FIRST so a heredoc/nowdoc body's ordinary prose (which can
        # contain an odd number of quote characters with no PHP significance) can never desync the
        # cross-line `open_quote` tracking below (#848 / PR #884 review). Both stages are
        # length-preserving, so the two line lists still pair up exactly.
        code_lines = strip_php_comments(strip_php_heredocs(text)).splitlines()
        open_quote = ""  # PHP string state carried across lines (#848 corpus scan)
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            line_open_quote = open_quote
            open_quote = _string_state_at(line, len(line), open_quote)
            if _PRAGMA in view:
                continue
            for m in _SHELL_SINK.finditer(line):
                if _string_state_at(line, m.start(), line_open_quote):
                    continue  # the sink NAME itself is quoted string data, not a live call
                arg = _first_arg(line, m.end() - 1)
                if _is_dynamic(arg):
                    out.append(self._finding(root, f, i))
                    break
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title="OS command built from untrusted input",
            location=f"{rel(root, f)}:{line}",
            message=(
                "This shell sink (system/exec/passthru/popen/shell_exec/proc_open) receives a "
                "variable, superglobal, concatenated, or interpolated argument — an attacker who "
                "controls that value controls the command (e.g. `; rm -rf /`), giving remote "
                "code execution on the host."
            ),
            remediation=(
                "Validate/allow-list the value before it reaches the shell, or avoid the shell "
                "sink entirely (e.g. use a native PHP extension instead of shelling out). If "
                "escaping is unavoidable, wrap every dynamic piece with escapeshellarg()/"
                "escapeshellcmd(). If this call is audited-safe, suppress with "
                "`// security: allow-php-shell-exec`."
            ),
            rule="php-command-injection/tainted-shell-sink",
            standards=list(_STANDARDS),
        )
