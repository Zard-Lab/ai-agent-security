"""Guard: no OS-command injection via a shell sink (checklist §3b).

A shell sink that receives interpolated, concatenated, or variable input runs
whatever the attacker can steer that string to — `os.system(f"ping {host}")`
with `host = "8.8.8.8; rm -rf /"` is remote code execution. This is the sibling
of SQL injection (`3b-sql-parameterized`) for the OS shell, and a top agent-tool
risk: a tool that shells out turns one prompt injection into host RCE.

Fires CRITICAL on a shell sink whose argument is **dynamic** (an f-string,
`+`/`%`/`.format` concatenation, or a bare variable):

  * always-shell sinks — `os.system`, `os.popen`, `subprocess.getoutput`,
    `subprocess.getstatusoutput`, `commands.getoutput`;
  * `subprocess.run/call/Popen/check_output/check_call(..., shell=True)`.

A static string literal (`os.system("ls -la")`) does NOT fire. The fix is
array-form exec without a shell: `subprocess.run(["ping", host])`. Suppress an
audited case with:

    os.system(cmd)  # security: allow-shell-exec

Also fires CRITICAL on the argv-list form that recommendation itself would produce, when the array's
first element names a code interpreter (`bash`/`sh`/`python`/`python3`/`node`/`perl`/`ruby`/...) and
the array also carries a code-exec flag (`-c`/`-e`/`--eval`) whose trailing argument is dynamic —
`subprocess.run(["bash", "-c", user_cmd])` never sets `shell=True` and is not an always-shell sink,
but it re-invokes a shell/interpreter one level down with attacker-steerable code, so the array form
alone does not make it safe. `subprocess.run(["python3", "-c", "print('static')"])` does NOT fire —
the interpreter's own argument is a literal, not attacker-controlled.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    _SL_STRING,
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_ALWAYS_SHELL = re.compile(
    r"\b(?:os\.system|os\.popen[234]?|subprocess\.getoutput|"
    r"subprocess\.getstatusoutput|commands\.getoutput)\s*\("
)
_SUBPROCESS = re.compile(r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(")
_SHELL_TRUE = re.compile(r"\bshell\s*=\s*True\b")
# One call argument's `name=` keyword head (`name == x` is a comparison, not a keyword).
_KWARG = re.compile(r"\s*([A-Za-z_]\w*)\s*=(?!=)")
_PRAGMA = re.compile(r"#\s*security:\s*allow-shell-exec")

# Argv-list form: subprocess.run(["bash", "-c", cmd]) — no shell=True, not an always-shell sink,
# but the array's own first element re-invokes a shell/interpreter one level down.
_ARGV_SUBPROCESS = re.compile(
    r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*\[([^\]]*)\]"
)
_CODE_INTERPRETERS = frozenset(
    {"bash", "sh", "dash", "zsh", "ksh", "python", "python3", "python2", "node", "nodejs", "perl", "ruby"}
)
_CODE_FLAGS = frozenset({"-c", "-e", "--eval"})
_QUOTED = re.compile(r"""^(['"])(.*)\1$""")

# An argument is "dynamic" (attacker-steerable) if it is an f-string, a format/
# concat expression, or has no string literal at all (a bare variable).
_FSTRING = re.compile(r"(?:^|[\s(,=+])[rR]?[fF]['\"]")
_PCT = re.compile(r"%[sdrfeg]|['\"]\s*%|%\s*\(")
_CONCAT = re.compile(r"['\"]\s*\+|\+\s*['\"]")


def _is_dynamic(arg: str) -> bool:
    a = arg.strip()
    if not a:
        return False
    if _FSTRING.search(a):
        return True
    if "'" not in a and '"' not in a:  # no literal anywhere -> a variable/expression
        return True
    if ".format(" in a:
        return True
    if _PCT.search(a):
        return True
    return bool(_CONCAT.search(a))


def _split_list_items(items: str) -> list[str]:
    """Split an argv-list's inner text on top-level commas, quote-aware: a comma INSIDE a
    single- or double-quoted element is content, not a separator (Dean's review repro,
    the bare `split(",")` cut `["python3","-c","print(1, 2)"]`'s static payload at
    the comma inside `print(1, 2)`, so the fractured last fragment `' 2)"'` no longer matched
    `_QUOTED`'s whole-literal shape and the guard read a fully static call as dynamic — CRITICAL
    on code with no attacker-reachable input at all). A backslash inside a quoted element
    escapes the next character (so an escaped quote can't end the element early); this is
    still line-scoped, matching this module's existing "good enough for the single-line shapes
    this guard targets" tolerance (see `_call_args`). No nested `[`/`(` tracking either — a
    subprocess argv list nesting a call or another list inside one of its elements is rare
    enough not to warrant a real bracket-depth walk."""
    parts: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i, n = 0, len(items)
    while i < n:
        ch = items[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < n:
                buf.append(items[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch == ",":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def _argv_invokes_interpreter_with_dynamic_code(items: str) -> bool:
    """True if the argv list's first element names a code interpreter, a later element is a
    code-exec flag (`-c`/`-e`/`--eval`), and the list's LAST element is not a plain string
    literal. `_QUOTED` only matches a token that is ENTIRELY one quoted string with nothing
    else attached, so an f-string (`f"..."`, prefix breaks the match), a format/concat
    expression (trailing `.format(...)`/`+ x`, suffix breaks the match), and a bare variable
    all correctly fail it and count as dynamic — no separate check needed for those shapes."""
    parts = _split_list_items(items)
    if len(parts) < 3:
        return False
    first = _QUOTED.match(parts[0])
    if not first or first.group(2).lower() not in _CODE_INTERPRETERS:
        return False
    if not any((q := _QUOTED.match(p)) and q.group(2) in _CODE_FLAGS for p in parts):
        return False
    return _QUOTED.match(parts[-1]) is None


def _call_args(line: str, masked: str, start: int) -> list[tuple[str | None, str]]:
    """Split the call whose arguments begin at `start` (just past its `(`) into one
    `(keyword or None, text)` pair per top-level argument. The walk runs on `masked`, the line
    with its single-line string literals blanked to same-length spaces, so a comma or bracket
    inside a literal (`"a, b" + x`, `"%s %s" % (a, b)`) is never structure. The text is sliced
    from the ORIGINAL `line` at the same offsets, because `_is_dynamic` needs the real quotes.
    `([{` depth is tracked, so `env={"A": "1", "B": x}` stays one argument. The walk stops at
    the call's own `)`, and a call still open at the end of the line (a multi-line call) is
    closed there: good enough for the single-line shell sinks this guard targets."""
    out: list[tuple[str | None, str]] = []
    depth, seg = 0, start
    for j in range(start, len(masked) + 1):
        ch = masked[j] if j < len(masked) else ")"
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth:
            depth -= 1
        elif ch in ",)" and depth == 0:
            kw = _KWARG.match(masked, seg, j)
            if kw:
                out.append((kw.group(1), line[kw.end() : j]))
            elif masked[seg:j].strip():
                out.append((None, line[seg:j]))
            seg = j + 1
            if ch == ")":
                break
    return out


def _command_arg(line: str, masked: str, start: int) -> str:
    """The sink's COMMAND argument, the only text `_is_dynamic` may judge: the first positional
    argument, else the `args=` keyword's value (`shell=True` passed first, #972). Judging a wider
    span let an unrelated literal hide a bare-variable command (`subprocess.run(cmd, cwd="/tmp",
    shell=True)`, `os.popen(cmd, "r")`) and let unrelated dynamic text convict a static one
    (`subprocess.run("make", cwd=base + "/x", shell=True)`) (#971). When the command is reachable
    only through a `**mapping` unpack, that unpack is its source and is judged instead (a bare
    `**opts` reads as a variable). No command on this line gives `""`, which is never dynamic."""
    args = _call_args(line, masked, start)
    for kw, val in args:
        if kw is None and not val.lstrip().startswith("**"):
            return val
    for kw, val in args:
        if kw == "args":
            return val
    return next((val for kw, val in args if kw is None), "")


class CommandInjectionGuard(Guard):
    id = "command-injection"
    title = "No OS-command injection via a shell sink"
    area = "Code safety"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # Canary plant: `os.system` with an f-string argument -> an untrusted shell sink.
    # FIRE-strings: `import os` (the sink's module) + the `os.system(f"...{service}")` call,
    # whose f-string interpolation is what makes the argument untrusted rather than a literal.
    # Kept as ONE single-line dict value, matching how it read in the canary base — a plant is
    # moved byte-verbatim, never reflowed (`test_assembled_canary_matches_golden` reports a
    # reformat as CHANGED, which is a failed migration, not something to re-pin away).
    # Second plant, a distinct file: `subprocess.run(["python3", "-c", code])` -> no `shell=True`,
    # not an always-shell sink, but the argv list's own first element re-invokes an interpreter
    # with a dynamic trailing argument. Kept in its own file rather than appended to `deploy.py`
    # so the existing plant string above stays untouched (never reflowed, per the note above it).
    canary_plant = CanaryPlant(
        files={
            "deploy.py": ("import os\n\n\ndef restart(service: str) -> None:\n    os.system(f\"systemctl restart {service}\")\n"),
            "argv_runner.py": ("import subprocess\n\n\ndef run_snippet(code: str) -> None:\n    subprocess.run([\"python3\", \"-c\", code])\n"),
        },
        expects=frozenset({"command-injection/shell-exec-untrusted", "command-injection/argv-interpreter-untrusted"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        dirs = python_scan_dirs(root, profile)
        seen: set[Path] = set()
        for d in dirs:
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                # Skip tests/fixtures/vendored trees (sibling code_injection_eval_exec does the
                # same): a planted shell-injection EXAMPLE in a test is not a product finding (#424).
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        # Blank triple-quoted docstring/template CONTENT so a shell-sink EXAMPLE in a docstring
        # (this guard's own module docstring self-matches, issue #424) doesn't fire. Single-line
        # f-strings/args in real calls are left intact, so detection is unaffected.
        raw = read(f)
        text = strip_python_strings(raw, filename=f)
        # The pragma counts only as a real comment on the line, never quoted in a string
        # there (#1040), numbered on the text walked below (a form feed in a docstring
        # shifts the raw count, #1132).
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
        for i, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#") or i in pragmas:
                continue
            # Both shell-sink branches judge only the sink's COMMAND argument (`_command_arg`), so
            # neither the other arguments nor trailing code on the line can sway the verdict (#971,
            # #972). The argument walk and the `shell=True` gate both run on a copy of the line whose
            # single-line string literals are masked to same-length spaces: a `,` or `shell=` inside
            # a literal is not structure (`subprocess.run("usermod --shell=/bin/zsh " + user,
            # shell=True)` keeps its dynamic tail), and a `shell=True` that only appears inside a
            # literal runs no shell (#589). The command text is sliced from the ORIGINAL line,
            # because `_is_dynamic` needs the real quotes.
            masked = _SL_STRING.sub(lambda m: " " * len(m.group()), line)
            m = _ALWAYS_SHELL.search(line)
            if m and _is_dynamic(_command_arg(line, masked, m.end())):
                out.append(self._finding(root, f, i))
                continue
            s = _SUBPROCESS.search(line)
            if s and _SHELL_TRUE.search(masked) and _is_dynamic(_command_arg(line, masked, s.end())):
                out.append(self._finding(root, f, i))
                continue
            a = _ARGV_SUBPROCESS.search(line)
            if a and _argv_invokes_interpreter_with_dynamic_code(a.group(1)):
                out.append(self._argv_finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title="OS command built from untrusted input",
            location=f"{rel(root, f)}:{line}",
            message=(
                "This shell call receives interpolated/variable input — an attacker who "
                "controls that string controls the command (e.g. `; rm -rf /`), giving "
                "remote code execution on the host."
            ),
            remediation=(
                "Use array-form exec without a shell: `subprocess.run([\"ping\", host])` "
                "(no `shell=True`). Never build a shell string from user/model input. If "
                "this call is audited-safe, suppress with `# security: allow-shell-exec`."
            ),
            rule="command-injection/shell-exec-untrusted",
            standards=["OWASP:A03", "OWASP-LLM:LLM05"],
        )

    def _argv_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title="Interpreter re-invoked with untrusted code via an argv list",
            location=f"{rel(root, f)}:{line}",
            message=(
                "This argv-form call never sets `shell=True`, but its own array re-invokes a "
                "code interpreter (`bash -c`/`python -c`/`node -e`/...) with a dynamic trailing "
                "argument — an attacker who controls that argument controls what the "
                "interpreter runs, the same outcome as a shell-string injection one level down."
            ),
            remediation=(
                "Don't hand attacker-influenceable input to an interpreter's own -c/-e/--eval "
                "flag at all — call the target functionality directly, or pass the untrusted "
                "value as a separate argv element the interpreter receives as data, not code. "
                "If this call is audited-safe, suppress with `# security: allow-shell-exec`."
            ),
            rule="command-injection/argv-interpreter-untrusted",
            standards=["OWASP:A03", "OWASP-LLM:LLM05"],
        )
