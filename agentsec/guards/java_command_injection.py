"""Guard: no OS-command injection via a Java process-exec sink (checklist §3b).

The Java counterpart to agentsec's existing Python (`command-injection`) and JS/Node
(`js-command-injection`) guards — same requirement (a process-exec sink built from
untrusted/concatenated input is remote code execution), a genuinely different code
surface (`java.lang.Runtime`/`java.lang.ProcessBuilder` instead of `os`/`subprocess`
or Node's `child_process`), so it extends the same `3b-command-injection` checklist
item rather than duplicating it.

Sinks verified against Find Security Bugs' real source (rule `COMMAND_INJECTION`, sink
list `injection-sinks/command.txt`) — the sink names are cited for provenance; detection
logic and test fixtures here are original, developed independently against the pattern
description, not copied or derived from that (Java) source:

  * `Runtime.getRuntime().exec(...)` / `Runtime.exec(...)`
  * `new ProcessBuilder(...)`
  * `.command(...)` called on a `ProcessBuilder` instance

Fires CRITICAL when the sink's argument is **dynamic** — a `+` concatenation, or a bare
identifier/expression with no string literal at all — mirroring the "tainted, not
literal" heuristic `command_injection.py`/`js_command_injection.py` already use.

The single-string form is the classic vulnerable idiom this guard fires hardest on:
`Runtime.getRuntime().exec("cmd " + userInput)`. Java's single-string `exec()` overload
tokenizes the string itself (a naive whitespace split, not a real shell) before handing
argv[0..n] to the OS — the same "one string, attacker-steerable" shape as Python's
`os.system(f"...")` / `subprocess.run(..., shell=True)`. A fully static string literal
(`exec("ls -la")`) does NOT fire.

**Known, deliberate scope gap — array-literal arguments are never reasoned about.** The
array-argument form (`exec(new String[]{"cmd", "arg"})`) does not invoke a shell-like
tokenizer at all when every element is a literal, so it is correctly silent. But this
guard does not inspect array-literal CONTENTS at all — `exec(new String[]{"cmd",
userInput})`, with one tainted element, is **also silent**, a known bypass rather than
a proof of safety (no dataflow, text/regex-only). The same gap applies to a
`ProcessBuilder`/`.command()` call whose arguments are a comma-separated varargs list
mixing literals and a variable (`new ProcessBuilder("sh", "-c", cmd)`) — reasoning about
individual elements of a multi-argument call is out of scope for this guard, same as the
array case above.

Suppress an audited case with:

    Runtime.getRuntime().exec(cmd);  // security: allow-java-command-injection
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
    is_nonproduct_path,
    iter_files,
    java_scan_dirs,
    read,
    rel,
    strip_java_comments,
)

# `Runtime.getRuntime().exec(` or the bare `Runtime.exec(` spelling (both listed as sinks by Find
# Security Bugs' COMMAND_INJECTION rule). Case-sensitive: matches the real JDK class name.
_RUNTIME_EXEC = re.compile(r"\bRuntime\s*\.\s*(?:getRuntime\s*\(\s*\)\s*\.\s*)?exec\s*\(")
# `new ProcessBuilder(...)` constructor call.
_NEW_PROCESS_BUILDER = re.compile(r"\bnew\s+ProcessBuilder\s*\(")
# `.command(...)` — matched on the bare method name (no type resolution available without
# dataflow), so this can also match an unrelated `.command(...)` method on some other class. A
# text/regex-only guard cannot distinguish them; documented as a known FP source, not silently
# assumed to always be `ProcessBuilder`.
_PB_COMMAND = re.compile(r"\.command\s*\(")

# An argument opening with `new String[` (or `new String []`) is the array-literal form — never
# reasoned about here (see module docstring "Known, deliberate scope gap").
_ARRAY_ARG = re.compile(r"^new\s+String\s*\[\s*\]")
# A string literal glued to something else via `+` (Java has no f-strings/template literals —
# only `+` concatenation — so this is the whole dynamism surface beyond a bare identifier).
_CONCAT = re.compile(r'"\s*\+|\+\s*"')
_PRAGMA = "security: allow-java-command-injection"


def _is_dynamic(arg: str) -> bool:
    """An argument is "dynamic" (attacker-steerable) if it is a `+` concatenation or has no
    string literal at all (a bare variable/expression). An array-literal argument (`new
    String[]{...}`) is never evaluated — see the module docstring's scope note."""
    a = arg.strip()
    if not a:
        return False
    if _ARRAY_ARG.match(a):
        return False
    if '"' not in a:  # no literal anywhere -> a bare variable/expression
        return True
    return bool(_CONCAT.search(a))


def _arg_after(line: str, paren: int) -> str:
    """Return the argument text from just after `paren` to the line end (trailing `)` trimmed).
    Good enough for the single-line sinks this guard targets — mirrors
    `js_command_injection.py`'s own `_arg_after`."""
    return line[paren + 1:].rstrip().rstrip(")")


class JavaCommandInjectionGuard(Guard):
    id = "java-command-injection"
    title = "No OS-command injection via a Java process-exec sink"
    area = "Code safety"

    # Deploy.java: Runtime.getRuntime().exec("systemctl restart " + service) -> the classic
    # single-string, concatenated exec() idiom -> java-command-injection/runtime-exec-tainted.
    canary_plant = CanaryPlant(
        files={
            "Deploy.java": (
                "class Deploy {\n"
                "    void restart(String service) throws Exception {\n"
                '        Runtime.getRuntime().exec("systemctl restart " + service);\n'
                "    }\n"
                "}\n"
            ),
        },
        expects=frozenset({"java-command-injection/runtime-exec-tainted"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "java" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in java_scan_dirs(root, profile):
            for f in iter_files(d, (".java",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # The pragma check runs on the COMMENT-ONLY view (#424) — it IS the comment `strip_java_comments`
        # below would blank, so checking it after stripping would always miss it.
        view_lines = comment_view(text, "java").splitlines()  # same length: comments only (#424)
        # `strip_java_comments` preserves length and splitlines() count exactly (tested), so
        # the two line lists always pair up — `strict=True` documents that invariant.
        code_lines = strip_java_comments(text).splitlines()
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA in view:
                continue
            m = _RUNTIME_EXEC.search(line)
            if m and _is_dynamic(_arg_after(line, m.end() - 1)):
                out.append(self._finding(root, f, i, "runtime-exec-tainted"))
                continue
            m = _NEW_PROCESS_BUILDER.search(line)
            if m and _is_dynamic(_arg_after(line, m.end() - 1)):
                out.append(self._finding(root, f, i, "process-builder-tainted"))
                continue
            m = _PB_COMMAND.search(line)
            if m and _is_dynamic(_arg_after(line, m.end() - 1)):
                out.append(self._finding(root, f, i, "process-builder-command-tainted"))
        return out

    def _finding(self, root: Path, f: Path, line: int, slug: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "This process-exec sink receives a concatenated/variable argument — an "
                "attacker who controls that value controls what the OS process runs, giving "
                "remote code execution on the host."
            ),
            remediation=(
                "Pass each argument as a separate array element with no shell involved: "
                '`Runtime.getRuntime().exec(new String[]{"cmd", arg})` or '
                '`new ProcessBuilder("cmd", arg).start()` — never a single concatenated '
                "string. If this call is audited-safe, suppress with "
                "`// security: allow-java-command-injection`."
            ),
            rule=f"java-command-injection/{slug}",
            standards=["OWASP:A03", "OWASP-LLM:LLM05"],
        )
