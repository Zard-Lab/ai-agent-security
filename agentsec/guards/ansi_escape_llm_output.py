"""Guard: LLM response printed to a terminal without ANSI-escape stripping (checklist §4, new item).

Sourced from Garak's `probes/ansiescape.py` + `detectors/ansiescape.py`: a malicious or
hallucinated LLM completion can embed ANSI/VT100 escape sequences. When an agentic CLI tool
prints that response straight to a terminal, the escape codes are interpreted by the
terminal emulator, not displayed as text — cursor repositioning, screen/scrollback
clearing, color tricks that hide or spoof output, and on vulnerable terminal emulators,
more dangerous exploits (title-bar injection, clipboard writes, and historically even code
execution in specific emulator bugs). This is a real terminal-hijack-via-LLM-output vector,
distinct from two other guards that might look adjacent:

  - `log-injection` is CRLF-only log-forging (newlines faking log lines) — it does not
    consider ANSI control sequences or terminal rendering at all.
  - `claude-code-compromise` covers hook/permission/config abuse in AI *coding assistant*
    configuration files (CLAUDE.md, settings.json, hooks) — a completely different attack
    surface from a script printing a model's own response text.

**Detected pattern — `unstripped-print`** (MEDIUM):

Within one function, a variable assigned from a recognized LLM generation call
(`.invoke`/`.run_sync`/`.ainvoke`/`.arun`/`chat.completions.create`/`.messages.create`/an
`agent`/`llm`/`chain`/`model`/`client`/`graph`-named `.run`/`.generate`/`.complete`/
`.predict`) reaches a terminal-print sink — `print(...)`, `click.echo(...)`,
`rich.console.print(...)`, or any `<expr>.print(...)` (covers `console.print(...)` where
`console = Console()`) — either directly or via an f-string/concatenation that embeds the
variable name, with no ANSI-stripping signal anywhere in the same function.

An "ANSI-stripping signal" is deliberately broad rather than requiring a specific helper
name: a call to something named `strip_ansi(...)`, a reference to an `ANSI_ESCAPE`-named
compiled pattern, or a literal ANSI escape-code marker (`\\x1b`, `\\033`, `\\u001b`) anywhere
in the function — the last of these covers an inline `re.sub(r"\\x1b\\[[0-9;]*[a-zA-Z]", ...)`
without requiring the guard to parse the regex itself.

Deliberately scoped: this guard does NOT attempt to prove the code path is a CLI tool
printing to a real terminal (vs. a web API response body) — that structural distinction is
not practically achievable from static text alone, and the task is explicit that the
narrower, more precise version isn't worth chasing. Any `print`/`click.echo`/`.print(`
reached by an LLM-result variable, unstripped, fires. If a web app happens to shell out to a
`print()` for local debug output, that is still a plausible finding (uncommon in FastAPI
route handlers, which write JSON responses, not terminal output).

**Silence conditions:**
- An ANSI-stripping signal (`strip_ansi(`, `ANSI_ESCAPE`, or a literal `\\x1b`/`\\033`/
  `\\u001b` marker) appears anywhere in the same function.
- The print/echo call's line does not reference any LLM-result variable name tracked in
  the enclosing function.
- The file contains `# security: allow-ansi-escape-llm-output` anywhere.

**False-negative scope:** Single-file, per-function, name-based dataflow — same limits as
`llm-json-output-unvalidated`: a variable renamed via a plain reassignment before the print
call, or an LLM result returned from one function and printed in another, is not tracked.
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
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_PRAGMA = "security: allow-ansi-escape-llm-output"

_STANDARDS = ["OWASP-LLM:LLM05", "CWE-150"]

# A variable assigned (on one line) from a recognized LLM-framework generation call — mirrors
# `llm_output_to_sink.py`'s `_LLM_ASSIGN` (the established call-site-tracking shape in this
# codebase for "a variable holds LLM output").
_LLM_ASSIGN = re.compile(
    r"^\s*([A-Za-z_]\w*)\s*=\s*.*"
    r"(?:\.(?:run_sync|ainvoke|invoke|arun)\s*\(|chat\.completions\.create\s*\(|\.messages\.create\s*\(|"
    r"\b(?:agent|llm|chain|model|client|graph)\w*\.(?:run|generate|complete|predict)\s*\()",
    re.IGNORECASE,
)

# Gates the per-file scan: an LLM call anywhere in the file (same shape as `llm_output_to_sink.py`).
_LLM_CALL_ANYWHERE = re.compile(
    r"\.(?:run_sync|ainvoke|invoke|arun)\s*\("
    r"|\b(?:agent|llm|chain|model|client|graph)\w*\.(?:run|generate|complete|predict)\s*\("
    r"|chat\.completions\.create\s*\("
    r"|\.messages\.create\s*\("
    r"|\b(?:OpenAI|AsyncOpenAI|Anthropic|AsyncAnthropic|ChatOpenAI|ChatAnthropic)\s*\(",
    re.IGNORECASE,
)

# print(...) / click.echo(...) / rich.console.print(...) / <expr>.print(...). `\bprint\s*\(`
# alone already covers the dotted forms — a `.` immediately before `print` is a non-word
# character, so `\b` still matches the transition (verified: this does NOT match `pprint(`,
# where `print` is preceded by a word character with no boundary).
_PRINT_SINK = re.compile(r"\bprint\s*\(|\bclick\.echo\s*\(", re.IGNORECASE)

# A signal that ANSI/VT100 escape codes are stripped somewhere in the function: a dedicated
# helper call, a compiled pattern conventionally named ANSI_ESCAPE(_RE)?, or a literal escape
# marker (as it appears in SOURCE TEXT — `\x1b`/`\033`/`` are 4-6 literal characters in
# the file regardless of whether the enclosing string is raw, since this is a text scan, not
# an executed one).
_ANSI_STRIP_SIGNAL = re.compile(
    r"strip_ansi\s*\(|\bANSI_ESCAPE\w*\b|\\x1[bB]|\\033|\\u001[bB]",
)

_DEF = re.compile(r"[ \t]*(?:async[ \t]+)?def[ \t]")


def _enclosing_def_span(lines: list[str], i: int) -> tuple[int, int] | None:
    """(start, end) line indices of the function whose body contains line `i`, or None if `i` is at
    module level. Copied from `llm_json_output_unvalidated.py`'s helper of the same name (private,
    not shared via base.py) — scopes LLM-result-variable tracking and the ANSI-strip signal check to
    the enclosing FUNCTION, not the whole file, so a same-named variable in an unrelated function
    can't taint this one."""
    if not lines[i].strip():
        return None
    line_indent = len(lines[i]) - len(lines[i].lstrip())
    j = i - 1
    while j >= 0:
        s = lines[j]
        if s.strip():
            ind = len(s) - len(s.lstrip())
            if ind < line_indent:
                if _DEF.match(s):
                    k = j + 1
                    while k < len(lines):
                        ln = lines[k]
                        if ln.strip() and (len(ln) - len(ln.lstrip())) <= ind:
                            break
                        k += 1
                    return j, k
                line_indent = ind
        j -= 1
    return None


class AnsiEscapeLlmOutputGuard(Guard):
    id = "ansi-escape-llm-output"
    title = "LLM response printed to a terminal without ANSI-escape stripping"
    area = "AI agent"

    # cli_tool.py: response = agent.run_sync(prompt); print(response.output) -> fires
    # ansi-escape-llm-output/unstripped-print (no strip_ansi/ANSI_ESCAPE/escape-marker anywhere
    # in `main`). Must NOT contain: allow-ansi-escape-llm-output pragma, strip_ansi(, ANSI_ESCAPE.
    canary_plant = CanaryPlant(
        files={
            "cli_tool.py": (
                "from pydantic_ai import Agent\n"
                "\n"
                "agent = Agent('openai:gpt-4o')\n"
                "\n"
                "\n"
                "def main(prompt: str) -> None:\n"
                "    response = agent.run_sync(prompt)\n"
                "    print(response.output)\n"
            ),
        },
        expects=frozenset({"ansi-escape-llm-output/unstripped-print"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                rel_path = rel(root, f)
                if is_nonproduct_path(rel_path, profile.archive_segments):
                    continue
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                # Blank triple-quoted docstring content up front so anti-pattern examples in a
                # guard's own module docstring (this file included) don't self-match.
                stripped_text = strip_python_strings(text, filename=f)
                if not _LLM_CALL_ANYWHERE.search(stripped_text):
                    continue
                lines = stripped_text.splitlines()
                for i, line in enumerate(lines):
                    if line.lstrip().startswith("#"):
                        continue
                    if not _PRINT_SINK.search(line):
                        continue
                    span = _enclosing_def_span(lines, i)
                    scope_lines = lines[span[0]:span[1]] if span else lines
                    scope = "\n".join(scope_lines)

                    llm_vars = {m.group(1) for ln in scope_lines if (m := _LLM_ASSIGN.match(ln))}
                    if not llm_vars:
                        continue
                    if not any(re.search(r"\b" + re.escape(v) + r"\b", line) for v in llm_vars):
                        continue
                    if _ANSI_STRIP_SIGNAL.search(scope):
                        continue

                    lineno = i + 1
                    findings.append(Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=f"{rel_path}:{lineno}",
                        message=(
                            "An LLM response variable is printed straight to the terminal "
                            "(print/click.echo/rich console .print) with no ANSI-escape "
                            "stripping anywhere in the function. A malicious or hallucinated "
                            "model completion can embed ANSI/VT100 control sequences that the "
                            "terminal emulator interprets: cursor manipulation, screen/"
                            "scrollback clearing, color-based spoofing, or (on vulnerable "
                            "terminal emulators) more dangerous escape-sequence exploits."
                        ),
                        remediation=(
                            "Strip ANSI escape sequences before printing model output: "
                            "`print(strip_ansi(response.output))`, or filter with "
                            "`ANSI_ESCAPE_RE.sub('', text)` using a pattern like "
                            "`re.compile(r'\\x1b\\[[0-9;]*[a-zA-Z]')`. Prefer a maintained "
                            "helper (e.g. the `strip-ansi` package or `rich`'s own text "
                            "escaping) over a hand-rolled regex. If output is genuinely "
                            "sandboxed (piped, not a real TTY), suppress with "
                            "`# security: allow-ansi-escape-llm-output`."
                        ),
                        rule="ansi-escape-llm-output/unstripped-print",
                        standards=list(_STANDARDS),
                    ))
        return findings
