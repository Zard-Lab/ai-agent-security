"""Guard: no server-side template injection (checklist §3b).

Rendering user/model input *as a template* — `render_template_string(user)` or a
Jinja `Environment(autoescape=False)` — lets `{{7*7}}`-style payloads reach the
template engine's sandbox and, on Jinja, escalate to RCE (`{{''.__class__...}}`).
The fix is to pass user input as template *data* (`render_template("p.html",
name=user)`), never as the template string, and keep `autoescape=True`. CWE-94.

Fires HIGH on:
  * `render_template_string(` with a non-literal first argument (f-string / concat
    / variable);
  * a Jinja `Environment(...)` constructed with `autoescape=False`;
  * a raw `jinja2.Template(...)`/`Template(...)` constructor, or a `.from_string(...)`
    call on an `Environment`, given a non-literal argument — the template *string*
    itself, not a value later passed into it. CVE-2024-41950 (Haystack): components let
    a caller create and render a Jinja2 template directly, with no `render_template_string`
    wrapper in sight, so the original absence-only check missed it entirely.

Suppress an audited case with `# security: allow-ssti` on the line.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_line_comment,
    strip_python_strings,
)

_RENDER_STRING = re.compile(r"\brender_template_string\s*\(")
_AUTOESCAPE_OFF = re.compile(r"\bEnvironment\s*\(")
_AUTOESCAPE_FALSE = re.compile(r"autoescape\s*=\s*False")
# Both the bare `Template(` (from `from jinja2 import Template`) and the module-qualified
# `jinja2.Template(` — the latter's leading `.` would otherwise be excluded by the lookbehind,
# which is the common CVE-2024-41950 shape. Still excludes an unrelated `SomeLib.Template(`.
_RAW_TEMPLATE_CTOR = re.compile(r"\bjinja2\s*\.\s*Template\s*\(|(?<!\.)\bTemplate\s*\(")
_FROM_STRING = re.compile(r"\.\s*from_string\s*\(")
_PRAGMA = re.compile(r"#\s*security:\s*allow-ssti")

# An argument is a safe constant only if it is a single quoted literal with no
# f-prefix / concat / format. Anything else is attacker-steerable.
_FSTRING = re.compile(r"(?:^|[\s(,=+])[rR]?[fF]['\"]")
_CONCAT = re.compile(r"['\"]\s*\+|\+\s*['\"]|\.format\s*\(|%[sdrfeg]")


def _first_arg(line: str, paren: int) -> str:
    """The first top-level (depth-0) call argument after the `(` at `paren`.

    Bracket- AND quote-aware: a comma inside brackets or inside a string literal does not
    split the argument (so a template arg like `"Hi, " + name`, whose literal contains a
    comma, is kept whole rather than truncated at the in-string comma). Only the first
    positional (the template) reaches the engine; scanning all args caused both an FP and an
    FN (see wiki/guards/ssti.md)."""
    rest = line[paren + 1 :]
    depth = 0
    quote: str | None = None
    idx = 0
    while idx < len(rest):
        ch = rest[idx]
        if quote is not None:
            if ch == "\\":
                idx += 2  # skip the escaped char
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            # Terminate at the call's OWN closing `)` so a chained `.render(f"…")` after
            # `Template("literal")` doesn't leak its f-string into the template arg (#423).
            if depth == 0:
                return rest[:idx]
            depth -= 1
        elif ch == "," and depth == 0:
            return rest[:idx]
        idx += 1
    return rest


def _is_dynamic(arg: str) -> bool:
    a = arg.strip()
    if not a:
        return False
    if _FSTRING.search(a):
        return True
    if "'" not in a and '"' not in a:  # bare variable / expression
        return True
    return bool(_CONCAT.search(a))


class SstiGuard(Guard):
    id = "ssti"
    title = "No server-side template injection"
    area = "Code safety"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # render_template_string on concatenated input -> ssti/user-input-in-template.
    # jinja2.Template(user_template).render() -> ssti/raw-template-constructor.
    canary_plant = CanaryPlant(
        files={
            "web.py": (
                "from flask import render_template_string\n"
                "from jinja2 import Template\n\n\n"
                "def page(name: str) -> str:\n    return render_template_string(\"Hi \" + name)\n\n\n"
                "def render_custom(user_template: str) -> str:\n"
                "    return Template(user_template).render()\n"
            ),
        },
        expects=frozenset({
            "ssti/raw-template-constructor",
            "ssti/user-input-in-template",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        # Blank TRIPLE-quoted docstrings (line-preserving) before scanning, so prose like
        # `"""renders via jinja2.Template(...) internally"""` no longer fires. Single-line
        # f-strings survive (strip_python_strings only blanks triple-quoted), so the f-string
        # dynamic-template signal is unaffected (PR #450 review).
        text = strip_python_strings(read(f), filename=f)
        # The pragma counts only as a real comment on the line, never quoted in a string there (#1040),
        # numbered on the text walked below (a form feed in a docstring shifts the raw count, #1132).
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
        for i, raw in enumerate(text.splitlines(), start=1):
            if raw.lstrip().startswith("#") or i in pragmas:
                continue
            # Also drop a TRAILING comment (string-aware), so `x = 1  # ... Template(y) ...`
            # in a comment doesn't fire — the pragma comment is checked above first
            # (PR #450 re-review).
            line = strip_python_line_comment(raw)
            m = _RENDER_STRING.search(line)
            renders_dynamic = bool(m and _is_dynamic(_first_arg(line, m.end() - 1)))
            autoescape_disabled = bool(_AUTOESCAPE_OFF.search(line)) and bool(_AUTOESCAPE_FALSE.search(line))
            if renders_dynamic or autoescape_disabled:
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="User input rendered through a template engine (SSTI)",
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "Rendering non-constant input as a template exposes the engine to "
                            "`{{...}}` injection — on Jinja this escalates from data disclosure "
                            "to remote code execution."
                        ),
                        remediation=(
                            "Pass user input as template *data* (`render_template(\"p.html\", "
                            "name=user)`), never as the template string, and keep "
                            "`autoescape=True`. Suppress with `# security: allow-ssti`."
                        ),
                        rule="ssti/user-input-in-template",
                        standards=["OWASP:A03"],
                    )
                )
                continue
            m = _RAW_TEMPLATE_CTOR.search(line) or _FROM_STRING.search(line)
            # Isolate the FIRST argument (the template) with _first_arg, as the
            # render_template_string path already does — testing the whole line tail let a
            # chained `.render(f"…")` after a literal template fire a HIGH FP (#423).
            if m and _is_dynamic(_first_arg(line, m.end() - 1)):
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="Template constructed from non-literal string (SSTI)",
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "A `Template(...)`/`.from_string(...)` call builds a Jinja2 "
                            "template directly from a non-literal string — if that string "
                            "is user- or LLM-influenced, an attacker controls the template's "
                            "own `{{...}}` grammar, not just a value substituted into it. "
                            "On Jinja this escalates to remote code execution "
                            "(CVE-2024-41950 was this exact shape)."
                        ),
                        remediation=(
                            "Keep the template string a fixed literal or loaded from a "
                            "trusted, version-controlled file; pass only values through "
                            "the render-time context. Suppress with "
                            "`# security: allow-ssti` only after confirming the template "
                            "source is fully trusted."
                        ),
                        rule="ssti/raw-template-constructor",
                        standards=["OWASP:A03"],
                    )
                )
        return out
