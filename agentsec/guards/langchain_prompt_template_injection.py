"""Guard: LangChain PromptTemplate built from a dynamic template string (§3a).

`PromptTemplate(template=user_supplied)` / `ChatPromptTemplate.from_template(built)`
create a template whose **structure**, not just its filled-in variables, is attacker-
influenced. LangChain's default template format is Python `str.format()`-style
`{variable}` substitution — if the template *string itself* is dynamic, an attacker who
controls it can inject additional `{...}` placeholders that pull unintended values out
of whatever kwargs the app passes at render time (`{secret_api_key}`, `{system_prompt}`),
or use format-spec attribute/index traversal (`{obj.__class__.__mro__}`,
`{cfg.__init__.__globals__}`) to walk Python object internals through the substitution
engine. This is a **different** vector from `prompt-string-interp` (which flags user
input interpolated as a *value* into an already-fixed template): here the template's
own `{...}` grammar is what the attacker controls.

Fires HIGH when `PromptTemplate(` or `ChatPromptTemplate.from_template(` is called with
a non-literal template argument (f-string / concat / bare variable / expression — not a
plain string literal, an UPPER_SNAKE module constant, or a config-object attribute).

Suppress an audited case with `# security: allow-prompt-template-injection`.
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
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_line_comment,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-prompt-template-injection")

_STANDARDS = ["OWASP-LLM:LLM01"]

# Any `*PromptTemplate` subclass (`PromptTemplate` — the canonical modern API — plus
# `ChatPromptTemplate`, `FewShotPromptTemplate`) `.from_template(`.
_FROM_TEMPLATE = re.compile(r"\b\w*PromptTemplate\s*\.\s*from_template\s*\(")
# Both the module-qualified `langchain.PromptTemplate(` and the bare `PromptTemplate(`. A bare
# `(?<!\.)` lookbehind would drop the dotted form (the import-idiom `import langchain; ...`);
# the first alternation catches `<module>.PromptTemplate(` while still excluding an unrelated
# `SomeClass.PromptTemplate(` is acceptable here (any `.PromptTemplate(` in an llm repo is LangChain).
_PROMPT_TEMPLATE_CTOR = re.compile(r"\b\w*\.PromptTemplate\s*\(|(?<!\.)\bPromptTemplate\s*\(")
_TEMPLATE_KWARG = re.compile(r"\btemplate\s*=\s*")

_STRING_LITERAL = re.compile(r"""^["'rRbBfF]*["']""")
_FSTRING_LITERAL = re.compile(r"""^(?:[rR][fF]|[fF][rR]?)["']""")
_CONST_ARG = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_CONFIG_ATTR = re.compile(r"^(?:settings|config|conf|cfg)\.[A-Za-z_]\w*$", re.IGNORECASE)


_JOIN_LINES = 10  # max continuation lines to join for a call wrapped across lines


def _joined_call_args(lines: list[str], idx: int, col: int) -> str:
    """Argument text of a call opened at lines[idx][col:], joined across continuation
    lines until the call's parens balance (capped at _JOIN_LINES extra lines).

    Lines are comment-stripped before counting AND joining: a stray `)` in a trailing
    `#` comment must not end the join early (#437 review High-2), and comment text must
    not reach the template-kwarg matching."""
    parts = [strip_python_line_comment(lines[idx])[col:]]
    depth = 1 + parts[0].count("(") - parts[0].count(")")
    j = idx + 1
    while depth > 0 and j < len(lines) and j <= idx + _JOIN_LINES:
        code = strip_python_line_comment(lines[j])
        parts.append(code)
        depth += code.count("(") - code.count(")")
        j += 1
    return " ".join(p.strip() for p in parts)


def _first_arg(text_after_open: str) -> str:
    """Extract the first top-level argument from the text following an opening paren."""
    depth = 0
    for j, ch in enumerate(text_after_open):
        if ch in ("(", "[", "{"):
            depth += 1
        elif ch in (")", "]", "}"):
            if depth == 0:
                return text_after_open[:j].strip()
            depth -= 1
        elif ch == "," and depth == 0:
            return text_after_open[:j].strip()
    return text_after_open.strip()


def _is_dynamic_template(arg: str) -> bool:
    """A non-plain-literal template string: excludes a static string literal, a
    trusted constant, or a config-object attribute. An f-string, concatenation, or a
    bare variable/expression counts as dynamic."""
    a = arg.strip()
    if not a:
        return False
    if _FSTRING_LITERAL.match(a):
        return True
    if _CONST_ARG.match(a):
        return False
    if _CONFIG_ATTR.match(a):
        return False
    return not (_STRING_LITERAL.match(a) and "+" not in a)


class LangchainPromptTemplateInjectionGuard(Guard):
    id = "langchain-prompt-template-injection"
    title = "LangChain PromptTemplate built from a dynamic template string"
    area = "AI agent"

    # langchain_dynamic_prompt.py: ChatPromptTemplate.from_template(f"...") with an
    # f-string arg -> langchain-prompt-template-injection.
    canary_plant = CanaryPlant(
        files={
            "langchain_dynamic_prompt.py": (
                "from langchain.prompts import ChatPromptTemplate\n"
                "\n"
                "\n"
                "def build_prompt(user_supplied_instructions: str):\n"
                "    template_str = f'Answer using: {user_supplied_instructions}'\n"
                "    return ChatPromptTemplate.from_template(template_str)\n"
            ),
        },
        expects=frozenset({
            "langchain-prompt-template-injection/dynamic-template-string",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features and "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            lineno = idx + 1
            if line.lstrip().startswith("#"):
                continue
            m = _FROM_TEMPLATE.search(line)
            call_name = "ChatPromptTemplate.from_template"
            if m:
                arg = _first_arg(line[m.end():])
            else:
                m = _PROMPT_TEMPLATE_CTOR.search(line)
                if not m:
                    continue
                call_name = "PromptTemplate"
                rest = line[m.end():]
                if 1 + rest.count("(") - rest.count(")") > 0:
                    # Multi-line ctor: the call is not closed on this line, so join
                    # continuation lines to recover the argument text (lineno stays here).
                    rest = _joined_call_args(lines, idx, m.end())
                kw = _TEMPLATE_KWARG.search(rest)
                arg = _first_arg(rest[kw.end():]) if kw else _first_arg(rest)
            if not _is_dynamic_template(arg):
                continue
            out.append(Finding(
                check_id=self.id,
                severity="high",
                title=self.title,
                location=f"{rel(root, f)}:{lineno}",
                message=(
                    f"`{call_name}(...)` builds a prompt template from a non-literal "
                    "string. If this template's own structure (not just the variables "
                    "substituted into it) can be influenced by an attacker, they can "
                    "inject additional `{...}` placeholders that pull unintended values "
                    "out of the render-time kwargs, or use format-spec attribute/index "
                    "traversal (`{obj.__class__.__mro__}`) to walk Python object "
                    "internals through the substitution engine (OWASP-LLM:LLM01)."
                ),
                remediation=(
                    "Keep the template string a fixed literal (or loaded from a trusted, "
                    "version-controlled file) and pass only VALUES through the render-"
                    "time kwargs — never let user input, LLM output, or any external "
                    "source shape the template's own `{...}` structure. Suppress with "
                    "`# security: allow-prompt-template-injection` only after confirming "
                    "the template source is fully trusted."
                ),
                rule="langchain-prompt-template-injection/dynamic-template-string",
                standards=list(_STANDARDS),
            ))
        return out
