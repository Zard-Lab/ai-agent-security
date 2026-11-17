"""Guard: LangChain load_prompt / load_prompt_from_config path traversal (§4 / CVE-2026-34070).

`langchain.prompts.load.load_prompt(path)` and `load_prompt_from_config(config)` accept
caller-supplied file paths and load arbitrary YAML/JSON prompt templates. When path originates
from LLM output or user input without a base-directory restriction, an attacker can supply
`../../etc/passwd` or a crafted path to read arbitrary files (path traversal, CWE-22).

CVE-2026-34070 demonstrated this on LangChain <= 0.3.24: LLM-suggested template paths passed
directly to load_prompt() read files outside the intended directory.

Fires HIGH when load_prompt() or load_prompt_from_config() is called with a non-literal argument
and no base-directory guard is present anywhere from the start of the enclosing function through
the call itself (`enclosing_function_span()` — a 4-line fallback look-back when no
enclosing function is found).

Suppress with `# security: allow-path-traversal` on the call line.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    enclosing_function_span,
    iter_files,
    iter_functions,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_LOAD_PROMPT = re.compile(r"\b(?:load_prompt|load_prompt_from_config)\s*\(")
_PRAGMA = re.compile(r"#\s*security:\s*allow-path-traversal")
# A traversal guard is a CONTAINMENT check. `.resolve()`/`realpath` alone are NOT —
# `Path("../../etc/passwd").resolve()` resolves fine; only is_relative_to / safe_join contain.
_SAFE = re.compile(r"is_relative_to|safe_join")
_STRING_LITERAL = re.compile(r"""^["'rRbB]*["']""")
# A module-level UPPER_SNAKE constant is a trusted in-repo value, not user input.
_CONST_ARG = re.compile(r"^[A-Z_][A-Z0-9_]*\s*[),]")
# `os.path.join(...)` — only trusted when EVERY segment is a string literal (a static path);
# a bare identifier (variable) keeps it firing. Validated in `_is_literal_join` by blanking the
# quoted spans and checking nothing but commas/whitespace/parens remains — a flat scan that
# avoids a nested-quantifier regex (which would itself be a ReDoS smell).
_JOIN_CALL = re.compile(r"^(?:os\.path\.)?join\(")
_QUOTED_SPAN = re.compile(r"""[rRbB]?(['"]).*?\1""")
# A trusted config-object attribute (settings.template / config.prompt_path). NARROW by design —
# only these conventional app-config object names, NOT all `.attr`, so `request.path` (which is
# user-controlled) keeps firing.
_CONFIG_ATTR = re.compile(r"^(?:settings|config|conf|cfg)\.[A-Za-z_]\w*\s*[),]", re.IGNORECASE)


def _is_literal_join(a: str) -> bool:
    """True for `os.path.join(...)` whose every argument is a string literal. Blanks the quoted
    spans; if only commas/whitespace/parens remain, no bare identifier (variable) was present."""
    if not _JOIN_CALL.match(a):
        return False
    body = a[a.index("(") + 1:]
    residue = _QUOTED_SPAN.sub("", body)
    return residue.strip(" ,)\t") == ""


def _literal_arg(arg: str) -> bool:
    """Returns True if the call argument is a trusted value rather than a dynamic /
    user-controlled path. Trusted shapes: a string literal, `Path(...)`, an UPPER_SNAKE module
    constant, `os.path.join(...)` of all-literal segments, or a config-object attribute
    (`settings.`/`config.`/`conf.`/`cfg.`)."""
    a = arg.strip()
    return (
        bool(_STRING_LITERAL.match(a))
        or a.startswith("Path(")
        or bool(_CONST_ARG.match(a))
        or _is_literal_join(a)
        or bool(_CONFIG_ATTR.match(a))
    )


class LangchainLoadPromptGuard(Guard):
    id = "langchain-load-prompt-traversal"
    title = "LangChain load_prompt path not validated (CWE-22 / CVE-2026-34070)"
    area = "AI agent"

    # langchain_prompt_loader.py: load_prompt(template_name) with a variable arg -> langchain-load-prompt-traversal
    # Must NOT contain: allow-path-traversal pragma.
    canary_plant = CanaryPlant(
        files={
            "langchain_prompt_loader.py": (
                "from langchain.prompts import load_prompt\n"
                "\n"
                "\n"
                "def get_prompt(template_name: str):\n"
                "    return load_prompt(template_name)\n"
            ),
        },
        expects=frozenset({"langchain-load-prompt-traversal/dynamic-path"}),
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
                out.extend(self._scan(root, f))
        return out

    # How many preceding lines to scan for a containment guard. A single-preceding-line check is
    # fragile — a blank line or a multi-line `is_relative_to`/`safe_join` guard between the check
    # and the call breaks suppression. A small window restores robustness without over-reaching.
    _LOOKBACK = 4

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        # Blank triple-quoted docstring/template CONTENT so a dynamic load-prompt EXAMPLE in a
        # docstring (this guard's own module docstring self-matches, issue #424) doesn't fire.
        # Real call sites and the look-back window are single-line code, unaffected.
        raw = read(f)
        text = strip_python_strings(raw, filename=f)
        lines = text.splitlines()
        # The pragma counts only as a real comment on the line, never quoted in a string
        # there (#1040), numbered on the text walked below (a form feed in a docstring
        # shifts the raw count, #1132).
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
        # Parsed lazily: computed once per file, but only after a real anchor is found. Most scanned
        # files contain no load_prompt anchor, and iter_functions() is a full safe_ast_parse +
        # strip_python_strings — pure waste on an anchor-free file (issue #771). Memoized after the
        # first parse so enclosing_function_span() doesn't re-parse per match (~900x slower over a
        # many-function file #685 review).
        funcs: list[tuple[int, str]] | None = None
        for i, line in enumerate(lines, start=1):
            if i in pragmas:
                continue
            m = _LOAD_PROMPT.search(line)
            if not m:
                continue
            if funcs is None:
                funcs = iter_functions(text, filename=f)
            # look back to the START of the enclosing function first (a containment
            # guard can sit further back than a small fixed look-back reaches), falling back to
            # the fixed look-back only when no enclosing function is found. Look-BACK only,
            # never forward — a guard written AFTER the call has already run doesn't mitigate it.
            span = enclosing_function_span(text, i, functions=funcs)
            if span is not None:
                scope_start, _scope_end = span
                window = "\n".join(lines[scope_start - 1 : i])
            else:
                window = "\n".join(lines[max(0, i - 1 - self._LOOKBACK):i])
            if _SAFE.search(window):
                continue
            arg_text = line[m.end():]
            if _literal_arg(arg_text):
                continue  # trusted literal / constant — safe
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="LangChain load_prompt called with dynamic path (path traversal risk)",
                    location=f"{rel(root, f)}:{i}",
                    message=(
                        f"`{m.group().rstrip('(')}()` receives a dynamic path argument. "
                        "If this path originates from LLM output or user input, an attacker "
                        "can supply `../../etc/passwd` to read arbitrary files "
                        "(CVE-2026-34070, CWE-22)."
                    ),
                    remediation=(
                        "Validate the path before passing it: "
                        "`p = Path(ALLOWED_DIR).joinpath(template_name).resolve(); "
                        "assert p.is_relative_to(ALLOWED_DIR)`. "
                        "Or use a fixed allowlist of template names. "
                        "Suppress with `# security: allow-path-traversal`."
                    ),
                    rule="langchain-load-prompt-traversal/dynamic-path",
                    standards=["OWASP:A01", "OWASP-LLM:LLM02"],
                )
            )
        return out
