"""Guard: user input injected into LLM prompt via .format() or % operator (checklist §3a).

Sister guard to `prompt-string-interp` (which catches f-strings). This guard catches the
two older Python string-formatting idioms used to build LLM prompts:

  - `.format(user_message)` / `"...{}...".format(user_question)` — PEP-3101 format strings
  - `"...%s..." % user_message` — C-style percent formatting

Both patterns produce the same injection risk as f-string interpolation: the user-supplied
content becomes part of the prompt with no sanitization, allowing "Ignore previous
instructions" attacks (OWASP-LLM:LLM01). The `.format()` idiom is especially common in
code that predates f-strings or was ported from Python 2.

Two rules, both HIGH severity:

  **`format-user-var`** (HIGH): `.format(user_*, request.*)` call in a file with a direct
  LLM API call.

  **`percent-user-var`** (HIGH): `% user_*` or `% (user_*` string-format in a file with a
  direct LLM API call.

Only scans files containing a direct LLM API call site to minimise noise.

Checklist item: `3a-user-content-sanitized-before-llm` (additional check_id on existing
covered item — extends detection breadth).

Suppress: `# security: allow-prompt-format-interpolation` anywhere in a file silences this
guard for that file.
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
)

_PRAGMA = "security: allow-prompt-format-interpolation"

# Direct LLM API calls with explicit receiver — excludes high-level wrappers and
# guard source files that mention these patterns in docstrings.
_LLM_CALL_DIRECT = re.compile(
    r"\b\w+\.chat\.completions\.create\s*\("
    r"|\b\w+\.responses\.create\s*\("
    r"|\b\w+\.messages\.create\s*\(",
    re.IGNORECASE,
)

# .format( with a user_* or request.* argument (keyword or positional position after comma).
_FORMAT_USER = re.compile(
    r"\.format\s*\(\s*(?:[^)]*?,\s*)?(?:user_\w+|request\.)",
    re.IGNORECASE,
)

# % operator applied to a user_* variable or request.* field.
_PERCENT_USER = re.compile(
    r"%\s*(?:user_\w+|\(\s*user_\w+|request\.\w+)",
    re.IGNORECASE,
)

_STANDARDS = ["OWASP-LLM:LLM01"]


class StringFormatInjectionGuard(Guard):
    id = "string-format-injection"
    title = "User input injected into LLM prompt via .format() or % operator"
    area = "AI agent"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted across the canary's shared
    # `format_inject.py` and `prompt_interp_ext.py` (which `prompt-string-interp` also trips), so
    # both files stay in `canary.py`'s base owned by no guard. The ownership rule this follows is
    # documented on `xxe_safe.py`.
    # format_inject.py: "...".format(user_message) in file with LLM call -> format-user-var (HIGH).
    canary_plant = CanaryPlant(expects=frozenset({"string-format-injection/format-user-var"}))

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                if not _LLM_CALL_DIRECT.search(text):
                    continue
                out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        r = rel(root, f)
        out: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if _FORMAT_USER.search(line):
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="User input injected into LLM prompt via .format()",
                        location=f"{r}:{lineno}",
                        message=(
                            "A user-tainted variable (user_* prefix or request.* field) "
                            "is passed as an argument to .format() in a file that calls "
                            "an LLM directly. If the format string becomes the prompt, "
                            "the user controls prompt content and can inject instructions "
                            "(OWASP-LLM:LLM01)."
                        ),
                        remediation=(
                            "Validate or sanitize user input before passing it to "
                            ".format(). Options: (1) constrain with a Pydantic field "
                            "(max_length + pattern); (2) wrap in explicit delimiters in "
                            "the format string itself "
                            "('<user_input>{user_message}</user_input>'); "
                            "(3) reject inputs containing injection markers before the "
                            "LLM call. Suppress with "
                            "`# security: allow-prompt-format-interpolation` only after "
                            "confirming the variable is validated upstream."
                        ),
                        rule="string-format-injection/format-user-var",
                        standards=list(_STANDARDS),
                    )
                )
            if _PERCENT_USER.search(line):
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="User input injected into LLM prompt via % operator",
                        location=f"{r}:{lineno}",
                        message=(
                            "A user-tainted variable (user_* prefix or request.* field) "
                            "is used as the value in a % string-format operation in a "
                            "file that calls an LLM directly. The resulting string may "
                            "become the LLM prompt, giving the user full control over "
                            "prompt content (OWASP-LLM:LLM01)."
                        ),
                        remediation=(
                            "Replace % formatting with validated, delimited prompt "
                            "construction. Validate user input with a Pydantic model "
                            "before use, then wrap in delimiters: "
                            "prompt = f'<user_input>{safe_input}</user_input>'. "
                            "See checklist §3a/§3b for the full delimiter pattern."
                        ),
                        rule="string-format-injection/percent-user-var",
                        standards=list(_STANDARDS),
                    )
                )
        return out
