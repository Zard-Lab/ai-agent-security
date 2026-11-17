"""Guard: dynamic module import with a non-literal module name (checklist §3b, new item).

`importlib.import_module(name)` and `__import__(name)` load and execute arbitrary
Python modules by name. When `name` is attacker-influenceable — a request parameter, a
config value read from an untrusted source — the caller effectively chooses which
module gets imported and run, including one that doesn't exist on a fixed allowlist.
CWE-706 (Use of Incorrectly-Resolved Name or Reference), OWASP:A01 (Broken Access
Control — the caller can reach code paths / modules they shouldn't).

    importlib.import_module(request.query_params["plugin"])   # attacker picks the module
    importlib.import_module("myapp.plugins.pdf_export")        # static literal -> safe

Fires HIGH on `importlib.import_module(`/`__import__(` whose first argument is
**dynamic** (an f-string, `+`/`%`/`.format` concatenation, or a bare variable with no
string literal at all).

Suppress an audited plugin-loader case with:

    importlib.import_module(plugin_name)  # security: allow-dynamic-import
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
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_IMPORT_SINK = re.compile(r"\b(?:importlib\.import_module|__import__)\s*\(")
_FSTRING = re.compile(r"(?:^|[\s(,=+])[rR]?[fF]['\"]")
_PCT = re.compile(r"%[sdrfeg]|['\"]\s*%|%\s*\(")
_CONCAT = re.compile(r"['\"]\s*\+|\+\s*['\"]")
_PRAGMA = re.compile(r"#\s*security:\s*allow-dynamic-import")

_STANDARDS = ["OWASP:A01", "CWE-706"]


def _is_dynamic(arg: str) -> bool:
    a = arg.strip()
    if not a:
        return False
    if _FSTRING.search(a):
        return True
    if "'" not in a and '"' not in a:
        return True
    if ".format(" in a:
        return True
    if _PCT.search(a):
        return True
    return bool(_CONCAT.search(a))


def _first_arg(line: str, paren: int) -> str:
    """Return everything from just after `paren` to the matching close (best-effort:
    up to the first top-level comma or the line's trailing close-paren)."""
    rest = line[paren + 1 :]
    depth = 0
    for i, ch in enumerate(rest):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return rest[:i]
            depth -= 1
        elif ch == "," and depth == 0:
            return rest[:i]
    return rest.rstrip().rstrip(")")


class DynamicImportNonLiteralGuard(Guard):
    id = "dynamic-import-non-literal"
    title = "Dynamic module import with a non-literal, attacker-influenceable name"
    area = "Code safety"

    # importlib.import_module() with a bare variable -> fires
    # dynamic-import-non-literal/attacker-influenced-name (HIGH).
    canary_plant = CanaryPlant(
        files={
            "dynamic_import.py": (
                "import importlib\n"
                "\n"
                "\n"
                "def load_plugin(plugin_name: str) -> object:\n"
                "    return importlib.import_module(plugin_name)\n"
            ),
        },
        expects=frozenset({"dynamic-import-non-literal/attacker-influenced-name"}),
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
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
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
            m = _IMPORT_SINK.search(line)
            if m and _is_dynamic(_first_arg(line, m.end() - 1)):
                out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "A module is imported dynamically (importlib.import_module()/"
                "__import__()) with a name built from dynamic content (an f-string, "
                "concatenation, or a bare variable). If that name is caller-"
                "influenceable, the caller effectively chooses which module gets "
                "imported and executed."
            ),
            remediation=(
                "Validate the module name against a fixed allowlist before import, "
                "or restrict it to a known-safe namespace prefix. Never build the "
                "import target directly from unvalidated input."
            ),
            rule="dynamic-import-non-literal/attacker-influenced-name",
            standards=list(_STANDARDS),
        )
