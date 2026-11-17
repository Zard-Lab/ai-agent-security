"""Guard: `indexOf`/`lastIndexOf` used to emulate `endsWith` without handling the `-1`
case (checklist §3a, new item, CWE-020).

`String.prototype.endsWith()` exists; `x.indexOf(y) === x.length - y.length` is a
hand-rolled reimplementation of it that breaks silently in a way `endsWith()` cannot:
when `y` is not a suffix of `x` at all, `indexOf()` returns `-1`. If `x.length -
y.length` also happens to equal `-1` (i.e. `y` is exactly one character longer than
`x`), the comparison is TRUE even though `y` is not a suffix of `x` — the check passes
when it should fail.

  if (path.indexOf(".json") === path.length - ".json".length) { ... }
  // path = "x", ".json" is 6 chars -> path.length(1) - 6 = -5, indexOf("x", ".json") = -1
  // -5 !== -1, so this specific case is safe, but the SHAPE is fragile: any input whose
  // length is exactly (suffix.length - 1) makes the check pass without the suffix
  // actually being present.

Sourced from GitHub CodeQL's `js/incorrect-suffix-check`
(`javascript/ql/src/Security/CWE-020/IncorrectSuffixCheck.ql`, verified against real
fetched source) — the query's own full form tracks equivalent `indexOf` calls, several
comparison shapes, and whether a companion `-1`/range check already neutralizes the bug
across the whole containing function via real dataflow. This guard implements a
narrower, same-line-only approximation of the SAME core anti-pattern: it does not
re-verify whether a separate `-1` check exists elsewhere in the function, so it is
more willing to fire than the full CodeQL query — the tradeoff documented in Known
bypasses below.

Fires MEDIUM per match: `<recv>.indexOf(<arg>)` (or `.lastIndexOf(`) compared with
`===`/`!==`/`==`/`!=` against `<recv>.length - <arg>.length`, using the SAME receiver
and SAME argument on both sides, on one line.

Suppress an audited case (e.g. a length pairing where the off-by-one is provably
unreachable) with `// security: allow-incorrect-suffix-check` on the line.
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
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA_TEXT = "security: allow-incorrect-suffix-check"

# `<recv>.indexOf(<arg>)` (or lastIndexOf) compared against `<recv>.length - <arg>.length`,
# same receiver (\1) and same argument (\2) on both sides.
_SUFFIX_CHECK = re.compile(
    r"\b(\w+)\.(?:indexOf|lastIndexOf)\s*\(\s*(\w+|'[^']*'|\"[^\"]*\")\s*\)\s*"
    r"(?:===?|!==?)\s*\1\.length\s*-\s*\2\.length\b"
)

_STANDARDS = ["CWE-020"]


class IncorrectSuffixCheckGuard(Guard):
    id = "incorrect-suffix-check"
    title = "indexOf/lastIndexOf used as a homemade endsWith without handling -1"
    area = "Network requests"

    # express_suffix_check.js: path.indexOf(ext) === path.length - ext.length ->
    # fires incorrect-suffix-check/indexof-endswith-emulation.
    canary_plant = CanaryPlant(
        files={
            "express_suffix_check.js": (
                "function hasExtension(path, ext) {\n"
                "  return path.indexOf(ext) === path.length - ext.length;\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "incorrect-suffix-check/indexof-endswith-emulation"
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return (
            "javascript" in profile.features
            or "express" in profile.features
            or "typescript" in profile.features
        )

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            raw = read(f)
            code = strip_js_comments(raw)
            out.extend(self._scan_file(root, f, code, raw))
        return out

    def _scan_file(self, root: Path, f: Path, code: str, raw: str) -> list[Finding]:
        out: list[Finding] = []
        view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
        for m in _SUFFIX_CHECK.finditer(code):
            lineno = code.count("\n", 0, m.start()) + 1
            line_text = view_lines[lineno - 1] if lineno - 1 < len(view_lines) else ""
            if _PRAGMA_TEXT in line_text:
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        f"`{m.group(1)}.indexOf({m.group(2)}) === {m.group(1)}.length - "
                        f"{m.group(2)}.length` is a hand-rolled `endsWith` that does not "
                        "handle the -1 case: when the argument is not found at all, "
                        "`indexOf()` returns -1, and if the length difference also "
                        "equals -1 (the argument is exactly one character longer than "
                        "the receiver), this comparison passes even though the suffix "
                        "is not actually present."
                    ),
                    remediation=(
                        f"Use `{m.group(1)}.endsWith({m.group(2)})` instead — it has no "
                        "such edge case. Suppress a reviewed case with "
                        "`// security: allow-incorrect-suffix-check`."
                    ),
                    rule="incorrect-suffix-check/indexof-endswith-emulation",
                    standards=list(_STANDARDS),
                )
            )
        return out
