"""Guard: weak minimum password length hardcoded directly in validation logic.

    if len(password) < 8:
        raise ValueError("password too short")

    if len(pwd) <= 6:
        return False

A minimum-length policy for a credential variable (`password`/`passwd`/`pwd`) enforced by a
literal, small threshold is easily brute-forced — CWE-521 (Weak Password Requirements),
OWASP:A07 (Identification and Authentication Failures). This mirrors drogonsec's `PY-012` rule
(`len\\(password\\)\\s*[<>]\\s*[1-7]\\b`): "Passwords shorter than 8 characters are easily
brute-forced. Modern security standards recommend at least 12 characters." Broadened here to the
same `password`/`passwd`/`pwd` credential-variable family this codebase already uses elsewhere
(see `hardcoded_password_default_arg.py`), and to both comparison idioms code actually writes a
"reject if too short" gate with:

  - `len(<var>) < N`  — weak when the enforced minimum `N` is 8 or below (`< 1` .. `< 8`)
  - `len(<var>) <= N` — weak when the enforced minimum `N + 1` is 8 or below (`<= 0` .. `<= 7`)

`>`/`>=` comparisons are deliberately NOT matched — a `len(password) > N` check is at least as
likely to be a *maximum*-length guard (`len(password) > 100: reject`) as a minimum-length gate
written backwards, and the two are indistinguishable from the comparison text alone. Flagging
both directions would trade a real false-positive (rejecting a generous max-length check) for a
narrower true-positive; drogonsec's own `>` half of its pattern is not carried over for this
reason (see "Known bypasses" in the design doc).

Fires LOW on any `len(password|passwd|pwd) < N` / `<= N` comparison whose threshold implies an
enforced minimum length of 8 characters or fewer.

Suppress an audited case with `# security: allow-weak-password-length` on the offending line.
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
    strip_python_line_comment,
    strip_python_strings,
)

_LEN_CHECK = re.compile(
    r"\blen\(\s*(?:password|passwd|pwd)\s*\)\s*(?P<op><=?)\s*(?P<n>\d+)\b",
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-weak-password-length")

_STANDARDS = ["OWASP:A07", "CWE-521"]


class WeakPasswordLengthCheckGuard(Guard):
    id = "weak-password-length-check"
    title = "Weak minimum password length check"
    area = "Login & access"

    # weak_password_policy.py: len(password) < 8 minimum-length gate -> fires
    # weak-password-length-check. Must NOT contain: allow-weak-password-length pragma.
    canary_plant = CanaryPlant(
        files={
            "weak_password_policy.py": (  # nosec B105 (canary plant fixture text, not a real credential)
                "def validate(password):\n"
                "    if len(password) < 8:\n"
                "        raise ValueError('too short')\n"
            ),
        },
        expects=frozenset({"weak-password-length-check/short-minimum"}),
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
        text = strip_python_strings(read(f), filename=f)
        # The pragma counts only as a real comment on the line, never quoted in a string there (#1040),
        # numbered on the text walked below (a form feed in a docstring shifts the raw count, #1132).
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
        for i, raw_line in enumerate(text.splitlines(), start=1):
            code = strip_python_line_comment(raw_line)  # drop a trailing/whole-line `#` comment
            m = _LEN_CHECK.search(code)
            if m is None:
                continue
            if i in pragmas:
                continue
            n = int(m.group("n"))
            op = m.group("op")
            weak = (op == "<" and 1 <= n <= 8) or (op == "<=" and 0 <= n <= 7)
            if weak:
                out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="low",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "A password/passwd/pwd length check enforces a minimum of 8 characters or "
                "fewer. Passwords this short are easily brute-forced; modern guidance (NIST "
                "SP 800-63B) recommends at least 12 characters."
            ),
            remediation=(
                "Raise the minimum enforced password length to 12+ characters. Suppress an "
                "audited case with `# security: allow-weak-password-length`."
            ),
            rule="weak-password-length-check/short-minimum",
            standards=list(_STANDARDS),
        )
