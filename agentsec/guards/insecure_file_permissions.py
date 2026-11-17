"""Guard: os.chmod() grants overly-permissive group/other access (checklist §8, new item).

    os.chmod("/etc/app/secrets.env", 0o666)   # group AND other can write it
    os.chmod(upload_path, 0o777)              # anyone can read/write/execute it

A chmod call that grants **write** permission to the file's group or other bits widens
tamper access to more principals than almost any application file needs. CWE-276
(Incorrect Default Permissions), OWASP:A01 (Broken Access Control). A common way for a
secrets file, an uploaded artifact, or a generated config to end up world-writable.

Fires HIGH when `os.chmod()`/`os.lchmod()`/`os.fchmod()` is called with:

  * an octal mode literal (`0o666`, `0666`, `0o777`, ...) whose group or other digit
    grants write access (digit value 2, 3, 6, or 7), or
  * a `stat` module constant that grants the same (`stat.S_IWGRP`, `stat.S_IWOTH`,
    `stat.S_IRWXO`, `stat.S_IRWXG`).

Execute/read alone to group or other is not flagged — a mode like `0o640` (owner rw,
group r, other none) or the ubiquitous `0o755`/`0o750` (group/other read+execute, no
write) does NOT fire.

Suppress an audited case (e.g. a genuinely shared upload directory) with:

    os.chmod(shared_dir, 0o777)  # security: allow-insecure-permissions
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

_CHMOD_CALL = re.compile(r"\bos\.(?:chmod|lchmod|fchmod)\s*\(")
_OCTAL_LITERAL = re.compile(r"\b0[oO]?([0-7]{3,4})\b")
_STAT_PERMISSIVE = re.compile(
    r"\bstat\.(?:S_IWGRP|S_IWOTH|S_IRWXO|S_IRWXG)\b"  # write to group/other (S_IRWX* includes write)
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-insecure-permissions")

# A group/other octal digit with the WRITE bit set (digit & 2). Execute-only (1, 5) and
# read-only (4) do NOT fire — `0o755`/`0o750` are ubiquitous, non-alarming permissions.
_GROUP_OTHER_WRITE_DIGITS = {"2", "3", "6", "7"}

_STANDARDS = ["OWASP:A01", "CWE-276"]


def _arg_after(line: str, paren: int) -> str:
    return line[paren + 1 :].rstrip().rstrip(")")


def _grants_group_or_other_access(arg: str) -> bool:
    if _STAT_PERMISSIVE.search(arg):
        return True
    m = _OCTAL_LITERAL.search(arg)
    if not m:
        return False
    digits = m.group(1)
    # Last two digits are group and other; a 4-digit literal's first digit is
    # the special-bits nibble (setuid/setgid/sticky), not owner/group/other.
    group_other = digits[-2:]
    return any(d in _GROUP_OTHER_WRITE_DIGITS for d in group_other)


class InsecureFilePermissionsGuard(Guard):
    id = "insecure-file-permissions"
    title = "os.chmod() grants overly-permissive group/other access"
    area = "Files"

    # os.chmod(path, 0o777) -> fires insecure-file-permissions/group-or-other-write (HIGH).
    canary_plant = CanaryPlant(
        files={
            "file_permissions.py": (
                "import os\n"
                "\n"
                "\n"
                "def save_upload(path: str, data: bytes) -> None:\n"
                "    with open(path, 'wb') as f:\n"
                "        f.write(data)\n"
                "    os.chmod(path, 0o777)\n"
            ),
        },
        expects=frozenset({
            "insecure-file-permissions/group-or-other-write",
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
            if i in pragmas:
                continue
            m = _CHMOD_CALL.search(line)
            if m and _grants_group_or_other_access(_arg_after(line, m.end() - 1)):
                out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "This chmod call grants write access to the file's group or other "
                "permission bits — widening tamper access to more principals than "
                "most application files need."
            ),
            remediation=(
                "Use the narrowest mode that works, typically 0o600 (owner "
                "read/write only) or 0o644 (owner read/write, others read-only). "
                "Grant group/other write access only for a genuinely shared "
                "directory, and prefer a dedicated group over world-writable bits."
            ),
            rule="insecure-file-permissions/group-or-other-write",
            standards=list(_STANDARDS),
        )
