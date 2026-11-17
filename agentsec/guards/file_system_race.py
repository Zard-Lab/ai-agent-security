"""Guard: file existence/stat check followed by a separate use of the same path — a
time-of-check-to-time-of-use race (checklist §8, new item, CWE-367).

Checking whether a file exists (or reading its stat/permissions) and then, in a separate
call, writing to or opening that same path assumes nothing changes in between. Between the
check and the use, an attacker who can influence the target path or filesystem — a symlink
race, a shared/predictable temp location, a multi-tenant upload directory — can swap what
the path resolves to, so the later write/open acts on a different file than the one that
was checked.

Sourced from GitHub CodeQL's `js/file-system-race` query
(`javascript/ql/src/Security/CWE-367/FileSystemRace.ql`, verified against real fetched
source): a `FileCheck` (`fs.exists`/`existsSync`/`stat`/`statSync`/`lstat`/`lstatSync`/
`access`/`accessSync`) on a path, followed by a `FileUse` (`fs.writeFile`/`writeFileSync`/
`appendFile`/`appendFileSync`/`open`/`openSync`/`readFile`/`readFileSync`) on the SAME
path — except an `exists`/`existsSync` check followed by a `readFile`/`readFileSync` on the
same path, which CodeQL's own query explicitly treats as fine ("a read after an exists
check is fine").

Fires MEDIUM, at most once per matched pair: a check call on a path variable, followed
within the next 10 lines by a use call on the SAME path variable, in the same file.

    if (fs.existsSync(uploadPath)) {
      fs.writeFileSync(uploadPath, data);   // <-- race: the check proved nothing here
    }
    // security: allow-file-system-race

**Scope:** JS/TS files only, matched on a simple identifier path argument (`fs.exists(p)`,
not `fs.exists(getPath())` or a property-access expression) — the same tradeoff several
sibling window-based guards make. A check and use separated by more than 10 lines, or
whose path arguments are anything other than a bare identifier, are not tracked.

Suppress an audited case (e.g. a check-then-use pair that is not attacker-reachable, or
already protected by an exclusive-open flag) with `// security: allow-file-system-race`
on the check line.
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
_PRAGMA_TEXT = "security: allow-file-system-race"

_WINDOW = 10

_FS_CHECK = re.compile(
    r"\bfs\.(exists(?:Sync)?|stat(?:Sync)?|lstat(?:Sync)?|access(?:Sync)?)\s*\(\s*(\w+)\b"
)
_FS_USE = re.compile(
    r"\bfs\.(writeFile(?:Sync)?|appendFile(?:Sync)?|open(?:Sync)?|readFile(?:Sync)?)\s*\(\s*(\w+)\b"
)

_STANDARDS = ["CWE-367"]


class FileSystemRaceGuard(Guard):
    id = "file-system-race"
    title = "File checked then used separately — time-of-check-to-time-of-use race"
    area = "Files"

    # fs_race.js: fs.existsSync(uploadPath) then fs.writeFileSync(uploadPath, ...) ->
    # fires file-system-race/check-then-use.
    # Must NOT contain: the allow-file-system-race pragma.
    canary_plant = CanaryPlant(
        files={
            "fs_race.js": (
                "function saveUpload(uploadPath, data) {\n"
                "  if (fs.existsSync(uploadPath)) {\n"
                "    return false;\n"
                "  }\n"
                "  fs.writeFileSync(uploadPath, data);\n"
                "  return true;\n"
                "}\n"
            ),
        },
        expects=frozenset({"file-system-race/check-then-use"}),
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
            lines = code.splitlines()
            view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
            for i, line in enumerate(lines):
                check_m = _FS_CHECK.search(line)
                if not check_m:
                    continue
                check_method, check_var = check_m.group(1), check_m.group(2)
                pragma_line = view_lines[i] if i < len(view_lines) else ""
                if _PRAGMA_TEXT in pragma_line:
                    continue
                window_end = min(len(lines), i + 1 + _WINDOW)
                for j in range(i + 1, window_end):
                    use_m = _FS_USE.search(lines[j])
                    if not use_m:
                        continue
                    use_method, use_var = use_m.group(1), use_m.group(2)
                    if use_var != check_var:
                        continue
                    # CodeQL's own exemption: an exists check followed by a read is fine.
                    if check_method in ("exists", "existsSync") and use_method in (
                        "readFile", "readFileSync"
                    ):
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title=self.title,
                            location=f"{rel(root, f)}:{i + 1}",
                            message=(
                                f"`{check_var}` is checked with `fs.{check_method}(...)` and "
                                f"then used with `fs.{use_method}(...)` a few lines later. "
                                "Nothing prevents the filesystem entry this path resolves to "
                                "from changing between the check and the use — a symlink "
                                "swap, a shared temp location, or a concurrent write can "
                                "make the later call act on a different file than the one "
                                "that was checked (CWE-367)."
                            ),
                            remediation=(
                                "Avoid the separate check entirely where possible: open the "
                                "file directly and handle the error (e.g. `fs.open(path, "
                                "'wx')` to atomically fail if it already exists), rather than "
                                "checking first and using second. If the check is genuinely "
                                "needed, suppress a reviewed, non-attacker-reachable case with "
                                "`// security: allow-file-system-race` on the check line."
                            ),
                            rule="file-system-race/check-then-use",
                            standards=list(_STANDARDS),
                        )
                    )
                    break
        return out
