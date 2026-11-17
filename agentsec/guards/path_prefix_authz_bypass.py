"""Guard: path containment checked with a naive string-prefix match (§3a).

`requested_path.startswith(allowed_root)` looks like a directory-containment check but
isn't one: `"/data/users"` is a genuine prefix of `"/data/users_evil"` even though the
second path is a **sibling directory**, not a subdirectory. There is no path-segment
boundary in a plain string comparison, so `startswith()` alone lets an attacker escape
the intended root by choosing a sibling directory name that merely shares the prefix
(`/data/users-backup/../../etc/passwd` also passes, since it starts with `/data/users`
character-for-character before the traversal even needs to bite). CWE-22.

This is a **presence-based** detection, unlike `path-traversal` (which fires on the
*absence* of any containment marker on a dynamic file-sink line). This guard flags the
anti-pattern directly — a check IS present, but it's the wrong one — so it catches
cases `path-traversal` structurally can't: the containment decision made in an
authorization/middleware function, separate from the file sink itself, where
`path-traversal`'s same-line-lookback never sees it.

Fires MEDIUM when a line has BOTH of:
  * a `.startswith(` call whose receiver looks like a path/URL value (`path`,
    `filepath`, `requested`, `target`, `resolved`, or ends in `_path`/`_dir`);
  * an argument that looks like a trusted root/allowlist boundary (`allowed`, `base`,
    `root`, `safe`, or ends in `_dir`/`_root`/`_path`/`_prefix`), used as a boolean gate
    (inside an `if`/`assert`/`while`/`elif` — a bare expression-statement call is not a
    security decision).

The real fix is unaffected: `os.path.commonpath` / `Path(...).is_relative_to(...)` don't
call `startswith(` at all, and the `os.sep`-boundary-aware `startswith(root + os.sep)` /
`startswith(root + "/")` form is explicitly suppressed (`_BOUNDARY_SUFFIX`) — appending a
separator is precisely what makes the prefix check boundary-safe.

Suppress an audited case with `# security: allow-path-prefix-authz-bypass`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import _SL_STRING, CanaryPlant, Guard, iter_files, pragma_present, python_scan_dirs, read, rel

_PRAGMA = re.compile(r"#\s*security:\s*allow-path-prefix-authz-bypass")

_STANDARDS = ["OWASP:A01", "CWE-22"]

_GATE_KEYWORD = re.compile(r"\b(?:if|elif|while|assert)\b")

# `<receiver>.startswith(<arg>)` — captures both sides so each can be checked against
# the path-shaped / root-shaped vocabulary independently. The receiver may end in a
# simple call suffix (#422 S7): `os.path.abspath(p).startswith(base)` is the textbook
# CWE-22 shape and must match alongside the bare-name form.
_STARTSWITH = re.compile(
    r"(?P<receiver>[\w.\[\]\"']+(?:\([^()]*\))?)\s*\.\s*startswith\s*\(\s*(?P<arg>[^()]+?)\s*\)",
)

_PATH_RECEIVER = re.compile(
    r"^(?:.*[._])?(?:path|filepath|requested|target|resolved|dir)\b", re.IGNORECASE,
)
# `basename(...)` strips every directory component, so its result is a LEAF NAME and can never
# begin with a directory prefix. A prefix check on it is not the CWE-22 naive-prefix bypass this
# guard is about — it is at worst dead code — yet `os.path.basename(name).startswith(SAFE_PREFIX)`
# matched, because the receiver still contains the word `path` (#437 review). Note `dirname` is
# deliberately NOT excluded: it keeps the directory, so a prefix check there is meaningful.
_LEAF_NAME_RECEIVER = re.compile(r"\bbasename\s*\(", re.IGNORECASE)
# The `allowed|base|root|safe` alternative is left-anchored with `\b` so it matches a
# root-shaped *word*, not a bare substring (`database`, `un[safe]_input` must NOT match).
_ROOT_ARG = re.compile(
    r"\b(?:allowed|base|root|safe)[\w.]*|[\w.]*(?:_dir|_root|_path|_prefix)\b", re.IGNORECASE,
)
# The boundary-aware fix — `startswith(root + os.sep)` / `startswith(root + "/")` — appends
# a path separator, so it is NOT the vulnerable naive-prefix shape. Suppress when the arg
# ends in such a separator concatenation.
_BOUNDARY_SUFFIX = re.compile(
    r"""\+\s*(?:(?:os\.altsep|os\.path\.sep|os\.sep)\b|(['"])[\\/]+\1)""",
)


def _code_only(line: str) -> str:
    """The code portion of a line: any trailing `#` comment removed, string-aware (a `#`
    inside a single-line string literal is not a comment). Single-line strings are blanked
    to same-length spaces first so indices are preserved and the real comment is found."""
    blanked = _SL_STRING.sub(lambda m: " " * len(m.group()), line)
    idx = blanked.find("#")
    return line if idx < 0 else line[:idx]


class PathPrefixAuthzBypassGuard(Guard):
    id = "path-prefix-authz-bypass"
    title = "Path containment checked with a naive startswith() (sibling-directory bypass)"
    area = "Files"

    # a naive startswith() path-containment check -> path-prefix-authz-bypass.
    canary_plant = CanaryPlant(
        files={
            "tenant_files.py": (
                "def serve_tenant_file(requested_path, allowed_root):\n"
                "    if requested_path.startswith(allowed_root):\n"
                "        return open(requested_path).read()\n"
                "    raise PermissionError\n"
            ),
        },
        expects=frozenset({"path-prefix-authz-bypass/naive-startswith-containment"}),
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
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect="python"):
            return out
        for lineno, line in enumerate(text.splitlines(), start=1):
            code = _code_only(line)
            # Gate keyword must be in real code, not a trailing comment (else
            # `x = p.startswith(root)  # decide if allowed` fires on the comment's "if").
            if not _GATE_KEYWORD.search(code):
                continue
            m = _STARTSWITH.search(code)
            if not m:
                continue
            # Path vocabulary must be in the CALLEE, not a call's argument text:
            # `get_user(session_dir).startswith(prefix)` is not a path check just
            # because a parameter is *_dir-named (#437 review High-4).
            if not _PATH_RECEIVER.search(m.group("receiver").split("(", 1)[0]):
                continue
            if _LEAF_NAME_RECEIVER.search(m.group("receiver")):
                continue  # a basename is a leaf, not a path — see _LEAF_NAME_RECEIVER
            if not _ROOT_ARG.search(m.group("arg")):
                continue
            if _BOUNDARY_SUFFIX.search(m.group("arg")):
                continue
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{rel(root, f)}:{lineno}",
                message=(
                    "This authorization decision uses `.startswith()` to check whether a "
                    "path stays within an allowed root — but a plain string prefix has no "
                    "path-segment boundary, so a sibling directory that merely shares the "
                    "prefix (`/data/users_evil` starts with `/data/users`) passes the check "
                    "as if it were a genuine subdirectory (CWE-22)."
                ),
                remediation=(
                    "Use a boundary-aware containment check instead: "
                    "`Path(requested).resolve().is_relative_to(Path(allowed_root).resolve())`, "
                    "or `os.path.commonpath([requested, allowed_root]) == allowed_root` after "
                    "resolving both to absolute paths. Suppress with "
                    "`# security: allow-path-prefix-authz-bypass` only after confirming the "
                    "prefix can never collide with a sibling path in this deployment."
                ),
                rule="path-prefix-authz-bypass/naive-startswith-containment",
                standards=list(_STANDARDS),
            ))
        return out
