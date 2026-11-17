"""Guard: no hardcoded destructive filesystem-wipe command in source (checklist §8, new item).

A literal command that recursively deletes or overwrites an entire root-level
directory (`rm -rf /`, `rmtree('/')`, `dd if=/dev/zero of=/dev/sda`) is the classic
"sabotage payload" shape: a disgruntled-insider or supply-chain-planted destructive
action with no legitimate reason to target the filesystem root, a user's home
directory, or a whole-disk device. Adapted from Datadog GuardDog's
`threat-filesystem-destruction` source-code rule (GuardDog screens third-party
packages; this guard applies the same signatures to the target app's own source).

Deliberately scoped to ROOT-LEVEL/whole-device targets only. `rm -rf ./build`,
`shutil.rmtree(tempdir)`, or any ordinary subdirectory cleanup never fires. It's the
destination (`/`, `/home`, `/Users`, `~`, or a raw disk device), not the destructive
verb alone, that makes this a sabotage shape rather than routine cleanup code.

Fires on Python/JS/shell source when `python`/`javascript`/`typescript` is detected.
Suppress an audited case (a maintained provisioning/wipe tool that genuinely needs
this) with a whole-file pragma comment anywhere in the file:

    # security: allow-destructive-filesystem-command
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_hash_comments,
    strip_js_comments,
    strip_python_strings,
)

_SHELL_SUFFIXES = (".sh", ".bash", ".zsh")
_JS_SUFFIXES = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
_PY_SUFFIXES = (".py", ".pyi")

_RM_ROOT = re.compile(r"\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+/\s*(?:[;&|\n]|$)", re.IGNORECASE)
_RM_HOME_ROOT = re.compile(
    r"\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+['\"]?(?:/home|/Users)/?['\"]?\s*(?:[;&|\n]|$)",
    re.IGNORECASE,
)
_RMTREE_ROOT = re.compile(r"\brmtree\s*\(\s*['\"]/\s*['\"]", re.IGNORECASE)
# The home directory ITSELF: `expanduser('~')` / `expanduser("~/")`, never a subpath or a variable
# (`rmtree(expanduser('~/.cache/myapp'))` is ordinary cache cleanup, PR #1048 review H3).
_RMTREE_HOME = re.compile(
    r"\brmtree\s*\(\s*['\"]~['\"]"
    r"|\brmtree\s*\(\s*os\.path\.expanduser\s*\(\s*(['\"])~/?\1\s*\)",
    re.IGNORECASE,
)
_DD_WIPE = re.compile(r"\bdd\s+if=/dev/(?:zero|urandom)\s+of=/dev/\w+", re.IGNORECASE)
_SHRED = re.compile(r"\bshred\s+-[a-z]*\s+/dev/\w+", re.IGNORECASE)
_RIMRAF_ROOT = re.compile(r"\brimraf\s*\(\s*['\"]/\s*['\"]", re.IGNORECASE)

_PRAGMA = re.compile(r"security:\s*allow-destructive-filesystem-command")
_STANDARDS = ["OWASP:A01", "CWE-732"]


class DestructiveFilesystemCommandGuard(Guard):
    id = "destructive-filesystem-command"
    title = "No hardcoded destructive filesystem-wipe command targeting a root/home/device path"
    area = "Code safety"

    # wipe.sh: rm -rf / -> fires destructive-filesystem-command/rm-root (HIGH).
    canary_plant = CanaryPlant(
        files={"wipe.sh": "#!/bin/sh\nrm -rf /\n"},
        expects=frozenset({"destructive-filesystem-command/rm-root"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return bool({"python", "javascript", "typescript"} & profile.features)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for f in iter_files(root, _PY_SUFFIXES + _JS_SUFFIXES + _SHELL_SUFFIXES):
            if f in seen:
                continue
            seen.add(f)
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        suffix = f.suffix.lower()
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return []

        if suffix in _SHELL_SUFFIXES:
            code = strip_hash_comments(text)
        elif suffix in _PY_SUFFIXES:
            code = strip_python_strings(text, filename=f)
            code = "\n".join(
                ln if not ln.lstrip().startswith("#") else "" for ln in code.splitlines()
            )
        else:
            code = strip_js_comments(text, strip_strings=False)

        out: list[Finding] = []
        for i, line in enumerate(code.splitlines(), start=1):
            if _RM_ROOT.search(line):
                out.append(self._finding(root, f, i, "rm-root", "`rm -rf /`: recursively deletes the entire filesystem root."))
            elif _RM_HOME_ROOT.search(line):
                out.append(self._finding(root, f, i, "rm-home-root", "`rm -rf` targets the whole `/home` or `/Users` directory."))
            elif _RMTREE_ROOT.search(line):
                out.append(self._finding(root, f, i, "rmtree-root", "`rmtree('/')` recursively deletes the filesystem root."))
            elif _RMTREE_HOME.search(line):
                out.append(self._finding(root, f, i, "rmtree-home", "`rmtree` targets a user's whole home directory (`'~'` or `os.path.expanduser('~')`)."))
            elif _RIMRAF_ROOT.search(line):
                out.append(self._finding(root, f, i, "rimraf-root", "Node's `rimraf('/')` recursively deletes the filesystem root."))
            elif _DD_WIPE.search(line):
                out.append(self._finding(root, f, i, "dd-wipe", "`dd if=/dev/zero|urandom of=/dev/...` overwrites a whole disk device."))
            elif _SHRED.search(line):
                out.append(self._finding(root, f, i, "shred-device", "`shred` targets a raw disk device."))
        return out

    def _finding(self, root: Path, f: Path, line: int, rule_suffix: str, message: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=message + " This is the classic sabotage/destructive-payload shape: no "
            "ordinary application code needs to target the filesystem root, a whole home "
            "directory, or a raw disk device.",
            remediation=(
                "Remove the destructive command, or scope it to a specific, non-root "
                "subdirectory. If this is genuinely a maintained provisioning/wipe tool, mark "
                "it with the inline suppress pragma."
            ),
            rule=f"destructive-filesystem-command/{rule_suffix}",
            standards=list(_STANDARDS),
        )
