"""Guard: no code writes a cron entry, systemd unit, macOS LaunchAgent/Daemon, or Windows
Startup-folder file (checklist §8, new item).

Writing a cron job, a systemd unit, a macOS LaunchAgent/LaunchDaemon plist, or a file into the
Windows Start Menu's Startup folder is how malware survives a reboot without touching a shell
profile — a backdoored dependency or AI-agent skill plants itself so it restarts
automatically. Ordinary application code has essentially no legitimate reason to touch any of
these (MITRE ATT&CK T1053.003, Scheduled Task/Job: Cron; T1543.003, Create or Modify System
Process: Windows Service is the Windows-service analogue; T1547.011, Boot or Logon Autostart
Execution: Plist Modification). Ported from `rakshit-737/warden-supply-chain-security`'s
`warden-python.yml` semgrep rule (`warden.malicious_behavior.persistence-write`, fetched and
read in full).

**Sibling to `autostart-persistence-mechanism` (held, unmerged PR #1048 at the time this guard
was written), not a duplicate.** That guard already covers shell-config writes (`.bashrc`/
`.bash_profile`/`.profile`/`.zshrc`/`/etc/rc.local`) and the Windows registry Run/RunOnce key —
confirmed by reading its real source, not assumed from checklist status. This guard covers the
DIFFERENT target-path family the source's rule also includes that the held guard does not:
cron, systemd units, macOS LaunchAgents/LaunchDaemons, and the Windows Startup FOLDER (as
opposed to the registry key). Built as an independent guard rather than extending the held
one, since that guard's own file does not exist on `origin/main` yet — a future session should
fold the two together once PR #1048 merges, rather than carrying two separate "persistence"
guards indefinitely.

Two tiers of signal, mirroring the held sibling's own structure:

  **system-wide cron/systemd path + nearby WRITE (HIGH):** a literal reference to
  `/etc/cron.d/`, `/etc/cron.daily/`(`.hourly`/`.weekly`/`.monthly`), `/var/spool/cron/`,
  `/etc/systemd/`, or `/lib/systemd/system/`(`/usr/lib/systemd/system/`), with an actual file
  WRITE (`open(..., "w"/"a")`, `fs.writeFile`/`fs.appendFile`) within a few lines. **Originally
  fired on a bare reference alone** ("even a bare reference is already unusual for application
  code to need") — Dean's review found this fires HIGH on the same string
  appearing in argparse help text, a log message, or other prose that never touches the
  filesystem, since only comments and triple-quoted docstrings are stripped before the regex
  scan, not ordinary single/double-quoted string literals. Now requires the same nearby-WRITE
  signal as the user-level tier below, closing the FP while a real `open('/etc/systemd/system/
  evil.service', 'w')` still fires.

  **macOS LaunchAgent/Daemon or Windows Startup-folder WRITE (HIGH):** an actual file WRITE
  (`open(..., "w"/"a")`, `fs.writeFile`/`fs.appendFile`) targeting a path containing
  `LaunchAgents`/`LaunchDaemons`, a user-level systemd unit directory
  (`~/.config/systemd/user/`), or the Windows `Start Menu/Programs/Startup` folder — reading
  these paths has ordinary uses (an installer checking what autostart entries already exist);
  it is the WRITE that is the persistence signal. The Python write check is balanced-paren-aware
  (`close_paren_map`, not a bounded `[^)]*` regex), so a path built through a nested call —
  `open(os.path.expanduser("~/Library/LaunchAgents/com.evil.plist"), "w")` — is still recognized
  as a write; a bounded-width regex can't see past the nested call's own closing paren
  (the same class of bug `matching_close_paren`'s own docstring documents).
  The mode is read from `open()`'s OWN top-level arguments (`split_call_args`): the second
  positional argument or a `mode=` keyword, in any position, so trailing keywords such as the
  `encoding="utf-8"` this codebase mandates do not hide it (PR #1093 round 2). Any mode carrying
  `w`, `a`, `x` or `+` is a write, text or binary; a `"w"` passed to a NESTED call is not.

Fires on Python/JS source when `python`/`javascript`/`typescript` is detected. Suppress an
audited case (a legitimate provisioning/deployment tool) with a whole-file pragma comment
anywhere in the file:

    # security: allow-cron-systemd-persistence-write
"""
from __future__ import annotations

import re
from bisect import bisect_right
from itertools import accumulate
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    close_paren_map,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
    split_call_args,
    strip_js_comments,
    strip_python_line_comment,
    strip_python_strings,
)

_JS_SUFFIXES = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
_PY_SUFFIXES = (".py", ".pyi")

_SYSTEM_WIDE_PATH = re.compile(
    r"/etc/cron\.(?:d|daily|hourly|weekly|monthly)/?"
    r"|/var/spool/cron/"
    r"|/etc/systemd/"
    r"|/(?:usr/)?lib/systemd/system/",
    re.IGNORECASE,
)

_USER_LEVEL_PERSISTENCE_PATH = re.compile(
    r"LaunchAgents|LaunchDaemons"
    r"|\.config[\\/]systemd[\\/]user[\\/]"
    r"|Start Menu[\\/]Programs[\\/]Startup",
    re.IGNORECASE,
)
_PY_OPEN_CALL = re.compile(r"\bopen\s*\(")
# A keyword argument's `name=` head (matched at the argument's start; the value is the rest).
_PY_KWARG = re.compile(r"(?<!\w)(\w+)\s*=(?!=)")
_PY_MODE_LITERAL = re.compile(r"[rRuU]?(['\"])([rwaxbt+]{1,4})\1")
# An open() call longer than this is not a real file open; skipping it bounds the argument split
# on a hostile file of deeply nested `open(open(...))` calls.
_MAX_OPEN_CALL_CHARS = 4096
_JS_FS_WRITE = re.compile(r"fs\s*\.\s*(?:writeFile|appendFile)(?:Sync)?\s*\(")

_PRAGMA = "security: allow-cron-systemd-persistence-write"
_STANDARDS = ["OWASP:A08", "CWE-506"]


class CronSystemdPersistenceWriteGuard(Guard):
    id = "cron-systemd-persistence-write"
    title = "No code writes a cron entry, systemd unit, macOS LaunchAgent/Daemon, or Windows Startup-folder file"
    area = "Code safety"

    # cron_systemd_persist.py: writes a plist into ~/Library/LaunchAgents -> fires
    # cron-systemd-persistence-write/user-level-persistence-write (HIGH).
    # Named cron_systemd_persist.py, not persist.py, to avoid colliding with
    # autostart-persistence-mechanism's own persist.py plant (merge fallout -- see
    # the identical note on environ_dump_to_network.py's canary rename).
    canary_plant = CanaryPlant(
        files={
            "cron_systemd_persist.py": (
                "import os\n"
                "def install():\n"
                "    path = os.path.expanduser('~/Library/LaunchAgents/com.evil.plist')\n"
                "    with open(path, 'w') as f:\n"
                "        f.write(PLIST_CONTENT)\n"
            ),
        },
        expects=frozenset({"cron-systemd-persistence-write/user-level-persistence-write"}),
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
        if not text or pragma_present(_PRAGMA, text, dialect="python" if suffix in _PY_SUFFIXES else "js"):
            return []

        if suffix in _PY_SUFFIXES:
            stripped = strip_python_strings(text, filename=f)
            code = "\n".join(strip_python_line_comment(ln) for ln in stripped.splitlines())
        else:
            code = strip_js_comments(text, strip_strings=False)

        out: list[Finding] = []
        lines = code.splitlines()
        py_writes = self._py_write_calls(code) if suffix in _PY_SUFFIXES else {}

        def window_has_write(i: int) -> bool:
            # Lines i-2 .. i+2. A Python write must open AND close inside the window.
            lo, hi = max(1, i - 2), min(len(lines), i + 2)
            if suffix in _JS_SUFFIXES:
                return bool(_JS_FS_WRITE.search("\n".join(lines[lo - 1:hi])))
            return any(py_writes.get(s, hi + 1) <= hi for s in range(lo, hi + 1))

        for i, line in enumerate(lines, start=1):
            if _SYSTEM_WIDE_PATH.search(line):
                if window_has_write(i):
                    out.append(self._finding(
                        root, f, i, "system-wide-cron-systemd-reference",
                        "References a root-owned, system-wide cron or systemd location "
                        "(/etc/cron.d/, /var/spool/cron/, /etc/systemd/, or "
                        "/lib/systemd/system/) with a file write nearby -- unusual for "
                        "application code to need, and the write makes it persistence rather "
                        "than a bare mention.",
                    ))
                continue
            if _USER_LEVEL_PERSISTENCE_PATH.search(line) and window_has_write(i):
                out.append(self._finding(
                    root, f, i, "user-level-persistence-write",
                    "A macOS LaunchAgent/LaunchDaemon, a user-level systemd unit "
                    "directory, or the Windows Startup folder is opened for writing -- "
                    "the classic autostart-persistence shape for these locations.",
                ))
        return out

    @staticmethod
    def _py_write_calls(code: str) -> dict[int, int]:
        """Every write-mode `open(...)` call in the file, as {start line: earliest end line}.

        One pass over the file (`close_paren_map`), not one walk per path line: an unclosed
        `open(` used to be re-walked for each of the five windows that contain it (PR #1093
        round 2, M4). The mode comes from open()'s own top-level arguments, so a nested call's
        `)` cannot end the scan early and a trailing `encoding=` keyword cannot hide
        the mode (round 2, H1)."""
        pairs = close_paren_map(code)
        line_starts = [0, *accumulate(len(ln) for ln in code.splitlines(keepends=True))]
        out: dict[int, int] = {}
        for m in _PY_OPEN_CALL.finditer(code):
            open_idx = m.end() - 1
            close_idx = pairs.get(open_idx)
            if close_idx is None or close_idx - open_idx > _MAX_OPEN_CALL_CHARS:
                continue
            args = split_call_args(code[open_idx:close_idx + 1], 0)
            if not args or not CronSystemdPersistenceWriteGuard._is_write_mode(args):
                continue
            start, end = bisect_right(line_starts, m.start()), bisect_right(line_starts, close_idx)
            out[start] = min(out.get(start, end), end)
        return out

    @staticmethod
    def _is_write_mode(args: list[str]) -> bool:
        mode = None
        for pos, arg in enumerate(args):
            text = arg.strip()
            kw = _PY_KWARG.match(text)
            if kw:
                if kw.group(1) == "mode":
                    mode = text[kw.end():]
            elif pos == 1:
                mode = text
        lit = _PY_MODE_LITERAL.fullmatch(mode.strip()) if mode else None
        return bool(lit and set(lit.group(2)) & set("wax+"))

    def _finding(self, root: Path, f: Path, lineno: int, rule_suffix: str, message: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=message,
            remediation=(
                "Remove the persistence code. If this is a genuinely maintained provisioning "
                f"or deployment tool, mark it with `# {_PRAGMA}`."
            ),
            rule=f"cron-systemd-persistence-write/{rule_suffix}",
            standards=list(_STANDARDS),
        )
