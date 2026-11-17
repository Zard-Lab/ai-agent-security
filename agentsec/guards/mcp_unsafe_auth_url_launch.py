"""Guard: an MCP OAuth authorization URL is launched via a browser-opener/shell call with no
scheme validation (checklist §4, new item; mined from MCPVul (BarDavid2394)'s
`analyzers/project_risks.py` `MCP15-UNSAFE-AUTH-URL` rule, verified against real source).

MCP clients commonly drive the user through an OAuth authorization-code flow by opening a
browser at a dynamically-constructed authorization URL. Two ways that step goes wrong:

1. **No scheme validation before opening.** `webbrowser.open(auth_url)` / `os.startfile(auth_url)`
   hands the OS whatever string the code built — if an attacker can influence any part of that
   URL (a redirected discovery document, a malformed client-supplied callback), a `file://` or
   `javascript:` scheme reaches the OS opener with no check that it's actually `https://`.

2. **Opened through a shell.** `subprocess.run(f"open {auth_url}", shell=True)` or
   `os.system(f"start {auth_url}")` re-invokes a shell with the URL as part of the command line —
   shell metacharacters in the URL become command injection, not just an unexpected browser tab.

Two statically detectable patterns, scoped to files that both carry an MCP SDK import (`from
mcp`/`import mcp`/`fastmcp`, the same file-level marker `mcp-oauth-flow-hardening` anchors to —
H3, PR #1053 review) AND show MCP OAuth vocabulary nearby (`auth`/`oauth` within the same call)
so this does not fire on an unrelated `webbrowser.open()` call, or on a repo that merely uses MCP
elsewhere, with nothing to do with an OAuth flow:

  1. **`browser-opener-no-scheme-check`** (HIGH): `webbrowser.open(...)` or `os.startfile(...)`
     is called with an argument referencing `auth`/`oauth`/`authorize`/`authorization` that does
     not run on into a longer word (`auth_url`, `authUrl`, `authurl`, `server_auth_url`,
     `googleauth_url`, `/oauth/`; not `author_page`, `authority` or `authenticated_url`), and the
     file shows no `startswith('https')`/`startswith("https")`/`urlparse(...).scheme`
     comparison/scheme-allowlist check anywhere.

  2. **`auth-url-opened-via-shell`** (HIGH): `os.system(...)` (always shell-interprets) or a
     `subprocess.run/Popen/call/check_call/check_output(...)` call that invokes a shell is called
     with an argument referencing an `auth`/`authorization` URL variable name (`*_url`/`*url`
     ending in "url", preceded by "auth"/"authorization"). A subprocess call invokes a shell when
     it passes `shell=True`, when its first argument is not a list (a command string), or when
     it is a list whose program IS a shell (`sh`/`bash`/`zsh`/`dash`/`ksh`/`fish`/`csh`/`tcsh`/
     `cmd`/`powershell`/`pwsh`, path-qualified or not, optionally `.exe`, optionally reached
     through an `env`/`wsl`/`busybox` launcher): `["cmd", "/c", "start", auth_url]` re-parses the URL, so a
     `&` in it is command injection on Windows. The recommended-safe argv form,
     `subprocess.run(['xdg-open', auth_url])` (positional or `args=`), passes no string to a
     shell at all and does not fire.

**False-negative scope:** single-file, line-based regex — a URL built across several statements
before being passed to the opener, or an opener call aliased/wrapped in a local helper, is not
detected. `endpoint`/bare `url` are deliberately not OAuth hints (H3) — a variable merely named
`url`/`endpoint` with no `auth`/`oauth` in its name is not detected either.

Suppress an audited/accepted case with:

    # security: allow-mcp-unsafe-auth-url-launch
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
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-mcp-unsafe-auth-url-launch"

_STANDARDS = ["OWASP-ASI:ASI04"]

# H3 fix (PR #1053 review): bare `endpoint`/`url` dropped — they matched ANY opener call
# (`webbrowser.open(url)`, `webbrowser.open(server_url)`) with nothing tying it to OAuth.
# Round-2 L1: `auth` must not run on into a longer word, or `author_page`/`authority` fire. After
# `auth` (plus an optional `orize`/`orization` suffix) comes either no LOWERCASE letter, or a
# lowercase `url`/`uri`/`link` that ends the word (round-3 M2: `authurl`/`oauthurl`, which the
# shell rule below also treats as an auth URL). The no-lowercase check is case-sensitive on
# purpose: the rule compiles with IGNORECASE, and a camelCase continuation (`authUrl`) is a new
# segment. Nothing is required BEFORE `auth` (round-3 L1), so `oauth_url`, `server_auth_url` and a
# vendor prefix (`googleauth_url`, `reauth_url`) all match.
_AUTH_URL_HINT = r"auth(?:ori[sz]ation|ori[sz]ed?)?(?-i:(?![a-z])|(?=(?:url|uri|link)\b))"

# Import-shaped MCP use only — own copy, per this codebase's convention (see
# `mcp_session_id_security.py::_FILE_HAS_MCP_MARKER` for the same precedent, both mirroring
# `mcp_oauth_flow_hardening.py::_PY_MCP_IMPORT_RE`). Anchors both rules below to files that
# actually show MCP SDK usage, not merely the repo-wide `mcp` feature (H3, PR #1053 review).
_FILE_HAS_MCP_MARKER = re.compile(r"^[ \t]*(?:from|import)[ \t]+(?:mcp|fastmcp)\b", re.MULTILINE)

# Rule 1: a browser-opener/OS-file-opener call referencing an auth-flow-shaped argument.
_BROWSER_OPEN_AUTH_URL = re.compile(
    rf"\b(?:webbrowser\.open|os\.startfile)\s*\([^)]*{_AUTH_URL_HINT}",
    re.IGNORECASE,
)
# Widened (H3, PR #1053 review) to also accept a `urlparse(...).scheme` comparison, not just
# `.startswith("https")` — `if urlparse(auth_url).scheme != 'https': raise` is a real,
# equally-valid mitigation that the original pattern missed entirely.
_SCHEME_CHECK_PRESENT = re.compile(
    r"""\.startswith\s*\(\s*["']https|urlparse\s*\([^)]*\)\s*\.\s*scheme\s*(?:==|!=)\s*["']https""",
    re.IGNORECASE,
)

# Rule 2: a shell/subprocess call referencing an auth-url-shaped variable name.
_SHELL_OPEN_AUTH_URL = re.compile(
    r"\b(?P<call>subprocess\.(?:run|Popen|call|check_call|check_output)|os\.system)\s*\("
    r"(?P<args>[^)]*\bauth(?:orization)?[_a-zA-Z]*url\b[^)]*)\)",
    re.IGNORECASE,
)
# H3 fix (PR #1053 review): the recommended-safe argv/list form —
# `subprocess.run(['xdg-open', auth_url])` — passes NO string to a shell at all, so it must not
# fire. A subprocess call is unsafe when it hands a string to a shell: `shell=True`, a non-list
# first argument (a command string), or a list whose program is itself a shell (round-2 H1).
# `args=` is the keyword spelling of the same first argument (round-2 M3).
_ARGV_LIST_FORM = re.compile(r"^\s*(?:args\s*=\s*)?\[")
_SHELL_TRUE = re.compile(r"\bshell\s*=\s*True\b")
# Round-2 H1: a list whose FIRST element names a shell, bare or path-qualified (`/bin/sh`,
# `C:\Windows\System32\cmd.exe`), optionally `.exe`. The closing quote right after the name keeps
# `cmdline-tool`, `sha256sum` and `fishy-tool` out. The interpreter set extends
# `command_injection.py::_CODE_INTERPRETERS`' shells with the Windows ones, which matter most
# here: `cmd /c start <url>` is the classic launcher-injection shape for an OAuth URL. Round-3 L2:
# fish/csh/tcsh too, and a shell reached through an `env`/`wsl`/`busybox` launcher as the first
# element (`["/usr/bin/env", "sh", "-c", ...]`). A launcher with flags or `VAR=value` before the
# shell (`["wsl", "-e", "bash", ...]`) is not recognized.
_SHELL_INTERPRETER_ARGV = re.compile(
    r"""^\s*(?:args\s*=\s*)?\[\s*"""
    r"""(?:["'](?:[^"'\s]*[/\\])?(?:env|wsl|busybox)(?:\.exe)?["']\s*,\s*)?"""
    r"""["'](?:[^"'\s]*[/\\])?"""
    r"""(?:sh|bash|zsh|dash|ksh|fish|csh|tcsh|cmd|powershell|pwsh)(?:\.exe)?["']""",
    re.IGNORECASE,
)


class McpUnsafeAuthUrlLaunchGuard(Guard):
    id = "mcp-unsafe-auth-url-launch"
    title = "MCP OAuth authorization URL opened without scheme validation or via a shell"
    area = "AI agent"

    # auth_launch.py: webbrowser.open(auth_url) with no scheme check anywhere in the file ->
    # fires browser-opener-no-scheme-check; a second function opens the same URL through a
    # shell -> fires auth-url-opened-via-shell.
    canary_plant = CanaryPlant(
        files={
            "mcp_auth_launch.py": (
                "import webbrowser\n"
                "import subprocess\n"
                "from mcp.server import Server\n"
                "\n"
                "\n"
                "def start_login(auth_url):\n"
                "    webbrowser.open(auth_url)\n"
                "\n"
                "\n"
                "def start_login_fallback(auth_url):\n"
                "    subprocess.run(f'open {auth_url}', shell=True)\n"
            ),
        },
        expects=frozenset({
            "mcp-unsafe-auth-url-launch/browser-opener-no-scheme-check",
            "mcp-unsafe-auth-url-launch/auth-url-opened-via-shell",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                if not _FILE_HAS_MCP_MARKER.search(text):
                    continue
                out.extend(self._scan(r, text))
        return out

    def _scan(self, r: str, text: str) -> list[Finding]:
        out: list[Finding] = []
        has_scheme_check = bool(_SCHEME_CHECK_PRESENT.search(text))
        for idx, line in enumerate(text.splitlines()):
            if not has_scheme_check and _BROWSER_OPEN_AUTH_URL.search(line):
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{r}:{idx + 1}",
                    message=(
                        "A dynamically-built OAuth authorization URL is opened via a browser/"
                        "OS-file opener with no scheme validation anywhere in the file. If any "
                        "part of the URL is attacker-influenced (a redirected discovery "
                        "document, a malformed callback), a `file://` or `javascript:` scheme "
                        "reaches the OS opener unchecked."
                    ),
                    remediation=(
                        "Validate the URL's scheme is exactly `https://` (or a loopback "
                        "`http://127.0.0.1`/`http://localhost` for local development) before "
                        "calling `webbrowser.open`/`os.startfile`, e.g. "
                        "`if not auth_url.startswith('https://'): raise ValueError(...)`."
                    ),
                    rule="mcp-unsafe-auth-url-launch/browser-opener-no-scheme-check",
                    standards=list(_STANDARDS),
                ))
            m = _SHELL_OPEN_AUTH_URL.search(line)
            if m and self._shell_call_is_unsafe(m):
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{r}:{idx + 1}",
                    message=(
                        "An OAuth authorization URL is opened by re-invoking a shell "
                        "(`subprocess`/`os.system`). Shell metacharacters in the URL become "
                        "command injection, not just an unexpected browser tab."
                    ),
                    remediation=(
                        "Never pass a URL to a shell. Use `webbrowser.open(auth_url)` "
                        "(platform-independent, no shell involved), with a scheme check as "
                        "above."
                    ),
                    rule="mcp-unsafe-auth-url-launch/auth-url-opened-via-shell",
                    standards=list(_STANDARDS),
                ))
        return out

    @staticmethod
    def _shell_call_is_unsafe(m: re.Match[str]) -> bool:
        """`os.system(...)` always shell-interprets its argument, so it is unconditionally unsafe.
        A `subprocess.*` call is unsafe when it hands a string to a shell: `shell=True`, a first
        argument that is not a list (a command string), or a list whose program is a shell
        (`["cmd", "/c", "start", auth_url]`, round-2 H1). Only a list naming a non-shell program
        (`subprocess.run(['xdg-open', auth_url])`) passes no string to a shell at all."""
        if m.group("call").lower() == "os.system":
            return True
        args = m.group("args")
        if _SHELL_TRUE.search(args):
            return True
        if not _ARGV_LIST_FORM.match(args):
            return True
        return bool(_SHELL_INTERPRETER_ARGV.match(args))
