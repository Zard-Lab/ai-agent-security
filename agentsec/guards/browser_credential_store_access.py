"""Guard: no code reads a browser/chat-client's saved-credential store (checklist §8, new item).

A dependency, AI-agent skill, or backdoored contribution that reads a browser's or chat
client's own saved-credential files is credential-stealer behavior with essentially zero
legitimate reason to appear in application source — MITRE ATT&CK T1555.003 (Credentials
from Web Browsers). Four independent, high-signal shapes, ported from
`rakshit-737/warden-supply-chain-security`'s `warden_credential_theft.yar` YARA rules
(fetched and read in full; each real rule requires a COMBINATION of artefacts that only
credential-store access needs, never a single browser path or API name alone):

  **chromium-master-key (CRITICAL):** `"Local State"` + `"encrypted_key"` +
  `"CryptUnprotectData"` all present — reads Chromium's encrypted master key and decrypts
  it with Windows DPAPI, the first step of Chromium browser-password theft.

  **chromium-login-data (CRITICAL):** `"Login Data"` + `"password_value"`, combined with
  either `"sqlite"` or a `SELECT ... FROM logins` query shape — opens Chromium's saved-
  password SQLite database directly.

  **firefox-credential-store (CRITICAL):** `"key4.db"` + `"logins.json"` both present —
  references Firefox's NSS key database and its saved-logins file together, the pairing a
  legitimate Firefox-profile backup tool would copy as whole directories instead of naming
  both files individually.

  **discord-token-grabber-webhook (CRITICAL):** a Discord webhook URL
  (`discord(app)?.com/api/webhooks/`) combined with either the known hardcoded
  encrypted-token marker (`dQw4w9WgXcQ:`) or Discord's own LevelDB client-storage shape
  (`"Local Storage"` + `"leveldb"` + a discord/discordcanary/discordptb/lightcord path
  segment) — a webhook alone is an everyday notification channel; it's the pairing with a
  token-extraction signal that is a grabber.

**Narrower than the source on rule 4 only:** the source's rule also accepts a literal
Discord-token-shaped regex PATTERN (or an MFA-token-shaped regex pattern) appearing as TEXT
in the scanned file — a YARA idiom matching the source text of another regex, not the data
it matches. That meta-pattern is fragile to port faithfully into a Python string scan and
drops out here; this guard's two remaining signals (`dQw4w9WgXcQ:`, or the LevelDB/client-
path combination) are themselves unambiguous enough that nothing is lost in practice.

False positives the source itself discloses and this guard inherits: cookie-export, browser-
forensics, and password-manager-import tools read the same files/APIs on purpose. There is
no automated way to distinguish "legitimate forensics tool" from "credential stealer" by
source shape alone — this guard flags the capability for human review, same as the rest of
this project's malware-pattern guards (`reverse-shell-pattern`, `download-execute-chain`,
etc.).

Fires on Python/JS/TS source when `python`/`javascript`/`typescript` is detected, plus
`.sh`/`.bash`/`.zsh` shell scripts. Suppress an audited case (a maintained browser-forensics
or credential-migration tool) with a whole-file pragma comment anywhere in the file:

    # security: allow-browser-credential-store-access
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
    strip_python_line_comment,
    strip_python_strings,
)

_SHELL_SUFFIXES = (".sh", ".bash", ".zsh")
_JS_SUFFIXES = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
_PY_SUFFIXES = (".py", ".pyi")

_LOCAL_STATE = re.compile(r"Local State")
_ENCRYPTED_KEY = re.compile(r"encrypted_key")
_DPAPI = re.compile(r"CryptUnprotectData")

_LOGIN_DATA = re.compile(r"Login Data")
_PASSWORD_VALUE = re.compile(r"password_value")
_SQLITE = re.compile(r"sqlite", re.IGNORECASE)
_LOGINS_QUERY = re.compile(r"select\s[^;\n]{0,256}from\s{1,8}logins\b", re.IGNORECASE)

_KEY4_DB = re.compile(r"key4\.db")
_LOGINS_JSON = re.compile(r"logins\.json")

_DISCORD_WEBHOOK = re.compile(r"discord(?:app)?\.com/api/webhooks/", re.IGNORECASE)
_ENCRYPTED_TOKEN_PREFIX = re.compile(r"dQw4w9WgXcQ:")
_LOCAL_STORAGE = re.compile(r"Local Storage")
_LEVELDB = re.compile(r"leveldb", re.IGNORECASE)
_DISCORD_CLIENT_DIR = re.compile(r"[\\/'\"](?:discord|discordcanary|discordptb|lightcord)[\\/'\"]", re.IGNORECASE)

_PRAGMA = "security: allow-browser-credential-store-access"
_STANDARDS = ["OWASP:A08", "CWE-522"]


def _strip(suffix: str, text: str, *, filename: Path) -> str:
    if suffix in _SHELL_SUFFIXES:
        return strip_hash_comments(text)
    if suffix in _PY_SUFFIXES:
        # Blanks triple-quoted DOCSTRINGS only (not ordinary single/double-quoted string
        # literals, which is where the real markers this guard looks for actually live, e.g.
        # `open('Local State')`) -- this guard's own module docstring names every trigger
        # phrase in prose form, so without this it would self-fire on every rule the moment
        # agentsec audits its own tree (the same self-fire class `mcp-oauth-scope-
        # creep` hit once already).
        stripped = strip_python_strings(text, filename=filename)
        return "\n".join(strip_python_line_comment(ln) for ln in stripped.splitlines())
    return strip_js_comments(text, strip_strings=False)


class BrowserCredentialStoreAccessGuard(Guard):
    id = "browser-credential-store-access"
    title = "No code reads a browser/chat-client's saved-credential store"
    area = "Code safety"

    # steal.py: reads Chromium's Local State encrypted_key and calls CryptUnprotectData ->
    # fires browser-credential-store-access/chromium-master-key (CRITICAL).
    canary_plant = CanaryPlant(
        files={
            "steal.py": (
                "import json\n"
                "data = json.load(open('Local State'))\n"
                "key = data['os_crypt']['encrypted_key']\n"
                "decrypted = win32crypt.CryptUnprotectData(key)\n"
            ),
        },
        expects=frozenset({"browser-credential-store-access/chromium-master-key"}),
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
        text = read(f)
        if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return []
        code = _strip(f.suffix.lower(), text, filename=f)
        out: list[Finding] = []

        if _LOCAL_STATE.search(code) and _ENCRYPTED_KEY.search(code) and _DPAPI.search(code):
            out.append(self._finding(
                root, f, self._lineno(code, _ENCRYPTED_KEY), "chromium-master-key",
                "This file reads Chromium's 'Local State' file, extracts its encrypted_key, "
                "and decrypts it with Windows DPAPI -- the first step of Chromium browser-"
                "password theft.",
            ))
        if (
            _LOGIN_DATA.search(code)
            and _PASSWORD_VALUE.search(code)
            and (_SQLITE.search(code) or _LOGINS_QUERY.search(code))
        ):
            out.append(self._finding(
                root, f, self._lineno(code, _PASSWORD_VALUE), "chromium-login-data",
                "This file opens Chromium's 'Login Data' SQLite database and reads the "
                "saved password_value column -- direct Chromium saved-password theft.",
            ))
        if _KEY4_DB.search(code) and _LOGINS_JSON.search(code):
            out.append(self._finding(
                root, f, self._lineno(code, _LOGINS_JSON), "firefox-credential-store",
                "This file references both Firefox credential-store files (key4.db and "
                "logins.json) together -- a legitimate profile-backup tool would copy whole "
                "directories rather than naming both files individually.",
            ))
        if _DISCORD_WEBHOOK.search(code) and (
            _ENCRYPTED_TOKEN_PREFIX.search(code)
            or (
                _LOCAL_STORAGE.search(code)
                and _LEVELDB.search(code)
                and _DISCORD_CLIENT_DIR.search(code)
            )
        ):
            out.append(self._finding(
                root, f, self._lineno(code, _DISCORD_WEBHOOK), "discord-token-grabber-webhook",
                "This file combines a Discord webhook URL with a Discord token-extraction "
                "signal (the known encrypted-token marker, or the client's LevelDB storage "
                "path) -- harvesting a Discord auth token and exfiltrating it via webhook.",
            ))
        return out

    @staticmethod
    def _lineno(code: str, pattern: re.Pattern[str]) -> int:
        m = pattern.search(code)
        if m is None:
            return 1
        return code.count("\n", 0, m.start()) + 1

    def _finding(self, root: Path, f: Path, lineno: int, rule_suffix: str, message: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=message,
            remediation=(
                "Remove the credential-store access. If this is genuinely a maintained "
                "browser-forensics, credential-migration, or cookie-export tool, mark it "
                f"with `# {_PRAGMA}`."
            ),
            rule=f"browser-credential-store-access/{rule_suffix}",
            standards=list(_STANDARDS),
        )
