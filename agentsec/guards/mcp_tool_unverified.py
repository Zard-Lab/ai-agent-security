"""Guard: MCP (Model Context Protocol) server auto-loaded without trust verification (§4 — AI Agent Security).

MCP lets an LLM host connect to external "tool servers" that expose callable functions
described by natural-language specs. If a server is auto-connected without an explicit
allowlist or trust check, that server can supply arbitrary tool descriptions to the
model — including ones that override prior instructions, exfiltrate data, or redirect
the agent's actions. This is the MCP-specific variant of indirect prompt injection /
tool poisoning (OWASP-LLM:LLM03).

Three statically detectable patterns:

  1. **Python — `mcp-server-auto-loaded`** (HIGH): An `mcp` SDK import (`from mcp …`,
     `MCPClient(`, `ClientSession(` from the `mcp` package) appears in a Python file
     with NO trust check in the surrounding 20 lines. Trust markers recognised:
     `allowlist`, `allow_list`, `trusted`, `verified`, `approved`, `whitelist`,
     `APPROVED_SERVERS`, `ALLOWED_SERVERS`. If a trust marker appears anywhere in
     those 20 lines, the match is considered safe.

  2. **Config — `mcp-server-auto-loaded`** (HIGH): A JSON or YAML file whose name
     matches `*mcp*.json`, `*mcp*.yaml`, `*mcp*.yml`, or `claude*.json` contains a
     `mcpServers` or `mcp_servers` key where at least one entry lacks `"trusted": true`.
     This covers the claude_desktop_config.json / claude.json pattern where MCP servers
     are declared without per-server trust attestation.

  3. **package.json — `cve-2025-6514-mcp-remote`** (CRITICAL): A `package.json` file
     lists `mcp-remote` in `dependencies` or `devDependencies` at a version in the
     vulnerable range 0.0.5–0.1.15 (CVE-2025-6514, CVSS 9.6). The mcp-remote npm
     package concatenates the OAuth `authorization_endpoint` URL without validation,
     allowing an attacker-controlled MCP server to redirect the OAuth flow to an
     arbitrary URL and capture credentials or tokens. Versions >=0.1.16 are safe.
     Ranges like `^0.0.5`, `~0.0.5`, `>=0.0.5 <0.2.0`, `0.0.x`, `0.1.x` are flagged.
     `latest` is flagged at MEDIUM (ambiguous). `^0.1.16`, `^0.2.0`, `>=0.1.16` are safe.

**Why HIGH?** An unverified MCP server controls the tool descriptions the model sees.
A malicious or compromised server can inject instructions into the model's context via
tool specs (tool poisoning), overriding safety instructions and redirecting agent
actions. The model has no independent way to distinguish a legitimate tool description
from a poisoned one — the only defense is an allowlist enforced before connection.

**Why CRITICAL for CVE-2025-6514?** An attacker-controlled MCP server can redirect the
OAuth authorization flow to steal access tokens or credentials with no user interaction
beyond connecting to the server. CVSS 9.6 (Critical) — network-accessible, no auth
required, high confidentiality/integrity/availability impact.

**False-negative scope:** Multi-file trust checks (where the allowlist lives in a
different module) are NOT caught. The guard looks at a 20-line window around the import
call site; if the trust gate is implemented in a separate helper, it will not silence
the finding. Suppress with the pragma.

**Suppress:** `# security: allow-mcp-unverified` in any Python file silences the Python
check repo-wide. For config files the pragma is not applicable — add `"trusted": true`
to each server entry instead.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_llm_framework_repo,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-mcp-unverified"

# Also OWASP-ASI:ASI04 (Agentic Supply Chain Vulnerabilities, OWASP Top 10 for Agentic
# Applications 2026): an MCP server auto-loaded without trust attestation is exactly a compromised
# or unvetted agentic component entering the pipeline — see wiki/research/owasp-asi-2026.md.
_STANDARDS = ["OWASP-LLM:LLM03", "OWASP-LLM:LLM01", "OWASP-ASI:ASI04"]

# MCP SDK usage patterns — import of the mcp package or explicit MCP client construction.
# NOTE: `ClientSession(` was removed from this pattern because it is a very common name
# in async Python (aiohttp.ClientSession, botocore, etc.) and produced FPs on any repo
# using async HTTP clients. MCP's ClientSession is already caught by the `from mcp`
# import pattern — `from mcp.client.session import ClientSession` matches `^\s*from\s+mcp\b`.
_MCP_IMPORT = re.compile(
    r"^[^\S\n]*from\s+mcp\b|"                  # from mcp import ...  / from mcp.client...
    r"\bMCPClient\s*\(",                  # MCPClient(command=...)
    re.MULTILINE,
)

# Server-definition signals: when a file defines an MCP server (publishes tools), it is
# NOT consuming external servers and does not carry the trust-verification risk.
# Files with these signals and no explicit client calls are skipped.
_MCP_SERVER_DEF = re.compile(
    r"\bFastMCP\s*\(|"           # FastMCP() — high-level server constructor
    r"from\s+mcp\.server\b|"     # from mcp.server import ...
    r"^[^\S\n]*from\s+mcp\s+import\s+[^\n]*\bServer\b|"  # from mcp import Server, ...
    r"@\w*\.?(?:tool|resource|prompt)\s*\b",         # @mcp.tool / @app.tool decorator
    re.MULTILINE | re.IGNORECASE,
)

# Explicit client-side signals: these always indicate CONSUMING an external MCP server.
_MCP_CLIENT_CALL = re.compile(r"\bMCPClient\s*\(|\bClientSession\s*\(", re.IGNORECASE)

# Trust markers that indicate an explicit allowlist or approval check nearby.
_TRUST_MARKER = re.compile(
    r"\ballowlist\b|"
    r"\ballow_list\b|"
    r"\btrusted\b|"
    r"\bverified\b|"
    r"\bapproved\b|"
    r"\bwhitelist\b|"
    r"\bAPPROVED_SERVERS\b|"
    r"\bALLOWED_SERVERS\b",
    re.IGNORECASE,
)

# JSON / YAML config file names that may declare MCP servers.
_MCP_CONFIG_NAME = re.compile(
    r"(?:mcp.*\.(?:json|ya?ml)|claude.*\.json)$",
    re.IGNORECASE,
)

# Keys that hold the map of MCP server definitions.
_MCP_SERVERS_KEY = re.compile(r"\bmcp[_-]?servers\b", re.IGNORECASE)

_CONTEXT_LINES = 20  # window to check for a trust marker around an MCP call site

# ---------------------------------------------------------------------------
# CVE-2025-6514: mcp-remote OAuth URL injection (CRITICAL, CVSS 9.6)
# Vulnerable: 0.0.5 through 0.1.15 (inclusive).
# Safe: >=0.1.16, ^0.1.16, ^0.2.0, 0.2.0, 2.0.0, etc.
# Ambiguous (flag MEDIUM): "latest", "*".
# ---------------------------------------------------------------------------

# Semver strings that are unambiguously in the vulnerable range.
# Matches bare versions like "0.0.5", "0.1.15", "0.0.x", "0.1.x"
# OR range prefixes that pin into the vulnerable range.
_CVE6514_VULN_VERSION = re.compile(
    r"^(?:"
    # Explicit vulnerable bare versions 0.0.5 – 0.0.99 and 0.1.0 – 0.1.15
    r"0\.0\.[5-9]|0\.0\.[1-9]\d+"
    r"|0\.1\.(?:[0-9]|1[0-5])\b"
    # Wildcard patch for vulnerable minors
    r"|0\.0\.x|0\.1\.x"
    # Caret range that can only resolve within 0.0.x or 0.1.x (vulnerable minor)
    r"|\^0\.0\.[5-9]|\^0\.0\.[1-9]\d+"
    r"|\^0\.1\.(?:[0-9]|1[0-5])\b"
    # Tilde range pinned in 0.0.x or 0.1.x (vulnerable minor)
    r"|~0\.0\.[5-9]|~0\.0\.[1-9]\d+"
    r"|~0\.1\.(?:[0-9]|1[0-5])\b"
    # Broad ">=0.0.5" or ">=0.1.0..15" style ranges that admit a vulnerable version.
    # (The earlier ">=0\.1\." alternative was dead: the trailing `$` made it match only
    # the literal string ">=0.1." — it now matches the vulnerable >=0.1.0–0.1.15 band.)
    r"|>=0\.0\.[5-9]|>=0\.0\.[1-9]\d+|>=0\.1\.(?:[0-9]|1[0-5])\b"
    r"|0\.[01]\.\*"
    r")"
    r"$",
    re.ASCII,
)

# Versions that are definitively safe.
#
# Several alternatives here are PREFIXES (`[1-9]\d*\.` for "major >= 1", `0\.2\.` for "minor >= 2"),
# but the pattern was `$`-anchored and consumed with `.match()`, so a prefix could only match when
# it was the ENTIRE string. `1.2.3` therefore was not provably safe, fell through to the ambiguous
# branch, and drew a finding — which is why `^1.0.0 || ^2.0.0`, wholly above the vulnerable band,
# was flagged (#437 review). Each prefix now carries an explicit `\S*` remainder.
_CVE6514_SAFE_VERSION = re.compile(
    r"^(?:"
    r"\^?0\.1\.1[6-9]\S*|\^?0\.1\.[2-9]\d+\S*"   # 0.1.16+ (and the ^ form)
    r"|\^?[1-9]\d*\.\S*"                          # major >= 1
    r"|\^?0\.[2-9]\.\S*|\^?0\.\d{2,}\.\S*"        # minor >= 2 within 0.x (incl. 0.10+)
    r"|>=0\.1\.1[6-9]\S*|>=[1-9]\d*\.\S*|>=0\.[2-9]\.\S*"
    r")$",
    re.ASCII,
)


class McpToolUnverifiedGuard(Guard):
    id = "mcp-tool-unverified"
    title = "MCP server auto-loaded without explicit trust verification or allowlist"
    area = "AI agent"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted across the canary's shared
    # `mcp_client.py`, `mcp-dangerous-env.json` and `package.json`, each of which several guards trip at once,
    # so those files stay in `canary.py`'s base owned by no guard. The ownership rule this follows is
    # documented on `xxe_safe.py`.
    # mcp_client.py: from mcp import ClientSession; ClientSession(read, write) without
    # any trust marker (no allowlist/trusted/verified/approved) -> mcp-server-auto-loaded.
    # package.json: mcp-remote at 0.1.0 (in the 0.0.5-0.1.15 vulnerable range)
    # -> cve-2025-6514-mcp-remote (CRITICAL, CVE-2025-6514 OAuth URL injection).
    canary_plant = CanaryPlant(expects=frozenset({
        "mcp-tool-unverified/mcp-server-auto-loaded",
        "mcp-tool-unverified/cve-2025-6514-mcp-remote",
    }))

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []

        # --- Python scan ---
        py_files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                py_files.append((f, read(f)))

        # Repo-wide pragma silences all Python findings.
        pragma_anywhere = any(pragma_present(_PRAGMA, text, dialect="python") for _f, text in py_files)
        # Framework repos implement the MCP protocol in their source — their imports
        # are the implementation, not untrusted server consumption.
        if not pragma_anywhere and not is_llm_framework_repo(root, profile):
            out += self._check_python(root, py_files)

        # --- Config scan (JSON + YAML) ---
        config_files: list[Path] = []
        config_seen: set[Path] = set()
        for p in iter_files(root, (".json", ".yaml", ".yml")):
            if not _MCP_CONFIG_NAME.search(p.name):
                continue
            # Skip config files in test fixtures, examples, docs, etc.
            if is_nonproduct_path(rel(root, p), profile.archive_segments):
                continue
            if p not in config_seen:
                config_seen.add(p)
                config_files.append(p)

        # Framework repo MCP config files are dev tooling (e.g. .mcp.json for Claude
        # Code), not production deployments — trust verification doesn't apply.
        if not is_llm_framework_repo(root, profile):
            out += self._check_configs(root, config_files)

        # --- package.json scan — CVE-2025-6514 mcp-remote OAuth URL injection ---
        pkg_seen: set[Path] = set()
        for p in iter_files(root, (".json",)):
            if p.name != "package.json":
                continue
            if is_nonproduct_path(rel(root, p), profile.archive_segments):
                continue
            if p not in pkg_seen:
                pkg_seen.add(p)
                finding = self._check_package_json_cve6514(root, p)
                if finding is not None:
                    out.append(finding)

        return out

    def _check_python(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        for f, text in files:
            # Skip files that only DEFINE an MCP server — they publish tools to callers
            # but don't connect to external/untrusted MCP servers themselves.
            # Files that also have explicit client calls (MCPClient/ClientSession) are
            # still checked — they could be both defining and consuming.
            if _MCP_SERVER_DEF.search(text) and not _MCP_CLIENT_CALL.search(text):
                continue
            lines = text.splitlines()
            for m in _MCP_IMPORT.finditer(text):
                # Find the 1-based line number of the match.
                lineno = text[: m.start()].count("\n") + 1
                # Build the context window (0-based slice).
                lo = max(0, lineno - 1 - _CONTEXT_LINES)
                hi = min(len(lines), lineno - 1 + _CONTEXT_LINES + 1)
                window = "\n".join(lines[lo:hi])
                if _TRUST_MARKER.search(window):
                    continue  # trust check present nearby — skip
                return [Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "An MCP (Model Context Protocol) client import or construction "
                        "was found with no trust check in the surrounding code. An MCP "
                        "server controls the tool descriptions delivered to the model — "
                        "a malicious or compromised server can inject arbitrary instructions "
                        "into the model's context via those descriptions (tool poisoning / "
                        "indirect prompt injection via tool specs, OWASP-LLM:LLM03). "
                        "Without an explicit allowlist enforced before connection, any "
                        "server the agent connects to is implicitly trusted."
                    ),
                    remediation=(
                        "Maintain an explicit server allowlist (e.g. `APPROVED_SERVERS = "
                        "{...}`) and validate the server identity before establishing the "
                        "MCP session. Reject connections to servers not on the list. If "
                        "the trust check lives in a separate helper module and this finding "
                        "is a false positive, suppress with "
                        "`# security: allow-mcp-unverified`."
                    ),
                    rule="mcp-tool-unverified/mcp-server-auto-loaded",
                    standards=list(_STANDARDS),
                )]
        return []

    def _check_configs(self, root: Path, files: list[Path]) -> list[Finding]:
        for f in files:
            text = read(f)
            if not _MCP_SERVERS_KEY.search(text):
                continue
            # Try to parse as JSON; YAML without PyYAML falls back to text scan.
            finding = self._check_config_file(root, f, text)
            if finding is not None:
                return [finding]
        return []

    def _check_config_file(self, root: Path, f: Path, text: str) -> Finding | None:
        if f.suffix.lower() == ".json":
            return self._check_json_config(root, f, text)
        return self._check_yaml_config_text(root, f, text)

    def _check_json_config(self, root: Path, f: Path, text: str) -> Finding | None:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        servers = _extract_servers_json(data)
        if servers is None:
            return None
        # Flag if any server entry lacks "trusted": true.
        for _name, entry in servers.items():
            if not isinstance(entry, dict):
                continue
            if entry.get("trusted") is not True:
                return Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=rel(root, f),
                    message=(
                        "An MCP server entry in this config file does not have "
                        '`"trusted": true`. MCP servers defined without explicit trust '
                        "attestation are auto-connected, giving them unrestricted access "
                        "to inject tool descriptions into the model's context. This enables "
                        "tool poisoning: a compromised server rewrites the tool specs the "
                        "model sees, redirecting agent actions without the user's knowledge."
                    ),
                    remediation=(
                        'Add `"trusted": true` to each server entry you have deliberately '
                        "allowlisted and reviewed. Remove entries for servers you do not "
                        "control or have not audited. Prefer an explicit runtime allowlist "
                        "in application code over a flat config file for dynamic server "
                        "registrations."
                    ),
                    rule="mcp-tool-unverified/mcp-server-auto-loaded",
                    standards=list(_STANDARDS),
                )
        return None

    def _check_package_json_cve6514(self, root: Path, f: Path) -> Finding | None:
        """Detect mcp-remote versions in the CVE-2025-6514 vulnerable range (0.0.5–0.1.15)."""
        text = read(f)
        if "mcp-remote" not in text:
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        # Check both dependencies and devDependencies.
        version: str | None = None
        for section in ("dependencies", "devDependencies"):
            sec = data.get(section)
            if isinstance(sec, dict) and "mcp-remote" in sec:
                raw = sec["mcp-remote"]
                if isinstance(raw, str):
                    version = raw.strip()
                break
        if version is None:
            return None

        # "latest" / "*" — ambiguous, may resolve to vulnerable version.
        if version in ("latest", "*"):
            return self._cve6514_ambiguous(root, f, version)

        # Compound ranges (">=0.0.5 <0.2.0", "0.0.5 - 0.1.15") match neither anchored
        # regex; classify by the lower bound (the first whitespace-split token). For a
        # single-token version this is the version itself, so behavior is unchanged.
        parts = version.split()
        if not parts:
            return None
        lower_bound = parts[0]

        # Definitively safe — skip.
        if _CVE6514_SAFE_VERSION.match(lower_bound):
            return None

        # Vulnerable or range overlapping with vulnerable versions.
        if _CVE6514_VULN_VERSION.match(lower_bound):
            return Finding(
                check_id=self.id,
                severity="critical",
                title="mcp-remote OAuth URL injection (CVE-2025-6514, CVSS 9.6)",
                location=rel(root, f),
                message=(
                    f'`mcp-remote` is pinned to `"{version}"` which is in the vulnerable '
                    "range 0.0.5–0.1.15 (CVE-2025-6514, CVSS 9.6). The mcp-remote package "
                    "concatenates the OAuth `authorization_endpoint` URL without validation, "
                    "allowing an attacker-controlled MCP server to redirect the OAuth "
                    "authorization flow to an arbitrary URL — stealing access tokens or "
                    "credentials with no additional user interaction."
                ),
                remediation=(
                    "mcp-remote 0.0.5-0.1.15 has OAuth URL injection (CVE-2025-6514, CVSS 9.6) "
                    "— upgrade to >=0.1.16"
                ),
                rule="mcp-tool-unverified/cve-2025-6514-mcp-remote",
                standards=list(_STANDARDS),
            )

        # A compound range whose lower bound classifies as neither safe nor vulnerable
        # may still admit a vulnerable version; flag it MEDIUM instead of staying silent.
        if len(parts) > 1:
            return self._cve6514_ambiguous(root, f, version)

        return None

    def _cve6514_ambiguous(self, root: Path, f: Path, version: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title="mcp-remote version is ambiguous — may resolve to CVE-2025-6514 range",
            location=rel(root, f),
            message=(
                f'`mcp-remote` is pinned to `"{version}"` which may resolve to a version '
                "in the vulnerable range 0.0.5–0.1.15 (CVE-2025-6514, CVSS 9.6). "
                "The mcp-remote package concatenates the OAuth `authorization_endpoint` "
                "URL without validation, allowing an attacker-controlled MCP server to "
                "redirect the OAuth flow and steal credentials or tokens."
            ),
            remediation=(
                'Pin `mcp-remote` to `">=0.1.16"` or `"^0.1.16"` in package.json '
                "and run `npm install` to regenerate the lockfile with a safe version."
            ),
            rule="mcp-tool-unverified/cve-2025-6514-mcp-remote",
            standards=list(_STANDARDS),
        )

    def _check_yaml_config_text(self, root: Path, f: Path, text: str) -> Finding | None:
        # Without PyYAML (zero runtime deps policy), do a lightweight text check:
        # if the file has mcpServers/mcp_servers but no "trusted: true" line nearby,
        # flag it. This is intentionally conservative (may have FNs) but never crashes.
        if not re.search(r"trusted\s*:\s*true", text, re.IGNORECASE):
            return Finding(
                check_id=self.id,
                severity="high",
                title=self.title,
                location=rel(root, f),
                message=(
                    "An MCP server configuration was found in this YAML file with no "
                    '`trusted: true` field on any server entry. Auto-connected MCP servers '
                    "can inject arbitrary tool descriptions into the model's context "
                    "(tool poisoning / indirect prompt injection via tool specs)."
                ),
                remediation=(
                    "Add `trusted: true` under each server entry you have explicitly "
                    "allowlisted and reviewed. Remove entries for servers you do not "
                    "control. For dynamic registrations, enforce the allowlist in "
                    "application code rather than a flat config file."
                ),
                rule="mcp-tool-unverified/mcp-server-auto-loaded",
                standards=list(_STANDARDS),
            )
        return None


def _extract_servers_json(data: object) -> dict[str, object] | None:
    """Return the first mcpServers/mcp_servers dict found in a parsed JSON object."""
    if not isinstance(data, dict):
        return None
    for key in data:
        if re.fullmatch(r"mcp[_-]?servers", key, re.IGNORECASE):
            val = data[key]
            if isinstance(val, dict):
                return val
    return None
