"""Guard: a Claude Code `.claude/settings.json` (or `settings.local.json`) misconfigures the
tool-permission or MCP-server trust boundary (checklist §4, new item; adapted from
agent-audit-kit's `trust_boundary.py` concept and Anthropic's own Claude Code settings docs).

Six checks, each scanning `.claude/settings.json` and `.claude/settings.local.json`:

  1. **`enable-all-project-mcp-servers`** (HIGH): `enableAllProjectMcpServers: true` trusts
     every MCP server declared in `.mcp.json`, including ones added later by anyone with write
     access to the repo, with no per-server review.
  2. **`base-url-env-override`** (HIGH): the `env` block sets a key matching
     `_BASE_URL$|_API_URL$|_ENDPOINT$` (e.g. `ANTHROPIC_BASE_URL`) — silently redirecting model
     or tool API traffic through a non-default endpoint.
  3. **`wildcard-permission-pattern`** (HIGH): `permissions.allow` contains a bare `"*"` or an
     unconstrained-argument tool pattern (`"Bash(*)"`, `"Bash"`, `"WebFetch(*)"`) — grants a
     tool with no argument scoping at all.
  4. **`allow-list-with-no-deny-list`** (MEDIUM): `permissions.allow` is non-empty while
     `permissions.deny` is absent or empty — no explicit exclusion sits alongside a broad grant
     surface.
  5. **`project-shadows-local-deny`** (HIGH): an entry in the checked-in, team-shared
     `settings.json`'s `permissions.allow` also appears in the sibling, personal
     `settings.local.json`'s `permissions.deny` in the same `.claude/` directory — the shared
     file silently overrides an individual's own deny decision.
  6. **`mcp-json-with-no-explicit-allowlist`** (MEDIUM): a sibling `.mcp.json` declares project
     MCP servers, but `settings.json` records no explicit trust decision for them at all — no
     `enableAllProjectMcpServers` key (true or false) and no `mcp__`-prefixed entry in either
     `permissions.allow` or `permissions.deny`.

Suppress an audited case with a top-level `"//": "security: allow-trust-boundary"` string
anywhere in the JSON document (JSON has no comment syntax).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files_named, pragma_present, read, rel

# `.claude/settings*.json` has no comment syntax (the documented opt-out is a `"//"` string value), so its
# pragma is matched on the raw text by contract (`dialect=None`, #1040 T5).
_PRAGMA = "security: allow-trust-boundary"

_BASE_URL_KEY_RE = re.compile(r"(?:_BASE_URL|_API_URL|_ENDPOINT)$", re.IGNORECASE)
_WILDCARD_RE = re.compile(r"^\*$|\(\s*\*\s*\)$|^[A-Za-z][A-Za-z0-9_]*$")
_BARE_TOOL_NAMES = frozenset({
    "Bash", "WebFetch", "Write", "Edit", "Read", "Task", "NotebookEdit",
})

_STD_MCP_TRUST = ["OWASP-LLM:LLM06", "CWE-284"]
_STD_ENV_OVERRIDE = ["CWE-923", "OWASP:A05"]
_STD_WILDCARD = ["CWE-284", "OWASP:A01"]
_STD_ALLOW_NO_DENY = ["CWE-284"]
_STD_SHADOW = ["CWE-284", "OWASP:A01"]
_STD_MCP_NO_ALLOWLIST = ["OWASP-LLM:LLM06"]


def _load(raw: str) -> dict[str, Any] | None:
    try:
        data = json.loads(raw.lstrip("\ufeff"))  # a Windows editor's BOM is not a parse failure
    except (ValueError, RecursionError):  # hostile deep nesting: not a usable settings file
        return None
    return data if isinstance(data, dict) else None


def _permission_entries(data: dict[str, Any], key: str) -> list[str]:
    perms = data.get("permissions")
    if not isinstance(perms, dict):
        return []
    entries = perms.get(key)
    if not isinstance(entries, list):
        return []
    return [e for e in entries if isinstance(e, str)]


def _is_wildcard_entry(entry: str) -> bool:
    if entry.strip() == "*":
        return True
    if _WILDCARD_RE.match(entry) and "(" not in entry:
        return entry in _BARE_TOOL_NAMES
    return bool(re.search(r"\(\s*\*\s*\)$", entry))


class TrustBoundaryGuard(Guard):
    id = "trust-boundary"
    title = "Claude Code settings.json misconfigures the tool-permission or MCP-server trust boundary"
    area = "AI agent"

    # trust-boundary-canary/.claude/settings.json: enableAllProjectMcpServers: true -> fires
    # trust-boundary/enable-all-project-mcp-servers. A nested directory (not the repo-root
    # .claude/settings.json, which canary.py's shared scaffolding already owns for
    # ai-instruction-poisoning) so this guard gets its own unshared plant file.
    canary_plant = CanaryPlant(
        files={
            "trust-boundary-canary/.claude/settings.json": (
                '{\n  "enableAllProjectMcpServers": true\n}\n'
            ),
        },
        expects=frozenset({
            "trust-boundary/enable-all-project-mcp-servers",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        settings_files = list(iter_files_named(
            root, "settings.json", "settings.local.json", respect_gitignore=False,
        ))
        by_dir: dict[Path, dict[str, tuple[str, dict[str, Any]]]] = {}

        for p in settings_files:
            if p.parent.name != ".claude":
                continue
            r = rel(root, p)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            raw = read(p)
            if not raw or pragma_present(_PRAGMA, raw, dialect=None):
                continue
            data = _load(raw)
            if data is None:
                continue
            by_dir.setdefault(p.parent, {})[p.name] = (r, data)

        for claude_dir, files in by_dir.items():
            for fname in ("settings.json", "settings.local.json"):
                if fname not in files:
                    continue
                r, data = files[fname]
                out.extend(self._check_file(r, data))

            if "settings.json" in files and "settings.local.json" in files:
                shared_r, shared_data = files["settings.json"]
                _, local_data = files["settings.local.json"]
                out.extend(self._check_shadow(shared_r, shared_data, local_data))

            mcp_json = claude_dir.parent / ".mcp.json"
            if mcp_json.is_file() and "settings.json" in files:
                r, data = files["settings.json"]
                out.extend(self._check_mcp_allowlist(r, data, mcp_json))

        return out

    def _check_file(self, r: str, data: dict[str, Any]) -> list[Finding]:
        out: list[Finding] = []

        if data.get("enableAllProjectMcpServers") is True:
            out.append(self._finding(
                r, "enable-all-project-mcp-servers", "high", _STD_MCP_TRUST,
                "enableAllProjectMcpServers is true — every MCP server declared in .mcp.json "
                "is trusted, including any added later, with no per-server review.",
            ))

        env = data.get("env")
        if isinstance(env, dict):
            for key in env:
                if isinstance(key, str) and _BASE_URL_KEY_RE.search(key):
                    out.append(self._finding(
                        r, "base-url-env-override", "high", _STD_ENV_OVERRIDE,
                        f"env sets {key!r}, redirecting model/tool API traffic through a "
                        "non-default endpoint.",
                    ))

        allow = _permission_entries(data, "allow")
        deny = _permission_entries(data, "deny")

        for entry in allow:
            if _is_wildcard_entry(entry):
                out.append(self._finding(
                    r, "wildcard-permission-pattern", "high", _STD_WILDCARD,
                    f"permissions.allow entry {entry!r} grants a tool with no argument "
                    "scoping at all.",
                ))

        if allow and not deny:
            out.append(self._finding(
                r, "allow-list-with-no-deny-list", "medium", _STD_ALLOW_NO_DENY,
                "permissions.allow is non-empty but permissions.deny is absent or empty — "
                "no explicit exclusion accompanies the grant surface.",
            ))

        return out

    def _check_shadow(
        self, shared_r: str, shared_data: dict[str, Any], local_data: dict[str, Any],
    ) -> list[Finding]:
        shared_allow = set(_permission_entries(shared_data, "allow"))
        local_deny = set(_permission_entries(local_data, "deny"))
        shadowed = sorted(shared_allow & local_deny)
        if not shadowed:
            return []
        return [self._finding(
            shared_r, "project-shadows-local-deny", "high", _STD_SHADOW,
            f"The checked-in, team-shared settings.json allows {shadowed!r}, which the "
            "sibling personal settings.local.json explicitly denies — the shared file "
            "silently overrides an individual's own deny decision.",
        )]

    def _check_mcp_allowlist(
        self, r: str, data: dict[str, Any], mcp_json: Path,
    ) -> list[Finding]:
        if "enableAllProjectMcpServers" in data:
            return []
        allow = _permission_entries(data, "allow")
        deny = _permission_entries(data, "deny")
        if any(e.startswith("mcp__") for e in (*allow, *deny)):
            return []
        return [self._finding(
            r, "mcp-json-with-no-explicit-allowlist", "medium", _STD_MCP_NO_ALLOWLIST,
            f"{mcp_json.name} declares project MCP servers but settings.json records no "
            "explicit trust decision for them (no enableAllProjectMcpServers key and no "
            "mcp__-prefixed permissions entry).",
        )]

    def _finding(
        self, r: str, rule_suffix: str, severity: Severity, standards: list[str], message: str,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=r,
            message=message,
            remediation=(
                "Scope permissions.allow entries to specific tools and arguments, pair any "
                "allow-list with an explicit deny-list, avoid enableAllProjectMcpServers in "
                "favor of per-server review, never let a shared settings.json grant what a "
                "personal settings.local.json denies, and record an explicit MCP "
                "allow/deny decision whenever .mcp.json declares servers."
            ),
            rule=f"trust-boundary/{rule_suffix}",
            standards=list(standards),
        )
