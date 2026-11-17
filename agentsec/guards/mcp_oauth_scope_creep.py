"""Guard: an MCP server's OAuth config grants a broad/wildcard scope, or uses a dangerous
authorization-URL scheme (checklist §4 — Batch C).

Two rules, both ported from `erayyilmmaz/mcp-security-scanner`'s real `BroadOAuthScopeRule`
(`MCP-AUTH-001`) and `DangerousAuthorizationUrlRule` (`MCP-AUTH-002`) (fetched and read in full),
covering the OAuth/auth-flow half of **MCP02 (Privilege Escalation via Scope Creep)** and **MCP07
(Insufficient Auth)** — a class this project's own prior MCP guards do not cover:
`mcp_config_security.py`'s 8 rules are hardcoded-secrets/wildcard-paths/HTTP-transport/param-
injection/BCC-allowlist/dangerous-exec/env-hijack/consent-bypass, none of them an OAuth-scope-breadth
or dangerous-redirect-scheme check.

**Rule 1 — `broad-oauth-scope` (MEDIUM).** A `scope`/`scopes` field assigned a broad or wildcard
value: `*`, `all`, `admin`, `full_access`/`full-access`, or `read:*`/`write:*`. Anchors CVE-2026-31944
(LibreChat OAuth callback account takeover) and the broader MCP02 pattern this project's own research
effort found (75 real CVEs, a mixed bucket of OAuth-scope-creep and filesystem-scope-escape). Over-
broad scopes turn a single leaked/misused token into full account access rather than the narrow
capability the integration actually needed.

**Rule 2 — `dangerous-auth-url-scheme` (HIGH).** An `authorization`/`auth`/`redirect` URL/URI/
endpoint field assigned a `javascript:`/`file:`/`data:` value instead of a real HTTPS authorization
endpoint — these schemes can execute script, expose local files, or embed untrusted content in place
of directing a user to a secure authorization endpoint.

**Widened one deliberate step beyond the source**, which requires no OAuth-context signal at all for
either rule: Rule 1's field name ("scope"/"scopes") is a very common, generic identifier outside the
OAuth domain (a database query scope, a pytest fixture scope, CSS scoping, a Django/SQLAlchemy
`.scope()` call) — firing on it with no surrounding context would be considerably more FP-prone here
than in the source's own narrower "MCP repo config" scanning scope. This guard requires an OAuth-
context hint (`oauth`, `authorization`, `client_id`, `redirect_uri`, `token_endpoint`) present
ANYWHERE in the same file before Rule 1 can fire. Rule 2's field-name vocabulary is already specific
enough (`authorization_url`/`redirect_uri`/etc, combined with a dangerous scheme) that no such hint
is needed, and none is added, to stay faithful to the source.

Scans Python, JS/TS, JSON, YAML, and TOML — OAuth scope/URL config appears in application source code
at least as often as in a dedicated config file, so this guard is not restricted to
`mcp_config_security.py`'s own MCP-config-file-only scope.

Suppress an audited case with `# security: allow-mcp-oauth-scope-creep`.
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

_PRAGMA = "security: allow-mcp-oauth-scope-creep"
_STANDARDS = ["OWASP:A01", "OWASP-ASI:ASI04"]

_EXTS = (".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml")

_OAUTH_CONTEXT_HINT_RE = re.compile(
    r"oauth|authorization|client_id|redirect_uri|token_endpoint", re.IGNORECASE
)
_SCOPE_FIELD_RE = re.compile(r"""["']?scopes?["']?\s*[:=]\s*(?P<value>[^\r\n]+)""", re.IGNORECASE)
_BROAD_SCOPE_RE = re.compile(
    r"(?<![\w:-])(?:\*|all|admin|full[_-]?access|(?:read|write):\*)(?![\w:-])", re.IGNORECASE
)
_DANGEROUS_AUTH_URL_RE = re.compile(
    r"""["']?(?:authorization|auth|redirect)[_-]?(?:url|uri|endpoint)["']?\s*[:=]\s*["']?"""
    r"""(?:javascript|file|data):""",
    re.IGNORECASE,
)


def _scan_text(f: Path, text: str) -> str:
    """Blank comments (and, for Python, docstrings) before either rule scans, so a design-doc
    disclaimer like `**False-negative scope:** ... all ...` doesn't read as a real `scope:` config
    value. Dean's review: rule 1 fired 10 times on agentsec's own tree, every single
    hit a `**False-negative scope:**` guard-docstring heading followed by prose that happened to
    contain a broad-scope keyword ("all") somewhere in its own free text -- invisible to CI
    self-audit only because `mcp` isn't a feature of agentsec's own codebase (it scans MCP
    servers, it isn't one), not because the bug wasn't real."""
    suffix = f.suffix.lower()
    if suffix == ".py":
        stripped = strip_python_strings(text)
        return "\n".join(strip_python_line_comment(ln) for ln in stripped.splitlines())
    if suffix in (".js", ".ts"):
        return strip_js_comments(text)
    if suffix in (".yaml", ".yml", ".toml"):
        return strip_hash_comments(text)
    return text  # .json has no comment syntax


def _find_rule1(text: str) -> int | None:
    if not _OAUTH_CONTEXT_HINT_RE.search(text):
        return None
    for lineno, line in enumerate(text.splitlines(), 1):
        m = _SCOPE_FIELD_RE.search(line)
        if m and _BROAD_SCOPE_RE.search(m.group("value")):
            return lineno
    return None


def _find_rule2(text: str) -> int | None:
    for lineno, line in enumerate(text.splitlines(), 1):
        if _DANGEROUS_AUTH_URL_RE.search(line):
            return lineno
    return None


class McpOauthScopeCreepGuard(Guard):
    id = "mcp-oauth-scope-creep"
    title = "MCP server OAuth config grants a broad scope or uses a dangerous authorization URL scheme"
    area = "AI agent"

    # oauth_config.py: an oauth client requests scope "admin" with no narrower alternative
    # anywhere in the (OAuth-context-hinting) file -> fires
    # mcp-oauth-scope-creep/broad-oauth-scope.
    canary_plant = CanaryPlant(
        files={
            "oauth_config.py": (
                "OAUTH_CLIENT_ID = 'canary-client-id'\n"
                "OAUTH_AUTHORIZATION_URL = 'https://auth.example.com/authorize'\n"
                "OAUTH_SCOPE = 'admin'\n"
            ),
        },
        expects=frozenset({"mcp-oauth-scope-creep/broad-oauth-scope"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _EXTS):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            scan_text = _scan_text(f, text)
            line1 = _find_rule1(scan_text)
            if line1 is not None:
                out.append(self._finding_rule1(root, f, line1))
            line2 = _find_rule2(scan_text)
            if line2 is not None:
                out.append(self._finding_rule2(root, f, line2))
        return out

    def _finding_rule1(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "An OAuth `scope`/`scopes` field requests a broad or wildcard grant (`*`, `all`, "
                "`admin`, `full_access`, or `read:*`/`write:*`). A leaked or misused token then "
                "carries far more access than the integration actually needs -- the same class as "
                "CVE-2026-31944 (LibreChat OAuth callback account takeover)."
            ),
            remediation=(
                "Request the smallest resource-specific scopes required for the operation; use "
                "incremental authorization when elevated access is genuinely needed. "
                f"Suppress an audited case with `# {_PRAGMA}`."
            ),
            rule="mcp-oauth-scope-creep/broad-oauth-scope",
            standards=list(_STANDARDS),
        )

    def _finding_rule2(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "An authorization/redirect URL field uses a `javascript:`, `file:`, or `data:` "
                "scheme instead of a real HTTPS authorization endpoint. These schemes can execute "
                "script, expose local files, or embed untrusted content in place of a secure "
                "authorization flow."
            ),
            remediation=(
                "Use a registered HTTPS authorization or redirect URI. Never use `javascript:`/"
                "`file:`/`data:` values for an authorization flow. "
                f"Suppress an audited case with `# {_PRAGMA}`."
            ),
            rule="mcp-oauth-scope-creep/dangerous-auth-url-scheme",
            standards=list(_STANDARDS),
        )
