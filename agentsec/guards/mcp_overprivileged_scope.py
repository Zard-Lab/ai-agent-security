"""Guard: an MCP server's own source declares a filesystem root, scope, or allowed-hosts/
origins setting as unrestricted (checklist §4, new item; mined from sentrymcp's
`MCPA-AUTH-OVERPRIV-001`, fetched and read in full).

A variable named like a scope boundary (`root_path`, `root_dir`, `allowed_root`, `base_path`,
`scope`, `allowed_hosts`, `allowed_origins`, `allowed_paths`, or bare `root`) is assigned the
filesystem root (`"/"`) or a bare wildcard (`"*"`, `"**"`) where a narrower value is the more
obvious fit for a tool server:

    ROOT_PATH = "/"                    # the whole filesystem, not a project directory
    ALLOWED_ORIGINS = ["*"]            # any origin at all

This is LOW severity and heuristic, matching sentrymcp's own classification: a broad path/host
wildcard is not inherently wrong (some tools genuinely need it), so this is an informational
review signal, not a proven misconfiguration.

**Distinct from `mcp-config-security`'s `wildcard-path-grant` rule**, which reads MCP server
CONFIG files (`mcp.json`/`.mcp.json`) for the same shape in `allowed_paths`/`roots`/
`allowed_dirs` keys. This guard reads the server's own SOURCE CODE — a different surface: a
server whose config file is scoped correctly but whose own source hardcodes a broader default
(or ignores the config value entirely) is invisible to the config-file check.

**Why MCP-gated.** The name vocabulary here (`scope`, `root`, `allowed_hosts`) is common in
ordinary application code unrelated to any MCP tool-server boundary. Scoping `applies()` to
`"mcp" in profile.features` keeps the same broad vocabulary a reasonable review signal instead
of noise on every Python/JS/TS repo that happens to have a variable named `scope`.

One statically detectable pattern:

  **`overprivileged-scope-declaration`** (LOW, heuristic): one of the recognized scope-boundary
  names, assigned (directly, or as the sole/first element of a list literal) a quoted `"/"`,
  `"*"`, or `"**"` literal.

**False-negative scope:** single-line regex only, comment-stripped but not string-stripped. A
value assembled from concatenation, read from config/env, or a list literal with the wildcard
NOT in the first position is not recognized.

Suppress an audited case with:

    # security: allow-mcp-overprivileged-scope   (Python)
    // security: allow-mcp-overprivileged-scope  (JS/TS)
"""
from __future__ import annotations

import re
from collections.abc import Callable
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
    strip_js_comments,
    strip_python_line_comment,
)

_PRAGMA = "security: allow-mcp-overprivileged-scope"
_STANDARDS = ["OWASP:A01"]

# A scope-boundary name assigned the filesystem root or a bare wildcard, optionally as the
# first element of a list literal. Ported from sentrymcp's MCPA-AUTH-OVERPRIV-001 sink_pattern.
_OVERPRIVILEGED_SCOPE = re.compile(
    r"""\b(?:root[_-]?path|root[_-]?dir|allowed[_-]?root|base[_-]?path|scope"""
    r"""|allowed[_-]?hosts?|allowed[_-]?origins?|allowed[_-]?paths?|root)\b"""
    r"""\s*[:=]\s*(?:\[\s*)?["'](/|\*{1,2})["']""",
    re.IGNORECASE,
)


class McpOverprivilegedScopeGuard(Guard):
    id = "mcp-overprivileged-scope"
    title = "MCP server source declares an unrestricted filesystem root or allowed-hosts scope"
    area = "AI agent"

    # The guard's only rule is explicitly heuristic/informational (matching sentrymcp's own
    # classification), so this is a flat surfacing=True rather than a prefix list.
    surfacing = True

    # mcp_server_scope.py: ROOT_PATH = "/" -> fires
    # mcp-overprivileged-scope/overprivileged-scope-declaration.
    # mcp_server_scope.js: allowed_origins list with a bare wildcard -> same rule, JS/TS side.
    canary_plant = CanaryPlant(
        files={
            "mcp_server_scope.py": 'ROOT_PATH = "/"\n',
            "mcp_server_scope.js": 'const allowed_origins = ["*"];\n',
        },
        expects=frozenset({"mcp-overprivileged-scope/overprivileged-scope-declaration"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        if "mcp" not in profile.features:
            return False
        return bool({"python", "javascript", "typescript"} & profile.features)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        if "python" in profile.features:
            seen: set[Path] = set()
            for d in python_scan_dirs(root, profile):
                for f in iter_files(d, (".py",)):
                    if f in seen:
                        continue
                    seen.add(f)
                    if is_nonproduct_path(rel(root, f), profile.archive_segments):
                        continue
                    text = read(f)
                    if pragma_present(_PRAGMA, text, dialect="python"):
                        continue
                    out.extend(self._scan(root, f, text, strip_python_line_comment))
        if {"javascript", "typescript"} & profile.features:
            for f in iter_files(root, (".js", ".jsx", ".ts", ".tsx")):
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="js"):
                    continue
                out.extend(self._scan(root, f, strip_js_comments(text), lambda ln: ln))
        return out

    def _scan(
        self, root: Path, path: Path, text: str, strip_comment: Callable[[str], str]
    ) -> list[Finding]:
        out: list[Finding] = []
        for lineno, raw_line in enumerate(text.splitlines(), 1):
            line = strip_comment(raw_line)
            if not _OVERPRIVILEGED_SCOPE.search(line):
                continue
            out.append(Finding(
                check_id=self.id,
                severity="low",
                title=self.title,
                location=f"{rel(root, path)}:{lineno}",
                message=(
                    "A filesystem root, scope, or allowed-hosts/origins/paths setting is "
                    "declared as unrestricted ('/' or '*'/'**') in this MCP server's own "
                    "source, where a narrower value is the more obvious fit for a tool "
                    "server. Informational: a broad scope is not inherently wrong, but is "
                    "worth a deliberate review."
                ),
                remediation=(
                    "Review whether this scope genuinely needs to be this broad. A tool "
                    "that only needs a project directory or a specific API host shouldn't "
                    "default to filesystem root or a wildcard host/origin. "
                    f"Suppress an audited case with `# {_PRAGMA}`."
                ),
                rule="mcp-overprivileged-scope/overprivileged-scope-declaration",
                standards=list(_STANDARDS),
            ))
        return out
