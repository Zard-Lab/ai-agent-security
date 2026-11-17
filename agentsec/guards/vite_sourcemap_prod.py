"""Guard: Vite build sourcemaps enabled in production (OWASP:A05).

When `sourcemap: true` or `sourcemap: "inline"` appears in a Vite build configuration
**outside** the dev-server block, the compiled JavaScript bundle ships with a matching
`.map` file (or an embedded Data URL) that reconstructs the original TypeScript/JSX
source verbatim. Anyone who can load the deployed app can read the full application
source in their browser DevTools — including internal API routes, business logic,
internal identifiers, and any secrets accidentally hard-coded in the frontend.

This guard scans every `vite.config.*` file found in the repository and flags any
`sourcemap: true` or `sourcemap: "inline"` that is NOT inside a `server:` block.
Sourcemaps in the dev-server block (`server: { sourcemap: true }`) are fine — they
only exist locally and are never deployed.

**Detection heuristic:** for each line matching ``sourcemap\\s*:\\s*(true|"inline"|'inline')``,
we inspect the 5 lines above it. If the word `server` appears in those 5 lines, the
occurrence is assumed to be inside a `server:` block and is skipped. Otherwise it fires.

**Why MEDIUM?** Sourcemaps in production don't directly enable remote code execution,
but they substantially lower the bar for reverse-engineering proprietary logic, mounting
targeted XSS payloads, or discovering additional attack surface. OWASP A05 (Security
Misconfiguration) is the closest match — enabling a debug artifact in a prod build.

**Suppress:** `# security: allow-vite-sourcemap` anywhere in the vite config file
silences this check for that file. Use only after confirming the sourcemaps are
intentionally exposed (e.g. an open-source project, a purely public app with no
confidential logic).

**Checklist item:** `5-vite-sourcemaps-not-in-prod` (§5 — Frontend Hardening).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_dialect_for, iter_files_named, pragma_present, read, rel

_PRAGMA = "security: allow-vite-sourcemap"

_STANDARDS = ["OWASP:A05"]

# Matches lines like:  sourcemap: true   "sourcemap": true   sourcemap: 'inline'
_SOURCEMAP_LINE = re.compile(
    r"""["']?sourcemap["']?\s*:\s*(?:true|["']inline["'])""",
    re.IGNORECASE,
)

_VITE_CONFIG_NAMES = ("vite.config.js", "vite.config.ts", "vite.config.mts", "vite.config.mjs")

# The identifier naming the `{` block a `sourcemap:` key lives in (`build: {` / `"build": {` -> "build").
_NAME_BEFORE_BRACE = re.compile(r"""["']?(\w+)["']?\s*[:=]\s*$""")


def _block_stack_at(text: str) -> list[str]:
    """Names of the blocks whose `{` is still open at the end of `text`.

    A best-effort brace tracker (skips string literals and // and /* */ comments) so we
    can tell whether a `sourcemap: true` sits inside the dev-only `server:` block (safe)
    or the production `build:` block / top level (unsafe). Each `{` pushes the identifier
    that named it, or "" for an anonymous brace, so the stack top is the innermost block.
    """
    stack: list[str] = []
    i, n = 0, len(text)
    while i < n:
        two = text[i : i + 2]
        if two == "//":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if two == "/*":
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        ch = text[i]
        if ch in "\"'`":
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if ch == "{":
            # Bounded window: searching the whole `text[:i]` prefix per `{` (slice copy +
            # `$`-anchored scan) is O(n²) on a hostile brace-heavy file (issue #419). The
            # naming identifier sits immediately before its `{` in any real config; 200
            # chars is generous headroom for whitespace/newlines.
            m = _NAME_BEFORE_BRACE.search(text[max(0, i - 200) : i])
            stack.append(m.group(1) if m else "")
        elif ch == "}" and stack:
            stack.pop()
        i += 1
    return stack


class ViteSourcemapProdGuard(Guard):
    id = "vite-sourcemap-prod"
    title = "Vite build sourcemaps enabled - exposes source to production users"
    area = "Build pipeline"

    # vite.config.js: sourcemap: true in build block (not server block) ->
    # fires vite-sourcemap-prod.
    canary_plant = CanaryPlant(
        files={
            "vite.config.js": (
                "import { defineConfig } from 'vite'\n"
                "import react from '@vitejs/plugin-react'\n"
                "\n"
                "export default defineConfig({\n"
                "    plugins: [react()],\n"
                "    build: {\n"
                "        sourcemap: true,\n"
                "    },\n"
                "})\n"
            ),
        },
        expects=frozenset({"vite-sourcemap-prod/build-sourcemap-true"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for cfg in self._find_configs(root):
            text = read(cfg)
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(cfg)):
                continue
            out.extend(self._check_file(root, cfg, text))
        return out

    def _find_configs(self, root: Path) -> list[Path]:
        found: list[Path] = []
        for p in iter_files_named(root, "vite.config.*"):
            if p.name in _VITE_CONFIG_NAMES:
                found.append(p)
        return found

    def _check_file(self, root: Path, cfg: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = text.splitlines()
        for lineno, line in enumerate(lines, 1):
            # Skip commented-out lines (both // and # style).
            stripped = line.lstrip()
            if stripped.startswith("//") or stripped.startswith("#"):
                continue
            m = _SOURCEMAP_LINE.search(line)
            if not m:
                continue
            # Suppress only when the sourcemap key is inside the dev-only `server:` block;
            # `build:` / top-level sourcemaps ship to production and must fire.
            prefix = "\n".join(lines[: lineno - 1]) + "\n" + line[: m.start()]
            stack = _block_stack_at(prefix)
            if stack and stack[-1].lower() == "server":
                continue
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title="Vite build sourcemaps enabled in production",
                location=f"{rel(root, cfg)}:{lineno}",
                message=(
                    "A `sourcemap: true` or `sourcemap: \"inline\"` setting outside the "
                    "`server:` block causes Vite to bundle source maps into the production "
                    "build. Any user who can load the deployed app can reconstruct the full "
                    "original TypeScript/JSX source — including internal API routes, business "
                    "logic, and any accidentally hard-coded secrets — directly in browser DevTools."
                ),
                remediation=(
                    "Remove `sourcemap: true` from the `build:` block (or top-level config) "
                    "in your vite.config file. If you need sourcemaps for error tracking in "
                    "production, upload them to your error-monitoring service (Sentry, Datadog) "
                    "at deploy time and keep them off the public CDN. "
                    "Suppress with `# security: allow-vite-sourcemap` only if sourcemaps are "
                    "intentionally public (e.g. an open-source app with no confidential logic)."
                ),
                rule="vite-sourcemap-prod/build-sourcemap-true",
                standards=list(_STANDARDS),
            ))
        return out
