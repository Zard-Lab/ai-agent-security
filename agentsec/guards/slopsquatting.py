"""Guard: Package name confusion or TLS bypass in dependency installation.

Slopsquatting — the term coined for the attack where an LLM hallucinates a
package name that does not exist on PyPI, and an attacker pre-registers that
name as a malicious package. This guard detects the enabling conditions:

1. **MLSC-016 — pip --trusted-host TLS bypass** (HIGH):
   ``--trusted-host`` disables TLS certificate validation for a pip host,
   enabling man-in-the-middle substitution of packages with malicious ones.

2. **MLSC-022 — Non-HTTPS pip index** (HIGH):
   ``--index-url`` / ``--extra-index-url`` pointing at a plain ``http://``
   URL exposes every install to MitM package substitution on the wire.
   Loopback hosts (localhost / 127.0.0.1) are exempt — no network path.

3. **MLSC-021 — Cross-ecosystem pip install of npm-only packages** (CRITICAL):
   LLMs frequently suggest ``pip install react``, ``pip install webpack``, etc.
   These names belong to npm's ecosystem; installing them via pip is a
   slopsquatting indicator. The install *target* is tokenised (not substring
   matched), so ``pip install django-react-templatetags`` does NOT fire, and
   the npm-only set excludes names that are also legitimate PyPI packages
   (babel, sass, moment, …).

4. **SQ-085 — npm / yarn non-HTTPS registry** (HIGH):
   An ``.npmrc`` ``registry=http://`` or ``package.json`` ``"registry":
   "http://..."`` exposes npm installs to MitM substitution. Loopback exempt.

Standards: transport rules (1/2/4) are TLS failures → OWASP:A02 + A06 + LLM03;
the cross-ecosystem rule (3) is supply-chain → OWASP:A06 + LLM03.

**Suppress:** ``# security: allow-slopsquatting`` anywhere in the file.
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
    iter_files_named,
    pragma_present,
    read,
    rel,
    strip_hash_comments,
)

_PRAGMA = "security: allow-slopsquatting"

# Standards.
_STD_TRANSPORT = ["OWASP:A02", "OWASP:A06", "OWASP-LLM:LLM03"]  # TLS bypass (rules 1/2/4)
_STD_SLOP = ["OWASP:A06", "OWASP-LLM:LLM03"]                    # cross-ecosystem (rule 3)

# A line is a comment if it (after stripping) starts with # or //
_COMMENT_LINE_RE = re.compile(r"^\s*(?:#|//)")

# Loopback hosts carry no MitM risk (no network path) — exempt http:// to these
# (mirrors pg_ssl_required's loopback carve-out).
_LOOPBACK_HTTP_RE = re.compile(r"https?://(?:localhost|127\.0\.0\.1|\[::1\]|::1)\b", re.IGNORECASE)

# ── Rule 1 — MLSC-016: pip --trusted-host TLS bypass ────────────────────────
# `pip3?` covers the `pip3` spelling that many distros default to.
_TRUSTED_HOST_RE = re.compile(r"pip3?\s+install\b[^\n]*--trusted-host", re.MULTILINE)

# File extensions scanned for Rules 1–3.
_PIP_SCAN_SUFFIXES = (
    ".py", ".sh", ".cfg", ".ini", ".txt",
    ".yml", ".yaml", ".toml",
)

# ── Rule 2 — MLSC-022: Non-HTTPS pip index ──────────────────────────────────
_HTTP_INDEX_RE = re.compile(r"--(?:extra-)?index-url\s+http://", re.MULTILINE)

# ── Rule 3 — MLSC-021: Cross-ecosystem pip install of npm-only packages ──────
# Names that are unambiguously npm-ecosystem AND not legitimate, installable PyPI
# packages. Curated against PyPI: babel (Babel i18n), sass (libsass bindings),
# moment, lodash, prettier, parcel, vite, nuxt, next, tailwindcss, autoprefixer are
# all real PyPI packages and were REMOVED — a CRITICAL false positive on a real
# Python install is worse than missing one npm name.
KNOWN_NPM_ONLY: frozenset[str] = frozenset({
    "react", "react-dom", "vue", "angular", "webpack", "webpack-cli", "typescript",
    "express", "axios", "jquery", "babel-core", "eslint", "postcss", "rollup",
    "svelte", "node-sass",
})

# pip flags that consume the following whitespace-separated token as their argument.
_FLAGS_WITH_ARG = frozenset({
    "-r", "-c", "-e", "--editable", "--index-url", "--extra-index-url",
    "--trusted-host", "--cert", "--client-cert", "--find-links", "--proxy",
    "--root", "--prefix", "--target", "--cache-dir",
})

# Split a package token off its version specifier / extras.
_PKG_NAME_SPLIT = re.compile(r"[<>=!~;\[ ]")

# The `pip install` command token for Rule 3 (`pip3?` covers the pip3 spelling).
_PIP_INSTALL_CMD = re.compile(r"\bpip3?\s+install\b")


def _pip_install_targets(line: str) -> list[str]:
    """Return the bare install-target package names on a `pip install` line.

    Tokenises the arguments after `pip install`: flags (and their separate args)
    are skipped, an inline `# comment` tail is dropped, and version specifiers /
    extras are stripped. So `pip install django-react-templatetags` yields
    `['django-react-templatetags']` (NOT `react`), and `pip install -r
    react-reqs.txt` yields `[]`.
    """
    m = _PIP_INSTALL_CMD.search(line)
    if m is None:
        return []
    rest = line[m.end():]
    rest = strip_hash_comments(rest)  # drop an inline comment tail
    targets: list[str] = []
    skip_next = False
    for tok in rest.split():
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-"):
            base = tok.split("=", 1)[0]
            if base in _FLAGS_WITH_ARG and "=" not in tok:
                skip_next = True
            continue
        name = _PKG_NAME_SPLIT.split(tok, 1)[0].strip()
        if name:
            targets.append(name)
    return targets


# ── Rule 4 — SQ-085: npm / yarn non-HTTPS registry ──────────────────────────
_NPM_NPMRC_HTTP_RE = re.compile(r"registry\s*=\s*http://", re.MULTILINE)
_NPM_PKGJSON_HTTP_RE = re.compile(r'"registry"\s*:\s*"http://', re.MULTILINE)


def _line_at(text: str, pos: int) -> str:
    """Return the full line containing offset `pos`."""
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    return text[line_start:line_end if line_end != -1 else len(text)]


class SlopsquattingGuard(Guard):
    id = "slopsquatting"
    title = "Package name confusion or TLS bypass in dependency installation"
    area = "Dependencies"

    # slop_install.sh: pip install react requests -> fires slopsquatting/cross-ecosystem-pip-install.
    # react is an npm-only package; pip install of it is a slopsquatting indicator.
    # Must NOT contain: security: allow-slopsquatting pragma.
    canary_plant = CanaryPlant(
        files={
            "slop_install.sh": (
                "#!/bin/bash\n"
                "# AI-suggested install script\n"
                "pip install react requests flask\n"
            ),
        },
        expects=frozenset({"slopsquatting/cross-ecosystem-pip-install"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features or "frontend" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []

        # --- Rules 1–3: pip-related files ------------------------------------
        pip_files = [
            f for f in iter_files(root, _PIP_SCAN_SUFFIXES)
            if not is_nonproduct_path(rel(root, f), profile.archive_segments)
        ]
        docker_and_make = [
            f for f in iter_files_named(root, "Dockerfile", "Dockerfile.*", "Makefile")
            if not is_nonproduct_path(rel(root, f), profile.archive_segments)
        ]
        all_pip_targets = list(dict.fromkeys(pip_files + docker_and_make))

        for f in all_pip_targets:
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            rel_path = rel(root, f)

            # Rule 1: --trusted-host
            for m in _TRUSTED_HOST_RE.finditer(text):
                line = _line_at(text, m.start())
                if _COMMENT_LINE_RE.match(line):
                    continue
                lineno = text[:m.start()].count("\n") + 1
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="pip --trusted-host disables TLS certificate validation",
                    location=f"{rel_path}:{lineno}",
                    message=(
                        "--trusted-host disables TLS certificate validation for pip, "
                        "enabling man-in-the-middle package substitution attacks."
                    ),
                    remediation=(
                        "Remove --trusted-host. If behind a corporate proxy, configure "
                        "the CA bundle: pip install --cert /path/to/ca-bundle.crt"
                    ),
                    rule="slopsquatting/pip-trusted-host-tls-bypass",
                    standards=list(_STD_TRANSPORT),
                ))
                break  # one finding per file

            # Rule 2: HTTP pip index (skip comments + loopback)
            for m2 in _HTTP_INDEX_RE.finditer(text):
                line = _line_at(text, m2.start())
                if _COMMENT_LINE_RE.match(line) or _LOOPBACK_HTTP_RE.search(line):
                    continue
                lineno = text[:m2.start()].count("\n") + 1
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="pip index configured over HTTP (MitM risk)",
                    location=f"{rel_path}:{lineno}",
                    message=(
                        "pip is configured to fetch packages from a non-HTTPS index, "
                        "exposing installs to MitM substitution."
                    ),
                    remediation="Use HTTPS for all package indexes: --extra-index-url https://...",
                    rule="slopsquatting/pip-http-index",
                    standards=list(_STD_TRANSPORT),
                ))
                break  # one finding per file

            # Rule 3: cross-ecosystem pip install of an npm-only package (tokenised)
            for i, line in enumerate(text.splitlines()):
                if not _PIP_INSTALL_CMD.search(line) or _COMMENT_LINE_RE.match(line):
                    continue
                hit = next((t for t in _pip_install_targets(line) if t in KNOWN_NPM_ONLY), None)
                if hit is None:
                    continue
                out.append(Finding(
                    check_id=self.id,
                    severity="critical",
                    title=f"pip install of npm-only package '{hit}' (slopsquatting indicator)",
                    location=f"{rel_path}:{i + 1}",
                    message=(
                        f"'{hit}' is a JavaScript/npm package, not a Python package. "
                        "pip install of npm package names is a slopsquatting indicator "
                        "— an LLM hallucinated this package name, and an attacker may "
                        "have registered it as a malicious package on PyPI."
                    ),
                    remediation=(
                        f"Remove '{hit}' from pip install. "
                        "For JavaScript dependencies, use npm/yarn."
                    ),
                    rule="slopsquatting/cross-ecosystem-pip-install",
                    standards=list(_STD_SLOP),
                ))
                break  # one finding per file

        # --- Rule 4: npm / yarn non-HTTPS registry ---------------------------
        for f in iter_files_named(root, ".npmrc"):
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            for m4 in _NPM_NPMRC_HTTP_RE.finditer(text):
                line = _line_at(text, m4.start())
                if _COMMENT_LINE_RE.match(line) or _LOOPBACK_HTTP_RE.search(line):
                    continue
                lineno = text[:m4.start()].count("\n") + 1
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="npm registry configured over HTTP (MitM risk)",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "npm is configured to fetch packages from a non-HTTPS registry, "
                        "exposing installs to MitM substitution."
                    ),
                    remediation="Use HTTPS for the npm registry: registry=https://...",
                    rule="slopsquatting/npm-http-registry",
                    standards=list(_STD_TRANSPORT),
                ))
                break

        for f in iter_files_named(root, "package.json"):
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            for m5 in _NPM_PKGJSON_HTTP_RE.finditer(text):
                line = _line_at(text, m5.start())
                if _LOOPBACK_HTTP_RE.search(line):
                    continue
                lineno = text[:m5.start()].count("\n") + 1
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="npm registry configured over HTTP in package.json (MitM risk)",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "package.json specifies a non-HTTPS npm registry, "
                        "exposing installs to MitM substitution."
                    ),
                    remediation='Use HTTPS for the npm registry: "registry": "https://..."',
                    rule="slopsquatting/npm-http-registry",
                    standards=list(_STD_TRANSPORT),
                ))
                break

        return out
