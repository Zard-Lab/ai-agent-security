"""Guard: hostname/URL allowlist regex is unsafe — unescaped dot or missing end anchor
(checklist §3a, new item, CWE-020).

A hand-written regular expression used to validate that a URL or hostname belongs to a
trusted domain is a common SSRF/open-redirect defence, and a common place for a subtle
bypass to hide:

  const ALLOWED = /^https:\\/\\/trusted\\.com/;
  if (ALLOWED.test(new URL(target).hostname)) fetch(target);

Two independent mistakes both defeat this defence, sourced from GitHub CodeQL's
`js/incomplete-hostname-regexp` and `js/regex/missing-regexp-anchor`
(`javascript/ql/src/Security/CWE-020/IncompleteHostnameRegExp.ql` +
`MissingRegExpAnchor.ql`, verified against real fetched source — both share the same
`HostnameRegexp` library, so this guard treats them as one threat, not two):

  **`unescaped-dot`** (HIGH): a bare `.` immediately before a common TLD-like suffix
  (`.com`, `.org`, `.net`, `.io`, `.dev`, `.app`, `.co`, `.gov`, `.edu`) inside the
  pattern. `.` in a regex matches ANY character, so `trusted.com` also matches
  `trustedXcom` — and combined with the next mistake, `trusted-com.evil.com`.

  **`missing-end-anchor`** (HIGH): the pattern has no trailing `$` (or `$/` before the
  closing delimiter). Without it, `^https://trusted\\.com` matches the PREFIX of
  `https://trusted.com.evil.com/steal` — the attacker's domain, not the trusted one.

Both rules are scoped to a regex literal used in a hostname/URL-checking context —
assigned to a variable whose name suggests one (`host`/`hostname`/`origin`/`domain`/
`trusted`/`allowed`), or passed to `.test(...)` with an argument that mentions one
(`hostname`/`.host`/`origin`/`url`) — so an unrelated regex elsewhere in the file
(a form-validation pattern, a slug matcher) is not swept in.

**Scope:** JS/TS regex LITERALS only (`/pattern/flags`), not `new RegExp("...")` built
from a string — the literal form is overwhelmingly the common case for a static
allowlist pattern, and a dynamically-built pattern needs string-concatenation tracking
this guard does not attempt.

Suppress an audited case (e.g. a pattern deliberately permissive by design, reviewed and
accepted) with `// security: allow-hostname-regex-unsafe` on the line.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    is_nonproduct_path,
    iter_files,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA_TEXT = "security: allow-hostname-regex-unsafe"

# A JS regex literal: /pattern/flags — pattern excludes a bare unescaped `/` or newline.
# Captures (pattern, flags). Simple by design: does not handle a `/` inside a character
# class (e.g. `/[a/b]/`), a known, accepted limitation shared with other JS-literal guards.
_REGEX_LITERAL = re.compile(r"/((?:[^/\\\n]|\\.)+)/([a-z]*)")

# The variable-name side of the context gate: an assignment target that names a
# hostname/URL-allowlist concept.
_HOSTNAME_VAR_NAME = re.compile(
    r"\b(?:const|let|var)\s+\w*(?:host|origin|domain|trusted|allowed)\w*\s*=\s*$", re.IGNORECASE
)
# The call-site side of the context gate: a `.test(` argument that mentions a
# hostname/URL concept. Each bare-word alternative (`hostname`/`origin`/`url`) is boundaried on
# BOTH sides (`\b...\b`), not just the trailing side: an unanchored leading edge let the bare
# substring "url" match inside an unrelated camelCase identifier like `reportUrl` (an asset
# filename check has no hostname/URL parsing involved at all, but "reportUrl" contains "Url" as
# its tail) — `\breportUrl\b` still doesn't split at the "t"/"U" boundary (both are word chars to
# regex `\b`, case doesn't matter), so this genuinely requires "url"/"origin"/"hostname" to be the
# WHOLE identifier a `.test()` argument reduces to, or a `.`-prefixed property access, not merely a
# substring of a longer name. `\.host\b` (property access, e.g. `req.host`) already had a natural
# leading boundary from the literal dot and is unchanged.
_HOSTNAME_TEST_CALL = re.compile(
    r"\.test\s*\([^)]*(?:\bhostname\b|\.host\b|\borigin\b|\burl\b)", re.IGNORECASE
)

_TLD_SUFFIX = r"(?:com|org|net|io|dev|app|co|gov|edu)\b"
# An unescaped `.` (not preceded by a backslash) directly before a TLD-like suffix.
_UNESCAPED_DOT_BEFORE_TLD = re.compile(r"(?<!\\)\." + _TLD_SUFFIX)

_STANDARDS = ["CWE-020"]


class HostnameRegexUnsafeGuard(Guard):
    id = "hostname-regex-unsafe"
    title = "Hostname/URL allowlist regex is unsafe (unescaped dot or missing end anchor)"
    area = "Network requests"

    # express_hostname_check.js: an unescaped dot + no end anchor in a hostname allowlist
    # regex -> fires hostname-regex-unsafe/unescaped-dot and
    # hostname-regex-unsafe/missing-end-anchor.
    canary_plant = CanaryPlant(
        files={
            "express_hostname_check.js": (
                "const TRUSTED_HOST = /^https:\\/\\/trusted.com/;\n"
                "\n"
                "function isTrusted(target) {\n"
                "  return TRUSTED_HOST.test(new URL(target).hostname);\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "hostname-regex-unsafe/unescaped-dot",
            "hostname-regex-unsafe/missing-end-anchor",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return (
            "javascript" in profile.features
            or "express" in profile.features
            or "typescript" in profile.features
        )

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            raw = read(f)
            code = strip_js_comments(raw)
            out.extend(self._scan_file(root, f, code, raw))
        return out

    def _scan_file(self, root: Path, f: Path, code: str, raw: str) -> list[Finding]:
        out: list[Finding] = []
        view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
        for m in _REGEX_LITERAL.finditer(code):
            pattern = m.group(1)
            line_start = code.count("\n", 0, m.start())
            lineno = line_start + 1
            # Context gate: a hostname-ish variable name on this line before the literal,
            # or a hostname-ish `.test(` call within 80 chars after the literal.
            before = code[max(0, m.start() - 80) : m.start()]
            after = code[m.end() : m.end() + 80]
            if not (_HOSTNAME_VAR_NAME.search(before) or _HOSTNAME_TEST_CALL.search(after)):
                continue
            line_text = view_lines[line_start] if line_start < len(view_lines) else ""
            if _PRAGMA_TEXT in line_text:
                continue
            if _UNESCAPED_DOT_BEFORE_TLD.search(pattern):
                out.append(self._finding(
                    root, f, lineno,
                    rule="hostname-regex-unsafe/unescaped-dot",
                    message=(
                        "This hostname/URL-allowlist regex has an unescaped `.` directly "
                        "before a domain suffix. `.` matches ANY character in a regex, so "
                        "the pattern also matches a lookalike domain (`trustedXcom`), and "
                        "combined with a missing end anchor, an attacker-controlled "
                        "subdomain (`trusted.com.evil.com`)."
                    ),
                    remediation=(
                        "Escape the dot: `\\.com` instead of `.com`. Prefer parsing the URL "
                        "(`new URL(value).hostname`) and comparing against an exact allowlist "
                        "over a hand-written regex. Suppress a reviewed case with "
                        "`// security: allow-hostname-regex-unsafe`."
                    ),
                ))
            if not re.search(r"\$/?$", pattern):
                out.append(self._finding(
                    root, f, lineno,
                    rule="hostname-regex-unsafe/missing-end-anchor",
                    message=(
                        "This hostname/URL-allowlist regex has no trailing `$` anchor. "
                        "Without it, the pattern matches a PREFIX of the tested value, so "
                        "`https://trusted.com.evil.com/...` still matches a pattern meant to "
                        "require the string end at `trusted.com`."
                    ),
                    remediation=(
                        "Add a trailing `$` to the pattern so it must match to the end of "
                        "the string, not just a prefix. Suppress a reviewed case with "
                        "`// security: allow-hostname-regex-unsafe`."
                    ),
                ))
        return out

    def _finding(
        self, root: Path, f: Path, lineno: int, *, rule: str, message: str, remediation: str
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=message,
            remediation=remediation,
            rule=rule,
            standards=list(_STANDARDS),
        )
