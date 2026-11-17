r"""Guard: a JS/TS SSRF guard classifies a hostname without normalizing the brackets WHATWG
keeps on an IPv6 literal, so the private-address check never runs (checklist §3a, new item;
agent-audit-kit's `ssrf_bracketed_host.py` AAK-SSRF-BRACKETED-HOST-001).

CVE-2026-80347 (mcp-fetch): the guard is present. That is the whole problem, and it is why
neither a "no allow-list at all" check nor a "follows a redirect" check can see it::

    const host = new URL(raw).hostname;   // "[::1]" -- brackets kept
    if (net.isIP(host)) {                 // returns 0 for a bracketed literal
      if (host === "::1") return false;   // never reached
      return true;
    }
    return true;                          // falls through to allow

``URL.hostname`` in WHATWG (Node, browsers) keeps the brackets on an IPv6 literal.
``net.isIP`` does not accept them, so it returns 0, the entire private-address branch is
skipped, and the guard's own default-allow tail runs. A caller asking for ``http://[::1]/``
reaches loopback through a guard written specifically to stop that.

**JS/TS only, deliberately.** Python's ``urlsplit().hostname`` strips the brackets before
the caller ever sees them, so the same code shape in Python is not vulnerable — this is a
WHATWG-URL semantic, not a universal one, and flagging Python would be inventing a finding.

Fires HIGH when, in one file: a hostname is read off a parsed URL (`new URL(...).hostname`,
or a `.hostname` access on a `parsed`/`url`/`u`/`target`/`dest`-named variable), an
IP-classification call is applied to it (`net.isIP(`, `isIPv6(`, `ipaddress.ip_address(`),
an outbound fetch call exists in the same file (`fetch(`, `axios.`, `got(`, `request(`,
`https?.get(`), the surrounding code reads like an SSRF/allow-list guard (`isSafe`,
`isAllowed`, `validateUrl`, `ssrf`, `blocklist`/`allowlist`, `private-address`), and NO
bracket-stripping normalization (`.replace(/^\[|\]$/g, "")`, `.slice(1, -1)`,
`stripBrackets`, ...) appears anywhere in the file, and the function around the
classification call does not end default-DENY: when its last `return` is a lookup or a
comparison (`return isAllowedDomain(host);`), `[::1]` reaches that check and is refused, so
nothing "falls through to allow". A literal `true` tail (or `false` from an `isBlocked`-style
predicate), and a tail the scan cannot locate (an arrow expression body, top-level code), are
still reported.

Suppress an audited case with:

    // security: allow-ssrf-bracketed-ipv6-bypass
"""
from __future__ import annotations

import itertools
import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_PRAGMA = "security: allow-ssrf-bracketed-ipv6-bypass"

_JS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")

_TS_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT = re.compile(r"//[^\n]*")
_NOT_NEWLINE = re.compile(r"[^\n]")

_URL_HOSTNAME_RE = re.compile(
    r"new\s+URL\s*\([^)]{0,200}\)\s*\.\s*hostname"
    r"|\b(?:parsed|url|u|target|dest)\w*\s*\.\s*hostname\b"
    r"|\.\s*hostname\s*(?:;|,|\)|$)",
    re.MULTILINE,
)
_IP_CLASSIFY_RE = re.compile(
    r"\bnet\s*\.\s*isIP\s*\("
    r"|\bisIPv?6?\s*\("
    r"|\bipaddress\s*\.\s*ip_address\s*\(",
)
_BRACKET_STRIP_RE = re.compile(
    r"replace\s*\(\s*/\^?\\?\[.{0,40}?/[gimsuy]*\s*,"
    r"|replaceAll\s*\(\s*['\"]\[['\"]"
    r"|\.replace\s*\(\s*['\"]\[['\"]"
    r"|slice\s*\(\s*1\s*,\s*-\s*1\s*\)"
    r"|startsWith\s*\(\s*['\"]\[['\"]"
    r"|strip\s*\(\s*['\"]\[\]['\"]\s*\)"
    r"|\bunbracket\w*\s*\("
    r"|\bstripBrackets\b",
)
_FETCH_RE = re.compile(
    r"\bfetch\s*\(|\baxios\s*\.|\bgot\s*\(|\brequest\s*\(|https?\s*\.\s*get\s*\(",
)
_GUARD_RE = re.compile(
    r"\bis\w*Safe\w*\s*\(|\bisAllowed\w*\s*\(|\bvalidate\w*Url\w*\s*\("
    r"|\bssrf\b|\bblock(?:ed|list)\b|\ballow(?:ed)?list\b|\bguard\b|private[-_ ]?address",
    re.IGNORECASE,
)

_STANDARDS = ["OWASP-ASI:ASI06", "CWE-918"]


def _blank(m: re.Match[str]) -> str:
    """Same-length replacement that keeps newlines, so offsets and line numbers survive."""
    return _NOT_NEWLINE.sub(" ", m.group(0))


def _strip_comments(text: str) -> str:
    return _TS_LINE_COMMENT.sub(_blank, _TS_BLOCK_COMMENT.sub(_blank, text))


# --- default-allow tail detection (the "falls through to allow" claim) ------------------------
# A guard whose last statement is `return isAllowedDomain(host);` is default-DENY: bracketed
# `[::1]` reaches the allow-list lookup and is refused. Only a literal-allow tail is the CVE shape.
_BLOCK_KEYWORDS = frozenset({"if", "for", "while", "switch", "catch", "with"})
_RETURN_TYPE_RE = re.compile(r"\)\s*:\s*[\w<>\[\]|,.? ]+$")
_LAST_RETURN_RE = re.compile(r"\breturn\b([^;\n}]*)")
_ALLOW_EXPR_RE = re.compile(r"^(?:true|!0|!!1|\{\s*(?:ok|allowed|safe)\s*:\s*true\b.*)$", re.DOTALL)
_BLOCKING_PREDICATE_RE = re.compile(r"block|den(?:y|ied)|private|internal|reserved|unsafe|forbid", re.IGNORECASE)
_MAX_CLASSIFY_SITES = 10


def _is_function_header(header: str) -> bool:
    h = header.rstrip()
    if h.endswith("=>"):
        return True
    if not h.endswith(")"):
        m = _RETURN_TYPE_RE.search(h)
        if m is None:
            return False
        h = h[: m.start() + 1]
    depth = 0
    for i in range(len(h) - 1, -1, -1):
        if h[i] == ")":
            depth += 1
        elif h[i] == "(":
            depth -= 1
            if depth == 0:
                kw = re.search(r"(\w+)\s*$", h[:i])
                return kw is None or kw.group(1) not in _BLOCK_KEYWORDS
    return False


def _enclosing_function(text: str, pos: int) -> tuple[int, int] | None:
    """`(open, close)` offsets of the braces of the function containing `pos`, or None."""
    depth = 0
    for i in range(pos - 1, -1, -1):
        c = text[i]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth:
                depth -= 1
                continue
            if _is_function_header(text[max(0, i - 300): i]):
                d = 0
                for j in range(i, len(text)):
                    if text[j] == "{":
                        d += 1
                    elif text[j] == "}":
                        d -= 1
                        if d == 0:
                            return i, j
                return None
    return None


def _tail_verdict(text: str, pos: int) -> str:
    """`"allow"` if the function around `pos` ends by unconditionally allowing, `"deny"` if its
    last `return` is anything else (a lookup, a comparison, a literal `false`), `"unknown"` if the
    function or a `return` cannot be located (treated as allow, the pre-existing behaviour)."""
    span = _enclosing_function(text, pos)
    if span is None:
        return "unknown"
    open_idx, close_idx = span
    body = text[open_idx + 1: close_idx]
    returns = list(_LAST_RETURN_RE.finditer(body))
    if not returns:
        return "unknown"
    expr = returns[-1].group(1).strip()
    if _ALLOW_EXPR_RE.match(expr):
        return "allow"
    if expr == "false" and _BLOCKING_PREDICATE_RE.search(text[max(0, open_idx - 300): open_idx]):
        return "allow"  # `isBlocked(host)` returning false means "not blocked"
    return "deny"


class SsrfBracketedIpv6BypassGuard(Guard):
    id = "ssrf-bracketed-ipv6-bypass"
    title = "SSRF guard classifies a bracketed IPv6 hostname and never normalizes it"
    area = "Network requests"

    # url_guard.ts: reads .hostname, checks net.isIP with no bracket-strip, then fetches
    # -> fires ssrf-bracketed-ipv6-bypass/no-bracket-normalization.
    canary_plant = CanaryPlant(
        files={
            "url_guard.ts": (
                "function isSafeUrl(raw: string): boolean {\n"
                "  const host = new URL(raw).hostname;\n"
                "  if (net.isIP(host)) {\n"
                "    if (host === '::1') return false;\n"
                "    return true;\n"
                "  }\n"
                "  return true;\n"
                "}\n\n"
                "if (isSafeUrl(target)) {\n"
                "  fetch(target);\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "ssrf-bracketed-ipv6-bypass/no-bracket-normalization",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        # JS/TS only (`iter_files(root, _JS_SUFFIXES)` below, and the checklist item's
        # `applies_when`): on a Python- or Go-only repo this is N/A, not "ran clean".
        return bool({"javascript", "typescript"} & profile.features)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _JS_SUFFIXES):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            raw = read(f)
            if not raw or pragma_present(_PRAGMA, raw, dialect="js"):
                continue
            text = _strip_comments(raw)
            if not (
                _URL_HOSTNAME_RE.search(text)
                and _IP_CLASSIFY_RE.search(text)
                and _FETCH_RE.search(text)
                and _GUARD_RE.search(text)
            ):
                continue
            if _BRACKET_STRIP_RE.search(text):
                continue
            # Report the first classification site whose function does NOT end default-deny.
            for m in itertools.islice(_IP_CLASSIFY_RE.finditer(text), _MAX_CLASSIFY_SITES):
                if _tail_verdict(text, m.start()) != "deny":
                    line = text.count("\n", 0, m.start()) + 1
                    out.append(self._finding(r, line))
                    break
        return out

    def _finding(self, r: str, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{r}:{line}",
            message=(
                "SSRF guard reads `.hostname` from a parsed URL and hands it to an "
                "IP-classification call without removing the brackets WHATWG keeps on "
                "an IPv6 literal. `net.isIP('[::1]')` returns 0, so the private-address "
                "branch is skipped and the guard falls through to allow — "
                "`http://[::1]/` reaches loopback through a check written to stop it "
                "(CVE-2026-80347 class)."
            ),
            remediation=(
                "Strip the brackets before classifying (`host.replace(/^\\[|\\]$/g, "
                "'')` or `host.slice(1, -1)` when bracketed), and default to DENY rather "
                "than allow when classification is inconclusive."
            ),
            rule="ssrf-bracketed-ipv6-bypass/no-bracket-normalization",
            standards=list(_STANDARDS),
        )
