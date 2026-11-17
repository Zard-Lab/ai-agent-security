"""Guard: no SSRF from a tainted `java.net.URL` fetch (checklist §3a).

Server-Side Request Forgery on the Java side: `new URL(userInput).openConnection()` (or
`.openStream()`/`.getContent()`) lets an attacker point the server's own outbound HTTP fetch at
internal services or the cloud metadata endpoint (`http://169.254.169.254/`), turning the backend
into a proxy for reaching things the attacker can't reach directly. CWE-918, OWASP:A10.

This is the Java counterpart to the existing Python `ssrf-general` guard (its `applies()` gates on
`"python" in profile.features` — zero Java SSRF detection existed in agentsec before this guard),
extending the same `3a-ssrf-general` checklist item rather than duplicating it.

Pattern verified against Find Security Bugs' real source (rule `URLCONNECTION_SSRF_FD`, sink list
`injection-sinks/urlconnection-ssrf.txt`) — the rule id is cited for provenance; detection logic
and test fixtures here are original, developed independently against the pattern description, not
copied or derived from that (Java) source.

The classic Java SSRF idiom is a `java.net.URL` object built from a tainted string, then opened:

  * `new URL(userInput).openConnection()` / `.openStream()` / `.getContent()` — chained on one
    statement;
  * `URL url = new URL(userInput); ... url.openConnection();` — built once, opened a few lines
    later (a small forward line-window, not full dataflow — see "Known bypasses").

Fires HIGH only when the `new URL(...)` argument is NOT a pure string literal (or a concatenation
of only string literals) — a bare identifier, a method call (`request.getParameter("url")`), or a
literal `+` a variable are all "tainted" for this guard's purposes; this is conservative-by-design
scope, not a dataflow proof (see "Known bypasses" in `wiki/guards/java-ssrf.md`). Suppress an
audited case with:

    new URL(target).openConnection(); // security: allow-java-ssrf
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
    java_scan_dirs,
    read,
    rel,
    strip_java_comments,
)

# How many lines forward of a `Type var = new URL(...);` assignment to look for
# `var.openConnection()`/`.openStream()`/`.getContent()` — a small proximity window, not
# real dataflow (the guard cannot tell if the variable is reassigned or the call is on a
# different branch in between; see the module docstring's "Known bypasses").
_WINDOW = 6

# `new URL(<arg>).openConnection()|.openStream()|.getContent()` chained on one statement.
# The capture group tolerates one level of nested parens in the argument (e.g. a method call).
_NEW_URL_CHAINED = re.compile(
    r"\bnew\s+URL\s*\(\s*([^()]*(?:\([^()]*\)[^()]*)*)\)\s*\.\s*"
    r"(?:openConnection|openStream|getContent)\s*\("
)
# `[<Type> ]<var> = new URL(<arg>);` — the two-statement shape. The optional `(?:\w+\s+)?`
# covers a type name (`URL`, `var`, `final`... one token) or a bare reassignment (`url = ...`).
_VAR_ASSIGN_NEW_URL = re.compile(
    r"\b(?:final\s+)?(?:\w+\s+)?([A-Za-z_]\w*)\s*=\s*new\s+URL\s*"
    r"\(\s*([^()]*(?:\([^()]*\)[^()]*)*)\)\s*;"
)
_STRING_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"')
_PRAGMA = "security: allow-java-ssrf"


def _sink_on_var(line: str, var: str) -> bool:
    return bool(re.search(rf"\b{re.escape(var)}\s*\.\s*(?:openConnection|openStream|getContent)\s*\(", line))


def _is_literal_arg(arg: str) -> bool:
    """True if the `new URL(...)` argument is a string literal, or a `+`-concatenation of only
    string literals — nothing left over once literals and `+`/whitespace are stripped means no
    variable or method call fed into it."""
    text = arg.strip()
    if not text:
        return True
    remainder = _STRING_LITERAL.sub("", text)
    remainder = re.sub(r"[\s+]", "", remainder)
    return remainder == ""


class JavaSsrfGuard(Guard):
    id = "java-ssrf"
    title = "Server-side fetch from a tainted java.net.URL (SSRF)"
    area = "Network requests"

    # UrlFetcher.java: new URL(target).openConnection() on a non-literal argument, chained on
    # one statement -> fires java-ssrf/tainted-url-open-connection.
    canary_plant = CanaryPlant(
        files={
            "UrlFetcher.java": (
                "import java.net.URL;\n\n"
                "class UrlFetcher {\n"
                "    void fetch(String target) throws Exception {\n"
                "        new URL(target).openConnection();\n"
                "    }\n"
                "}\n"
            ),
        },
        expects=frozenset({"java-ssrf/tainted-url-open-connection"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "java" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in java_scan_dirs(root, profile):
            for f in iter_files(d, (".java",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # The pragma check runs on the COMMENT-ONLY view of the line — it IS the comment
        # `strip_java_comments` below would blank, and a string quoting it must not count (#424).
        view_lines = comment_view(text, "java").splitlines()  # same length: comments only (#424)
        # `strip_java_comments` preserves length and splitlines() count exactly (tested), so the
        # two line lists always pair up — `strict=True` documents that invariant.
        code_lines = strip_java_comments(text).splitlines()
        n = len(code_lines)
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True)):
            if _PRAGMA in view:
                continue

            m = _NEW_URL_CHAINED.search(line)
            if m and not _is_literal_arg(m.group(1)):
                out.append(self._finding(root, f, i + 1))
                continue

            m2 = _VAR_ASSIGN_NEW_URL.search(line)
            if not m2 or _is_literal_arg(m2.group(2)):
                continue
            var = m2.group(1)
            for j in range(i, min(i + _WINDOW, n)):
                if _PRAGMA in view_lines[j]:
                    break  # suppressed anywhere in the proximity window
                if _sink_on_var(code_lines[j], var):
                    out.append(self._finding(root, f, i + 1))
                    break
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "This `java.net.URL` is constructed from a non-literal argument and then opened "
                "(`.openConnection()`/`.openStream()`/`.getContent()`) with no allow-list — an "
                "attacker can point it at internal services or the cloud metadata endpoint "
                "(169.254.169.254) and exfiltrate credentials."
            ),
            remediation=(
                "Validate the URL against an allow-list of permitted hosts/schemes before opening "
                "it, and block RFC-1918 / link-local / metadata IPs (resolve the host, then "
                "check). Suppress an audited internal fetch with `// security: allow-java-ssrf`."
            ),
            rule="java-ssrf/tainted-url-open-connection",
            standards=["OWASP:A10"],
        )
