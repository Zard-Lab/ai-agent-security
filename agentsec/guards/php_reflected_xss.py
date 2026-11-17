"""Guard: reflected XSS via unescaped superglobal output (`echo`/`print`/`<?=`) (checklist §3b).

agentsec's second PHP-language guard (2/9), built on the PHP stack detection and
`strip_php_comments` helper landed with `php-preg-replace-eval-modifier`.

Pattern verified against graudit's real signature dictionary (`wireghoul/graudit`,
`signatures/php.db`) — its PHP XSS entries key off `echo`/`print`/short-echo-tag output of a
superglobal (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`). graudit's own documentation flags this
pattern as needing extra escaping-context care to avoid false positives, since a very common,
perfectly safe idiom is the same output wrapped in an escaping call
(`echo htmlspecialchars($_GET['name']);`). That caveat directly shaped this guard's design: the
detection logic and the escaping-function exclusion list below are original, developed
independently against the pattern description, not copied from graudit's own implementation.

Fires HIGH on `echo`/`print`/`<?=` directly outputting a bare superglobal reference — e.g.
`echo $_GET['name'];`, `print $_POST['x'];`, `<?= $_REQUEST['y'] ?>` — with no call to
`htmlspecialchars(`, `htmlentities(`, `strip_tags(`, or `filter_var(` anywhere in that same output
statement. When user-controlled request data is echoed straight into an HTML response with no
output encoding, an attacker who controls the query string, POST body, or a cookie can inject
markup/script that executes in the victim's browser — classic reflected XSS (CWE-79, OWASP:A03).

Scope is deliberately same-line/same-statement, textual/regex-only — no dataflow. A superglobal
assigned to a variable and echoed later (`$x = $_GET['y']; /* ... */ echo $x;`), even if that
variable was properly escaped in between, is not traced; that cross-line tracing is a real, honestly
documented limitation, not a guard defect to silently paper over.

Suppress an audited case (e.g. output known to be plain-text, non-HTML context, or escaped by a
framework template layer this guard cannot see) with:

    echo $_GET['name']; // security: allow-php-reflected-xss
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, php_scan_dirs, read, rel, strip_php_comments

_STANDARDS = ["CWE-79", "OWASP:A03"]

# `echo`, `print`, or the short-echo-tag `<?=` opening an output statement. `(?<!\$)` keeps a
# variable literally named `$echo`/`$print` from being mistaken for the keyword (the `\b...\b`
# word-boundary alone would still match inside `$echo` since `$` is a non-word character).
_OUTPUT_OPEN = re.compile(r"(?<!\$)\becho\b|(?<!\$)\bprint\b|<\?=")

# A bare superglobal reference — `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` — optionally followed
# by simple array/key access (`['name']`, `["id"]`, `[0]`); the key form itself is not load-bearing
# for the match, `\$_(?:...)\b` alone already identifies the superglobal.
_SUPERGLOBAL = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\b")

# The four escaping/sanitizing calls that make a superglobal safe to output directly. Matched with
# a following `(` (allowing whitespace) so a same-named local helper wrapping one of these doesn't
# also need special-casing — the real function call always has this shape at the call site.
_ESCAPE_FUNC = re.compile(r"\b(?:htmlspecialchars|htmlentities|strip_tags|filter_var)\s*\(")

_PRAGMA = "security: allow-php-reflected-xss"


class PhpReflectedXssGuard(Guard):
    id = "php-reflected-xss"
    title = "Reflected XSS via unescaped superglobal output (echo/print/short-echo-tag)"
    area = "Code safety"

    # Reflected.php: echo $_GET['name']; -> php-reflected-xss/unescaped-superglobal-echo.
    canary_plant = CanaryPlant(
        files={
            "Reflected.php": (
                "<?php\n"
                "function greet() {\n"
                "    echo $_GET['name'];\n"
                "}\n"
            ),
        },
        expects=frozenset({"php-reflected-xss/unescaped-superglobal-echo"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "php" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in php_scan_dirs(root, profile):
            for f in iter_files(d, (".php",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # The pragma check runs on the COMMENT-ONLY view of the line — it IS the comment
        # `strip_php_comments` below would blank, and a string quoting it must not count (#424).
        view_lines = comment_view(text, "php").splitlines()  # same length: comments only (#424)
        # `strip_php_comments` preserves length and splitlines() count exactly (tested), so the
        # two line lists always pair up — `strict=True` documents that invariant.
        code_lines = strip_php_comments(text).splitlines()
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA in view:
                continue
            if self._flags(line):
                out.append(self._finding(root, f, i))
        return out

    def _flags(self, line: str) -> bool:
        """True if any output statement (`echo`/`print`/`<?=` up to the next `;`, or end of line
        when there isn't one) on this line outputs a bare superglobal with no escaping-function
        call anywhere in that same statement."""
        for m in _OUTPUT_OPEN.finditer(line):
            semi = line.find(";", m.end())
            stmt = line[m.end():] if semi == -1 else line[m.end():semi]
            if _SUPERGLOBAL.search(stmt) and not _ESCAPE_FUNC.search(stmt):
                return True
        return False

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "A superglobal ($_GET/$_POST/$_REQUEST/$_COOKIE) is output via echo/print/<?= "
                "with no htmlspecialchars()/htmlentities()/strip_tags()/filter_var() call "
                "anywhere in the statement — an attacker who controls the request can inject "
                "markup or script that executes in the victim's browser (reflected XSS, CWE-79)."
            ),
            remediation=(
                "Escape the value before output, e.g. "
                "echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8'); . If this output is "
                "genuinely not HTML context (plain text, JSON, etc.) or escaped by a framework "
                "layer this guard can't see, suppress with `// security: allow-php-reflected-xss`."
            ),
            rule="php-reflected-xss/unescaped-superglobal-echo",
            standards=list(_STANDARDS),
        )
