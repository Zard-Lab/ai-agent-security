"""Guard: `extract()` called directly on a request superglobal — arbitrary variable overwrite
(checklist §3b).

agentsec's second PHP-language guard. Pattern verified against graudit's real signature
dictionary (`wireghoul/graudit`, `signatures/php.db`, the `extract(` entry) — cited for provenance;
detection logic and test fixtures here are original, developed independently against the pattern
description, not copied from graudit's own (POSIX ERE) implementation.

Fires HIGH on `extract($_GET)`, `extract($_POST)`, `extract($_REQUEST)`, or `extract($_COOKIE)` —
PHP's `extract()` imports every key of the given array into the current symbol table as a variable.
Called directly on unfiltered user input, this lets an attacker define or overwrite ARBITRARY local
variables by choosing the request's parameter names (e.g. `?is_admin=1` silently creates
`$is_admin = "1"` in the calling scope). This is the modern-day resurgence of the notorious
`register_globals` vulnerability class: `register_globals` was a PHP misconfiguration (auto-creating
globals from request data) removed by default in PHP 4.2 and the directive itself removed in
PHP 5.4 — `extract()` on a superglobal recreates the exact same risk deliberately, in application
code, on any PHP version.

Deliberately scoped to `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE` only — NOT `$_ENV`/`$_SERVER`, which
are not attacker-controlled in the same direct, per-request way (documented as a scoping choice, not
an oversight). `extract($someLocalArray)` where the array is visibly built from safe, hardcoded data
is not distinguishable from an unsafe alias by text alone, so it is intentionally not flagged — see
the wiki doc for the full honesty statement on this guard's limits.

Suppress an audited case (e.g. the array is filtered/allowlisted before the `extract()` call, or the
superglobal keys are provably attacker-unreachable in this deployment) with:

    extract($_GET); // security: allow-extract-superglobal-overwrite
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, php_scan_dirs, read, rel, strip_php_comments

_STANDARDS = ["CWE-473", "OWASP:A08"]

# extract($_GET) / extract($_POST) / extract($_REQUEST) / extract($_COOKIE) — a direct call with one
# of the four request superglobals as the (first) argument. Allows leading whitespace/newlines
# between `extract(` and the superglobal, and an optional trailing comma/second EXTR_* flag arg
# (the flags argument doesn't change that the superglobal's keys still drive variable creation).
_EXTRACT_SUPERGLOBAL = re.compile(
    r"""extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\b"""
)
_PRAGMA = "security: allow-extract-superglobal-overwrite"


class PhpExtractSuperglobalOverwriteGuard(Guard):
    id = "php-extract-superglobal-overwrite"
    title = "extract() called directly on a request superglobal"
    area = "Code safety"

    # ExtractOverwrite.php: extract($_GET) ->
    # php-extract-superglobal-overwrite/direct-superglobal-extract.
    canary_plant = CanaryPlant(
        files={
            "ExtractOverwrite.php": (
                "<?php\n"
                "function importRequest() {\n"
                "    extract($_GET);\n"
                "    return $is_admin ?? false;\n"
                "}\n"
            ),
        },
        expects=frozenset({"php-extract-superglobal-overwrite/direct-superglobal-extract"}),
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
            if _EXTRACT_SUPERGLOBAL.search(line):
                out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "extract() imports every key of the given array into the current symbol table "
                "as a variable. Calling it directly on a request superglobal lets an attacker "
                "define or overwrite arbitrary local variables by choosing the request's "
                "parameter names (CWE-473) — the same risk class as the deprecated "
                "register_globals setting, recreated deliberately in application code."
            ),
            remediation=(
                "Never extract() a request superglobal directly. Read only the specific keys "
                "you expect (e.g. $_GET['id']), or filter/allowlist the array before extracting "
                "it, or pass EXTR_SKIP with a controlled prefix. If this call is genuinely "
                "audited and the keys are provably attacker-unreachable, suppress with "
                "`// security: allow-extract-superglobal-overwrite`."
            ),
            rule="php-extract-superglobal-overwrite/direct-superglobal-extract",
            standards=list(_STANDARDS),
        )
