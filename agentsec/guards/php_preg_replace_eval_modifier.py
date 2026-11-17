"""Guard: `preg_replace()` with the deprecated `/e` (eval) modifier — regex-to-RCE (checklist §3b).

agentsec's first PHP-language guard — PHP stack detection (`.php` suffix,
`php_dirs`/`php_scan_dirs`) and `strip_php_comments` landed in this same PR to support it.

Pattern verified against graudit's real signature dictionary (`wireghoul/graudit`,
`signatures/php.db`: `preg_replace[[:space:]]*\\([\\'"](.).*\\1[igsu]*e`) — the regex shape is cited
for provenance; detection logic and test fixtures here are original, developed independently
against the pattern description, not copied from graudit's own (POSIX ERE) implementation.

Fires CRITICAL on `preg_replace($pattern, $replacement, $subject)` where `$pattern` is a string
literal whose regex-delimiter-closed modifier suffix includes the `e` flag — e.g.
`preg_replace('/(.*)/e', $replacement, $subject)` or `preg_replace("/pattern/ie", ...)` (the `e`
flag combined with any other modifier, in any order, still triggers PHP's eval-the-replacement
behavior).

When the `/e` modifier is set, PHP evaluates the REPLACEMENT string as literal PHP code after
performing backreference substitution — so if either the pattern or the replacement argument
incorporates attacker-controlled input, an attacker can inject arbitrary PHP code that gets
`eval()`'d. This was one of the most common real-world PHP RCE vectors before the modifier was
deprecated in PHP 5.5 and removed entirely in PHP 7.0 — legacy PHP 5.x codebases (and code that
still targets them) can carry it. CWE-95 (Eval Injection), OWASP:A03.

Suppress an audited case (e.g. a hardcoded, non-attacker-reachable pattern/replacement pair, or a
deliberate legacy-compat shim already covered by other controls) with:

    preg_replace('/(.*)/e', $replacement, $subject); // security: allow-preg-replace-e-modifier
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, php_scan_dirs, read, rel, strip_php_comments

_STANDARDS = ["CWE-95", "OWASP:A03"]

# preg_replace('DELIM...DELIMflags', ...) where flags (in any order, any position among the other
# modifier letters) include a lowercase 'e'. The quote (' or ") and the regex delimiter (any single
# non-whitespace char immediately after the opening quote — conventionally '/', but PHP allows any
# non-alphanumeric, non-backslash, non-whitespace character) are each captured and backreferenced,
# so a pattern using '#'/'~'/etc. as its delimiter is matched just as correctly as the conventional
# '/'. Modifier letters between the closing delimiter and the closing quote are matched loosely
# ([a-zA-Z]*e[a-zA-Z]*) since PHP does not require a fixed modifier order.
_PREG_REPLACE_E_MODIFIER = re.compile(
    r"""preg_replace\s*\(\s*(?P<q>['"])(?P<d>[^\s'"\\])(?:(?!(?P=d)).)*?(?P=d)[a-zA-Z]*e[a-zA-Z]*(?P=q)"""
)
_PRAGMA = "security: allow-preg-replace-e-modifier"


class PhpPregReplaceEvalModifierGuard(Guard):
    id = "php-preg-replace-eval-modifier"
    title = "preg_replace() with the deprecated /e (eval) modifier"
    area = "Code safety"

    # RegexEval.php: preg_replace('/(.*)/e', $replacement, $subject) ->
    # php-preg-replace-eval-modifier/e-modifier-set.
    canary_plant = CanaryPlant(
        files={
            "RegexEval.php": (
                "<?php\n"
                "function unsafeReplace($replacement, $subject) {\n"
                "    return preg_replace('/(.*)/e', $replacement, $subject);\n"
                "}\n"
            ),
        },
        expects=frozenset({"php-preg-replace-eval-modifier/e-modifier-set"}),
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
            if _PREG_REPLACE_E_MODIFIER.search(line):
                out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "The /e modifier makes preg_replace() evaluate the replacement string as PHP "
                "code after backreference substitution — if the pattern or replacement "
                "incorporates attacker-controlled input, this is arbitrary code execution "
                "(CWE-95). The modifier was deprecated in PHP 5.5 and removed in PHP 7.0."
            ),
            remediation=(
                "Use preg_replace_callback() instead, which passes matches to a real PHP "
                "callback rather than eval()'ing a string. If this call is genuinely unreachable "
                "by attacker input, suppress with `// security: allow-preg-replace-e-modifier`."
            ),
            rule="php-preg-replace-eval-modifier/e-modifier-set",
            standards=list(_STANDARDS),
        )
