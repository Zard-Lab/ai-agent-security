"""Guard: `unserialize()` called on untrusted/dynamic data — PHP Object Injection (checklist §3b).

Sibling of `unsafe_deserialization.py` (the Python/JS "deserialization API called on untrusted
data" guard), ported to PHP's `unserialize()` surface — agentsec's second PHP-language guard
(2/9).

`unserialize($_GET['data'])` (or on `$_POST`/`$_REQUEST`/`$_COOKIE`/any other non-literal
expression) can instantiate arbitrary PHP objects from attacker-controlled bytes. PHP calls the
resulting object's `__wakeup()` magic method immediately, and its `__destruct()` method when it
falls out of scope — if any class reachable via autoloading has a `__wakeup`/`__destruct`/
`__toString` that does something dangerous (writes a file, runs a query, deletes something,
invokes another magic method that chains further), an attacker who controls the serialized bytes
can trigger that behavior without ever calling the method directly. This is the classic "PHP
Object Injection" (POI) class — the mechanism behind real-world gadget-chain RCE in WordPress
plugins, Magento, phpMyAdmin, and many other PHP CMSs/frameworks (CWE-502, OWASP:A08).

Pattern verified against graudit's real signature dictionary (`wireghoul/graudit`,
`signatures/php.db`, the `unserialize(` entry) for provenance only — the taint-shape logic below
(distinguishing a sole string literal from everything else) is original, not copied from graudit's
own implementation.

Fires CRITICAL on `unserialize(...)` where the first argument is NOT a sole string literal:

    unserialize($_GET['data']);            // superglobal — attacker-controlled
    unserialize($_COOKIE['session']);      // superglobal — attacker-controlled
    unserialize($payload);                 // bare variable — provenance unknown to this scanner
    unserialize('prefix' . $suffix);       // string concatenation — dynamic
    unserialize(file_get_contents($path)); // function-call result — dynamic

Stays silent on a sole string literal — the one shape this textual scanner can prove is not
attacker-reachable at the call site itself:

    unserialize('a:1:{i:0;s:3:"foo";}');   // hardcoded literal — silent

Suppress an audited case (e.g. a variable that genuinely never carries attacker input) with:

    unserialize($trustedInternalConfig); // security: allow-php-unsafe-deserialization

Known limitation, same class as every sibling deserialization guard: no dataflow. A bare
`$variable` argument fires regardless of what actually flows into it — this scanner cannot tell
`unserialize($_GET['x'])` (obviously tainted) apart from `unserialize($cachedInternalBlob)` (very
likely trusted) by variable name alone, so it flags both and leaves the call site for a human to
confirm reachability. The pragma above is the intended correction, not a guard limitation to fix
later.
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
    iter_files,
    php_scan_dirs,
    read,
    rel,
    split_call_args,
    strip_php_comments,
)

_STANDARDS = ["CWE-502", "OWASP:A08", "OWASP-LLM:LLM03"]

# `unserialize(` — a leading `\b` keeps a method/function name that merely ENDS in "unserialize"
# (e.g. `my_unserialize(`) from matching, since `_` is a word character and so carries no boundary
# before the final "u". This does NOT exclude an object-method call spelled `->unserialize(` (e.g.
# a class implementing PHP's `Serializable` interface) — `>` is a non-word char, so a boundary
# exists there too. That is a disclosed, accepted over-match: textually a method call and the
# built-in function are indistinguishable, and Serializable::unserialize() implementations
# themselves frequently pass their own $serialized argument to the real built-in internally, so
# treating the call site the same way is not unreasonable — see the guard's wiki doc.
_UNSERIALIZE_CALL = re.compile(r"\bunserialize\s*\(")
# A "sole string literal" argument: the ENTIRE (trimmed) argument text is one quoted literal, with
# nothing before or after it — no concatenation, no trailing expression. `re.DOTALL` lets `.` cross
# a rare embedded newline inside the captured argument text (split_call_args itself is line-
# oriented in this guard's usage, so this is mostly defensive).
_SOLE_STRING_LITERAL = re.compile(
    r"""^[ \t]*(?P<q>['"])(?:\\.|(?!(?P=q)).)*(?P=q)[ \t]*$""", re.DOTALL
)
_PRAGMA = "security: allow-php-unsafe-deserialization"


class PhpUnsafeDeserializationGuard(Guard):
    id = "php-unsafe-deserialization"
    title = "unserialize() called on untrusted or dynamic data — PHP Object Injection"
    area = "Code safety"

    # SessionHandler.php: unserialize($_COOKIE['session']) ->
    # php-unsafe-deserialization/tainted-unserialize.
    canary_plant = CanaryPlant(
        files={
            "SessionHandler.php": (
                "<?php\n"
                "function loadSession() {\n"
                "    return unserialize($_COOKIE['session']);\n"
                "}\n"
            ),
        },
        expects=frozenset({"php-unsafe-deserialization/tainted-unserialize"}),
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
            if self._hit(line):
                out.append(self._finding(root, f, i))
        return out

    def _hit(self, line: str) -> bool:
        for m in _UNSERIALIZE_CALL.finditer(line):
            open_idx = m.end() - 1
            args = split_call_args(line, open_idx)
            if not args:
                # Unbalanced parens on this line (a multi-line call) — not traced, disclosed
                # single-line limitation.
                continue
            first_arg = args[0]
            if not first_arg.strip():
                # unserialize() with no arguments is not valid PHP; nothing to flag.
                continue
            if _SOLE_STRING_LITERAL.match(first_arg):
                continue
            return True
        return False

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "unserialize() on data that is not a hardcoded string literal — a superglobal, "
                "a bare variable, a concatenation, or a function-call result — can instantiate "
                "arbitrary PHP objects from attacker-controlled bytes. PHP invokes the resulting "
                "object's __wakeup()/__destruct() magic methods automatically; a gadget chain "
                "reachable via autoloading turns this into remote code execution (CWE-502, PHP "
                "Object Injection)."
            ),
            remediation=(
                "Prefer a non-executing format (json_decode()/json_encode()) for data that "
                "doesn't need to carry PHP objects. If unserialize() is required, pass the "
                "'allowed_classes' option to restrict which classes may be instantiated (PHP "
                "7+): unserialize($data, ['allowed_classes' => false]) disables object "
                "instantiation entirely. If this call is genuinely unreachable by attacker "
                "input, suppress with `// security: allow-php-unsafe-deserialization`."
            ),
            rule="php-unsafe-deserialization/tainted-unserialize",
            standards=list(_STANDARDS),
        )
