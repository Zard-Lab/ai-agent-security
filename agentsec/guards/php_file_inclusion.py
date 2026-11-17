"""Guard: PHP local/remote file inclusion (LFI/RFI) — checklist §3b.

agentsec's second PHP-language guard (2/9). Two reconciled graudit candidates, confirmed
as one coherent threat family — untrusted input reaching PHP's file-inclusion machinery — rather
than two separate concerns needing two guards:

1. **Tainted `include`/`require`.** Verified against graudit's real signature dictionary
   (`wireghoul/graudit`, `signatures/php.db`:
   ``^[[:space:]]*(include|require)(_once)?\\(...\\$...\\)``) — the regex shape is cited for
   provenance; detection logic and test fixtures here are original, developed independently against
   the pattern description, not copied from graudit's own (POSIX ERE) implementation. Fires CRITICAL
   on `include`/`include_once`/`require`/`require_once` called with a variable/superglobal path
   rather than a fixed string literal, e.g. `include($_GET['page'])`. If `allow_url_include` is
   enabled (or on older PHP configs), a tainted path can point at a remote attacker-controlled URL
   (Remote File Inclusion, full RCE); even without that, Local File Inclusion lets an attacker
   read/execute unintended local files (config files, uploaded "image" files containing PHP code,
   log-poisoning RCE chains).

2. **Dangerous PHP stream wrappers.** Also verified against graudit's `signatures/php.db` (the
   literal strings `php://filter`, `php://input`, `phar://`, `expect://`). Fires CRITICAL wherever
   `php://filter`, `phar://` or `expect://` appears in PHP source — not gated to any particular
   function call, since those three are dangerous wherever they appear: they are commonly chained
   with `include`/`file_get_contents`/`fopen`/etc. for LFI-to-RCE or filter-chain deserialization
   attacks, and none has a common benign first-party use.

   `php://input` is the documented exception and IS gated. It is the canonical way to read a raw
   request body (`file_get_contents('php://input')` in every PHP JSON API, `fopen('php://input',
   'rb')` in every PSR-7 implementation), so the bare literal is not evidence of anything. It
   fires only as an include target (`include('php://input')`, which executes the POST body as
   PHP) or when built from user input.

CWE-98 (Improper Control of Filename for Include/Require Statement in PHP Program), OWASP:A01.

Suppress an audited case (e.g. a hardcoded allowlist already validated elsewhere, or a
deliberate, reviewed diagnostic use of a stream wrapper) with:

    include($page); // security: allow-php-file-inclusion
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, php_scan_dirs, read, rel, strip_php_comments

_STANDARDS = ["CWE-98", "OWASP:A01"]

# include/require(_once) called with a `$` somewhere between the parens — a variable, a
# superglobal ($_GET/$_POST/$_REQUEST/$_COOKIE/...), or a concatenation involving one, rather than
# a fixed string literal. Mirrors graudit's own signature shape
# (`^[[:space:]]*(include|require)(_once)?\(...\$...\)`): broad and textual by design, not a
# dataflow proof — see the wiki doc's "Known bypasses" for what this does and does not catch.
# `\b` before the keyword keeps a function/method NAME ending in "include"/"require" (e.g.
# `$loader->include(...)`, `smarty_include(...)`) from being mistaken for the language construct —
# a `->` or an identifier char immediately before the keyword fails the boundary.
_TAINTED_INCLUDE = re.compile(
    r"\b(?:include|require)(?:_once)?\s*\(\s*[^()]*\$[^()]*\)"
)

# Dangerous PHP stream-wrapper literals, matched as plain substrings — these are dangerous
# wherever they appear, not only inside a particular function call: `php://filter` (filter-chain
# read/write, including base64/rot13/… conversion chains usable for deserialization gadgets and
# the classic source-disclosure read), `phar://` (PHP object injection via a crafted .phar,
# CVE-class "phar deserialization"), `expect://` (direct shell command execution when the
# `expect` extension is loaded). None of these has a common benign first-party use.
_DANGEROUS_STREAM_WRAPPER = re.compile(r"php://filter|phar://|expect://")
# `php://input` is deliberately NOT in the list above. Unlike the other three it is the canonical,
# entirely benign way to read a raw request body — `file_get_contents('php://input')` is in every
# PHP JSON API and `fopen('php://input','rb')` is in every PSR-7 implementation. Firing on the
# bare literal red-gates ordinary code at `critical`. It is only a sink when it is an INCLUDE
# target (RFI: `include('php://input')` executes the POST body as PHP) or when it is built from
# user input, so it is gated on one of those two contexts instead.
_PHP_INPUT_WRAPPER = re.compile(r"php://input")
_INCLUDE_CONTEXT = re.compile(r"\b(?:include|include_once|require|require_once)\b")
_USER_INPUT_CONCAT = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\.\s*\$")

_PRAGMA = "security: allow-php-file-inclusion"


class PhpFileInclusionGuard(Guard):
    id = "php-file-inclusion"
    title = "PHP local/remote file inclusion (LFI/RFI)"
    area = "Code safety"

    # FileInclude.php: include($_GET['page']) -> php-file-inclusion/tainted-include.
    canary_plant = CanaryPlant(
        files={
            "FileInclude.php": (
                "<?php\n"
                "function loadPage() {\n"
                "    include($_GET['page']);\n"
                "}\n"
            ),
        },
        expects=frozenset({"php-file-inclusion/tainted-include"}),
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
            if _TAINTED_INCLUDE.search(line):
                out.append(self._tainted_include_finding(root, f, i))
            if _DANGEROUS_STREAM_WRAPPER.search(line) or (
                _PHP_INPUT_WRAPPER.search(line)
                and (_INCLUDE_CONTEXT.search(line) or _USER_INPUT_CONCAT.search(line))
            ):
                out.append(self._stream_wrapper_finding(root, f, i))
        return out

    def _tainted_include_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "include()/require() called with a variable or superglobal path rather than a "
                "fixed string literal. If allow_url_include is enabled (or on older PHP "
                "configs), a tainted path can point at a remote attacker-controlled URL "
                "(Remote File Inclusion, full RCE); even without that, an attacker can direct "
                "the include at an unintended local file — a config file, an uploaded file "
                "containing embedded PHP, or a log file (log-poisoning RCE) — (CWE-98)."
            ),
            remediation=(
                "Never build an include/require path from user input. Use a hardcoded allowlist "
                "of known-safe includes (a switch/match over a fixed set of literal filenames), "
                "or map the input to a fixed literal via a lookup array before including. If this "
                "path is genuinely constrained to a safe value already, suppress with "
                "`// security: allow-php-file-inclusion`."
            ),
            rule="php-file-inclusion/tainted-include",
            standards=list(_STANDARDS),
        )

    def _stream_wrapper_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "A dangerous PHP stream wrapper literal (php://filter, php://input, phar://, "
                "or expect://) appears in this source. These are commonly chained with "
                "include()/file_get_contents()/fopen()/etc. for LFI-to-RCE (php://filter "
                "conversion-chain gadgets, php://input reading the raw POST body, phar:// "
                "deserialization) or direct command execution (expect://) — (CWE-98)."
            ),
            remediation=(
                "Do not pass a stream-wrapper-prefixed value built from (or reachable by) user "
                "input into a file-reading/including function. If this is a deliberate, reviewed "
                "diagnostic or filter use with no attacker-controlled input reaching it, suppress "
                "with `// security: allow-php-file-inclusion`."
            ),
            rule="php-file-inclusion/dangerous-stream-wrapper",
            standards=list(_STANDARDS),
        )
