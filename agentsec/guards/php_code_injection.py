"""Guard: PHP code injection via `eval()`/`assert()`/`create_function()`/backtick fed dynamic
content (checklist §3b, extends `3b-eval-exec-injection`).

The PHP counterpart to agentsec's existing `code-injection-eval-exec` (Python) and
`js-code-injection` (JS/Node) guards — same requirement (a dynamic-evaluation sink fed
non-literal content is arbitrary code execution), a genuinely different code surface (PHP's
`eval`/`assert`/`create_function`/backtick shell-out instead of Python's `eval`/`exec` or JS's
`eval`/`Function`/`vm`), so it extends the same `3b-eval-exec-injection` checklist item rather than
duplicating it.

Four sinks, all CWE-95 (Eval Injection):

  * `eval($code)` — the classic PHP code-eval sink.
  * `assert($code)` — PHP's OLD (pre-PHP 8) `assert()` behavior: a STRING argument was evaluated
    as PHP code (not just tested truthy) if `zend.assertions` was enabled. This behavior was
    deprecated in PHP 7.2 and removed in PHP 8.0 — but this is a regex-only, version-blind scan,
    and legacy PHP 5.x/7.x codebases (and code still written to target them) can still carry it,
    so `assert()` fed dynamic, STRING-SHAPED content is flagged the same way `eval()` is.
    `assert()` only ever eval'd a STRING, never a boolean result — so unlike `eval()`, a boolean
    or comparison expression argument (`assert($x > 5)`, `assert(1 === 1)`, `assert(true)`) can
    NEVER be this string-eval vector and is deliberately excluded (Dean's review repro,
    fixed since), even though it is still "not a sole string literal" by the same test `eval()` uses.
  * `create_function($args, $code)` — deprecated since PHP 7.2, removed in PHP 8.0. Builds an
    anonymous function from two STRING arguments (both of which are effectively `eval()`'d
    internally) — so either argument being non-literal is the same code-injection primitive.
  * The backtick shell-execution operator (`` `$cmd` ``) — PHP's shorthand for `shell_exec()`.
    Not `eval()`-class code injection in the strict sense, but the same "attacker-controlled text
    fed to an interpreter" shape graudit's `php.db` groups alongside the eval/exec sinks, so it is
    included here rather than split into its own guard.

Fires HIGH on `eval(`/`assert(`/`create_function(` called with an argument that is NOT a sole
string literal — a bare `$variable`, a superglobal (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/
`$_ENV`/`$_SERVER`), string concatenation with `.`, or a function-call result all count as
non-literal. An all-literal `eval("some hardcoded string")` does NOT fire — unusual, but not
itself the vulnerability this guard targets. Also fires on a backtick expression whose content
contains a `$` variable interpolation (a pure-literal backtick like `` `ls -la` `` does not fire):

    eval($_GET['code'])                              # superglobal arg -> fires
    assert($userInput)                                # bare variable, could be a string -> fires
    create_function($_POST['args'], $_POST['code'])   # superglobal args -> fires
    $out = `rm -rf $target`;                          # tainted backtick -> fires

    eval("2 + 2")                                      # sole string literal -> does NOT fire
    `ls -la`                                            # pure-literal backtick -> does NOT fire
    assert(true)                                        # boolean literal, never string-eval'd -> does NOT fire
    assert($x > 5)                                      # comparison expression, always bool -> does NOT fire
    assert(1 === 1)                                      # comparison expression, always bool -> does NOT fire

A backtick character that is merely quoted string DATA — most commonly a SQL identifier quote
(`` `col` ``) embedded in a query string built via `.` concatenation — is NOT PHP's own backtick
operator and does NOT fire, even when the raw line has two backtick characters with a `$variable`
textually between them (#848 corpus scan, matomo-org/matomo's real ``"... FROM `" . $access . "` ...
"`` pattern). The check tracks PHP string-literal state across lines, since a `.`-concatenated
query string commonly spans a literal newline:

    return "SELECT " . $select . " FROM `" . $access . "` as t1  # both backticks are inside
            JOIN `" . $siteTable . "` as t2 ...";                # `"..."` literals -> does NOT fire

Suppress an audited case with:

    eval($trustedConstant); // security: allow-php-code-injection
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    php_scan_dirs,
    pragma_line_set,
    read,
    rel,
    split_call_args,
    strip_php_comments,
    strip_php_heredocs,
)

_PRAGMA = "security: allow-php-code-injection"

# `(?<!->)(?<!::)` so a method/static call like `$obj->eval(...)` or `Foo::eval(...)` is NOT
# matched — only the bare, global-scope `eval(`/`assert(`/`create_function(` sinks.
_EVAL_CALL = re.compile(r"(?<!->)(?<!::)\beval\s*\(")
_ASSERT_CALL = re.compile(r"(?<!->)(?<!::)\bassert\s*\(")
_CREATE_FUNCTION_CALL = re.compile(r"(?<!->)(?<!::)\bcreate_function\s*\(")

# A backtick shell-execution expression: `` `...` `` (no nested backtick — PHP doesn't allow one).
_BACKTICK = re.compile(r"`([^`]*)`")
# An unescaped `$` inside a backtick's content means it interpolates a variable (PHP backtick
# strings support the same interpolation double-quoted strings do) — not a pure literal.
_BACKTICK_VAR = re.compile(r"(?<!\\)\$")

# A single argument that is, in its entirety, one quoted string literal — nothing before or after
# it but whitespace. Escape-aware (`\\.`) so an escaped quote inside the literal doesn't end the
# match early. Anything that does NOT fully match this — a bare `$variable`, a superglobal
# subscript, `.`-concatenation, a function call, a numeric/bool literal — is treated as dynamic.
_SOLE_STRING_LITERAL = re.compile(r"""^(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")$""")

_STANDARDS = ["OWASP:A03", "ASVS:1.3.2", "CWE-95"]

# assert()-only exclusions: a boolean literal or a comparison/logical expression can
# NEVER be the string that pre-PHP-8 assert() evaluates as code — assert() only ever eval'd a
# STRING argument, never a boolean result, so these shapes are never the injection vector even
# though they fail the generic "not a sole string literal" test eval()/create_function() use.
_BOOL_LITERAL = re.compile(r"^(?:true|false)$", re.IGNORECASE)
_NUMERIC_LITERAL = re.compile(r"^-?\d+(?:\.\d+)?$")
# A comparison or logical operator at the TOP LEVEL of the expression means it evaluates to a bool,
# not a string, regardless of what its operands look like (`$x > 5`, `1 === 1`, `$a && $b`,
# `!$done`). "Top level" is load-bearing (follow-up): an operator character INSIDE a
# string literal (`$in . " >= 5"`) is content, not a comparison, and a comparison that is only a
# ternary's condition (`$a > 1 ? $b : $c`) doesn't make the whole expression bool-valued — its
# value is a (possibly-tainted-string) branch. `_top_level()` below reduces the argument to just
# its real top-level tokens before this is applied, so the search never sees a nested operator.
# `instanceof` belongs here for the same reason `===` does: it is a bool-valued operator, so
# `$x instanceof Foo` can never be the string assert() eval'd. It was missing from this list but
# stayed silent by accident, because the `->` in the usual `$this->dep instanceof Foo` was itself
# being misread as a comparison. Removing that misreading (below) exposed the omission.
_COMPARISON_OR_LOGICAL = re.compile(
    r"===|!==|==|!=|<>|<=|>=|<|>|&&|\|\||^\s*!(?!=)|\b(?:and|or|xor|instanceof)\b", re.IGNORECASE
)
# Mask PHP string-literal spans before the top-level-operator search so an operator char inside a
# quoted concatenation element isn't mistaken for a comparison — same char classes as
# `_SOLE_STRING_LITERAL`, unanchored so it matches every literal in a larger expression.
_PHP_STRING_LITERAL = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")
# `->` and `?->` are member-access tokens. Their `>` is not a comparison and the `?` of `?->` is
# not a ternary, so both have to be removed before either test runs — otherwise `->` "proves" the
# expression bool and silently drops a real sink (`assert($obj->getPayload() . $b)`).
_MEMBER_ACCESS = re.compile(r"\?->|->")
# A parenthesized sub-expression is by definition not top level. Collapsing these is what keeps
# `($a ?? 0) > 5` and `($a ?: 0) > 5` recognizable as bool-valued: their `?` is nested, while the
# `?` of a genuine top-level ternary (`$a > 1 ? $b : $c`) is not and survives.
_PAREN_GROUP = re.compile(r"\([^()]*\)")
# A real value-selecting ternary `?`, i.e. not the `??` null-coalescing operator (`?->` is already
# gone by the time this runs). Its presence means the expression's value is a branch, which may be
# a tainted string, so the bool-proof below must NOT be applied.
_TERNARY = re.compile(r"(?<!\?)\?(?!\?)")


def _top_level(arg: str) -> str:
    """Reduce `arg` to only its top-level tokens: string literals, member-access arrows and
    parenthesized sub-expressions are removed, so what remains is what actually determines the
    expression's shape. Used for both the ternary check and the comparison/logical check."""
    s = _PHP_STRING_LITERAL.sub("", arg)
    s = _MEMBER_ACCESS.sub(" ", s)
    prev = None
    while prev != s:  # innermost-out, so nesting depth doesn't matter
        prev, s = s, _PAREN_GROUP.sub(" ", s)
    return s


def _live(raw: str, code: str, idx: int) -> bool:
    """True when the character at `idx` survived comment stripping — i.e. the match is real
    code and not text inside a `//`/`#` line comment or a `/* */` block.

    `strip_php_comments` is length-preserving (it overwrites a blanked character with a space),
    so an index comparison IS the "is this inside a comment" test. The backtick branch needs it
    because PHP's backtick shell-exec literal is NOT comment-aware in the stripper: the `//` of
    `` `wget http://$_GET[h]/x` `` reads as a line-comment start and blanks the rest of the
    line — including the closing backtick — so the sink has to be matched against the RAW line,
    and then the position check is what keeps a commented-out example silent. Mirrors
    `ruby_command_injection.py::_live`, which solved the identical problem for Ruby backticks.
    """
    return idx < len(code) and code[idx] == raw[idx]


def _is_dynamic(arg: str) -> bool:
    a = arg.strip()
    if not a:
        return False
    return not _SOLE_STRING_LITERAL.match(a)


def _is_dynamic_string_shaped(arg: str) -> bool:
    """`_is_dynamic`, narrowed for `assert()`: also excludes boolean/numeric literals and
    expressions whose TOP-LEVEL shape is a comparison/logical operator — those are always
    bool-valued and can never be the STRING pre-PHP-8 `assert()` evaluates as code. An operator
    char inside a string literal, inside a parenthesized sub-expression, or in a member-access
    arrow is NOT top-level and does not exclude: `$in . " >= 5"`, `$a > 1 ? $b : $c` and
    `$obj->getPayload() . $b` are all string-shaped and must still fire. Conversely a nested `?`
    (`($a ?? 0) > 5`, `($a ?: 0) > 5`, `$obj?->x() === "y"`) does not make the expression a
    ternary, so it must not waive the bool-proof (follow-up round 2)."""
    a = arg.strip()
    if not a:
        return False
    if _BOOL_LITERAL.match(a) or _NUMERIC_LITERAL.match(a):
        return False
    top = _top_level(a)
    if not _TERNARY.search(top) and _COMPARISON_OR_LOGICAL.search(top):
        return False
    return _is_dynamic(a)


def _first_arg(line: str, open_paren: int) -> str | None:
    args = split_call_args(line, open_paren)
    return args[0] if args else None


def _string_state_at(line: str, pos: int, open_quote: str | None) -> str | None:
    """The active quote state (`None`, `"'"`, or `'"'`) right before `line[pos]`, given the state
    carried in from a PRIOR line (`open_quote`) — a PHP string literal built across a `.`
    concatenation can legally contain a literal newline, so a `"..."`/`'...'` opened on one line
    and closed on a later one is real, common PHP (#848 corpus scan: matomo's multi-line query
    string spanning `"... FROM `" . $access . "` as t1` then `JOIN `" . $siteTable . "` ..."`).

    Escape-aware inside double-quoted strings (`\\"` doesn't close them); PHP single-quoted strings
    only recognize `\\'`/`\\\\` as escapes, but treating any `\\` as an escape char here is a safe
    over-approximation for this narrow use.

    Scans `line` (the comment-STRIPPED text, not the raw one) deliberately: an apostrophe inside a
    `//`/`#` comment (`// don't do this`) must not be read as opening a real string, and
    `strip_php_comments` blanks comments to spaces while preserving length/positions, so this stays
    aligned with the raw-line backtick-match positions the caller checks against."""
    quote = open_quote
    i = 0
    n = min(pos, len(line))
    while i < n:
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
        i += 1
    return quote


def _string_state_after(line: str, open_quote: str | None) -> str | None:
    return _string_state_at(line, len(line), open_quote)


class PhpCodeInjectionGuard(Guard):
    id = "php-code-injection"
    title = "No code injection via a PHP eval()/assert()/create_function()/backtick sink"
    area = "Code safety"

    # CodeInject.php: eval($_GET['code']) with a superglobal argument (no pragma) ->
    # fires php-code-injection/eval-tainted-arg.
    canary_plant = CanaryPlant(
        files={
            "CodeInject.php": (
                "<?php\n"
                "function runFromRequest() {\n"
                "    return eval($_GET['code']);\n"
                "}\n"
            ),
        },
        expects=frozenset({"php-code-injection/eval-tainted-arg"}),
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
        raw_lines = text.splitlines()  # the backtick check below still reads the raw line
        pragma_lines = pragma_line_set(_PRAGMA, text, dialect="php")  # lines whose COMMENT carries it (#424)
        # `strip_php_heredocs` runs FIRST so a heredoc/nowdoc body's ordinary prose (which can
        # contain an odd number of quote characters with no PHP significance) can never desync the
        # cross-line `open_quote` tracking below (#848 / PR #884 review). Both stages are
        # length-preserving, so the two line lists still pair up exactly.
        code_lines = strip_php_comments(strip_php_heredocs(text)).splitlines()
        open_quote: str | None = None  # PHP string state carried across lines (#848 corpus scan)
        for i, (raw, line) in enumerate(zip(raw_lines, code_lines, strict=True), start=1):
            line_open_quote = open_quote
            open_quote = _string_state_after(line, open_quote)
            if i in pragma_lines:
                continue

            m = _EVAL_CALL.search(line)
            if m:
                arg = _first_arg(line, m.end() - 1)
                if arg is not None and _is_dynamic(arg):
                    out.append(self._finding(root, f, i, "eval-tainted-arg", self._eval_message()))
                    continue

            m = _ASSERT_CALL.search(line)
            if m:
                arg = _first_arg(line, m.end() - 1)
                if arg is not None and _is_dynamic_string_shaped(arg):
                    out.append(self._finding(root, f, i, "assert-tainted-arg", self._assert_message()))
                    continue

            m = _CREATE_FUNCTION_CALL.search(line)
            if m:
                args = split_call_args(line, m.end() - 1)
                if args and any(_is_dynamic(a) for a in args):
                    out.append(
                        self._finding(
                            root, f, i, "create-function-tainted-arg", self._create_function_message()
                        )
                    )
                    continue

            # Matched against the RAW line, not the stripped one: the backtick literal is not
            # comment-aware in `strip_php_comments`, so a `//` or `#` INSIDE the shelled-out
            # command (any URL, `git clone http://…`, a `#`-bearing flag) blanks the rest of the
            # line and takes the closing backtick with it. `_live` then supplies the comment
            # suppression the stripped line used to provide incidentally.
            bt = _BACKTICK.search(raw)
            if (
                bt
                and _live(raw, line, bt.start())
                and _string_state_at(line, bt.start(), line_open_quote) is None
                and _string_state_at(line, bt.end() - 1, line_open_quote) is None
                and _BACKTICK_VAR.search(bt.group(1))
            ):
                out.append(self._finding(root, f, i, "backtick-tainted", self._backtick_message()))
        return out

    @staticmethod
    def _eval_message() -> str:
        return (
            "eval() is called with an argument that is not a sole string literal (a bare "
            "variable, superglobal, concatenation, or function-call result). If that content is "
            "attacker-influenceable, this is arbitrary PHP code execution (CWE-95)."
        )

    @staticmethod
    def _assert_message() -> str:
        return (
            "assert() is called with an argument that is not a sole string literal. Pre-PHP 8, "
            "assert() evaluated a STRING argument as PHP code (not just tested it truthy) when "
            "zend.assertions was enabled — a legacy code-injection primitive still reachable in "
            "PHP 5.x/7.x deployments (CWE-95)."
        )

    @staticmethod
    def _create_function_message() -> str:
        return (
            "create_function() builds an anonymous function from its string arguments, which are "
            "internally eval()'d. At least one argument here is not a sole string literal — if it "
            "is attacker-influenceable, this is arbitrary PHP code execution (CWE-95). "
            "create_function() itself is deprecated since PHP 7.2 and removed in PHP 8.0."
        )

    @staticmethod
    def _backtick_message() -> str:
        return (
            "This backtick shell-execution expression interpolates a variable into the command "
            "text. If that variable is attacker-influenceable, this is shell command injection "
            "(CWE-95) — the backtick operator is shorthand for shell_exec()."
        )

    def _finding(self, root: Path, f: Path, line: int, rule_suffix: str, message: str) -> Finding:
        remediation = {
            "eval-tainted-arg": (
                "Never eval() attacker-influenceable input. Use json_decode() for data, an "
                "explicit allowlist of accepted operations, or a restricted expression parser "
                "instead. If this call is audited-safe, suppress with "
                "`// security: allow-php-code-injection`."
            ),
            "assert-tainted-arg": (
                "Never pass dynamic content to assert() as a string. Use assert() only with a "
                "real boolean expression (its PHP 8 behavior), and validate/allowlist any input "
                "before it can influence one. If audited-safe, suppress with "
                "`// security: allow-php-code-injection`."
            ),
            "create-function-tainted-arg": (
                "Replace create_function() with a real anonymous function (`function(...) {...}` "
                "or an arrow function) — it takes no eval()'d string arguments at all. If this "
                "call is audited-safe, suppress with `// security: allow-php-code-injection`."
            ),
            "backtick-tainted": (
                "Never interpolate attacker-influenceable data into a shell command. Use "
                "escapeshellarg()/escapeshellcmd() on every dynamic component, or avoid shelling "
                "out entirely. If audited-safe, suppress with "
                "`// security: allow-php-code-injection`."
            ),
        }[rule_suffix]
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=message,
            remediation=remediation,
            rule=f"php-code-injection/{rule_suffix}",
            standards=list(_STANDARDS),
        )
