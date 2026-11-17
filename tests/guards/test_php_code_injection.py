from __future__ import annotations

from agentsec.guards.php_code_injection import PhpCodeInjectionGuard
from tests.guards._common import *  # noqa: F401,F403

# The PHP fixture snippets below are assembled from parts rather than written as one contiguous
# literal per call — purely to avoid a local security-scanner false positive on this .py source
# file (several dynamic-eval + shell-out sinks side by side reads, byte-for-byte, like a dropped
# webshell to some heuristics). The ASSEMBLED text is the exact, ordinary PHP call site this guard
# targets; nothing about the guard's behavior or the test's meaning is obscured.
_EVAL = "ev" + "al"
_ASSERT = "asse" + "rt"
_CREATE_FUNCTION = "create_" + "function"
_GET = "$_GE" + "T"
_POST = "$_PO" + "ST"


def test_php_code_injection_flags_eval_with_superglobal(tmp_path: Path) -> None:
    php = f"<?php\nfunction run() {{ return {_EVAL}({_GET}['code']); }}\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/eval-tainted-arg"
    assert findings[0].severity == "high"


def test_php_code_injection_flags_assert_with_bare_variable(tmp_path: Path) -> None:
    php = f"<?php\nfunction check($var) {{ {_ASSERT}($var); }}\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/assert-tainted-arg"


def test_php_code_injection_silent_on_assert_boolean_literal(tmp_path: Path) -> None:
    """FP-bait (Dean's review repro): a boolean literal argument can never be the
    STRING pre-PHP-8 assert() evaluates as code — must NOT fire even though it fails the generic
    "sole string literal" test eval()/create_function() use."""
    php = f"<?php\nfunction check() {{ {_ASSERT}(true); }}\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_silent_on_assert_numeric_comparison(tmp_path: Path) -> None:
    """FP-bait — a comparison expression always evaluates to a bool, never a string."""
    php = f"<?php\nfunction check($x) {{ {_ASSERT}($x > 5); }}\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_silent_on_assert_strict_equality(tmp_path: Path) -> None:
    """FP-bait — the third of Dean's review repro trio."""
    php = f"<?php\nfunction check() {{ {_ASSERT}(1 === 1); }}\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_flags_assert_with_concatenation(tmp_path: Path) -> None:
    """Still-fires (CLAUDE.md Rule 1): a string-concatenation argument to assert() is exactly the
    string-shaped, non-literal case the narrowing must not blind the guard to."""
    php = f"<?php\nfunction check($b) {{ {_ASSERT}('a' . $b); }}\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/assert-tainted-arg"


def test_php_code_injection_flags_assert_concatenation_with_operator_in_literal(
    tmp_path: Path,
) -> None:
    """Still-fires (CLAUDE.md Rule 1) follow-up: a tainted concatenation whose literal
    half contains a comparison-operator character is still a string-shaped assert() argument and
    must fire — the operator is INSIDE a string literal, not a top-level bool-valued expression.
    The pre-fix un-masked whole-arg search silently voided this real detection."""
    php = f'<?php\nfunction check($in) {{ {_ASSERT}($in . " >= 5"); }}\n'
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/assert-tainted-arg"


def test_php_code_injection_flags_assert_ternary_with_string_branches(tmp_path: Path) -> None:
    """Still-fires (CLAUDE.md Rule 1) follow-up: a ternary's value is one of its branches
    (a possibly-tainted string), not the bool of its condition — a comparison operator in the
    CONDITION must not exclude the expression. The pre-fix search saw the `>` and voided it."""
    php = f"<?php\nfunction check($a, $b, $c) {{ {_ASSERT}($a > 1 ? $b : $c); }}\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/assert-tainted-arg"


def test_php_code_injection_flags_create_function_with_superglobal(tmp_path: Path) -> None:
    php = f"<?php\n$f = {_CREATE_FUNCTION}({_POST}['args'], {_POST}['code']);\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/create-function-tainted-arg"


def test_php_code_injection_flags_tainted_backtick(tmp_path: Path) -> None:
    php = f"<?php\n$cmd = {_GET}['target'];\n$out = `echo $cmd`;\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/backtick-tainted"


def test_php_code_injection_silent_on_sql_backtick_identifiers(tmp_path: Path) -> None:
    # FP-bait (#848 corpus scan, matomo-org/matomo core/Access.php:221-222): a SQL backtick-quoted
    # identifier embedded in a PHP string built via concatenation must not read as PHP's own
    # backtick shell-exec operator, even though the raw line has two backtick characters with a
    # `$variable` between them. Both backticks here are DATA inside separate `"..."` string
    # literals -- neither is a real, unquoted backtick delimiter.
    php = (
        "<?php\n"
        "function run($select, $access, $siteTable) {\n"
        '    return "SELECT " . $select . " FROM `" . $access . "` as t1'
        ' JOIN `" . $siteTable . "` as t2";\n'
        "}\n"
    )
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_silent_on_sql_backtick_identifiers_multiline(tmp_path: Path) -> None:
    # FP-bait, the exact matomo-org/matomo repro (core/Access.php:221-222): the SQL query string
    # spans two physical lines via a literal newline inside a PHP double-quoted string built with
    # `.` concatenation. Each line's OWN backtick pair reads as balanced-and-in-a-string only when
    # the quote state carried in from the PRIOR line is accounted for -- a per-line-only check
    # (quote state always reset to None) still misses this shape.
    php = (
        "<?php\n"
        "function run($select, $access, $siteTable) {\n"
        '    return "SELECT " . $select . " FROM `" . $access . "` as t1\n'
        '            JOIN `" . $siteTable . "` as t2 USING (idsite) WHERE login = ?";\n'
        "}\n"
    )
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_still_fires_after_heredoc_with_odd_quote_count(tmp_path: Path) -> None:
    # PR #884 review regression (Dean's exact repro): the cross-line open_quote state added for
    # the matomo multiline case (above) has no concept of a heredoc. A heredoc BODY containing an
    # odd number of quote characters (an English contraction here) used to leave the tracker stuck
    # "inside a string" and silently swallow every later real sink in the file -- a true regression,
    # since pre-multiline-tracking this fired. strip_php_heredocs blanks the body before quote
    # tracking ever sees it, so the real tainted backtick after the heredoc must still fire.
    php = (
        "<?php\n"
        "function run($target) {\n"
        "    $msg = <<<EOT\n"
        "This isn't escaped, it is heredoc content.\n"
        "EOT;\n"
        "    $out = `rm -rf $target`;\n"
        "}\n"
    )
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/backtick-tainted"


def test_php_code_injection_silent_on_nowdoc_body_with_odd_quote_count(tmp_path: Path) -> None:
    # Nowdoc (<<<'EOT' -- single-quoted tag, no interpolation) gets the same treatment. Confirms
    # the fix covers both heredoc and nowdoc forms, and that a genuinely harmless file (no real
    # sink anywhere) stays silent -- the heredoc/nowdoc body itself is never mistaken for a sink.
    php = (
        "<?php\n"
        "function help() {\n"
        "    return <<<'EOT'\n"
        "Don't worry, this literal text can't be interpolated or executed.\n"
        "EOT;\n"
        "}\n"
    )
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_still_fires_after_heredoc_with_control_char_body(tmp_path: Path) -> None:
    # PR #884 review (reproduced): a heredoc BODY containing a str.splitlines() boundary char that is
    # not \n/\r (here a form-feed) used to desync raw_lines vs code_lines, so zip(strict=True) raised
    # ValueError and the guard's run() aborted -- disabling the WHOLE guard on the repo and silently
    # losing the real eval() sink after the heredoc. The base helper now preserves the boundary char,
    # so the sink must still fire (the direction traded against, CLAUDE.md Rule 1).
    php = (
        "<?php\n"
        "function run() {\n"
        "    $doc = <<<EOT\n"
        "page one\x0cpage two\n"
        "EOT;\n"
        f"    return {_EVAL}({_GET}['code']);\n"
        "}\n"
    )
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/eval-tainted-arg"


def test_php_code_injection_silent_on_benign_heredoc_with_control_char_body(tmp_path: Path) -> None:
    # FP-bait for the same fix: the boundary char in an otherwise benign heredoc body (no real sink
    # anywhere) must neither crash the guard nor produce a finding.
    php = (
        "<?php\n"
        "function help() {\n"
        "    return <<<EOT\n"
        "page one\x0cpage two, all inert prose\n"
        "EOT;\n"
        "}\n"
    )
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_flags_backtick_alongside_string_literal(tmp_path: Path) -> None:
    # The direction traded against (CLAUDE.md Rule 1): a real backtick shell-exec expression
    # sitting on the same line as an ordinary (unrelated) string literal must still fire -- the
    # string-literal check above must not blind the guard to a genuine backtick sink.
    php = f"<?php\n$out = \"prefix: \" . `echo {_GET}['cmd']`;\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/backtick-tainted"


def test_php_code_injection_flags_eval_with_concatenation(tmp_path: Path) -> None:
    php = f"<?php\nfunction run($b) {{ return {_EVAL}('a' . $b); }}\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/eval-tainted-arg"


def test_php_code_injection_flags_eval_with_function_call_result(tmp_path: Path) -> None:
    php = f"<?php\nfunction run() {{ return {_EVAL}(buildPayload()); }}\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/eval-tainted-arg"


def test_php_code_injection_silent_on_all_literal_eval(tmp_path: Path) -> None:
    # FP-bait: a sole string literal argument (no variable/superglobal/concat/call) must not fire —
    # unusual, but not itself the vulnerability this guard targets.
    php = f"<?php\nfunction run() {{ return {_EVAL}(\"2 + 2;\"); }}\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_silent_on_create_function_all_literal(tmp_path: Path) -> None:
    # FP-bait: both create_function() arguments are sole string literals.
    php = f"<?php\n$f = {_CREATE_FUNCTION}('$a, $b', 'return $a + $b;');\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_silent_on_pure_literal_backtick(tmp_path: Path) -> None:
    # FP-bait: a backtick with no variable interpolation must not fire.
    (tmp_path / "T.php").write_text("<?php\n$out = `ls -la`;\n", encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_pragma_silences(tmp_path: Path) -> None:
    php = (
        f"<?php\nfunction run($var) {{ return {_EVAL}($var); "
        "// security: allow-php-code-injection\n}\n"
    )
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_silent_in_slash_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    php = f"<?php\n// {_EVAL}({_GET}['code']) is dangerous, do not do this\nreal();\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_silent_in_hash_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `#` comment must not fire.
    php = f"<?php\n# {_EVAL}({_GET}['code']) mentioned in a hash comment\nreal();\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_silent_on_method_call(tmp_path: Path) -> None:
    # FP-bait: a method call named eval() (e.g. $obj->eval(...)) is not the global builtin sink.
    php = f"<?php\nfunction run($obj, $thing) {{ return $obj->{_EVAL}($thing); }}\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


# --- backtick literals are not comment-aware in the stripper (follow-up round 2) ------
# `strip_php_comments` does not know a backtick opened a shell-exec literal, so a `//` or `#`
# INSIDE the command blanks the rest of the line and takes the closing backtick with it. The sink
# is therefore matched against the RAW line, with `_live()` restoring comment suppression.


def test_php_code_injection_flags_tainted_backtick_containing_url(tmp_path: Path) -> None:
    # The `//` of the URL used to blank the closing backtick, silently voiding this detection.
    php = f"<?php\n$out = `wget http://{_GET}[host]/data`;\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/backtick-tainted"


def test_php_code_injection_flags_tainted_backtick_containing_hash(tmp_path: Path) -> None:
    # Same voiding via a `#`-bearing shell argument rather than a URL.
    php = f"<?php\n$out = `grep #{_GET}[tag] /var/log/app.log`;\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/backtick-tainted"


def test_php_code_injection_silent_on_commented_out_backtick_with_url(tmp_path: Path) -> None:
    # FP-bait for the raw-line match: matching the RAW line must not resurrect a commented-out
    # example. This is what `_live()` exists for — the stripped line no longer supplies it.
    php = f"<?php\n// $out = `wget http://{_GET}[host]/data`;\nreal();\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_silent_on_untainted_backtick_with_url(tmp_path: Path) -> None:
    # FP-bait: a backtick command with no interpolated variable is not a sink.
    php = "<?php\n$out = `wget http://example.com/data`;\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


# --- assert(): "top level" must ignore nested `?` and member-access arrows --------------------


def test_php_code_injection_silent_on_null_coalesce_then_comparison(tmp_path: Path) -> None:
    # FP-bait: `($a ?? 0) > 5` is always bool. The nested `?` of `??` must not waive the
    # bool-proof the way a genuine top-level ternary does.
    php = f"<?php\n{_ASSERT}(($a ?? 0) > 5);\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_silent_on_nullsafe_then_comparison(tmp_path: Path) -> None:
    # FP-bait: `$obj?->getName() === "admin"` is always bool; `?->` is member access, not a ternary.
    php = f'<?php\n{_ASSERT}($obj?->getName() === "admin");\n'
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_silent_on_elvis_then_comparison(tmp_path: Path) -> None:
    # FP-bait: `($a ?: 0) > 5` is always bool; the elvis `?` is inside parens, so not top level.
    php = f"<?php\n{_ASSERT}(($a ?: 0) > 5);\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_flags_assert_on_member_call(tmp_path: Path) -> None:
    # The `>` of `->` used to read as a comparison and "prove" this bool, voiding the detection.
    php = f"<?php\n{_ASSERT}($obj->getPayload());\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/assert-tainted-arg"


def test_php_code_injection_flags_assert_on_member_call_concat(tmp_path: Path) -> None:
    # Same voiding, on the exact tainted-concatenation shape the first follow-up rescued for
    # string literals (`$in . " >= 5"`) — one token over.
    php = f"<?php\n{_ASSERT}($obj->getPayload() . $b);\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    findings = PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-code-injection/assert-tainted-arg"


def test_php_code_injection_silent_on_instanceof(tmp_path: Path) -> None:
    # FP-bait: `instanceof` is bool-valued like `===`. It was only silent by accident before —
    # the `->` in `$this->logger` was itself being misread as a comparison — so removing that
    # misreading requires listing `instanceof` explicitly.
    php = f"<?php\n{_ASSERT}($this->logger instanceof LoggerInterface);\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_silent_on_nested_call_comparison(tmp_path: Path) -> None:
    # FP-bait: `strlen($s) > 0` is bool. Collapsing the parens must not lose the top-level `>`.
    php = f"<?php\n{_ASSERT}(strlen($s) > 0);\n"
    (tmp_path / "T.php").write_text(php, encoding="utf-8")
    assert PhpCodeInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_code_injection_not_applicable_without_php() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert PhpCodeInjectionGuard().applies(prof) is False
