from __future__ import annotations

from agentsec.guards.unawaited_async_truthy import UnawaitedAsyncTruthyGuard
from tests.guards._common import *  # noqa: F401,F403

# A real async declaration (lines 1-3, then a blank line 4), so a fixture's own code starts at line 5.
_ASYNC_IS_ADMIN = "async function isAdmin(u) {\n  return u.role === 'admin';\n}\n\n"


def test_flags_unawaited_call_from_function_declaration(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "async function validatePassword(pw) {\n"
        "  return pw === getStoredHash();\n"
        "}\n\n"
        "if (validatePassword(req.body.password)) {\n"
        "  grantAccess();\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = UnawaitedAsyncTruthyGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "unawaited-async-truthy/unawaited-call"
    assert findings[0].severity == "critical"
    assert "CWE-252" in findings[0].standards


def test_flags_unawaited_call_from_arrow_assignment(tmp_path: Path) -> None:
    (tmp_path / "auth.ts").write_text(
        "const validatePassword = async (pw) => pw === getStoredHash();\n\n"
        "if (validatePassword(pw)) {\n"
        "  grantAccess();\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    findings = UnawaitedAsyncTruthyGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_silent_on_member_call_to_declared_async_name(tmp_path: Path) -> None:
    # The resolver tracks FREE calls only (mirrors js_command_injection.py's own free-vs-member
    # call distinction) — a method-shorthand-declared async name called on its own receiver
    # (`auth.validatePassword(pw)`, not a bare `validatePassword(pw)`) is a member call and is
    # deliberately not tracked, since resolving which receiver's method it is would need the same
    # binding-resolution machinery as child_process's module-binding resolver.
    (tmp_path / "auth.js").write_text(
        "const auth = {\n"
        "  async validatePassword(pw) {\n"
        "    return pw === getStoredHash();\n"
        "  },\n"
        "};\n\n"
        "if (auth.validatePassword(pw)) {\n"
        "  grantAccess();\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert UnawaitedAsyncTruthyGuard().run(tmp_path, profile) == []


def test_flags_unawaited_call_in_while(tmp_path: Path) -> None:
    (tmp_path / "poll.js").write_text(
        "async function hasMore() {\n"
        "  return queue.length > 0;\n"
        "}\n\n"
        "while (hasMore()) {\n"
        "  process(queue.shift());\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = UnawaitedAsyncTruthyGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_silent_when_awaited(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "async function validatePassword(pw) {\n"
        "  return pw === getStoredHash();\n"
        "}\n\n"
        "async function login(req) {\n"
        "  if (await validatePassword(req.body.password)) {\n"
        "    grantAccess();\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert UnawaitedAsyncTruthyGuard().run(tmp_path, profile) == []


def test_silent_on_sync_function_call(tmp_path: Path) -> None:
    # A plain (non-async) function called in a conditional is ordinary, correct code — the guard
    # must only fire on calls to a LOCALLY-DECLARED async function.
    (tmp_path / "auth.js").write_text(
        "function isValid(pw) {\n"
        "  return pw.length > 8;\n"
        "}\n\n"
        "if (isValid(pw)) {\n"
        "  grantAccess();\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert UnawaitedAsyncTruthyGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "async function validatePassword(pw) {\n"
        "  return pw === getStoredHash();\n"
        "}\n\n"
        "// if (validatePassword(pw)) { grantAccess(); }\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert UnawaitedAsyncTruthyGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "async function validatePassword(pw) {\n"
        "  return pw === getStoredHash();\n"
        "}\n\n"
        "if (validatePassword(pw)) {  // security: allow-unawaited-async-truthy\n"
        "  grantAccess();\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert UnawaitedAsyncTruthyGuard().run(tmp_path, profile) == []


def test_pragma_scope_is_the_whole_file_not_the_annotated_line(tmp_path: Path) -> None:
    """The pragma is a WHOLE-FILE marker (`js_sql_injection.py`'s convention), so annotating
    one reviewed call silences every other finding in that file too.

    `test_pragma_suppresses` cannot prove this: its fixture holds exactly ONE finding, so it
    passes identically whether the scope is per-line or whole-file. This one discriminates —
    two findings, only the first annotated. Whole-file scope gives 0; a per-line scope would
    leave the second firing. The un-annotated control asserts the fixture really does carry
    two findings, so the test cannot pass by the guard going silent for an unrelated reason."""
    def source(annotation: str) -> str:
        return (
            "async function validatePassword(pw) {\n"
            "  return pw === getStoredHash();\n"
            "}\n\n"
            "if (validatePassword(pw)) {" + annotation + "\n"
            "  grantAccess();\n"
            "}\n\n"
            "if (validatePassword(other)) {\n"
            "  grantAdmin();\n"
            "}\n"
        )

    profile = mkprofile(tmp_path, features={"javascript"})

    # Control: without the pragma the fixture carries TWO independent findings.
    (tmp_path / "auth.js").write_text(source(""), encoding="utf-8")
    assert len(UnawaitedAsyncTruthyGuard().run(tmp_path, profile)) == 2

    # Annotating only the FIRST one silences the whole file, including the second.
    (tmp_path / "auth.js").write_text(
        source("  // security: allow-unawaited-async-truthy"), encoding="utf-8"
    )
    assert UnawaitedAsyncTruthyGuard().run(tmp_path, profile) == []


def test_silent_on_pattern_inside_a_string_literal(tmp_path: Path) -> None:
    # #749 (the issue's a.js): a docs string spelling out the vulnerable call, next to a REAL async
    # declaration of that name. The scan runs on the anchor mask, so string content is blank. It
    # fired CRITICAL before.
    (tmp_path / "auth.js").write_text(
        "async function validatePassword(pw) {\n"
        "  return pw === getStoredHash();\n"
        "}\n\n"
        'const docExample = "if (validatePassword(pw)) { grantAccess(); }";\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert UnawaitedAsyncTruthyGuard().run(tmp_path, profile) == []


def test_silent_when_async_declaration_exists_only_inside_a_string(tmp_path: Path) -> None:
    # #749: an `async function check` spelled out in a string must not mint `check` as async, else a
    # real `if (check(x))` against the ordinary, synchronous `check` fires CRITICAL.
    (tmp_path / "util.js").write_text(
        'const snippet = "async function check(x) { return true; }";\n'
        "function check(x) {\n"
        "  return x > 0;\n"
        "}\n\n"
        "if (check(x)) {\n"
        "  go();\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert UnawaitedAsyncTruthyGuard().run(tmp_path, profile) == []


def test_silent_on_async_name_inside_a_string_argument(tmp_path: Path) -> None:
    # #749: the async name appears in the condition only as text inside a string argument.
    (tmp_path / "auth.js").write_text(
        _ASYNC_IS_ADMIN + 'if (log("isAdmin(u)")) {\n  audit();\n}\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert UnawaitedAsyncTruthyGuard().run(tmp_path, profile) == []


def test_flags_unawaited_call_nested_in_a_template_substitution(tmp_path: Path) -> None:
    # #749, the traded direction: a call inside a `${...}` substitution is CODE (the Promise is
    # stringified, so the condition is always a truthy string). A mask built on plain
    # `strip_strings=True` would blank it and drop this finding silently.
    (tmp_path / "auth.js").write_text(
        _ASYNC_IS_ADMIN + "if (`${isAdmin(u)}`) {\n  grant();\n}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = UnawaitedAsyncTruthyGuard().run(tmp_path, profile)
    assert [f.location for f in findings] == ["auth.js:5"]


def test_condition_between_two_desyncing_substitutions_fires(tmp_path: Path) -> None:
    # #543, formerly the accepted trade #749 made (PR #1057 round-1 review): a `{` in a regex inside
    # one substitution and a `}` in a later one left the file balanced, so the lexer's restore caps
    # did not fire and a real condition between them read as template text (pair.js). The lexer now
    # consumes a substitution's regexes and comments whole, so all three placements fire.
    # Lexer-level pin: `test_strip_js_comments_anchor_mask_rebalancing_regex_pair_reads_as_code`.
    opens = "const t = `a ${ s.replace(/{/g, '') } b`;\n"
    closes = "const u = `a ${ s.replace(/}/g, '') } b`;\n"
    cond = "if (isAdmin(u)) { grant(); }\n"
    (tmp_path / "pair.js").write_text(_ASYNC_IS_ADMIN + opens + cond + closes, encoding="utf-8")
    (tmp_path / "single.js").write_text(_ASYNC_IS_ADMIN + opens + cond, encoding="utf-8")
    (tmp_path / "after.js").write_text(_ASYNC_IS_ADMIN + opens + closes + cond, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"javascript"})
    locations = sorted(f.location for f in UnawaitedAsyncTruthyGuard().run(tmp_path, profile))
    assert locations == ["after.js:7", "pair.js:6", "single.js:6"]


def test_quoted_condition_no_longer_hides_a_real_one_later_on_the_line(tmp_path: Path) -> None:
    # #749 WIDENING, a fixed false negative: `_COND_OPEN.search` takes the FIRST `if (` on a line,
    # which used to be the one inside the string, so the real unawaited call after it was missed.
    (tmp_path / "auth.js").write_text(
        _ASYNC_IS_ADMIN + 'const s = "if (x)"; if (isAdmin(u)) { grant(); }\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert [f.location for f in UnawaitedAsyncTruthyGuard().run(tmp_path, profile)] == ["auth.js:5"]


def test_quoted_condition_then_awaited_call_stays_silent(tmp_path: Path) -> None:
    # The FP-bait for the widening above (review-doctrine Rule 1): the same line with `await` is
    # correct code, and seeing the real condition must not make it fire.
    (tmp_path / "auth.js").write_text(
        _ASYNC_IS_ADMIN + 'const s = "if (x)"; if (await isAdmin(u)) { grant(); }\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert UnawaitedAsyncTruthyGuard().run(tmp_path, profile) == []


def test_not_applies_without_js_or_ts(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"})
    assert not UnawaitedAsyncTruthyGuard().applies(profile)


def test_applies_with_typescript(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"typescript"})
    assert UnawaitedAsyncTruthyGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.js").write_text(
        "async function validatePassword(pw) {\n"
        "  return pw === getStoredHash();\n"
        "}\n\n"
        "if (validatePassword(pw)) {\n"
        "  grantAccess();\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert UnawaitedAsyncTruthyGuard().run(tmp_path, profile) == []
