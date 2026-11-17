"""Unit tests for `comment_view` / `pragma_present` / `pragma_line_set` (issue #424, the
pragma-anchoring rider) — the primitive the guards' suppress-pragma checks are to route through.

Both directions, per CLAUDE.md rule 1, in every dialect: a pragma quoted INSIDE string content
(docstring, single-line string, f-string, template literal, SQL literal / `E'…'` / identifier, YAML
quoted or block scalar, HCL heredoc, Go raw string, PHP heredoc) must be ABSENT from the view — the
false-negative class the issue measured on 199 guards — and a pragma written in EVERY comment form
the docs show (`#`, `//`, `--`, `/* */`) must be PRESENT, because a view that drops a real comment
voids a user's own opt-out (rule 4), which is worse than the FN it fixes.

The same-length / line-count invariant is asserted on every case: it is what lets an adopting guard
slice the view at the offsets it already slices the raw text, so a pragma's reach never moves.

The pragma phrase used here names no real guard (`allow-i424-probe`), so nothing in this file can
silence a guard on a scan of the tree.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import get_args

import pytest

from agentsec.guards.base import (
    CommentDialect,
    _comment_view_cache,
    _hash_comment_start,
    comment_view,
    derived_state_run,
    pragma_line_set,
    pragma_present,
    strip_hash_comments,
)

_P = "security: allow-i424-probe"
_PAT = re.compile(r"#\s*security:\s*allow-i424-probe")
_DIALECTS: tuple[CommentDialect, ...] = get_args(CommentDialect)


def _crlf(text: str) -> str:
    return text.replace("\n", chr(13) + "\n")


def _assert_invariants(text: str, dialect: CommentDialect) -> str:
    view = comment_view(text, dialect)
    assert len(view) == len(text), f"{dialect}: the view must be the same length as the text"
    assert len(view.splitlines()) == len(text.splitlines()), f"{dialect}: line count must not move"
    for got, want in zip(view, text, strict=True):
        assert got == " " or got == want, f"{dialect}: a view character is either a space or the original"
    return view


# --- direction 1: string content never yields a pragma --------------------------------------------
# (dialect, text) — each quotes the pragma inside string content, in the documented `#`/`//`/`--`
# forms, and must NOT count. These are the shapes the issue measured silencing real findings.
_STRING_CASES: list[tuple[str, CommentDialect, str]] = [
    ("python docstring", "python", f'"""Opt out: add `# {_P}` to the line."""\nx = 1\n'),
    ("python single-line string", "python", f'doc = "# {_P}"\nx = 1\n'),
    ("python f-string", "python", f'doc = f"# {_P} {{x}}"\n'),
    ("python bytes", "python", f'doc = b"# {_P}"\n'),
    ("python implicit concat", "python", f'doc = ("a"\n       "# {_P}")\n'),
    ("js string", "js", f'const d = "// {_P}";\n'),
    ("js single-quoted", "js", f"const d = '# {_P}';\n"),
    ("js template literal", "js", f"const d = `// {_P}`;\n"),
    ("js nested template", "js", f"const d = `a ${{ `// {_P}` }}`;\n"),
    ("sql literal", "sql", f"SELECT '-- {_P}';\n"),
    ("sql doubled-quote literal", "sql", f"SELECT 'it''s -- {_P}';\n"),
    ("sql E literal", "sql", f"SELECT E'it\\'s -- {_P}';\n"),
    ("sql /* inside literal", "sql", f"SELECT '/* {_P} */';\n"),
    # #442: the FP-bait for the restored comments below. Text after a `/*`-bearing body is lexed
    # normally again, so a pragma quoted in a literal there is still content.
    ("sql literal after a $$ glob", "sql", f"SELECT $$See docs/*.md$$;\nSELECT '-- {_P}';\n/* note */\n"),
    # #1040: a `;` inside a `"…"` identifier revokes its comment-immunity in `strip_sql_comments`,
    # so the view used to read these as comments, while the `'…'` twins above never did.
    ("sql identifier holding ;", "sql", f'SELECT "x ; -- {_P}";\n'),
    ("sql identifier holding ; and /* */", "sql", f'SELECT "x ; /* {_P} */";\n'),
    ("sql doubled-quote identifier holding ;", "sql", f'SELECT "a""b ; -- {_P}";\n'),
    ("sql identifier holding ; after a quote in a literal", "sql", f"SELECT 'a\"b', \"x ; -- {_P}\";\n"),
    # #1040 T2: a dollar body is code, so a literal or identifier INSIDE it is still content.
    ("sql literal inside a $$ body", "sql", f"DO $$ BEGIN PERFORM '-- {_P}'; END $$;\n"),
    ("sql identifier holding ; inside a $$ body", "sql", f'DO $$ BEGIN PERFORM "x ; -- {_P}"; END $$;\n'),
    # #1125 round 1, L2: a CRLF body, and a different tag inside a body (plain text there).
    ("sql literal inside a CRLF $$ body", "sql", _crlf(f"DO $$ BEGIN\n  PERFORM '-- {_P}';\nEND $$;\n")),
    ("sql literal after a mismatched tag in a body", "sql", f"DO $a$ $b$ PERFORM '-- {_P}'; $a$;\n"),
    ("yaml double-quoted scalar", "yaml", f'doc: "# {_P}"\n'),
    ("yaml single-quoted scalar", "yaml", f"doc: '# {_P}'\n"),
    ("yaml hash inside a value", "yaml", f"doc: a#{_P}\n"),
    ("yaml literal block scalar", "yaml", f"run: |\n  echo hi\n  # {_P}\nnext: 1\n"),
    ("yaml folded block scalar", "yaml", f"run: >-\n  # {_P}\nnext: 1\n"),
    ("yaml block scalar with indicators", "yaml", f"run: |2+\n  # {_P}\n"),
    ("yaml block scalar in a list", "yaml", f"steps:\n  - run: |\n      # {_P}\n  - x: 1\n"),
    ("yaml bare block scalar entry", "yaml", f"steps:\n  - |\n    # {_P}\n  - x\n"),
    ("yaml nested list block scalar", "yaml", f"- - run: |\n      # {_P}\n"),
    ("yaml blank line inside block", "yaml", f"run: |\n  a\n\n  # {_P}\n"),
    ("hash quoted value", "hash", f'X="# {_P}"\n'),
    ("hcl string", "hcl", f'x = "# {_P}"\n'),
    ("hcl url string", "hcl", f'x = "https://example.test/{_P}"\n'),
    ("hcl heredoc", "hcl", f"user_data = <<EOF\n# {_P}\nEOF\ny = 1\n"),
    ("hcl indented heredoc", "hcl", f"user_data = <<-EOF\n  // {_P}\n  EOF\n"),
    ("go string", "go", f'var d = "// {_P}"\n'),
    ("go raw string", "go", f"var d = `// {_P}`\n"),
    ("java string", "java", f'String d = "// {_P}";\n'),
    ("ruby string", "ruby", f'd = "# {_P}"\n'),
    ("ruby interpolated string", "ruby", f'd = "#{{x}} # {_P}"\n'),
    ("php string", "php", f"<?php\n$d = '# {_P}';\n"),
    ("php heredoc", "php", f"<?php\n$d = <<<EOT\n// {_P}\nEOT;\n"),
]


@pytest.mark.parametrize(("dialect", "text"), [(d, t) for _, d, t in _STRING_CASES], ids=[n for n, _, _ in _STRING_CASES])
def test_a_pragma_inside_string_content_is_not_in_the_view(dialect: CommentDialect, text: str) -> None:
    view = _assert_invariants(text, dialect)
    assert _P not in view, f"string content leaked into the view:\n{view!r}"
    assert not pragma_present(_P, text, dialect=dialect)
    assert pragma_line_set(_P, text, dialect=dialect) == frozenset()


# --- direction 2: every documented comment form yields the pragma -----------------------------------
# (name, dialect, text, line) — the 1-based line the pragma comment sits on.
_COMMENT_CASES: list[tuple[str, CommentDialect, str, int]] = [
    ("python # comment", "python", f"x = 1  # {_P}\n", 1),
    ("python whole-line comment", "python", f"# {_P}\nx = 1\n", 1),
    ("python comment after a docstring", "python", f'"""doc"""\n# {_P}\n', 2),
    ("python comment inside brackets", "python", f"x = (\n    1,  # {_P}\n)\n", 2),
    ("js // comment", "js", f"x(); // {_P}\n", 1),
    ("js /* */ comment", "js", f"/* {_P} */ x();\n", 1),
    ("js jsdoc", "js", f"/**\n * {_P}\n */\n", 2),
    ("js regex literal then comment", "js", f"const r = /\\/\\//; // {_P}\n", 1),
    ("sql -- comment", "sql", f"-- {_P}\nSELECT 1;\n", 1),
    ("sql /* */ comment", "sql", f"/* {_P} */ SELECT 1;\n", 1),
    ("sql apostrophe in an earlier comment", "sql", f"-- don't\n-- {_P}\nSELECT 1;\n", 2),
    ("sql comment after a $$ body", "sql", f"DO $$ x $$;\n-- {_P}\n", 2),
    # #442: a `/*` inside the body used to open a phantom comment that took the body's close with
    # it, so the literal pass saw the body as unterminated and dropped every later real comment.
    ("sql comment after a $$ glob", "sql", f"SELECT $$See docs/*.md$$;\n-- {_P}\n/* note */\n", 2),
    ("sql comment after a $$ body holding --", "sql", f"SELECT $$a--b$$; -- {_P}\n", 1),
    # #1040's rule-4 side: only an identifier that closes on its own line is taken back. A stray
    # `"` pairs with the next one however far ahead (or with nothing), and every real comment in
    # between must stay visible; the cost, a multi-line identifier holding `;` and a pragma
    # phrase, is the safe direction.
    ("sql comment after an identifier holding ;", "sql", f'SELECT "x;y"; -- {_P}\n', 1),
    ("sql comment inside a stray quote's far pairing", "sql", f'SELECT "x;\n-- {_P}\nSELECT "y";\n', 2),
    ("sql comment after an unclosed quote", "sql", f'SELECT "x;\n-- {_P}\n', 2),
    ("sql comment after a stray apostrophe", "sql", f"SELECT it's;\n-- {_P}\n", 2),
    # #1040 T2: a dollar body is code to Postgres and to `strip_sql_comments`, so a real comment in
    # a `DO` or function body is one, bounded by the body: an apostrophe in it pairs only inside it,
    # and a tag with no partner is plain text, never a literal running to EOF.
    ("sql comment in a $$ function body", "sql", f"CREATE FUNCTION f() AS $$\n  -- {_P}\n$$;\n", 2),
    ("sql comment in a DO $tag$ body", "sql", f"DO $x$ -- {_P} $x$;\n", 1),
    ("sql comment in a body after a $$ glob", "sql", f"SELECT $$See docs/*.md$$;\nDO $x$ -- {_P} $x$;\n/* note */\n", 2),
    ("sql comment in a DO body on a policy", "sql", f"DO $$ BEGIN\n  CREATE POLICY p ON t USING (true); -- {_P}\nEND $$;\n", 2),
    ("sql apostrophe in a body pairs only inside it", "sql", f"DO $$ it's $$;\n-- {_P}\nSELECT 'a';\n", 2),
    ("sql comment after an unterminated $$", "sql", f"SELECT $$x;\n-- {_P}\n", 2),
    ("sql comment in a CRLF $$ body", "sql", _crlf(f"DO $$ BEGIN\n  -- {_P}\nEND $$;\n"), 2),
    ("sql comment after a mismatched tag in a body", "sql", f"DO $a$ BEGIN $b$ -- {_P}\nEND $a$;\n", 1),
    ("yaml comment line", "yaml", f"# {_P}\nfoo: bar\n", 1),
    ("yaml trailing comment", "yaml", f"foo: bar # {_P}\n", 1),
    ("yaml comment on a block scalar header", "yaml", f"run: | # {_P}\n  echo\n", 1),
    ("yaml comment after the block ends", "yaml", f"a:\n  run: |\n    echo\n  # {_P}\n", 4),
    ("yaml comment at the parent's column", "yaml", f"steps:\n  - run: |\n      echo\n  # {_P}\n", 4),
    ("yaml quoted pipe is not an indicator", "yaml", f'x: "|"\n  # {_P}\n', 2),
    ("yaml bare key is not an indicator", "yaml", f"x:\n  # {_P}\n", 2),
    ("hash comment", "hash", f"X=1 # {_P}\n", 1),
    ("hash: a block-scalar shape is not special", "hash", f"run: |\n  # {_P}\n", 2),
    ("hcl # comment", "hcl", f"x = 1 # {_P}\n", 1),
    ("hcl // comment", "hcl", f"x = 1 // {_P}\n", 1),
    ("hcl block comment", "hcl", f"/* {_P} */\n", 1),
    ("hcl quote inside a block comment", "hcl", f'/* say " */ x = 1 # {_P}\n', 1),
    ("hcl comment after a heredoc", "hcl", f"u = <<EOF\nbody\nEOF\n# {_P}\n", 4),
    ("go // comment", "go", f"// {_P}\n", 1),
    ("go /* */ comment", "go", f"/* {_P} */\n", 1),
    ("java // comment", "java", f"int x = 1; // {_P}\n", 1),
    ("java /* */ comment", "java", f"/* {_P} */\n", 1),
    ("ruby # comment", "ruby", f"x = 1 # {_P}\n", 1),
    ("ruby =begin block", "ruby", f"=begin\n{_P}\n=end\n", 2),
    ("php # comment", "php", f"<?php\n$x = 1; # {_P}\n", 2),
    ("php // comment", "php", f"<?php\n$x = 1; // {_P}\n", 2),
    ("php comment after a heredoc", "php", f"<?php\n$d = <<<EOT\nbody\nEOT;\n// {_P}\n", 5),
]


@pytest.mark.parametrize(
    ("dialect", "text", "line"), [(d, t, n) for _, d, t, n in _COMMENT_CASES], ids=[n for n, _, _, _ in _COMMENT_CASES]
)
def test_a_pragma_in_a_real_comment_is_in_the_view(dialect: CommentDialect, text: str, line: int) -> None:
    view = _assert_invariants(text, dialect)
    assert _P in view, f"a real comment was dropped from the view (rule 4):\n{view!r}"
    assert pragma_present(_P, text, dialect=dialect)
    assert pragma_line_set(_P, text, dialect=dialect) == frozenset({line})


# --- the python dialect's degrade: best-effort tokens, then a RAW tail ------------------------------

def test_python_tokens_before_a_tokenize_error_are_honoured() -> None:
    # The comment on line 1 is classified before the unterminated string on line 2 raises.
    text = f"# {_P}\ny = '''open\n"
    assert pragma_present(_P, text, dialect="python")
    # And a STRING before the error stays blanked — the partial token stream is trusted as far as
    # it goes, so the fix does not switch off wholesale on an unparseable file.
    text = f'd = "# {_P}"\ny = \'\'\'open\n'
    assert not pragma_present(_P, text, dialect="python")


def test_python_tail_past_a_tokenize_error_is_kept_raw() -> None:
    # Rule 4: a real comment AFTER the error point must still be seen. The cost is that a string
    # there suppresses too (today's behaviour on that text) — the #370 degrade, never worse than now.
    text = f"y = '''open\n# {_P}\n"
    view = _assert_invariants(text, "python")
    assert pragma_present(_P, text, dialect="python")
    assert view.endswith(f"# {_P}\n")


def test_python_eof_in_multi_line_statement_keeps_the_comment_inside() -> None:
    text = f"x = (1,\n  # {_P}\n"  # unclosed bracket: TokenError after the comment was yielded
    assert pragma_present(_P, text, dialect="python")


@pytest.mark.parametrize("newline", ["\r\n", "\r", "\x0c\n"], ids=["crlf", "lone-cr", "form-feed"])
def test_python_rows_survive_non_lf_line_breaks(newline: str) -> None:
    # tokenize counts only `\n` as a row; a lone `\r` ends the comment but not the row and a form
    # feed is a bare line. The line-start table indexes `text.split("\n")`, so all three line up.
    text = f"a = 1  # first{newline}b = 2  # {_P}\n"
    view = _assert_invariants(text, "python")
    assert _P in view
    assert view.index(_P) == text.index(_P), "the pragma must sit at its own offset"


# --- documented residuals, pinned by direction so a reader knows which way each one fails ----------

def test_sql_copy_data_rows_read_as_comment_is_the_more_view_residual() -> None:
    # `strip_sql_comments` blanks the rows of a terminated COPY section (#528), and the view cannot
    # tell a blanked row from a blanked comment. MORE view: a pragma phrase in dump data could still
    # suppress — the FN direction, exactly today's behaviour on that text, never a dropped comment.
    text = f"COPY t (c) FROM stdin;\n# {_P}\n\\.\n"
    assert pragma_present(_P, text, dialect="sql")


def test_sql_dollar_string_that_is_not_a_body_reads_as_code_is_the_more_view_residual() -> None:
    # #1040 T2: every terminated dollar span is a body to the view, as it is to `strip_sql_comments`,
    # so a pragma phrase in a dollar-quoted STRING (not a function or DO body) reads as a comment.
    # MORE view: the FN direction, the raw match these guards ran before, never a dropped comment.
    assert pragma_present(_P, f"COMMENT ON TABLE t IS $$-- {_P}$$;\n", dialect="sql")


def test_hash_long_line_is_classified_like_a_short_one() -> None:
    # A >1 KB line used to be kept RAW here, because the quote mask was capped at 1 KB. The mask is
    # linear now (#508), so a long line gets the short-line answer both ways: a real comment opt-out
    # still suppresses (rule 4: the narrower view must not void it), and pragma text inside a quoted
    # value no longer does, exactly as on a short line.
    pad = "a" * 1100
    real = f"x={pad} # {_P}\n"
    quoted = f'x: "{pad} # {_P}"\n'
    assert _hash_comment_start(real.rstrip("\n")) == len(f"x={pad}")
    for dialect in ("hash", "yaml"):
        assert pragma_present(_P, real, dialect=dialect)
        assert not pragma_present(_P, quoted, dialect=dialect)


def test_blanked_code_is_whitespace_so_a_line_anchored_pattern_sees_a_trailing_comment() -> None:
    # The one semantic the space-fill changes, stated in the docstring: a `^\s*#…` pattern under
    # MULTILINE matches a trailing comment on a code line of the view. A guard that means
    # "whole-line comment only" keeps that test on its raw line.
    text = f"x = 1  # {_P}\n"
    anchored = re.compile(r"^\s*#\s*security:\s*allow-i424-probe", re.MULTILINE)
    assert anchored.search(text) is None
    assert pragma_present(anchored, text, dialect="python")


# --- the check helpers ---------------------------------------------------------------------------

def test_pragma_present_takes_a_compiled_pattern_too() -> None:
    assert pragma_present(_PAT, f"x = 1  # {_P}\n", dialect="python")
    assert not pragma_present(_PAT, f'd = "# {_P}"\n', dialect="python")


def test_pragma_line_set_numbers_lines_the_way_splitlines_does() -> None:
    text = f"a = 1\r\nb = 2  # {_P}\r\n\r\nc = 3  # {_P}\n"
    assert pragma_line_set(_P, text, dialect="python") == frozenset({2, 4})
    assert pragma_line_set(_PAT, text, dialect="python") == frozenset({2, 4})
    assert pragma_line_set(_P, "", dialect="python") == frozenset()


@pytest.mark.parametrize("dialect", _DIALECTS)
def test_every_dialect_is_total_on_hostile_input(dialect: CommentDialect) -> None:
    # Unterminated everything, in every grammar at once. Must never raise, and must keep the
    # same-length / line-count invariant, because a guard calls this on files it did not write.
    hostile = (
        "'''\n\"\"\"\n`\n/*\n<<EOF\n$$\n=begin\n\"unclosed\n'unclosed\nkey: |\n  - |\n\\\n"
        "\x0c\n\r\n\u2028x\u2029y\n# " + _P + "\n"
    )
    for text in (hostile, hostile * 3, "", "\n", "\r\n", "#", "a"):
        _assert_invariants(text, dialect)


def test_unknown_dialect_is_a_programming_error() -> None:
    with pytest.raises(KeyError):
        comment_view("x = 1\n", "cobol")  # type: ignore[arg-type]


# --- memoisation under derived_state_run (issue #544) ------------------------------------------------

def test_comment_view_is_memoised_only_inside_a_derived_state_run_scope() -> None:
    text = f"x = 1  # {_P}\n"
    outside_a = comment_view(text, "python")
    outside_b = comment_view(text, "python")
    assert outside_a == outside_b and outside_a is not outside_b, "no scope: always recomputed"
    assert _comment_view_cache == {}
    with derived_state_run():
        inside_a = comment_view(text, "python")
        inside_b = comment_view(text, "python")
        assert inside_a is inside_b, "inside the scope the second call is served from the table"
        # Keyed on the dialect as well as the text: the same text has one view PER dialect.
        other = comment_view(text, "hash")
        assert other is not inside_a
        assert set(_comment_view_cache) == {(text, "python"), (text, "hash")}
    assert _comment_view_cache == {}, "leaving the outermost scope clears the table"


# --- the strip_hash_comments refactor is behaviour-identical --------------------------------------

@pytest.mark.parametrize(
    "line",
    [
        "a: 1 # c",
        "b: 'x # y' # d",
        'msg: "Info #1: {{ secret }}"',
        "# only",
        "  # indented",
        "plain",
        "",
        "x=" + "a" * 2000 + " # over-long, masked like any other line",
        "msg: don't fail # it's fine",
    ],
)
def test_hash_comment_start_is_the_decision_strip_hash_comments_truncates_at(line: str) -> None:
    cut = _hash_comment_start(line)
    assert strip_hash_comments(line) == (line if cut == -1 else line[:cut])


# --- the per-path dialect helper and the raw fallback (E1: mixed-suffix guards) ---------------------

@pytest.mark.parametrize(
    ("path", "dialect"),
    [
        ("app/main.py", "python"), ("x.pyi", "python"),
        ("src/a.js", "js"), ("a.jsx", "js"), ("a.ts", "js"), ("a.tsx", "js"), ("a.mjs", "js"), ("a.cjs", "js"),
        ("sql/schema.sql", "sql"),
        ("docker-compose.yml", "yaml"), (".github/workflows/ci.yaml", "yaml"),
        ("infra/main.tf", "hcl"), ("a.hcl", "hcl"), ("prod.tfvars", "hcl"),
        ("main.go", "go"), ("index.php", "php"), ("App.java", "java"), ("app.rb", "ruby"),
        ("pyproject.toml", "hash"), ("setup.cfg", "hash"), ("tox.ini", "hash"), ("nginx.conf", "hash"),
        (".env", "hash"), (".env.production", "hash"), ("deploy.sh", "hash"), ("x.bash", "hash"),
        ("Dockerfile", "hash"), ("Dockerfile.dev", "hash"), ("service.dockerfile", "hash"), ("Containerfile", "hash"),
        ("requirements.txt", "hash"), ("requirements-dev.txt", "hash"), ("constraints.txt", "hash"), (".npmrc", "hash"),
        ("package.json", None), ("README.md", None), ("notes.txt", None), ("key.pem", None), ("a.svg", None), ("x", None),
        # #990 review H1: a real extension wins over the Dockerfile / `.env` NAME heuristic, which
        # answers only for names the table cannot (under `hash`, a `#` line inside these files'
        # docstrings would have read as a comment).
        ("dockerfile_generator.py", "python"), ("dockerfile_test.go", "go"), ("DockerfileUtils.js", "js"),
        (".environment.py", "python"),
        # #990 review M1: Kotlin shares Java's comment grammar; Rust is deliberately unmapped (a
        # lifetime `'a` would open a phantom char literal in the Java lexer and hide a `//` pragma).
        ("Main.kt", "java"), ("lib.rs", None),
    ],
)
def test_comment_dialect_for_maps_the_file_name(path: str, dialect: CommentDialect | None) -> None:
    from agentsec.guards.base import comment_dialect_for
    assert comment_dialect_for(path) == dialect
    assert comment_dialect_for(Path(path)) == dialect


def test_a_python_file_named_like_a_dockerfile_keeps_its_docstring_out_of_the_view() -> None:
    # The end-to-end shape of #990 H1: the dialect the name resolves to must be the one that reads
    # a docstring as content.
    from agentsec.guards.base import comment_dialect_for
    text = f'"""Opt out with\n    # {_P}\n"""\nx = 1\n'
    assert not pragma_present(_P, text, dialect=comment_dialect_for("tools/dockerfile_generator.py"))
    assert pragma_present(_P, f"x = 1  # {_P}\n", dialect=comment_dialect_for("tools/dockerfile_generator.py"))


def test_kotlin_reads_under_the_java_dialect_in_both_directions() -> None:
    from agentsec.guards.base import comment_dialect_for
    kt = comment_dialect_for("app/src/main/Main.kt")
    assert not pragma_present(_P, f'val help = "// {_P}"\n', dialect=kt)
    assert pragma_present(_P, f"val x = 1 // {_P}\n", dialect=kt)


def test_dialect_none_matches_the_raw_text() -> None:
    # A grammar with no comment dialect keeps today's behaviour: the phrase anywhere counts (more
    # view, never a dropped comment) — so a mixed-suffix guard adopting `comment_dialect_for` loses
    # nothing on its `.json`/`.md` files.
    text = f'{{"note": "# {_P}"}}\n'
    assert pragma_present(_P, text, dialect=None)
    assert pragma_line_set(_P, text, dialect=None) == frozenset({1})
    assert not pragma_present(_P, "{}\n", dialect=None)
