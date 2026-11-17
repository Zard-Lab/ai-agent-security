"""Unit tests for the SQL GRANT/REVOKE reading helpers in `guards/base.py` (#1096, #1100):
`sql_role_names`, `sql_execute_literals` and `blank_sql_literals_nested`.

The guard tests reach these only through `definer-function-grants` and `matview-exposed`, which
leaves the helpers' own edges (E-strings, unterminated literals, nested dollar bodies) unpinned
(#1100 R2-L2). Both directions throughout: what a view must hide, and what it must keep visible.
"""
from __future__ import annotations

from agentsec.guards.base import blank_sql_literals_nested, sql_execute_literals, sql_role_names
from tests._timing import assert_growth

# --- sql_role_names ------------------------------------------------------------------------------


def test_role_names_reads_the_whole_list_and_cuts_the_trailing_clauses() -> None:
    assert sql_role_names('PUBLIC, "anon" CASCADE;') == {"public", "anon"}
    assert sql_role_names("GROUP authenticated, service_role GRANTED BY postgres;") == {
        "authenticated", "service_role",
    }


def test_role_names_matches_whole_roles_only() -> None:
    assert sql_role_names("public_role, anon;") == {"public_role", "anon"}


# --- sql_execute_literals ------------------------------------------------------------------------


def test_execute_literals_returns_each_literal_with_doubled_quotes_folded() -> None:
    sql = (
        "DO $$ BEGIN EXECUTE 'REVOKE ALL ON FUNCTION f() FROM anon'; "
        "EXECUTE format('COMMENT ON TABLE t IS ''it''''s''') ; END $$;"
    )
    assert sql_execute_literals(sql) == [
        "REVOKE ALL ON FUNCTION f() FROM anon",
        "COMMENT ON TABLE t IS 'it''s'",
    ]


def test_execute_literals_keeps_an_e_string_backslash_as_written() -> None:
    # The pairing honours the escape (the literal does not end at `\'`); the text is not unescaped.
    assert sql_execute_literals(r"EXECUTE E'REVOKE ALL ON t FROM \'anon\'';") == [
        r"REVOKE ALL ON t FROM \'anon\'"
    ]


def test_execute_literals_skips_an_unterminated_literal() -> None:
    assert sql_execute_literals("EXECUTE 'REVOKE ALL ON t FROM anon") == []


def test_execute_literals_ignores_grant_execute_and_a_non_literal_argument() -> None:
    assert sql_execute_literals("GRANT EXECUTE ON FUNCTION f() TO anon; EXECUTE stmt;") == []


# --- blank_sql_literals_nested -------------------------------------------------------------------


def _check(sql: str) -> str:
    view = blank_sql_literals_nested(sql)
    assert len(view) == len(sql) and view.count("\n") == sql.count("\n")
    return view


def test_nested_view_blanks_a_quoted_statement_at_every_level() -> None:
    view = _check("RAISE NOTICE 'revoke x'; DO $$ BEGIN RAISE NOTICE 'revoke y'; END $$;")
    assert "revoke" not in view
    assert "RAISE NOTICE" in view and "BEGIN" in view


def test_nested_view_keeps_a_dollar_body_visible() -> None:
    view = _check("DO $$ BEGIN REVOKE ALL ON t FROM anon; END $$;")
    assert "REVOKE ALL ON t FROM anon" in view


def test_nested_view_caps_a_lone_apostrophe_at_its_own_dollar_body() -> None:
    # #1100 R2-M1: the apostrophe in `Don't` must not blank the REVOKE that follows the COMMENT.
    view = _check("COMMENT ON TABLE t IS $$Don't expose$$;\nREVOKE ALL ON t FROM anon;\n")
    assert "REVOKE ALL ON t FROM anon" in view


def test_nested_view_reads_an_inner_dollar_tag_inside_an_outer_body() -> None:
    sql = (
        "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $fn$ BEGIN\n"
        "  RAISE NOTICE $m$it's$m$;\n  RAISE NOTICE 'revoke hidden';\nEND $fn$;\n"
        "REVOKE ALL ON t FROM anon;\n"
    )
    view = _check(sql)
    assert "REVOKE ALL ON t FROM anon" in view
    assert "revoke hidden" not in view


def test_nested_view_still_blanks_a_literal_after_an_unclosed_dollar_tag() -> None:
    # An opener with no close is plain text, not a body that swallows the rest of the file.
    view = _check("SELECT $x$ 1; RAISE NOTICE 'revoke z';")
    assert "revoke z" not in view and "SELECT $x$ 1" in view


def test_nested_view_is_linear_on_hostile_dollar_input() -> None:
    """Guards scan attacker-controlled SQL: a flood of distinct unclosed tags (a per-opener
    `str.find` would be O(n^2)), deep nesting (recursion would overflow) and a lone apostrophe in
    every body (each one fails to close) must all stay linear."""
    sizes = [2000, 4000, 8000, 16000]
    cases = {
        "unclosed": {n: "".join(f"$t{i}$ " for i in range(n)) for n in sizes},
        "nested": {
            n: "".join(f"$t{i}$" for i in range(n)) + "x" + "".join(f"$t{i}$" for i in reversed(range(n)))
            for n in sizes
        },
        "apostrophes": {n: "$$ ' $$ " * n for n in sizes},
    }
    for texts in cases.values():
        def scan(n: int, texts: dict[int, str] = texts) -> None:
            blank_sql_literals_nested(texts[n])

        assert_growth(scan, sizes, expected="linear")
