from __future__ import annotations

import pytest

from agentsec.guards.pg_function_search_path import PgFunctionSearchPathGuard
from tests.guards._common import *  # noqa: F401,F403


def test_pg_function_search_path_flags_missing(tmp_path: Path) -> None:
    (tmp_path / "funcs.sql").write_text(
        "CREATE FUNCTION get_secret() RETURNS text LANGUAGE plpgsql"
        " SECURITY DEFINER AS $$ BEGIN RETURN secret; END; $$;",
        encoding="utf-8",
    )
    findings = PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path))
    assert len(findings) >= 1
    assert findings[0].rule == "pg-function-search-path/security-definer-no-search-path"
    assert findings[0].severity == "high"

def test_pg_function_search_path_silent_with_set_search_path(tmp_path: Path) -> None:
    (tmp_path / "funcs.sql").write_text(
        "CREATE FUNCTION safe_fn() RETURNS void LANGUAGE plpgsql"
        " SECURITY DEFINER SET search_path = public, pg_temp"
        " AS $$ BEGIN END; $$;",
        encoding="utf-8",
    )
    findings = PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path))
    assert findings == []

def test_pg_function_search_path_pragma_silences(tmp_path: Path) -> None:
    content = (
        "-- security: allow-pg-definer-search-path\n"
        "CREATE FUNCTION get_secret() RETURNS text LANGUAGE plpgsql"
        " SECURITY DEFINER AS $$ BEGIN RETURN secret; END; $$;\n"
    )
    (tmp_path / "funcs.sql").write_text(content, encoding="utf-8")
    findings = PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path))
    assert findings == []

def test_pg_function_search_path_not_applies_without_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python", "fastapi"})
    assert PgFunctionSearchPathGuard().applies(prof) is False

def test_pg_function_search_path_applies_supabase(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"supabase"})
    assert PgFunctionSearchPathGuard().applies(prof) is True

def test_pg_function_search_path_adjacent_pinned_function_does_not_vouch(tmp_path: Path) -> None:
    # Regression (issue #422 S6): the flat +/-500-char window crossed into the NEXT function,
    # so an adjacent function's SET search_path suppressed an unpinned SECURITY DEFINER.
    (tmp_path / "funcs.sql").write_text(
        "CREATE FUNCTION unpinned() RETURNS void LANGUAGE plpgsql\n"
        "SECURITY DEFINER\n"
        "AS $$ BEGIN END; $$;\n"
        "\n"
        "CREATE FUNCTION pinned() RETURNS void LANGUAGE plpgsql\n"
        "SECURITY DEFINER SET search_path = public, pg_temp\n"
        "AS $$ BEGIN END; $$;\n",
        encoding="utf-8",
    )
    findings = PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-function-search-path/security-definer-no-search-path"
    assert findings[0].location.endswith(":2")

def test_pg_function_search_path_preceding_pinned_function_does_not_vouch(tmp_path: Path) -> None:
    # Same boundary bug in the backward direction: a PRECEDING function's SET search_path
    # must not vouch for the unpinned function that follows it.
    (tmp_path / "funcs.sql").write_text(
        "CREATE FUNCTION pinned() RETURNS void LANGUAGE plpgsql\n"
        "SECURITY DEFINER SET search_path = public, pg_temp\n"
        "AS $$ BEGIN END; $$;\n"
        "\n"
        "CREATE FUNCTION unpinned() RETURNS void LANGUAGE plpgsql\n"
        "SECURITY DEFINER\n"
        "AS $$ BEGIN END; $$;\n",
        encoding="utf-8",
    )
    findings = PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":6")

def test_pg_function_search_path_or_replace_variant(tmp_path: Path) -> None:
    (tmp_path / "v2.sql").write_text(
        "CREATE OR REPLACE FUNCTION update_user_meta()\n"
        "RETURNS void LANGUAGE plpgsql\n"
        "SECURITY DEFINER\n"
        "AS $$ BEGIN UPDATE users SET meta = '{}'; END; $$;",
        encoding="utf-8",
    )
    findings = PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path))
    assert len(findings) >= 1
    assert findings[0].rule == "pg-function-search-path/security-definer-no-search-path"



def test_pgsp_alter_after_another_function_still_counts(tmp_path: Path) -> None:
    # Regression (#437 review): cutting the look-forward at the next CREATE FUNCTION also
    # discarded an `ALTER FUNCTION … SET search_path` sitting past it — so a function hardened
    # by the guard's OWN recommended remediation fired a false HIGH. An ALTER names the
    # function it hardens, so it is now matched by name, file-wide.
    (tmp_path / "0001.sql").write_text(
        "CREATE FUNCTION f1() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql SECURITY DEFINER;\n"
        "CREATE FUNCTION f2() RETURNS int AS $$ SELECT 2 $$ LANGUAGE sql;\n"
        "ALTER FUNCTION f1() SET search_path = '';\n",
        encoding="utf-8",
    )
    assert PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path)) == []


def test_pgsp_alter_naming_a_different_function_does_not_vouch(tmp_path: Path) -> None:
    # FP-bait for the above, and a pre-existing hole the same change closes: an ALTER hardening
    # some OTHER function used to vouch for this one just by landing inside the window. ALTERs
    # are now blanked out of the window text, so proximity alone proves nothing.
    (tmp_path / "0001.sql").write_text(
        "CREATE FUNCTION f1() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql SECURITY DEFINER;\n"
        "ALTER FUNCTION f2() SET search_path = '';\n",
        encoding="utf-8",
    )
    assert len(PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path))) == 1


def test_pgsp_neighbour_inline_setting_does_not_vouch(tmp_path: Path) -> None:
    # FP-bait: the window bound exists to stop an adjacent function's INLINE `SET search_path`
    # vouching for this one. That must survive the ALTER change.
    (tmp_path / "0001.sql").write_text(
        "CREATE FUNCTION f1() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql SECURITY DEFINER;\n"
        "CREATE FUNCTION f2() RETURNS int AS $$ SELECT 2 $$ LANGUAGE sql SET search_path = '';\n",
        encoding="utf-8",
    )
    assert len(PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path))) == 1


# --- #442: line numbers below a multi-line block comment ----------------------------------------

_LICENSE_HEADER = "/* license\n a\n b\n c\n*/\n"  # 5 lines, so the next line is 6


@pytest.mark.parametrize(
    "definer",
    ["SECURITY DEFINER", "SECURITY /* inline */ DEFINER"],
    ids=["plain", "inline-comment-inside-the-phrase"],
)
def test_pgsp_line_below_block_comment_header_is_the_raw_line(tmp_path: Path, definer: str) -> None:
    # Delete-mode stripping drops a `/* … */` block WITH its newlines, so this reported `funcs.sql:3`
    # for a SECURITY DEFINER on raw line 7 (#442).
    (tmp_path / "funcs.sql").write_text(
        _LICENSE_HEADER
        + "CREATE FUNCTION f() RETURNS void LANGUAGE sql\n"
        + f"{definer} AS $$ select 1 $$;\n",
        encoding="utf-8",
    )
    findings = PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path))
    assert [f.location.endswith(":7") for f in findings] == [True]


def test_pgsp_two_definers_around_a_block_comment_report_their_own_lines(tmp_path: Path) -> None:
    # A block comment BETWEEN two definers shifted only the second one on the pre-fix code.
    (tmp_path / "funcs.sql").write_text(
        "CREATE FUNCTION f() RETURNS void LANGUAGE sql\n"
        "SECURITY DEFINER AS $$ select 1 $$;\n"
        "/* a\n b\n c\n*/\n"
        "CREATE FUNCTION g() RETURNS void LANGUAGE sql\n"
        "SECURITY DEFINER AS $$ select 1 $$;\n",
        encoding="utf-8",
    )
    findings = PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path))
    assert [f.location.rsplit(":", 1)[1] for f in findings] == ["2", "8"]


def test_pgsp_window_is_measured_on_stripped_text_so_long_body_comments_still_fire(tmp_path: Path) -> None:
    # The window non-regression that rejects the naive `strip_sql_comments(raw, blank=True)` swap:
    # blanked comments would count against the 500-char look-back, push `CREATE FUNCTION` out of it,
    # and the guard would skip this unhardened definer silently. Detection stays on delete mode.
    note = "  -- " + "x" * 120 + "\n"
    (tmp_path / "f.sql").write_text(
        "CREATE FUNCTION public.f() RETURNS void\nLANGUAGE plpgsql\nAS $$\nBEGIN\n"
        + note * 5
        + "  PERFORM 1;\nEND;\n$$ SECURITY DEFINER;\n",
        encoding="utf-8",
    )
    findings = PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path))
    assert [f.location.endswith(":12") for f in findings] == [True]


def test_pgsp_comment_welded_inside_the_phrase_leaves_the_other_definers_line_exact(tmp_path: Path) -> None:
    # `SECURITY/**/DEFINER` matches once blanked but not once deleted, so the two match lists differ
    # in length. g's definer still has its blanked counterpart at the same code position, so it keeps
    # its exact raw line (5) below the block comment, where the old whole-file fallback read 4.
    (tmp_path / "funcs.sql").write_text(
        "/* a\nb */\n"
        "CREATE FUNCTION f() RETURNS int LANGUAGE sql SECURITY/**/DEFINER AS $$ select 1 $$;\n"
        "CREATE FUNCTION g() RETURNS int LANGUAGE sql\n"
        "SECURITY DEFINER AS $$ select 1 $$;\n",
        encoding="utf-8",
    )
    findings = PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path))
    assert [f.location.endswith(":5") for f in findings] == [True]


def test_pgsp_opposite_welds_do_not_swap_two_definers_lines(tmp_path: Path) -> None:
    # #1006 round-1 M1: pairing the k-th match in each text trusted equal counts to mean equal
    # order. A comment inside a word matches only once DELETED (`DEF/**/INER`), one between the words
    # only once BLANKED (`SECURITY/**/DEFINER`); one of each cancels out in the count, and a and c
    # took the lines of c and b (5 and 7). Matches now pair by code position. a has no blanked
    # counterpart, so it keeps the stripped-text count (2, exact here: no block comment above it);
    # c, below a multi-line comment, gets its exact raw line 5 where that count would read 4.
    (tmp_path / "funcs.sql").write_text(
        "CREATE FUNCTION a() RETURNS void LANGUAGE sql\n"
        "SECURITY DEF/**/INER AS $$ select 1 $$;\n"
        "CREATE FUNCTION c() RETURNS void LANGUAGE sql\n"
        "/* x\n*/ SECURITY DEFINER AS $$ select 1 $$;\n"
        "CREATE FUNCTION b() RETURNS void LANGUAGE sql\n"
        "SECURITY/**/DEFINER AS $$ select 1 $$;\n",
        encoding="utf-8",
    )
    findings = PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path))
    assert [f.location.rsplit(":", 1)[1] for f in findings] == ["2", "5"]


# --- #442 phase 2: a `/*` inside a dollar-quoted body cannot hide the SQL after it -------------
# Both directions: this guard detects a definer AND credits a hardening statement, so a hidden
# definer was a silent miss and a hidden `ALTER FUNCTION … SET search_path` a false HIGH.

_I442_DEFINER = "CREATE FUNCTION f() RETURNS void LANGUAGE sql\nSECURITY DEFINER AS $fn$ select 1 $fn$;\n"
_I442_ALTER = "ALTER FUNCTION f() SET search_path = '';"


def _pgsp_lines(tmp_path: Path, sql: str) -> list[str]:
    (tmp_path / "f.sql").write_text(sql, encoding="utf-8")
    return [f.location.rsplit(":", 1)[1] for f in PgFunctionSearchPathGuard().run(tmp_path, _pgsp_prof(tmp_path))]


def test_pgsp_definer_after_a_dollar_quoted_glob_still_fires(tmp_path: Path) -> None:
    assert _pgsp_lines(tmp_path, _dollar_glob_sandwich(_I442_DEFINER)) == ["3"]


def test_pgsp_definer_commented_out_inside_a_do_body_is_silent(tmp_path: Path) -> None:
    definer = "CREATE FUNCTION g() RETURNS void LANGUAGE sql SECURITY DEFINER AS 'select 1';"
    assert _pgsp_lines(tmp_path, _dollar_glob_sandwich(_do_commented_out(definer))) == []


def test_pgsp_alter_after_a_dollar_quoted_glob_is_credited(tmp_path: Path) -> None:
    assert _pgsp_lines(tmp_path, _I442_DEFINER + _dollar_glob_sandwich(_I442_ALTER)) == []


def test_pgsp_alter_commented_out_inside_a_do_body_is_not_credited(tmp_path: Path) -> None:
    # Rule 1 for the credit above: a hardening statement that is only commented out is not one.
    assert _pgsp_lines(tmp_path, _I442_DEFINER + _dollar_glob_sandwich(_do_commented_out(_I442_ALTER))) == ["2"]
