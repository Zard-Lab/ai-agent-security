from __future__ import annotations

from collections.abc import Callable

import pytest

from agentsec.guards.pg_security_definer_view import PgSecurityDefinerViewGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def test_pg_security_definer_view_flags_missing_invoker(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "CREATE VIEW public.user_data WITH (security_barrier = true) AS SELECT * FROM users;",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"supabase", "postgres"})
    findings = PgSecurityDefinerViewGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "pg-security-definer-view/view-without-security-invoker"
    assert findings[0].severity == "high"

def test_pg_security_definer_view_silent_with_option(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "CREATE VIEW public.user_data WITH (security_invoker = true, security_barrier = true) "
        "AS SELECT * FROM users;",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"supabase", "postgres"})
    findings = PgSecurityDefinerViewGuard().run(tmp_path, profile)
    assert findings == []

def test_pg_security_definer_view_silent_security_invoker_clause(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "CREATE OR REPLACE VIEW v WITH (security_barrier = true) SECURITY INVOKER AS SELECT 1;",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"supabase", "postgres"})
    findings = PgSecurityDefinerViewGuard().run(tmp_path, profile)
    assert findings == []

def test_pg_security_definer_view_pragma_silences(tmp_path: Path) -> None:
    content = (
        "CREATE VIEW public.user_data WITH (security_barrier = true) AS SELECT * FROM users;\n"
        "-- security: allow-security-definer-view\n"
    )
    (tmp_path / "schema.sql").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"supabase", "postgres"})
    findings = PgSecurityDefinerViewGuard().run(tmp_path, profile)
    assert findings == []

def test_pg_security_definer_view_not_applies_no_postgres(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "CREATE VIEW public.user_data AS SELECT * FROM users;",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    assert PgSecurityDefinerViewGuard().applies(profile) is False

def test_pg_security_definer_view_or_replace_fires(tmp_path: Path) -> None:
    (tmp_path / "migration.sql").write_text(
        "CREATE OR REPLACE VIEW public.user_data WITH (security_barrier = true) "
        "AS SELECT id, email FROM users;",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"postgres"})
    findings = PgSecurityDefinerViewGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "pg-security-definer-view/view-without-security-invoker"


# --- security_barrier (pgrls VIEW002) ---------------------------------------

def test_pg_security_definer_view_flags_missing_barrier(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "CREATE VIEW public.user_data WITH (security_invoker = true) AS SELECT * FROM users;",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"supabase", "postgres"})
    findings = PgSecurityDefinerViewGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "pg-security-definer-view/view-without-security-barrier"
    assert findings[0].severity == "medium"

def test_pg_security_definer_view_missing_both_fires_both(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "CREATE VIEW public.user_data AS SELECT * FROM users;",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"supabase", "postgres"})
    findings = PgSecurityDefinerViewGuard().run(tmp_path, profile)
    rules = {f.rule for f in findings}
    assert rules == {
        "pg-security-definer-view/view-without-security-invoker",
        "pg-security-definer-view/view-without-security-barrier",
    }

def test_pg_security_definer_view_barrier_pragma_silences_only_barrier(tmp_path: Path) -> None:
    content = (
        "CREATE VIEW public.user_data AS SELECT * FROM users;\n"
        "-- security: allow-security-barrier-missing\n"
    )
    (tmp_path / "schema.sql").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"supabase", "postgres"})
    findings = PgSecurityDefinerViewGuard().run(tmp_path, profile)
    # The barrier finding is suppressed, but the independent invoker finding still fires --
    # the two pragmas are deliberately separate since the two defenses are independent.
    assert len(findings) == 1
    assert findings[0].rule == "pg-security-definer-view/view-without-security-invoker"


# --- #442: comment-blanked detection, statement-bounded window, ALTER VIEW credit ----------------

_INVOKER = "pg-security-definer-view/view-without-security-invoker"
_BARRIER = "pg-security-definer-view/view-without-security-barrier"
_HARDENED = "WITH (security_invoker = true, security_barrier = true)"


def _pgsdv_run(tmp_path: Path, sql: str) -> list[tuple[str, str]]:
    (tmp_path / "v.sql").write_text(sql, encoding="utf-8")
    findings = PgSecurityDefinerViewGuard().run(tmp_path, mkprofile(tmp_path, features={"supabase", "postgres"}))
    return [(f.rule, f.location.rsplit(":", 1)[1]) for f in findings]


@pytest.mark.parametrize(
    "sql",
    [
        # The flagship shapes verbatim: comment PROSE that reads as a CREATE VIEW head.
        "-- Step 2.2: Create view to join embedding models with decrypted API keys\n",
        "-- Step 1.2: Create view for decrypted access (service_role only)\n",
        "SELECT 1; -- CREATE VIEW v AS SELECT 1;\n",
        "/* CREATE VIEW v AS SELECT 1; */\n",
        # The flagship's `04-security-hardening.sql` "UNCOMMENT WHEN READY" block shape.
        "/*\nDROP VIEW IF EXISTS v;\n\nCREATE VIEW v AS\nSELECT 1;\n*/\n",
    ],
    ids=["flagship-prose-1", "flagship-prose-2", "trailing", "single-line-block", "multi-line-block"],
)
def test_pgsdv_commented_out_view_is_silent(tmp_path: Path, sql: str) -> None:
    assert _pgsdv_run(tmp_path, sql) == []


def test_pgsdv_live_view_below_comment_prose_still_fires_on_its_own_line(tmp_path: Path) -> None:
    # The flagship shape: the prose line above fired a duplicate HIGH + MEDIUM; the real view must
    # keep both of its own.
    sql = (
        "-- Step 2.2: Create view to join embedding models with decrypted API keys\n"
        "CREATE OR REPLACE VIEW embedding_models_with_keys AS -- service_role only\n"
        "SELECT 1;\n"
    )
    assert sorted(_pgsdv_run(tmp_path, sql)) == [(_BARRIER, "2"), (_INVOKER, "2")]


def test_pgsdv_neighbouring_hardened_view_does_not_vouch_for_an_unhardened_one(tmp_path: Path) -> None:
    # The FN the fixed 10-line window had: v2's options sat inside v1's window and silenced v1.
    sql = f"CREATE VIEW v1 AS\nSELECT 1;\n\nCREATE VIEW v2 {_HARDENED} AS\nSELECT 2;\n"
    assert sorted(_pgsdv_run(tmp_path, sql)) == [(_BARRIER, "1"), (_INVOKER, "1")]


def test_pgsdv_option_more_than_ten_lines_into_the_statement_is_credited(tmp_path: Path) -> None:
    # The FP the fixed window had: a long column list pushes the WITH clause past line 10.
    columns = ",\n".join(f"  c{i}" for i in range(12))
    sql = f"CREATE VIEW v (\n{columns}\n) {_HARDENED} AS\nSELECT {', '.join(str(i) for i in range(12))};\n"
    assert _pgsdv_run(tmp_path, sql) == []


@pytest.mark.parametrize("gap", [0, 15], ids=["adjacent", "beyond-the-old-10-line-window"])
def test_pgsdv_name_matched_alter_view_hardens_the_view(tmp_path: Path, gap: int) -> None:
    # The adjacent case is the credit the old window gave and the statement bound alone would have
    # dropped (a new FP on correctly hardened views); the distant one it never gave.
    sql = (
        "CREATE VIEW public.v AS\nSELECT 1;\n"
        + "\n" * gap
        + 'ALTER VIEW "public"."v" SET (security_invoker = true, security_barrier = true);\n'
    )
    assert _pgsdv_run(tmp_path, sql) == []


@pytest.mark.parametrize(
    "alter",
    [
        "ALTER VIEW other SET (security_invoker = true, security_barrier = true);\n",
        "ALTER VIEW v SET (security_invoker = false, security_barrier = false);\n",
        "-- ALTER VIEW v SET (security_invoker = true, security_barrier = true);\n",
        "ALTER VIEW v OWNER TO postgres;\n",
    ],
    ids=["different-view", "flags-off", "commented-out", "not-a-set"],
)
def test_pgsdv_alter_view_that_does_not_harden_this_view_is_not_credited(tmp_path: Path, alter: str) -> None:
    sql = "CREATE VIEW v AS\nSELECT 1;\n" + alter
    assert sorted(_pgsdv_run(tmp_path, sql)) == [(_BARRIER, "1"), (_INVOKER, "1")]


def test_pgsdv_alter_before_a_create_or_replace_is_not_credited(tmp_path: Path) -> None:
    # `CREATE OR REPLACE VIEW` replaces the view's options, so an ALTER that ran before it no longer
    # applies to the view it produces.
    sql = (
        "ALTER VIEW v SET (security_invoker = true, security_barrier = true);\n"
        "CREATE OR REPLACE VIEW v AS\nSELECT 1;\n"
    )
    assert sorted(_pgsdv_run(tmp_path, sql)) == [(_BARRIER, "2"), (_INVOKER, "2")]


def test_pgsdv_alter_view_credits_only_the_flag_it_sets(tmp_path: Path) -> None:
    sql = "CREATE VIEW v AS\nSELECT 1;\nALTER VIEW v SET (security_barrier = true);\n"
    assert _pgsdv_run(tmp_path, sql) == [(_INVOKER, "1")]


@pytest.mark.parametrize(
    "undo",
    [
        "ALTER VIEW v SET (security_invoker = false, security_barrier = false);\n",
        "ALTER VIEW IF EXISTS public.v SET (security_invoker = 'off', security_barrier = 0);\n",
        "ALTER VIEW v RESET (security_invoker, security_barrier);\n",
    ],
    ids=["set-false", "set-off-spellings", "reset"],
)
def test_pgsdv_later_alter_turning_the_flags_off_revokes_the_credit(tmp_path: Path, undo: str) -> None:
    # #1006 round-1 H1: the credit kept the last ALTER turning a flag ON and ignored one turning it
    # back off, so a view hardened and then un-hardened in the same file passed silently. The last
    # ALTER that touches a flag is that flag's final word.
    sql = (
        "CREATE VIEW v AS\nSELECT 1;\n"
        "ALTER VIEW v SET (security_invoker = true, security_barrier = true);\n" + undo
    )
    assert sorted(_pgsdv_run(tmp_path, sql)) == [(_BARRIER, "1"), (_INVOKER, "1")]


@pytest.mark.parametrize(
    ("undo", "fires"),
    [
        ("ALTER VIEW v SET (security_invoker = off);\n", [(_INVOKER, "1")]),
        ("ALTER VIEW v RESET (security_barrier);\n", [(_BARRIER, "1")]),
    ],
    ids=["invoker-off", "barrier-reset"],
)
def test_pgsdv_later_alter_turning_a_flag_off_overrides_the_views_own_option(
    tmp_path: Path, undo: str, fires: list[tuple[str, str]]
) -> None:
    # The same final-word rule over the CREATE's own WITH options (silent on main too: the old
    # 10-line window credited the option and never read an ALTER). Only the flag the ALTER turns
    # off is revoked.
    assert _pgsdv_run(tmp_path, f"CREATE VIEW v {_HARDENED} AS\nSELECT 1;\n" + undo) == fires


@pytest.mark.parametrize(
    "sql",
    [
        # Turned off, then back on: the last word is on.
        "CREATE VIEW v AS\nSELECT 1;\n"
        "ALTER VIEW v SET (security_invoker = false, security_barrier = false);\n"
        "ALTER VIEW v SET (security_invoker = true, security_barrier = true);\n",
        # Un-hardening a DIFFERENT view revokes nothing here.
        f"CREATE VIEW v {_HARDENED} AS\nSELECT 1;\n"
        "ALTER VIEW other SET (security_invoker = false, security_barrier = false);\n",
        # An ALTER before a CREATE OR REPLACE applied to the view that the replace discarded.
        "ALTER VIEW v RESET (security_invoker, security_barrier);\n"
        f"CREATE OR REPLACE VIEW v {_HARDENED} AS\nSELECT 1;\n",
        # `on` is true to Postgres; a value spelled any way but `true` or an off-spelling leaves the
        # flag as it was, and never revokes it.
        f"CREATE VIEW v {_HARDENED} AS\nSELECT 1;\nALTER VIEW v SET (security_invoker = on);\n",
        # An option list that names neither flag touches neither.
        f"CREATE VIEW v {_HARDENED} AS\nSELECT 1;\nALTER VIEW v SET (check_option = local);\n",
    ],
    ids=["off-then-on", "different-view", "before-create-or-replace", "on-spelling", "other-option"],
)
def test_pgsdv_alter_that_does_not_leave_a_flag_off_does_not_revoke_it(tmp_path: Path, sql: str) -> None:
    # FP-bait for the two revocation tests above: each of these views ends the file hardened.
    assert _pgsdv_run(tmp_path, sql) == []


def test_pgsdv_head_split_across_lines_is_a_view(tmp_path: Path) -> None:
    # The head is matched on the whole blanked text, so `CREATE OR REPLACE` and `VIEW` on separate
    # lines is a view too (the per-line scan before #442 could not see it).
    assert sorted(_pgsdv_run(tmp_path, "CREATE OR REPLACE\nVIEW v AS SELECT 1;\n")) == [
        (_BARRIER, "1"),
        (_INVOKER, "1"),
    ]


def test_pgsdv_hardened_head_split_across_lines_is_silent(tmp_path: Path) -> None:
    # FP-bait for the test above: a split head's window still reaches its own options.
    assert _pgsdv_run(tmp_path, f"CREATE OR REPLACE\nVIEW v\n{_HARDENED} AS SELECT 1;\n") == []


def test_pgsdv_semicolon_inside_a_quoted_column_name_does_not_end_the_statement(tmp_path: Path) -> None:
    # The bound is `find_statement_end`, quote-aware: a bare `find(";")` would stop inside "x;y",
    # cut the window before its own WITH options, and fire on a hardened view.
    assert _pgsdv_run(tmp_path, f'CREATE VIEW v ("x;y") {_HARDENED} AS SELECT 1;\n') == []


@pytest.mark.slow
@pytest.mark.parametrize(
    ("unit", "head", "expected_per_size"),
    [
        # Every head is a real unhardened view, so every one must still fire both rules.
        ("CREATE VIEW v AS SELECT 1\n", "", lambda n: 2 * n),
        # One real view, then ALTER heads that never close: no credit, so the view fires both.
        ("ALTER VIEW v SET (\n", "CREATE VIEW v AS SELECT 1;\n", lambda n: 2),
    ],
    ids=["create-view-heads-no-semicolon", "alter-view-set-never-closed"],
)
def test_pgsdv_hostile_semicolonless_sql_stays_linear(
    tmp_path: Path, unit: str, head: str, expected_per_size: Callable[[int], int]
) -> None:
    # #419 class, introduced and closed in #442: the statement-bounded window rescanned to EOF from
    # every `CREATE VIEW` head on `;`-less SQL, and the ALTER option list from every unclosed
    # `SET (`; both measured quadratic (35 s and 8 s at 8000 heads). The window now also stops at
    # the next head and the option list is capped.
    sizes = [500, 1000, 2000, 4000]
    roots = {}
    for n in sizes:
        root = tmp_path / f"n{n}"
        root.mkdir()
        (root / "hostile.sql").write_text(head + unit * n, encoding="utf-8")
        roots[n] = root
    fired: dict[int, int] = {}

    def scan(n: int) -> None:
        fired[n] = len(PgSecurityDefinerViewGuard().run(roots[n], mkprofile(roots[n], features={"postgres"})))

    assert_growth(scan, sizes, expected="linear")
    assert all(fired[n] == expected_per_size(n) for n in sizes), fired


# --- #442 phase 2: a `/*` inside a dollar-quoted body cannot hide the view after it ------------

def test_pgsdv_view_after_a_dollar_quoted_glob_still_fires(tmp_path: Path) -> None:
    # Silent since #1006 moved this guard onto blank mode: the glob's `/*` blanked the view
    # through to the trailing comment's `*/`.
    assert sorted(_pgsdv_run(tmp_path, _dollar_glob_sandwich("CREATE VIEW v AS SELECT 1;"))) == [
        (_BARRIER, "2"),
        (_INVOKER, "2"),
    ]


def test_pgsdv_view_commented_out_inside_a_do_body_is_silent(tmp_path: Path) -> None:
    view = "CREATE VIEW v AS SELECT 1;"
    assert _pgsdv_run(tmp_path, _dollar_glob_sandwich(_do_commented_out(view))) == []
    # Control: the guard reads DO bodies, so the same view left live in one fires both rules.
    assert len(_pgsdv_run(tmp_path, f"DO $$ BEGIN\n{view}\nEND $$;\n")) == 2
