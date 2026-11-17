from __future__ import annotations

from agentsec.guards.matview_exposed import MatviewExposedGuard
from tests.guards._common import *  # noqa: F401,F403


def _run(tmp_path: Path, sql: str) -> list:
    sql_dir = tmp_path / "sql"
    sql_dir.mkdir(exist_ok=True)
    (sql_dir / "p.sql").write_text(sql, encoding="utf-8")
    return MatviewExposedGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql"))


def test_matview_exposed_fires_on_public_matview_no_mitigation(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.order_totals AS SELECT owner, sum(amount) "
        "FROM orders GROUP BY owner;\n",
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].rule == "matview-exposed/public-materialized-view-unmitigated"
    assert "public.order_totals" in findings[0].message
    assert "OWASP:A01" in findings[0].standards
    assert "CIS:6.3" in findings[0].standards


def test_matview_exposed_fires_with_no_schema_prefix(tmp_path: Path) -> None:
    # No schema prefix defaults to public -- still fully exposed.
    findings = _run(tmp_path, "CREATE MATERIALIZED VIEW order_totals AS SELECT 1;\n")
    assert len(findings) == 1


def test_matview_exposed_silent_with_revoke(tmp_path: Path) -> None:
    """FP-bait: an explicit REVOKE pulling Data API access off -> stays silent."""
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.order_totals AS SELECT 1;\n"
        "REVOKE ALL ON public.order_totals FROM PUBLIC, anon, authenticated;\n",
    )
    assert findings == []


def test_matview_exposed_silent_with_schema_move(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.order_totals AS SELECT 1;\n"
        "ALTER MATERIALIZED VIEW public.order_totals SET SCHEMA private;\n",
    )
    assert findings == []


def test_matview_exposed_silent_for_nonpublic_schema(tmp_path: Path) -> None:
    findings = _run(
        tmp_path, "CREATE MATERIALIZED VIEW private.order_totals AS SELECT 1;\n"
    )
    assert findings == []


def test_matview_exposed_revoke_on_different_view_still_fires(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.order_totals AS SELECT 1;\n"
        "REVOKE ALL ON public.other_view FROM PUBLIC;\n",
    )
    assert len(findings) == 1


def test_matview_exposed_set_schema_to_public_is_a_noop(tmp_path: Path) -> None:
    # Moving TO public is not a mitigation -- must still fire.
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.order_totals AS SELECT 1;\n"
        "ALTER MATERIALIZED VIEW public.order_totals SET SCHEMA public;\n",
    )
    assert len(findings) == 1


def test_matview_exposed_pragma_suppresses(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.order_totals AS SELECT 1; "
        "-- security: allow-matview-exposed\n",
    )
    assert findings == []


def test_matview_exposed_applies_gate() -> None:
    assert MatviewExposedGuard().applies(mkprofile(Path("/tmp"), features={"supabase"})) is True
    assert MatviewExposedGuard().applies(mkprofile(Path("/tmp"), features={"postgres"})) is False
    assert MatviewExposedGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False


def test_matview_exposed_no_sql_files(tmp_path: Path) -> None:
    assert MatviewExposedGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql")) == []


def test_matview_exposed_skips_examples_dir(tmp_path: Path) -> None:
    d = tmp_path / "sql" / "examples"
    d.mkdir(parents=True)
    (d / "mv.sql").write_text(
        "CREATE MATERIALIZED VIEW public.order_totals AS SELECT 1;\n", encoding="utf-8"
    )
    assert MatviewExposedGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql")) == []


def test_matview_exposed_hostile_headless_sql_is_linear(tmp_path: Path) -> None:
    # Same DoS class as pg_rls_no_policy.py (issue #419): an ALTER-MATVIEW head with no
    # terminating `;` must not re-scan the tail per occurrence.
    import time

    sql_dir = tmp_path / "sql"
    sql_dir.mkdir()
    (sql_dir / "hostile.sql").write_text(
        "alter materialized view " * 30_000, encoding="utf-8"  # no SET SCHEMA/`;`
    )
    start = time.monotonic()
    findings = MatviewExposedGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql"))
    # 8.0s ceiling over a ~0.5s healthy run (measured, >10x headroom, tests/test_timing_budgets.py's
    # gate) — the quadratic regression this guards against takes minutes at this input size, not
    # single-digit seconds, so this stays exactly as discriminating (2026-08-25).
    assert time.monotonic() - start < 8.0, "quadratic ALTER MATVIEW scan reintroduced"
    assert findings == []


# ── #1096: a REVOKE from ONE Data API role is not a mitigation ───────────────────────────────

def test_issue_1096_matview_revoke_from_public_only_still_fires(tmp_path: Path) -> None:
    # Supabase grants anon/authenticated directly: revoking from PUBLIC leaves both.
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT owner, count(*) FROM public.priv GROUP BY owner;\n"
        "REVOKE ALL ON public.totals FROM PUBLIC;\n",
    )
    assert len(findings) == 1


def test_issue_1096_matview_revoke_missing_authenticated_fires(tmp_path: Path) -> None:
    # A matview cannot carry RLS, so a signed-in user reads every row: authenticated is required.
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "REVOKE SELECT ON public.totals FROM PUBLIC, anon;\n",
    )
    assert len(findings) == 1


def test_issue_1096_matview_roles_split_across_statements_stay_silent(tmp_path: Path) -> None:
    # FP-bait: the flagship's split shape (one REVOKE per role) still covers both roles.
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "REVOKE ALL ON public.totals FROM anon;\n"
        "REVOKE ALL ON TABLE totals FROM \"authenticated\";\n",
    )
    assert findings == []


def test_issue_1096_matview_on_table_keyword_is_skipped(tmp_path: Path) -> None:
    # `ON TABLE public.v` used to capture `TABLE` as the view name (a false positive).
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "REVOKE ALL ON TABLE public.totals FROM PUBLIC, anon, authenticated;\n",
    )
    assert findings == []


def test_issue_1096_matview_on_table_other_view_still_fires(tmp_path: Path) -> None:
    # The neighbour of the ON TABLE fix: a revoke on a DIFFERENT relation must not cover it.
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "REVOKE ALL ON TABLE public.other FROM PUBLIC, anon, authenticated;\n",
    )
    assert len(findings) == 1


def test_issue_1096_matview_multi_target_revoke_covers_each_view(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.a AS SELECT 1;\n"
        "CREATE MATERIALIZED VIEW public.b AS SELECT 1;\n"
        "REVOKE ALL ON public.a, public.b FROM anon, authenticated;\n",
    )
    assert findings == []


def test_issue_1096_matview_revoke_on_other_schema_does_not_cover_public(tmp_path: Path) -> None:
    # Mitigations are indexed by qualified name only: private.v no longer covers public.v.
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "REVOKE ALL ON private.totals FROM anon, authenticated;\n",
    )
    assert len(findings) == 1 and "public.totals" in findings[0].message


def test_issue_1096_matview_granted_to_public_needs_public_revoked(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "GRANT SELECT ON public.totals TO PUBLIC;\n"
        "REVOKE ALL ON public.totals FROM anon, authenticated;\n",
    )
    assert len(findings) == 1


def test_issue_1096_matview_granted_to_public_and_fully_revoked_stays_silent(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "GRANT SELECT ON public.totals TO PUBLIC;\n"
        "REVOKE ALL ON public.totals FROM PUBLIC, anon, authenticated;\n",
    )
    assert findings == []


def test_issue_1096_matview_schema_revoke_is_not_a_view_revoke(tmp_path: Path) -> None:
    # `ON SCHEMA public` is not a relation named `schema` or `public`.
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "REVOKE ALL ON SCHEMA public FROM anon, authenticated;\n",
    )
    assert len(findings) == 1


def test_issue_1096_matview_pragma_still_silences_partial_revoke(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "-- security: allow-matview-exposed\n"
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "REVOKE ALL ON public.totals FROM PUBLIC;\n",
    )
    assert findings == []


# #1100 R1-M1: a REVOKE an `EXECUTE` runs counts; one merely quoted in a string does not.
def test_issue_1096_matview_execute_literal_revoke_counts(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "DO $$ BEGIN EXECUTE 'REVOKE ALL ON public.totals FROM anon, authenticated'; END $$;\n",
    )
    assert findings == []


def test_issue_1096_matview_execute_format_literal_revoke_counts(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "DO $$ BEGIN EXECUTE format('REVOKE SELECT ON TABLE public.totals FROM anon, authenticated'); END $$;\n",
    )
    assert findings == []


def test_issue_1096_matview_execute_literal_missing_a_role_still_fires(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "DO $$ BEGIN EXECUTE 'REVOKE ALL ON public.totals FROM anon'; END $$;\n",
    )
    assert len(findings) == 1


def test_issue_1096_matview_revoke_quoted_in_a_notice_is_not_a_revoke(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "DO $$ BEGIN RAISE NOTICE 'revoke all on public.totals from anon, authenticated;'; END $$;\n",
    )
    assert len(findings) == 1


def test_issue_1096_matview_static_revokes_in_do_block_and_quoted_names_still_count(tmp_path: Path) -> None:
    # FP-bait for the literal-blanked view: a dollar-quoted DO body and "quoted" identifiers stay visible.
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "DO $$ BEGIN REVOKE ALL ON public.totals FROM anon; END $$;\n"
        'REVOKE ALL ON TABLE "public"."totals" FROM "authenticated";\n',
    )
    assert findings == []


# #1100 R2-M1: an apostrophe in an earlier dollar-quoted string must not hide a later REVOKE.
def test_issue_1096_matview_apostrophe_in_a_dollar_quoted_comment_keeps_a_later_revoke(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.totals AS SELECT 1;\n"
        "COMMENT ON MATERIALIZED VIEW public.totals IS $$Don't expose this$$;\n"
        "REVOKE ALL ON public.totals FROM anon, authenticated;\n",
    )
    assert findings == []


# #1100 R2-L1: `public.%I` must not credit a view that is literally named `public`.
def test_issue_1096_matview_placeholder_target_does_not_credit_a_view_named_like_its_schema(
    tmp_path: Path,
) -> None:
    findings = _run(
        tmp_path,
        "CREATE MATERIALIZED VIEW public.public AS SELECT 1;\n"
        "DO $$ BEGIN EXECUTE format('REVOKE ALL ON public.%I FROM anon, authenticated', 'x'); END $$;\n",
    )
    assert len(findings) == 1

