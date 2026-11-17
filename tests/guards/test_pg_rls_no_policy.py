from __future__ import annotations

from agentsec.guards.pg_rls_no_policy import PgRlsNoPolicyGuard
from tests.guards._common import *  # noqa: F401,F403


def test_pg_rls_no_policy_fires_on_enable_without_policy(tmp_path: Path) -> None:
    # HIGH requires a CLIENT grant (issue #802): a client role holds a grant but no
    # policy scopes it — the stale-grant footgun. Bare-ENABLE-with-no-grant is INFO now
    # (see test_pg_rls_no_policy_info_when_no_grant_at_all).
    (tmp_path / "schema.sql").write_text(
        "ALTER TABLE users ENABLE ROW LEVEL SECURITY;\n"
        "GRANT SELECT ON users TO authenticated;\n",
        encoding="utf-8",
    )
    findings = PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].rule == "pg-rls-no-policy/rls-enabled-without-policy"
    assert "users" in findings[0].message
    assert "OWASP:A01" in findings[0].standards
    assert "CIS:6.3" in findings[0].standards


def test_pg_rls_no_policy_info_when_no_grant_at_all(tmp_path: Path) -> None:
    # Narrowing (issue #802): RLS on + no policy + NO grant → deny-all is the fail-closed
    # secure state. The rule still FIRES (evidence chain preserved) but as INFO, not HIGH,
    # so a correctly-locked-down table no longer fails the gate.
    (tmp_path / "schema.sql").write_text(
        "ALTER TABLE users ENABLE ROW LEVEL SECURITY;\n",
        encoding="utf-8",
    )
    findings = PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].rule == "pg-rls-no-policy/rls-enabled-without-policy"
    assert "users" in findings[0].message


def test_pg_rls_no_policy_info_when_service_role_only(tmp_path: Path) -> None:
    # The reported false positive: the flagship's service-role-only IdP/eval tables
    # (GRANT … TO service_role, RLS on, 0 policies). service_role bypasses RLS, so this
    # is deny-all for every client — the deliberate design. Must be INFO, not HIGH.
    (tmp_path / "235-circle-sso.sql").write_text(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON public.oauth_authorization_codes TO service_role;\n"
        "ALTER TABLE public.oauth_authorization_codes ENABLE ROW LEVEL SECURITY;\n",
        encoding="utf-8",
    )
    findings = PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "oauth_authorization_codes" in findings[0].message


def test_pg_rls_no_policy_high_when_client_grant_in_other_file(tmp_path: Path) -> None:
    # Negative control (issue #802): RLS-on + 0 policies + a client (authenticated) grant
    # — even in a SEPARATE migration file — MUST still fire HIGH. The demotion applies only
    # when NO client-role grant exists anywhere.
    (tmp_path / "10-table.sql").write_text(
        "ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8"
    )
    (tmp_path / "20-grants.sql").write_text(
        "GRANT SELECT, INSERT ON public.reports TO authenticated;\n", encoding="utf-8"
    )
    findings = PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "reports" in findings[0].message


def test_pg_rls_no_policy_high_on_blanket_all_tables_grant(tmp_path: Path) -> None:
    # A blanket `GRANT … ON ALL TABLES IN SCHEMA public TO authenticated` makes every
    # public table client-reachable, so RLS-on-no-policy on any of them is the footgun → HIGH.
    (tmp_path / "schema.sql").write_text(
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO authenticated;\n"
        "ALTER TABLE public.widgets ENABLE ROW LEVEL SECURITY;\n",
        encoding="utf-8",
    )
    findings = PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "widgets" in findings[0].message


def test_pg_rls_no_policy_service_role_grant_is_not_a_client_grant(tmp_path: Path) -> None:
    # A table granted to BOTH service_role and authenticated is client-reachable → HIGH;
    # but a grant ONLY to service_role must not tip a sibling table into HIGH. Guards the
    # role-parsing: `service_role` alone is never read as a client role.
    (tmp_path / "schema.sql").write_text(
        "GRANT ALL ON public.svc_only TO service_role;\n"
        "ALTER TABLE public.svc_only ENABLE ROW LEVEL SECURITY;\n"
        "GRANT SELECT ON public.client_tbl TO service_role, authenticated;\n"
        "ALTER TABLE public.client_tbl ENABLE ROW LEVEL SECURITY;\n",
        encoding="utf-8",
    )
    findings = PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path))
    sev = {("svc_only" in f.message, "client_tbl" in f.message): f.severity for f in findings}
    assert sev[(True, False)] == "info"   # svc_only: service_role only
    assert sev[(False, True)] == "high"   # client_tbl: also granted to authenticated

def test_pg_rls_no_policy_ignores_generated_dump_grants(tmp_path: Path) -> None:
    # The real flagship shape (issue #802): the hand-authored schema grants the table to
    # service_role ONLY, but an auto-generated `supabase db dump` snapshot captures Supabase's
    # implicit `GRANT ALL … TO anon/authenticated` default. The dump's grants must be IGNORED,
    # so the table stays INFO (service-role-only) instead of being promoted to HIGH.
    (tmp_path / "0-all-tables.sql").write_text(
        "ALTER TABLE public.oauth_authorization_codes ENABLE ROW LEVEL SECURITY;\n"
        "GRANT SELECT, INSERT, UPDATE, DELETE ON public.oauth_authorization_codes TO service_role;\n",
        encoding="utf-8",
    )
    (tmp_path / "schema-snapshot.sql").write_text(
        "-- Schema Snapshot: auto-generated 2026-09-06 07:01 UTC\n"
        "-- Tool: supabase db dump (project-defined objects only)\n"
        'GRANT ALL ON TABLE "public"."oauth_authorization_codes" TO "anon";\n'
        'GRANT ALL ON TABLE "public"."oauth_authorization_codes" TO "authenticated";\n'
        'ALTER TABLE "public"."oauth_authorization_codes" ENABLE ROW LEVEL SECURITY;\n',
        encoding="utf-8",
    )
    findings = PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "oauth_authorization_codes" in findings[0].message
    # And the finding anchors in the hand-authored file, never the DO-NOT-EDIT dump.
    assert "0-all-tables.sql" in findings[0].location


def test_pg_rls_no_policy_dump_mention_in_prose_does_not_skip(tmp_path: Path) -> None:
    # #819 review (High #1): the dump detector keys on a STRUCTURED header comment line, not a
    # substring anywhere. A hand-authored migration whose header merely discusses a dump — even a
    # NEGATION — must NOT be skipped, or its real client-grant HIGH is silently voided.
    for header in (
        "-- Migration 42: replaces our old manual postgresql database dump restore process\n",
        "-- NOTE: this file is NOT the supabase db dump; edit it directly.\n",
        "-- Run `pg_dump` before applying, then:\n",
    ):
        (tmp_path / "m.sql").write_text(
            header
            + "ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;\n"
            + "GRANT SELECT ON public.reports TO authenticated;\n",
            encoding="utf-8",
        )
        findings = PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path))
        assert len(findings) == 1, f"prose header wrongly skipped: {header!r}"
        assert findings[0].severity == "high", header


def test_pg_rls_no_policy_real_dump_header_still_skips(tmp_path: Path) -> None:
    # The other direction of #1: a genuine dump header (marker as its own `-- …` line) is still
    # detected, so the dump's implicit anon/authenticated grant does not promote the table.
    (tmp_path / "0-all-tables.sql").write_text(
        "ALTER TABLE public.svc ENABLE ROW LEVEL SECURITY;\n"
        "GRANT SELECT ON public.svc TO service_role;\n",
        encoding="utf-8",
    )
    for dump_header in (
        "--\n-- PostgreSQL database dump\n--\n-- Dumped by pg_dump version 15.2\n",
        "-- Tool: supabase db dump (project-defined objects only)\n",
    ):
        (tmp_path / "dump.sql").write_text(
            dump_header + 'GRANT ALL ON TABLE "public"."svc" TO "authenticated";\n',
            encoding="utf-8",
        )
        findings = PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path))
        assert len(findings) == 1 and findings[0].severity == "info", dump_header


def test_pg_rls_no_policy_high_on_multiline_role_list(tmp_path: Path) -> None:
    # #819 review (High #2): a client role after a line break in the TO list must not be dropped.
    # `service_role,\n authenticated` is a real client grant → HIGH, not INFO.
    (tmp_path / "schema.sql").write_text(
        "GRANT SELECT ON public.reports TO\n    service_role,\n    authenticated;\n"
        "ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;\n",
        encoding="utf-8",
    )
    findings = PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_pg_rls_no_policy_policy_only_in_dump_still_suppresses(tmp_path: Path) -> None:
    # #819 review (Medium #3): a CREATE POLICY that lives ONLY in a dump (e.g. authored via Studio,
    # never migrated) must still suppress — a policy anywhere means the table is covered. The dump's
    # ENABLE/GRANT stay ignored, but its policy is read, so this stays SILENT (no new false positive).
    (tmp_path / "0-all-tables.sql").write_text(
        "ALTER TABLE public.foo ENABLE ROW LEVEL SECURITY;\n"
        "GRANT SELECT ON public.foo TO authenticated;\n",
        encoding="utf-8",
    )
    (tmp_path / "schema-snapshot.sql").write_text(
        "-- Tool: supabase db dump (project-defined objects only)\n"
        "CREATE POLICY foo_policy ON public.foo USING (true);\n",
        encoding="utf-8",
    )
    assert PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path)) == []


def test_pg_rls_no_policy_dump_skip_is_content_based_not_name(tmp_path: Path) -> None:
    # The skip keys on the dump HEADER, not the filename: an identically-named file WITHOUT the
    # dump marker is a normal migration — its client grant still promotes the table to HIGH.
    (tmp_path / "schema-snapshot.sql").write_text(
        'GRANT ALL ON TABLE "public"."reports" TO "authenticated";\n'
        'ALTER TABLE "public"."reports" ENABLE ROW LEVEL SECURITY;\n',
        encoding="utf-8",
    )
    findings = PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "reports" in findings[0].message


def test_pg_rls_no_policy_silent_when_policy_same_file(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "ALTER TABLE users ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY user_isolation ON users USING (user_id = auth.uid());\n",
        encoding="utf-8",
    )
    assert PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path)) == []

def test_pg_rls_no_policy_silent_when_policy_other_file(tmp_path: Path) -> None:
    (tmp_path / "a.sql").write_text(
        "ALTER TABLE users ENABLE ROW LEVEL SECURITY;\n",
        encoding="utf-8",
    )
    (tmp_path / "b.sql").write_text(
        "CREATE POLICY user_isolation ON users USING (user_id = auth.uid());\n",
        encoding="utf-8",
    )
    assert PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path)) == []

def test_pg_rls_no_policy_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "ALTER TABLE users ENABLE ROW LEVEL SECURITY;  -- security: allow-rls-no-policy\n",
        encoding="utf-8",
    )
    assert PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path)) == []

def test_pg_rls_no_policy_applies_gate() -> None:
    assert PgRlsNoPolicyGuard().applies(mkprofile(Path("/tmp"), features={"supabase"})) is True
    assert PgRlsNoPolicyGuard().applies(mkprofile(Path("/tmp"), features={"postgres"})) is True
    assert PgRlsNoPolicyGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False

def test_pg_rls_no_policy_no_sql_files(tmp_path: Path) -> None:
    # No .sql files — should return empty list without crashing
    assert PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path)) == []


def test_pg_rls_no_policy_silent_for_qualified_enable_unqualified_policy(tmp_path: Path) -> None:
    """A schema-qualified ENABLE matched by an unqualified CREATE POLICY (search_path
    resolution) must NOT be flagged — previously a false 'RLS enabled, no policy'."""
    (tmp_path / "schema.sql").write_text(
        "ALTER TABLE app.widgets ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON widgets FOR SELECT USING (true);\n",
        encoding="utf-8",
    )
    assert PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path)) == []


def test_pg_rls_no_policy_skips_examples_dir(tmp_path: Path) -> None:
    # §C.2: an RLS gap in a reference/example schema is not the deployed app's risk.
    d = tmp_path / "examples"
    d.mkdir()
    (d / "schema.sql").write_text("ALTER TABLE users ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8")
    assert PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path)) == []


def test_pg_rls_no_policy_still_fires_on_supabase_migrations(tmp_path: Path) -> None:
    # CRITICAL regression (PR #484 review): for SQL, `migrations/` is the DEPLOYED schema (Supabase's
    # canonical `supabase/migrations/*.sql`), NOT a non-product tree — the guard MUST still fire there.
    d = tmp_path / "supabase" / "migrations"
    d.mkdir(parents=True)
    (d / "0001_init.sql").write_text(
        "ALTER TABLE users ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"supabase", "python"}, python_dirs=["."], sql_dir="supabase/migrations")
    findings = PgRlsNoPolicyGuard().run(tmp_path, prof)
    assert any(f.rule == "pg-rls-no-policy/rls-enabled-without-policy" for f in findings)


def test_pg_rls_no_policy_hostile_headless_sql_is_linear(tmp_path: Path) -> None:
    # Regression (issue #419): `create\s+policy\b[^;]*?\bon…` re-scanned the whole `;`-less span
    # from every head — O(n²). `iter_bounded_matches` skips a failed span in one pass.
    # Actual ~0.01s; the quadratic form at this size takes minutes.
    import time

    (tmp_path / "hostile.sql").write_text("create policy " * 30_000, encoding="utf-8")  # no on/`;`
    start = time.monotonic()
    findings = PgRlsNoPolicyGuard().run(tmp_path, mkprofile(tmp_path, features={"supabase"}))
    assert time.monotonic() - start < 5.0, "quadratic policy scan reintroduced"
    assert findings == []


def test_pg_rls_no_policy_semicolon_in_policy_name_still_covers_the_table(tmp_path: Path) -> None:
    # Issue #559, the FALSE-POSITIVE arm via `iter_bounded_matches`: on main the statement bound
    # landed on the `;` inside the name, the `ON users` tail was outside it, the tuple was never
    # yielded and `users` never entered `policy_tables` — a HIGH on a table that IS covered
    # (measured). Same fixture as the same-file control above, only the name differs.
    (tmp_path / "schema.sql").write_text(
        "ALTER TABLE users ENABLE ROW LEVEL SECURITY;\n"
        'CREATE POLICY "user; isolation" ON users USING (user_id = auth.uid());\n',
        encoding="utf-8",
    )
    assert PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path)) == []


# --- #824 review, Medium 1: the policy NAME is free text, never SQL structure --------------------
_TWO_TABLES = (
    "CREATE TABLE documents (id uuid);\nALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n"
    'CREATE POLICY "NAME" ON documents FOR SELECT TO authenticated USING (true);\n'
    "CREATE TABLE bar (id uuid);\nALTER TABLE bar ENABLE ROW LEVEL SECURITY;\n"
)


def test_pg_rls_no_policy_on_word_inside_policy_name_does_not_cover_that_table(tmp_path: Path) -> None:
    # Unanchored `_POLICY_ON` matched `on bar` INSIDE the name before reaching `ON documents`, so
    # `bar` was marked covered and its real HIGH went silent while `documents` drew a false one.
    # Measured before the mask: both name shapes flagged `public.documents` only. The `;` variant
    # is the one #559's carve made reachable; the plain one was wrong on `main` all along.
    for name in ("foo; on bar", "foo on bar"):
        (tmp_path / "schema.sql").write_text(_TWO_TABLES.replace("NAME", name), encoding="utf-8")
        findings = PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path))
        assert len(findings) == 1, name
        assert "`public.bar`" in findings[0].message and "documents" not in findings[0].message, name


def test_pg_rls_no_policy_on_word_inside_policy_name_still_covers_the_real_table(tmp_path: Path) -> None:
    # FP-bait for the mask: a name containing `on <word>` must not hide the REAL `ON documents`.
    (tmp_path / "schema.sql").write_text(
        "ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n"
        'CREATE POLICY "grant on docs" ON documents FOR SELECT USING (true);\n',
        encoding="utf-8",
    )
    assert PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path)) == []


def test_pg_rls_no_policy_prose_in_a_data_literal_cannot_fabricate_a_finding(tmp_path: Path) -> None:
    # Issue #528 repro 2, end-to-end: the data literal spans the `;` it contains, so its
    # comment-immunity is revoked and the `/* … */` is stripped — but DELETING it welded
    # `ALTER TABLE foo` onto `ENABLE ROW LEVEL SECURITY`, and this guard reported an
    # rls-enabled-without-policy finding for a table that exists nowhere in the schema.
    (tmp_path / "seed.sql").write_text(
        "CREATE TABLE public.docs (id serial primary key, body text);\n"
        "INSERT INTO public.docs (body) VALUES "
        "('Example: ALTER TABLE foo /* run this in staging */ ENABLE ROW LEVEL SECURITY; end of note');\n",
        encoding="utf-8",
    )
    assert PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path)) == []


def test_pg_rls_no_policy_pragma_quoted_in_a_literal_does_not_suppress(tmp_path: Path) -> None:
    # #424 E3: a COMMENT ON literal quoting the documented `-- security: …` form is SQL content,
    # not a comment; the trailing real comment in the test above still suppresses.
    (tmp_path / "schema.sql").write_text(
        "ALTER TABLE users ENABLE ROW LEVEL SECURITY;\n"
        "COMMENT ON TABLE users IS 'opt out with -- security: allow-rls-no-policy';\n",
        encoding="utf-8",
    )
    assert len(PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path))) == 1


# --- #442 phase 2: a `/*` inside a dollar-quoted body cannot hide the SQL after it -------------
# Both directions for a presence check: a hidden CREATE POLICY was a false HIGH, a hidden ENABLE a
# silent miss.

_I442_ENABLED = "ALTER TABLE users ENABLE ROW LEVEL SECURITY;\nGRANT SELECT ON users TO authenticated;\n"
_I442_POLICY = "CREATE POLICY user_isolation ON users USING (user_id = auth.uid());"


def _prnp_severities(tmp_path: Path, text: str) -> list[str]:
    (tmp_path / "schema.sql").write_text(text, encoding="utf-8")
    return [f.severity for f in PgRlsNoPolicyGuard().run(tmp_path, _pgprof(tmp_path))]


def test_pg_rls_no_policy_policy_after_a_dollar_quoted_glob_is_credited(tmp_path: Path) -> None:
    assert _prnp_severities(tmp_path, _I442_ENABLED + _dollar_glob_sandwich(_I442_POLICY)) == []


def test_pg_rls_no_policy_policy_commented_out_inside_a_do_body_is_not_credited(tmp_path: Path) -> None:
    # Rule 1 for the credit above: a commented-out policy inside a body is still commented out.
    text = _I442_ENABLED + _dollar_glob_sandwich(_do_commented_out(_I442_POLICY))
    assert _prnp_severities(tmp_path, text) == ["high"]


def test_pg_rls_no_policy_enable_after_a_dollar_quoted_glob_is_still_seen(tmp_path: Path) -> None:
    assert _prnp_severities(tmp_path, _dollar_glob_sandwich(_I442_ENABLED)) == ["high"]
