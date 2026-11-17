from __future__ import annotations

from agentsec.guards.public_table_rls import PublicTableRlsGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rls_flags_public_table_without_rls(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text("CREATE TABLE public.secrets (id int);\n", encoding="utf-8")
    # supabase => a PostgREST Data API is present, so `public` is anon-reachable by default (§D.4).
    prof = mkprofile(tmp_path, features={"sql", "supabase"}, sql_dir="sql")
    findings = PublicTableRlsGuard().run(tmp_path, prof)
    assert len(findings) == 1 and "public.secrets" in findings[0].message
    assert findings[0].severity == "high"

def test_rls_passes_when_enabled_or_dropped(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE TABLE public.a (id int);\nALTER TABLE public.a ENABLE ROW LEVEL SECURITY;\n"
        "CREATE TABLE public.tmp (id int);\nDROP TABLE public.tmp;\n"
        "-- CREATE TABLE public.commented (id int);\n", encoding="utf-8"  # comment-stripped, ignored
    )
    prof = mkprofile(tmp_path, features={"sql", "supabase"}, sql_dir="sql")
    assert PublicTableRlsGuard().run(tmp_path, prof) == []

def test_rls_flags_table_protected_only_in_consolidated_bundle(tmp_path: Path) -> None:
    # Mirrors 9_Agent_SaaS: a consolidated bundle (0-all-tables.sql) enables RLS on
    # everything, but the *granular* migration path creates the documents tables
    # WITHOUT RLS. The two are mutually-exclusive install paths — the granular
    # deploy leaves those tables exposed, so the guard must flag them (not let the
    # bundle's ENABLE excuse the granular CREATE).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1-profiles.sql").write_text("CREATE TABLE public.profiles (id int);\n", encoding="utf-8")
    (sql / "2-profiles-rls.sql").write_text("ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8")
    (sql / "5-meta.sql").write_text("CREATE TABLE public.document_metadata (id int);\n", encoding="utf-8")
    (sql / "6-rows.sql").write_text("CREATE TABLE public.document_rows (id int);\n", encoding="utf-8")
    (sql / "7-documents.sql").write_text("CREATE TABLE public.documents (id int);\n", encoding="utf-8")
    (sql / "0-all-tables.sql").write_text(
        "CREATE TABLE public.profiles (id int);\n"
        "CREATE TABLE public.documents (id int);\n"
        "CREATE TABLE public.document_metadata (id int);\n"
        "CREATE TABLE public.document_rows (id int);\n"
        "ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE public.document_metadata ENABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE public.document_rows ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"sql", "supabase"}, sql_dir="sql")
    findings = PublicTableRlsGuard().run(tmp_path, prof)
    flagged = {t for f in findings for t in ("documents", "document_metadata", "document_rows", "profiles") if f"public.{t}`" in f.message}
    assert flagged == {"documents", "document_metadata", "document_rows"}  # profiles NOT flagged (RLS in granular file 2)
    assert all(f.severity == "high" for f in findings)
    assert any("only enabled in a different schema variant" in f.message for f in findings)

def test_rls_flags_exposed_nonpublic_schema_without_rls(tmp_path: Path) -> None:
    # Mirrors the flagship blind spot: a table moved into a custom schema that is
    # exposed to the Data API (GRANTed to authenticated) but left without RLS.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "161-workbook.sql").write_text(
        "GRANT USAGE ON SCHEMA workbook TO anon, authenticated, service_role;\n"
        "CREATE TABLE workbook.courses (id int);\n"
        "GRANT SELECT ON workbook.courses TO authenticated;\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"sql"}, sql_dir="sql")
    findings = PublicTableRlsGuard().run(tmp_path, prof)
    assert len(findings) == 1 and "workbook.courses" in findings[0].message
    assert findings[0].severity == "high"

def test_rls_exposed_schema_passes_when_rls_enabled(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "161-workbook.sql").write_text(
        "GRANT USAGE ON SCHEMA workbook TO anon, authenticated;\n"
        "CREATE TABLE workbook.courses (id int);\n"
        "GRANT SELECT ON workbook.courses TO authenticated;\n", encoding="utf-8"
    )
    (sql / "168-rls.sql").write_text("ALTER TABLE workbook.courses ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8")
    prof = mkprofile(tmp_path, features={"sql"}, sql_dir="sql")
    assert PublicTableRlsGuard().run(tmp_path, prof) == []

def test_rls_non_exposed_schema_not_flagged(tmp_path: Path) -> None:
    # A schema with no anon/authenticated grant is NOT API-reachable — RLS-off
    # there is not a finding (would be a false positive).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1-private.sql").write_text(
        "CREATE TABLE private.secrets (id int);\n"
        "GRANT SELECT ON private.secrets TO service_role;\n", encoding="utf-8"  # service_role only, not exposed
    )
    prof = mkprofile(tmp_path, features={"sql"}, sql_dir="sql")
    findings = PublicTableRlsGuard().run(tmp_path, prof)
    # No RLS finding — but the guard now DISCLOSES that it could not assess exposure, rather than
    # returning nothing and reading as a passing check (#481 review).
    assert [f for f in findings if f.severity != "info"] == []
    assert [f.rule for f in findings] == ["public-table-rls/not-analysed-no-data-api"]


def test_rls_plain_postgres_public_table_not_flagged(tmp_path: Path) -> None:
    # FP-bait (§D.4): a plain-Postgres app (direct `pg`/driver, no PostgREST/anon key — NO `supabase`
    # feature) whose `public` tables lack RLS and are NOT granted to anon must NOT fire. `public` is
    # only anon-reachable under a Data API. This is the 8-FP remote-coding-agent case.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1-init.sql").write_text(
        "CREATE TABLE public.remote_agent_sessions (id uuid primary key);\n"
        "CREATE TABLE public.remote_agent_tasks (id uuid primary key);\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"sql"}, sql_dir="sql")  # no `supabase`
    findings = PublicTableRlsGuard().run(tmp_path, prof)
    assert [f for f in findings if f.severity != "info"] == []
    # ...and the info disclosure names both tables, so a detection MISS cannot read as a pass.
    assert len(findings) == 1 and findings[0].severity == "info"
    assert "remote_agent_sessions" in findings[0].message
    assert "remote_agent_tasks" in findings[0].message


def test_rls_public_flagged_via_explicit_anon_grant_without_supabase(tmp_path: Path) -> None:
    # Self-hosted PostgREST (no `supabase` feature) that EXPLICITLY grants `public` to anon still
    # exposes those tables — the guard must still flag them. This is why the Data-API gate lives on the
    # `public` *default*, not on `applies()`.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE TABLE public.notes (id int);\n"
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO anon;\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"sql"}, sql_dir="sql")  # no `supabase`
    findings = PublicTableRlsGuard().run(tmp_path, prof)
    assert len(findings) == 1 and "public.notes" in findings[0].message


def test_rls_exposed_via_pgrst_db_schemas_literal(tmp_path: Path) -> None:
    # A schema named in a literal pgrst.db_schemas setting counts as exposed even
    # without a per-table grant.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "ALTER ROLE authenticator SET pgrst.db_schemas = 'public,graphql_public,workbook';\n"
        "CREATE TABLE workbook.notes (id int);\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"sql"}, sql_dir="sql")
    findings = PublicTableRlsGuard().run(tmp_path, prof)
    assert len(findings) == 1 and "workbook.notes" in findings[0].message

def test_rls_stray_apostrophe_in_copy_data_does_not_silence_the_guard(tmp_path: Path) -> None:
    # End-to-end lock for the #435 re-review Critical. `strip_sql_comments` used to pair the
    # apostrophe in the COPY payload `don't panic` with the OPENING delimiter of the unrelated
    # `COMMENT ON … IS 'ok'` literal two lines later, so everything between — including the
    # commented-out `-- ALTER TABLE … ENABLE ROW LEVEL SECURITY;` — survived as "string content".
    # This guard then read that comment as a real RLS-enable and went silent on an unprotected
    # table. Ordinary `pg_dump` output; no malformed SQL involved.
    #
    # The ORDER is the trigger: the commented-out hardening line must sit BETWEEN the stray
    # apostrophe and the later literal. Both payloads below must give the SAME verdict.
    body = (
        "CREATE TABLE public.notes (id serial primary key, body text);\n"
        "COPY public.notes (body) FROM stdin;\n"
        "{payload}\n"
        "\\.\n"
        "-- ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
        "COMMENT ON TABLE public.notes IS 'ok';\n"
    )
    verdicts = []
    for name, payload in (("plain", "dont panic"), ("apostrophe", "don't panic")):
        sql = tmp_path / name
        sql.mkdir()
        (sql / "1.sql").write_text(body.format(payload=payload), encoding="utf-8")
        prof = mkprofile(tmp_path, features={"sql"}, sql_dir=name)
        verdicts.append([f.message for f in PublicTableRlsGuard().run(tmp_path, prof)])
    assert verdicts[0] == verdicts[1], "one apostrophe changed the guard's verdict"
    assert len(verdicts[1]) == 1 and "public.notes" in verdicts[1][0]


def test_rls_copy_payload_apostrophe_cannot_fabricate_an_unprotected_finding(tmp_path: Path) -> None:
    # Issue #528 repro 1, end-to-end: RLS on public.notes is GENUINELY enabled here, but the
    # apostrophe in the COPY payload used to steal the `'note -- …'` literal's opening quote; the
    # literal's own `--` then deleted the real ALTER TABLE, and this guard reported the table
    # unprotected. Terminated COPY payloads are opaque now, so the verdict must be clean.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "dump.sql").write_text(
        "CREATE TABLE public.notes (id serial primary key, body text);\n"
        "COPY public.notes (body) FROM stdin;\n"
        "don't panic\n"
        "\\.\n"
        "SELECT 'note -- not a real comment, just data' AS x; "
        "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"sql", "supabase"}, sql_dir="sql")
    findings = PublicTableRlsGuard().run(tmp_path, prof)
    assert [f.message for f in findings if "public.notes" in f.message] == []


def test_rls_fake_copy_head_in_a_literal_does_not_unprotect_a_later_real_block(tmp_path: Path) -> None:
    # PR #826 review Critical 1, end-to-end: example COPY syntax quoted inside a literal, then a
    # real pg_dump-style block whose payload holds an apostrophe. The raw pre-scan paired the fake
    # head with the real block's `\.`, the real block lost its opacity, the apostrophe stole a
    # later literal's delimiter, the genuine ALTER was deleted, and this guard fabricated an
    # unprotected finding for a table whose RLS is enabled in the raw SQL.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "dump.sql").write_text(
        "CREATE TABLE public.notes (id serial primary key, body text);\n"
        "INSERT INTO public.notes (body) VALUES ('example:\n"
        "COPY x FROM stdin;\n"
        "sample row\n"
        "end');\n"
        "COPY public.notes (body) FROM stdin;\n"
        "don't panic\n"
        "\\.\n"
        "SELECT 'steal -- comment' AS z; "
        "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"sql", "supabase"}, sql_dir="sql")
    findings = PublicTableRlsGuard().run(tmp_path, prof)
    assert [f.message for f in findings if "public.notes" in f.message] == []


def test_public_table_rls_hostile_grant_run_is_bounded(tmp_path: Path) -> None:
    # Regression (issue #419): the unbounded lazy `[\w\s,]+?` between `grant` and `on` re-scanned
    # from every `grant` token inside one long word/space run — O(n²). The privilege list is now
    # length-capped. Actual ~0.1s; the quadratic form at this size takes minutes.
    import time

    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "hostile.sql").write_text("grant select, insert, " * 20_000 + "\n", encoding="utf-8")
    start = time.monotonic()
    findings = PublicTableRlsGuard().run(tmp_path, mkprofile(tmp_path, features={"sql"}, sql_dir="sql"))
    assert time.monotonic() - start < 5.0, "quadratic grant-list scan reintroduced"
    assert findings == []


# --- #442 phase 2: a `/*` inside a dollar-quoted body cannot hide the SQL after it -------------
# Both directions for a presence check: a hidden ENABLE was a false HIGH, a hidden CREATE TABLE a
# silent miss.

_I442_NOTES = "CREATE TABLE public.notes (id int);\n"
_I442_ENABLE = "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;"


def _ptr_messages(tmp_path: Path, text: str) -> list[str]:
    sql = tmp_path / "sql"
    sql.mkdir(exist_ok=True)
    (sql / "1.sql").write_text(text, encoding="utf-8")
    prof = mkprofile(tmp_path, features={"sql", "supabase"}, sql_dir="sql")
    return [f.message for f in PublicTableRlsGuard().run(tmp_path, prof)]


def test_rls_enable_after_a_dollar_quoted_glob_is_credited(tmp_path: Path) -> None:
    assert _ptr_messages(tmp_path, _I442_NOTES + _dollar_glob_sandwich(_I442_ENABLE)) == []


def test_rls_enable_commented_out_inside_a_do_body_is_not_credited(tmp_path: Path) -> None:
    # Rule 1 for the credit above: a commented-out ENABLE inside a body is still commented out.
    messages = _ptr_messages(tmp_path, _I442_NOTES + _dollar_glob_sandwich(_do_commented_out(_I442_ENABLE)))
    assert len(messages) == 1 and "public.notes" in messages[0]


def test_rls_table_after_a_dollar_quoted_glob_is_still_seen(tmp_path: Path) -> None:
    messages = _ptr_messages(tmp_path, _dollar_glob_sandwich(_I442_NOTES))
    assert len(messages) == 1 and "public.notes" in messages[0]
