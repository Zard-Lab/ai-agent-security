from __future__ import annotations

from agentsec.guards.rls_realtime_published_no_rls import RlsRealtimePublishedNoRlsGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rls_realtime_published_no_rls_fires(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.messages (id bigint, room_id uuid, body text);\n"
        "ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;\n", encoding="utf-8"
    )
    findings = RlsRealtimePublishedNoRlsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-realtime-published-no-rls/published-without-rls"
    assert findings[0].severity == "high"

def test_rls_realtime_published_no_rls_fires_multiple_tables(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.messages (id bigint);\n"
        "CREATE TABLE public.rooms (id bigint);\n"
        "ALTER PUBLICATION supabase_realtime ADD TABLE public.messages, public.rooms;\n", encoding="utf-8"
    )
    findings = RlsRealtimePublishedNoRlsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 2

def test_rls_realtime_published_no_rls_passes_with_rls(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.messages (id bigint, room_id uuid, body text);\n"
        "ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.messages USING (room_id = auth.uid());\n"
        "ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;\n", encoding="utf-8"
    )
    assert RlsRealtimePublishedNoRlsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_realtime_published_no_rls_cross_file(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("CREATE TABLE public.messages (id bigint);\n", encoding="utf-8")
    (sql / "b.sql").write_text("ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;\n", encoding="utf-8")
    findings = RlsRealtimePublishedNoRlsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1

def test_rls_realtime_published_no_rls_passes_not_published(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("CREATE TABLE public.messages (id bigint, body text);\n", encoding="utf-8")
    assert RlsRealtimePublishedNoRlsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_realtime_published_no_rls_pg15_column_list_and_where_not_misparsed_as_tables(
    tmp_path: Path,
) -> None:
    # M2: PG15's real grammar allows a column list and a WHERE expression per
    # entry (`ADD TABLE t1 (a, b) WHERE (a > 0), t2`) -- a naive identifier scan over the
    # whole tail used to report `a`, `b` as two fabricated extra "tables" alongside the
    # 2 real ones, from a single real statement.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.messages (id bigint, room_id uuid);\n"
        "CREATE TABLE public.rooms (id bigint, owner_id uuid);\n"
        "ALTER PUBLICATION supabase_realtime "
        "ADD TABLE public.messages (id, room_id) WHERE (room_id IS NOT NULL), "
        "public.rooms;\n", encoding="utf-8"
    )
    findings = RlsRealtimePublishedNoRlsGuard().run(tmp_path, _sqlprof(tmp_path))
    tables = {f.message.split("`")[1] for f in findings}
    assert tables == {"public.messages", "public.rooms"}, (
        f"column-list/WHERE identifiers must not be reported as fake tables, got {tables}"
    )

def test_rls_realtime_published_no_rls_pg15_only_and_star_still_matches_the_real_table(
    tmp_path: Path,
) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.messages (id bigint);\n"
        "ALTER PUBLICATION supabase_realtime ADD TABLE ONLY public.messages *;\n", encoding="utf-8"
    )
    findings = RlsRealtimePublishedNoRlsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert "public.messages" in findings[0].message


def test_rls_realtime_published_no_rls_fires_on_repeated_table_keyword(tmp_path: Path) -> None:
    # (Dean's re-review of the M2 fix): a later publication_object in the
    # same ADD list may repeat the `TABLE` keyword of its own accord (valid grammar for mixing
    # per-object column lists/WHERE clauses) -- `_TABLE_REF` didn't skip it, so the repeated
    # keyword itself was read as the "table name" and the real second table dropped entirely.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.messages (id bigint);\n"
        "CREATE TABLE public.rooms (id bigint);\n"
        "ALTER PUBLICATION supabase_realtime ADD TABLE public.messages, TABLE public.rooms;\n", encoding="utf-8"
    )
    findings = RlsRealtimePublishedNoRlsGuard().run(tmp_path, _sqlprof(tmp_path))
    tables = {f.message.split("`")[1] for f in findings}
    assert tables == {"public.messages", "public.rooms"}, (
        f"a repeated TABLE keyword must not be read as the table name, got {tables}"
    )


def test_rls_realtime_published_no_rls_repeated_table_keyword_with_only(tmp_path: Path) -> None:
    # TABLE and ONLY compose: `TABLE ONLY t2` on the second entry, not just `TABLE t2`.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.messages (id bigint);\n"
        "CREATE TABLE public.rooms (id bigint);\n"
        "ALTER PUBLICATION supabase_realtime ADD TABLE public.messages, TABLE ONLY public.rooms;\n", encoding="utf-8"
    )
    findings = RlsRealtimePublishedNoRlsGuard().run(tmp_path, _sqlprof(tmp_path))
    tables = {f.message.split("`")[1] for f in findings}
    assert tables == {"public.messages", "public.rooms"}


def test_rls_realtime_published_no_rls_repeated_table_keyword_silent_when_rls_on(
    tmp_path: Path,
) -> None:
    # Rule 1 FP-bait for the `(?:table\s+)?` widening (#956 round-2 re-review, L1): with RLS on
    # both published tables the repeated-keyword list must stay silent. Before the fix the
    # keyword itself parsed as a table named `table` and fired as `public.table`.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.messages (id bigint);\n"
        "CREATE TABLE public.rooms (id bigint);\n"
        "ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE public.rooms ENABLE ROW LEVEL SECURITY;\n"
        "ALTER PUBLICATION supabase_realtime ADD TABLE public.messages, TABLE public.rooms;\n",
        encoding="utf-8",
    )
    assert RlsRealtimePublishedNoRlsGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_rls_realtime_published_no_rls_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.messages (id bigint, body text);\n"
        "ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;\n"
        "-- security: allow-realtime-published-no-rls\n", encoding="utf-8"
    )
    assert RlsRealtimePublishedNoRlsGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_rls_realtime_published_no_rls_pragma_quoted_in_a_literal_does_not_opt_out(tmp_path: Path) -> None:
    # #424 E3: the phrase inside a string literal is content, not a comment (the opt-out test above
    # keeps the real `--` comment working).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.messages (id bigint, body text);\n"
        "ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;\n"
        "COMMENT ON TABLE public.messages IS 'opt out with -- security: allow-realtime-published-no-rls';\n",
        encoding="utf-8",
    )
    assert len(RlsRealtimePublishedNoRlsGuard().run(tmp_path, _sqlprof(tmp_path))) == 1
