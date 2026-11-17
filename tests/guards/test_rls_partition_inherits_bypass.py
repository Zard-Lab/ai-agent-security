from __future__ import annotations

from agentsec.guards.rls_partition_inherits_bypass import RlsPartitionInheritsBypassGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rls_partition_inherits_bypass_fires_on_partition_child(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.events (id uuid, tenant_id int) PARTITION BY LIST (tenant_id);\n"
        "CREATE TABLE public.events_t1 PARTITION OF public.events FOR VALUES IN (1);\n"
        "ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.events USING (tenant_id = current_setting('app.tenant_id')::int);\n", encoding="utf-8"
    )
    findings = RlsPartitionInheritsBypassGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-partition-inherits-bypass/partition-child-no-rls"
    assert findings[0].severity == "high"

def test_rls_partition_inherits_bypass_fires_on_inherits_child(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.events (id uuid, tenant_id int);\n"
        "ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.events USING (tenant_id = current_setting('app.tenant_id')::int);\n"
        "CREATE TABLE public.events_legacy () INHERITS (public.events);\n", encoding="utf-8"
    )
    findings = RlsPartitionInheritsBypassGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-partition-inherits-bypass/inherits-child-no-rls"

def test_rls_partition_inherits_bypass_passes_child_with_own_rls(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.events (id uuid, tenant_id int) PARTITION BY LIST (tenant_id);\n"
        "CREATE TABLE public.events_t1 PARTITION OF public.events FOR VALUES IN (1);\n"
        "ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;\n"
        "ALTER TABLE public.events_t1 ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.events USING (tenant_id = current_setting('app.tenant_id')::int);\n", encoding="utf-8"
    )
    assert RlsPartitionInheritsBypassGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_partition_inherits_bypass_passes_parent_no_rls(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.events (id uuid, tenant_id int) PARTITION BY LIST (tenant_id);\n"
        "CREATE TABLE public.events_t1 PARTITION OF public.events FOR VALUES IN (1);\n", encoding="utf-8"
    )
    assert RlsPartitionInheritsBypassGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_partition_inherits_bypass_cross_file(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.events (id uuid, tenant_id int) PARTITION BY LIST (tenant_id);\n"
        "ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.events USING (tenant_id = current_setting('app.tenant_id')::int);\n", encoding="utf-8"
    )
    (sql / "b.sql").write_text(
        "CREATE TABLE public.events_t1 PARTITION OF public.events FOR VALUES IN (1);\n", encoding="utf-8"
    )
    findings = RlsPartitionInheritsBypassGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1

def test_rls_partition_inherits_bypass_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.events (id uuid, tenant_id int) PARTITION BY LIST (tenant_id);\n"
        "CREATE TABLE public.events_t1 PARTITION OF public.events FOR VALUES IN (1);\n"
        "ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.events USING (tenant_id = current_setting('app.tenant_id')::int);\n"
        "-- security: allow-partition-inherits-bypass\n", encoding="utf-8"
    )
    assert RlsPartitionInheritsBypassGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_partition_inherits_bypass_passes_ordinary_table(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "CREATE TABLE public.docs (id uuid, body text);\n"
        "ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY p ON public.docs USING (owner_id = auth.uid());\n", encoding="utf-8"
    )
    assert RlsPartitionInheritsBypassGuard().run(tmp_path, _sqlprof(tmp_path)) == []
