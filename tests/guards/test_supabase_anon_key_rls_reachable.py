from __future__ import annotations

import pytest

from agentsec.guards.supabase_anon_key_rls_reachable import SupabaseAnonKeyRlsReachableGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(tmp_path: Path):
    return mkprofile(
        tmp_path, features={"supabase", "sql"}, sql_dir="sql", frontend_dir="frontend"
    )


def _rls_gap_schema(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir(exist_ok=True)
    (sql / "1.sql").write_text(
        "CREATE TABLE public.orders (id uuid primary key);\n"
        "GRANT SELECT ON public.orders TO anon;\n",
        encoding="utf-8",
    )


def _direct_supabase_client(tmp_path: Path) -> None:
    fe = tmp_path / "frontend"
    fe.mkdir(exist_ok=True)
    (fe / "client.ts").write_text(
        "import { createClient } from '@supabase/supabase-js';\n\n"
        "export const supabase = createClient(\n"
        "  process.env.NEXT_PUBLIC_SUPABASE_URL!,\n"
        "  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,\n"
        ");\n",
        encoding="utf-8",
    )


def test_confirmed_reachable_fires_when_both_signals_present(tmp_path: Path) -> None:
    _rls_gap_schema(tmp_path)
    _direct_supabase_client(tmp_path)
    findings = SupabaseAnonKeyRlsReachableGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "supabase-anon-key-rls-reachable/confirmed-reachable-rls-gap"
    assert findings[0].severity == "critical"
    assert "public.orders" in findings[0].message


def test_confirmed_reachable_silent_without_frontend_client(tmp_path: Path) -> None:
    # FP-bait: the RLS gap exists, but nothing confirms a direct client-side connection --
    # e.g. the app is server-mediated only. public-table-rls's own HIGH finding still exists
    # separately; this guard's ADDITIVE critical must not fire without both signals.
    _rls_gap_schema(tmp_path)
    findings = SupabaseAnonKeyRlsReachableGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_confirmed_reachable_silent_without_rls_gap(tmp_path: Path) -> None:
    # FP-bait: a direct client-side connection exists, but RLS is properly enabled everywhere.
    sql = tmp_path / "sql"
    sql.mkdir(exist_ok=True)
    (sql / "1.sql").write_text(
        "CREATE TABLE public.orders (id uuid primary key);\n"
        "ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n"
        "GRANT SELECT ON public.orders TO anon;\n",
        encoding="utf-8",
    )
    _direct_supabase_client(tmp_path)
    assert SupabaseAnonKeyRlsReachableGuard().run(tmp_path, _prof(tmp_path)) == []


def test_confirmed_reachable_silent_on_ctor_only_no_import(tmp_path: Path) -> None:
    # FP-bait: a `createClient(...)` call with NO @supabase/supabase-js import anywhere --
    # too generic a name to trust alone (mirrors webhook_signature_not_verified's
    # _library_verified two-signal requirement).
    _rls_gap_schema(tmp_path)
    fe = tmp_path / "frontend"
    fe.mkdir(exist_ok=True)
    (fe / "client.ts").write_text(
        "import { createClient } from 'some-other-sdk';\n"
        "export const client = createClient('https://example.com', 'key');\n",
        encoding="utf-8",
    )
    assert SupabaseAnonKeyRlsReachableGuard().run(tmp_path, _prof(tmp_path)) == []


def test_confirmed_reachable_silent_on_import_only_no_ctor(tmp_path: Path) -> None:
    # FP-bait: the library is imported but never actually instantiated in the frontend.
    _rls_gap_schema(tmp_path)
    fe = tmp_path / "frontend"
    fe.mkdir(exist_ok=True)
    (fe / "types.ts").write_text(
        "import type { SupabaseClient } from '@supabase/supabase-js';\n"
        "export type Client = SupabaseClient;\n",
        encoding="utf-8",
    )
    assert SupabaseAnonKeyRlsReachableGuard().run(tmp_path, _prof(tmp_path)) == []


def test_confirmed_reachable_silent_on_cross_file_import_and_unrelated_ctor(tmp_path: Path) -> None:
    # PR #742 review, Major 3 (verified FP #2): a type-only Supabase import in ONE file and an
    # UNRELATED SDK's createClient() in a DIFFERENT file used to combine into a CRITICAL finding,
    # because the two signals were tracked as independent booleans across the whole tree rather
    # than required to co-occur in the same file. Must stay silent now.
    _rls_gap_schema(tmp_path)
    fe = tmp_path / "frontend"
    fe.mkdir(exist_ok=True)
    (fe / "types.ts").write_text(
        "import type { SupabaseClient } from '@supabase/supabase-js';\n"
        "export type Client = SupabaseClient;\n",
        encoding="utf-8",
    )
    (fe / "other_client.ts").write_text(
        "import { createClient } from 'some-other-sdk';\n"
        "export const client = createClient('https://example.com', 'key');\n",
        encoding="utf-8",
    )
    assert SupabaseAnonKeyRlsReachableGuard().run(tmp_path, _prof(tmp_path)) == []


def test_confirmed_reachable_silent_on_example_path_client(tmp_path: Path) -> None:
    # PR #742 review, Major 3 (verified FP #1): a real createClient()+import pair that is the
    # ONLY one in the tree, but sits under frontend/examples/ (non-shipped sample code), used to
    # count as a working connection because is_nonproduct_path was never consulted.
    _rls_gap_schema(tmp_path)
    examples = tmp_path / "frontend" / "examples"
    examples.mkdir(parents=True, exist_ok=True)
    (examples / "sample.ts").write_text(
        "import { createClient } from '@supabase/supabase-js';\n"
        "export const supabase = createClient('https://example.supabase.co', 'anon-key');\n",
        encoding="utf-8",
    )
    assert SupabaseAnonKeyRlsReachableGuard().run(tmp_path, _prof(tmp_path)) == []


def test_confirmed_reachable_fires_on_granular_path_when_bundle_protects(tmp_path: Path) -> None:
    # PR #742 review, Major 2 (verified false negative): the flagship case
    # public_table_rls.py's own docstring cites -- a repo ships BOTH a granular migration path
    # (table exposed) and a consolidated bundle (table protected). The original whole-file scan
    # here aggregated both paths together and saw "RLS enabled somewhere", missing that the
    # granular deploy path alone leaves the table exposed. Now reuses public_table_rls.py's own
    # variant-aware analysis, so it must fire exactly like public-table-rls does.
    sql = tmp_path / "sql"
    sql.mkdir(exist_ok=True)
    (sql / "1-orders.sql").write_text(
        "CREATE TABLE public.orders (id uuid primary key);\n"
        "GRANT SELECT ON public.orders TO anon;\n",
        encoding="utf-8",
    )
    (sql / "2-documents.sql").write_text(
        "CREATE TABLE public.documents (id uuid primary key);\n"
        "GRANT SELECT ON public.documents TO anon;\n",
        encoding="utf-8",
    )
    (sql / "3-other.sql").write_text(
        "CREATE TABLE public.other (id uuid primary key);\n"
        "GRANT SELECT ON public.other TO anon;\n",
        encoding="utf-8",
    )
    # Consolidated bundle re-creates all 3 tables AND enables RLS on them -- but this is an
    # ALTERNATIVE install path, not additive; the granular path above never enables RLS at all.
    (sql / "0-all-tables.sql").write_text(
        "CREATE TABLE public.orders (id uuid primary key);\n"
        "ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\n"
        "CREATE TABLE public.documents (id uuid primary key);\n"
        "ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;\n"
        "CREATE TABLE public.other (id uuid primary key);\n"
        "ALTER TABLE public.other ENABLE ROW LEVEL SECURITY;\n"
        "GRANT SELECT ON public.orders TO anon;\n"
        "GRANT SELECT ON public.documents TO anon;\n"
        "GRANT SELECT ON public.other TO anon;\n",
        encoding="utf-8",
    )
    _direct_supabase_client(tmp_path)
    findings = SupabaseAnonKeyRlsReachableGuard().run(tmp_path, _prof(tmp_path))
    assert {f.message for f in findings} and len(findings) == 3
    assert all(f.severity == "critical" for f in findings)


def test_confirmed_reachable_python_client_fires(tmp_path: Path) -> None:
    _rls_gap_schema(tmp_path)
    fe = tmp_path / "frontend"
    fe.mkdir(exist_ok=True)
    (fe / "client.py").write_text(
        "from supabase import create_client\n"
        "supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)\n",
        encoding="utf-8",
    )
    findings = SupabaseAnonKeyRlsReachableGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1


def test_confirmed_reachable_silent_without_sql_files(tmp_path: Path) -> None:
    _direct_supabase_client(tmp_path)
    assert SupabaseAnonKeyRlsReachableGuard().run(tmp_path, _prof(tmp_path)) == []


def test_confirmed_reachable_not_applicable_without_supabase() -> None:
    prof = mkprofile(Path("/tmp"), features={"sql"})
    assert SupabaseAnonKeyRlsReachableGuard().applies(prof) is False


# --- #1055: the JS/TS createClient() call counts only when it is live code ------------------------

_JS_IMPORT = "import { createClient } from '@supabase/supabase-js';\n"


def _run_js_client(tmp_path: Path, body: str, imp: str = _JS_IMPORT) -> list[str]:
    _rls_gap_schema(tmp_path)
    fe = tmp_path / "frontend"
    fe.mkdir(exist_ok=True)
    (fe / "client.ts").write_text(imp + body, encoding="utf-8")
    return [f.rule for f in SupabaseAnonKeyRlsReachableGuard().run(tmp_path, _prof(tmp_path))]


@pytest.mark.parametrize(
    ("imp", "body"),
    [
        # The RCA's CRITICAL FP: a type-only import and the ctor named only in a help string.
        (
            "import type { SupabaseClient } from '@supabase/supabase-js';\n",
            "export const help = 'call createClient(url, key) first';\n",
        ),
        (_JS_IMPORT, "export const help = `createClient(url, key) is wired in app.ts`;\n"),
    ],
)
def test_quoted_create_client_call_stays_silent(tmp_path: Path, imp: str, body: str) -> None:
    assert _run_js_client(tmp_path, body, imp) == []


@pytest.mark.parametrize(
    "body",
    [
        "export const supabase = createClient(url, key);\n",
        # The real call nested in a `${...}` substitution is code: the shortcut-separating case,
        # which plain `strip_strings=True` would have blanked.
        "export const label = `${createClient(url, key)}`;\n",
        # A quoted copy earlier on the line must not hide the real call after it.
        "log('createClient( docs'); export const supabase = createClient(url, key);\n",
    ],
)
def test_real_create_client_call_still_fires(tmp_path: Path, body: str) -> None:
    assert _run_js_client(tmp_path, body) == ["supabase-anon-key-rls-reachable/confirmed-reachable-rls-gap"]
