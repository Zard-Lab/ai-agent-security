from __future__ import annotations

from agentsec.guards.supabase_filter_injection import SupabaseFilterInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_supabase_filter_injection_fstring_or_fires(tmp_path: Path) -> None:
    (tmp_path / "orders_api.py").write_text(
        "def get_order(supabase, order_id, user_id):\n"
        "    return (\n"
        "        supabase.table('orders')\n"
        "        .select('*')\n"
        "        .or_(f'id.eq.{order_id},user_id.eq.{user_id}')\n"
        "        .execute()\n"
        "    )\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SupabaseFilterInjectionGuard().run(tmp_path, prof)
    assert len(findings) == 1
    assert findings[0].rule == "supabase-filter-injection/unparameterized-filter"
    assert findings[0].severity == "critical"


def test_supabase_filter_injection_concat_or_fires(tmp_path: Path) -> None:
    (tmp_path / "orders_api.py").write_text(
        "def get_order(supabase, order_id):\n"
        "    return supabase.table('orders').select('*').or_('id.eq.' + order_id).execute()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SupabaseFilterInjectionGuard().run(tmp_path, prof)
    assert len(findings) == 1


def test_supabase_filter_injection_format_call_fires(tmp_path: Path) -> None:
    (tmp_path / "orders_api.py").write_text(
        "def get_order(supabase, order_id):\n"
        "    return supabase.table('orders').select('*').or_('id.eq.{}'.format(order_id)).execute()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SupabaseFilterInjectionGuard().run(tmp_path, prof)
    assert len(findings) == 1


def test_supabase_filter_injection_percent_format_fires(tmp_path: Path) -> None:
    (tmp_path / "orders_api.py").write_text(
        "def get_order(supabase, order_id):\n"
        "    return supabase.table('orders').select('*').or_('id.eq.%s' % order_id).execute()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SupabaseFilterInjectionGuard().run(tmp_path, prof)
    assert len(findings) == 1


def test_supabase_filter_injection_single_arg_filter_fires(tmp_path: Path) -> None:
    (tmp_path / "orders_api.py").write_text(
        "def get_order(supabase, order_id):\n"
        "    return supabase.table('orders').select('*').filter(f'id.eq.{order_id}').execute()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SupabaseFilterInjectionGuard().run(tmp_path, prof)
    assert len(findings) == 1


def test_supabase_filter_injection_static_literal_stays_silent(tmp_path: Path) -> None:
    # FP-bait: a static, non-injectable filter string -- no untrusted input at all.
    (tmp_path / "orders_api.py").write_text(
        "def get_active_orders(supabase):\n"
        "    return supabase.table('orders').select('*').or_('status.eq.active,status.eq.pending').execute()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert SupabaseFilterInjectionGuard().run(tmp_path, prof) == []


def test_supabase_filter_injection_parameterized_eq_stays_silent(tmp_path: Path) -> None:
    # FP-bait: the SAFE, parameterized form -- value passed as a separate argument.
    (tmp_path / "orders_api.py").write_text(
        "def get_order(supabase, order_id, user_id):\n"
        "    return (\n"
        "        supabase.table('orders')\n"
        "        .select('*')\n"
        "        .eq('id', order_id)\n"
        "        .eq('user_id', user_id)\n"
        "        .execute()\n"
        "    )\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert SupabaseFilterInjectionGuard().run(tmp_path, prof) == []


def test_supabase_filter_injection_three_arg_filter_stays_silent(tmp_path: Path) -> None:
    # FP-bait: the SAFE 3-argument .filter(column, operator, value) form.
    (tmp_path / "orders_api.py").write_text(
        "def get_order(supabase, order_id):\n"
        "    return supabase.table('orders').select('*').filter('id', 'eq', order_id).execute()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert SupabaseFilterInjectionGuard().run(tmp_path, prof) == []


def test_supabase_filter_injection_any_or_method_fires_disclosed_scope(tmp_path: Path) -> None:
    # Pins a disclosed, deliberate over-approximation (see the design doc's Known bypasses): the
    # guard matches ANY `.or_(<f-string>)` call, not just one provably chained off a Supabase
    # `.table(...)` builder -- narrowing to a provable chain would also narrow away real
    # Supabase calls that build the builder object in a different statement/helper. A `.or_()`
    # method on an unrelated object with the same unsafe shape still fires.
    (tmp_path / "logic.py").write_text(
        "def combine(a, b):\n"
        "    return a.or_(f'{b}')\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SupabaseFilterInjectionGuard().run(tmp_path, prof)
    assert len(findings) == 1


def test_supabase_filter_injection_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "orders_api.py").write_text(
        "# security: allow-supabase-filter-concat\n"
        "def get_order(supabase, order_id):\n"
        "    return supabase.table('orders').select('*').or_(f'id.eq.{order_id}').execute()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert SupabaseFilterInjectionGuard().run(tmp_path, prof) == []


def test_supabase_filter_injection_not_applicable_without_python() -> None:
    prof = mkprofile(Path("/tmp"), features={"javascript"})
    assert SupabaseFilterInjectionGuard().applies(prof) is False
