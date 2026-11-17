"""Tests for the static ↔ Splinter cross-confirmation seam (provenance + dedup)."""
from __future__ import annotations

from pathlib import Path

from agentsec.crosscheck import _norm_object, _static_object, crosscheck
from agentsec.findings import Finding
from agentsec.prioritize import priority_rank


def _sql(tmp_path: Path, name: str, body: str) -> None:
    sql = tmp_path / "sql"
    sql.mkdir(exist_ok=True)
    (sql / name).write_text(body, encoding="utf-8")


def _static(check_id: str, location: str, rule: str = "") -> Finding:
    return Finding(check_id=check_id, severity="high", title="t", location=location, rule=rule or f"{check_id}/x")


def _splinter(lint: str, entity: str, sev: str = "high") -> Finding:
    return Finding(check_id="splinter", severity=sev, title="lint", location=entity, rule=f"splinter-{lint}")


# --- object normalization + extraction ---

def test_norm_object_strips_schema_and_quotes() -> None:
    assert _norm_object('"public"."documents_1024"') == "documents_1024"
    assert _norm_object("public.t") == "t"
    assert _norm_object("documents_1024") == "documents_1024"


def test_static_object_extraction_by_category(tmp_path: Path) -> None:
    _sql(tmp_path, "s.sql",
         "CREATE POLICY p ON public.docs USING (true);\n"
         "CREATE VIEW v_users AS SELECT 1;\n"
         "CREATE EXTENSION IF NOT EXISTS pgcrypto;\n")
    assert _static_object(_static("rls-permissive-policy", "sql/s.sql:1"), tmp_path) == "docs"
    assert _static_object(_static("pg-security-definer-view", "sql/s.sql:2"), tmp_path) == "v_users"
    assert _static_object(_static("pg-extension-in-public", "sql/s.sql:3"), tmp_path) == "pgcrypto"


# --- provenance classes ---

def test_confirmed_live_and_dedup(tmp_path: Path) -> None:
    _sql(tmp_path, "snap.sql", "CREATE POLICY p ON public.docs FOR SELECT TO authenticated USING (true);\n")
    sf = _static("rls-permissive-policy", "sql/snap.sql:1", "rls-permissive-policy/always-true")
    spl = _splinter("rls_policy_always_true", "public.docs")
    res = crosscheck([sf, spl], tmp_path)
    assert sf.provenance == "confirmed-live"
    assert res.confirmed == 1 and res.deduped == 1
    assert spl not in res.findings          # duplicate Splinter folded out
    assert sf in res.findings               # actionable static one kept


def test_static_only_when_no_splinter_match_is_tag_only(tmp_path: Path) -> None:
    _sql(tmp_path, "snap.sql", "CREATE POLICY p ON public.docs USING (true);\n")
    sf = _static("rls-permissive-policy", "sql/snap.sql:1")
    other_splinter = _splinter("rls_policy_always_true", "public.unrelated")
    from agentsec.prioritize import reachability
    res = crosscheck([sf, other_splinter], tmp_path)
    assert sf.provenance == "static-only" and res.static_only == 1
    assert reachability(sf) == "product"    # TAG ONLY — never demoted


def test_splinter_only_when_no_static_match(tmp_path: Path) -> None:
    spl = _splinter("extension_in_public", "public.dashboard_made_obj")
    res = crosscheck([spl], tmp_path)
    assert spl.provenance == "splinter-only" and res.splinter_only == 1


def test_no_splinter_is_noop(tmp_path: Path) -> None:
    _sql(tmp_path, "snap.sql", "CREATE POLICY p ON public.docs USING (true);\n")
    sf = _static("rls-permissive-policy", "sql/snap.sql:1")
    res = crosscheck([sf], tmp_path)
    assert sf.provenance == "" and res.confirmed == res.static_only == res.splinter_only == 0


# --- prioritize boost ---

def test_confirmed_live_ranks_above_unconfirmed() -> None:
    confirmed = _static("rls-permissive-policy", "sql/a.sql:1")
    confirmed.provenance = "confirmed-live"
    plain = _static("rls-permissive-policy", "sql/b.sql:1")
    assert priority_rank(confirmed) < priority_rank(plain)


def test_confirmed_live_overrides_superseded_demotion() -> None:
    # #1: the live DB confirming an issue means it is NOT historical, even if its file is superseded.
    from agentsec.prioritize import reachability
    f = _static("rls-permissive-policy", "sql/36-old.sql:1")
    f.superseded = True
    f.provenance = "confirmed-live"
    assert reachability(f) == "product"  # un-demoted by the live confirmation
    # superseded + static-only stays demoted
    g = _static("rls-permissive-policy", "sql/36-old.sql:1")
    g.superseded, g.provenance = True, "static-only"
    assert reachability(g) == "low"


def test_pg_anon_grant_on_definer_function_confirmed_live(tmp_path: Path) -> None:
    # #3: a GRANT EXECUTE on a definer function ↔ Splinter's executable-definer lint, matched by name.
    _sql(tmp_path, "g.sql", "GRANT EXECUTE ON FUNCTION public.can_access_subdirectory(text, uuid) TO anon;\n")
    gf = _static("pg-anon-grant", "sql/g.sql:1", "pg-anon-grant/grant-to-anon-public")
    spl = _splinter("anon_security_definer_function_executable", "can_access_subdirectory", "medium")
    res = crosscheck([gf, spl], tmp_path)
    assert gf.provenance == "confirmed-live" and res.deduped == 1


def test_superseded_static_only_renders_combined_label(tmp_path: Path) -> None:
    # #4a: superseded + static-only collapses to one "historical" tag (not two).
    from agentsec.findings import to_markdown
    f = _static("rls-permissive-policy", "sql/36-old.sql:1")
    f.superseded, f.provenance = True, "static-only"
    md = to_markdown([f])
    assert "history: a schema dump is authoritative here; not in the live DB" in md
    assert "static — not confirmed live" not in md  # not the separate tag
