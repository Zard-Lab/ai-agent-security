"""Efficacy corpus fixture: a multi-tenant SaaS API on FastAPI + Supabase.

Proves 3 critical guards (service-role-key, definer-function-grants,
privileged-field-assignment) fire on realistic multi-file backend + SQL + frontend
code, each paired with an adjacent safe counterpart: an anon JWT next to the leaked
service_role JWT, a properly-revoked SECURITY DEFINER function next to the unrevoked
one, and an admin-checked PATCH handler next to the unchecked one.
"""
from __future__ import annotations

from pathlib import Path

from agentsec.audit import audit
from agentsec.detect import detect

FIX = Path(__file__).resolve().parent / "fixtures" / "efficacy_multitenant_api"


def test_efficacy_multitenant_api_detection() -> None:
    p = detect(FIX)
    assert p.backend_framework == "fastapi"
    assert p.db == "supabase"
    assert {"python", "fastapi", "supabase", "sql"} <= p.features


def test_efficacy_multitenant_api_critical_guards_fire() -> None:
    r = audit(FIX, run_scanners=False)
    rules = {f.rule for f in r.findings}
    assert "service-role-key/jwt-literal-in-frontend" in rules
    assert "definer-function-grants/executable-by-public" in rules
    assert "privileged-field-assignment/unchecked-privilege-write" in rules
    critical = [f for f in r.findings if f.severity == "critical"]
    assert len(critical) >= 3


def test_efficacy_multitenant_api_fp_bait_stays_silent() -> None:
    r = audit(FIX, run_scanners=False)
    counts: dict[str, int] = {}
    for f in r.findings:
        counts[f.rule] = counts.get(f.rule, 0) + 1
    # the anon JWT must not also decode-match the service_role rule
    assert counts.get("service-role-key/jwt-literal-in-frontend") == 1
    assert counts.get("service-role-key/reference-in-frontend") is None
    # the revoked get_tenant_summary() must not also fire
    assert counts.get("definer-function-grants/executable-by-public") == 1
    # the same function, proven vault-reading by its BODY; get_tenant_summary() touches no vault
    vault = [f for f in r.findings if f.rule == "supabase-vault-exposure/definer-function-executable"]
    assert [f.location.replace("\\", "/") for f in vault] == ["sql/001_functions.sql:2"]
    # the admin-checked handler must not also fire
    assert counts.get("privileged-field-assignment/unchecked-privilege-write") == 1


def test_efficacy_multitenant_api_na_suppression() -> None:
    r = audit(FIX, run_scanners=False)
    # no payments/mcp/llm anywhere in this fixture
    assert "stripe-payments" in r.skipped
