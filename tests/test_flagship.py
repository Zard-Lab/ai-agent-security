"""Phase 6 regression oracle: a synthetic `9_Agent_SaaS`-shaped repo.

Mirrors the flagship target (Pydantic-AI + FastAPI + Supabase + Stripe) with
planted violations, so the end-to-end behavior is pinned without cloning the
upstream. Guards-only → deterministic regardless of which scanners are installed.
"""
from __future__ import annotations

from pathlib import Path

from agentsec.audit import audit
from agentsec.detect import detect

FIX = Path(__file__).resolve().parent / "fixtures" / "saas_sample"


def test_flagship_detection() -> None:
    p = detect(FIX)
    assert p.backend_framework == "fastapi"
    assert p.llm_framework == "pydantic-ai"
    assert p.db == "supabase"
    assert p.frontend is not None
    assert p.has_payments is True
    assert {"payments", "pydantic-ai", "llm", "supabase", "frontend", "sql"} <= p.features


def test_flagship_payments_and_trifecta_fire() -> None:
    r = audit(FIX, run_scanners=False)
    rules = {f.rule for f in r.findings}
    # payments checks fire because Stripe is detected (the N/A-suppression worked example, on side)
    assert "stripe-payments/webhook-unverified" in rules
    assert "stripe-payments/secret-in-client-env" in rules
    # public billing table without RLS
    assert "public-table-rls/rls-disabled-in-public" in rules
    # full lethal trifecta, no defense
    assert "lethal-trifecta/no-defense" in rules
    assert any(f.severity in ("high", "critical") for f in r.findings)
    assert "stripe-payments" in r.ran and "stripe-payments" not in r.skipped


def test_flagship_security_headers_fires() -> None:
    # The flagship backend (agent.py imports FastAPI but sets no security headers
    # anywhere) is a true positive for the §6a absence guard.
    r = audit(FIX, run_scanners=False)
    assert "security-headers/no-security-headers-middleware" in {f.rule for f in r.findings}


def test_flagship_system_prompt_leak_fires() -> None:
    # The flagship agent defines a system prompt (agent.py) with no leak filter
    # anywhere — a true positive for the §4 absence guard. It coexists with the
    # full-trifecta lethal-trifecta/no-defense finding (two framings of the gap).
    r = audit(FIX, run_scanners=False)
    assert "system-prompt-leak/no-leak-filter" in {f.rule for f in r.findings}


def test_flagship_sensitive_logging_fires() -> None:
    # The flagship billing webhook logs the raw request body — a true positive
    # for the §10 sensitive-data-in-logs guard (HIGH tier).
    r = audit(FIX, run_scanners=False)
    assert "sensitive-logging/request-body-logged" in {f.rule for f in r.findings}


def test_flagship_input_delimiters_fires() -> None:
    # The flagship agent feeds raw user input into agent.run_sync() with no
    # delimiter wrapping anywhere — a true positive for the §3b absence guard.
    # Coexists with system-prompt-leak + lethal-trifecta/no-defense.
    r = audit(FIX, run_scanners=False)
    assert "input-delimiters/unwrapped-user-input" in {f.rule for f in r.findings}


def test_flagship_frontend_xss_fires() -> None:
    # Locks in the three frontend findings the REAL 9_Agent_SaaS app exposed
    # (the original synthetic fixture had only package.json under frontend/).
    r = audit(FIX, run_scanners=False)
    by_rule = {f.rule: f for f in r.findings}
    assert "frontend-xss/rehype-raw-unsanitized" in by_rule          # MessageItem.tsx
    assert "frontend-xss/dangerously-set-inner-html" in by_rule      # chart.tsx
    assert "frontend-xss/script-no-sri" in by_rule                   # index.html (cdn.gpteng.co)
    # the first-party relative script in index.html must NOT be flagged
    assert "/src/main.tsx" not in by_rule["frontend-xss/script-no-sri"].message


def test_donor_repo_suppresses_payments() -> None:
    # The agentsec repo itself / a no-payments stack must N/A-suppress the
    # payments guard. Use a payments-free synthetic to keep it hermetic.
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "app.py").write_text("from fastapi import FastAPI\nfrom pydantic_ai import Agent\n", encoding="utf-8")
        r = audit(root, run_scanners=False)
        assert "stripe-payments" in r.skipped
        assert not any(f.check_id == "stripe-payments" for f in r.findings)
