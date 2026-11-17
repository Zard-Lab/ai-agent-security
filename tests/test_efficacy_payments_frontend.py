"""Efficacy corpus fixture: React + Stripe frontend with a docker-compose deployment.

Proves 4 critical guards (stripe-payments, build-secret, dom-xss-sinks,
compose-db-port-exposed) fire on realistic multi-file frontend + deploy config, each
paired with an adjacent safe counterpart in the same fixture: a publishable key next to
the leaked secret key, a public ANON env read next to the leaked secret env-ref, a
literal-only eval() next to the dynamic one, and a loopback-bound redis port next to the
exposed postgres port.
"""
from __future__ import annotations

from pathlib import Path

from agentsec.audit import audit
from agentsec.detect import detect

FIX = Path(__file__).resolve().parent / "fixtures" / "efficacy_payments_frontend"


def test_efficacy_payments_frontend_detection() -> None:
    p = detect(FIX)
    assert p.frontend == "vite-react"
    assert p.has_docker is True
    assert p.has_payments is True
    assert {"frontend", "docker", "payments"} <= p.features


def test_efficacy_payments_frontend_critical_guards_fire() -> None:
    r = audit(FIX, run_scanners=False)
    rules = {f.rule for f in r.findings}
    assert "stripe-payments/secret-literal-in-frontend" in rules
    assert "build-secret/secret-env-ref" in rules
    assert "dom-xss-sinks/eval-sink" in rules
    assert "compose-db-port-exposed/datastore-port-published" in rules
    critical = [f for f in r.findings if f.severity == "critical"]
    assert len(critical) >= 4


def test_efficacy_payments_frontend_fp_bait_stays_silent() -> None:
    r = audit(FIX, run_scanners=False)
    counts: dict[str, int] = {}
    for f in r.findings:
        counts[f.rule] = counts.get(f.rule, 0) + 1
    # the publishable key must not also trigger the secret-literal rule
    assert counts.get("stripe-payments/secret-literal-in-frontend") == 1
    # the public ANON key read must not also trigger the secret-env-ref rule
    assert counts.get("build-secret/secret-env-ref") == 1
    # the literal-argument eval() must not also trigger the eval-sink rule
    assert counts.get("dom-xss-sinks/eval-sink") == 1
    # the loopback-bound redis port must not also trigger the exposed-port rule
    assert counts.get("compose-db-port-exposed/datastore-port-published") == 1


def test_efficacy_payments_frontend_na_suppression() -> None:
    r = audit(FIX, run_scanners=False)
    # no llm/sql/supabase anywhere in this fixture
    assert "service-role-key" in r.skipped
