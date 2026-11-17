"""Efficacy corpus fixture: AI coding-assistant tooling repo with planted config compromises.

Proves the two ungated critical guards (claude-code-compromise, ai-instruction-poisoning) fire on
a realistic, multi-file repo rather than an isolated snippet, while staying silent on the
surrounding safe config in the same repo (a loopback-only netcat healthcheck, a hooks command that
runs a local script, and a negation-guarded instruction line).
"""
from __future__ import annotations

from pathlib import Path

from agentsec.audit import audit
from agentsec.detect import detect

FIX = Path(__file__).resolve().parent / "fixtures" / "efficacy_ai_devtools"


def test_efficacy_ai_devtools_detection() -> None:
    p = detect(FIX)
    assert p.backend_framework == "fastapi"
    assert p.llm_framework == "pydantic-ai"
    assert {"python", "fastapi", "pydantic-ai", "llm"} <= p.features


def test_efficacy_ai_devtools_critical_guards_fire() -> None:
    r = audit(FIX, run_scanners=False)
    rules = {f.rule for f in r.findings}
    assert "claude-code-compromise/reverse-shell" in rules
    assert "claude-code-compromise/codex-home-redirect" in rules
    assert "ai-instruction-poisoning/auto-approve-enabled" in rules
    critical = [f for f in r.findings if f.severity == "critical"]
    assert len(critical) >= 3


def test_efficacy_ai_devtools_fp_bait_stays_silent() -> None:
    r = audit(FIX, run_scanners=False)
    rules = {f.rule for f in r.findings}
    # the healthcheck is a loopback-only `nc -z`, not a reverse-shell `-e /bin/sh`
    # the hook's command runs a local script, not curl/wget to an external host
    assert "ai-instruction-poisoning/hook-exfiltration" not in rules
    # "Never bypass..." is negation-guarded guidance, not an escalation instruction
    assert "ai-instruction-poisoning/privilege-escalation-instruction" not in rules


def test_efficacy_ai_devtools_na_suppression() -> None:
    r = audit(FIX, run_scanners=False)
    # no payments/sql/frontend anywhere in this fixture
    assert "stripe-payments" in r.skipped
