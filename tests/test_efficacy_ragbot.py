"""Efficacy corpus fixture: a RAG/PDF-chat backend on FastAPI + pydantic-ai + LangChain.

Proves 6 critical guards (dataset-injection, ml-model-provenance, path-traversal,
unsafe-deserialization, command-injection, langchain-serialization) fire on realistic
multi-file agent code, each paired with an adjacent safe counterpart in the same
fixture: a literal template path next to the LLM-output-as-path, an HTTPS download
next to the HTTP one, a static shell command next to the interpolated one, JSON
loading next to pickle, ordinary template formatting next to the unsafe
langchain-core loads() call, and a clean FAQ document next to the poisoned one.
"""
from __future__ import annotations

from pathlib import Path

from agentsec.audit import audit
from agentsec.detect import detect

FIX = Path(__file__).resolve().parent / "fixtures" / "efficacy_ragbot"


def test_efficacy_ragbot_detection() -> None:
    p = detect(FIX)
    assert p.backend_framework == "fastapi"
    assert p.llm_framework == "pydantic-ai"
    assert {"python", "fastapi", "pydantic-ai", "llm"} <= p.features


def test_efficacy_ragbot_critical_guards_fire() -> None:
    r = audit(FIX, run_scanners=False)
    rules = {f.rule for f in r.findings}
    assert "dataset-injection/payload-marker" in rules
    assert "ml-model-provenance/http-model-download" in rules
    assert "path-traversal/llm-output-as-path" in rules
    assert "unsafe-deserialization/untrusted-load" in rules
    assert "command-injection/shell-exec-untrusted" in rules
    assert "langchain-serialization/loads-dynamic-content" in rules
    critical = [f for f in r.findings if f.severity == "critical"]
    assert len(critical) >= 6


def test_efficacy_ragbot_fp_bait_stays_silent() -> None:
    r = audit(FIX, run_scanners=False)
    counts: dict[str, int] = {}
    for f in r.findings:
        counts[f.rule] = counts.get(f.rule, 0) + 1
    # the poisoned onboarding doc must fire exactly once; the clean FAQ doc must not
    assert counts.get("dataset-injection/payload-marker") == 1
    # the HTTPS download must not also trigger the HTTP-download rule
    assert counts.get("ml-model-provenance/http-model-download") == 1
    # the literal template path must not also trigger the LLM-output-as-path rule
    assert counts.get("path-traversal/llm-output-as-path") == 1
    # json.loads must not also trigger the untrusted-load rule
    assert counts.get("unsafe-deserialization/untrusted-load") == 1
    # the static `ls -la` command must not also trigger the shell-exec rule
    assert counts.get("command-injection/shell-exec-untrusted") == 1
    # ordinary template formatting must not also trigger the loads-dynamic-content rule
    assert counts.get("langchain-serialization/loads-dynamic-content") == 1


def test_efficacy_ragbot_na_suppression() -> None:
    r = audit(FIX, run_scanners=False)
    # no payments/sql/supabase anywhere in this fixture
    assert "stripe-payments" in r.skipped
    assert "service-role-key" in r.skipped
