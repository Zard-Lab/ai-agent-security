"""Efficacy corpus fixture: a Python agent consuming external MCP tool servers.

Proves 4 critical guards (mcp-tool-unverified, mcp-config-security,
dependency-version-floor, slopsquatting) fire on realistic multi-file agent + config +
dependency-manifest code, each paired with an adjacent safe counterpart: a
properly-pinned `mcp` package next to the vulnerable `mcp-server-git` pin, a scoped
`roots` path next to the hardcoded secret, and an ordinary PyPI package next to the
npm-only `pip install`.
"""
from __future__ import annotations

from pathlib import Path

from agentsec.audit import audit
from agentsec.detect import detect

FIX = Path(__file__).resolve().parent / "fixtures" / "efficacy_mcp_agent"


def test_efficacy_mcp_agent_detection() -> None:
    p = detect(FIX)
    assert p.llm_framework == "pydantic-ai"
    assert {"python", "llm", "mcp"} <= p.features


def test_efficacy_mcp_agent_critical_guards_fire() -> None:
    r = audit(FIX, run_scanners=False)
    rules = {f.rule for f in r.findings}
    assert "mcp-tool-unverified/cve-2025-6514-mcp-remote" in rules
    assert "mcp-config/hardcoded-secret-in-env" in rules
    assert "dependency-version-floor/below-patched-version" in rules
    assert "slopsquatting/cross-ecosystem-pip-install" in rules
    critical = [f for f in r.findings if f.severity == "critical"]
    assert len(critical) >= 4


def test_efficacy_mcp_agent_fp_bait_stays_silent() -> None:
    r = audit(FIX, run_scanners=False)
    counts: dict[str, int] = {}
    for f in r.findings:
        counts[f.rule] = counts.get(f.rule, 0) + 1
    # the mcp-remote CVE check must fire exactly once (not duplicated / not confused
    # by the fixed mcp==1.28.1 pin)
    assert counts.get("mcp-tool-unverified/cve-2025-6514-mcp-remote") == 1
    # the hardcoded secret must fire exactly once
    assert counts.get("mcp-config/hardcoded-secret-in-env") == 1
    # the scoped /app/uploads root must not also trigger a wildcard-path finding
    assert counts.get("mcp-config/wildcard-path-grant") is None
    # `mcp`'s floor was bumped 1.23.0 -> 1.27.2 (CVE-2026-52869). (this
    # project's own MCP research) bumped it again, 1.27.2 -> 1.28.1, for CVE-2026-59950 (a 2nd,
    # WebSocket-transport-specific DNS-rebinding path) + CVE-2026-52870 (task-handler cross-client
    # access, same patch release as 52869). The fixture pin was bumped to match each time so this
    # stays a genuine "properly patched" case rather than newly tripping its own version-floor
    # finding.
    # the properly-pinned mcp==1.28.1 dependency must not also fire a version-floor finding
    below_floor = [
        f for f in r.findings if f.rule == "dependency-version-floor/below-patched-version"
    ]
    assert all("mcp-server-git" in f.title for f in below_floor)
    # the ordinary `pip install requests` must not also trigger the cross-ecosystem rule
    assert counts.get("slopsquatting/cross-ecosystem-pip-install") == 1


def test_efficacy_mcp_agent_na_suppression() -> None:
    r = audit(FIX, run_scanners=False)
    # no payments/sql/supabase anywhere in this fixture
    assert "stripe-payments" in r.skipped
