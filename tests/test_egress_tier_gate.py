"""Phase 2 (RFC #135 decision #4): the Tier-0 egress gate on the external scanners.

A runner that phones out (`tier_required >= 1`) must be SKIPPED — not run, so nothing
egresses — when the active `--network` tier is lower, and DISCLOSED (never silently dropped).
react-doctor is local-only at every tier: it sends no scan data (Score API + Socket both off).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.audit import audit
from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.runners.base import Runner, RunnerResult
from agentsec.runners.react_doctor import ReactDoctorRunner
from tests.conftest import mkprofile


class _StubRunner(Runner):
    """A runner whose `run()` always 'succeeds' with one finding — no binary needed."""

    def __init__(self, rid: str, tier: int) -> None:
        self.id = rid
        self.tier_required = tier

    def applies(self, profile: object) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: object) -> RunnerResult:  # noqa: ARG002
        return RunnerResult(
            runner_id=self.id, available=True,
            findings=[Finding(check_id=self.id, severity="high", title=self.id,
                              location="a.py:1", rule=f"{self.id}/r")],
        )


_STUBS = [
    _StubRunner("pip-audit", 1), _StubRunner("node-audit", 1),
    _StubRunner("trivy", 1), _StubRunner("react-doctor", 1),
    _StubRunner("bandit", 0),  # local scanner — never tier-gated
]


def _run(tmp_path: Path, tier: int, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agentsec.audit.select_runners", lambda profile: _STUBS)
    monkeypatch.setattr("agentsec.audit.select_guards", lambda profile: [])
    monkeypatch.setattr("agentsec.audit.detect", lambda root: mkprofile(tmp_path, features={"python", "frontend"}))
    return audit(tmp_path, network_tier=tier, exceptions_path=Path("/dev/null"))


def test_deterministic_suppresses_kev_and_epss_egress_even_at_tier1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Review #609 H4: kev/epss enrichment was gated on the RAW network_tier parameter, not the
    # deterministic-capped profile.network_tier — so `--deterministic --network tier1 --kev/--epss`
    # egressed and stamped a live, daily-changing score into a run that's supposed to be
    # reproducible. A CVE-bearing finding is required to trigger the branch at all (fetch_epss
    # returns early on an empty CVE set) — mirrors the review's own repro.
    monkeypatch.setattr("agentsec.audit.select_runners", lambda profile: [])
    monkeypatch.setattr("agentsec.audit.select_guards", lambda profile: [])
    monkeypatch.setattr("agentsec.audit.detect", lambda root: mkprofile(tmp_path, features={"python"}))

    kev_calls: list[int] = []
    epss_calls: list[int] = []
    monkeypatch.setattr("agentsec.kev.fetch_kev", lambda **kw: (kev_calls.append(1), set())[1])
    monkeypatch.setattr("agentsec.epss.fetch_epss", lambda *a, **kw: (epss_calls.append(1), {})[1])

    cve_finding = Finding(check_id="dependency-version-floor", severity="high", title="x",
                           rule="CVE-2024-3094", location="requirements.txt:1")
    audit(
        tmp_path, network_tier=1, deterministic=True, kev=True, epss=True,
        extra_findings=[cve_finding], exceptions_path=Path("/dev/null"),
    )
    assert kev_calls == [] and epss_calls == [], "deterministic must suppress KEV/EPSS egress at any tier"


def test_non_deterministic_tier1_still_calls_kev_and_epss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The counterweight: the fix must not also break the intended non-deterministic path.
    monkeypatch.setattr("agentsec.audit.select_runners", lambda profile: [])
    monkeypatch.setattr("agentsec.audit.select_guards", lambda profile: [])
    monkeypatch.setattr("agentsec.audit.detect", lambda root: mkprofile(tmp_path, features={"python"}))

    kev_calls: list[int] = []
    epss_calls: list[int] = []
    monkeypatch.setattr("agentsec.kev.fetch_kev", lambda **kw: (kev_calls.append(1), set())[1])
    monkeypatch.setattr("agentsec.epss.fetch_epss", lambda *a, **kw: (epss_calls.append(1), {})[1])

    cve_finding = Finding(check_id="dependency-version-floor", severity="high", title="x",
                           rule="CVE-2024-3094", location="requirements.txt:1")
    audit(
        tmp_path, network_tier=1, deterministic=False, kev=True, epss=True,
        extra_findings=[cve_finding], exceptions_path=Path("/dev/null"),
    )
    assert kev_calls == [1] and epss_calls == [1]


def test_audit_epss_integration_badge_reaches_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Review #609 M4: every existing EPSS test exercised epss.py/prioritize.py in isolation.
    # Nothing drove `audit(..., epss=True)` end to end -- H1's crash lived exactly there (the
    # malformed-response path only becomes visible once a real response travels through
    # fetch_epss into audit()). Stub agentsec.net.get directly (not epss.fetch_epss) so this is
    # a genuine integration test of the real fetch path, not a re-test of the unit already covered.
    from agentsec.findings import to_markdown

    monkeypatch.setattr("agentsec.audit.select_runners", lambda profile: [])
    monkeypatch.setattr("agentsec.audit.select_guards", lambda profile: [])
    monkeypatch.setattr("agentsec.audit.detect", lambda root: mkprofile(tmp_path, features={"python"}))
    monkeypatch.setattr(
        "agentsec.net.get",
        lambda *a, **k: b'{"data":[{"cve":"CVE-2024-3094","epss":"0.94"}]}',
    )
    # epss.fetch_epss() has no cache_dir override reachable from audit() — without redirecting
    # cache_path() this would read/write the real ~/.agentsec/epss-cache.json, both polluting the
    # developer's machine and leaking state across test runs (a CVE cached by one test masks the
    # next test's stub response entirely).
    monkeypatch.setattr("agentsec.epss.cache_path", lambda cache_dir=None: tmp_path / "epss-cache.json")

    cve_finding = Finding(check_id="dependency-version-floor", severity="high", title="x",
                           rule="CVE-2024-3094", location="requirements.txt:1")
    result = audit(
        tmp_path, network_tier=1, epss=True,
        extra_findings=[cve_finding], exceptions_path=Path("/dev/null"),
    )
    assert "📈 **[EPSS: 94%]**" in to_markdown(result.findings)


def test_audit_epss_malformed_response_does_not_lose_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The counterweight: the H1 fix must degrade the enrichment, not the whole audit -- the
    # underlying finding list must be identical to the epss=False run, not lost or crashed.
    monkeypatch.setattr("agentsec.audit.select_runners", lambda profile: [])
    monkeypatch.setattr("agentsec.audit.select_guards", lambda profile: [])
    monkeypatch.setattr("agentsec.audit.detect", lambda root: mkprofile(tmp_path, features={"python"}))
    monkeypatch.setattr("agentsec.net.get", lambda *a, **k: b'{"status":"error","data":null}')
    monkeypatch.setattr("agentsec.epss.cache_path", lambda cache_dir=None: tmp_path / "epss-cache.json")

    cve_finding = Finding(check_id="dependency-version-floor", severity="high", title="x",
                           rule="CVE-2024-3094", location="requirements.txt:1")
    result = audit(  # must not raise
        tmp_path, network_tier=1, epss=True,
        extra_findings=[cve_finding], exceptions_path=Path("/dev/null"),
    )
    assert len(result.findings) == 1
    assert result.findings[0].epss is None


def test_tier0_skips_all_egressing_runners(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    r = _run(tmp_path, 0, monkeypatch)
    assert set(r.tools_offline_skipped) == {"pip-audit", "node-audit", "trivy", "react-doctor"}
    assert "bandit" in r.ran                      # local scanner still runs at tier 0
    assert not any(f.check_id in {"pip-audit", "node-audit", "trivy", "react-doctor"} for f in r.findings)


def test_tier1_runs_all_egressing_runners(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    r = _run(tmp_path, 1, monkeypatch)
    assert r.tools_offline_skipped == []
    assert {"pip-audit", "node-audit", "trivy", "react-doctor", "bandit"} <= set(r.ran)


def test_local_scanner_runs_at_tier0(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    r = _run(tmp_path, 0, monkeypatch)
    assert "bandit" in r.ran and "bandit" not in r.tools_offline_skipped


def test_egress_catalog_matches_runner_tiers() -> None:
    from agentsec.cli import _EGRESS_CATALOG
    from agentsec.registry import ALL_RUNNERS

    egressing = {r.id: r.tier_required for r in ALL_RUNNERS if r.tier_required > 0}
    assert egressing == {
        "pip-audit": 1, "node-audit": 1, "trivy": 1, "react-doctor": 1, "scorecard": 1,
        "go-osv-hygiene": 1,
    }
    runner_dests = {e[0] for e in _EGRESS_CATALOG}
    # scorecard has a disclosure row in the catalog (tier 1, sends no source code).
    assert "scorecard" in runner_dests
    sc = next(e for e in _EGRESS_CATALOG if e[0] == "scorecard")
    assert sc[3] == 1 and "no source code" in sc[2].lower()
    # No runner-backed catalog entry may claim tier 2 (react-doctor was demoted to tier 1).
    assert "react-doctor" in runner_dests
    rd = next(e for e in _EGRESS_CATALOG if e[0] == "react-doctor")
    assert rd[3] == 1 and "nothing" in rd[2].lower()  # tier 1, sends nothing about your code
    # #421: semgrep's registry-config fetch is disclosed as a tier-1 advisory download that
    # sends nothing about your code. semgrep keeps tier_required=0 (it still runs at tier 0
    # with its local pack), so it is a static catalog row, not in the `egressing` dict above.
    assert "semgrep" not in egressing
    sg = next(e for e in _EGRESS_CATALOG if e[0].startswith("semgrep"))
    assert sg[3] == 1 and "nothing about your code" in sg[2].lower()


def test_react_doctor_disables_supply_chain_when_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, str | None] = {}

    def fake_exec(args, cwd, timeout=600, env_extra=None):  # noqa: ANN001, ARG001
        cfg = Path(cwd) / "react-doctor.config.json"
        seen["during"] = cfg.read_text(encoding="utf-8") if cfg.exists() else None
        return (0, "{}", "")

    monkeypatch.setattr("agentsec.runners.react_doctor.exec_capture_or_raise", fake_exec)
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir="")
    ReactDoctorRunner().invoke(tmp_path, prof)
    assert seen["during"] is not None and "false" in seen["during"]  # supplyChain disabled during run
    assert not (tmp_path / "react-doctor.config.json").exists()       # our temp config cleaned up


def test_react_doctor_respects_existing_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    existing = '{"my": "config"}'
    (tmp_path / "react-doctor.config.json").write_text(existing, encoding="utf-8")
    captured: dict[str, str] = {}

    def fake_exec(args, cwd, timeout=600, env_extra=None):  # noqa: ANN001, ARG001
        captured["content"] = (Path(cwd) / "react-doctor.config.json").read_text(encoding="utf-8")
        return (0, "{}", "")

    monkeypatch.setattr("agentsec.runners.react_doctor.exec_capture_or_raise", fake_exec)
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir="")
    ReactDoctorRunner().invoke(tmp_path, prof)
    assert captured["content"] == existing                                   # not clobbered during run
    assert (tmp_path / "react-doctor.config.json").read_text(encoding="utf-8") == existing  # still intact


def test_react_doctor_does_not_remove_a_config_it_did_not_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrency-ownership (the O_EXCL guard): if a `react-doctor.config.json` is already
    present when invoke() starts — e.g. a *concurrent* audit's temp config — our atomic
    O_EXCL create fails, so we do NOT own it and must NOT remove it on cleanup (the owner
    does). This is what prevents the double-create / double-remove race Marconi flagged."""
    cfg = tmp_path / "react-doctor.config.json"
    cfg.write_text('{"supplyChain": {"enabled": false}}\n', encoding="utf-8")  # "another run" made it
    removed_during = {"gone": False}

    def fake_exec(args, cwd, timeout=600, env_extra=None):  # noqa: ANN001, ARG001
        removed_during["gone"] = not (Path(cwd) / "react-doctor.config.json").exists()
        return (0, "{}", "")

    monkeypatch.setattr("agentsec.runners.react_doctor.exec_capture_or_raise", fake_exec)
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir="")
    ReactDoctorRunner().invoke(tmp_path, prof)
    assert removed_during["gone"] is False  # present during our run (we didn't touch it)
    assert cfg.exists()                     # and we did NOT remove it afterwards — not our config


def test_react_doctor_cleans_up_orphan_when_write_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Write-failure cleanup: if O_EXCL create succeeds but the subsequent os.write raises
    (disk full / quota / NFS), we must remove the empty file we created. Otherwise every
    future audit sees the zero-byte orphan as a pre-existing user config and silently stops
    injecting `supplyChain.enabled:false` — a persistent supply-chain egress bypass. The run
    itself must still proceed (never crash the audit)."""
    def fail_write(fd, data):  # noqa: ANN001, ANN202
        raise OSError("simulated disk full")

    def fake_exec(args, cwd, timeout=600, env_extra=None):  # noqa: ANN001, ARG001
        return (0, "{}", "")

    monkeypatch.setattr("agentsec.runners.react_doctor.os.write", fail_write)
    monkeypatch.setattr("agentsec.runners.react_doctor.exec_capture_or_raise", fake_exec)
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir="")
    out = ReactDoctorRunner().invoke(tmp_path, prof)
    assert out == "{}"                                              # run still proceeded
    assert not (tmp_path / "react-doctor.config.json").exists()     # the empty orphan was cleaned up


class _TierProbeRunner(Runner):
    """Records the `profile.network_tier` it observes — proves what audit() stamps."""

    def __init__(self) -> None:
        self.id = "tier-probe"
        self.tier_required = 0
        self.seen_tier: int | None = None

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> RunnerResult:  # noqa: ARG002
        self.seen_tier = profile.network_tier
        return RunnerResult(runner_id=self.id, available=True, findings=[])


def test_deterministic_caps_runner_tier_to_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # #421 review (High): a --deterministic run (CI gate / baseline) must be reproducible, so the
    # tier a config-choosing runner (semgrep) sees is capped to 0 even at --network tier1/--kev —
    # otherwise semgrep would fetch the drifting OSS registry packs inside a gate meant to be
    # hermetic. Paired with test_semgrep_invoke_tier0_runs_local_pack_only (tier 0 → no p/ configs),
    # this proves the whole path: audit() caps → profile.network_tier → semgrep runs local-only.
    probe = _TierProbeRunner()
    monkeypatch.setattr("agentsec.audit.select_runners", lambda profile: [probe])
    monkeypatch.setattr("agentsec.audit.select_guards", lambda profile: [])
    monkeypatch.setattr("agentsec.audit.detect", lambda root: mkprofile(tmp_path, features={"python"}))

    audit(tmp_path, network_tier=1, deterministic=True, exceptions_path=Path("/dev/null"))
    assert probe.seen_tier == 0            # capped despite network_tier=1

    probe.seen_tier = None
    audit(tmp_path, network_tier=1, deterministic=False, exceptions_path=Path("/dev/null"))
    assert probe.seen_tier == 1            # a non-deterministic run passes the real tier through
