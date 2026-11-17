"""Honest coverage disclosure — a scanner that RAN but covered less must say so (#434).

#433 correctly moved semgrep's OSS registry packs (`p/python`, `p/owasp-top-ten`,
`p/secrets`) behind `--network tier1`, because `--config p/...` downloads them and the
Tier-0 default promises no egress. The cost is a real rule-set drop at the DEFAULT tier
(`subprocess-shell-true`, `insecure-file-permissions`, `insecure-hash-algorithm-md5` fire
at Tier 1 and not at Tier 0) — and semgrep is not `unavailable`, not `offline_skipped` and
not `errored`, so it appears plainly under *Checks run* and the report is indistinguishable
from a full-coverage run. Whether a *given* dropped rule leaves a real hole depends on
guard overlap, which is exactly why the disclosure has to name the missing packs and let
the reader judge, rather than the tool asserting either "covered" or "lost".

These tests pin the disclosure end to end: the runner hook → `AuditResult.tools_reduced` →
the markdown footer → SARIF `toolExecutionNotifications` (the documented CI path, which
previously carried no scanner disclosure at all).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.audit import AuditResult, audit
from agentsec.detect import StackProfile
from agentsec.findings import COVERAGE_NOTIFICATION_ID, Finding, to_sarif
from agentsec.runners.base import Runner, RunnerResult
from agentsec.runners.semgrep import _REGISTRY_CONFIGS, SemgrepRunner
from tests.conftest import mkprofile


class _FakeSemgrep(SemgrepRunner):
    """The REAL semgrep runner (so the real `coverage_note` is exercised) with the
    binary invocation stubbed out — the disclosure must not depend on a local install."""

    def run(self, root: Path, profile: StackProfile) -> RunnerResult:  # noqa: ARG002
        return RunnerResult(runner_id=self.id, available=True, findings=[])


def _audit_with(runners: list[Runner], tmp_path: Path, tier: int,
                monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agentsec.audit.select_runners", lambda profile: runners)
    monkeypatch.setattr("agentsec.audit.select_guards", lambda profile: [])
    monkeypatch.setattr("agentsec.audit.detect",
                        lambda root: mkprofile(tmp_path, features={"python"}))
    return audit(tmp_path, network_tier=tier, exceptions_path=Path("/dev/null"))


# --- the runner hook ---------------------------------------------------------------

def test_semgrep_discloses_reduced_rule_set_at_tier0(tmp_path: Path) -> None:
    profile = StackProfile(root=tmp_path, features={"python"}, python_dirs=["."], network_tier=0)
    note = SemgrepRunner().coverage_note(profile)
    assert note is not None
    # Naming the missing packs is the point — "reduced" alone doesn't let a reader judge.
    for pack in _REGISTRY_CONFIGS:
        assert pack in note
    assert "tier1" in note


def test_semgrep_has_no_coverage_note_at_tier1(tmp_path: Path) -> None:
    profile = StackProfile(root=tmp_path, features={"python"}, python_dirs=["."], network_tier=1)
    assert SemgrepRunner().coverage_note(profile) is None


def test_runner_base_defaults_to_full_coverage(tmp_path: Path) -> None:
    """Every other runner keeps a silent default — no false "reduced" noise."""
    from agentsec.runners.bandit import BanditRunner

    profile = StackProfile(root=tmp_path, features={"python"}, python_dirs=["."])
    assert BanditRunner().coverage_note(profile) is None


# --- audit() records it ------------------------------------------------------------

def test_audit_records_reduced_coverage_at_tier0(tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    r = _audit_with([_FakeSemgrep()], tmp_path, 0, monkeypatch)
    assert "semgrep" in r.ran                    # it DID run — that is the trap
    assert r.tools_errored == [] and r.tools_offline_skipped == []
    assert len(r.tools_reduced) == 1
    assert r.tools_reduced[0].startswith("semgrep — ")
    assert "p/owasp-top-ten" in r.tools_reduced[0]


def test_audit_reports_full_coverage_at_tier1(tmp_path: Path,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    r = _audit_with([_FakeSemgrep()], tmp_path, 1, monkeypatch)
    assert "semgrep" in r.ran
    assert r.tools_reduced == []


def test_deterministic_run_discloses_reduced_coverage(tmp_path: Path,
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    """`--deterministic` caps the runner tier to 0 even at `--network tier1`, so a
    deterministic/baseline run gets the reduced rule set — and must disclose it."""
    monkeypatch.setattr("agentsec.audit.select_runners", lambda profile: [_FakeSemgrep()])
    monkeypatch.setattr("agentsec.audit.select_guards", lambda profile: [])
    monkeypatch.setattr("agentsec.audit.detect",
                        lambda root: mkprofile(tmp_path, features={"python"}))
    r = audit(tmp_path, network_tier=1, deterministic=True, exceptions_path=Path("/dev/null"))
    assert len(r.tools_reduced) == 1 and "semgrep" in r.tools_reduced[0]


def test_coverage_note_crash_never_aborts_the_audit(tmp_path: Path,
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    class _Exploding(_FakeSemgrep):
        def coverage_note(self, profile: StackProfile) -> str | None:
            raise RuntimeError("boom")

    r = _audit_with([_Exploding()], tmp_path, 0, monkeypatch)
    assert "semgrep" in r.ran and r.tools_reduced == []


def test_coverage_notices_cover_every_disclosure_channel() -> None:
    from agentsec.audit import AuditResult

    res = AuditResult(
        profile=StackProfile(root=Path(".")), findings=[], ran=[], skipped=[],
        tools_unavailable=["gitleaks"], tools_errored=["bandit"],
        tools_offline_skipped=["pip-audit"], tools_reduced=["semgrep — local pack only"],
    )
    notices = res.coverage_notices()
    assert any("gitleaks" in n for n in notices)
    assert any("pip-audit" in n for n in notices)
    assert any("Reduced coverage" in n and "semgrep" in n for n in notices)
    assert any("errored" in n and "bandit" in n for n in notices)


# --- an errored check is NOT claimed under "Checks run" (#895) ----------------------
#
# `_Checks run:_` is the positive coverage inventory a reviewer reads. `ran` means
# *attempted*: a guard/runner that crashed or partial-scanned lands in BOTH `ran` and
# `tools_errored`, so rendering raw `ran` claimed coverage for a check that errored — a
# Rule-3 "failure that presents as success". `checks_run_clean` = `ran` minus
# `tools_errored`; every excluded id must still reappear under "Scanners that errored"
# (Rule 3: excluded, never silently dropped).


def _checks_run_line(footer: str) -> str:
    """The single `_Checks run:_ …` line, isolated so a `bandit` in the SEPARATE
    `_Scanners that errored:_` line can't satisfy a "Checks run" assertion."""
    for line in footer.splitlines():
        if line.startswith("_Checks run:_"):
            return line
    raise AssertionError(f"no '_Checks run:_' line in footer:\n{footer}")


def test_errored_check_left_out_of_checks_run_but_still_disclosed() -> None:
    # Narrowing direction (the fix): bandit errored, so it leaves the positive inventory
    # AND must reappear under the errored disclosure.
    from agentsec.cli import _meta_lines

    res = AuditResult(
        profile=StackProfile(root=Path(".")), findings=[], ran=["bandit", "semgrep"],
        skipped=[], tools_errored=["bandit"],
    )
    assert res.checks_run_clean == ["semgrep"]
    footer = "\n".join(_meta_lines(res, []))
    run_line = _checks_run_line(footer)
    assert "semgrep" in run_line
    assert "bandit" not in run_line
    assert "_Scanners that errored:_ bandit" in footer


def test_clean_checks_are_not_dropped_from_checks_run() -> None:
    # Direction traded against (Rule 1 — FP-bait): nothing errored, so BOTH still list. The
    # fix must not quietly shrink a clean run's inventory.
    from agentsec.cli import _meta_lines

    res = AuditResult(
        profile=StackProfile(root=Path(".")), findings=[], ran=["bandit", "semgrep"],
        skipped=[], tools_errored=[],
    )
    assert res.checks_run_clean == ["bandit", "semgrep"]
    run_line = _checks_run_line("\n".join(_meta_lines(res, [])))
    assert "bandit" in run_line and "semgrep" in run_line


class _ErroringRunner(Runner):
    """A runner whose binary RAN but threw — the runners/base.py invoke-crash shape:
    available=True (so it is not 'unavailable'), error set, zero findings."""

    id = "boomscan"

    def run(self, root: Path, profile: StackProfile) -> RunnerResult:  # noqa: ARG002
        return RunnerResult(runner_id=self.id, available=True, error="boom", findings=[])


def test_errored_runner_end_to_end_left_out_of_checks_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Assert the artifact (Rule 3): drive a crashing runner through the real audit() and read
    # the rendered footer, not just the property.
    from agentsec.cli import _meta_lines

    r = _audit_with([_ErroringRunner()], tmp_path, 0, monkeypatch)
    assert "boomscan" in r.ran            # attempted…
    assert "boomscan" in r.tools_errored  # …but errored
    footer = "\n".join(_meta_lines(r, []))
    assert "boomscan" not in _checks_run_line(footer)
    assert "_Scanners that errored:_ boomscan" in footer


def test_errored_guard_end_to_end_left_out_of_checks_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The guard axis (the parallel the issue omits): the legacy guard loop appends a crashed
    # guard to BOTH `ran` and `errored`, so the one-line emitter fix must cover it too.
    from agentsec.cli import _meta_lines
    from agentsec.guards.base import Guard

    class _ErroringGuard(Guard):
        id = "boomguard"

        def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
            return True

        def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
            raise RuntimeError("boom")

    monkeypatch.setattr("agentsec.audit.select_runners", lambda profile: [])
    monkeypatch.setattr("agentsec.audit.select_guards", lambda profile: [_ErroringGuard()])
    monkeypatch.setattr("agentsec.audit.detect",
                        lambda root: mkprofile(tmp_path, features={"python"}))
    r = audit(tmp_path, exceptions_path=Path("/dev/null"))
    assert "boomguard" in r.ran and "boomguard" in r.tools_errored
    footer = "\n".join(_meta_lines(r, []))
    assert "boomguard" not in _checks_run_line(footer)
    assert "_Scanners that errored:_ boomguard" in footer


# --- the markdown footer -----------------------------------------------------------

def test_markdown_footer_discloses_reduced_coverage(tmp_path: Path,
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    from agentsec.cli import _meta_lines

    r = _audit_with([_FakeSemgrep()], tmp_path, 0, monkeypatch)
    footer = "\n".join(_meta_lines(r, []))
    assert "Reduced coverage" in footer
    assert "p/python" in footer


def test_markdown_footer_silent_at_full_coverage(tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    from agentsec.cli import _meta_lines

    r = _audit_with([_FakeSemgrep()], tmp_path, 1, monkeypatch)
    assert "Reduced coverage" not in "\n".join(_meta_lines(r, []))


# --- an unconfirmed stack (a DETECTION miss, not a scanner one) ---------------------

def _result_with_unconfirmed(stacks: set[str]) -> AuditResult:
    prof = StackProfile(root=Path("."))
    prof.unconfirmed_stacks = set(stacks)
    return AuditResult(profile=prof, findings=[], ran=[], skipped=["service-role-key"])


def test_markdown_footer_discloses_an_unconfirmed_stack() -> None:
    # The disclosure has to reach the REPORT, not just the profile — a field nobody renders is not
    # a disclosure. Assert the artifact (#481 review round 2).
    from agentsec.cli import _meta_lines

    footer = "\n".join(_meta_lines(_result_with_unconfirmed({"supabase"}), []))
    assert "Mentioned but not confirmed" in footer
    assert "supabase" in footer
    # The load-bearing half: it must say the skipped checks are NOT a pass. Without that, the line
    # sits next to "Skipped (N/A for this stack)" as an FYI, which is the exact reading it exists
    # to correct.
    assert "not a pass" in footer


def test_markdown_footer_silent_when_nothing_is_unconfirmed() -> None:
    from agentsec.cli import _meta_lines

    footer = "\n".join(_meta_lines(_result_with_unconfirmed(set()), []))
    assert "Mentioned but not confirmed" not in footer


# --- artifact-layer Go evidence (foreign_artifacts / Dean's review) -----

def _result_with_foreign_artifacts(artifacts: set[str]) -> AuditResult:
    prof = StackProfile(root=Path("."))
    prof.foreign_artifacts = set(artifacts)
    return AuditResult(profile=prof, findings=[], ran=[], skipped=[])


def test_markdown_footer_discloses_foreign_artifacts() -> None:
    # Same "the artifact has to reach the report" discipline as the unconfirmed-stack test above
    # (#481 review round 2) — a field nobody renders is not a disclosure.
    from agentsec.cli import _meta_lines

    footer = "\n".join(
        _meta_lines(_result_with_foreign_artifacts({"Caddy (Docker base image `caddy:2`)"}), [])
    )
    assert "Artifact-layer language evidence" in footer
    assert "Caddy" in footer
    assert "caddy:2" in footer
    # Must say plainly that this is NOT something the findings above cover — the load-bearing
    # half, same as "not a pass" is for the unconfirmed-stack line.
    assert "cannot see this language" in footer


def test_markdown_footer_silent_when_no_foreign_artifacts() -> None:
    from agentsec.cli import _meta_lines

    footer = "\n".join(_meta_lines(_result_with_foreign_artifacts(set()), []))
    assert "Artifact-layer language evidence" not in footer


def test_detect_text_discloses_foreign_artifacts() -> None:
    # `agentsec detect`'s own text output (the second of the two rendering paths, alongside the
    # audit-report footer above) must carry the same disclosure.
    from agentsec.cli import _detect_text

    prof = StackProfile(root=Path("."))
    prof.foreign_artifacts = {"HashiCorp Vault (Docker base image `hashicorp/vault:1.15`)"}
    text = _detect_text(prof)
    assert "artifact-layer language evidence" in text
    assert "HashiCorp Vault" in text


def test_detect_text_silent_when_no_foreign_artifacts() -> None:
    from agentsec.cli import _detect_text

    prof = StackProfile(root=Path("."))
    text = _detect_text(prof)
    assert "artifact-layer language evidence" not in text


# --- SARIF (the documented CI path) ------------------------------------------------

def test_sarif_carries_the_coverage_disclosure() -> None:
    sarif = to_sarif(
        [Finding(check_id="semgrep", severity="high", title="t", location="a.py:1")],
        notifications=["Reduced coverage — semgrep — local pack only"],
    )
    run = sarif["runs"][0]
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert run["invocations"][0]["executionSuccessful"] is True   # a disclosure, not a failure
    assert len(notes) == 1
    assert "semgrep" in notes[0]["message"]["text"]
    assert notes[0]["level"] == "note"
    assert notes[0]["descriptor"]["id"] == COVERAGE_NOTIFICATION_ID
    # the descriptor must be declared on the driver, or the reference dangles
    assert run["tool"]["driver"]["notifications"][0]["id"] == COVERAGE_NOTIFICATION_ID


def test_sarif_omits_invocations_when_nothing_to_disclose() -> None:
    sarif = to_sarif([Finding(check_id="x", severity="low", title="t")])
    assert "invocations" not in sarif["runs"][0]
    assert "notifications" not in sarif["runs"][0]["tool"]["driver"]


def test_audit_format_sarif_end_to_end_carries_disclosure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The whole point of #434's second half: `--format sarif` suppresses the footer, so
    the disclosure has to ride in the SARIF document itself."""
    from agentsec.cli import main

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr("agentsec.audit.select_runners", lambda profile: [_FakeSemgrep()])
    out = tmp_path / "report.sarif"
    rc = main(["audit", str(tmp_path), "--format", "sarif", "--no-fail", "--out", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    texts = [
        n["message"]["text"]
        for n in data["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    ]
    assert any("Reduced coverage" in t and "semgrep" in t for t in texts)


def test_scan_sarif_artifact_matches_the_markdown_footer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`agentsec scan` writes audit.md + audit.sarif from ONE run — they must not disagree."""
    from agentsec.cli import main

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr("agentsec.audit.select_runners", lambda profile: [_FakeSemgrep()])
    out_dir = tmp_path / "out"
    assert main(["scan", str(tmp_path), "--out-dir", str(out_dir), "--no-fail"]) == 0
    md = (out_dir / "audit.md").read_text(encoding="utf-8")
    data = json.loads((out_dir / "audit.sarif").read_text(encoding="utf-8"))
    assert "Reduced coverage" in md
    assert any(
        "Reduced coverage" in n["message"]["text"]
        for n in data["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    )
