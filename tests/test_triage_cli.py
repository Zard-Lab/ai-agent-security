"""Tests for agentsec/triage_cli.py — the `agentsec triage` driver, focused on the
`--write-exception` bridge wiring added in #330 (the tri-state flag, dry-run/rc skips,
and the end-to-end verdict → waiver → suppression path)."""

from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path

import pytest

import agentsec.triage_cli as tc
from agentsec.audit import AuditResult
from agentsec.exceptions import apply_exceptions, load_exceptions
from agentsec.findings import Finding
from agentsec.triage import TriageVerdict, fingerprint, save_triage


class _FakeResult:
    """The slice of `AuditResult` triage reads: the findings plus the four scanner-state
    lists the #864 source header discloses (not installed / offline-skipped / reduced / errored),
    and the #1001 unparsed-file notice, rendered by the REAL method so the fake cannot drift."""

    unparsed_python: list[tuple[str, str]] = []
    unparsed_python_truncated = False
    unparsed_python_notice = AuditResult.unparsed_python_notice

    def __init__(
        self,
        findings: list[Finding],
        *,
        tools_unavailable: list[str] | None = None,
        tools_offline_skipped: list[str] | None = None,
        tools_reduced: list[str] | None = None,
        tools_errored: list[str] | None = None,
    ) -> None:
        self.findings = findings
        self.tools_unavailable = tools_unavailable or []
        self.tools_offline_skipped = tools_offline_skipped or []
        self.tools_reduced = tools_reduced or []
        self.tools_errored = tools_errored or []


def _args(tmp: Path, **over: object) -> argparse.Namespace:
    base: dict[str, object] = {
        "repo": str(tmp), "triage_file": None, "guard": None, "rule": None, "location": None,
        "fingerprint": None, "verdict": None, "reason": None, "improvement": None, "triaged_by": None,
        "triaged_at": None, "dry_run": False, "write_exception": None,
        # #864: the scanner-selection surface `triage` shares with `audit`, at audit's defaults.
        "guards_only": False, "deterministic": False, "network": None, "ingest": None,
    }
    base.update(over)
    return argparse.Namespace(**base)


def _two_findings(monkeypatch: pytest.MonkeyPatch) -> tuple[Finding, Finding]:
    """Make triage's internal audit() return two findings in different files (no real scan)."""
    fa = Finding(check_id="error-info-leak", severity="medium", title="t",
                 location="app/rag/tools.py:12", message="return {'error': str(exc)}")
    fb = Finding(check_id="error-info-leak", severity="medium", title="t",
                 location="app/routes/api.py:34", message="raise HTTPException(detail=str(exc))")
    monkeypatch.setattr("agentsec.audit.audit", lambda *a, **k: _FakeResult([fa, fb]))
    return fa, fb


@pytest.fixture
def _one_finding(monkeypatch: pytest.MonkeyPatch) -> Finding:
    """Make triage's internal audit() return one canned finding (no real scan)."""
    f = Finding(check_id="cors-wildcard", severity="high", title="t",
                location="app/main.py:10", message="allow_origins=['*']")
    monkeypatch.setattr("agentsec.audit.audit", lambda *a, **k: _FakeResult([f]))
    return f


def test_write_exception_bridges_verdict_to_suppression(tmp_path: Path, _one_finding: Finding) -> None:
    rc = tc.run(_args(tmp_path, verdict="fp", reason="internal API only", write_exception=""))
    assert rc == 0
    # the verdict was persisted...
    tri = json.loads((tmp_path / "agentsec-triage.json").read_text(encoding="utf-8"))
    assert tri["verdicts"][0]["verdict"] == "fp"
    # ...and a matching waiver was emitted that actually suppresses the finding.
    excs = load_exceptions(tmp_path / "agentsec-exceptions.json")
    assert len(excs) == 1
    out = apply_exceptions([_one_finding], excs, date(2026, 7, 5))
    assert out.suppressed == [_one_finding] and out.kept == []


def test_write_exception_default_path_is_repo_root(tmp_path: Path, _one_finding: Finding) -> None:
    tc.run(_args(tmp_path, verdict="fp", reason="r", write_exception=""))
    assert (tmp_path / "agentsec-exceptions.json").is_file()


def test_write_exception_custom_path(tmp_path: Path, _one_finding: Finding) -> None:
    dest = tmp_path / "waivers.json"
    tc.run(_args(tmp_path, verdict="fp", reason="r", write_exception=str(dest)))
    assert dest.is_file() and not (tmp_path / "agentsec-exceptions.json").exists()


def test_write_exception_skipped_on_dry_run(tmp_path: Path, _one_finding: Finding) -> None:
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", write_exception="", dry_run=True))
    assert rc == 0
    assert not (tmp_path / "agentsec-exceptions.json").exists()  # dry-run writes nothing


def test_no_write_exception_flag_emits_no_waivers(tmp_path: Path, _one_finding: Finding) -> None:
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r"))  # write_exception absent (None)
    assert rc == 0
    assert not (tmp_path / "agentsec-exceptions.json").exists()


def test_non_tty_without_verdict_lists_findings_and_writes_nothing(
    tmp_path: Path, _one_finding: Finding, capsys: pytest.CaptureFixture[str]
) -> None:
    # Issue #865: pytest stdin is not a TTY; with neither --verdict nor --write-exception no mutation
    # was requested, so run() prints a READ-ONLY listing of the untriaged findings (fingerprints and
    # all) and exits 0 instead of dead-ending on an error. The reader can then pass --fingerprint.
    rc = tc.run(_args(tmp_path, verdict=None, write_exception=None))
    assert rc == 0
    out = capsys.readouterr().out
    assert fingerprint(_one_finding) in out          # the fingerprint --fingerprint needs is shown...
    assert _one_finding.check_id in out              # ...alongside the guard id.
    # the hint names every narrowing selector (all three compose) so the reader isn't left guessing.
    assert "--verdict" in out and "--guard" in out and "--location" in out and "--fingerprint" in out
    # ...and the read-only path wrote nothing: no triage file, no exceptions file.
    assert not (tmp_path / "agentsec-triage.json").exists()
    assert not (tmp_path / "agentsec-exceptions.json").exists()


def test_non_tty_dry_run_without_verdict_lists_findings_and_writes_nothing(
    tmp_path: Path, _one_finding: Finding, capsys: pytest.CaptureFixture[str]
) -> None:
    # Companion (issue #865): --dry-run in a non-TTY with no verdict reaches the same read-only
    # listing (it also dead-ended before the fix). Lists the fingerprint, rc 0, writes nothing.
    rc = tc.run(_args(tmp_path, verdict=None, write_exception=None, dry_run=True))
    assert rc == 0
    assert fingerprint(_one_finding) in capsys.readouterr().out
    assert not (tmp_path / "agentsec-triage.json").exists()
    assert not (tmp_path / "agentsec-exceptions.json").exists()


def test_non_tty_without_verdict_all_triaged_prints_friendly_message(
    tmp_path: Path, _one_finding: Finding, capsys: pytest.CaptureFixture[str]
) -> None:
    # Issue #865 empty case: when every finding is already triaged the pending list is empty, so the
    # listing path prints a friendly line instead of an empty block — and still writes nothing.
    triage_path = tmp_path / "agentsec-triage.json"
    save_triage(
        [TriageVerdict(guard_id=_one_finding.check_id, file="app/main.py",
                       fingerprint=fingerprint(_one_finding), verdict="fp", reason="r")],
        triage_path,
    )
    before = triage_path.read_bytes()
    rc = tc.run(_args(tmp_path, verdict=None, write_exception=None))
    assert rc == 0
    assert "All findings already triaged." in capsys.readouterr().out
    assert triage_path.read_bytes() == before                      # the triage file was not rewritten
    assert not (tmp_path / "agentsec-exceptions.json").exists()     # nothing derived


def test_non_tty_write_exception_reemits_from_triage_file(
    tmp_path: Path, _one_finding: Finding
) -> None:
    # Issue #6: `--write-exception` alone in a non-TTY re-derives waivers from the existing triage
    # file instead of erroring. Pre-seed a fp verdict, then re-emit non-interactively.
    triage_path = tmp_path / "agentsec-triage.json"
    fp = fingerprint(_one_finding)
    save_triage(
        [TriageVerdict(guard_id=_one_finding.check_id, file="app/main.py", fingerprint=fp,
                       verdict="fp", reason="internal API only")],
        triage_path,
    )
    rc = tc.run(_args(tmp_path, verdict=None, write_exception=""))
    assert rc == 0
    # a matching waiver was emitted that actually suppresses the finding.
    excs = load_exceptions(tmp_path / "agentsec-exceptions.json")
    assert len(excs) == 1
    out = apply_exceptions([_one_finding], excs, date(2026, 7, 5))
    assert out.suppressed == [_one_finding] and out.kept == []


def test_non_tty_write_exception_dry_run_writes_nothing(
    tmp_path: Path, _one_finding: Finding
) -> None:
    # Re-emit path honors --dry-run: nothing written, rc 0.
    fp = fingerprint(_one_finding)
    save_triage(
        [TriageVerdict(guard_id=_one_finding.check_id, file="app/main.py", fingerprint=fp,
                       verdict="fp", reason="r")],
        tmp_path / "agentsec-triage.json",
    )
    rc = tc.run(_args(tmp_path, verdict=None, write_exception="", dry_run=True))
    assert rc == 0
    assert not (tmp_path / "agentsec-exceptions.json").exists()


def test_write_exception_warns_and_skips_on_malformed_registry(
    tmp_path: Path, _one_finding: Finding, capsys: pytest.CaptureFixture[str]
) -> None:
    # a malformed target must not crash the triage run — verdicts still save, emit warns.
    (tmp_path / "agentsec-exceptions.json").write_text("{ mid-edit", encoding="utf-8")
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", write_exception=""))
    assert rc == 0
    assert (tmp_path / "agentsec-triage.json").is_file()  # verdict still persisted
    assert "unparseable" in capsys.readouterr().err
    assert (tmp_path / "agentsec-exceptions.json").read_text(encoding="utf-8") == "{ mid-edit"


# --- Backlog item #5: per-finding selectors (--location / --fingerprint) + dry-run listing ---


def test_location_filter_narrows_bulk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fa, _fb = _two_findings(monkeypatch)
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", location="app/rag/tools.py"))
    assert rc == 0
    tri = json.loads((tmp_path / "agentsec-triage.json").read_text(encoding="utf-8"))
    # only the rag/tools.py finding got a verdict.
    assert [v["fingerprint"] for v in tri["verdicts"]] == [fingerprint(fa)]


def test_location_filter_no_match_returns_0_no_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _two_findings(monkeypatch)
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", location="does/not/exist.py"))
    assert rc == 0
    assert not (tmp_path / "agentsec-triage.json").exists()


def test_fingerprint_filter_selects_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fa, fb = _two_findings(monkeypatch)
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", fingerprint=fingerprint(fb)))
    assert rc == 0
    tri = json.loads((tmp_path / "agentsec-triage.json").read_text(encoding="utf-8"))
    assert [v["fingerprint"] for v in tri["verdicts"]] == [fingerprint(fb)]


def test_fingerprint_filter_no_match_returns_0(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _two_findings(monkeypatch)
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", fingerprint="deadbeef"))
    assert rc == 0
    assert not (tmp_path / "agentsec-triage.json").exists()


def test_guard_and_location_compose(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # --guard AND --location narrow together: three findings, two guards, two files — only the
    # (guard-A, file-X) finding survives both filters and gets a verdict.
    fa = Finding(check_id="error-info-leak", severity="medium", title="t",
                 location="app/rag/tools.py:12", message="return {'error': str(exc)}")
    fb = Finding(check_id="error-info-leak", severity="medium", title="t",
                 location="app/routes/api.py:34", message="raise HTTPException(detail=str(exc))")
    fc = Finding(check_id="js-supply-chain", severity="medium", title="t",
                 location="app/rag/tools.py:99", message="lodash pinned range")
    monkeypatch.setattr("agentsec.audit.audit", lambda *a, **k: _FakeResult([fa, fb, fc]))
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r",
                      guard="error-info-leak", location="app/rag/tools.py"))
    assert rc == 0
    tri = json.loads((tmp_path / "agentsec-triage.json").read_text(encoding="utf-8"))
    assert [v["fingerprint"] for v in tri["verdicts"]] == [fingerprint(fa)]


def test_location_matches_path_not_line_number(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # --location matches the path part only: a bare line number must NOT match by the :line suffix.
    _two_findings(monkeypatch)  # locations end ":12" and ":34"
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", location="12"))
    assert rc == 0
    assert not (tmp_path / "agentsec-triage.json").exists()  # "12" is a line no., not a path substr


def test_dry_run_lists_fingerprints(
    tmp_path: Path, _one_finding: Finding, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", dry_run=True))
    assert rc == 0
    out = capsys.readouterr().out
    assert fingerprint(_one_finding) in out  # fingerprint is discoverable from the dry-run listing
    assert not (tmp_path / "agentsec-triage.json").exists()


# --- #474 re-review (2026-07-31): an EMPTY selector must match nothing, never everything ---
# `"" in s` is True for every s, so a bare substring test turned an unset shell variable
# (`--location "$UNSET"`) into "apply the bulk verdict to every untriaged finding". The first
# fix changed `if x:` to `if x is not None:`, which only changed WHICH BRANCH was taken; the
# substring test still passed for every finding. These pin the decision, not the branch.


def test_empty_location_selector_matches_nothing_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _two_findings(monkeypatch)
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", location=""))
    assert rc == 0
    # THE point: no verdict file at all. Before the fix this wrote a verdict for EVERY finding.
    assert not (tmp_path / "agentsec-triage.json").exists()


def test_empty_guard_selector_matches_nothing_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _two_findings(monkeypatch)
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", guard=""))
    assert rc == 0
    assert not (tmp_path / "agentsec-triage.json").exists()


def test_empty_fingerprint_selector_matches_nothing_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Already correct (equality, not substring) — pinned so a later refactor cannot regress it.
    _two_findings(monkeypatch)
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", fingerprint=""))
    assert rc == 0
    assert not (tmp_path / "agentsec-triage.json").exists()


def test_the_direction_traded_against_nonempty_selectors_still_narrow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The fix must not turn a WORKING selector into one that matches nothing. Both directions
    # in one test: a real --location still selects exactly its finding, and a real --guard does too.
    fa, _fb = _two_findings(monkeypatch)
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", location="app/rag/tools.py"))
    assert rc == 0
    tri = json.loads((tmp_path / "agentsec-triage.json").read_text(encoding="utf-8"))
    assert [v["fingerprint"] for v in tri["verdicts"]] == [fingerprint(fa)]

    (tmp_path / "agentsec-triage.json").unlink()
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", guard=fa.check_id))
    assert rc == 0
    tri = json.loads((tmp_path / "agentsec-triage.json").read_text(encoding="utf-8"))
    assert fingerprint(fa) in [v["fingerprint"] for v in tri["verdicts"]]


# --- #474 re-review, round 2: a DEGENERATE selector must not over-match either -------------
# Round 1 special-cased the empty string and left the bare substring test standing for every
# other value. `.` is not contrived: the python-supply-chain guard emits a real finding whose
# location IS `.`, and `dirname` of any repo-root file returns `.`. These run the REAL audit()
# pipeline over a real target repo and assert the DECISION (how many verdicts got written),
# because the bug is "which findings got waived", not "which branch ran".

_CORS_APP = (
    "from fastapi import FastAPI\n"
    "from fastapi.middleware.cors import CORSMiddleware\n"
    "app = FastAPI()\n"
    "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n"
)


@pytest.fixture
def real_repo(tmp_path: Path) -> Path:
    """A real FastAPI target repo: three CORS-wildcard files, one of them under a directory
    that is a strict prefix-sibling of another (`app/` vs `application/`)."""
    repo = tmp_path / "target"
    for d in ("app", "rag", "application"):
        (repo / d).mkdir(parents=True)
    (repo / "requirements.txt").write_text(
        "fastapi==0.110.0\nuvicorn==0.29.0\nopenai==1.30.0\n", encoding="utf-8"
    )
    (repo / "app" / "main.py").write_text(_CORS_APP, encoding="utf-8")
    (repo / "rag" / "tools.py").write_text(_CORS_APP, encoding="utf-8")
    (repo / "application" / "svc.py").write_text(_CORS_APP, encoding="utf-8")
    return repo


def _triage_real(repo: Path, out: Path, **over: object) -> tuple[int, list[str]]:
    """Run the real pipeline through `triage --verdict fp` and return (rc, waived locations).

    `guards_only=True` on purpose (#864): triage now runs the installed scanners by default,
    exactly as `audit` does, and bandit IS installed on dev machines (semgrep too). Without
    the flag these tests would scan the fixture with whatever toolchain the machine has —
    slow, and a different finding set per machine. The guard-only set is also the pre-#864
    set, so these tests double as the "direction traded against" pin (Rule 1): the guards-only
    path yields exactly what it yielded before scanners could enter."""
    over.setdefault("guards_only", True)
    rc = tc.run(_args(repo, triage_file=str(out), verdict="fp", reason="r", **over))
    if not out.exists():
        return rc, []
    tri = json.loads(out.read_text(encoding="utf-8"))
    return rc, sorted(v["file"] for v in tri["verdicts"])


def test_real_pipeline_dot_location_waives_only_the_dot_finding(real_repo: Path) -> None:
    # THE defect: `--location "."` wrote an fp verdict onto all 10 findings, including 3 HIGH
    # cors-wildcard, because "." is a substring of every path. It must select only the one
    # finding whose location IS "." (python-supply-chain's "no install cooldown configured").
    out = real_repo.parent / "t.json"
    rc, waived = _triage_real(real_repo, out)
    assert rc == 0 and len(waived) > 5, "sanity: the fixture must produce a broad finding set"

    out.unlink()
    rc, waived = _triage_real(real_repo, out, location=".")
    assert rc == 0
    assert waived == ["."], waived


@pytest.mark.parametrize(
    "selector",
    ["", "/", "//", "\\", "..", "./", "*", "?", ".*", "[a-z]", " ", "\t",
     "/app/main.py", "app\\main.py", "main.py", "pp/main.py", "a", "nonexistent-xyz"],
)
def test_real_pipeline_degenerate_location_waives_nothing(real_repo: Path, selector: str) -> None:
    # Every one of these either names no path segment, is anchored wrong, or is a suffix /
    # mid-string hit. None may waive anything, and the run must still exit 0 without writing.
    out = real_repo.parent / "t.json"
    rc, waived = _triage_real(real_repo, out, location=selector)
    assert rc == 0
    assert waived == [], f"{selector!r} over-matched: {waived}"
    assert not out.exists()


def test_real_pipeline_legitimate_location_selectors_still_narrow(real_repo: Path) -> None:
    # The direction traded against. A file, a directory (with and without the trailing slash),
    # and a repo-root file must all still select exactly their own findings.
    out = real_repo.parent / "t.json"

    rc, waived = _triage_real(real_repo, out, location="app/main.py")
    assert rc == 0 and set(waived) == {"app/main.py"} and len(waived) > 1

    out.unlink()
    rc, waived = _triage_real(real_repo, out, location="rag/")
    assert rc == 0 and set(waived) == {"rag/tools.py"} and len(waived) > 1

    out.unlink()
    rc, waived = _triage_real(real_repo, out, location="rag")
    assert rc == 0 and set(waived) == {"rag/tools.py"}

    out.unlink()
    rc, waived = _triage_real(real_repo, out, location="requirements.txt")
    assert rc == 0 and waived == ["requirements.txt"]


def test_real_pipeline_prefix_sibling_directory_is_not_swept(real_repo: Path) -> None:
    # `app` is a strict prefix of the path segment `application`. Under the substring test
    # `--location app` waived application/svc.py's findings too. Checked in both directions.
    out = real_repo.parent / "t.json"
    rc, waived = _triage_real(real_repo, out, location="app")
    assert rc == 0 and set(waived) == {"app/main.py"}, waived

    out.unlink()
    rc, waived = _triage_real(real_repo, out, location="application")
    assert rc == 0 and set(waived) == {"application/svc.py"}, waived


def test_real_pipeline_guard_and_fingerprint_selectors_still_work(real_repo: Path) -> None:
    out = real_repo.parent / "t.json"
    rc, waived = _triage_real(real_repo, out, guard="cors-wildcard")
    assert rc == 0
    assert sorted(waived) == ["app/main.py", "application/svc.py", "rag/tools.py"]

    out.unlink()
    rc, waived = _triage_real(real_repo, out, guard="cors-wildcard", location="rag/")
    assert rc == 0 and waived == ["rag/tools.py"]

    out.unlink()
    tri_all = real_repo.parent / "all.json"
    _triage_real(real_repo, tri_all)
    one = json.loads(tri_all.read_text(encoding="utf-8"))["verdicts"][0]["fingerprint"]
    rc, waived = _triage_real(real_repo, out, fingerprint=one)
    assert rc == 0 and len(waived) == 1

    out.unlink()
    for empty in ("guard", "fingerprint"):
        rc, waived = _triage_real(real_repo, out, **{empty: ""})
        assert rc == 0 and waived == [] and not out.exists()


# --- #474 gate (2026-08-11): the waiver a verdict is WRITTEN as must not eat a URL port ------
# The sibling half of the scheme fix in `findings.location_matches`. `_location_file` derives the
# `file` a waiver is keyed on, and its `:line[:col]` strip cannot tell a port from a line number,
# so a finding at `https://host:9200` was written as a waiver for `https://host` — which the
# boundary matcher then read as a prefix covering every other port on that host.


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        # The bug: a bare `scheme://host:port` (a SARIF result with no region) keeps its port.
        ("https://internal.example.com:9200", "https://internal.example.com:9200"),
        ("http://internal.example.com:6379", "http://internal.example.com:6379"),
        # A URL that really does carry a line suffix stays line-pinned (narrower, fails closed).
        ("https://internal.example.com/x:12", "https://internal.example.com/x:12"),
        # THE DIRECTION TRADED AGAINST: ordinary paths must still lose their line/col suffix,
        # or every waiver silently becomes line-pinned and stops covering its own file.
        ("app/main.py:42", "app/main.py"),
        ("app/main.py:42:11", "app/main.py"),
        ("app/main.py", "app/main.py"),
        ("host:sshd_config", "host:sshd_config"),
        ("", ""),
    ],
)
def test_location_file_keeps_a_url_port_but_still_strips_a_line_number(
    location: str, expected: str
) -> None:
    assert tc._location_file(location) == expected


def test_url_port_waiver_does_not_suppress_another_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The consequence, asserted on the artifact rather than on rc: waive the MEDIUM at :9200 and
    # the unrelated CRITICAL at :6379 must survive. Before the fix the emitted waiver was keyed on
    # `https://internal.example.com` and swallowed both — different port, message and severity.
    waived = Finding(check_id="sarif:zap", severity="medium", title="t",
                     location="https://internal.example.com:9200", message="verbose banner")
    other = Finding(check_id="sarif:zap", severity="critical", title="t",
                    location="https://internal.example.com:6379", message="unauthenticated redis")
    monkeypatch.setattr("agentsec.audit.audit", lambda *a, **k: _FakeResult([waived]))
    rc = tc.run(_args(tmp_path, verdict="fp", reason="staging only",
                      fingerprint=fingerprint(waived), write_exception=""))
    assert rc == 0

    excs = load_exceptions(tmp_path / "agentsec-exceptions.json")
    assert [e.location for e in excs] == ["https://internal.example.com:9200"]
    out = apply_exceptions([waived, other], excs, date(2026, 8, 11))
    assert out.suppressed == [waived]   # the one actually triaged
    assert out.kept == [other]          # the other port, untouched


def test_fp_verdict_on_one_secret_does_not_waive_a_second_untriaged_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Issue #507, end to end through the real bridge. Two AWS keys and two OpenAI keys in one
    # file. Triage the AWS pair as a false positive; the never-triaged OpenAI keys must survive.
    #
    # Before the fix the emitted waiver carried `rule=client-side-secret-literal` plus the
    # line-STRIPPED `location=src/config.js`, and `Exception_.matches` OR-ed that against the
    # fingerprint — so the entry swallowed all four, including two live secrets nobody had
    # looked at. Asserted on the artifact (which findings survive), never on the return code.
    def _secret(loc: str, provider: str) -> Finding:
        return Finding(
            check_id="client-side-secret-literal", severity="high", title="t",
            rule="client-side-secret-literal/hardcoded-api-key-literal", location=loc,
            message=f"A hardcoded {provider} API key / secret is in client-side JavaScript.",
        )

    aws = [_secret("src/config.js:2:26", "AWS"), _secret("src/config.js:3:29", "AWS")]
    openai = [_secret("src/config.js:4:26", "OpenAI"), _secret("src/config.js:5:26", "OpenAI")]
    everything = [*aws, *openai]

    monkeypatch.setattr("agentsec.audit.audit", lambda *a, **k: _FakeResult(aws))
    rc = tc.run(_args(tmp_path, verdict="fp", reason="believed to be a test placeholder",
                      fingerprint=fingerprint(aws[0]), write_exception=""))
    assert rc == 0

    excs = load_exceptions(tmp_path / "agentsec-exceptions.json")
    out = apply_exceptions(everything, excs, date(2026, 8, 23))
    assert [f.location for f in out.suppressed] == ["src/config.js:2:26", "src/config.js:3:29"]
    assert [f.location for f in out.kept] == ["src/config.js:4:26", "src/config.js:5:26"]
    # ...and the breadth of what WAS waived is disclosed rather than folded into a total.
    assert any("suppressed 2 findings" in line for line in out.broad_waivers())


# --- #864: delegated-scanner findings enter triage ----------------------------------------------
# `triage` called `audit(repo, run_scanners=False)`, hard-coded since its first commit, so a
# bandit/semgrep/pip-audit finding could never be classified or waived here and every scanner
# FP went into a `# nosec` / `# nosemgrep` — a permanent ignore with no `review_by`. These use
# a monkeypatched `audit` returning RUNNER-shaped findings (never a real binary): hermetic, and
# the identity/matching layers under test are source-agnostic by construction, so a canned
# runner finding exercises exactly the path a real one takes.


def _bandit(loc: str = "app/db.py:12", rule: str = "B608", msg: str = "Possible SQL injection") -> Finding:
    """A finding shaped exactly as `runners/bandit.py` emits it: `check_id` is the scanner,
    `rule` is the scanner's own test id."""
    return Finding(check_id="bandit", severity="medium", title="hardcoded_sql_expressions",
                   location=loc, message=msg, rule=rule, standards=["OWASP:A03"])


def _capture_audit_kwargs(monkeypatch: pytest.MonkeyPatch, findings: list[Finding]) -> dict[str, object]:
    """Monkeypatch triage's `audit()` and hand back the kwargs it was called with."""
    seen: dict[str, object] = {}

    def fake(*_a: object, **k: object) -> _FakeResult:
        seen.update(k)
        return _FakeResult(findings)

    monkeypatch.setattr("agentsec.audit.audit", fake)
    return seen


def test_scanner_finding_is_triaged_and_waived_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # THE planted case: a bandit finding can be selected by its scanner id, gets a verdict that
    # records the scanner rule, and the bridged waiver actually suppresses it. Before the fix
    # this printed "No findings for guard 'bandit'." and exited 0 — a failure that presents as
    # success (Rule 3).
    b = _bandit()
    monkeypatch.setattr("agentsec.audit.audit", lambda *a, **k: _FakeResult([b]))
    rc = tc.run(_args(tmp_path, guard="bandit", verdict="fp", reason="parameterized upstream",
                      write_exception=""))
    assert rc == 0
    tri = json.loads((tmp_path / "agentsec-triage.json").read_text(encoding="utf-8"))
    assert [(v["guard_id"], v["rule"], v["verdict"]) for v in tri["verdicts"]] == [("bandit", "B608", "fp")]
    excs = load_exceptions(tmp_path / "agentsec-exceptions.json")
    assert len(excs) == 1
    out = apply_exceptions([b], excs, date(2026, 9, 14))
    assert out.suppressed == [b] and out.kept == []


def test_audit_call_contract_defaults_to_scanners_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The root-cause line, asserted directly: default args → the same call `agentsec audit`
    # makes (scanners on, tier 0, not deterministic, nothing ingested).
    seen = _capture_audit_kwargs(monkeypatch, [_bandit()])
    assert tc.run(_args(tmp_path, verdict="fp", reason="r", dry_run=True)) == 0
    assert seen["run_scanners"] is True
    assert seen["deterministic"] is False
    assert seen["network_tier"] == 0
    assert seen["extra_findings"] == []


def test_audit_call_contract_forwards_the_selection_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `--guards-only` → run_scanners=False (the pre-#864 call, verbatim); `--deterministic`
    # forwarded; `--network tier1` resolves to tier 1. DO_NOT_TRACK would force tier 0, so
    # clear it for the assertion (the tier resolver is `audit`'s own, tested elsewhere).
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    monkeypatch.delenv("AGENTSEC_NETWORK", raising=False)
    seen = _capture_audit_kwargs(monkeypatch, [_bandit()])
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", dry_run=True,
                      guards_only=True, deterministic=True, network="tier1"))
    assert rc == 0
    assert seen["run_scanners"] is False
    assert seen["deterministic"] is True
    assert seen["network_tier"] == 1


def test_ingest_is_forwarded_as_extra_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `--ingest KIND=PATH` rides along for parity with audit: the ingested findings reach
    # `audit()` as `extra_findings`, the same channel `_cmd_audit` uses.
    sarif = tmp_path / "ext.sarif"
    sarif.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "semgrep", "rules": []}},
            "results": [{
                "ruleId": "python.lang.security.audit.eval-detected",
                "level": "warning",
                "message": {"text": "eval() detected"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "app/x.py"}, "region": {"startLine": 3}}}],
            }],
        }],
    }), encoding="utf-8")
    seen = _capture_audit_kwargs(monkeypatch, [])
    tc.run(_args(tmp_path, verdict="fp", reason="r", dry_run=True, ingest=[f"sarif={sarif}"]))
    extra = seen["extra_findings"]
    assert isinstance(extra, list) and len(extra) == 1
    assert extra[0].check_id == "sarif:semgrep"


def test_rule_selector_narrows_and_composes_with_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `--guard bandit` is the WHOLE scanner; `--rule B101` is the natural scanner granularity.
    # Three bandit rules plus a guard finding whose rule happens to equal a bandit id (a
    # collision `--guard` + `--rule` must resolve): only the (bandit, B101) rows get a verdict.
    b101a = _bandit("tests/test_a.py:4", "B101", "Use of assert detected")
    b101b = _bandit("tests/test_b.py:9", "B101", "Use of assert detected")
    b608 = _bandit("app/db.py:12", "B608", "Possible SQL injection")
    guard = Finding(check_id="some-guard", severity="low", title="t", location="app/y.py:1",
                    message="m", rule="B101")
    monkeypatch.setattr("agentsec.audit.audit",
                        lambda *a, **k: _FakeResult([b101a, b101b, b608, guard]))
    rc = tc.run(_args(tmp_path, guard="bandit", rule="B101", verdict="fp", reason="asserts in tests"))
    assert rc == 0
    tri = json.loads((tmp_path / "agentsec-triage.json").read_text(encoding="utf-8"))
    assert sorted(v["fingerprint"] for v in tri["verdicts"]) == sorted(
        [fingerprint(b101a), fingerprint(b101b)]
    )
    assert {v["rule"] for v in tri["verdicts"]} == {"B101"}

    # --rule alone (no --guard) crosses checks: both B101 carriers, the guard included.
    (tmp_path / "agentsec-triage.json").unlink()
    rc = tc.run(_args(tmp_path, rule="B101", verdict="fp", reason="r"))
    assert rc == 0
    tri = json.loads((tmp_path / "agentsec-triage.json").read_text(encoding="utf-8"))
    assert len(tri["verdicts"]) == 3


def test_rule_selector_no_match_returns_0_no_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("agentsec.audit.audit", lambda *a, **k: _FakeResult([_bandit()]))
    rc = tc.run(_args(tmp_path, rule="B999", verdict="fp", reason="r"))
    assert rc == 0
    assert not (tmp_path / "agentsec-triage.json").exists()


def test_empty_rule_selector_matches_nothing_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The #474 lesson applied to the new selector, with one twist: plain equality would make
    # `--rule ""` (an unset shell variable) select every finding whose rule IS empty — every
    # guard finding without a sub-rule. So the empty selector must select nothing even when
    # sub-rule-less findings are present.
    bare = Finding(check_id="cors-wildcard", severity="high", title="t",
                   location="app/main.py:10", message="allow_origins=['*']")   # rule == ""
    monkeypatch.setattr("agentsec.audit.audit", lambda *a, **k: _FakeResult([bare, _bandit()]))
    rc = tc.run(_args(tmp_path, rule="", verdict="fp", reason="r"))
    assert rc == 0
    assert not (tmp_path / "agentsec-triage.json").exists()


def test_guards_only_still_excludes_scanner_findings_from_the_bulk_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The direction traded against (Rule 1), at the artifact: with `--guards-only` the audit
    # is asked for guards only, so a bulk verdict cannot reach a scanner row. The fake honours
    # the flag the way the real `audit()` does — no runner findings when scanners are off.
    b = _bandit()
    g = Finding(check_id="cors-wildcard", severity="high", title="t",
                location="app/main.py:10", message="allow_origins=['*']")

    def fake(*_a: object, **k: object) -> _FakeResult:
        return _FakeResult([g] if not k.get("run_scanners") else [g, b])

    monkeypatch.setattr("agentsec.audit.audit", fake)
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r", guards_only=True))
    assert rc == 0
    tri = json.loads((tmp_path / "agentsec-triage.json").read_text(encoding="utf-8"))
    assert [v["guard_id"] for v in tri["verdicts"]] == ["cors-wildcard"]

    # ...and the same bare bulk verdict WITHOUT the flag now reaches both (the widening,
    # bounded to the already-"everything" selector and disclosed by the header).
    (tmp_path / "agentsec-triage.json").unlink()
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r"))
    assert rc == 0
    tri = json.loads((tmp_path / "agentsec-triage.json").read_text(encoding="utf-8"))
    assert sorted(v["guard_id"] for v in tri["verdicts"]) == ["bandit", "cors-wildcard"]


def test_guard_and_semgrep_finding_at_one_site_stay_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #809's negative control, pinned so #864 cannot break it: one defect reported by a guard
    # (`rule=jwt-claims-validated/verify-disabled`) and by the semgrep LLM pack
    # (`rule=agentsec-jwt-unverified-decode`) at the SAME location and message has two stable
    # fingerprints — `rule or check_id` is the identity — so an fp verdict on one leaves the
    # other pending, and a waiver for one does not suppress the other. The alias map that
    # would merge them is #809's own change, not this one.
    loc, msg = "app/auth.py:40", "jwt.decode(..., options={'verify_signature': False})"
    guard = Finding(check_id="jwt-claims-validated", severity="high", title="t", location=loc,
                    message=msg, rule="jwt-claims-validated/verify-disabled")
    semgrep = Finding(check_id="semgrep", severity="high", title="t", location=loc,
                      message=msg, rule="agentsec-jwt-unverified-decode")
    assert fingerprint(guard) != fingerprint(semgrep)

    monkeypatch.setattr("agentsec.audit.audit", lambda *a, **k: _FakeResult([guard, semgrep]))
    rc = tc.run(_args(tmp_path, guard="semgrep", verdict="fp", reason="covered by the guard",
                      write_exception=""))
    assert rc == 0
    tri = json.loads((tmp_path / "agentsec-triage.json").read_text(encoding="utf-8"))
    assert [v["guard_id"] for v in tri["verdicts"]] == ["semgrep"]

    excs = load_exceptions(tmp_path / "agentsec-exceptions.json")
    out = apply_exceptions([guard, semgrep], excs, date(2026, 9, 14))
    assert out.suppressed == [semgrep]
    assert out.kept == [guard]


def test_source_header_names_the_origin_mix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Rule 3: before a bulk verdict can touch "everything", stdout says what everything is.
    g = Finding(check_id="cors-wildcard", severity="high", title="t",
                location="app/main.py:10", message="allow_origins=['*']")
    ingested = Finding(check_id="sarif:zap", severity="low", title="t",
                       location="https://app.example.com/x", message="banner")
    monkeypatch.setattr(
        "agentsec.audit.audit",
        lambda *a, **k: _FakeResult([g, _bandit(), _bandit("app/z.py:1", "B101"), ingested]),
    )
    tc.run(_args(tmp_path, verdict="fp", reason="r", dry_run=True))
    out = capsys.readouterr().out
    assert "4 finding(s): 1 from guards, 2 from external scanners (bandit 2), 1 ingested" in out
    assert "--guards-only to exclude scanners" in out


def test_source_header_discloses_skipped_and_reduced_scanners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # An offline / partial toolchain must not LOOK complete: the scanners that did not run
    # (not installed, offline-skipped, reduced, errored) are named — even when the finding
    # set is empty and the run says "No findings to triage.", which is otherwise the most
    # complete-looking output triage has.
    monkeypatch.setattr(
        "agentsec.audit.audit",
        lambda *a, **k: _FakeResult(
            [], tools_unavailable=["trivy", "gitleaks"], tools_offline_skipped=["pip-audit"],
            tools_reduced=["semgrep — registry packs need tier 1; local LLM pack only"],
            tools_errored=["hadolint"],
        ),
    )
    rc = tc.run(_args(tmp_path, verdict="fp", reason="r"))
    assert rc == 0
    out = capsys.readouterr().out
    assert "scanners not installed (skipped): trivy, gitleaks" in out
    assert "scanners skipped (offline — raise --network to enable): pip-audit" in out
    assert "reduced coverage: semgrep — registry packs need tier 1" in out
    assert "scanners that errored: hadolint" in out
    assert "No findings to triage." in out


def test_source_header_under_guards_only_says_scanners_did_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    g = Finding(check_id="cors-wildcard", severity="high", title="t",
                location="app/main.py:10", message="allow_origins=['*']")
    monkeypatch.setattr("agentsec.audit.audit", lambda *a, **k: _FakeResult([g]))
    tc.run(_args(tmp_path, verdict="fp", reason="r", dry_run=True, guards_only=True))
    out = capsys.readouterr().out
    assert "1 finding(s): 1 from guards, external scanners not run (--guards-only)" in out


def test_dry_run_lists_the_rule_so_rule_is_discoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Mirror of `test_dry_run_lists_fingerprints`: the rule column is what makes `--rule`
    # discoverable, the way the fingerprint column does for `--fingerprint`.
    b = _bandit()
    monkeypatch.setattr("agentsec.audit.audit", lambda *a, **k: _FakeResult([b]))
    tc.run(_args(tmp_path, verdict="fp", reason="r", dry_run=True))
    out = capsys.readouterr().out
    assert f"{fingerprint(b)}  bandit  B608  app/db.py:12" in out


def test_triage_cli_parses_the_scanner_selection_flags_and_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The argparse surface, through `main`: the four selection flags + --rule are accepted on
    # `triage` and dispatch to the driver with the values the driver reads.
    from agentsec.cli import main

    seen = _capture_audit_kwargs(monkeypatch, [_bandit()])
    rc = main(["triage", str(tmp_path), "--guards-only", "--deterministic", "--rule", "B608",
               "--verdict", "fp", "--reason", "r", "--dry-run"])
    assert rc == 0
    assert seen["run_scanners"] is False and seen["deterministic"] is True
