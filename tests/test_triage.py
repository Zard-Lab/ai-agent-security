"""Tests for agentsec/triage.py — triage persistence layer."""

import json
from pathlib import Path

from agentsec.findings import Finding
from agentsec.triage import (
    TriageVerdict,
    apply_triage,
    fingerprint,
    load_triage,
    save_triage,
)


def _finding(check_id: str = "test-guard", location: str = "app/routes.py:42", message: str = "test msg") -> Finding:
    return Finding(check_id=check_id, severity="high", title="Test", location=location, message=message)


def test_fingerprint_excludes_line_number():
    """Same finding, different line number → same fingerprint."""
    f1 = _finding(location="app/routes.py:42")
    f2 = _finding(location="app/routes.py:99")
    assert fingerprint(f1) == fingerprint(f2)


def test_fingerprint_discriminates_different_message():
    """Same guard, same file, different message → different fingerprint."""
    f1 = _finding(message="msg A")
    f2 = _finding(message="msg B")
    assert fingerprint(f1) != fingerprint(f2)


def test_fingerprint_discriminates_different_guard():
    """Same location + message, different guard → different fingerprint."""
    f1 = _finding(check_id="guard-a")
    f2 = _finding(check_id="guard-b")
    assert fingerprint(f1) != fingerprint(f2)


def test_fingerprint_stability_no_line_col_suffix():
    """Finding with no line suffix produces same fingerprint as one with :line:col."""
    f1 = _finding(location="app/routes.py")
    f2 = _finding(location="app/routes.py:42:5")
    assert fingerprint(f1) == fingerprint(f2)


def test_fingerprint_delegates_to_stable_fingerprint():
    """Issue #325: triage keys on the canonical Finding.stable_fingerprint(), so the two
    subsystems agree on one identity (no more parallel hand-rolled hash)."""
    f = _finding(location="app/routes.py:42", message="test msg")
    assert fingerprint(f) == f.stable_fingerprint()


def test_save_and_load_roundtrip(tmp_path: Path):
    """save_triage then load_triage is idempotent."""
    f = _finding()
    fp = fingerprint(f)
    verdict = TriageVerdict(
        guard_id="test-guard",
        file="app/routes.py",
        fingerprint=fp,
        verdict="fp",
        reason="4xx response",
        improvement="only flag 5xx",
    )
    path = tmp_path / "agentsec-triage.json"
    save_triage([verdict], path)
    loaded = load_triage(path)
    assert len(loaded) == 1
    assert loaded[0].verdict == "fp"
    assert loaded[0].reason == "4xx response"
    assert loaded[0].improvement == "only flag 5xx"


def test_load_triage_missing_file(tmp_path: Path):
    """load_triage returns [] when file doesn't exist."""
    path = tmp_path / "nonexistent.json"
    assert load_triage(path) == []


def test_load_triage_malformed_json_degrades(tmp_path: Path):
    """A hand-broken (invalid JSON) triage file degrades to [] instead of crashing the scan."""
    path = tmp_path / "agentsec-triage.json"
    path.write_text("{ not valid json ", encoding="utf-8")
    assert load_triage(path) == []


def test_load_triage_tolerates_null_verdicts(tmp_path: Path):
    """H4: an explicit `"verdicts": null` hand-edit must degrade to [], not TypeError."""
    path = tmp_path / "agentsec-triage.json"
    path.write_text(json.dumps({"version": 1, "verdicts": None}), encoding="utf-8")
    assert load_triage(path) == []


def test_load_triage_skips_bad_entries(tmp_path: Path):
    """Unknown keys are tolerated; entries that are non-dict, lack a fingerprint, or miss a
    required field are skipped — a bad hand-edit never crashes load_triage."""
    path = tmp_path / "agentsec-triage.json"
    path.write_text(
        json.dumps({
            "version": 1,
            "verdicts": [
                {"guard_id": "g", "file": "f.py", "fingerprint": "aa11", "verdict": "fp",
                 "future_field": "ignored"},        # unknown key → tolerated, entry kept
                {"guard_id": "g", "file": "f.py", "verdict": "fp"},   # no fingerprint → skipped
                {"verdict": "real", "fingerprint": "bb22"},           # missing guard_id/file → skipped
                "not-a-dict",                                          # junk → skipped
            ],
        }),
        encoding="utf-8",
    )
    loaded = load_triage(path)
    assert len(loaded) == 1
    assert loaded[0].fingerprint == "aa11"
    assert loaded[0].verdict == "fp"


def test_apply_triage_attaches_verdict():
    """apply_triage attaches the correct verdict when fingerprint matches."""
    f = _finding()
    fp = fingerprint(f)
    verdict = TriageVerdict(
        guard_id="test-guard", file="app/routes.py", fingerprint=fp, verdict="real"
    )
    result = apply_triage([f], [verdict])
    assert len(result) == 1
    assert result[0].verdict is not None
    assert result[0].verdict.verdict == "real"


def test_apply_triage_leaves_unannotated_on_no_match():
    """apply_triage leaves finding without verdict when no fingerprint match."""
    f = _finding()
    verdict = TriageVerdict(
        guard_id="other-guard", file="other.py", fingerprint="aabbccdd11223344", verdict="fp"
    )
    result = apply_triage([f], [verdict])
    assert result[0].verdict is None


def test_save_triage_writes_version(tmp_path: Path):
    """Saved triage file has version field (bumped to 3 in #567 — fingerprint scheme changed)."""
    path = tmp_path / "triage.json"
    save_triage([], path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == 3
    assert data["verdicts"] == []


def test_save_triage_utf8(tmp_path: Path):
    """Triage file is written as UTF-8 (no BOM, handles non-ASCII)."""
    path = tmp_path / "triage.json"
    v = TriageVerdict(
        guard_id="g", file="f.py", fingerprint="aa", verdict="fp", reason="détail=str(e)"
    )
    save_triage([v], path)
    raw = path.read_bytes()
    assert b"\xef\xbb\xbf" not in raw  # no BOM
    assert "détail".encode() in raw


def _write_triage_file(path: Path, version: object) -> None:
    payload = {"version": version, "verdicts": [
        {"guard_id": "g", "file": "f.py", "fingerprint": "aa", "verdict": "fp", "reason": "r"}
    ]}
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_load_triage_warns_on_older_scheme(tmp_path: Path, capsys):
    """A v1-scheme file (pre-#325) still loads, but warns that its verdicts may no longer match."""
    path = tmp_path / "agentsec-triage.json"
    _write_triage_file(path, 1)
    out = load_triage(path)
    assert len(out) == 1  # verdicts still returned, not dropped
    err = capsys.readouterr().err
    assert "scheme v1" in err and "re-run `agentsec triage`" in err


def test_load_triage_no_warning_on_current_scheme(tmp_path: Path, capsys):
    """A current-version file loads silently."""
    path = tmp_path / "agentsec-triage.json"
    save_triage([TriageVerdict(guard_id="g", file="f.py", fingerprint="aa", verdict="fp")], path)
    load_triage(path)
    assert "scheme v" not in capsys.readouterr().err


def test_load_triage_warns_on_newer_scheme(tmp_path: Path, capsys):
    """A file from a newer agentsec warns to upgrade rather than silently mis-matching."""
    path = tmp_path / "agentsec-triage.json"
    _write_triage_file(path, 99)
    load_triage(path)
    assert "newer agentsec" in capsys.readouterr().err


def test_load_triage_no_warning_when_version_absent(tmp_path: Path, capsys):
    """A minimal hand-authored file with no version field must not spam a warning."""
    path = tmp_path / "agentsec-triage.json"
    path.write_text(json.dumps({"verdicts": []}), encoding="utf-8")
    load_triage(path)
    assert "scheme v" not in capsys.readouterr().err


def test_triage_location_file_strips_only_a_trailing_line_suffix() -> None:
    # Regression (#474 review, HIGH): the bridged waiver stored `location.split(":")[0]`, so a
    # ZAP/live finding's URL became `"https"`. Because `Exception_.matches` falls back to a
    # boundary PREFIX match, a waiver written for one finding at `/admin` then suppressed an
    # unrelated CRITICAL at `/checkout` — different message, different severity, site-wide.
    from agentsec.triage_cli import _location_file

    assert _location_file("app.py:42") == "app.py"
    assert _location_file("app.py:42:7") == "app.py"
    assert _location_file("app.py") == "app.py"
    assert _location_file("https://app.example.com/admin") == "https://app.example.com/admin"
    assert _location_file("https://app.example.com:8443/admin") == "https://app.example.com:8443/admin"
    assert _location_file("") == ""


def test_apply_triage_does_not_annotate_a_sibling_port():
    """#567: a verdict rendered on one port must not mark another port triaged.

    `triage --fingerprint` is documented as the exact per-finding pin, so a collapse here
    meant the unreviewed finding was never shown for classification at all."""
    a = _finding(location="https://internal.example.com:9200", message="Server leaks version information")
    b = _finding(location="https://internal.example.com:6379", message="Server leaks version information")
    verdict = TriageVerdict(guard_id="sarif:zap", file=a.location, fingerprint=fingerprint(a), verdict="fp")
    annotated = apply_triage([a, b], [verdict])
    assert annotated[0].verdict is verdict
    assert annotated[1].verdict is None


def test_apply_triage_still_spans_an_ordinary_line_shift():
    """The direction traded against: a verdict must still follow its finding across a line shift."""
    at_42 = _finding(location="app/routes.py:42")
    at_99 = _finding(location="app/routes.py:99")
    verdict = TriageVerdict(guard_id="test-guard", file="app/routes.py",
                            fingerprint=fingerprint(at_42), verdict="fp")
    annotated = apply_triage([at_42, at_99], [verdict])
    assert [a.verdict for a in annotated] == [verdict, verdict]


# --- #864: `TriageVerdict.rule` is additive; the fingerprint scheme (and so the version) is not bumped


def test_v3_verdict_without_rule_key_still_attaches(tmp_path: Path) -> None:
    """A v3 triage file written BEFORE #864 has no `rule` key. It must load without a version
    warning (the fingerprint basis is unchanged, so `_TRIAGE_VERSION` stays 3) and its verdict
    must still attach to its finding — an old verdict going inert would re-surface the finding
    as untriaged, i.e. lose the analyst's decision."""
    f = _finding()
    path = tmp_path / "agentsec-triage.json"
    path.write_text(json.dumps({
        "version": 3,
        "verdicts": [{
            "guard_id": f.check_id, "file": "app/routes.py", "fingerprint": fingerprint(f),
            "verdict": "fp", "reason": "pre-#864", "improvement": "", "risk": "",
            "fix_status": "", "fix_commit": "", "triaged_by": "", "triaged_at": "",
        }],
    }), encoding="utf-8")
    loaded = load_triage(path)
    assert len(loaded) == 1 and loaded[0].rule == ""
    annotated = apply_triage([f], loaded)
    assert annotated[0].verdict is not None and annotated[0].verdict.reason == "pre-#864"


def test_rule_roundtrips_and_is_descriptive_only(tmp_path: Path) -> None:
    """`rule` is written and read back, and does NOT participate in matching: a verdict whose
    recorded rule disagrees with the finding still attaches on the fingerprint alone (the same
    contract `file` has — descriptive, never a selector)."""
    f = Finding(check_id="bandit", severity="medium", title="t", location="app/db.py:12",
                message="Possible SQL injection", rule="B608")
    v = TriageVerdict(guard_id="bandit", file="app/db.py", fingerprint=fingerprint(f),
                      verdict="fp", rule="B608")
    path = tmp_path / "t.json"
    save_triage([v], path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["version"] == 3 and raw["verdicts"][0]["rule"] == "B608"
    loaded = load_triage(path)
    assert loaded[0].rule == "B608"
    loaded[0].rule = "B999"   # a hand-edited, wrong rule label
    assert apply_triage([f], loaded)[0].verdict is loaded[0]
