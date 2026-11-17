"""Tests for Phase 1 gap-memory and report-gap command (agentsec/gap_report.py)."""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from agentsec.gap_report import _issue_url, issue_url, list_gaps, open_in_browser, record_gaps

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _patch_gaps_file(tmp_path: Path) -> Path:
    """Return the patched gap-memory path (used by monkeypatch callers)."""
    return tmp_path / ".agentsec" / "gaps.json"


# ---------------------------------------------------------------------------
# record_gaps
# ---------------------------------------------------------------------------


def test_record_gaps_creates_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentsec.gap_report._gaps_file", lambda: _patch_gaps_file(tmp_path))

    record_gaps({"django", "flask"}, today=date(2026, 6, 21))

    path = _patch_gaps_file(tmp_path)
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["seen"]["django"] == "2026-06-21"
    assert data["seen"]["flask"] == "2026-06-21"


def test_record_gaps_preserves_existing_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _patch_gaps_file(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"seen": {"django": "2026-06-01"}}), encoding="utf-8")
    monkeypatch.setattr("agentsec.gap_report._gaps_file", lambda: path)

    record_gaps({"flask"}, today=date(2026, 6, 21))

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["seen"]["django"] == "2026-06-01"  # preserved, not overwritten
    assert data["seen"]["flask"] == "2026-06-21"    # new entry


def test_record_gaps_first_seen_not_overwritten(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _patch_gaps_file(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"seen": {"django": "2026-06-01"}}), encoding="utf-8")
    monkeypatch.setattr("agentsec.gap_report._gaps_file", lambda: path)

    record_gaps({"django"}, today=date(2026, 6, 21))

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["seen"]["django"] == "2026-06-01"  # first-seen date preserved


def test_record_gaps_empty_set_is_noop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentsec.gap_report._gaps_file", lambda: _patch_gaps_file(tmp_path))

    record_gaps(set(), today=date(2026, 6, 21))

    assert not _patch_gaps_file(tmp_path).exists()


def test_record_gaps_skips_write_when_all_already_seen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _patch_gaps_file(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"seen": {"django": "2026-06-01"}}), encoding="utf-8")
    monkeypatch.setattr("agentsec.gap_report._gaps_file", lambda: path)

    mtime_before = path.stat().st_mtime
    record_gaps({"django"}, today=date(2026, 6, 21))
    mtime_after = path.stat().st_mtime

    assert mtime_before == mtime_after  # no write happened


def test_record_gaps_silently_swallows_bad_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _patch_gaps_file(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text("not valid json", encoding="utf-8")
    monkeypatch.setattr("agentsec.gap_report._gaps_file", lambda: path)

    # Should not raise; bad existing JSON is treated as empty
    record_gaps({"django"}, today=date(2026, 6, 21))

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["seen"]["django"] == "2026-06-21"


# ---------------------------------------------------------------------------
# list_gaps
# ---------------------------------------------------------------------------


def test_list_gaps_returns_empty_when_no_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "agentsec.gap_report._gaps_file", lambda: tmp_path / "nonexistent" / "gaps.json"
    )
    assert list_gaps() == {}


def test_list_gaps_returns_seen_dict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _patch_gaps_file(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"seen": {"django": "2026-06-01"}}), encoding="utf-8")
    monkeypatch.setattr("agentsec.gap_report._gaps_file", lambda: path)

    assert list_gaps() == {"django": "2026-06-01"}


def test_list_gaps_returns_empty_on_bad_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _patch_gaps_file(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text("not valid json", encoding="utf-8")
    monkeypatch.setattr("agentsec.gap_report._gaps_file", lambda: path)

    assert list_gaps() == {}


# ---------------------------------------------------------------------------
# _issue_url
# ---------------------------------------------------------------------------


def test_issue_url_contains_stack_name() -> None:
    url = _issue_url("django")
    assert "django" in url
    assert "github.com" in url
    assert "issues/new" in url
    assert "title=" in url
    assert "body=" in url


def test_issue_url_different_stacks_differ() -> None:
    assert _issue_url("django") != _issue_url("flask")


def test_issue_url_labels_gap_report() -> None:
    assert "gap-report" in _issue_url("express")


# ---------------------------------------------------------------------------
# browser open (only on explicit --open) + the network-free guardrail
# ---------------------------------------------------------------------------


def test_open_in_browser_is_lazy_and_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    import webbrowser

    opened: list[str] = []
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url))
    url = issue_url("flask")
    open_in_browser(url)
    assert opened == [url]
    assert "flask" in url


def test_gap_report_module_imports_no_network_module() -> None:
    """G5 guardrail: the Phase-1 module must not import any network/egress module at
    module level (webbrowser is imported lazily inside open_in_browser, on --open only).
    The guard sandbox scan only covers agentsec/guards/*, so pin this module explicitly."""
    import ast
    from pathlib import Path

    # Network/egress modules (urllib.parse is string-building, NOT network — allowed).
    banned = (
        "socket", "ssl", "requests", "httpx", "aiohttp", "ftplib", "smtplib", "telnetlib",
        "webbrowser", "http.client", "http.server", "urllib.request", "urllib.error",
    )
    src = (Path(__file__).resolve().parents[1] / "agentsec" / "gap_report.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    mods: set[str] = set()
    for node in tree.body:  # top-level imports only (lazy webbrowser inside a fn is exempt)
        if isinstance(node, ast.Import):
            mods |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    hits = {m for m in mods for p in banned if m == p or m.startswith(p + ".")}
    assert not hits, f"gap_report.py imports network module(s) at top level: {hits}"


# ---------------------------------------------------------------------------
# CLI integration — record_gaps wired into detect and audit
# ---------------------------------------------------------------------------


def test_audit_records_uncovered_stacks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When audit detects uncovered stacks, they are silently recorded."""
    (tmp_path / "requirements.txt").write_text("django==4.2.0\n", encoding="utf-8")
    gaps_file = tmp_path / "gaps.json"
    monkeypatch.setattr("agentsec.gap_report._gaps_file", lambda: gaps_file)

    from agentsec.cli import main
    main(["audit", str(tmp_path), "--guards-only", "--no-fail"])

    assert gaps_file.exists()
    data = json.loads(gaps_file.read_text(encoding="utf-8"))
    assert "django" in data["seen"]


def test_detect_records_uncovered_stacks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When detect finds uncovered stacks, they are silently recorded."""
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    gaps_file = tmp_path / "gaps.json"
    monkeypatch.setattr("agentsec.gap_report._gaps_file", lambda: gaps_file)

    from agentsec.cli import main
    main(["detect", str(tmp_path)])

    assert gaps_file.exists()
    data = json.loads(gaps_file.read_text(encoding="utf-8"))
    assert "flask" in data["seen"]
