"""Tests for `agentsec harden-js` (the deterministic, offline JS hardener)."""
from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.cli import main
from agentsec.js_harden import ensure_npmrc, ensure_pnpm_workspace, harden

# --- config editors -----------------------------------------------------------

def test_ensure_npmrc_adds_keys() -> None:
    out, added = ensure_npmrc("", cooldown_min=2880)
    assert added == ["ignore-scripts", "min-release-age"]
    assert "ignore-scripts=true" in out
    assert "min-release-age=2" in out  # 2880 min → 2 days
    # idempotent
    out2, added2 = ensure_npmrc(out, cooldown_min=2880)
    assert added2 == [] and out2 == out


def test_ensure_npmrc_keeps_existing() -> None:
    out, added = ensure_npmrc("ignore-scripts=true\n", cooldown_min=2880)
    assert added == ["min-release-age"]  # ignore-scripts already present


def test_ensure_pnpm_workspace_adds_keys() -> None:
    out, added = ensure_pnpm_workspace("", cooldown_min=2880)
    assert "minimumReleaseAge" in added and "trustPolicy" in added
    assert "minimumReleaseAge: 2880" in out and "trustPolicy: no-downgrade" in out
    out2, added2 = ensure_pnpm_workspace(out, cooldown_min=2880)
    assert added2 == []


def test_ensure_pnpm_workspace_skips_existing_key() -> None:
    out, added = ensure_pnpm_workspace("minimumReleaseAge: 4320\n", cooldown_min=2880)
    assert "minimumReleaseAge" not in added  # don't overwrite a stronger value
    assert "trustPolicy" in added


# --- orchestration ------------------------------------------------------------

def _npm_project(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text('{"dependencies": {"react": "19.0.0"}}\n', encoding="utf-8")
    (root / "package-lock.json").write_text("{}\n", encoding="utf-8")


def _pnpm_project(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text('{"dependencies": {"react": "19.0.0"}}\n', encoding="utf-8")
    (root / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")


def test_harden_dry_run_writes_nothing(tmp_path: Path) -> None:
    _npm_project(tmp_path)
    result = harden(tmp_path, dry_run=True)
    assert any(a.status == "would-write" for a in result.actions)
    assert not (tmp_path / ".npmrc").exists()


def test_harden_npm_writes_npmrc(tmp_path: Path) -> None:
    _npm_project(tmp_path)
    harden(tmp_path)
    npmrc = (tmp_path / ".npmrc").read_text(encoding="utf-8")
    assert "ignore-scripts=true" in npmrc and "min-release-age=2" in npmrc


def test_harden_pnpm_writes_workspace(tmp_path: Path) -> None:
    _pnpm_project(tmp_path)
    harden(tmp_path)
    ws = (tmp_path / "pnpm-workspace.yaml").read_text(encoding="utf-8")
    assert "minimumReleaseAge: 2880" in ws and "trustPolicy: no-downgrade" in ws
    assert not (tmp_path / ".npmrc").exists()  # pnpm → workspace, not npmrc


def test_harden_clears_cooldown_and_lifecycle(tmp_path: Path) -> None:
    _npm_project(tmp_path)
    result = harden(tmp_path)
    rules = {f.rule for f in result.remaining}
    assert "js-supply-chain/no-cooldown" not in rules
    assert "js-supply-chain/lifecycle-scripts" not in rules  # ignore-scripts written


def test_harden_reports_unpinned(tmp_path: Path) -> None:
    # No lockfile, so a floating caret is a genuine exposure even after harden adds a cooldown
    # (a lockfile + cooldown together would neutralize it — see js-supply-chain T2b). harden reports it.
    tmp_path.joinpath("package.json").write_text('{"dependencies": {"react": "^19.0.0"}}\n', encoding="utf-8")
    result = harden(tmp_path)
    assert any(a.kind == "report" and a.detail.endswith("unpinned") for a in result.actions)


def test_harden_idempotent(tmp_path: Path) -> None:
    _npm_project(tmp_path)
    harden(tmp_path)
    result2 = harden(tmp_path)
    assert all(a.status != "wrote" for a in result2.actions if a.kind == ".npmrc")


def test_harden_preserves_existing_crlf(tmp_path: Path) -> None:
    # H6: hardening an existing CRLF .npmrc must not flatten its line endings while
    # appending the missing key (read + write both newline-preserving).
    _npm_project(tmp_path)
    (tmp_path / ".npmrc").write_bytes(b"ignore-scripts=true\r\n")  # existing CRLF, missing cooldown
    harden(tmp_path)
    raw = (tmp_path / ".npmrc").read_bytes()
    assert b"ignore-scripts=true\r\n" in raw   # existing CRLF terminator preserved
    assert b"min-release-age" in raw            # the missing key was appended


# --- CLI ----------------------------------------------------------------------

def test_cli_dry_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _npm_project(tmp_path)
    rc = main(["harden-js", str(tmp_path), "--dry-run"])
    assert rc == 0 and "Would write" in capsys.readouterr().out
    assert not (tmp_path / ".npmrc").exists()


def test_cli_writes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _pnpm_project(tmp_path)
    rc = main(["harden-js", str(tmp_path)])
    assert rc == 0
    assert "minimumReleaseAge: 2880" in (tmp_path / "pnpm-workspace.yaml").read_text(encoding="utf-8")
