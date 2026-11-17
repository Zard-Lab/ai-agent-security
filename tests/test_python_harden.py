"""Tests for `agentsec harden-python` (the deterministic uv hardener)."""
from __future__ import annotations

import shutil
import tomllib
from pathlib import Path

import pytest

import agentsec.python_harden as ph
from agentsec.cli import main
from agentsec.python_harden import ensure_cooldown_text, harden


def _project(root: Path, *, deps: str = '["fastapi==0.1"]', tool_uv: str = "") -> None:
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "x"\nversion = "0"\ndependencies = {deps}\n{tool_uv}', encoding="utf-8"
    )


# --- cooldown text editor -----------------------------------------------------

def test_ensure_cooldown_adds_block() -> None:
    text = '[project]\nname = "x"\n'
    out, changed = ensure_cooldown_text(text, 48, is_pyproject=True)
    assert changed
    data = tomllib.loads(out)  # valid TOML
    assert data["tool"]["uv"]["exclude-newer"] == "48 hours"
    # idempotent
    out2, changed2 = ensure_cooldown_text(out, 48, is_pyproject=True)
    assert changed2 is False and out2 == out


def test_ensure_cooldown_under_existing_tool_uv() -> None:
    text = '[project]\nname = "x"\n[tool.uv]\nindex-strategy = "first-index"\n'
    out, changed = ensure_cooldown_text(text, 48, is_pyproject=True)
    assert changed
    uv = tomllib.loads(out)["tool"]["uv"]
    assert uv["exclude-newer"] == "48 hours" and uv["index-strategy"] == "first-index"


def test_ensure_cooldown_idempotent_when_set() -> None:
    text = '[tool.uv]\nexclude-newer = "7 days"\n'
    out, changed = ensure_cooldown_text(text, 48, is_pyproject=True)
    assert changed is False and out == text


def test_ensure_cooldown_uv_toml_prepend() -> None:
    out, changed = ensure_cooldown_text("index-strategy = \"first-index\"\n", 48, is_pyproject=False)
    assert changed and out.startswith('exclude-newer = "48 hours"\n')
    tomllib.loads(out)


# --- orchestration ------------------------------------------------------------

def _fake_uv(calls: list[list[str]]):
    def runner(cmd: list[str], cwd: Path) -> tuple[int, str, str]:
        calls.append(cmd)
        return 0, "", ""
    return runner


def test_harden_dry_run_writes_nothing(tmp_path: Path) -> None:
    _project(tmp_path)
    before = (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    result = harden(tmp_path, dry_run=True)
    assert any(a.kind == "cooldown" and a.status == "would-write" for a in result.actions)
    assert (tmp_path / "pyproject.toml").read_text(encoding="utf-8") == before  # unchanged
    assert not (tmp_path / "uv.lock").exists()


def test_harden_sets_cooldown_and_runs_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _project(tmp_path)
    monkeypatch.setattr(ph, "which", lambda _b: "/usr/bin/uv")  # pretend uv is installed
    calls: list[list[str]] = []
    result = harden(tmp_path, uv_runner=_fake_uv(calls))
    assert 'exclude-newer = "48 hours"' in (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    assert ["uv", "lock"] in calls
    assert any(a.kind == "lock" and a.status == "ran" for a in result.actions)


def test_harden_lock_skipped_without_uv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _project(tmp_path)
    monkeypatch.setattr(ph, "which", lambda _b: None)
    result = harden(tmp_path)
    assert result.uv_available is False
    lock = [a for a in result.actions if a.kind == "lock"]
    assert lock and lock[0].status == "skipped" and "uv not on PATH" in lock[0].detail
    # cooldown still applied
    assert 'exclude-newer = "48 hours"' in (tmp_path / "pyproject.toml").read_text(encoding="utf-8")


def test_harden_requirements_only_uses_pip_compile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "requirements.txt").write_text("fastapi==0.1\n", encoding="utf-8")
    monkeypatch.setattr(ph, "which", lambda _b: "/usr/bin/uv")
    calls: list[list[str]] = []
    harden(tmp_path, uv_runner=_fake_uv(calls))
    assert calls and calls[0][:3] == ["uv", "pip", "compile"] and "--generate-hashes" in calls[0]
    assert (tmp_path / "uv.toml").read_text(encoding="utf-8").startswith('exclude-newer = "48 hours"')


def test_harden_scaffold_exceptions(tmp_path: Path) -> None:
    _project(tmp_path)
    harden(tmp_path, scaffold_exceptions=True, run_lock=False)
    excs = tmp_path / "pip-audit-exceptions.json"
    assert excs.is_file()
    import json
    assert json.loads(excs.read_text(encoding="utf-8")) == {"exceptions": []}


def test_harden_reverify_clears_cooldown_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _project(tmp_path)
    (tmp_path / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "fastapi"\n[[package.wheels]]\nhash = "sha256:beef"\n', encoding="utf-8"
    )
    monkeypatch.setattr(ph, "which", lambda _b: None)
    result = harden(tmp_path)
    rules = {f.rule for f in result.remaining}
    assert "python-supply-chain/no-cooldown" not in rules
    assert "python-supply-chain/no-locked-hashes" not in rules


def test_harden_no_deps_repo(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("nothing here\n", encoding="utf-8")
    result = harden(tmp_path)
    assert result.actions == [] and result.ok


# --- CLI ----------------------------------------------------------------------

def test_cli_dry_run_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _project(tmp_path)
    rc = main(["harden-python", str(tmp_path), "--dry-run"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Would write" in out
    assert 'exclude-newer' not in (tmp_path / "pyproject.toml").read_text(encoding="utf-8")


def test_cli_writes_cooldown(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _project(tmp_path)
    rc = main(["harden-python", str(tmp_path), "--no-lock"])
    assert rc == 0
    assert 'exclude-newer = "48 hours"' in (tmp_path / "pyproject.toml").read_text(encoding="utf-8")


# --- integration (only when uv is actually installed) -------------------------

def test_integration_real_uv_lock(tmp_path: Path) -> None:
    if shutil.which("uv") is None:
        pytest.skip("uv not installed — covered by the injected-runner tests above")
    # A real (non-empty) dependency is required: dependency_dirs only treats a
    # pyproject as a dep dir when it declares deps, so an empty list would make
    # harden a no-op and never reach the lock step. iniconfig is a tiny, stable
    # leaf package (no transitive deps) so the lock resolves fast.
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0"\n'
        'dependencies = ["iniconfig==2.0.0"]\nrequires-python = ">=3.12"\n', encoding="utf-8"
    )
    harden(tmp_path)
    assert (tmp_path / "uv.lock").is_file()


# ---------------------------------------------------------------------------
# #697 / #702: still-fires coverage for the converted anchors here
#
# `python_harden` is not a guard, so `doctor --canary` cannot reach it at all -- a point the #702
# fix-commit round made against the claim that the canary already covered the narrowing direction
# everywhere. `_TOOL_UV_HEADER` and `_EXCLUDE_NEWER_LINE` took the `^\s*` -> `^[^\S\n]*` conversion
# with no net of their own. These are it.
#
# The miss direction matters here: reading an existing `exclude-newer` as ABSENT would make
# `harden-python` rewrite a file the user had already configured.
#
# Round 3 note: these assert on the REGEX, not only on `_cooldown_already_set`. That helper falls
# back to `tomllib.loads` when the regex misses, and TOML accepts leading spaces/tabs -- so an
# end-to-end assertion stays green for every indent except the NBSP one even with the regex dead,
# and pins nothing about the anchor. The end-to-end path is still covered, once, below.
# ---------------------------------------------------------------------------

_NBSP = "\u00a0"  # spelled as an escape: an inline NBSP is indistinguishable from a space in source


@pytest.mark.parametrize(
    ("label", "indent"),
    [("none", ""), ("spaces", "  "), ("tab", "\t"), ("nbsp", _NBSP)],
)
def test_cooldown_regex_reads_every_same_line_indent(label: str, indent: str) -> None:
    """`[^\\S\\n]*` keeps the full same-line whitespace vocabulary; only the newline is excluded.

    `[ \\t]*` would silently drop the NBSP case -- the exact regression the #696 round caught on the
    Dockerfile anchors -- and a bare `^` would drop the other three.
    """
    text = f'[tool.uv]\n{indent}exclude-newer = "2026-01-01"\n'
    assert ph._EXCLUDE_NEWER_LINE.search(text) is not None, f"{label} indentation stopped matching"


def test_cooldown_regex_reads_a_key_after_a_blank_line_run() -> None:
    """The blank run is what the old anchor scanned across; the key after it must still be found."""
    text = '[tool.uv]\n' + "\n" * 200 + 'exclude-newer = "2026-01-01"\n'
    assert ph._EXCLUDE_NEWER_LINE.search(text) is not None


def test_cooldown_regex_does_not_read_a_key_mid_line() -> None:
    """The other direction: the anchor still has to mean "start of line", not "anywhere"."""
    assert ph._EXCLUDE_NEWER_LINE.search('note = "set exclude-newer = soon"\n') is None


def test_cooldown_already_set_end_to_end_including_the_nbsp_case() -> None:
    """The helper the hardener actually calls. The NBSP case is the one the TOML fallback cannot
    rescue -- `tomllib` rejects an NBSP-indented key outright -- so this is where a regex regression
    would surface end to end, as a rewrite of a file the user had already configured."""
    assert ph._cooldown_already_set('[tool.uv]\n  exclude-newer = "2026-01-01"\n') is True
    assert ph._cooldown_already_set(
        f'[tool.uv]\n{_NBSP}exclude-newer = "2026-01-01"\n'
    ) is True
    assert ph._cooldown_already_set('[tool.uv]\nname = "x"\n') is False


def test_tool_uv_header_detected_when_indented() -> None:
    """`_TOOL_UV_HEADER` took the same conversion. It decides whether the hardener APPENDS a new
    `[tool.uv]` block or edits the existing one, so a miss here duplicates the table."""
    assert ph._TOOL_UV_HEADER.search("[project]\n  [tool.uv]\n") is not None
    assert ph._TOOL_UV_HEADER.search("[project]\n\t[tool.uv]\n") is not None
    assert ph._TOOL_UV_HEADER.search(f"[project]\n{_NBSP}[tool.uv]\n") is not None
    assert ph._TOOL_UV_HEADER.search("[project]\n" + "\n" * 50 + "[tool.uv]\n") is not None
    # ...and it still must NOT match a header that is merely mentioned mid-line.
    assert ph._TOOL_UV_HEADER.search('name = "see [tool.uv] docs"\n') is None
