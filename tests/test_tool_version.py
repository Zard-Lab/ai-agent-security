"""Tests for `tool_version.py` — the installed-vs-pinned probe (#592) — and its
doctor rendering.

Hermetic: probes use an injected fake runner (the hostaudit/probes.py pattern),
never a real subprocess. Version literals compare against the LIVE pins, never
hardcoded pin values, so a deps bump cannot invalidate these tests.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from agentsec import pins, tool_version, tooling
from agentsec.tool_version import ToolVersion, compare_versions, parse_version_line, probe
from agentsec.tooling import TOOLS, ToolSpec


def _spec(pin_name: str = "trivy", version_args: tuple[str, ...] = ("--version",)) -> ToolSpec:
    return ToolSpec(id="demo", kind="native", binary="demo", summary="x",
                    pin_name=pin_name, version_args=version_args)


def _recorder(response: tuple[int, str] | None) -> tuple[list[list[str]], tool_version.Runner]:
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> tuple[int, str] | None:
        calls.append(argv)
        return response

    return calls, runner


# --- state ladder: fires -----------------------------------------------------

def test_stale_when_numerically_behind_the_pin() -> None:
    _calls, runner = _recorder((0, "Version: 0.1.0\n"))
    tv = probe(_spec(), "/managed/demo", runner=runner)
    assert tv.state == "stale"
    assert tv.installed == "0.1.0"
    assert tv.pinned == pins.version("trivy")


def test_probe_invokes_the_declared_version_args() -> None:
    calls, runner = _recorder((0, "Version: 0.1.0\n"))
    probe(_spec(), "/managed/demo", runner=runner)
    assert calls == [["/managed/demo", "--version"]]


# --- state ladder: FP-bait ---------------------------------------------------

def test_ahead_is_not_stale() -> None:
    _calls, runner = _recorder((0, "Version: 999.0.0\n"))
    tv = probe(_spec(), "/managed/demo", runner=runner)
    assert tv.state == "ahead"


def test_exact_pin_is_current() -> None:
    _calls, runner = _recorder((0, f"Version: {pins.version('trivy')}\n"))
    tv = probe(_spec(), "/managed/demo", runner=runner)
    assert tv.state == "current"


def test_zero_padded_compare() -> None:
    # '0.73' vs '0.73.0' is current, not stale — the likeliest real-world FP.
    assert compare_versions((0, 73), (0, 73, 0)) == "current"
    assert compare_versions((0, 73, 0), (0, 73)) == "current"
    assert compare_versions((0, 72, 9), (0, 73)) == "stale"
    assert compare_versions((0, 73, 1), (0, 73)) == "ahead"


def test_unpinned_tool_is_never_probed() -> None:
    calls, runner = _recorder((0, "Version: 0.1.0\n"))
    tv = probe(_spec(pin_name=""), "/managed/demo", runner=runner)
    assert tv.state == "no-pin"
    assert calls == [], "an unpinned tool must spawn NO subprocess"


def test_half_wired_spec_is_never_probed() -> None:
    # pin_name without version_args (the tripwire below rejects it in the real
    # catalog) — probe must degrade to no-probe rather than run the binary bare.
    calls, runner = _recorder((0, "Version: 0.1.0\n"))
    tv = probe(_spec(version_args=()), "/managed/demo", runner=runner)
    assert tv.state == "no-pin"
    assert calls == []


def test_absent_tool_is_never_probed() -> None:
    calls, runner = _recorder((0, "Version: 0.1.0\n"))
    tv = probe(_spec(), None, runner=runner)
    assert tv.state == "absent"
    assert calls == []


# --- state ladder: totality (rule 3 — no failure may land on `current`) ------

def test_unparseable_output_is_unknown() -> None:
    _calls, runner = _recorder((0, "utterly unversioned banner\n"))
    tv = probe(_spec(), "/managed/demo", runner=runner)
    assert tv.state == "unknown"
    assert tv.installed == ""


def test_probe_returning_none_is_unknown() -> None:
    _calls, runner = _recorder(None)
    assert probe(_spec(), "/managed/demo", runner=runner).state == "unknown"


def test_nonzero_rc_is_unknown_and_output_never_parsed() -> None:
    _calls, runner = _recorder((3, f"Version: {pins.version('trivy')}\n"))
    tv = probe(_spec(), "/managed/demo", runner=runner)
    assert tv.state == "unknown"
    assert tv.installed == "", "a failed probe's output must not be trusted"


def test_empty_output_is_unknown() -> None:
    _calls, runner = _recorder((0, ""))
    assert probe(_spec(), "/managed/demo", runner=runner).state == "unknown"


def test_raising_runner_still_returns_a_toolversion() -> None:
    def runner(argv: list[str]) -> tuple[int, str] | None:
        raise RuntimeError("boom")

    tv = probe(_spec(), "/managed/demo", runner=runner)
    assert tv.state == "unknown"


def test_unexecutable_binary_stays_unknown_to_the_pinned_ladder(tmp_path: Path) -> None:
    # #1043 made an OSError a verdict (rc 127) rather than None. The pinned ladder
    # must not notice: any rc != 0 was already `unknown`, so #592 is unchanged.
    missing = str(tmp_path / "no-such-binary")
    assert tool_version.real_runner([missing, "--version"])[0] == 127  # type: ignore[index]
    assert probe(_spec(), missing).state == "unknown"


# --- liveness (#1043): does a python tool start at all? ----------------------

def _python_spec(liveness_args: tuple[str, ...] = ("--version",)) -> ToolSpec:
    return ToolSpec(id="demo", kind="python", binary="demo", summary="x", liveness_args=liveness_args)


def test_liveness_runs_the_declared_args_and_reads_the_exit_code() -> None:
    calls, runner = _recorder((0, "demo 1.0\n"))
    assert tool_version.liveness(_python_spec(("--version", "--quiet")), "/m/demo", runner=runner) == "ok"
    assert calls == [["/m/demo", "--version", "--quiet"]]
    _calls, runner = _recorder((1, "ModuleNotFoundError: No module named 'demo'\n"))
    assert tool_version.liveness(_python_spec(), "/m/demo", runner=runner) == "broken"


def test_liveness_without_a_verdict_is_unknown_never_broken() -> None:
    # A timeout must not read as broken: setup rebuilds the managed venv on broken.
    _calls, runner = _recorder(None)
    assert tool_version.liveness(_python_spec(), "/m/demo", runner=runner) == "unknown"

    def raising(argv: list[str]) -> tuple[int, str] | None:
        raise RuntimeError("boom")

    assert tool_version.liveness(_python_spec(), "/m/demo", runner=raising) == "unknown"


def test_liveness_timeout_is_unknown_through_the_real_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    def timeout(*a: object, **k: object) -> object:
        raise subprocess.TimeoutExpired(cmd="demo", timeout=1)

    monkeypatch.setattr(tool_version.subprocess, "run", timeout)
    assert tool_version.liveness(_python_spec(), "/m/demo") == "unknown"


def test_script_whose_interpreter_is_gone_is_broken(tmp_path: Path) -> None:
    # The dangling-venv case: the console script exists but its shebang interpreter
    # does not, so exec raises an OSError (ENOENT on POSIX; on Windows an
    # extension-less file is not executable at all). That used to collapse into
    # None (`unknown`); it must read as broken, through the real runner.
    script = tmp_path / "demo"
    script.write_text(f"#!{tmp_path / 'gone' / 'python'}\nimport demo\n", encoding="utf-8")
    script.chmod(0o755)
    assert tool_version.liveness(_python_spec(), str(script)) == "broken"


def test_liveness_scope_is_exactly_the_python_kind() -> None:
    assert {t.id for t in TOOLS if tool_version.checks_liveness(t)} == {
        "bandit", "semgrep", "pip-audit", "schemathesis", "garak", "uv",
    }


def test_liveness_args_never_phone_home() -> None:
    """A bare `semgrep --version` calls semgrep.dev's version-check endpoint, and
    doctor runs at Tier 0 (offline). Its liveness argv must carry the same opt-out
    the runner passes on every scan."""
    semgrep = tooling.tool_by_id("semgrep")
    assert semgrep is not None and "--disable-version-check" in semgrep.liveness_args
    for t in TOOLS:
        if tool_version.checks_liveness(t):
            assert t.liveness_args, f"{t.id}: a python tool needs a liveness argv"


# --- parsing: measured first-line formats ------------------------------------

def test_verified_first_lines_parse() -> None:
    # All four formats verified live on 2026-09-07 (issue #592 RCA).
    assert parse_version_line("Version: 0.73.0") == "0.73.0"                    # trivy
    assert parse_version_line("Haskell Dockerfile Linter 2.14.0") == "2.14.0"   # hadolint
    assert parse_version_line("gitleaks version 8.30.1") == "8.30.1"            # gitleaks
    assert parse_version_line("st, version 4.24.3") == "4.24.3"                 # schemathesis
    assert parse_version_line("v8.30.1") == "8.30.1"                            # bare tag shape


def test_trivy_db_schema_version_is_not_the_tool_version() -> None:
    # Measured: `trivy --version` prints a second `Version: 2` further down (the
    # vulnerability-DB schema). First-line-only parsing is mandatory, or the
    # tool reports its version as `2`.
    out = (
        "Version: 0.1.0\n"
        "Vulnerability DB:\n"
        "  Version: 2\n"
        "  UpdatedAt: 2026-08-14 13:02:51 +0000 UTC\n"
    )
    _calls, runner = _recorder((0, out))
    tv = probe(_spec(), "/managed/demo", runner=runner)
    assert tv.installed == "0.1.0"
    assert tv.state == "stale"


def test_bare_integer_is_not_a_version() -> None:
    # A dotless integer (the DB-schema shape) must not parse as a version.
    assert parse_version_line("Version: 2") == ""


# --- is_managed --------------------------------------------------------------

def test_is_managed_boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tooling, "managed_root", lambda: tmp_path / "managed")
    bindir = tooling.managed_bin_dir()
    bindir.mkdir(parents=True)
    assert tool_version.is_managed(str(bindir / "trivy"))
    assert not tool_version.is_managed("/usr/bin/trivy")


# --- catalog tripwires -------------------------------------------------------

def test_pin_name_iff_version_args_and_resolves() -> None:
    """A half-wired future tool (one field set without the other, or a typo'd
    pin name) must fail the suite, not silently never-probe (#592)."""
    for t in TOOLS:
        assert bool(t.pin_name) == bool(t.version_args), f"{t.id}: set both pin_name and version_args, or neither"
        if t.pin_name:
            pins.pin(t.pin_name)  # raises KeyError on a name pins.py doesn't know


def test_probe_scope_is_exactly_the_pinned_four() -> None:
    assert {t.id for t in TOOLS if t.pin_name} == {"gitleaks", "trivy", "hadolint", "schemathesis"}


def test_react_doctor_declares_no_probe() -> None:
    """react-doctor's pin is applied at *invoke* time (`npx -y react-doctor@X`),
    so there is nothing on disk whose version could drift — probing `npx` would
    compare the wrong tool. It must never gain pin_name/version_args (#592)."""
    spec = tooling.tool_by_id("react-doctor")
    assert spec is not None
    assert spec.pin_name == "" and spec.version_args == ()


# --- doctor rendering --------------------------------------------------------

def _fake_probe(state: str, installed: str = "0.1.0", pinned: str = "9.9.9"):  # type: ignore[no-untyped-def]
    def fake(spec: ToolSpec, path: str | None, **kw: object) -> ToolVersion:
        return ToolVersion("demo", path, state, installed=installed, pinned=pinned)  # type: ignore[arg-type]

    return fake


def test_annotation_stale_managed(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentsec.cli import _version_annotation

    monkeypatch.setattr(tool_version, "probe", _fake_probe("stale"))
    monkeypatch.setattr(tool_version, "is_managed", lambda p: True)
    glyph, suffix = _version_annotation(_spec(), "/managed/demo")
    assert glyph == "⚠"
    assert "stale" in suffix and "agentsec setup" in suffix


def test_annotation_stale_external_names_the_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentsec.cli import _version_annotation

    monkeypatch.setattr(tool_version, "probe", _fake_probe("stale"))
    monkeypatch.setattr(tool_version, "is_managed", lambda p: False)
    glyph, suffix = _version_annotation(_spec(), "/usr/bin/demo")
    assert glyph == "⚠"
    assert "not agentsec-installed" in suffix and "/usr/bin/demo" in suffix


def test_annotation_unknown_is_its_own_glyph(monkeypatch: pytest.MonkeyPatch) -> None:
    # `?` on purpose: sharing ✓ would let a probe failure read as currency (the
    # exact bug being fixed); sharing ⚠ would make an unparseable tool look broken.
    from agentsec.cli import _version_annotation

    monkeypatch.setattr(tool_version, "probe", _fake_probe("unknown", installed=""))
    glyph, suffix = _version_annotation(_spec(), "/managed/demo")
    assert glyph == "?"
    assert "could not verify" in suffix
    assert "stale" not in suffix


def test_annotation_ahead_is_not_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentsec.cli import _version_annotation

    monkeypatch.setattr(tool_version, "probe", _fake_probe("ahead", installed="999.0.0"))
    glyph, suffix = _version_annotation(_spec(), "/managed/demo")
    assert glyph == "✓"
    assert "stale" not in suffix


def test_annotation_unpinned_renders_as_before(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentsec.cli import _version_annotation

    calls, runner = _recorder((0, "x"))
    monkeypatch.setattr(tool_version, "probe", lambda *a, **k: (_ for _ in ()).throw(AssertionError("probed")))
    assert _version_annotation(_spec(pin_name=""), "/usr/bin/demo") == ("✓", "")
    assert _version_annotation(None, "/usr/bin/demo") == ("✓", "")
    assert calls == []


def _fake_liveness(state: str, seen: list[str] | None = None):  # type: ignore[no-untyped-def]
    def fake(spec: ToolSpec, path: str, **kw: object) -> str:
        if seen is not None:
            seen.append(spec.id)
        return state

    return fake


def test_annotation_broken_managed_python_tool_points_at_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    # The issue's headline: doctor ticked a managed semgrep that cannot start.
    from agentsec.cli import _version_annotation

    monkeypatch.setattr(tool_version, "liveness", _fake_liveness("broken"))
    monkeypatch.setattr(tool_version, "is_managed", lambda p: True)
    glyph, suffix = _version_annotation(tooling.tool_by_id("semgrep"), "/managed/semgrep")
    assert glyph == "✗"
    assert "broken" in suffix and "agentsec setup" in suffix and "rebuild the managed venv" in suffix
    assert "`semgrep --version --disable-version-check` failed" in suffix


def test_annotation_broken_external_python_tool_names_the_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentsec.cli import _version_annotation

    monkeypatch.setattr(tool_version, "liveness", _fake_liveness("broken"))
    monkeypatch.setattr(tool_version, "is_managed", lambda p: False)
    glyph, suffix = _version_annotation(tooling.tool_by_id("bandit"), "/usr/bin/bandit")
    assert glyph == "✗"
    assert "not agentsec-installed" in suffix and "/usr/bin/bandit" in suffix


def test_annotation_unverifiable_python_tool_is_a_question_not_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agentsec.cli import _version_annotation

    monkeypatch.setattr(tool_version, "liveness", _fake_liveness("unknown"))
    glyph, suffix = _version_annotation(tooling.tool_by_id("bandit"), "/managed/bandit")
    assert glyph == "?" and "could not verify it starts" in suffix and "broken" not in suffix


def test_annotation_live_pinned_python_tool_still_gets_the_version_ladder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Liveness `ok` falls through to #592's ladder unchanged (schemathesis is pinned).
    from agentsec.cli import _version_annotation

    monkeypatch.setattr(tool_version, "liveness", _fake_liveness("ok"))
    monkeypatch.setattr(tool_version, "probe", _fake_probe("stale"))
    monkeypatch.setattr(tool_version, "is_managed", lambda p: True)
    glyph, suffix = _version_annotation(tooling.tool_by_id("schemathesis"), "/managed/st")
    assert glyph == "⚠" and "stale" in suffix


def test_annotation_never_runs_liveness_for_a_non_python_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    # FP-bait for the widening's scope: natives keep #592's pinned ladder only.
    from agentsec.cli import _version_annotation

    seen: list[str] = []
    monkeypatch.setattr(tool_version, "liveness", _fake_liveness("broken", seen))
    monkeypatch.setattr(tool_version, "probe", _fake_probe("current", installed="1.0.0"))
    assert _version_annotation(tooling.tool_by_id("trivy"), "/usr/bin/trivy") == ("✓", " 1.0.0")
    assert seen == []


def test_doctor_shows_a_broken_managed_venv_as_broken(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """The issue's negative control at the doctor surface: present-but-dead python
    tools render ✗ with the repair command, and a closing line counts them."""
    from agentsec.cli import main

    monkeypatch.setattr("agentsec.runners.base.which", lambda b: f"/managed/{b}")
    monkeypatch.setattr(tool_version, "liveness", _fake_liveness("broken"))
    monkeypatch.setattr(tool_version, "probe", _fake_probe("current", installed="1.0.0"))
    monkeypatch.setattr(tool_version, "is_managed", lambda p: True)
    rc = main(["doctor"])
    out = capsys.readouterr().out
    assert rc == 0, "doctor stays advisory"
    assert f"  ✗ {'semgrep':<11} (semgrep) broken — " in out
    assert f"  ✗ {'bandit':<11} (bandit) broken — " in out
    assert f"  ✓ {'trivy':<11} (trivy) 1.0.0\n" in out, "a native row must not change"
    assert "installed tool(s) cannot start" in out


def test_doctor_rows_stay_byte_identical_for_unpinned_and_binaryless(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """The widening must not reshape rows it has nothing to say about (#592), and a
    python tool that starts keeps its pre-#1043 row byte-for-byte."""
    from agentsec.cli import main

    monkeypatch.setattr("agentsec.runners.base.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(tool_version, "probe", _fake_probe("stale"))
    monkeypatch.setattr(tool_version, "liveness", _fake_liveness("ok"))
    monkeypatch.setattr(tool_version, "is_managed", lambda p: False)
    main(["doctor"])
    out = capsys.readouterr().out
    assert f"  ✓ {'bandit':<11} (bandit)\n" in out                              # unpinned: no suffix
    assert f"  ✓ {'go-osv-hygiene':<11} (no external binary — network only)\n" in out
    assert "⚠ trivy" in out and "not agentsec-installed" in out                 # pinned: annotated
    assert "cannot start" not in out
