"""CLI tests for the `agentsec ci` subcommands."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agentsec.cli import main

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "saas_sample"


def test_ci_list(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["ci", "list", str(_FIXTURE)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "react-doctor" in out and "secret-scan" in out
    assert "✓" in out and "–" in out  # frontend applies, docker N/A on the fixture


def test_ci_show(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["ci", "show", "react-doctor", str(_FIXTURE)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "frontend-health.yml" in out
    assert "secrets:" in out


def test_ci_show_unknown_component() -> None:
    rc = main(["ci", "show", "nope"])
    assert rc == 2


def test_ci_add_dry_run_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    dst = tmp_path / "repo"
    shutil.copytree(_FIXTURE, dst)
    rc = main(["ci", "add", "react-doctor", str(dst), "--dry-run"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Would write" in out
    assert not (dst / ".github").exists()


def test_ci_add_writes_then_conflicts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    dst = tmp_path / "repo"
    shutil.copytree(_FIXTURE, dst)

    rc = main(["ci", "add", "react-doctor", str(dst)])
    capsys.readouterr()
    assert rc == 0
    assert (dst / ".github" / "workflows" / "frontend-health.yml").is_file()
    assert (dst / "frontend" / "react-doctor.config.json").is_file()

    # second add → conflict, exit non-zero, files untouched
    rc2 = main(["ci", "add", "react-doctor", str(dst)])
    assert rc2 == 1

    # --force overwrites
    rc3 = main(["ci", "add", "react-doctor", str(dst), "--force"])
    assert rc3 == 0


def test_ci_add_surfaces_required_secrets(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    dst = tmp_path / "repo"
    shutil.copytree(_FIXTURE, dst)  # fixture has the `supabase` feature
    rc = main(["ci", "add", "db-lint", str(dst)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "DATABASE_URL" in out  # the required secret is surfaced to the user


def test_ci_add_na_for_stack(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # empty dir → no frontend feature → react-doctor is N/A
    rc = main(["ci", "add", "react-doctor", str(tmp_path)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "N/A" in err


def test_ci_add_multiple_components(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # `ci add <comp> <comp> <path>` installs several at once (one cross-platform call —
    # issue #78). The trailing token is the repo path because it isn't a known id.
    dst = tmp_path / "repo"
    shutil.copytree(_FIXTURE, dst)
    rc = main(["ci", "add", "react-doctor", "secret-scan", str(dst)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "=== react-doctor ===" in out and "=== secret-scan ===" in out
    assert (dst / ".github" / "workflows" / "frontend-health.yml").is_file()
    assert (dst / ".github" / "workflows" / "secret-scan.yml").is_file()


_SHA = "0123456789abcdef0123456789abcdef01234567"


def _self_audit_wf(root: Path) -> str:
    return (root / ".github" / "workflows" / "agentsec-audit.yml").read_text(encoding="utf-8")


@pytest.mark.parametrize("advisory", [False, True])
def test_ci_add_self_audit_advisory_flag(tmp_path: Path, advisory: bool) -> None:
    """`--advisory` renders the action's advisory mode; without it the gate stays blocking."""
    argv = ["ci", "add", "self-audit", str(tmp_path), "--action-sha", _SHA] + (["--advisory"] if advisory else [])
    assert main(argv) == 0
    modes = [ln.strip() for ln in _self_audit_wf(tmp_path).splitlines() if ln.strip().startswith("mode:")]
    assert modes == ["mode: advisory" if advisory else "mode: gate"]


def test_ci_add_self_audit_pins_the_resolved_release_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """With no --action-sha, the release tag is resolved once and the workflow pins that commit."""
    from agentsec import __version__
    from agentsec.ci import library
    tags: list[str] = []
    monkeypatch.setattr(library, "resolve_action_sha", lambda tag: tags.append(tag) or _SHA)
    assert main(["ci", "add", "self-audit", str(tmp_path)]) == 0
    assert tags == [f"v{__version__}"]
    assert f"uses: Zard-Lab/ai-agent-security@{_SHA}  # v{__version__}" in _self_audit_wf(tmp_path)
    assert f"Pinned agentsec's action to {_SHA} (v{__version__})" in capsys.readouterr().out


@pytest.mark.parametrize("ids", [["self-audit"], ["secret-scan", "self-audit"]])
def test_ci_add_self_audit_fails_before_writing_when_the_pin_cannot_be_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], ids: list[str],
) -> None:
    """Offline or no access: exit 2 with the reason and the escape hatch, and write NOTHING, not even
    a component listed before self-audit (a half-installed set would look like success)."""
    from agentsec.ci import library

    def fail(tag: str) -> str:
        raise library.ActionPinError(f"no release tag {tag}; pass `--action-sha <sha>`")

    monkeypatch.setattr(library, "resolve_action_sha", fail)
    dst = tmp_path / "repo"
    shutil.copytree(_FIXTURE, dst)
    assert main(["ci", "add", *ids, str(dst)]) == 2
    err = capsys.readouterr().err
    assert "Could not pin agentsec's action" in err and "--action-sha" in err
    assert not (dst / ".github").exists()


def test_ci_add_self_audit_dry_run_and_explicit_sha_never_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agentsec.ci import library

    def boom(tag: str) -> str:
        raise AssertionError("resolve_action_sha must not run")

    monkeypatch.setattr(library, "resolve_action_sha", boom)
    assert main(["ci", "add", "self-audit", str(tmp_path / "a"), "--dry-run"]) == 0
    assert main(["ci", "add", "self-audit", str(tmp_path / "b"), "--action-sha", _SHA.upper()]) == 0
    assert f"ai-agent-security@{_SHA}" in _self_audit_wf(tmp_path / "b")  # normalised to lower case


@pytest.mark.parametrize(("argv_tail", "message"), [
    (["self-audit", "--action-sha", "v0.22.0"], "--action-sha must be a full 40-hex commit SHA"),
    (["self-audit", "--action-sha", _SHA[:12]], "--action-sha must be a full 40-hex commit SHA"),
    (["secret-scan", "--action-sha", _SHA], "--action-sha applies to self-audit only"),
])
def test_ci_add_rejects_an_unusable_action_sha_before_writing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], argv_tail: list[str], message: str,
) -> None:
    dst = tmp_path / "repo"
    dst.mkdir()
    cid, *flags = argv_tail
    assert main(["ci", "add", cid, str(dst), *flags]) == 2
    assert message in capsys.readouterr().err
    assert not (dst / ".github").exists()


@pytest.mark.parametrize("ids", [["secret-scan"], ["self-audit", "secret-scan"]])
def test_ci_add_advisory_on_a_non_self_audit_component_fails_before_writing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], ids: list[str]
) -> None:
    """Only self-audit consumes --advisory. Anywhere else it used to exit 0 and write a BLOCKING
    gate while the user believed it was non-blocking (#1167 review M1): fail fast instead."""
    dst = tmp_path / "repo"
    shutil.copytree(_FIXTURE, dst)
    rc = main(["ci", "add", *ids, str(dst), "--advisory"])
    assert rc == 2
    assert "--advisory applies to self-audit only" in capsys.readouterr().err
    assert not (dst / ".github").exists()


def test_ci_add_multiple_unknown_id_fails_before_writing(tmp_path: Path) -> None:
    # a typo in any id fails fast (exit 2) before any component is installed
    dst = tmp_path / "repo"
    shutil.copytree(_FIXTURE, dst)
    rc = main(["ci", "add", "secret-scan", "nope", str(dst)])
    assert rc == 2
    assert not (dst / ".github").exists()


def test_ci_add_self_audit_lookup_is_disclosed_and_refused_under_do_not_track(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """The ls-remote is egress: disclosed before it runs, and DO_NOT_TRACK=1 (which forces tier 0)
    refuses it before anything is written, naming --action-sha. With a pin given there is no
    egress at all, so DO_NOT_TRACK does not stand in the way."""
    from agentsec.ci import library
    calls: list[str] = []
    monkeypatch.setattr(library, "resolve_action_sha", lambda tag: calls.append(tag) or _SHA)
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    assert main(["ci", "add", "self-audit", str(tmp_path / "a")]) == 0
    err = capsys.readouterr().err
    assert "agentsec network: git ls-remote → https://github.com/Zard-Lab/ai-agent-security" in err
    assert "sends: nothing about your repo" in err and len(calls) == 1

    monkeypatch.setenv("DO_NOT_TRACK", "1")
    assert main(["ci", "add", "self-audit", str(tmp_path / "b")]) == 2
    err = capsys.readouterr().err
    assert "network tier is 0 (DO_NOT_TRACK=1)" in err and "--action-sha" in err
    assert len(calls) == 1 and not (tmp_path / "b").exists()
    assert main(["ci", "add", "self-audit", str(tmp_path / "c"), "--action-sha", _SHA]) == 0
    assert "agentsec network" not in capsys.readouterr().err


def test_ci_add_self_audit_skips_the_lookup_when_it_would_write_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """R1 L4: an existing workflow without --force is "exists, skipped" (exit 1), with no lookup
    and no egress line; an offline machine used to get exit 2 here. --force still looks it up."""
    from agentsec.ci import library
    calls: list[str] = []

    def fail(tag: str) -> str:
        calls.append(tag)
        raise library.ActionPinError("offline; pass `--action-sha <sha>`")

    assert main(["ci", "add", "self-audit", str(tmp_path), "--action-sha", _SHA]) == 0
    before = _self_audit_wf(tmp_path)
    capsys.readouterr()
    monkeypatch.setattr(library, "resolve_action_sha", fail)
    assert main(["ci", "add", "self-audit", str(tmp_path)]) == 1
    out = capsys.readouterr()
    assert "exists, skipped" in out.out and "agentsec network" not in out.err and calls == []
    assert _self_audit_wf(tmp_path) == before
    assert main(["ci", "add", "self-audit", str(tmp_path), "--force"]) == 2  # a real write needs the pin
    assert len(calls) == 1 and _self_audit_wf(tmp_path) == before


@pytest.mark.parametrize("bad", ["mod\nevil: 1", "mod\r", "mod\tx"])
def test_ci_add_refuses_a_path_with_control_characters(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], bad: str,
) -> None:
    """R1 L5: no YAML quoting carries a line break into the rendered `path:` safely."""
    assert main(["ci", "add", "self-audit", str(tmp_path), "--path", bad, "--action-sha", _SHA]) == 2
    assert "--path must not contain control characters" in capsys.readouterr().err
    assert not (tmp_path / ".github").exists()
