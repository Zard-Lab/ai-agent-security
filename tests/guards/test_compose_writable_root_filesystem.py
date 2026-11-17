"""Tests for the compose-writable-root-filesystem guard (§6c)."""
from __future__ import annotations

from agentsec.guards.compose_writable_root_filesystem import ComposeWritableRootFilesystemGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-writable-root-filesystem/read-only-missing"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeWritableRootFilesystemGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str, name: str = "docker-compose.yml") -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")


# ── fires ─────────────────────────────────────────────────────────────────────

def test_no_read_only_at_all_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n")
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "medium"
    assert match.check_id == "compose-writable-root-filesystem"


def test_explicit_read_only_false_fires(tmp_path: Path) -> None:
    """An explicit opt-out is the same runtime outcome as leaving it unset — must fire."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    read_only: false\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_commented_out_read_only_still_fires(tmp_path: Path) -> None:
    """Indirect/bypass case: a commented-out `# read_only: true` must not be mistaken
    for a real directive."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    # read_only: true\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_multiple_services_each_evaluated(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n"
        "  app:\n    image: alpine\n"
        "  worker:\n    image: alpine\n",
    )
    assert len([f for f in _run(tmp_path) if f.rule == _RULE]) == 2


# ── silent (FP-bait) ────────────────────────────────────────────────────────────

def test_read_only_true_silent(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    read_only: true\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_read_only_true_case_insensitive_silent(tmp_path: Path) -> None:
    """Indirect case that must NOT fire: a differently-cased boolean is still true."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    read_only: True\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_read_only_true_quoted_silent(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    read_only: \"true\"\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-writable-container-rootfs\n"
        "services:\n  app:\n    image: alpine\n",
    )
    assert _run(tmp_path) == []


def test_dev_compose_out_of_scope(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n", name="docker-compose.dev.yml")
    assert _run(tmp_path) == []


# ── applies() gate ──────────────────────────────────────────────────────────────

def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert ComposeWritableRootFilesystemGuard().applies(profile) is False


def test_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert ComposeWritableRootFilesystemGuard().applies(profile) is True


def test_no_compose_silent(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert _run(tmp_path) == []
