"""Tests for the compose-image-digest-missing guard (§5)."""
from __future__ import annotations

from agentsec.guards.compose_image_digest_missing import ComposeImageDigestMissingGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-image-digest-missing/tag-not-digest"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeImageDigestMissingGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str) -> None:
    (tmp_path / "docker-compose.yml").write_text(body, encoding="utf-8")


def test_versioned_tag_without_digest_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: myapp:1.4.2\n")
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "medium"


def test_digest_pinned_silent(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: myapp:1.4.2@sha256:" + "a" * 64 + "\n")
    assert _run(tmp_path) == []


def test_latest_tag_out_of_scope(tmp_path: Path) -> None:
    """FP-bait: :latest is docker-latest-base-tag's territory, not this guard's."""
    _compose(tmp_path, "services:\n  app:\n    image: myapp:latest\n")
    assert _run(tmp_path) == []


def test_no_tag_out_of_scope(tmp_path: Path) -> None:
    """FP-bait: no tag at all defaults to :latest — also docker-latest-base-tag's territory."""
    _compose(tmp_path, "services:\n  app:\n    image: myapp\n")
    assert _run(tmp_path) == []


def test_registry_with_port_not_mistaken_for_tag(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: registry:5000/myapp\n")
    assert _run(tmp_path) == []


def test_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-compose-image-digest\nservices:\n  app:\n    image: myapp:1.4.2\n",
    )
    assert _run(tmp_path) == []


def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert ComposeImageDigestMissingGuard().applies(profile) is False


def test_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert ComposeImageDigestMissingGuard().applies(profile) is True
