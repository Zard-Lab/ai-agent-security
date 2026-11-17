from __future__ import annotations

import pytest

from agentsec.guards.dockerfile_workdir_sensitive_path import DockerfileWorkdirSensitivePathGuard
from tests.guards._common import *  # noqa: F401,F403


def test_sensitive_workdir_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nWORKDIR /root\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = DockerfileWorkdirSensitivePathGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "dockerfile-workdir-sensitive-path/sensitive-workdir"
    assert findings[0].severity == "medium"
    assert findings[0].check_id == "dockerfile-workdir-sensitive-path"


def test_bare_root_workdir_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nWORKDIR /\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = DockerfileWorkdirSensitivePathGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_etc_workdir_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nWORKDIR /etc\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = DockerfileWorkdirSensitivePathGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_app_workdir_stays_silent(tmp_path: Path) -> None:
    # FP-bait: the ordinary, overwhelmingly common case.
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nWORKDIR /app\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    assert DockerfileWorkdirSensitivePathGuard().run(tmp_path, profile) == []


def test_etc_subdirectory_stays_silent(tmp_path: Path) -> None:
    # FP-bait: a subdirectory of a sensitive path (/etc/myapp) is NOT the bare system
    # directory itself, mirroring the source rule's own anchoring.
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nWORKDIR /etc/myapp\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    assert DockerfileWorkdirSensitivePathGuard().run(tmp_path, profile) == []


def test_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "# security: allow-dockerfile-workdir-sensitive-path\n"
        "WORKDIR /root\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"})
    assert DockerfileWorkdirSensitivePathGuard().run(tmp_path, profile) == []


def test_applies_gate(tmp_path: Path) -> None:
    assert DockerfileWorkdirSensitivePathGuard().applies(mkprofile(tmp_path, features={"docker"})) is True
    assert DockerfileWorkdirSensitivePathGuard().applies(mkprofile(tmp_path, features={"python"})) is False


@pytest.mark.parametrize("workdir", ['"/root"', "/root/", "'/etc/'", '"/"', "/usr/"])
def test_quoted_or_trailing_slash_sensitive_workdir_fires(tmp_path: Path, workdir: str) -> None:
    # Docker resolves these to the bare system directory, so they fire like the unquoted form.
    (tmp_path / "Dockerfile").write_text(f"FROM debian:bookworm-slim\nWORKDIR {workdir}\n", encoding="utf-8")
    findings = DockerfileWorkdirSensitivePathGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"}))
    assert [(f.rule, f.severity) for f in findings] == [("dockerfile-workdir-sensitive-path/sensitive-workdir", "medium")]


@pytest.mark.parametrize("workdir", ['"/app"', "/rootfs", "/root/app", "'/etc/myapp/'", '"/root', "/usr/src/app/"])
def test_quoted_or_slashed_ordinary_workdir_stays_silent(tmp_path: Path, workdir: str) -> None:
    # FP-bait for the quote/slash widening: a different directory, a subdirectory, and an
    # unbalanced quote all stay silent.
    (tmp_path / "Dockerfile").write_text(f"FROM debian:bookworm-slim\nWORKDIR {workdir}\n", encoding="utf-8")
    assert DockerfileWorkdirSensitivePathGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"})) == []
