from __future__ import annotations

from agentsec.guards.docker_apt_update_not_alone import DockerAptUpdateNotAloneGuard
from tests.guards._common import *  # noqa: F401,F403


def test_docker_apt_update_not_alone_flags_bare_update(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "RUN apt-get update\n"
        "RUN apt-get install -y curl\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    findings = DockerAptUpdateNotAloneGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-apt-update-not-alone/update-without-install"
    assert findings[0].severity == "medium"

def test_docker_apt_update_not_alone_silent_combined(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "RUN apt-get update && apt-get install -y curl\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert DockerAptUpdateNotAloneGuard().run(tmp_path, profile) == []

def test_docker_apt_update_not_alone_silent_combined_multiline(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "RUN apt-get update && \\\n"
        "    apt-get install -y curl && \\\n"
        "    rm -rf /var/lib/apt/lists/*\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert DockerAptUpdateNotAloneGuard().run(tmp_path, profile) == []

def test_docker_apt_update_not_alone_flags_yum(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM centos:8\n"
        "RUN yum update -y\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    findings = DockerAptUpdateNotAloneGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_docker_apt_update_not_alone_silent_no_update(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "RUN pip install requests\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert DockerAptUpdateNotAloneGuard().run(tmp_path, profile) == []

def test_docker_apt_update_not_alone_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "RUN apt-get update  # security: allow-docker-update-not-alone\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert DockerAptUpdateNotAloneGuard().run(tmp_path, profile) == []

def test_docker_apt_update_not_alone_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert DockerAptUpdateNotAloneGuard().applies(profile) is False

def test_docker_apt_update_not_alone_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert DockerAptUpdateNotAloneGuard().applies(profile) is True

def test_docker_install_word_in_echo_still_fires(tmp_path: Path) -> None:
    # A bare "install" in an echo string used to mask a genuine update-only layer (FN); the
    # install verb is now anchored to an actual package-manager call.
    (tmp_path / "Dockerfile").write_text(
        'RUN apt-get update && echo "will install packages later"\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    findings = DockerAptUpdateNotAloneGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-apt-update-not-alone/update-without-install"

def test_docker_real_install_stays_silent(tmp_path: Path) -> None:
    # Control: a real `apt-get install` chained in the same layer must NOT fire.
    (tmp_path / "Dockerfile").write_text(
        "RUN apt-get update && apt-get install -y curl\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert DockerAptUpdateNotAloneGuard().run(tmp_path, profile) == []
