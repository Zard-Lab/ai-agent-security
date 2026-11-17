from __future__ import annotations

from agentsec.guards.docker_run_sudo import DockerRunSudoGuard
from tests.guards._common import *  # noqa: F401,F403


def test_docker_run_sudo_leading_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nRUN sudo apt-get update\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerRunSudoGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-run-sudo/sudo-invocation"
    assert findings[0].severity == "medium"
    assert findings[0].check_id == "docker-run-sudo"


def test_docker_run_sudo_after_and_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nRUN apt-get update && sudo apt-get install -y foo\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerRunSudoGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-run-sudo/sudo-invocation"


def test_docker_run_sudo_after_semicolon_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nRUN apt-get update; sudo apt-get install -y foo\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerRunSudoGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_docker_run_sudo_exec_array_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM ubuntu:22.04\nRUN ["sudo", "apt-get", "update"]\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerRunSudoGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_docker_run_sudo_no_sudo_silent(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y foo\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerRunSudoGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_run_sudo_word_boundary_silent(tmp_path: Path) -> None:
    # FP-bait: a package literally named "pseudo-package" must not match "sudo".
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nRUN apt-get install -y pseudo-package\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerRunSudoGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_run_sudo_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\n# security: allow-sudo-in-docker\nRUN sudo apt-get update\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerRunSudoGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_run_sudo_applies_always(tmp_path: Path) -> None:
    profile_empty = mkprofile(tmp_path, features=set())
    assert DockerRunSudoGuard().applies(profile_empty) is True


def test_docker_run_sudo_on_continuation_line_fires(tmp_path: Path) -> None:
    # Regression (PR #397 review #3): `sudo` on a backslash line-continuation of a multi-line
    # RUN chain — the commonest real RUN shape — must fire (was silently missed before the
    # shared join_dockerfile_continuations helper).
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\n"
        "RUN apt-get update && \\\n"
        "    sudo apt-get install -y curl\n",
        encoding="utf-8",
    )
    findings = DockerRunSudoGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1
    assert findings[0].location.endswith(":2")  # reported on the RUN's starting line
