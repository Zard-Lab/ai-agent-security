from __future__ import annotations

from agentsec.guards.docker_expose_ssh import DockerExposeSshGuard
from tests.guards._common import *  # noqa: F401,F403


def test_docker_expose_ssh_bare_port_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nEXPOSE 22\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerExposeSshGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-expose-ssh/ssh-port-exposed"
    assert findings[0].severity == "medium"
    assert findings[0].check_id == "docker-expose-ssh"


def test_docker_expose_ssh_protocol_suffix_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nEXPOSE 22/tcp\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerExposeSshGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_docker_expose_ssh_multi_port_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nEXPOSE 8080 443 22\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerExposeSshGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_docker_expose_ssh_substring_2200_silent(tmp_path: Path) -> None:
    # FP-bait: the terrascan source rule naively substring-matches "22" and would fire on
    # 2200/8220 — this guard parses exact port numbers instead, so it must stay silent.
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nEXPOSE 2200\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerExposeSshGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_expose_ssh_substring_8220_silent(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nEXPOSE 8220\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerExposeSshGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_expose_ssh_normal_port_silent(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nEXPOSE 8080\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerExposeSshGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_expose_ssh_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\n# security: allow-ssh-expose\nEXPOSE 22\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerExposeSshGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_expose_ssh_applies_always(tmp_path: Path) -> None:
    profile_empty = mkprofile(tmp_path, features=set())
    assert DockerExposeSshGuard().applies(profile_empty) is True


def test_docker_expose_ssh_on_continuation_line_fires(tmp_path: Path) -> None:
    # Regression (PR #397 review #3): a port 22 that lands on a backslash line-continuation of
    # a multi-port EXPOSE must fire (was silently missed pre-fix).
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:22.04\nEXPOSE 8000 \\\n    22\n", encoding="utf-8"
    )
    findings = DockerExposeSshGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1
    assert findings[0].location.endswith(":2")
