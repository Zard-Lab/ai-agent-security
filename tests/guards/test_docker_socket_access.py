from __future__ import annotations

from agentsec.guards.docker_socket_access import DockerSocketAccessGuard
from tests.guards._common import *  # noqa: F401,F403


def test_docker_socket_access_flags_socket_path(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  builder:\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = DockerSocketAccessGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-socket-access/socket-reference"
    assert findings[0].severity == "high"

def test_docker_socket_access_flags_docker_from_env(tmp_path: Path) -> None:
    (tmp_path / "agent_tool.py").write_text(
        "client = docker.from_env()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = DockerSocketAccessGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_docker_socket_access_flags_docker_client_ctor(tmp_path: Path) -> None:
    (tmp_path / "agent_tool.py").write_text(
        'client = DockerClient(base_url="unix:///var/run/docker.sock")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = DockerSocketAccessGuard().run(tmp_path, profile)
    assert len(findings) >= 1

def test_docker_socket_access_silent_unrelated_code(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "client = SomeOtherClient()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert DockerSocketAccessGuard().run(tmp_path, profile) == []

def test_docker_socket_access_silent_comment(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "# We deliberately do NOT use docker.from_env() here\n"
        "x = 1\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert DockerSocketAccessGuard().run(tmp_path, profile) == []

def test_docker_socket_access_pragma_silences(tmp_path: Path) -> None:
    content = (
        "# security: allow-docker-socket\n"
        "client = docker.from_env()\n"
    )
    (tmp_path / "ci_runner.py").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert DockerSocketAccessGuard().run(tmp_path, profile) == []

def test_docker_socket_access_covers_compose_only_repo(tmp_path: Path) -> None:
    # Regression (PR #393 review #1, same mis-gating class): a compose-only repo (no `python`
    # feature) still has its docker.sock bind-mount flagged now that the guard is universal.
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  builder:\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"})
    assert DockerSocketAccessGuard().applies(profile) is True
    assert len(DockerSocketAccessGuard().run(tmp_path, profile)) == 1

def test_docker_socket_access_skips_nonproduct_path(tmp_path: Path) -> None:
    # Regression (PR #393 review #2): a docker.from_env() in a test file is skipped.
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_client.py").write_text("client = docker.from_env()\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert DockerSocketAccessGuard().run(tmp_path, profile) == []

def test_docker_socket_access_applies_universally() -> None:
    # Universal guard: docker.sock references can appear in any stack.
    assert DockerSocketAccessGuard().applies(mkprofile(Path("/tmp"), features={"java"})) is True
    assert DockerSocketAccessGuard().applies(mkprofile(Path("/tmp"), features=set())) is True
