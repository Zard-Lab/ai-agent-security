from __future__ import annotations

from agentsec.guards.docker_add_misuse import DockerAddMisuseGuard
from tests.guards._common import *  # noqa: F401,F403


def test_docker_add_misuse_local_archive_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nADD app.tar.gz /app\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerAddMisuseGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-add-misuse/add-local-archive"
    assert findings[0].severity == "medium"
    assert findings[0].check_id == "docker-add-misuse"


def test_docker_add_misuse_remote_url_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nADD https://example.com/install.sh /tmp/install.sh\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerAddMisuseGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-add-misuse/add-remote-url"


def test_docker_add_misuse_json_array_url_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.12-slim\nADD ["https://example.com/x.sh", "/tmp/x.sh"]\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerAddMisuseGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-add-misuse/add-remote-url"


def test_docker_add_misuse_plain_file_silent(tmp_path: Path) -> None:
    # FP-bait: ADD of an ordinary source file (not an archive, not a URL) is a normal,
    # harmless use of ADD.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nADD app.py /app/app.py\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerAddMisuseGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_add_misuse_copy_of_tar_silent(tmp_path: Path) -> None:
    # FP-bait: COPY (not ADD) of a .tar file never auto-extracts — must stay silent.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nCOPY app.tar.gz /app\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerAddMisuseGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_add_misuse_directory_silent(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nADD mydir /app/mydir\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerAddMisuseGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_add_misuse_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "# security: allow-docker-add\n"
        "ADD app.tar.gz /app\n"
        "ADD https://example.com/x.sh /tmp/x.sh\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerAddMisuseGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_add_misuse_applies_always(tmp_path: Path) -> None:
    profile_empty = mkprofile(tmp_path, features=set())
    assert DockerAddMisuseGuard().applies(profile_empty) is True


def test_docker_add_misuse_on_continuation_line_fires(tmp_path: Path) -> None:
    # Regression (PR #397 review #3): the archive source on a backslash line-continuation of
    # the ADD instruction must be scanned (was silently missed pre-fix).
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nADD \\\n    app.tar.gz /app/\n", encoding="utf-8"
    )
    findings = DockerAddMisuseGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1
    assert findings[0].location.endswith(":2")
