from __future__ import annotations

from agentsec.guards.git_in_docker import GitInDockerGuard
from tests.guards._common import *  # noqa: F401,F403


def test_git_in_docker_no_dockerignore_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nCOPY . /app\nCMD ["python", "app.py"]\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = GitInDockerGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "git-in-docker/git-not-in-dockerignore"
    assert findings[0].severity == "medium"
    assert findings[0].check_id == "git-in-docker"

def test_git_in_docker_dockerignore_missing_git_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11\nCOPY . /app\n", encoding="utf-8"
    )
    (tmp_path / ".dockerignore").write_text(
        "node_modules\n__pycache__\n*.pyc\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = GitInDockerGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "git-in-docker/git-not-in-dockerignore"

def test_git_in_docker_dockerignore_has_git_silent(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11\nCOPY . /app\n", encoding="utf-8"
    )
    (tmp_path / ".dockerignore").write_text(
        ".git\nnode_modules\n__pycache__\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = GitInDockerGuard().run(tmp_path, profile)
    assert findings == []

def test_git_in_docker_sibling_dockerignore_silent(tmp_path: Path) -> None:
    # T2d precision: a Dockerfile in a subdir with its OWN .dockerignore (containing .git) next to
    # it is covered — checking only the repo root was a false positive on monorepos/nested services.
    svc = tmp_path / "backend_service"
    svc.mkdir()
    (svc / "Dockerfile").write_text("FROM python:3.11\nCOPY . /app\n", encoding="utf-8")  # broad copy
    (svc / ".dockerignore").write_text(".git\n__pycache__\n", encoding="utf-8")
    assert GitInDockerGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []

def test_git_in_docker_scoped_copy_silent(tmp_path: Path) -> None:
    # T2d precision: a Dockerfile that only does SCOPED copies (never `COPY .`) can't include .git,
    # so a missing .dockerignore is harmless — must be silent (the nested-service FP).
    svc = tmp_path / "svc"
    svc.mkdir()
    (svc / "Dockerfile").write_text("FROM python:3.11\nCOPY svc /app\nADD config /etc\n", encoding="utf-8")
    # no .dockerignore at all, but only scoped copies -> no .git exposure
    assert GitInDockerGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []

def test_git_in_docker_sibling_dockerignore_without_git_fires(tmp_path: Path) -> None:
    # ...but a sibling .dockerignore that LACKS .git still fires (no FN).
    svc = tmp_path / "svc"
    svc.mkdir()
    (svc / "Dockerfile").write_text("FROM python:3.11\nCOPY . /app\n", encoding="utf-8")
    (svc / ".dockerignore").write_text("node_modules\n", encoding="utf-8")
    findings = GitInDockerGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1 and findings[0].rule == "git-in-docker/git-not-in-dockerignore"

def test_git_in_docker_variant_dockerfile_names_fire(tmp_path: Path) -> None:
    # Regression (#422 S12): Dockerfile.<x> and *.dockerfile variants must be scanned like
    # the exact-name Dockerfile (base.py::iter_dockerfiles, used by every other docker guard).
    (tmp_path / "Dockerfile.prod").write_text(
        "FROM python:3.11\nCOPY . /app\n", encoding="utf-8"
    )
    (tmp_path / "app.dockerfile").write_text(
        "FROM python:3.11\nCOPY . /app\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = GitInDockerGuard().run(tmp_path, profile)
    assert len(findings) == 2
    assert {f.rule for f in findings} == {"git-in-docker/git-not-in-dockerignore"}

def test_git_in_docker_no_dockerfile_silent(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"})
    findings = GitInDockerGuard().run(tmp_path, profile)
    assert findings == []

def test_git_in_docker_copy_git_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11\nCOPY .git /app/.git\nCOPY . /app\n", encoding="utf-8"
    )
    (tmp_path / ".dockerignore").write_text(".git\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"})
    findings = GitInDockerGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "git-in-docker/git-not-in-dockerignore"
    assert "COPY .git" in findings[0].message or "COPY" in findings[0].message

def test_git_in_docker_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11\n# security: allow-git-in-docker\nCOPY . /app\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = GitInDockerGuard().run(tmp_path, profile)
    assert findings == []

def test_git_in_docker_pragma_in_dockerignore_silences(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11\nCOPY . /app\n", encoding="utf-8"
    )
    (tmp_path / ".dockerignore").write_text(
        "# security: allow-git-in-docker\nnode_modules\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = GitInDockerGuard().run(tmp_path, profile)
    assert findings == []

def test_git_in_docker_applies_always(tmp_path: Path) -> None:
    profile_empty = mkprofile(tmp_path, features=set())
    profile_python = mkprofile(tmp_path, features={"python", "fastapi"})
    assert GitInDockerGuard().applies(profile_empty) is True
    assert GitInDockerGuard().applies(profile_python) is True

def test_git_in_docker_trailing_slash_silent(tmp_path: Path) -> None:
    # Precision fix: '.git/' (with trailing slash) in .dockerignore is functionally
    # equivalent to '.git' — Docker normalizes trailing slashes. Some editors and
    # tools generate the slash form. This must suppress the finding.
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nCOPY . /app\n", encoding="utf-8")
    (tmp_path / ".dockerignore").write_text(".git/\n__pycache__\n", encoding="utf-8")
    findings = GitInDockerGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert findings == []



def test_git_in_docker_pragma_quoted_in_a_label_does_not_suppress(tmp_path: Path) -> None:
    # #424 E2: the documented form inside a quoted LABEL value is instruction content, not a
    # comment; the two tests above keep the Dockerfile and .dockerignore comment forms working.
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.11\nLABEL help="opt out with # security: allow-git-in-docker"\nCOPY . /app\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = GitInDockerGuard().run(tmp_path, profile)
    assert [f.rule for f in findings] == ["git-in-docker/git-not-in-dockerignore"]
