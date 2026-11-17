from __future__ import annotations

import pytest

from agentsec.guards.docker_nonroot_user import DockerNonrootUserGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def test_docker_nonroot_user_no_user_instruction_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.12-slim\nCOPY . /app\nCMD ["python", "app.py"]\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerNonrootUserGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-nonroot-user/no-user-instruction"
    assert findings[0].severity == "medium"
    assert findings[0].check_id == "docker-nonroot-user"


def test_docker_nonroot_user_last_user_root_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nUSER appuser\nRUN echo build-step\nUSER root\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerNonrootUserGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-nonroot-user/last-user-root"
    assert findings[0].severity == "high"


def test_docker_nonroot_user_uid_zero_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nUSER 0\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerNonrootUserGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-nonroot-user/last-user-root"


def test_docker_nonroot_user_switched_to_nonroot_silent(tmp_path: Path) -> None:
    # FP-bait: an earlier root USER (for setup) followed by a final non-root USER is fine —
    # Docker uses only the LAST USER in effect at runtime.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "USER root\n"
        "RUN apt-get update && apt-get install -y curl\n"
        "RUN useradd -m appuser\n"
        "USER appuser\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerNonrootUserGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_nonroot_user_group_suffix_root_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\nUSER root:root\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerNonrootUserGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-nonroot-user/last-user-root"


def test_docker_nonroot_user_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n# security: allow-root-container\nUSER root\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerNonrootUserGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_nonroot_user_no_dockerfile_silent(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerNonrootUserGuard().run(tmp_path, profile)
    assert findings == []


def test_docker_nonroot_user_applies_always(tmp_path: Path) -> None:
    profile_empty = mkprofile(tmp_path, features=set())
    profile_python = mkprofile(tmp_path, features={"python", "fastapi"})
    assert DockerNonrootUserGuard().applies(profile_empty) is True
    assert DockerNonrootUserGuard().applies(profile_python) is True


# ---------------------------------------------------------------------------
# #697: an ordinary multi-line Dockerfile must not cost quadratic time
#
# This guard sits downstream of BOTH halves of #697 and is the end-to-end net for them:
#   1. `join_dockerfile_continuations` rebuilt its whole accumulated line per fold (quadratic in
#      folds x line length, and regex-independent);
#   2. `_USER_INSTRUCTION` anchored with `^\s*`, which under re.MULTILINE re-anchors at every line
#      of the blank run that same joiner emits to keep line numbers stable.
# The fixture is deliberately ORDINARY: one idiomatic `RUN ... && \` chain, nothing hostile. Note
# the ~20-char continuation lines — the 2-char `" \"` line used elsewhere keeps the joined line
# short enough to mask defect 1 entirely.
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_docker_nonroot_user_multiline_run_stays_linear(tmp_path: Path) -> None:
    # Four sizes, not three: `classify`'s median only discards an outlier from THREE ratios up
    # (at two it is their mean, which is #758). The fourth size extends the TOP, where this
    # workload is cheap enough that the extra step costs single-digit milliseconds.
    sizes = [500, 2000, 8000, 32000]
    roots = {}
    for n in sizes:
        root = tmp_path / f"n{n}"
        root.mkdir()
        body = "".join(f"  && echo step{i} \\\n" for i in range(n))
        (root / "Dockerfile").write_text(
            "FROM python:3.12-slim\nRUN apt-get update \\\n" + body + "  && true\n",
            encoding="utf-8",
        )
        roots[n] = root

    found: dict[int, list[str]] = {}

    def scan(n: int) -> None:
        found[n] = [f.rule for f in DockerNonrootUserGuard().run(roots[n], mkprofile(roots[n], features={"python"}))]

    assert_growth(scan, sizes, expected="linear")
    # No USER instruction anywhere, so the guard must still fire at every size. A guard that
    # stopped scanning would be fast AND silent, which is the failure that presents as success.
    assert all(found[n] == ["docker-nonroot-user/no-user-instruction"] for n in sizes), found


def test_docker_nonroot_user_accepts_an_indented_user_instruction(tmp_path: Path) -> None:
    """Rule 1: `[^\\S\\n]*` keeps the FULL same-line whitespace vocabulary — space, tab, and the
    NBSP that ruled out `[ \\t]*` on the #696 round — and only stops crossing newlines."""
    for indent in ("", "  ", "\t", " "):
        root = tmp_path / f"i{len(indent)}{ord(indent[0]) if indent else 0}"
        root.mkdir()
        (root / "Dockerfile").write_text(
            f"FROM python:3.12-slim\n{indent}USER appuser\n", encoding="utf-8"
        )
        findings = DockerNonrootUserGuard().run(root, mkprofile(root, features={"python"}))
        assert findings == [], f"indent {indent!r} stopped registering the USER instruction"


def test_docker_nonroot_user_reports_the_user_line_not_a_blank_above_it(tmp_path: Path) -> None:
    """A side benefit of the conversion, worth pinning: with `^\\s*` a match could BEGIN on a blank
    line above the instruction, so the reported line number pointed at the blank. It no longer can."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n\n\n\nUSER root\n", encoding="utf-8"
    )
    findings = DockerNonrootUserGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}))
    assert len(findings) == 1
    assert findings[0].location.endswith(":5"), findings[0].location


def test_docker_nonroot_user_pragma_quoted_in_an_env_value_does_not_suppress(tmp_path: Path) -> None:
    # #424 E2: the documented `# security: …` form inside a quoted ENV value is instruction
    # content, not a Dockerfile comment — only a real `#` comment line (the test above) opts out.
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.12-slim\nENV HELP="opt out with # security: allow-root-container"\nUSER root\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = DockerNonrootUserGuard().run(tmp_path, profile)
    assert [f.rule for f in findings] == ["docker-nonroot-user/last-user-root"]
