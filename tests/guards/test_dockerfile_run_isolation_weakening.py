from __future__ import annotations

import pytest

from agentsec.guards.dockerfile_run_isolation_weakening import DockerfileRunIsolationWeakeningGuard
from tests.guards._common import *  # noqa: F401,F403


def test_insecure_run_flag_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nRUN --security=insecure apt-get update\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = DockerfileRunIsolationWeakeningGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "dockerfile-run-isolation-weakening/insecure-run-flag"
    assert findings[0].severity == "high"
    assert findings[0].check_id == "dockerfile-run-isolation-weakening"


def test_dangerous_chmod_777_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nRUN chmod -R 0777 /opt/app\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = DockerfileRunIsolationWeakeningGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "dockerfile-run-isolation-weakening/dangerous-chmod"


def test_dangerous_chmod_suid_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nRUN chmod u+s /opt/app/start.sh\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = DockerfileRunIsolationWeakeningGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "dockerfile-run-isolation-weakening/dangerous-chmod"


def test_both_rules_fire_independently_on_separate_run_lines(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "RUN --security=insecure apt-get update\n"
        "RUN chmod -R 0777 /opt/app && chmod u+s /opt/app/start.sh\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = DockerfileRunIsolationWeakeningGuard().run(tmp_path, profile)
    rules = sorted(f.rule for f in findings)
    assert rules == [
        "dockerfile-run-isolation-weakening/dangerous-chmod",
        "dockerfile-run-isolation-weakening/insecure-run-flag",
    ]


def test_ordinary_chmod_stays_silent(tmp_path: Path) -> None:
    # FP-bait: 0o644/0o755-class permissions, the ubiquitous non-alarming case, must not fire.
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nRUN chmod 0755 /opt/app/start.sh\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    assert DockerfileRunIsolationWeakeningGuard().run(tmp_path, profile) == []


def test_ordinary_security_opt_stays_silent(tmp_path: Path) -> None:
    # FP-bait: an unrelated --security-opt flag (a different concern, docker-privileged-flags'
    # own rule) must not be mistaken for --security=insecure.
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nRUN echo building --security-opt=seccomp:unconfined\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"})
    assert DockerfileRunIsolationWeakeningGuard().run(tmp_path, profile) == []


def test_pragma_silences_both_rules(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "# security: allow-dockerfile-run-isolation-weakening\n"
        "RUN --security=insecure apt-get update\n"
        "RUN chmod -R 0777 /opt/app\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"})
    assert DockerfileRunIsolationWeakeningGuard().run(tmp_path, profile) == []


def test_applies_gate(tmp_path: Path) -> None:
    assert DockerfileRunIsolationWeakeningGuard().applies(mkprofile(tmp_path, features={"docker"})) is True
    assert DockerfileRunIsolationWeakeningGuard().applies(mkprofile(tmp_path, features={"python"})) is False


def test_on_continuation_line_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "RUN apt-get update && \\\n"
        "    chmod -R 0777 /opt/app\n",
        encoding="utf-8",
    )
    findings = DockerfileRunIsolationWeakeningGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"}))
    assert len(findings) == 1
    assert findings[0].location.endswith(":2")


@pytest.mark.parametrize(
    "run_line",
    [
        "RUN chmod a+rwx /opt/app",
        "RUN chmod o+w /opt/app/conf",
        "RUN chmod 666 /opt/app/conf",
        "RUN chmod 0666 /opt/app/conf",
        "RUN chmod 4777 /opt/app/start.sh",
        "RUN chmod +s /opt/app/start.sh",
        "RUN chmod ug+s /opt/app/start.sh",
        "RUN chmod --recursive 777 /opt/app",
        "RUN chmod -v -R 0777 /opt/app",
        "RUN chmod -- 777 /opt/app",
        "RUN /bin/chmod 777 /opt/app",
        "RUN find /opt/app -type d -exec chmod 777 {} +",
        'RUN chmod "0777" /opt/app',
    ],
)
def test_dangerous_chmod_forms_beyond_the_source_list_fire(tmp_path: Path, run_line: str) -> None:
    # The mode is decoded instead of matched against cr0hn's literal list, so these forms (all
    # silent before) fire: non-sticky world write in any spelling, SUID/SGID, any flag order.
    (tmp_path / "Dockerfile").write_text(f"FROM debian:bookworm-slim\n{run_line}\n", encoding="utf-8")
    findings = DockerfileRunIsolationWeakeningGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"}))
    assert [f.rule for f in findings] == ["dockerfile-run-isolation-weakening/dangerous-chmod"]


@pytest.mark.parametrize(
    "run_line",
    [
        "RUN chmod 1777 /tmp",
        "RUN chmod 755 /opt/app/start.sh",
        "RUN chmod 0644 /opt/app/conf",
        "RUN chmod 775 /opt/app",
        "RUN chmod +x /opt/app/start.sh",
        "RUN chmod u+x /opt/app/start.sh",
        "RUN chmod go-w /opt/app",
        "RUN chmod a+r /opt/app/conf",
        "RUN chmod -R a+rX /opt/app",
        "RUN chmod +w /opt/app/conf",
        "RUN chmod -w /opt/app/conf",
        "RUN chmod -- 755 /opt/app",
        "RUN chmod --reference=/etc/hosts /opt/app/conf",
        "RUN chmod $MODE /opt/app",
        "RUN echo chmod",
    ],
)
def test_benign_chmod_forms_stay_silent(tmp_path: Path, run_line: str) -> None:
    # FP-bait for the widening above: sticky world-writable /tmp, read/execute grants, removals,
    # an umask-governed `+w`, and operands that are not a mode at all.
    (tmp_path / "Dockerfile").write_text(f"FROM debian:bookworm-slim\n{run_line}\n", encoding="utf-8")
    assert DockerfileRunIsolationWeakeningGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"})) == []


def test_comment_inside_a_continued_run_stays_silent(tmp_path: Path) -> None:
    # Docker drops a comment line inside a continued instruction; it must not be folded in as live.
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "RUN echo hi \\\n"
        "    # chmod 777 /x --security=insecure\n"
        "    && true\n",
        encoding="utf-8",
    )
    assert DockerfileRunIsolationWeakeningGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"})) == []


def test_run_continued_past_a_comment_still_fires_with_line_numbers_kept(tmp_path: Path) -> None:
    # The narrowing's traded direction: the fold continues PAST the dropped comment, so a chmod
    # after it still fires on the RUN's line, and a later RUN keeps its own physical line number.
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "RUN echo hi \\\n"
        "    # widen perms for the dev volume\n"
        "    && chmod 777 /data\n"
        "RUN --security=insecure apt-get update\n",
        encoding="utf-8",
    )
    findings = DockerfileRunIsolationWeakeningGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"}))
    assert sorted((f.rule, f.location) for f in findings) == [
        ("dockerfile-run-isolation-weakening/dangerous-chmod", "Dockerfile:2"),
        ("dockerfile-run-isolation-weakening/insecure-run-flag", "Dockerfile:5"),
    ]


def test_pragma_inside_a_continued_run_still_silences(tmp_path: Path) -> None:
    # Rule 4: dropping in-continuation comments for matching must not void a pragma written there.
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "RUN echo hi \\\n"
        "    # security: allow-dockerfile-run-isolation-weakening\n"
        "    && chmod 777 /data\n",
        encoding="utf-8",
    )
    assert DockerfileRunIsolationWeakeningGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"})) == []
