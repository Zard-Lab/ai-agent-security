from __future__ import annotations

import pytest

from agentsec.guards.build_secret import BuildSecretGuard
from agentsec.guards.dockerfile_credential_in_instruction import DockerfileCredentialInInstructionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_registry_auth_exposure_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nRUN docker login -u admin -p hunter2hunter2\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = DockerfileCredentialInInstructionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "dockerfile-credential-in-instruction/registry-auth-exposure"
    assert findings[0].severity == "high"
    assert findings[0].check_id == "dockerfile-credential-in-instruction"


def test_docker_password_env_is_build_secrets_job_not_this_guards(tmp_path: Path) -> None:
    # FP-bait: an `ENV DOCKER_PASSWORD=...` assignment is already `build-secret/secret-build-arg`'s
    # job (any secret-shaped ARG/ENV name, PASSWORD included) — this guard staying silent on it
    # is deliberate, not a miss. Firing a second rule on the same line under a different id would
    # let it bypass a user's existing `build-secret` suppression for that line (Dean's review,
    # review). Both guards run against the same fixture to prove the line is covered, just by
    # the other guard.
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nENV DOCKER_PASSWORD=hunter2hunter2\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    assert DockerfileCredentialInInstructionGuard().run(tmp_path, profile) == []
    build_secret_findings = BuildSecretGuard().run(tmp_path, profile)
    assert len(build_secret_findings) == 1
    assert build_secret_findings[0].rule == "build-secret/secret-build-arg"


def test_run_inline_password_assignment_still_fires(tmp_path: Path) -> None:
    # A RUN-prefixed inline env assignment (`RUN DOCKER_PASSWORD=x ./deploy.sh`) is NOT an
    # ARG/ENV instruction, so build-secret's `_DOCKER_ARG_ENV` (anchored on the instruction
    # keyword) never sees it — this guard still needs to catch it directly, no duplication.
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nRUN DOCKER_PASSWORD=hunter2hunter2 ./deploy.sh\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = DockerfileCredentialInInstructionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "dockerfile-credential-in-instruction/registry-auth-exposure"
    assert BuildSecretGuard().run(tmp_path, profile) == []


def test_dockerconfigjson_reference_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nRUN cat /kaniko/.dockerconfigjson\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = DockerfileCredentialInInstructionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "dockerfile-credential-in-instruction/registry-auth-exposure"


def test_healthcheck_token_in_url_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        'HEALTHCHECK --interval=5m CMD curl -f "http://localhost/health?token=abc123" || exit 1\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = DockerfileCredentialInInstructionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "dockerfile-credential-in-instruction/healthcheck-credential"


def test_healthcheck_bearer_header_fires(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        'HEALTHCHECK CMD curl -f http://localhost/ -H "Authorization: Bearer abcdef12345678" || exit 1\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = DockerfileCredentialInInstructionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "dockerfile-credential-in-instruction/healthcheck-credential"


def test_password_stdin_is_the_safe_form_and_stays_silent(tmp_path: Path) -> None:
    # FP-bait: `--password-stdin` reads the value from stdin, never argv/build history — the
    # documented-recommended safe form (Dean's review). Must not fire.
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "RUN --mount=type=secret,id=registry_pw cat /run/secrets/registry_pw | "
        "docker login -u admin --password-stdin registry.example.com\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"})
    assert DockerfileCredentialInInstructionGuard().run(tmp_path, profile) == []


def test_commented_out_registry_login_stays_silent(tmp_path: Path) -> None:
    # FP-bait: a commented-out instruction is not a real finding (Dean's review) —
    # unlike healthcheck-credential and dangerous-chmod/insecure-run-flag, this rule isn't
    # anchored to an instruction keyword at the start of the line, so it needs its own check.
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "# RUN docker login -u admin -p hunter2hunter2\n"
        "# DOCKER_PASSWORD=hunter2hunter2\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"})
    assert DockerfileCredentialInInstructionGuard().run(tmp_path, profile) == []


def test_ordinary_docker_login_without_password_flag_silent(tmp_path: Path) -> None:
    # FP-bait: `docker login` with no -p/--password flag at all (interactive prompt, or a
    # credential helper) must not fire.
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nRUN docker login registry.example.com\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    assert DockerfileCredentialInInstructionGuard().run(tmp_path, profile) == []


def test_ordinary_healthcheck_without_credential_silent(tmp_path: Path) -> None:
    # FP-bait: a plain, unauthenticated health endpoint must not fire.
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nHEALTHCHECK CMD curl -f http://localhost/health || exit 1\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"})
    assert DockerfileCredentialInInstructionGuard().run(tmp_path, profile) == []


def test_pragma_silences_both_rules(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\n"
        "# security: allow-dockerfile-credential-in-instruction\n"
        "RUN docker login -u admin -p hunter2hunter2\n"
        'HEALTHCHECK CMD curl -f "http://localhost/health?token=abc123" || exit 1\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"})
    assert DockerfileCredentialInInstructionGuard().run(tmp_path, profile) == []


def test_applies_gate(tmp_path: Path) -> None:
    assert DockerfileCredentialInInstructionGuard().applies(mkprofile(tmp_path, features={"docker"})) is True
    assert DockerfileCredentialInInstructionGuard().applies(mkprofile(tmp_path, features={"python"})) is False


def _registry_rules(tmp_path: Path, body: str) -> list[str]:
    (tmp_path / "Dockerfile").write_text("FROM debian:bookworm-slim\n" + body, encoding="utf-8")
    findings = DockerfileCredentialInInstructionGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"}))
    return [f.rule for f in findings]


@pytest.mark.parametrize(
    "line",
    [
        "RUN docker login -u admin --password hunter2hunter2\n",
        "RUN docker login -u admin --password=hunter2hunter2\n",
    ],
)
def test_long_password_flag_still_fires(tmp_path: Path, line: str) -> None:
    # Pins the `(?!-stdin\b)` narrowing's traded direction: the long flag with a value still fires.
    assert _registry_rules(tmp_path, line) == ["dockerfile-credential-in-instruction/registry-auth-exposure"]


def test_dockerconfigjson_on_an_env_line_still_fires(tmp_path: Path) -> None:
    # The ARG/ENV skip covers only the `DOCKER_PASSWORD=` assignment (build-secret's job, keyed on
    # the NAME). A `.dockerconfigjson` value under an innocuous name is not build-secret's, so it
    # must still fire here, and build-secret must stay silent on it (no double report).
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nENV DOCKER_CONFIG_FILE=/root/.dockerconfigjson\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = DockerfileCredentialInInstructionGuard().run(tmp_path, profile)
    assert [f.rule for f in findings] == ["dockerfile-credential-in-instruction/registry-auth-exposure"]
    assert BuildSecretGuard().run(tmp_path, profile) == []


def test_comment_inside_a_continued_run_stays_silent(tmp_path: Path) -> None:
    # Docker drops a comment line inside a continued instruction; it must not be folded in as live.
    body = "RUN docker build . \\\n    # docker login -p hunter2hunter2\n    && true\n"
    assert _registry_rules(tmp_path, body) == []


def test_login_after_a_comment_in_a_continued_run_still_fires(tmp_path: Path) -> None:
    # The narrowing's traded direction: the fold continues past the dropped comment.
    body = "RUN apt-get update \\\n    # log in to push\n    && docker login -u ci -p hunter2hunter2\n"
    assert _registry_rules(tmp_path, body) == ["dockerfile-credential-in-instruction/registry-auth-exposure"]


@pytest.mark.parametrize(
    "probe",
    [
        "curl -f -u admin:hunter2 http://localhost/",
        "curl -f --user=admin:hunter2 http://localhost/",
        'curl -f --user "admin:hunter2" http://localhost/',
        "curl -f http://admin:hunter2@localhost:8080/health",
        "redis-cli -u redis://default:hunter2@localhost:6379 ping",
    ],
)
def test_healthcheck_basic_auth_pair_fires(tmp_path: Path, probe: str) -> None:
    rules = _registry_rules(tmp_path, f"HEALTHCHECK CMD {probe} || exit 1\n")
    assert rules == ["dockerfile-credential-in-instruction/healthcheck-credential"]


@pytest.mark.parametrize(
    "probe",
    [
        "curl -f -u admin http://localhost/",
        "curl -f --user-agent probe:1 http://localhost/",
        "curl -f http://localhost:8080/health",
        "curl -f http://probe@localhost/health",
        "wget -q -O- http://[::1]:8080/health",
        "redis-cli -u redis://localhost:6379 ping",
        "redis-cli --user=default -u redis://cache:6379/0 ping",
    ],
)
def test_healthcheck_without_a_password_half_stays_silent(tmp_path: Path, probe: str) -> None:
    # FP-bait for the -u/--user and userinfo widening: no colon-separated password, no finding.
    assert _registry_rules(tmp_path, f"HEALTHCHECK CMD {probe} || exit 1\n") == []
