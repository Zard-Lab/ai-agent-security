"""Tests for the compose-user-directive-missing guard (§6c)."""
from __future__ import annotations

from agentsec.guards.compose_user_directive_missing import ComposeUserDirectiveMissingGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-user-directive-missing/no-user-directive"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeUserDirectiveMissingGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str, name: str = "docker-compose.yml") -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")


def _dockerfile(tmp_path: Path, relpath: str, body: str) -> None:
    dst = tmp_path / relpath
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(body, encoding="utf-8")


# ── fires ─────────────────────────────────────────────────────────────────────

def test_no_user_directive_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n")
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "medium"
    assert match.check_id == "compose-user-directive-missing"


def test_commented_out_user_still_fires(tmp_path: Path) -> None:
    """Indirect/bypass case: a commented-out `# user: appuser` must not be mistaken
    for a real directive."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    # user: appuser\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_environment_user_var_does_not_suppress(tmp_path: Path) -> None:
    """Indirect/bypass case: an environment variable literally named USER must not be
    mistaken for the compose `user:` service field."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n      - USER=root\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_multiple_services_each_evaluated(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n"
        "  app:\n    image: alpine\n"
        "  worker:\n    image: alpine\n",
    )
    assert len([f for f in _run(tmp_path) if f.rule == _RULE]) == 2


# ── silent (FP-bait) ────────────────────────────────────────────────────────────

def test_user_directive_present_silent(tmp_path: Path) -> None:
    _compose(tmp_path, 'services:\n  app:\n    image: alpine\n    user: "1000:1000"\n')
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_user_directive_named_user_silent(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    user: appuser\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_similarly_named_key_does_not_suppress_or_falsely_count(tmp_path: Path) -> None:
    """FP-bait for the OPPOSITE direction: a key merely ENDING in 'user' (not the
    literal `user:` field) must not be mistaken for the real directive either."""
    _compose(
        tmp_path,
        "services:\n  db:\n    image: postgres\n    environment:\n      - POSTGRES_USER=admin\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-compose-root-user\n"
        "services:\n  app:\n    image: alpine\n",
    )
    assert _run(tmp_path) == []


def test_dev_compose_out_of_scope(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n", name="docker-compose.dev.yml")
    assert _run(tmp_path) == []


# ── applies() gate ──────────────────────────────────────────────────────────────

def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert ComposeUserDirectiveMissingGuard().applies(profile) is False


def test_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert ComposeUserDirectiveMissingGuard().applies(profile) is True


def test_no_compose_silent(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert _run(tmp_path) == []


# ── #804: build-context Dockerfile resolution ──────────────────────────────────
# Narrowing (a new suppression): a `build:` service whose resolved Dockerfile's FINAL stage
# drops to a non-root USER is no longer a finding. Every case below is paired with a
# negative-control test proving the vulnerable/uncertain shape still fires (review Rule 1).

def test_build_short_form_nonroot_dockerfile_silent(tmp_path: Path) -> None:
    """FP fix: `build: ./svc` -> svc/Dockerfile ending on `USER appuser` stays silent."""
    _compose(tmp_path, "services:\n  app:\n    build: ./svc\n")
    _dockerfile(tmp_path, "svc/Dockerfile", "FROM python:3.11-slim\nRUN adduser appuser\nUSER appuser\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_build_long_form_custom_dockerfile_nonroot_silent(tmp_path: Path) -> None:
    """FP fix: long-form `build:` with `context:` + custom `dockerfile:` resolves and stays silent."""
    _compose(
        tmp_path,
        "services:\n  app:\n    build:\n      context: ./svc\n      dockerfile: Custom.Dockerfile\n",
    )
    _dockerfile(tmp_path, "svc/Custom.Dockerfile", "FROM python:3.11-slim\nUSER appuser\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_multistage_final_stage_nonroot_silent(tmp_path: Path) -> None:
    """FP fix (the flagship frontend shape): a multi-stage Dockerfile whose FINAL stage sets a
    non-root USER stays silent."""
    _compose(tmp_path, "services:\n  frontend:\n    build: ./frontend\n")
    _dockerfile(
        tmp_path,
        "frontend/Dockerfile",
        "FROM node:18-alpine as builder\nRUN echo build\n"
        "FROM nginx:alpine\nRUN adduser -S appuser\nUSER appuser\n",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_build_context_dockerfile_no_user_still_fires(tmp_path: Path) -> None:
    """Negative control: a build Dockerfile with NO `USER` at all must still fire."""
    _compose(tmp_path, "services:\n  app:\n    build: ./svc\n")
    _dockerfile(tmp_path, "svc/Dockerfile", "FROM python:3.11-slim\nRUN echo hi\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_build_context_dockerfile_last_user_root_still_fires(tmp_path: Path) -> None:
    """Negative control: last-USER-wins — a Dockerfile ending on `USER root` must still fire."""
    _compose(tmp_path, "services:\n  app:\n    build: ./svc\n")
    _dockerfile(tmp_path, "svc/Dockerfile", "FROM python:3.11-slim\nUSER appuser\nUSER root\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_multistage_only_builder_stage_user_still_fires(tmp_path: Path) -> None:
    """Negative control (the issue's explicit case): a multi-stage file where only a NON-final
    stage sets USER must still fire — the discarded stage's USER does not reach the image."""
    _compose(tmp_path, "services:\n  app:\n    build: ./svc\n")
    _dockerfile(
        tmp_path,
        "svc/Dockerfile",
        "FROM python:3.11-slim as builder\nUSER appuser\nFROM python:3.11-slim\nRUN echo final\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_build_context_missing_dockerfile_still_fires(tmp_path: Path) -> None:
    """Negative control: a `build:` context with no Dockerfile present cannot be confirmed, so
    the guard keeps firing (the safe, cannot-confirm direction)."""
    _compose(tmp_path, "services:\n  app:\n    build: ./svc\n")
    (tmp_path / "svc").mkdir()
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_image_only_service_still_fires(tmp_path: Path) -> None:
    """Negative control: an `image:`-only service (no build context to inspect) still fires even
    when an unrelated Dockerfile with a non-root USER exists elsewhere in the repo."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n")
    _dockerfile(tmp_path, "other/Dockerfile", "FROM python:3.11-slim\nUSER appuser\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_pragma_silences_even_a_root_build_service(tmp_path: Path) -> None:
    """Rule 4: the new build-resolution path must not void the user's own opt-out — the pragma
    still silences a service whose build Dockerfile runs as root. `run()` checks the pragma before
    `_scan()` today, so this passes by construction; it is kept as a regression guard against a
    future refactor that inlines the pragma check into `_scan` (where it could race the new path)."""
    _compose(
        tmp_path,
        "# security: allow-compose-root-user\nservices:\n  app:\n    build: ./svc\n",
    )
    _dockerfile(tmp_path, "svc/Dockerfile", "FROM python:3.11-slim\n")
    assert _run(tmp_path) == []


def test_build_context_nul_byte_does_not_raise_and_still_fires(tmp_path: Path) -> None:
    """#816 review #1: a compose `build:` value with an embedded NUL byte makes `Path.resolve()`
    raise `ValueError` (not `OSError`); run() must stay total and fall back to firing."""
    _compose(tmp_path, "services:\n  app:\n    build: ./svc\x00x\n")
    (tmp_path / "svc").mkdir()
    findings = _run(tmp_path)  # must not raise
    assert any(f.rule == _RULE for f in findings)


def test_build_long_form_dockerfile_only_defaults_context_silent(tmp_path: Path) -> None:
    """#816 review #2: a long-form `build:` block that sets only `dockerfile:` (no `context:`)
    defaults context to `.`, resolves against the compose dir, and stays silent when non-root."""
    _compose(tmp_path, "services:\n  app:\n    build:\n      dockerfile: Custom.Dockerfile\n")
    _dockerfile(tmp_path, "Custom.Dockerfile", "FROM python:3.11-slim\nUSER appuser\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_build_long_form_args_block_between_context_and_dockerfile_silent(tmp_path: Path) -> None:
    """#816 review #3: an intervening multi-key `args:` block between `context:` and `dockerfile:`
    must not break resolution — the parsing loop still finds both sub-keys."""
    _compose(
        tmp_path,
        "services:\n  app:\n    build:\n      context: ./svc\n"
        "      args:\n        FOO: bar\n        BAZ: qux\n"
        "      dockerfile: Custom.Dockerfile\n",
    )
    _dockerfile(tmp_path, "svc/Custom.Dockerfile", "FROM python:3.11-slim\nUSER appuser\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_build_context_escaping_root_still_fires(tmp_path: Path) -> None:
    """#816 review #3: a `build:` context that escapes the scanned root (`../outside`) must still
    fire even when the out-of-root Dockerfile is non-root — the escape cannot launder a suppression."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "docker-compose.yml").write_text(
        "services:\n  app:\n    build: ../outside\n", encoding="utf-8"
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Dockerfile").write_text("FROM python:3.11-slim\nUSER appuser\n", encoding="utf-8")
    findings = ComposeUserDirectiveMissingGuard().run(proj, mkprofile(proj, features={"docker"}))
    assert any(f.rule == _RULE for f in findings)


def test_build_inline_flow_mapping_still_fires(tmp_path: Path) -> None:
    """#816 review #3: the inline flow-mapping form (`build: {context: ./svc}`) is not parsed by the
    indent-based reader, so the service stays unresolved and keeps firing — and this pins that the
    #2 long-form default did NOT accidentally start resolving the inline form."""
    _compose(tmp_path, "services:\n  app:\n    build: {context: ./svc}\n")
    _dockerfile(tmp_path, "svc/Dockerfile", "FROM python:3.11-slim\nUSER appuser\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))
