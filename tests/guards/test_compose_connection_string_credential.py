"""Tests for the compose-connection-string-credential guard (§6c)."""
from __future__ import annotations

from agentsec.guards.compose_connection_string_credential import (
    ComposeConnectionStringCredentialGuard,
)
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-connection-string-credential/embedded-credential"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeConnectionStringCredentialGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str) -> None:
    (tmp_path / "docker-compose.yml").write_text(body, encoding="utf-8")


def test_postgres_url_with_literal_password_fires(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      DATABASE_URL: postgresql://admin:hunter2@db:5432/app\n",
    )
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "high"


def test_redis_url_empty_username_fires(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      REDIS_URL: redis://:hunter2@cache:6379\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_key_name_irrelevant_to_detection(tmp_path: Path) -> None:
    """Any key carrying a literal connection-string credential fires, not just *_URL names."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      CUSTOM_DSN: mysql://root:hunter2@mysql:3306/app\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_parameterized_password_does_not_fire(tmp_path: Path) -> None:
    """FP-bait: a pure ${VAR} password ships no literal secret."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      DATABASE_URL: postgresql://admin:${DB_PASSWORD}@db:5432/app\n",
    )
    assert _run(tmp_path) == []


def test_dsn_password_empty_default_does_not_fire(tmp_path: Path) -> None:
    """FP-bait (#663 review H2): a DSN password using the recommended `${VAR:-}`
    empty-fallback Compose pattern ships no literal secret — must NOT fire.
    (`postgresql://appuser:${POSTGRES_PASSWORD:-}@postgres:5432/app`, the exact shape
    measured as a false positive in the review.)"""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      DATABASE_URL: postgresql://appuser:${POSTGRES_PASSWORD:-}@postgres:5432/app\n",
    )
    assert _run(tmp_path) == []


def test_dsn_password_bare_dash_empty_default_does_not_fire(tmp_path: Path) -> None:
    """FP-bait: the `${VAR-}` (no colon) empty-default form in DSN password position
    must also stay silent."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      REDIS_URL: redis://:${REDIS_PASSWORD-}@redis:6379/0\n",
    )
    assert _run(tmp_path) == []


def test_dsn_password_error_message_does_not_fire(tmp_path: Path) -> None:
    """FP-bait: `${VAR:?msg}` in DSN password position is an error message shown when
    unset, never a shipped credential."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      DATABASE_URL: postgresql://appuser:${POSTGRES_PASSWORD:?must be set}@postgres:5432/app\n",
    )
    assert _run(tmp_path) == []


def test_dsn_password_non_empty_default_still_fires(tmp_path: Path) -> None:
    """Narrowing safety check (#663 review H2): a NON-EMPTY fallback in DSN password
    position (`${POSTGRES_PASSWORD:-postgres}`) is a literal credential baked into the
    compose file and must still fire at high — this is the subtle shape Dean measured
    as a true positive on real repos."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      DATABASE_URL: postgresql://appuser:${POSTGRES_PASSWORD:-postgres}@postgres:5432/app\n",
    )
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "high"


def test_dsn_password_bare_dash_non_empty_default_still_fires(tmp_path: Path) -> None:
    """Same narrowing check for the `${VAR-default}` (no colon) form in DSN password
    position."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      DATABASE_URL: postgresql://appuser:${POSTGRES_PASSWORD-postgres}@postgres:5432/app\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_no_credential_url_does_not_fire(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      API_URL: https://api.example.com/v1\n",
    )
    assert _run(tmp_path) == []


def test_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-compose-connection-string-credential\n"
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      DATABASE_URL: postgresql://admin:hunter2@db:5432/app\n",
    )
    assert _run(tmp_path) == []


def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert ComposeConnectionStringCredentialGuard().applies(profile) is False


def test_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert ComposeConnectionStringCredentialGuard().applies(profile) is True
