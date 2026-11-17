"""Tests for the compose-credential-env-literal guard (§6c)."""
from __future__ import annotations

from agentsec.guards.compose_credential_env_literal import ComposeCredentialEnvLiteralGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "compose-credential-env-literal/literal-credential"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"docker"})


def _run(tmp_path: Path):
    return ComposeCredentialEnvLiteralGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str) -> None:
    (tmp_path / "docker-compose.yml").write_text(body, encoding="utf-8")


def test_dict_form_password_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    environment:\n      DB_PASSWORD: hunter2\n")
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "high"


def test_list_form_password_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    environment:\n      - DB_PASSWORD=hunter2\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_api_key_fires(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    environment:\n      STRIPE_API_KEY: sk_live_abc123\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_file_suffix_exempt(tmp_path: Path) -> None:
    """FP-bait: the documented *_FILE opt-out points at a path, not a secret."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    environment:\n      DB_PASSWORD_FILE: /run/secrets/db_password\n")
    assert _run(tmp_path) == []


def test_var_reference_exempt(tmp_path: Path) -> None:
    """FP-bait: a pure ${VAR} reference ships nothing — the secret is sourced from env."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    environment:\n      DB_PASSWORD: ${DB_PASSWORD}\n")
    assert _run(tmp_path) == []


def test_var_reference_with_empty_default_exempt(tmp_path: Path) -> None:
    """FP-bait: ${VAR:-} (empty fallback) is the recommended Compose pattern, not a
    hard-coded credential — the fallback is empty, so nothing is baked into the file."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    environment:\n      DB_PASSWORD: ${DB_PASSWORD:-}\n")
    assert _run(tmp_path) == []


def test_var_reference_with_bare_dash_empty_default_exempt(tmp_path: Path) -> None:
    """FP-bait: the `${VAR-}` (no colon) empty-default form must also stay silent."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    environment:\n      DB_PASSWORD: ${DB_PASSWORD-}\n")
    assert _run(tmp_path) == []


def test_var_reference_with_error_message_exempt(tmp_path: Path) -> None:
    """FP-bait: ${VAR:?msg} is an error message shown when unset, never a credential."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n      DB_PASSWORD: ${DB_PASSWORD:?must be set}\n",
    )
    assert _run(tmp_path) == []


def test_var_reference_with_non_empty_default_still_fires(tmp_path: Path) -> None:
    """Narrowing safety check: a NON-EMPTY fallback (${VAR:-hunter2}) is a literal
    credential baked into the compose file and must still fire, including the
    subtle ${POSTGRES_PASSWORD:-postgres} shape Dean measured on real repos."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-postgres}\n",
    )
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "high"


def test_var_reference_with_bare_dash_non_empty_default_still_fires(tmp_path: Path) -> None:
    """Same narrowing check for the `${VAR-default}` (no colon) form."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n      DB_PASSWORD: ${DB_PASSWORD-hunter2}\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_flag_value_exempt(tmp_path: Path) -> None:
    """FP-bait: a boolean-shaped value on a credential-shaped key is a toggle, not a secret."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    environment:\n      ALLOW_EMPTY_PASSWORD: 'yes'\n")
    assert _run(tmp_path) == []


def test_quantity_knob_exempt(tmp_path: Path) -> None:
    """FP-bait: a duration on a *_TTL key is not a token."""
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    environment:\n      TOKEN_TTL_MINUTES: 30\n")
    assert _run(tmp_path) == []


def test_userinfo_free_url_exempt(tmp_path: Path) -> None:
    """FP-bait (#898): a GoTrue hook locator under a `*_TOKEN_URI` key is a URL with no
    userinfo — `postgres` in the authority is the database name, not a user — so it ships
    no credential, exactly as build_secret.py treats a userinfo-free Dockerfile ENV URL (#447)."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      GOTRUE_HOOK_CUSTOM_ACCESS_TOKEN_URI: pg-functions://postgres/public/custom_access_token_hook\n",
    )
    assert _run(tmp_path) == []


def test_oauth_token_endpoint_url_exempt(tmp_path: Path) -> None:
    """FP-bait (#898, same class): an OAuth/OIDC token endpoint under a `*_TOKEN_URL` /
    `*_TOKEN_ENDPOINT` key is a locator — in the dict form AND the list `KEY=value` form."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      OAUTH_TOKEN_URL: https://auth.example.com/oauth/token\n"
        "  kc:\n    image: alpine\n    environment:\n"
        "      - KEYCLOAK_TOKEN_ENDPOINT=https://kc.example.com/realms/x/protocol/openid-connect/token\n",
    )
    assert _run(tmp_path) == []


def test_quoted_userinfo_free_url_exempt(tmp_path: Path) -> None:
    """FP-bait: the URL arm runs after the quote-strip, so a quoted locator is exempt too."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      TOKEN_URI: 'pg-functions://postgres/public/custom_access_token_hook'\n",
    )
    assert _run(tmp_path) == []


def test_url_with_userinfo_still_fires(tmp_path: Path) -> None:
    """Narrowing safety check (#898, the #447 rule): a URL whose authority carries
    `user:pass@` IS the credential and must keep firing HIGH — the exemption is
    userinfo-free URLs only."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      DB_DSN: postgresql://admin:hunter2@db:5432/app\n",
    )
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    match = next(f for f in findings if f.rule == _RULE)
    assert match.severity == "high"


def test_url_with_user_only_userinfo_still_fires(tmp_path: Path) -> None:
    """Narrowing safety check: user-only userinfo (`https://<token>@github.com`) is a bare
    token in the URL. The sibling compose-connection-string-credential guard needs a
    `:password@` pair, so this guard is the ONLY coverage for the shape — any `@` in the
    authority must keep it a credential."""
    _compose(
        tmp_path,
        "services:\n  app:\n    image: alpine\n    environment:\n"
        "      GIT_TOKEN_URL: https://ghp_abc123@github.com/org/repo\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_non_credential_key_does_not_fire(tmp_path: Path) -> None:
    _compose(tmp_path, "services:\n  app:\n    image: alpine\n    environment:\n      LOG_LEVEL: debug\n")
    assert _run(tmp_path) == []


def test_pragma_silences(tmp_path: Path) -> None:
    _compose(
        tmp_path,
        "# security: allow-compose-credential-env-literal\n"
        "services:\n  app:\n    image: alpine\n    environment:\n      DB_PASSWORD: hunter2\n",
    )
    assert _run(tmp_path) == []


def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert ComposeCredentialEnvLiteralGuard().applies(profile) is False


def test_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert ComposeCredentialEnvLiteralGuard().applies(profile) is True
