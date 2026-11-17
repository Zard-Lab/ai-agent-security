from __future__ import annotations

import pytest

from agentsec.guards.mcp_hardcoded_credential import McpHardcodedCredentialGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "python"}, python_dirs=["."])


def _mcp_js_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "javascript"})


def test_fires_on_python_api_key_literal(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'API_KEY = "sk-live-abc123def456xyz"\n',
        encoding="utf-8",
    )
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-hardcoded-credential/hardcoded-credential-literal" for f in findings)


def test_fires_on_python_type_annotated_secret(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'token: str = "abcdef1234567890"\n',
        encoding="utf-8",
    )
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-hardcoded-credential/hardcoded-credential-literal" for f in findings)


def test_fires_on_js_camelcase_access_key(tmp_path: Path) -> None:
    (tmp_path / "config.js").write_text(
        'const accessKey = "AKIAABCDEFGH12345678";\n',
        encoding="utf-8",
    )
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert any(f.rule == "mcp-hardcoded-credential/hardcoded-credential-literal" for f in findings)


def test_fires_on_ts_object_literal_key(tmp_path: Path) -> None:
    (tmp_path / "config.ts").write_text(
        'const config = { password: "sup3rSecretValue!" };\n',
        encoding="utf-8",
    )
    findings = McpHardcodedCredentialGuard().run(tmp_path, mkprofile(tmp_path, features={"mcp", "typescript"}))
    assert any(f.rule == "mcp-hardcoded-credential/hardcoded-credential-literal" for f in findings)


def test_silent_on_env_var_read(tmp_path: Path) -> None:
    """FP-bait: reading from an environment variable is excluded by construction -- no
    quoted literal directly after the operator."""
    (tmp_path / "config.py").write_text(
        'API_KEY = os.getenv("API_KEY")\n',
        encoding="utf-8",
    )
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-hardcoded-credential/hardcoded-credential-literal" for f in findings)


def test_silent_on_placeholder_value(tmp_path: Path) -> None:
    """FP-bait, the important one: the extremely common tutorial/scaffolding placeholder
    idiom must not fire as a CRITICAL finding."""
    (tmp_path / "config.py").write_text(
        'API_KEY = "your-api-key-here"\n',
        encoding="utf-8",
    )
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-hardcoded-credential/hardcoded-credential-literal" for f in findings)


def test_silent_on_short_literal(tmp_path: Path) -> None:
    """FP-bait: a literal under the 8-character floor (e.g. a mode flag, not a credential)
    stays silent."""
    (tmp_path / "config.py").write_text(
        'token = "abc"\n',
        encoding="utf-8",
    )
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-hardcoded-credential/hardcoded-credential-literal" for f in findings)


def test_silent_without_mcp_feature(tmp_path: Path) -> None:
    """FP-bait: this guard is deliberately MCP-gated, not a general-purpose credential
    scanner -- a repo with no MCP feature detected never reaches it at all."""
    guard = McpHardcodedCredentialGuard()
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is False


def test_applies_requires_mcp_plus_a_language(tmp_path: Path) -> None:
    guard = McpHardcodedCredentialGuard()
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "javascript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "typescript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"mcp"})) is False


def test_pragma_suppresses_python_finding(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        "# security: allow-mcp-hardcoded-credential\n"
        'API_KEY = "sk-live-abc123def456xyz"\n',
        encoding="utf-8",
    )
    assert McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_pragma_suppresses_js_finding(tmp_path: Path) -> None:
    (tmp_path / "config.js").write_text(
        "// security: allow-mcp-hardcoded-credential\n"
        'const accessKey = "AKIAABCDEFGH12345678";\n',
        encoding="utf-8",
    )
    assert McpHardcodedCredentialGuard().run(tmp_path, _mcp_js_prof(tmp_path)) == []


# --- H3 (#1058 review): severity, masked/key-name FP-bait, and the word-boundary FN fix --------

def test_finding_is_a_non_gating_review_signal(tmp_path: Path) -> None:
    """A name-plus-value-shape heuristic cannot prove a secret, so the finding is a MEDIUM
    surfacing signal (round 3 of the #1058 review), below the default `--fail-on high`. Proven
    secrets keep gating through the provider-prefix and Stripe live-key guards and gitleaks."""
    from agentsec.findings import SEVERITY_RANK, _is_review_finding

    (tmp_path / "config.py").write_text(
        'API_KEY = "sk-live-abc123def456xyz"\n',
        encoding="utf-8",
    )
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-hardcoded-credential/hardcoded-credential-literal")
    assert hit.severity == "medium"
    assert SEVERITY_RANK[hit.severity] > SEVERITY_RANK["high"]
    assert _is_review_finding(hit) is True


def test_silent_on_masked_value(tmp_path: Path) -> None:
    """FP-bait (H3, measured in Dean's review): an all-asterisk masked display value, and a
    REDACTED-style placeholder, must not fire."""
    (tmp_path / "config.js").write_text(
        'const password = "********";\n'
        'const secret = "***REDACTED***";\n',
        encoding="utf-8",
    )
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert not any(f.rule == "mcp-hardcoded-credential/hardcoded-credential-literal" for f in findings)


def test_silent_on_key_name_shaped_value(tmp_path: Path) -> None:
    """FP-bait (H3, measured in Dean's review): the VALUE itself reads as a lookup-key name
    (e.g. a localStorage key), not a secret -- all lowercase words joined by `_`/`-`, no digits."""
    (tmp_path / "config.js").write_text(
        'const token = "access_token";\n'
        'const key = { token: "auth-token-storage-key" };\n',
        encoding="utf-8",
    )
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert not any(f.rule == "mcp-hardcoded-credential/hardcoded-credential-literal" for f in findings)


def test_fires_on_snake_case_env_style_name(tmp_path: Path) -> None:
    """Previously silent (H3): `_`-joined SCREAMING_CASE names did not match the old `\\b`-bounded
    regex at all, despite the module's own docstring claiming they did. A real secret value here
    (mixed case + digits) must now fire."""
    (tmp_path / "config.py").write_text(
        'GITHUB_TOKEN = "ghp_realtoken1234567890abcd"\n'
        'DB_PASSWORD = "Sup3rSecretDbPass!"\n',
        encoding="utf-8",
    )
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path))
    hits = [f.location for f in findings if f.rule == "mcp-hardcoded-credential/hardcoded-credential-literal"]
    assert "config.py:1" in hits
    assert "config.py:2" in hits


def test_fires_on_camelcase_and_underscore_prefixed_token_names(tmp_path: Path) -> None:
    """Previously silent (H3): `my_token`/`tokenValue` did not match the old `\\b`-bounded regex
    either (no boundary between `_` and a letter, none between a lowercase word and an immediate
    uppercase continuation) -- despite the docstring's own claim that both still matched."""
    (tmp_path / "config.js").write_text(
        'const my_token = "abcdef1234567890";\n'
        'const tokenValue = "fedcba0987654321";\n',
        encoding="utf-8",
    )
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    hits = [f.location for f in findings if f.rule == "mcp-hardcoded-credential/hardcoded-credential-literal"]
    assert "config.js:1" in hits
    assert "config.js:2" in hits


def test_silent_on_lowercase_substring_continuation(tmp_path: Path) -> None:
    """FP-bait for the new boundary logic itself: `tokenize`/`passwordless` must not be read as
    the credential-shaped name `token`/`password` -- a lowercase continuation right after the
    word is NOT a boundary, only an uppercase one (camelCase) or a non-letter/digit is."""
    (tmp_path / "config.py").write_text(
        'tokenize_method = "abcdef1234567890"\n'
        'passwordless_mode = "abcdef1234567890"\n',
        encoding="utf-8",
    )
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-hardcoded-credential/hardcoded-credential-literal" for f in findings)


# --- round 2 of the #1058 review: ReDoS, locator-shaped values, all-letter secrets ----------------

_RULE = "mcp-hardcoded-credential/hardcoded-credential-literal"


def test_assignment_scan_is_linear_on_a_long_identifier_run() -> None:
    """Round-2 H1: with no leading boundary, the assignment regex retried from every position
    inside a run of identifier characters and backtracked across the rest of it, so one embedded
    hex blob cost seconds per line (16 KB measured at 3.7 s). The lookbehind makes it linear."""
    from tests._timing import assert_growth

    def scan(n: int) -> object:
        return McpHardcodedCredentialGuard._line_fires('load("' + "ab12" * n + '");')

    assert_growth(scan, [1_000, 2_000, 4_000, 8_000], expected="linear")


@pytest.mark.parametrize(
    "line",
    [
        'TOKEN_URL = "https://github.com/login/oauth/access_token"',
        'TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"',
        'SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:foo"',
        'PASSWORD_RESET_PATH = "/auth/reset-password"',
        'token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"',
        # Mixed case, so only the absolute-path alternative (not the lowercase-path one) owns it.
        'PASSWORD_RESET_ROUTE = "/api/v1/resetPassword"',
        'SECRET_NAME = "prod/db/credentials"',
        'secret_manager_client = "projects/123/secrets/foo"',
        'token_expiry = "2026-12-31T00:00:00Z"',
    ],
)
def test_silent_on_locator_shaped_value(tmp_path: Path, line: str) -> None:
    """FP-bait (round-2 H2): the segment widening made any `*_TOKEN_URL`/`SECRET_ARN`/`*_PATH`
    constant fire a gating HIGH. A URL, a path, an ARN or a timestamp locates or dates a secret;
    it is not one."""
    (tmp_path / "config.py").write_text(line + "\n", encoding="utf-8")
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == _RULE for f in findings)


def test_js_silent_on_token_endpoint_url(tmp_path: Path) -> None:
    """The JS/TS spellings of the same FP: a camelCase constant and an unquoted object key."""
    (tmp_path / "config.ts").write_text(
        'const tokenUrl = "https://auth.foo.org/oauth/token";\n'
        'const oidc = { token_endpoint: "https://auth.foo.org/oauth/token" };\n',
        encoding="utf-8",
    )
    findings = McpHardcodedCredentialGuard().run(tmp_path, mkprofile(tmp_path, features={"mcp", "typescript"}))
    assert not any(f.rule == _RULE for f in findings)


@pytest.mark.parametrize(
    "line",
    [
        # A URL that carries its own password in the userinfo is still a hardcoded credential.
        'DB_PASSWORD = "postgresql://app:Sup3rS3cretPw@db.internal:5432/app"',
        # Base64 secrets contain `/`; a mixed-case one is not a path (AWS secret-key shape).
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ8k2LmN4p"',
    ],
)
def test_fires_on_secret_that_merely_contains_locator_characters(tmp_path: Path, line: str) -> None:
    """The direction H2 trades against: the locator exclusion must not swallow a credential URL
    or a base64 secret just because it contains `://` or `/`."""
    (tmp_path / "config.py").write_text(line + "\n", encoding="utf-8")
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == _RULE for f in findings)


@pytest.mark.parametrize(
    "line",
    [
        'password = "SuperSecretPassword"',
        'api_key = "AbCdEfGhIjKlMnOpQr"',
        'SECRET = "Correct-Horse-Battery"',
    ],
)
def test_fires_on_all_letter_mixed_case_secret(tmp_path: Path, line: str) -> None:
    """Round-2 M1: the key-name exclusion is meant for all-LOWERCASE words. Compiled with
    IGNORECASE it also silenced every all-letter secret with capitals, a narrowing with no
    still-fires test. Each of these fired before the round-1 fix."""
    (tmp_path / "config.py").write_text(line + "\n", encoding="utf-8")
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == _RULE for f in findings)


@pytest.mark.parametrize(
    "line",
    [
        'csrf_token_header = "X-CSRF-Token"',
        'API_KEY_HEADER = "X-API-Key"',
        'AUTH_TOKEN_HEADER = "Authorization"',
    ],
)
def test_silent_on_http_header_name_value(tmp_path: Path, line: str) -> None:
    """FP-bait for the M1 fix: once capitals count again, a constant holding an HTTP header NAME
    would fire. These were silent before only because of the IGNORECASE accident."""
    (tmp_path / "config.py").write_text(line + "\n", encoding="utf-8")
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == _RULE for f in findings)


# --- round 3 of the #1058 review: descriptor values surface without gating; X- header shape -------


@pytest.mark.parametrize(
    "line",
    [
        'TOKEN_TYPE = "BearerToken"',
        'token_class = "OAuthTokenManager"',
        'TOKEN_STATUS = "TokenExpired"',
        'PASSWORD_FIELD = "PasswordField"',
        'SECRET_KIND = "ClientSecret"',
        'api_key_scheme = "ApiKeyAuth"',
        'password_label = "EnterPassword"',
        'token_serializer = "JsonSerializer"',
    ],
)
def test_descriptor_valued_constant_surfaces_without_gating(tmp_path: Path, line: str) -> None:
    """Round-3 H1: an all-letter class, enum or type label under a credential-segment name is
    indistinguishable by shape from `"SuperSecretPassword"`, which must keep firing. It stays in
    the report as a review hint, but must not fail a build at the default `--fail-on high`."""
    from agentsec.findings import SEVERITY_RANK

    (tmp_path / "config.py").write_text(line + "\n", encoding="utf-8")
    findings = [f for f in McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path)) if f.rule == _RULE]
    assert findings, "the review hint should still be reported"
    assert all(SEVERITY_RANK[f.severity] > SEVERITY_RANK["high"] for f in findings)


def test_fires_on_x_prefixed_value_that_is_not_a_header_name(tmp_path: Path) -> None:
    """Round-3 L2: the header-name carve-out must not swallow a token that merely starts `X-`.
    Header names are letter words; a digit run after the prefix is a value."""
    (tmp_path / "config.py").write_text('API_KEY = "X-9f8a7b6c5d4e3f2a"\n', encoding="utf-8")
    findings = McpHardcodedCredentialGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == _RULE for f in findings)


def test_ts_mcp_server_credentials_surface_through_the_real_pipeline(tmp_path: Path) -> None:
    """Round 4 of the #1058 review: pin that in a pure-TS MCP repo (`{mcp, typescript}`) the real
    detect -> select -> run pipeline reports both lines as the documented MEDIUM review signal.
    Since #1082 the provider-key line is also gated HIGH by `client-side-secret-literal` (that is
    pinned in its own test file); the `dbPassword` line is still gated by no guard, so this MEDIUM
    is its only signal. It deliberately does not assert what ELSE fires on these lines."""
    import os

    from agentsec.audit import audit

    (tmp_path / "package.json").write_text(
        '{"name": "mcp-ts", "dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"},'
        ' "devDependencies": {"typescript": "^5"}}\n',
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "server.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n"
        'const dbPassword = "Sup3rS3cretPassw0rd";\n'
        'const apiKey = "sk-proj-abcdefghijklmnop1234567890";\n'
        "export const server = new McpServer({ name: 'x' });\n",
        encoding="utf-8",
    )
    res = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
    assert {"mcp", "typescript"} <= res.profile.features
    hits = {
        f.location.replace("\\", "/"): f.severity for f in res.findings if f.rule == _RULE
    }
    assert hits == {"src/server.ts:2": "medium", "src/server.ts:3": "medium"}
