from __future__ import annotations

import pytest

from agentsec.guards.mcp_oauth_scope_creep import McpOauthScopeCreepGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "llm", "python"}, python_dirs=["."])


# --- Rule 1: broad-oauth-scope -------------------------------------------------------------


def test_flags_wildcard_scope_with_oauth_context(tmp_path: Path) -> None:
    (tmp_path / "oauth_config.py").write_text(
        "OAUTH_CLIENT_ID = 'my-client-id'\n"
        "OAUTH_AUTHORIZATION_URL = 'https://auth.example.com/authorize'\n"
        "OAUTH_SCOPE = 'admin'\n",
        encoding="utf-8",
    )
    findings = McpOauthScopeCreepGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-scope-creep/broad-oauth-scope" for f in findings)


def test_flags_json_scopes_full_access(tmp_path: Path) -> None:
    (tmp_path / "oauth.json").write_text(
        '{"client_id": "abc", "redirect_uri": "https://app.example.com/cb", '
        '"scopes": "full_access"}\n',
        encoding="utf-8",
    )
    findings = McpOauthScopeCreepGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-scope-creep/broad-oauth-scope" for f in findings)


def test_flags_write_star_scope(tmp_path: Path) -> None:
    (tmp_path / "oauth_config.py").write_text(
        "AUTHORIZATION_ENDPOINT = 'https://auth.example.com/authorize'\n"
        "scope = 'write:*'\n",
        encoding="utf-8",
    )
    findings = McpOauthScopeCreepGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-scope-creep/broad-oauth-scope" for f in findings)


def test_narrow_scope_does_not_fire(tmp_path: Path) -> None:
    # FP bait: a genuinely narrow, resource-specific scope in a real OAuth-context file.
    (tmp_path / "oauth_config.py").write_text(
        "OAUTH_CLIENT_ID = 'my-client-id'\n"
        "OAUTH_AUTHORIZATION_URL = 'https://auth.example.com/authorize'\n"
        "OAUTH_SCOPE = 'read:calendar'\n",
        encoding="utf-8",
    )
    assert McpOauthScopeCreepGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_docstring_disclaimer_does_not_fire(tmp_path: Path) -> None:
    # (Dean's review): rule 1 fired 10 times on agentsec's own tree, every hit a
    # `**False-negative scope:**` guard-docstring heading followed by prose that happened to
    # contain a broad-scope keyword ("all") in its own free text -- comments/docstrings are
    # never a real config value. The OAuth-context hint ("authorization") is present too, the
    # same shape that made these self-fire in the first place.
    (tmp_path / "some_guard.py").write_text(
        '"""Guard: something unrelated to OAuth (checklist section).\n\n'
        "**False-negative scope:** this covers all direct cases but not indirect ones via a "
        "helper, and doesn't check the Authorization header shape either.\n"
        '"""\n'
        "def run():\n"
        "    return None\n",
        encoding="utf-8",
    )
    assert McpOauthScopeCreepGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_hash_comment_disclaimer_does_not_fire(tmp_path: Path) -> None:
    # Same FP class in a YAML/TOML-style file (# comments, no triple-quoted strings involved).
    # A real oauth-context hint stays on a live (non-comment) line, isolating that it's
    # specifically the commented-out "scope:" line being ignored, not just an empty file.
    (tmp_path / "notes.yaml").write_text(
        "authorization_note: unrelated_value\n"
        "# scope: covers all cases for now\n",
        encoding="utf-8",
    )
    assert McpOauthScopeCreepGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_unrelated_scope_field_does_not_fire_without_oauth_context(tmp_path: Path) -> None:
    # FP bait: "scope" is a generic identifier outside the OAuth domain (a pytest-fixture-
    # style config, nothing to do with OAuth) -- no oauth-context hint anywhere in the file.
    (tmp_path / "conftest.py").write_text(
        "def pytest_configure(config):\n"
        "    scope = 'all'\n"
        "    return scope\n",
        encoding="utf-8",
    )
    assert McpOauthScopeCreepGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


# --- Rule 2: dangerous-auth-url-scheme ------------------------------------------------------


def test_flags_javascript_scheme_authorization_url(tmp_path: Path) -> None:
    (tmp_path / "oauth_config.py").write_text(
        "AUTHORIZATION_URL = 'javascript:alert(1)'\n",
        encoding="utf-8",
    )
    findings = McpOauthScopeCreepGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-scope-creep/dangerous-auth-url-scheme" for f in findings)


def test_flags_data_scheme_redirect_uri_json(tmp_path: Path) -> None:
    (tmp_path / "oauth.json").write_text(
        '{"redirect_uri": "data:text/html,<script>alert(1)</script>"}\n',
        encoding="utf-8",
    )
    findings = McpOauthScopeCreepGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-scope-creep/dangerous-auth-url-scheme" for f in findings)


def test_https_authorization_url_does_not_fire(tmp_path: Path) -> None:
    # FP bait: a real, safe HTTPS authorization endpoint.
    (tmp_path / "oauth_config.py").write_text(
        "AUTHORIZATION_URL = 'https://auth.example.com/authorize'\n",
        encoding="utf-8",
    )
    assert McpOauthScopeCreepGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


# --- comment stripping must not eat a real value (PR #919 re-review) ----------------------
# 36a932e0 started blanking comments per extension before either rule scans. That is a narrowing,
# so each newly-stripped file type gets a still-fires case: a real value with a trailing comment
# on the SAME line, where an over-eager stripper would take the value with it.


@pytest.mark.parametrize(
    ("name", "body", "line"),
    [
        ("oauth.yaml", 'client_id: abc\nscope: "*"  # TODO narrow before launch\n', 2),
        ("oauth.yml", "client_id: abc\nscopes: ['read:*']  # temporary\n", 2),
        ("oauth.toml", '[oauth]\nclient_id = "abc"\nscope = "admin"  # temporary\n', 3),
        ("oauth.js", "const cfg = { client_id: 'abc', scope: 'admin' }; // temporary\n", 1),
        ("oauth.ts", "export const cfg = { client_id: 'abc', scope: '*' }; /* temporary */\n", 1),
    ],
)
def test_broad_scope_with_trailing_comment_still_fires(
    tmp_path: Path, name: str, body: str, line: int
) -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")
    findings = McpOauthScopeCreepGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [(f.rule, f.location) for f in findings] == [
        ("mcp-oauth-scope-creep/broad-oauth-scope", f"{name}:{line}")
    ]


@pytest.mark.parametrize(
    ("name", "body"),
    [
        ("oauth.yaml", 'redirect_uri: "javascript:alert(1)"  # never ship this\n'),
        ("oauth.toml", 'redirect_uri = "data:text/html,x"  # never ship this\n'),
        ("oauth.js", "const redirect_uri = 'javascript:alert(1)'; // never ship this\n"),
    ],
)
def test_dangerous_scheme_with_trailing_comment_still_fires(
    tmp_path: Path, name: str, body: str
) -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")
    findings = McpOauthScopeCreepGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [(f.rule, f.severity) for f in findings] == [
        ("mcp-oauth-scope-creep/dangerous-auth-url-scheme", "high")
    ]


# --- shared: pragma, applies() -----------------------------------------------------------


def test_pragma_suppresses_both_rules(tmp_path: Path) -> None:
    (tmp_path / "oauth_config.py").write_text(
        "# security: allow-mcp-oauth-scope-creep\n"
        "OAUTH_AUTHORIZATION_URL = 'javascript:alert(1)'\n"
        "OAUTH_SCOPE = 'admin'\n",
        encoding="utf-8",
    )
    assert McpOauthScopeCreepGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_applies_requires_only_mcp_feature(tmp_path: Path) -> None:
    guard = McpOauthScopeCreepGuard()
    assert guard.applies(mkprofile(tmp_path, features={"mcp"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "typescript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is False
