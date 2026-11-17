"""Tests for McpOauthFlowHardeningGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

from collections.abc import Callable

import pytest

from agentsec.findings import Finding
from agentsec.guards.mcp_oauth_flow_hardening import McpOauthFlowHardeningGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "python"}, python_dirs=["."])


# The guard anchors only on the MCP surface (#1023), so every fixture that stands for MCP code
# carries an SDK import, the FP-bait ones included: without it an FP-bait test would pass
# off the surface instead of exercising the suppression it is named for. JSON fixtures get an
# MCP config filename (`mcp-*.json`) for the same reason.
_MCP_PY = "from mcp.server.fastmcp import FastMCP\n"
_MCP_TS = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'


def _mcp_write(path: Path, src: str) -> None:
    """Write `src` as an MCP module: the SDK import first, which puts the file on the surface."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text((_MCP_PY if path.suffix == ".py" else _MCP_TS) + src, encoding="utf-8")


# ── missing-pkce ──────────────────────────────────────────────────────────

def test_missing_pkce_fires(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "oauth_client.py",
        "def start_login(client_id):\n"
        "    return authorize(client_id=client_id, response_type='code')\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-oauth-flow-hardening/missing-pkce")
    assert hit.severity == "high"


def test_pkce_present_is_safe(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "oauth_client.py",
        "def start_login(client_id, code_challenge):\n"
        "    return authorize(client_id=client_id, code_challenge=code_challenge)\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-oauth-flow-hardening/missing-pkce" for f in findings)


# ── pkce-plain-method ─────────────────────────────────────────────────────

def test_pkce_plain_method_fires(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "oauth_client.py",
        "params = {'client_id': CLIENT_ID, 'code_challenge_method': 'plain'}\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-flow-hardening/pkce-plain-method" for f in findings)


def test_pkce_s256_is_safe(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "oauth_client.py",
        "params = {'code_challenge_method': 'S256'}\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-oauth-flow-hardening/pkce-plain-method" for f in findings)


# ── token-passthrough ─────────────────────────────────────────────────────

def test_token_passthrough_fires(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "proxy.py",
        "# oauth token relay\n"
        "headers['Authorization'] = request.headers['Authorization']\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-flow-hardening/token-passthrough" for f in findings)


# ── wildcard-redirect-uri ─────────────────────────────────────────────────

def test_wildcard_redirect_uri_fires(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "oauth_config.py",
        "OAUTH_CONFIG = {'redirect_uri': '*'}\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-flow-hardening/wildcard-redirect-uri" for f in findings)


def test_specific_redirect_uri_is_safe(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "oauth_config.py",
        "OAUTH_CONFIG = {'redirect_uri': 'https://app.example.com/callback'}\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-oauth-flow-hardening/wildcard-redirect-uri" for f in findings)


# ── bearer-only-no-dpop ───────────────────────────────────────────────────

def test_bearer_only_no_dpop_fires(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "oauth_client.py",
        "# oauth client\n"
        "headers = {'Authorization': f'Bearer {access_token}'}\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-flow-hardening/bearer-only-no-dpop" for f in findings)


def test_dpop_present_is_safe(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "oauth_client.py",
        "# oauth client\n"
        "headers = {'Authorization': f'Bearer {access_token}', 'DPoP': dpop_proof}\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-oauth-flow-hardening/bearer-only-no-dpop" for f in findings)


# ── missing-iss-validation ────────────────────────────────────────────────

def test_missing_iss_validation_fires(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "callback.py",
        "# oauth callback handler\n"
        "def handle_callback(query_params):\n"
        "    code = query_params.get('code')\n"
        "    return exchangeCodeForToken(code)\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-flow-hardening/missing-iss-validation" for f in findings)


def test_iss_validated_is_safe(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "callback.py",
        "# oauth callback handler\n"
        "def handle_callback(query_params):\n"
        "    code = query_params.get('code')\n"
        "    iss = query_params.get('iss')\n"
        "    validate_issuer(iss)\n"
        "    return exchangeCodeForToken(code)\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-oauth-flow-hardening/missing-iss-validation" for f in findings)


# ── missing-resource-indicator ────────────────────────────────────────────

def test_missing_resource_indicator_fires(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "oauth_client.py",
        "def get_token(client_id):\n"
        "    return post(token_endpoint, data={'grant_type': 'client_credentials'})\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-flow-hardening/missing-resource-indicator" for f in findings)


def test_resource_indicator_present_is_safe(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "oauth_client.py",
        "def get_token(client_id):\n"
        "    return post(token_endpoint, data={'grant_type': 'client_credentials', 'resource': 'https://mcp.example.com'})\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-oauth-flow-hardening/missing-resource-indicator" for f in findings)


# ── missing-prm-discovery ─────────────────────────────────────────────────

def test_missing_prm_discovery_fires(tmp_path: Path) -> None:
    (tmp_path / "mcp_client_config.json").write_text(
        '{"type": "streamable-http", "url": "https://mcp.example.com", "auth": {"token": "abc"}}',
        encoding="utf-8",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-flow-hardening/missing-prm-discovery" for f in findings)


def test_prm_discovery_present_is_safe(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "mcp_client.py",
        "def discover(base_url):\n"
        "    return fetch(base_url + '/.well-known/oauth-protected-resource')\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-oauth-flow-hardening/missing-prm-discovery" for f in findings)


# ── OAuth hint scoping ────────────────────────────────────────

def test_bare_authorize_function_with_no_oauth_content_is_safe(tmp_path: Path) -> None:
    # (Dean's review corpus-scan review): reproduces the real FP on the python-sdk
    # repo's .github/scripts/docs_preview.js -- a PR-permission-check function named
    # `authorize(...)` with no `oauth`/`authorization_endpoint`/`token_endpoint`/`client_id`
    # anywhere in the file is not an OAuth client flow, so it must not be scanned for one.
    _mcp_write(
        tmp_path / "docs_preview.js",
        "async function authorize({ github, context, core }) {\n"
        "  const perm = await github.rest.repos.getCollaboratorPermissionLevel();\n"
        "  return perm.data.permission === 'admin';\n"
        "}\n",
    )
    assert McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_real_oauth_flow_named_authorize_still_fires(tmp_path: Path) -> None:
    # The direction traded against: a real OAuth authorization-code flow that happens to
    # call a function literally named authorize(...) still fires, because it also carries
    # client_id (or oauth/authorization_endpoint/token_endpoint) in the same file.
    _mcp_write(
        tmp_path / "oauth_client.py",
        "def start_login(client_id):\n"
        "    return authorize(client_id=client_id, response_type='code')\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-flow-hardening/missing-pkce" for f in findings)


def test_mintlify_docs_site_config_is_not_a_live_oauth_flow(tmp_path: Path) -> None:
    # (Dean's review corpus-scan review): reproduces the real FP on fastmcp's
    # docs/docs.json -- a Mintlify docs-site navigation manifest whose page-path strings
    # ("clients/auth/oauth", "servers/auth/remote-oauth") tripped _OAUTH_HINT, then every "no
    # PKCE/resource-indicator anywhere" absence check fired on a file that is pure site
    # navigation, not code. A top-level "$schema" key means "governed by an external schema",
    # not "live MCP client/server config" -- same signal used for JSON Schema documents.
    (tmp_path / "mcp-docs.json").write_text(
        '{\n'
        '  "$schema": "https://mintlify.com/docs.json",\n'
        '  "name": "FastMCP",\n'
        '  "navigation": {\n'
        '    "groups": [\n'
        '      {"group": "Authentication", "pages": ["clients/auth/oauth", "servers/auth/remote-oauth"]}\n'
        '    ]\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    assert McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_real_oauth_config_with_no_schema_key_still_fires(tmp_path: Path) -> None:
    # The direction traded against: a real OAuth client config with no "$schema" key still
    # fires -- the exclusion is scoped to schema-governed files, not JSON in general.
    (tmp_path / "mcp-oauth-config.json").write_text(
        '{"client_id": "abc123", "authorization_endpoint": "https://auth.example.com/authorize"}\n',
        encoding="utf-8",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-flow-hardening/missing-pkce" for f in findings)


def test_navigation_fragment_with_no_schema_key_is_not_a_live_oauth_flow(tmp_path: Path) -> None:
    # continued: fastmcp's real docs/v2-navigation.json and docs/v3-navigation.json are
    # referenced BY docs.json but carry no "$schema" marker of their own -- just a plain array of
    # page-path strings like "clients/auth/oauth" and "servers/auth/remote-oauth". No real OAuth
    # config or code value takes this multi-segment slash-path shape, so masking quoted path-like
    # strings before the hint search removes this FP without needing a schema key to anchor on.
    (tmp_path / "mcp-v2-navigation.json").write_text(
        '{\n'
        '  "dropdowns": [\n'
        '    {"dropdown": "Auth", "pages": ["clients/auth/oauth", "servers/auth/remote-oauth"]}\n'
        '  ],\n'
        '  "version": "v2"\n'
        '}\n',
        encoding="utf-8",
    )
    assert McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_oauth_config_value_without_path_shape_still_fires(tmp_path: Path) -> None:
    # The direction traded against: a real single-segment/non-path OAuth config value (no
    # slashes) must not be masked away by the path-like-string exclusion.
    (tmp_path / "mcp-oauth-settings.json").write_text(
        '{"client_id": "my-app", "authorization_endpoint": "https://auth.example.com"}\n',
        encoding="utf-8",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-oauth-flow-hardening/missing-pkce" for f in findings)


# ── suppression / scope ───────────────────────────────────────────────────

def test_pragma_suppresses_all_findings(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "oauth_client.py",
        "# security: allow-mcp-oauth-flow-hardening\n"
        "def start_login(client_id):\n"
        "    return authorize(client_id=client_id, response_type='code')\n",
    )
    findings = McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpOauthFlowHardeningGuard().applies(prof) is False


# ── `$schema` handling: a real config that carries the key must still fire ─────────────

_LIVE_CONFIG = (
    '{"servers": {"r": {"type": "sse", "url": "https://mcp.example.com/sse", '
    '"auth": {"client_id": "abc123", "authorization_endpoint": "https://auth.example.com", '
    '"redirect_uri": "*"}}}}'
)


def _rules(findings: list[Finding]) -> set[str]:
    return {f.rule.split("/")[-1] for f in findings}


def test_live_config_without_schema_key_fires(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text(_LIVE_CONFIG, encoding="utf-8")
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert {"wildcard-redirect-uri", "missing-pkce", "missing-resource-indicator",
            "missing-prm-discovery"} <= got


def test_live_config_carrying_a_schema_key_still_fires(tmp_path: Path) -> None:
    """The whole-file skip on any `$schema` key made a live `redirect_uri: "*"` config go from
    4 findings to none the moment an editor added `$schema`."""
    (tmp_path / "mcp.json").write_text(
        _LIVE_CONFIG.replace('{"servers"', '{"$schema": "https://json.schemastore.org/mcp.json", "servers"', 1),
        encoding="utf-8",
    )
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert {"wildcard-redirect-uri", "missing-pkce", "missing-resource-indicator",
            "missing-prm-discovery"} <= got


def test_json_schema_document_is_not_a_live_config(tmp_path: Path) -> None:
    """FP-bait: a JSON-Schema document DESCRIBING an oauth config (top-level `properties`, `$schema`
    at a json-schema.org meta-schema) is not a runtime file."""
    (tmp_path / "mcp-config.schema.json").write_text(
        '{"$schema": "http://json-schema.org/draft-07/schema#", "type": "object", "properties": '
        '{"client_id": {"type": "string"}, "authorization_endpoint": {"type": "string"}, '
        '"redirect_uri": {"default": "*"}}}',
        encoding="utf-8",
    )
    assert McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_metaschema_pointing_file_without_schema_body_still_scanned(tmp_path: Path) -> None:
    """A `$schema` at json-schema.org alone (no `properties`/`$defs`) is a config, not a schema."""
    (tmp_path / "mcp-oauth.json").write_text(
        '{"$schema": "http://json-schema.org/draft-07/schema#", "client_id": "a", '
        '"authorization_endpoint": "https://auth.example.com"}',
        encoding="utf-8",
    )
    assert "missing-pkce" in _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))


# ── PRM marker in a masked (path-like) string ────────────────────────────────

_PRM_CFG = (
    '{"type": "streamable-http", "url": "https://mcp.example.com", "auth": {"token": "abc"}, '
    '"discovery_url": "%s"}'
)


def test_relative_prm_path_in_json_counts_as_discovery(tmp_path: Path) -> None:
    (tmp_path / "mcp_client_config.json").write_text(
        _PRM_CFG % ".well-known/oauth-protected-resource", encoding="utf-8"
    )
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert "missing-prm-discovery" not in got


def test_json_without_prm_marker_still_fires_prm(tmp_path: Path) -> None:
    (tmp_path / "mcp_client_config.json").write_text(_PRM_CFG % "docs/other/path", encoding="utf-8")
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert "missing-prm-discovery" in got


# ── PKCE / resource resolved across the class hierarchy ──────────────────────

_BASE = (
    "import hashlib\n"
    "class OAuthProxy:\n"
    "    def _generate_pkce_pair(self):\n"
    "        return code_verifier, code_challenge\n"
    "    def exchange(self):\n"
    "        return {'grant_type': 'authorization_code', 'resource': self.resource}\n"
)
_SUBCLASS = (
    "from base import OAuthProxy\n"
    "class GitHubProvider(OAuthProxy):\n"
    "    def __init__(self):\n"
    "        super().__init__(upstream_authorization_endpoint='https://github.com/login/oauth/authorize')\n"
)


def test_subclass_of_pkce_implementing_base_is_not_missing_pkce(tmp_path: Path) -> None:
    """Providers that inherit from an S256-implementing OAuthProxy were flagged per file."""
    (tmp_path / "base.py").write_text(_BASE, encoding="utf-8")
    _mcp_write(tmp_path / "github.py", _SUBCLASS)
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert "missing-pkce" not in got and "missing-resource-indicator" not in got


def test_transitive_inheritance_resolves(tmp_path: Path) -> None:
    (tmp_path / "base.py").write_text(_BASE, encoding="utf-8")
    (tmp_path / "mid.py").write_text("from base import OAuthProxy\nclass Mid(OAuthProxy):\n    pass\n", encoding="utf-8")
    _mcp_write(
        tmp_path / "leaf.py",
        _SUBCLASS.replace("OAuthProxy", "Mid").replace("from base", "from mid"),
    )
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert "missing-pkce" not in got


def test_subclass_of_base_without_pkce_still_fires(tmp_path: Path) -> None:
    """Direction traded against: inheriting from a base that has NO PKCE is not a mitigation."""
    (tmp_path / "base.py").write_text("class OAuthProxy:\n    pass\n", encoding="utf-8")
    _mcp_write(tmp_path / "github.py", _SUBCLASS)
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert "missing-pkce" in got


def test_unrelated_no_config_instantiation_does_not_suppress_own_authorize_call(tmp_path: Path) -> None:
    """The review's repro: constructing a PKCE-marked class for an unrelated reason, with no
    OAuth-configuration kwarg, must not suppress a genuinely unguarded `authorize()` call
    elsewhere in the same file. Direction traded against: the pre-fix `_instantiates` matched
    on name-and-marker alone, whole-file, regardless of whether the construction is related."""
    (tmp_path / "provider.py").write_text(
        "class PkceProvider:\n    def _generate_pkce_pair(self):\n        return 'challenge', 'verifier'\n",
        encoding="utf-8",
    )
    _mcp_write(
        tmp_path / "client.py",
        "from provider import PkceProvider\n\n"
        "def do_login(client_id):\n"
        "    logger_provider = PkceProvider()\n"
        "    return authorize(client_id=client_id, response_type='code')\n",
    )
    assert "missing-pkce" in _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))


def test_instantiating_a_pkce_proxy_is_not_missing_pkce(tmp_path: Path) -> None:
    (tmp_path / "base.py").write_text(_BASE, encoding="utf-8")
    _mcp_write(
        tmp_path / "app.py",
        "from base import OAuthProxy\n"
        "auth = OAuthProxy(upstream_authorization_endpoint='https://idp.example.com/authorize')\n",
    )
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert "missing-pkce" not in got


def test_authorize_only_in_a_comment_is_not_a_call_site(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "handler.py",
        "# oauth handler: this used to call authorize(client_id=...) directly\n"
        "def noop():\n    return None\n",
    )
    assert McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_real_authorize_call_next_to_a_docstring_mention_still_fires(tmp_path: Path) -> None:
    """Direction traded against: blanking docstring CONTENT must not blank the real call site
    that follows it in the same file."""
    _mcp_write(
        tmp_path / "client.py",
        'def start_flow():\n'
        '    """See oauth/authorize in the upstream docs for background."""\n'
        '    return authorize(client_id="abc123")\n',
    )
    assert "missing-pkce" in _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))


def test_authorization_endpoint_field_on_a_plain_data_schema_is_not_missing_pkce(tmp_path: Path) -> None:
    """The review's repro (sampled live on python-sdk's real OAuthMetadata): a field DECLARATION
    on a metadata/data-schema class is not a call site, the same annotation exclusion the sibling
    resource-indicator anchor already has."""
    _mcp_write(
        tmp_path / "auth.py",
        "from pydantic import BaseModel\n\n"
        "class OAuthMetadata(BaseModel):\n"
        "    issuer: str\n"
        "    authorization_endpoint: str\n"
        "    token_endpoint: str\n"
        "    client_id: str\n",
    )
    assert "missing-pkce" not in _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))


def test_authorize_only_in_a_docstring_example_is_not_a_call_site(tmp_path: Path) -> None:
    """The review's repro (sampled live on python-sdk's exceptions.py): a docstring's example
    prose mentioning `oauth/authorize` is not a call site. The whole-line `#` comment blanking
    never reached text inside a triple-quoted docstring block."""
    _mcp_write(
        tmp_path / "exceptions.py",
        'class TokenError(Exception):\n'
        '    """Raised when a token request fails.\n\n'
        '    Example:\n'
        '        See the docs at oauth/authorize for the auth flow, then POST /oauth/token.\n'
        '    """\n',
    )
    assert McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


# ── bearer-only-no-dpop needs a CLIENT-SIDE call site ────────────────────────

def test_server_side_bearer_challenge_is_not_bearer_only_client(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "middleware.py",
        "# oauth resource server middleware\n"
        "def challenge(resource_metadata):\n"
        "    headers = {'WWW-Authenticate': f'Bearer error=\"invalid_token\", resource_metadata=\"{resource_metadata}\"'}\n"
        "    if 'Authorization' not in request.headers:\n"
        "        return 401, headers\n",
    )
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert "bearer-only-no-dpop" not in got


def test_client_bearer_assignment_still_fires_bearer_only(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "client.py",
        "# oauth client\nrequest.headers['Authorization'] = f'Bearer {token}'\n",
    )
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert "bearer-only-no-dpop" in got


# ── `grant_type` only counts as a request field ──────────────────────────────

def test_grant_type_annotation_and_constant_are_not_token_requests(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "helpers.py",
        "# oauth helpers\n"
        "DEVICE_AUTH_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code'\n"
        "def build(url: str, *, grant_type: str = 'authorization_code', token_endpoint: str = '') -> None:\n"
        "    return None\n",
    )
    assert "missing-resource-indicator" not in _rules(
        McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    )


def test_grant_type_dict_field_still_fires_resource_indicator(tmp_path: Path) -> None:
    _mcp_write(
        tmp_path / "req.py",
        "# oauth\ndata = {'grant_type': 'client_credentials'}\n",
    )
    assert "missing-resource-indicator" in _rules(
        McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))
    )


# ── locations carry a line; absence rules are review signals ─────────────────

def test_findings_carry_line_numbers_and_absence_rules_are_surfacing(tmp_path: Path) -> None:
    from agentsec.findings import _is_review_finding

    _mcp_write(
        tmp_path / "oauth_client.py",
        "# oauth client\n\n"
        "def go(client_id):\n"
        "    return authorize(client_id=client_id, redirect_uri='*')\n",
    )
    by_rule = {f.rule.split("/")[-1]: f for f in
               McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path))}
    # Line 5: the fixture's own line 4, after the one-line MCP import `_mcp_write` puts first.
    assert by_rule["missing-pkce"].location.endswith("oauth_client.py:5")
    assert by_rule["wildcard-redirect-uri"].location.endswith("oauth_client.py:5")
    assert _is_review_finding(by_rule["missing-pkce"]) is True
    assert _is_review_finding(by_rule["wildcard-redirect-uri"]) is False


def test_deeply_nested_json_file_does_not_zero_the_guard(tmp_path: Path) -> None:
    """One hostile deep-nesting file used to raise RecursionError out of the schema-document probe;
    the real wildcard-redirect finding next to it must survive."""
    (tmp_path / "deep.json").write_text('{"oauth": ' + '[' * 200_000 + ']' * 200_000 + "}", encoding="utf-8")
    (tmp_path / "mcp.json").write_text(_LIVE_CONFIG, encoding="utf-8")
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert "wildcard-redirect-uri" in got


# ── round-3 follow-up: class-call scan, S256 advertisement ────────────────

def test_class_call_scan_is_linear_on_unclosed_calls() -> None:
    """The round-3 `_CALLED_CLASS_RE` wrapped `[^()]*` in a repeated group with an optional
    nested-paren alternative, which backtracks exponentially on an unclosed or doubly-nested call
    (1.1 s at 22 characters, and python-sdk never finished). The paren-stack scan is linear."""
    from agentsec.guards.mcp_oauth_flow_hardening import _instantiates
    from tests._timing import assert_growth

    def scan(n: int) -> object:
        return _instantiates(("OAuthProxy(" + "x" * 30 + "(a(b)\n") * n, {"OAuthProxy"})

    assert_growth(scan, [1_000, 2_000, 4_000, 8_000], expected="linear")


def test_class_call_scan_is_linear_on_deeply_nested_calls() -> None:
    """Deep, well-formed nesting (a minified bundle's shape): slicing each call's arguments made
    this quadratic (11.8 s at 40,000 levels). Offsets plus a sorted kwarg index keep it linear."""
    from agentsec.guards.mcp_oauth_flow_hardening import _instantiates
    from tests._timing import assert_growth

    def scan(n: int) -> object:
        return _instantiates("OAuthProxy(" * n + "x" + ")" * n, {"OAuthProxy"})

    assert_growth(scan, [10_000, 20_000, 40_000, 80_000], expected="linear")


def test_paren_inside_a_string_does_not_let_a_call_swallow_the_file(tmp_path: Path) -> None:
    """A stray `(` inside a string in a PKCE class's own positional argument must not unbalance
    the paren pairing: the call would then capture the later, unrelated `authorize(client_id=...)`
    as its arguments, and those kwargs would vouch for PKCE that is not there. (The PKCE class
    lives in another file; a file that defines it carries file-wide PKCE evidence anyway.)"""
    (tmp_path / "provider.py").write_text(
        "class OAuthProxy:\n    def _generate_pkce_pair(self):\n        return 'c', 'v'\n",
        encoding="utf-8",
    )
    _mcp_write(
        tmp_path / "client.py",
        "from provider import OAuthProxy\n"
        'x = OAuthProxy("see (draft")\n\n'
        "def start_login(client_id):\n"
        "    return authorize(client_id=client_id, response_type='code')\n",
    )
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert "missing-pkce" in got


@pytest.mark.parametrize(
    ("provider", "client"),
    [
        (
            ("provider.py", "class OAuthProxy:\n    def _generate_pkce_pair(self):\n        return 'c', 'v'\n"),
            (
                "client.py",
                "from provider import OAuthProxy\n"
                'x = OAuthProxy("""see (draft\nmulti-line note""")\n\n'
                "def start_login(client_id):\n"
                "    return authorize(client_id=client_id, response_type='code')\n",
            ),
        ),
        (
            ("provider.ts", "export class OAuthProxy { gen() { return code_verifier; } }\n"),
            (
                "client.ts",
                "import { OAuthProxy } from './provider';\n"
                "const x = new OAuthProxy(`see (draft`);\n"
                "const cfg = 1;\n\n"
                "function startLogin(clientId) {\n"
                "  return authorize(clientId, 'code');\n"
                "}\n",
            ),
        ),
        (
            ("provider.py", "class OAuthProxy:\n    def _generate_pkce_pair(self):\n        return 'c', 'v'\n"),
            (
                "client.py",
                "from provider import OAuthProxy\n"
                "x = OAuthProxy(\n"
                "# note: uses `unclosed backtick here, no partner on this line\n"
                ")\n\n"
                "# stray closer in a second comment`\n"
                "def start_login(client_id):\n"
                "    return authorize(client_id=client_id, response_type='code')\n",
            ),
        ),
        (
            ("provider.ts", "export class OAuthProxy { gen() { return code_verifier; } }\n"),
            (
                "client.ts",
                "import { OAuthProxy } from './provider';\n"
                "const x = new OAuthProxy(someValue\n"
                "  * factor);\n"
                "const cfg = 1;\n\n"
                "function startLogin(clientId) {\n"
                "  return authorize(clientId, 'code');\n"
                "}\n",
            ),
        ),
        (
            ("provider.ts", "export class OAuthProxy { gen() { return code_verifier; } }\n"),
            (
                "client.ts",
                "import { OAuthProxy } from './provider';\n"
                "const x = new OAuthProxy(/* see (draft */ someValue);\n"
                "const y = new OAuthProxy(v); // see `draft\n"
                "const cfg = 1; // closes it`\n\n"
                "function startLogin(clientId) {\n"
                "  return authorize(clientId, 'code');\n"
                "}\n",
            ),
        ),
        (
            ("provider.py", "class OAuthProxy:\n    def _generate_pkce_pair(self):\n        return 'c', 'v'\n"),
            (
                "client.py",
                "from provider import OAuthProxy\n"
                "x = OAuthProxy(value  # see (draft\n"
                ")\n\n"
                "def start_login(client_id):\n"
                "    return authorize(client_id=client_id, response_type='code')\n",
            ),
        ),
    ],
    ids=[
        "python-triple-quoted", "ts-template-literal", "python-backticks-in-comments",
        "ts-star-continuation-line", "ts-block-and-inline-comments", "python-inline-comment",
    ],
)
def test_paren_inside_a_multiline_or_template_string_does_not_swallow_the_file(
    tmp_path: Path, provider: tuple[str, str], client: tuple[str, str]
) -> None:
    """The same spillover through the two string forms a one-line mask misses: a Python
    triple-quoted string and a JS/TS template literal (which needs no kwarg nearby; any later
    `cfg = 1` would do)."""
    (tmp_path / provider[0]).write_text(provider[1], encoding="utf-8")
    _mcp_write(tmp_path / client[0], client[1])
    prof = mkprofile(tmp_path, features={"mcp", "python", "typescript"}, python_dirs=["."])
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, prof))
    assert "missing-pkce" in got


def test_client_holding_fetched_as_metadata_still_fires_missing_pkce(tmp_path: Path) -> None:
    """Direction traded against the S256 evidence: a CLIENT storing discovery metadata it
    fetched (a quoted dict key) says nothing about its own flow, so its PKCE-less authorize call
    still fires."""
    _mcp_write(
        tmp_path / "client.py",
        "AS_METADATA = {\n"
        "    'authorization_endpoint': 'https://auth.example.com/authorize',\n"
        "    'code_challenge_methods_supported': ['S256'],\n"
        "}\n\n"
        "def start_login(client_id):\n"
        "    return authorize(client_id=client_id, response_type='code')\n",
    )
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert "missing-pkce" in got


def test_doubly_nested_pkce_proxy_construction_still_vouches(tmp_path: Path) -> None:
    """fastmcp's shape with two levels of nesting in an argument: the construction configures a
    PKCE-implementing proxy, so it is not missing PKCE. The one-level regex could not match it."""
    (tmp_path / "provider.py").write_text(
        "class OAuthProxy:\n    def _generate_pkce_pair(self):\n        return 'c', 'v'\n",
        encoding="utf-8",
    )
    _mcp_write(
        tmp_path / "server.py",
        "from provider import OAuthProxy\n"
        "auth = OAuthProxy(upstream_authorization_endpoint=Url(str(BASE)), client_id='abc')\n",
    )
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert "missing-pkce" not in got


def test_as_metadata_advertising_s256_is_not_missing_pkce(tmp_path: Path) -> None:
    """python-sdk's `server/auth/routes.py` shape: an authorization server building its RFC 8414
    metadata passes `authorization_endpoint=` and advertises S256. That is PKCE support, not a
    client flow missing it."""
    _mcp_write(
        tmp_path / "routes.py",
        "metadata = OAuthMetadata(\n"
        "    issuer=issuer_url,\n"
        "    authorization_endpoint=authorization_url,\n"
        "    token_endpoint=token_url,\n"
        '    code_challenge_methods_supported=["S256"],\n'
        ")\n",
    )
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert "missing-pkce" not in got


def test_as_metadata_advertising_only_plain_still_fires_missing_pkce(tmp_path: Path) -> None:
    """Direction traded against: advertising only `plain` is not S256 PKCE support."""
    _mcp_write(
        tmp_path / "routes.py",
        "metadata = OAuthMetadata(\n"
        "    authorization_endpoint=authorization_url,\n"
        '    code_challenge_methods_supported=["plain"],\n'
        ")\n",
    )
    got = _rules(McpOauthFlowHardeningGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert "missing-pkce" in got


# ── #1023: findings anchor only on the MCP surface ──────────────────────────────

_FLOW_PY = (  # the canary shape: fires missing-pkce and missing-resource-indicator
    "def start_login(client_id):\n"
    "    return authorize(client_id=client_id, response_type='code')\n"
)
_FLOW_TS = (  # remote-mcp-server-with-auth's handler shape: no `resource` anywhere
    "const app = new Hono();\n"
    'app.get("/authorize", async (c) => {\n'
    "  const oauthReq = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);\n"
    "  return redirect(oauthReq.clientId);\n"
    "});\n"
)


def _ts_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "typescript"})


def _anchors(root: Path, prof: StackProfile | None = None) -> set[str]:
    """`path::rule` per finding, the path with forward slashes: `rel()` keeps the OS separator, so
    on Windows a raw location never equals a `/` key and a `not any(a.startswith(...))` FP-bait
    assertion would pass vacuously."""
    findings = McpOauthFlowHardeningGuard().run(root, prof or _mcp_prof(root))
    return {
        f"{f.location.replace(chr(92), '/').rsplit(':', 1)[0]}::{f.rule.split('/')[-1]}" for f in findings
    }


def test_same_flow_fires_on_the_surface_and_is_silent_off_it(tmp_path: Path) -> None:
    """The narrowing and the direction it traded against, on one fixture: an MCP module's
    unmitigated flow still fires; the identical flow in a module nothing MCP touches does not."""
    _mcp_write(tmp_path / "mcp_server.py", _FLOW_PY)
    (tmp_path / "billing_sso.py").write_text(_FLOW_PY, encoding="utf-8")
    got = _anchors(tmp_path)
    assert "mcp_server.py::missing-pkce" in got
    assert not any(a.startswith("billing_sso.py::") for a in got)


def test_one_hop_ts_handler_imported_by_the_mcp_entry_fires(tmp_path: Path) -> None:
    """remote-mcp-server-with-auth: `src/auth/github-handler.ts` imports no MCP SDK, but the
    entry point that does imports it, so both files anchor `missing-resource-indicator`."""
    (tmp_path / "src" / "auth").mkdir(parents=True)
    (tmp_path / "src" / "index.ts").write_text(
        'import OAuthProvider from "@cloudflare/workers-oauth-provider";\n'
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        'import { GitHubHandler } from "./auth/github-handler";\n'
        "export default new OAuthProvider({\n"
        '  authorizeEndpoint: "/authorize",\n'
        '  tokenEndpoint: "/token",\n'
        "  defaultHandler: GitHubHandler,\n"
        "});\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "auth" / "github-handler.ts").write_text(_FLOW_TS, encoding="utf-8")
    got = _anchors(tmp_path, _ts_prof(tmp_path))
    assert "src/index.ts::missing-resource-indicator" in got
    assert "src/auth/github-handler.ts::missing-resource-indicator" in got


@pytest.mark.parametrize(
    ("spec", "target"),
    [
        ("./auth/handler.js", "src/auth/handler.ts"),  # ESM: a `.js` specifier names the `.ts` source
        ("./auth", "src/auth/index.ts"),  # a directory import resolves to its index module
        ("../lib/handler", "lib/handler.tsx"),
    ],
    ids=["esm-js-to-ts", "dir-index", "parent-dir-tsx"],
)
def test_one_hop_ts_specifier_shapes_resolve(tmp_path: Path, spec: str, target: str) -> None:
    _mcp_write(tmp_path / "src" / "server.ts", f'import {{ handler }} from "{spec}";\n')
    (tmp_path / target).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / target).write_text(_FLOW_TS, encoding="utf-8")
    assert f"{target}::missing-resource-indicator" in _anchors(tmp_path, _ts_prof(tmp_path))


@pytest.mark.parametrize(
    ("server_import", "target"),
    [
        ("from .auth import start_login\n", "myserver/auth.py"),
        ("from . import auth\n", "myserver/auth.py"),
        ("from myserver.auth import start_login  # noqa: F401\n", "myserver/auth.py"),
        ("import myserver.auth as auth\n", "myserver/auth.py"),
        ("from ..shared import oauth\n", "shared/oauth.py"),
        ("from myserver.auth import (\n    start_login,\n)\n", "myserver/auth/__init__.py"),
    ],
    ids=["relative-module", "relative-submodule", "absolute-from", "absolute-import",
         "parent-relative", "package-init"],
)
def test_one_hop_python_import_shapes_resolve(tmp_path: Path, server_import: str, target: str) -> None:
    _mcp_write(tmp_path / "myserver" / "server.py", server_import)
    (tmp_path / target).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / target).write_text(_FLOW_PY, encoding="utf-8")
    assert f"{target}::missing-pkce" in _anchors(tmp_path)


def test_two_hop_helper_does_not_anchor(tmp_path: Path) -> None:
    """The radius is pinned at ONE hop, so widening it is a deliberate change: the module the MCP
    server imports anchors, the helper that module imports does not."""
    _mcp_write(tmp_path / "srv" / "server.py", "from .auth import start_login\n")
    (tmp_path / "srv" / "auth.py").write_text("from .helpers import go\n" + _FLOW_PY, encoding="utf-8")
    (tmp_path / "srv" / "helpers.py").write_text(_FLOW_PY, encoding="utf-8")
    got = _anchors(tmp_path)
    assert "srv/auth.py::missing-pkce" in got
    assert not any(a.startswith("srv/helpers.py::") for a in got)


def test_non_mcp_oauth_in_an_mcp_repo_is_silent(tmp_path: Path) -> None:
    """langfuse's shapes: a NextAuth credentials provider and a Slack installer, in a repo whose
    MCP server imports neither. Both used to fire gating HIGHs once `mcp` was on."""
    _mcp_write(tmp_path / "web" / "src" / "features" / "mcp" / "server" / "index.ts",
               'import { registerTools } from "./tools";\n')
    (tmp_path / "web" / "src" / "server").mkdir(parents=True)
    (tmp_path / "web" / "src" / "server" / "auth.ts").write_text(
        "export const authOptions = { providers: [CredentialsProvider({\n"
        "  async authorize(credentials, _req) { return checkPassword(credentials); },\n"
        "})], clientId: env.AUTH_CLIENT_ID };\n// oauth providers below\n",
        encoding="utf-8",
    )
    (tmp_path / "web" / "src" / "slack").mkdir(parents=True)
    (tmp_path / "web" / "src" / "slack" / "SlackService.ts").write_text(
        "// Slack oauth installer\n"
        "const res = await this.installer.authorize({ teamId, client_id: CLIENT_ID });\n",
        encoding="utf-8",
    )
    assert _anchors(tmp_path, _ts_prof(tmp_path)) == set()


@pytest.mark.parametrize(
    "name",
    ["src/routeTree.gen.ts", "packages/api-types/types/api-v1.d.ts"],
    ids=["gen-ts", "d-ts"],
)
def test_generated_and_declaration_files_never_anchor(tmp_path: Path, name: str) -> None:
    """Even carrying an MCP import (so the surface rule alone would let them anchor), a generated
    module and a type declaration are not OAuth flows. The control is the same text in an
    ordinary module, which fires."""
    body = "export interface paths { '/v1/oauth/authorize': { get: operations['authorize'] } }\n"
    _mcp_write(tmp_path / name, body)
    _mcp_write(tmp_path / "src" / "ordinary.ts", body)
    got = _anchors(tmp_path, _ts_prof(tmp_path))
    assert "src/ordinary.ts::missing-resource-indicator" in got
    assert not any(a.startswith(f"{name}::") for a in got)


def test_artifact_imported_by_the_mcp_entry_never_anchors(tmp_path: Path) -> None:
    """One hop puts a generated module the MCP entry imports on the surface, so the artifact skip
    on the ANCHOR is what keeps it silent. The hand-written sibling it also imports still fires."""
    _mcp_write(tmp_path / "src" / "server.ts",
               'import { routeTree } from "./routeTree.gen";\nimport { h } from "./handler";\n')
    (tmp_path / "src" / "routeTree.gen.ts").write_text(_FLOW_TS, encoding="utf-8")
    (tmp_path / "src" / "handler.ts").write_text(_FLOW_TS, encoding="utf-8")
    got = _anchors(tmp_path, _ts_prof(tmp_path))
    assert "src/handler.ts::missing-resource-indicator" in got
    assert not any(a.startswith("src/routeTree.gen.ts::") for a in got)


def test_generated_mcp_entry_still_extends_to_hand_written_auth(tmp_path: Path) -> None:
    """A codegen'd MCP server (an openapi-to-MCP generator's output) never anchors itself, but the
    hand-written auth module it imports is MCP OAuth and still fires."""
    _mcp_write(tmp_path / "src" / "server.gen.ts", 'import { handler } from "./auth";\n' + _FLOW_TS)
    (tmp_path / "src" / "auth.ts").write_text(_FLOW_TS, encoding="utf-8")
    got = _anchors(tmp_path, _ts_prof(tmp_path))
    assert "src/auth.ts::missing-resource-indicator" in got
    assert not any(a.startswith("src/server.gen.ts::") for a in got)


def test_generated_header_never_anchors(tmp_path: Path) -> None:
    _mcp_write(tmp_path / "gen" / "client.ts", "// @generated by openapi-typescript. Do not edit.\n" + _FLOW_TS)
    _mcp_write(tmp_path / "src" / "client.ts", "// written by hand\n" + _FLOW_TS)
    got = _anchors(tmp_path, _ts_prof(tmp_path))
    assert "src/client.ts::missing-resource-indicator" in got
    assert not any(a.startswith("gen/client.ts::") for a in got)


def test_snapshot_and_lockfile_never_anchor(tmp_path: Path) -> None:
    """A test snapshot named like an MCP config (so it would be a config marker) and a lockfile
    full of OAuth package keys, next to a real MCP server. The control is the same config text
    outside `__snapshots__/`, which fires."""
    cfg = '{"client_id": "abc", "authorization_endpoint": "https://auth.example.com", "redirect_uri": "*"}'
    (tmp_path / "web" / "__snapshots__").mkdir(parents=True)
    (tmp_path / "web" / "__snapshots__" / "mcp.json").write_text(cfg, encoding="utf-8")
    (tmp_path / "mcp.json").write_text(cfg, encoding="utf-8")
    (tmp_path / "pnpm-lock.yaml").write_text(
        "packages:\n"
        "  '@aws-sdk/token-providers@3.1.0':\n    resolution: {integrity: sha512-x}\n"
        "  'oauth4webapi@2.0.0':\n    resolution: {integrity: sha512-y}\n"
        "  '@modelcontextprotocol/sdk@1.0.0':\n    resolution: {integrity: sha512-z}\n"
        "mcpServers: {}\n",  # a config marker, so the artifact skip is what keeps this silent
        encoding="utf-8",
    )
    got = _anchors(tmp_path)
    assert "mcp.json::wildcard-redirect-uri" in got
    assert not any(a.startswith(("web/__snapshots__/", "pnpm-lock.yaml")) for a in got)


def test_gateway_config_without_mcp_marker_is_silent(tmp_path: Path) -> None:
    """supabase's `docker/volumes/api/kong.yml`: an API gateway's OAuth routes, no MCP marker."""
    (tmp_path / "kong.yml").write_text(
        "services:\n  - name: auth-v1-open-authorize\n    url: http://auth:9999/authorize\n"
        "    routes:\n      - paths: [/auth/v1/authorize]\n# oauth\n",
        encoding="utf-8",
    )
    assert _anchors(tmp_path) == set()


@pytest.mark.parametrize(
    ("name", "anchors"),
    [
        ("supabase/config.toml", False),  # supabase's own auth config: not an MCP file
        ("mcp_config.toml", True),
        (".mcp/auth.toml", True),
        ("codex.toml", False),
    ],
)
def test_config_markers(tmp_path: Path, name: str, anchors: bool) -> None:
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(
        '[auth.external.github]\nclient_id = "abc"\nredirect_uri = "*"\n', encoding="utf-8"
    )
    assert (f"{name}::wildcard-redirect-uri" in _anchors(tmp_path)) is anchors


def test_mcp_servers_key_marks_a_config(tmp_path: Path) -> None:
    (tmp_path / "codex.toml").write_text(
        '[mcp_servers.remote]\nurl = "https://mcp.example.com"\nclient_id = "abc"\nredirect_uri = "*"\n',
        encoding="utf-8",
    )
    assert "codex.toml::wildcard-redirect-uri" in _anchors(tmp_path)


@pytest.mark.parametrize(
    ("name", "marker"),
    [
        ("worker.ts", 'import { McpAgent } from "agents/mcp";\n'),  # Cloudflare, no SDK import
        ("route.ts", 'const { createMcpHandler } = require("mcp-handler");\n'),
        ("srv.py", "import fastmcp\n"),
    ],
    ids=["cloudflare-agents", "vercel-mcp-handler", "fastmcp"],
)
def test_non_sdk_mcp_framework_markers(tmp_path: Path, name: str, marker: str) -> None:
    (tmp_path / name).write_text(marker + (_FLOW_PY if name.endswith(".py") else _FLOW_TS), encoding="utf-8")
    prof = mkprofile(tmp_path, features={"mcp", "python", "typescript"}, python_dirs=["."])
    assert f"{name}::missing-resource-indicator" in _anchors(tmp_path, prof)


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("a.py", "# from mcp.server.fastmcp import FastMCP\n" + _FLOW_PY),
        ("b.py", '"""\nfrom mcp import types\n"""\n' + _FLOW_PY),
        ("c.ts", "// import { McpServer } from '@modelcontextprotocol/sdk';\n" + _FLOW_TS),
        ("d.ts", "/*\nimport { McpServer } from '@modelcontextprotocol/sdk';\n*/\n" + _FLOW_TS),
        ("e.py", "from mcpx import tools\nimport mcp_utils\n" + _FLOW_PY),
        ("f.ts", "// MCP server helpers\nconst mcpServer = new McpServer();\n" + _FLOW_TS),
    ],
    ids=["py-comment", "py-docstring", "ts-line-comment", "ts-block-comment",
         "py-lookalike-package", "ts-identifier-only"],
)
def test_marker_must_be_a_real_import(tmp_path: Path, name: str, text: str) -> None:
    (tmp_path / name).write_text(text, encoding="utf-8")
    prof = mkprofile(tmp_path, features={"mcp", "python", "typescript"}, python_dirs=["."])
    assert _anchors(tmp_path, prof) == set()


def test_test_path_marker_does_not_extend_the_surface(tmp_path: Path) -> None:
    """A test that imports the MCP SDK and some product module is not evidence the product module
    is MCP code. The direction traded against, a product marker importing it, is
    `test_one_hop_python_import_shapes_resolve`."""
    _mcp_write(tmp_path / "tests" / "test_server.py", "from app.auth import start_login\n")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "auth.py").write_text(_FLOW_PY, encoding="utf-8")
    assert _anchors(tmp_path) == set()


def test_pragma_on_the_mcp_entry_does_not_silence_the_module_it_imports(tmp_path: Path) -> None:
    """The pragma stays a whole-file opt-out for the file it is written in, nothing wider."""
    _mcp_write(tmp_path / "srv" / "server.py",
               "# security: allow-mcp-oauth-flow-hardening\nfrom .auth import start_login\n" + _FLOW_PY)
    (tmp_path / "srv" / "auth.py").write_text(_FLOW_PY, encoding="utf-8")
    got = _anchors(tmp_path)
    assert "srv/auth.py::missing-pkce" in got
    assert not any(a.startswith("srv/server.py::") for a in got)


@pytest.mark.parametrize(
    "base_file",
    ["vendor_auth/proxy.py", "vendor_auth/generated_proxy.py"],
    ids=["non-mcp-module", "generated-artifact"],
)
def test_pkce_base_off_the_surface_still_vouches_for_its_mcp_subclass(tmp_path: Path, base_file: str) -> None:
    """Rule 4: the surface narrows where a finding may ANCHOR, never what the class index reads.
    The base is neither an MCP module nor imported by one (the subclass names it through a
    package this tree does not contain), and in the second case it is a generated artifact too.
    Its own unmitigated `authorize(` proves it is off the surface: on it, that would fire."""
    header = "# @generated by authgen. Do not edit.\n" if "generated" in base_file else ""
    (tmp_path / "vendor_auth").mkdir()
    (tmp_path / base_file).write_text(
        header + _BASE + "    def legacy(self):\n        return authorize(client_id=self.client_id)\n",
        encoding="utf-8",
    )
    _mcp_write(tmp_path / "server.py", "from authlib_shim import OAuthProxy\n" + _SUBCLASS.split("\n", 1)[1])
    got = _anchors(tmp_path)
    assert not any(a.startswith(base_file) for a in got)
    assert "server.py::missing-pkce" not in got


def test_subclass_of_a_base_without_pkce_off_the_surface_still_fires(tmp_path: Path) -> None:
    """Direction traded against the test above: an off-surface base with no PKCE vouches nothing."""
    (tmp_path / "vendor_auth").mkdir()
    (tmp_path / "vendor_auth" / "proxy.py").write_text("class OAuthProxy:\n    pass\n", encoding="utf-8")
    _mcp_write(tmp_path / "server.py", "from authlib_shim import OAuthProxy\n" + _SUBCLASS.split("\n", 1)[1])
    assert "server.py::missing-pkce" in _anchors(tmp_path)


# ── #1023: the localhost arm of wildcard-redirect-uri ───────────────────────────

@pytest.mark.parametrize(
    ("value", "fires"),
    [
        ('"http://localhost"', True),
        ('"http://localhost/"', True),
        ("'*'", True),
        ('"https://*"', True),
        # A port or path wildcard is the opposite of a pin, so it still fires (#1027 R1-H1).
        ('"http://localhost:*"', True),
        ('"http://localhost/*"', True),
        ('"http://localhost:*/cb"', True),
        ('"http://localhost:3000/*"', True),
        ('"http://localhost:3000/confirm"', False),  # supabase's config.toml value
        ('"http://localhost:3000"', False),
        ('"http://localhost/callback"', False),
        ('"http://localhost.evil.com/cb"', False),
        ('"https://app.example.com/cb"', False),
        # The wildcard scan stops at the closing quote: a `*` in the NEXT value is not the URI's.
        ('"http://localhost:3000/cb", \'scope\': \'*\'', False),
        # ... and at a query, fragment or list separator inside the same string (#1027 R2-L1).
        ('"http://localhost:3000/cb&scope=*"', False),
        ('"http://localhost:3000/cb?x=*"', False),
        ('"http://localhost:3000/cb#*"', False),
        ('"http://localhost:3000/cb,*"', False),
        ('"http://localhost:*/cb?x=1"', True),
        ('"http://localhost/*?next=1"', True),
        ('"http://localhost:*,http://localhost:3000"', True),  # a wildcard FIRST entry still fires
        # Pinned boundary, a documented bypass (#1027 R3-L1): the scan stops at the separator, so a
        # wildcard in a LATER entry is not seen. Widening this is a deliberate change.
        ('"http://localhost:3000/cb,http://localhost:*"', False),
    ],
)
def test_localhost_redirect_fires_only_when_bare(tmp_path: Path, value: str, fires: bool) -> None:
    _mcp_write(tmp_path / "oauth_config.py", f"OAUTH = {{'client_id': 'abc', 'redirect_uri': {value}}}\n")
    assert ("oauth_config.py::wildcard-redirect-uri" in _anchors(tmp_path)) is fires


@pytest.mark.parametrize(
    ("name", "text", "fires"),
    [
        ("mcp.yaml", "client_id: abc\nredirect_uri: http://localhost\n", True),
        ("mcp.yaml", "client_id: abc\nredirect_uri: http://localhost:8080/cb\n", False),
        ("mcp.toml", 'client_id = "abc"\nredirect_uri = http://localhost', True),  # unquoted, at EOF
        ("mcp.yaml", "client_id: abc\nredirect_uri: http://localhost:*\n", True),
        ("mcp.yaml", "client_id: abc\nredirect_uri: http://localhost:8080/cb  # not *\n", False),
        ("mcp.yaml", "client_id: abc\nredirect_uri: http://localhost:3000/cb,scope=*\n", False),
    ],
    ids=["yaml-bare", "yaml-pinned", "unquoted-eof", "yaml-port-wildcard", "yaml-pinned-star-after",
         "yaml-pinned-comma-star"],
)
def test_localhost_redirect_in_config_shapes(tmp_path: Path, name: str, text: str, fires: bool) -> None:
    (tmp_path / name).write_text(text, encoding="utf-8")
    assert (f"{name}::wildcard-redirect-uri" in _anchors(tmp_path)) is fires


# ── #1023: the artifact predicate itself ────────────────────────────────────────

@pytest.mark.parametrize(
    ("key", "head", "artifact"),
    [
        ("pnpm-lock.yaml", "", True),
        ("web/package-lock.json", "", True),
        ("npm-shrinkwrap.json", "", True),
        ("apps/studio/routeTree.gen.ts", "", True),
        ("types/api-v1.d.ts", "", True),
        ("src/__snapshots__/auth.test.ts.snap.json", "", True),
        ("src/client.ts", "// @generated\n", True),
        ("src/client.py", "# Code generated by protoc. DO NOT EDIT.\n", True),
        ("src/generator.ts", "", False),
        ("src/gen.ts", "", False),
        ("src/token-generated.ts", "", False),
        ("src/client.ts", "// the token is generated server-side\n", False),
        ("src/client.ts", "\n" * 12 + "// @generated\n", False),  # past the header window
        ("snapshots/mcp.json", "", False),
    ],
)
def test_is_artifact(key: str, head: str, artifact: bool) -> None:
    from agentsec.guards.mcp_oauth_flow_hardening import _is_artifact

    assert _is_artifact(key, head + "const x = 1;\n") is artifact


def test_mcp_surface_scan_is_linear_on_long_whitespace_runs() -> None:
    """`import\\s*\\(?\\s*['"]` backtracked quadratically on a whitespace run after `import` (1.3 s at
    20,000 characters). The marker and import-resolution regexes must stay linear."""
    from agentsec.guards.mcp_oauth_flow_hardening import _JS_MCP_IMPORT_RE, _js_targets
    from tests._timing import assert_growth

    def scan(n: int) -> object:
        text = ("import" + " " * n + "x;\nrequire" + " " * n + "(x);\n") * 4
        return (_JS_MCP_IMPORT_RE.search(text), _js_targets("src/a.ts", text))

    assert_growth(scan, [5_000, 10_000, 20_000, 40_000], expected="linear")


@pytest.mark.parametrize(
    ("make", "copies"),
    [
        # `(\.*)([\w.]*)` both matched a dot: a long dot run backtracked quadratically (#1027 R1-M1).
        (lambda n: "from " + "." * n + "x\n", 16),
        # `\([^)]*\)` ran to EOF from every unclosed `(` line: quadratic in the line count.
        (lambda n: "from a import (\n" * (n // 16), 4),
        # With the module optional, `from[ \t]+` and `[ \t]+import` split one space run (#1027 R2-L2).
        (lambda n: "from " + " " * n + "x\n", 64),
    ],
    ids=["dot-run", "unclosed-parens", "space-run"],
)
def test_python_import_resolution_is_linear(make: Callable[[int], str], copies: int) -> None:
    # `copies` repeats the input so the healthy readings are tens of milliseconds, not one or two:
    # a ratio of ms-scale readings is what a scheduling stall turns into `quadratic` (#758), and it
    # did, on the self-hosted Windows leg, where one copy read 0.2-6 ms. Measured there (2026-11-06)
    # with these copies: healthy 11-116 ms across the sizes, linear. The copies scale a reintroduced
    # quadratic too (its top reading would be 30-180 s), so `ceiling` is 10 s rather than the default
    # 60 s: still ~80x the healthy top reading, and the probe stops a broken regex early instead of
    # running it to the default ceiling (a stopped series is `indeterminate`, which fails as well).
    from agentsec.guards.mcp_oauth_flow_hardening import _py_targets
    from tests._timing import assert_growth

    assert_growth(lambda n: _py_targets("srv/server.py", make(n) * copies), [5_000, 10_000, 20_000, 40_000],
                  expected="linear", ceiling=10.0)


def test_wildcard_redirect_scan_is_linear() -> None:
    """The localhost `*` scan ran to the next separator from every `redirect_uri=http://localhost:`
    start, so one long unbroken line backtracked quadratically (4 s at 240 KB). It is bounded now
    (#1027 R3-M1)."""
    from agentsec.guards.mcp_oauth_flow_hardening import _WILDCARD_REDIRECT_RE
    from tests._timing import assert_growth

    assert_growth(lambda n: _WILDCARD_REDIRECT_RE.search("redirect_uri=http://localhost:" * (n // 30)),
                  [10_000, 20_000, 40_000, 80_000], expected="linear")


def test_python_import_resolution_after_the_linearity_fix() -> None:
    """The bounded paren group and the identifier-led module still resolve the ordinary shapes."""
    from agentsec.guards.mcp_oauth_flow_hardening import _py_targets

    got = _py_targets(
        "srv/server.py",
        "from . import auth\nfrom ..shared import oauth\nfrom .tools import (\n    a,\n    b,\n)\n",
    )
    assert {"srv/auth.py", "shared/oauth.py", "srv/tools.py", "srv/tools/a.py", "srv/tools/b.py"} <= got


# ── #1027 R1-M2: a UTF-8 BOM must not take a Python MCP module off the surface ──────────

def test_bom_prefixed_python_mcp_module_stays_on_the_surface(tmp_path: Path) -> None:
    """`read()` keeps a leading BOM, and the `^`-anchored Python marker and import regexes did not
    match past it, so a Windows-saved MCP server silently dropped off the surface. Both the
    marker itself and its one-hop import sit on the BOM'd first line here."""
    (tmp_path / "srv").mkdir()
    (tmp_path / "srv" / "server.py").write_text(
        "\ufefffrom .auth import start_login\n" + _MCP_PY + _FLOW_PY, encoding="utf-8",
    )
    (tmp_path / "srv" / "auth.py").write_text(_FLOW_PY, encoding="utf-8")
    (tmp_path / "srv" / "solo.py").write_text("\ufeff" + _MCP_PY + _FLOW_PY, encoding="utf-8")
    got = _anchors(tmp_path)
    assert {"srv/server.py::missing-pkce", "srv/auth.py::missing-pkce", "srv/solo.py::missing-pkce"} <= got


def test_bom_prefixed_python_module_without_a_marker_stays_off_the_surface(tmp_path: Path) -> None:
    """Direction traded against the test above: stripping the BOM does not make a marker."""
    _mcp_write(tmp_path / "server.py", "")
    (tmp_path / "billing_sso.py").write_text("\ufeff" + _FLOW_PY, encoding="utf-8")
    assert not any(a.startswith("billing_sso.py::") for a in _anchors(tmp_path))


# ── #1027 R1-L3: package-absolute Python imports resolve under an ancestor (src/ layout) ──

def test_one_hop_python_package_import_from_a_src_layout(tmp_path: Path) -> None:
    """`src/pkg/server.py` importing `pkg.auth` resolves to `src/pkg/auth.py` through the `src`
    ancestor. Every other absolute-import case resolves from the scan root, so this is the one
    test that pins the ancestor search."""
    _mcp_write(tmp_path / "src" / "pkg" / "server.py", "from pkg.auth import start_login\n")
    (tmp_path / "src" / "pkg" / "auth.py").write_text(_FLOW_PY, encoding="utf-8")
    assert "src/pkg/auth.py::missing-pkce" in _anchors(tmp_path)


@pytest.mark.parametrize(
    "server_import",
    ["from .élan import start_login\n", "from . import élan\n", "import srv.élan\n"],
    ids=["relative-module", "relative-submodule", "absolute-import"],
)
def test_one_hop_python_unicode_module_name_resolves(tmp_path: Path, server_import: str) -> None:
    """A Python 3 identifier may START with a non-ASCII letter; an `[A-Za-z_]` start dropped the
    import (#1027 R2-L3). (`clé` would prove nothing: its ASCII `c` already matched.)"""
    _mcp_write(tmp_path / "srv" / "server.py", server_import)
    (tmp_path / "srv" / "élan.py").write_text(_FLOW_PY, encoding="utf-8")
    assert "srv/élan.py::missing-pkce" in _anchors(tmp_path)


# ── #424 E6 (#1000): the pragma counts only as a real comment, in the file's own grammar ──
# Self-contained (own fixtures and helper, appended last) so a merge with the #1023 surface rewrite
# is a clean take-both. Each code fixture imports an MCP SDK and each config is named `mcp.*`, so it
# stays on the MCP surface that rewrite anchors findings to.

_E6_PY = "import mcp\n\ndef start_login(client_id):\n    return authorize(client_id=client_id, response_type='code')\n"
_E6_TS = (
    "import { Client } from '@modelcontextprotocol/sdk/client/index.js';\n\n"
    "export function startLogin(clientId: string) {\n"
    "  return authorize({ client_id: clientId, response_type: 'code' });\n"
    "}\n"
)
_E6_YAML = 'oauth:\n  client_id: abc123\n  redirect_uri: "*"\n'
_E6_TOML = '[oauth]\nclient_id = "abc123"\nredirect_uri = "*"\n'
_E6_CODE_RULES = ["missing-pkce", "missing-resource-indicator"]


def _e6_rules(root: Path, name: str, text: str) -> list[str]:
    (root / name).write_text(text, encoding="utf-8")
    return sorted(f.rule.split("/")[-1] for f in McpOauthFlowHardeningGuard().run(root, _mcp_prof(root)))


def test_mcp_oauth_flow_hardening_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): the whole-file opt-out reads the comment-only view, so a Python string quoting
    # the pragma is content; only a real `#` comment (`test_pragma_suppresses_all_findings`) opts out.
    text = 'HELP = "opt out with # security: allow-mcp-oauth-flow-hardening"\n' + _E6_PY
    assert _e6_rules(tmp_path, "oauth_client.py", text) == _E6_CODE_RULES


@pytest.mark.parametrize("marker", ["//", "#"], ids=["slash-form", "hash-form"])
def test_mcp_oauth_flow_hardening_pragma_quoted_in_a_string_does_not_suppress_ts(
    tmp_path: Path, marker: str
) -> None:
    # #424 E6 (#1000): D2 widened the pragma to `//`, so a TS string quoting either comment form must
    # stay content (the CLAUDE.md rule-1 test for that widening).
    text = f'const help = "opt out with {marker} security: allow-mcp-oauth-flow-hardening";\n' + _E6_TS
    assert _e6_rules(tmp_path, "oauth_client.ts", text) == _E6_CODE_RULES


def test_mcp_oauth_flow_hardening_ts_slash_comment_pragma_suppresses(tmp_path: Path) -> None:
    # #424 E6 (#1000) D2: TS comments are `//`, and the old `#`-only regex never saw one, so the
    # documented opt-out could not be written in a .ts file at all.
    assert _e6_rules(tmp_path, "oauth_client.ts", _E6_TS) == _E6_CODE_RULES
    text = "// security: allow-mcp-oauth-flow-hardening\n" + _E6_TS
    assert _e6_rules(tmp_path, "oauth_client.ts", text) == []


def test_mcp_oauth_flow_hardening_pragma_quoted_in_a_string_does_not_suppress_yaml(tmp_path: Path) -> None:
    # #424 E6 (#1000): .yaml reads under the yaml dialect, so a quoted scalar is content, not a comment.
    text = 'name: "opt out with # security: allow-mcp-oauth-flow-hardening"\n' + _E6_YAML
    assert _e6_rules(tmp_path, "mcp.yaml", text) == ["wildcard-redirect-uri"]


def test_mcp_oauth_flow_hardening_pragma_comment_suppresses_yaml(tmp_path: Path) -> None:
    # #424 E6 (#1000): reach unchanged, a real YAML `#` comment still opts the whole file out.
    assert _e6_rules(tmp_path, "mcp.yaml", _E6_YAML) == ["wildcard-redirect-uri"]
    assert _e6_rules(tmp_path, "mcp.yaml", "# security: allow-mcp-oauth-flow-hardening\n" + _E6_YAML) == []


def test_mcp_oauth_flow_hardening_pragma_quoted_in_a_string_does_not_suppress_toml(tmp_path: Path) -> None:
    # #424 E6 (#1000): .toml reads under the quote-aware hash dialect, so a quoted value is content.
    text = 'description = "opt out with # security: allow-mcp-oauth-flow-hardening"\n' + _E6_TOML
    assert _e6_rules(tmp_path, "mcp.toml", text) == ["wildcard-redirect-uri"]


def test_mcp_oauth_flow_hardening_pragma_comment_suppresses_toml(tmp_path: Path) -> None:
    # #424 E6 (#1000): reach unchanged, a real TOML `#` comment still opts the whole file out.
    assert _e6_rules(tmp_path, "mcp.toml", _E6_TOML) == ["wildcard-redirect-uri"]
    assert _e6_rules(tmp_path, "mcp.toml", "# security: allow-mcp-oauth-flow-hardening\n" + _E6_TOML) == []
