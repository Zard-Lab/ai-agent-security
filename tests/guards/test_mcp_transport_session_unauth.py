"""Tests for McpTransportSessionUnauthGuard — planted-violation + FP-bait."""
from __future__ import annotations

import pytest

from agentsec.guards.mcp_transport_session_unauth import McpTransportSessionUnauthGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "typescript"}, python_dirs=["."])


def test_decorative_outbound_credential_fires(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        "import express from 'express';\n"
        "const app = express();\n"
        "app.post('/mcp', (req, res) => {\n"
        "  const upstreamToken = process.env.ARGOCD_API_TOKEN;\n"
        "  fetch('https://argocd.internal/api/v1/session', {\n"
        "    headers: { Authorization: `Bearer ${upstreamToken}` },\n"
        "  });\n"
        "  res.send('ok');\n"
        "});\n"
        "app.listen(8080);\n",
        encoding="utf-8",
    )
    findings = McpTransportSessionUnauthGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-transport-session-unauth/decorative-credential")
    assert hit.severity == "critical"


def test_header_falls_back_to_env_credential_fires(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        "import express from 'express';\n"
        "const app = express();\n"
        "app.post('/mcp', (req, res) => {\n"
        "  const token = req.headers['x-argocd-api-token'] || process.env.ARGOCD_API_TOKEN || '';\n"
        "  res.send('ok');\n"
        "});\n"
        "app.listen(0.0.0.0);\n",
        encoding="utf-8",
    )
    findings = McpTransportSessionUnauthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-transport-session-unauth/decorative-credential" for f in findings)


def test_explicit_loopback_bind_is_safe(tmp_path: Path) -> None:
    """FP-bait: an explicit host argument to .listen() is not an any-interface bind."""
    (tmp_path / "server.ts").write_text(
        "app.post('/mcp', (req, res) => {\n"
        "  const upstreamToken = process.env.ARGOCD_API_TOKEN;\n"
        "  fetch('https://x/y', { headers: { Authorization: `Bearer ${upstreamToken}` } });\n"
        "});\n"
        "app.listen(8080, 'localhost');\n",
        encoding="utf-8",
    )
    findings = McpTransportSessionUnauthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_inbound_auth_marker_present_is_safe(tmp_path: Path) -> None:
    """FP-bait: a real inbound check (requireAuth) clears the finding even with an env credential."""
    (tmp_path / "server.ts").write_text(
        "app.post('/mcp', requireAuth(), (req, res) => {\n"
        "  const upstreamToken = process.env.ARGOCD_API_TOKEN;\n"
        "  fetch('https://x/y', { headers: { Authorization: `Bearer ${upstreamToken}` } });\n"
        "});\n"
        "app.listen(8080);\n",
        encoding="utf-8",
    )
    findings = McpTransportSessionUnauthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_no_env_credential_at_all_is_safe(tmp_path: Path) -> None:
    """FP-bait: a bare unauthenticated server with no env-credential fallback is out of
    this guard's scope (that's `mcp-transport-no-auth`'s job, not this one's)."""
    (tmp_path / "server.ts").write_text(
        "app.post('/mcp', (req, res) => { res.send('ok'); });\n"
        "app.listen(8080);\n",
        encoding="utf-8",
    )
    findings = McpTransportSessionUnauthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_not_an_mcp_http_server_is_safe(tmp_path: Path) -> None:
    """FP-bait: no /mcp route and no MCP transport marker at all -- irrelevant file."""
    (tmp_path / "server.ts").write_text(
        "app.post('/api/health', (req, res) => {\n"
        "  const token = process.env.SOME_TOKEN;\n"
        "  fetch('https://x/y', { headers: { Authorization: `Bearer ${token}` } });\n"
        "});\n"
        "app.listen(8080);\n",
        encoding="utf-8",
    )
    findings = McpTransportSessionUnauthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    # #424 E6 (#1000): rebuilt on the firing fixture. The old one-line `fetch('https://x/y', ...)`
    # fixture never fired (comment stripping read `//x/y` as a line comment and blanked its headers),
    # so it passed with or without the pragma. Now it must fire bare and go silent under `//`.
    src = (
        "import express from 'express';\n"
        "const app = express();\n"
        "app.post('/mcp', (req, res) => {\n"
        "  const upstreamToken = process.env.ARGOCD_API_TOKEN;\n"
        "  fetch('https://argocd.internal/api/v1/session', {\n"
        "    headers: { Authorization: `Bearer ${upstreamToken}` },\n"
        "  });\n"
        "  res.send('ok');\n"
        "});\n"
        "app.listen(8080);\n"
    )
    (tmp_path / "server.ts").write_text(src, encoding="utf-8")
    findings = McpTransportSessionUnauthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [f.rule for f in findings] == ["mcp-transport-session-unauth/decorative-credential"]
    (tmp_path / "server.ts").write_text("// security: allow-mcp-transport-session-unauth\n" + src, encoding="utf-8")
    findings = McpTransportSessionUnauthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_python_server_no_implicit_bind_inference(tmp_path: Path) -> None:
    """FP-bait: Python web servers default to loopback, so an implicit-bind inference
    (no host argument) must never apply there — only explicit 0.0.0.0/:: does."""
    (tmp_path / "server.py").write_text(
        "from mcp.server.sse import SSEServerTransport\n"
        "import os\n"
        "token = os.environ.get('ARGOCD_API_TOKEN')\n"
        "headers = {'Authorization': f'Bearer {token}'}\n"
        "uvicorn.run(app)\n",
        encoding="utf-8",
    )
    findings = McpTransportSessionUnauthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"typescript"}, python_dirs=["."])
    assert McpTransportSessionUnauthGuard().applies(prof) is False


# --------------------------------------------------------------------------- PR #963 review round
def _locations(tmp_path: Path, name: str, src: str) -> list[str]:
    (tmp_path / name).write_text(src, encoding="utf-8")
    return [f.location for f in McpTransportSessionUnauthGuard().run(tmp_path, _mcp_prof(tmp_path))]


def test_outbound_credential_finding_points_at_the_authorization_header(tmp_path: Path) -> None:
    src = (
        "import express from 'express';\n"
        "const app = express();\n"
        "app.post('/mcp', (req, res) => {\n"
        "  const upstreamToken = process.env.ARGOCD_API_TOKEN;\n"
        "  fetch('https://argocd.internal/api/v1/session', {\n"
        "    headers: { Authorization: `Bearer ${upstreamToken}` },\n"
        "  });\n"
        "});\n"
        "app.listen(8080);\n"
    )
    assert _locations(tmp_path, "server.ts", src) == ["server.ts:6"]


def test_fallback_finding_points_at_the_header_to_env_fallback_after_block_comments(
    tmp_path: Path,
) -> None:
    """Comment stripping keeps newlines, so a multi-line block comment above does not shift the line."""
    src = (
        "/* header\n   comment\n   here */\n"
        "const app = express();\n"
        "app.post('/mcp', (req, res) => {\n"
        "  const token = req.headers['x-argocd-api-token'] || process.env.ARGOCD_API_TOKEN || '';\n"
        "});\n"
        "app.listen(0.0.0.0);\n"
    )
    assert _locations(tmp_path, "server.ts", src) == ["server.ts:6"]


def test_two_files_each_report_their_own_line(tmp_path: Path) -> None:
    fallback = (
        "const app = express();\n\n\n"
        "app.post('/mcp', (req, res) => {\n"
        "  const t = req.headers['x'] || process.env.OP_TOKEN;\n"
        "});\n"
        "app.listen(0.0.0.0);\n"
    )
    (tmp_path / "a.ts").write_text(fallback, encoding="utf-8")
    (tmp_path / "b.ts").write_text("// pad\n" + fallback, encoding="utf-8")
    got = sorted(f.location for f in McpTransportSessionUnauthGuard().run(tmp_path, _mcp_prof(tmp_path)))
    assert got == ["a.ts:5", "b.ts:6"]


# ── #424 E6 (#1000): the pragma counts only as a real comment, in the file's own grammar ──

_RULE = "mcp-transport-session-unauth/decorative-credential"
_PY_FIRING = (
    "import os\n"
    "from mcp.server.sse import SSEServerTransport\n\n"
    "token = os.environ.get('ARGOCD_API_TOKEN')\n"
    "headers = {'Authorization': f'Bearer {token}'}\n"
    "uvicorn.run(app, host='0.0.0.0')\n"
)
_TS_OUTBOUND_FIRING = (
    "import express from 'express';\n"
    "const app = express();\n"
    "app.post('/mcp', (req, res) => {\n"
    "  const upstreamToken = process.env.ARGOCD_API_TOKEN;\n"
    "  fetch('https://argocd.internal/api/v1/session', {\n"
    "    headers: { Authorization: `Bearer ${upstreamToken}` },\n"
    "  });\n"
    "  res.send('ok');\n"
    "});\n"
    "app.listen(8080);\n"
)
_TS_FALLBACK_FIRING = (
    "import express from 'express';\n"
    "const app = express();\n"
    "app.post('/mcp', (req, res) => {\n"
    "  const token = req.headers['x-argocd-api-token'] || process.env.ARGOCD_API_TOKEN || '';\n"
    "  res.send('ok');\n"
    "});\n"
    "app.listen(0.0.0.0);\n"
)


def _rule_list(root: Path, name: str, text: str) -> list[str]:
    (root / name).write_text(text, encoding="utf-8")
    return [f.rule for f in McpTransportSessionUnauthGuard().run(root, _mcp_prof(root))]


def test_mcp_transport_session_unauth_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): the whole-file opt-out reads the comment-only view, so a Python string quoting
    # the pragma is content; only a real `#` comment (`..._pragma_comment_suppresses_py`) opts out.
    text = 'HELP = "opt out with # security: allow-mcp-transport-session-unauth"\n' + _PY_FIRING
    assert _rule_list(tmp_path, "server.py", text) == [_RULE]


def test_mcp_transport_session_unauth_pragma_comment_suppresses_py(tmp_path: Path) -> None:
    # #424 E6 (#1000): reach unchanged, a real Python `#` comment still opts the whole file out.
    assert _rule_list(tmp_path, "server.py", _PY_FIRING) == [_RULE]
    text = "# security: allow-mcp-transport-session-unauth\n" + _PY_FIRING
    assert _rule_list(tmp_path, "server.py", text) == []


@pytest.mark.parametrize("marker", ["//", "#"], ids=["slash-form", "hash-form"])
def test_mcp_transport_session_unauth_pragma_quoted_in_a_string_does_not_suppress_ts(
    tmp_path: Path, marker: str
) -> None:
    # #424 E6 (#1000): D2 widened the pragma to `//`, so a TS string quoting either comment form must
    # stay content (the CLAUDE.md rule-1 test for that widening).
    text = f'const help = "opt out with {marker} security: allow-mcp-transport-session-unauth";\n'
    assert _rule_list(tmp_path, "server.ts", text + _TS_OUTBOUND_FIRING) == [_RULE]


def test_mcp_transport_session_unauth_ts_slash_comment_pragma_suppresses(tmp_path: Path) -> None:
    # #424 E6 (#1000) D2: TS comments are `//`, and the old `#`-only regex never saw one, so the
    # documented opt-out could not be written in a .ts file at all (the header-to-env fallback shape;
    # `test_pragma_suppresses_finding` covers the outbound-credential shape).
    assert _rule_list(tmp_path, "server.ts", _TS_FALLBACK_FIRING) == [_RULE]
    text = "// security: allow-mcp-transport-session-unauth\n" + _TS_FALLBACK_FIRING
    assert _rule_list(tmp_path, "server.ts", text) == []
