from __future__ import annotations

import pytest

from agentsec.findings import Finding
from agentsec.guards.mcp_transport_no_auth import McpTransportNoAuthGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "llm", "python"}, python_dirs=["."])


def _mcp_js_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "llm", "javascript"})


def test_flags_sse_transport_with_no_auth_marker(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server.sse import SSEServerTransport\n"
        "from mcp.server import Server\n"
        "\n"
        "app = Server('my-server')\n"
        "transport = SSEServerTransport('/messages')\n"
        "\n"
        "def main():\n"
        "    app.run(transport='sse', host='0.0.0.0', port=8080)\n",
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mcp-transport-no-auth/http-transport-unauthenticated"
    assert findings[0].severity == "critical"
    # Line-anchors on the FIRST line matching any transport signal -- here that's the
    # `SSEServerTransport` import on line 1, not the later `.run(transport='sse', ...)`
    # call on line 8; both are real transport signals, the guard doesn't privilege one.
    assert findings[0].location == "server.py:1"


def test_flags_streamable_http_transport_with_unset_host(tmp_path: Path) -> None:
    # No explicit host literal at all -- the SDK's own default bind is not loopback-only,
    # so this must still fire (mirrors the real CVE-2026-59971 shape: no security_settings,
    # no explicit host, binds 0.0.0.0 by the framework's own default).
    (tmp_path / "server.py").write_text(
        "from mcp.server.streamable_http import StreamableHTTPServerTransport\n"
        "\n"
        "def main():\n"
        "    app.run(transport='streamable-http', port=8080)\n",
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1


def test_stdio_only_server_does_not_fire(tmp_path: Path) -> None:
    # FP bait: stdio transport has no network exposure by construction -- must not fire.
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "\n"
        "app = Server('my-server')\n"
        "\n"
        "def main():\n"
        "    app.run(transport='stdio')\n",
        encoding="utf-8",
    )
    assert McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_explicit_loopback_bind_does_not_fire(tmp_path: Path) -> None:
    # FP bait: explicitly bound to localhost -- not network-reachable from another host.
    (tmp_path / "server.py").write_text(
        "from mcp.server.sse import SSEServerTransport\n"
        "\n"
        "def main():\n"
        "    app.run(transport='sse', host='127.0.0.1', port=8080)\n",
        encoding="utf-8",
    )
    assert McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_auth_provider_present_does_not_fire(tmp_path: Path) -> None:
    # FP bait: a real auth marker anywhere in the file silences the guard, even with a
    # bind-all host -- the whole-file marker check errs toward not double-flagging a server
    # that visibly wires SOME auth mechanism, matching mcp-tool-unverified's own trust-marker
    # philosophy.
    (tmp_path / "server.py").write_text(
        "from mcp.server.sse import SSEServerTransport\n"
        "from mcp.server.auth.provider import TokenVerifier\n"
        "\n"
        "def main():\n"
        "    app.run(transport='sse', host='0.0.0.0', port=8080)\n",
        encoding="utf-8",
    )
    assert McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_bearer_token_check_marker_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server.sse import SSEServerTransport\n"
        "\n"
        "def check(req):\n"
        "    token = req.headers.get('Authorization')\n"
        "    if not token or not token.startswith('Bearer '):\n"
        "        raise PermissionError\n"
        "\n"
        "def main():\n"
        "    app.run(transport='sse', host='0.0.0.0', port=8080)\n",
        encoding="utf-8",
    )
    assert McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_non_mcp_http_server_does_not_fire(tmp_path: Path) -> None:
    # FP bait: a plain, unrelated Python web server with no MCP transport signal at all.
    (tmp_path / "server.py").write_text(
        "import http.server\n"
        "\n"
        "server = http.server.HTTPServer(('0.0.0.0', 8080), http.server.BaseHTTPRequestHandler)\n"
        "server.serve_forever()\n",
        encoding="utf-8",
    )
    assert McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server.sse import SSEServerTransport\n"
        "# security: allow-mcp-transport-no-auth\n"
        "\n"
        "def main():\n"
        "    app.run(transport='sse', host='0.0.0.0', port=8080)\n",
        encoding="utf-8",
    )
    assert McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_applies_requires_mcp_and_python_features(tmp_path: Path) -> None:
    guard = McpTransportNoAuthGuard()
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is False
    # widening: the JS/TS rule applies on mcp + javascript/typescript too.
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "typescript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "javascript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"typescript"})) is False


def test_unrelated_security_helper_no_longer_masks_finding(tmp_path: Path) -> None:
    # F3 (PR #915 review): `Depends(`/`Security(` in _AUTH_MARKER are now `\b`-anchored. Without the
    # `\b`, IGNORECASE matched an unrelated helper such as `configure_security(` as a substring and
    # silenced a genuinely unauthenticated transport -- a false NEGATIVE on a CRITICAL. This is the
    # direction the fix WIDENED (the guard now fires here); asserting it proves the FN is closed.
    (tmp_path / "server.py").write_text(
        "from mcp.server.sse import SSEServerTransport\n"
        "\n"
        "def configure_security(app):\n"  # NOT an auth marker: `_security(` only matched pre-`\b`
        "    return app\n"
        "\n"
        "def main():\n"
        "    app.run(transport='sse', host='0.0.0.0', port=8080)\n",
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mcp-transport-no-auth/http-transport-unauthenticated"


def test_real_fastapi_security_dependency_still_silences(tmp_path: Path) -> None:
    # F3 FP-bait (the direction traded against, per review Rule 1): the `\b` anchor must NOT stop a
    # genuine FastAPI-style `Depends(...)`/`Security(...)` auth marker from silencing the guard. Both
    # are preceded by whitespace here, so `\b` matches and the finding is (correctly) suppressed.
    (tmp_path / "server.py").write_text(
        "from fastapi import Security, Depends\n"
        "from mcp.server.sse import SSEServerTransport\n"
        "\n"
        "def protected(user = Depends(get_current_user), scopes = Security(oauth2_scheme)):\n"
        "    return user\n"
        "\n"
        "def main():\n"
        "    app.run(transport='sse', host='0.0.0.0', port=8080)\n",
        encoding="utf-8",
    )
    assert McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_multiline_run_transport_anchors_to_the_run_line(tmp_path: Path) -> None:
    # F4 (PR #915 review): when the ONLY transport signal is a `.run(` whose `transport=` kwarg is on a
    # later physical line, no single line matches the whole-file regex, so the old per-line loop left
    # `lineno` at its `1` default and mis-pointed this CRITICAL finding at the file's first import. The
    # offset-based line now resolves to the real `.run(` call on line 6.
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"   # 1
        "\n"                                # 2
        "app = Server('my-server')\n"       # 3
        "\n"                                # 4
        "def main():\n"                     # 5
        "    app.run(\n"                    # 6  <- the real transport call
        "        host='0.0.0.0',\n"         # 7
        "        port=8080,\n"              # 8
        "        transport='sse',\n"        # 9
        "    )\n",                          # 10
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location == "server.py:6"


def test_kwarg_heavy_run_with_transport_past_300_chars_still_fires(tmp_path: Path) -> None:
    # F1-residual (PR #915 re-review): F1 first bounded the `.run(` body to `[^)]{0,300}`, which a
    # kwarg-heavy `.run(` crosses. For a high-level FastMCP server (no `SSEServerTransport` /
    # `sse_app(` literal) that `.run(` branch is the ONLY transport signal, so the whole file went
    # silent on a bind-all, unauthenticated transport. The bound is now 2000; this FAILS at 300.
    src = (
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('team-tools')\n"
        "\n"
        "def main():\n"
        "    mcp.run(\n"
        "        # Shared team server: bind every interface so laptops on the office network can reach\n"
        "        # it, keep the port stable for the reverse-proxy config, and log verbosely for now.\n"
        "        host='0.0.0.0',\n"
        "        port=8080,\n"
        "        log_level='debug',\n"
        "        mount_path='/mcp',\n"
        "        sse_path='/sse',\n"
        "        message_path='/messages/',\n"
        "        # Keep-alive tuned for the slow VPN; revisit after the network migration lands.\n"
        "        timeout_keep_alive=120,\n"
        "        transport='sse',\n"
        "    )\n"
    )
    gap = src.index("transport=") - src.index(".run(")
    assert 300 < gap < 2000, gap  # the fixture must actually sit past the old bound, inside the new one
    (tmp_path / "server.py").write_text(src, encoding="utf-8")
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location == "server.py:6"


def test_closed_run_then_unrelated_transport_literal_does_not_fire(tmp_path: Path) -> None:
    # FP-bait for the 300 -> 2000 widening (the direction traded against, per review Rule 1): a longer
    # reach must still stop at the `.run(` call's own `)`. Here a stdio `mcp.run()` closes at once, and
    # an unrelated `transport='sse'` (a client-side default, a helper's default arg) follows well
    # inside 2000 chars — the guard must stay silent, since no `.run(` actually selects SSE.
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('local-tools')\n"
        "\n"
        "def main():\n"
        "    mcp.run()\n"
        "\n"
        "UPSTREAM = dict(transport='sse', url='http://upstream.internal:9000/sse')\n"
        "\n"
        "def describe(transport='sse'):\n"
        "    return f'client transport: {transport}'\n",
        encoding="utf-8",
    )
    assert McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


@pytest.mark.slow
def test_http_transport_regex_is_not_superlinear(tmp_path: Path) -> None:
    # F1 (PR #915 review): the `.run(...)` alternative's body was an unbounded `[^)]*` before a literal
    # it must find. On a `.py` file with many `.run(`-shaped runs that never reach a `)` and no
    # `transport=` anywhere, the engine backtracks the whole tail at every occurrence -- O(n^2), an
    # audit that merely APPEARS to hang. `corpus-scan` clones arbitrary public repos, so this input is
    # untrusted; it is the same failure-that-presents-as-success class the sibling js-command-injection
    # guard already measures and pins. Bounding the body to `[^)]{0,2000}` makes it linear.
    #
    # Measured on the raw regex: unbounded 0.24s / 3.83s / 16.1s / 60.9s at n = 8k / 32k / 64k / 128k
    # (a clean 4x-per-doubling quadratic) against the 2000-bounded 0.015s / 0.059s / 0.117s / 0.232s
    # (2x per doubling; the re-review widened F1's first 300 bound, which measured 0.067s at 128k). The
    # 15.0s ceiling (mirroring the js sibling's) clears the bounded guard run (worst 0.247s of 7) by
    # ~60x while the unbounded form blows ~4x through it. Verified to FAIL against the unbounded pattern.
    import time

    n = 128_000
    (tmp_path / "big.py").write_text("app.run(" * n, encoding="utf-8")
    start = time.monotonic()
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert time.monotonic() - start < 15.0
    assert findings == []  # no `transport=` present -> the search fails (linearly) and nothing fires


@pytest.mark.slow
def test_many_transport_signals_stay_linear(tmp_path: Path) -> None:
    # PR #915 fix-commit review: the F4 lineno fix first took `min` over `_HTTP_TRANSPORT.finditer`
    # with a `text.count("\n", 0, m.start())` per match — O(n) per match x O(n) matches. A file of
    # many transport signals measured 0.10s / 0.31s / 1.50s at n = 4k / 8k / 16k (quadratic), a path
    # the test above never reaches because its input has no match at all. The lineno now comes from
    # the ONE leftmost `search` match. Growth CLASS is the assertion, not wall clock (tests/_timing.py);
    # four sizes so `classify`'s median can discard one contended reading (#758).
    sizes = [8000, 16000, 32000, 64000]
    roots = {}
    for n in sizes:
        root = tmp_path / f"n{n}"
        root.mkdir()
        # Every line is a real, unauthenticated transport signal, so the guard must still fire once:
        # a guard that stopped matching cannot pass as "fast".
        (root / "server.py").write_text("SSEServerTransport\n" * n, encoding="utf-8")
        roots[n] = root

    found: dict[int, list[str]] = {}

    def scan(n: int) -> None:
        found[n] = [f.location for f in McpTransportNoAuthGuard().run(roots[n], _mcp_prof(roots[n]))]

    assert_growth(scan, sizes, expected="linear")
    assert all(found[n] == ["server.py:1"] for n in sizes), found


# --- JS/TS no-auth transport ---------------------------------------------------

def test_js_flags_app_listen_with_no_auth_marker(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');\n"
        "const express = require('express');\n"
        "const app = express();\n\n"
        "app.listen(8080, '0.0.0.0', () => console.log('listening'));\n",
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert any(f.rule == "mcp-transport-no-auth/js-http-transport-unauthenticated" for f in findings)


def test_js_silent_on_generic_listen_with_no_mcp_signal_in_file(tmp_path: Path) -> None:
    """FP-bait (H1, #1058 review): a plain Express API's own `app.listen(` must not fire just
    because the REPO has the `mcp` feature detected somewhere else -- the file itself needs an
    MCP SDK signal before the generic listen/createServer pair counts as a transport candidate."""
    (tmp_path / "server.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n\n"
        "app.listen(8080, '0.0.0.0', () => console.log('listening'));\n",
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert findings == []


def test_js_cross_file_auth_in_sibling_file_still_silences(tmp_path: Path) -> None:
    """Multi-file fixture (CLAUDE.md step 3, H1's exact measured FP): an MCP server file with no
    auth marker of its own, alongside a plain Express API file in the same repo whose auth is
    wired in A THIRD file -- the API file must not fire (no MCP signal of its own), and the real
    MCP file still fires on its own merits."""
    (tmp_path / "mcp_server.js").write_text(
        "const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');\n"
        "const app = require('express')();\n\n"
        "app.listen(8081, '0.0.0.0', () => console.log('mcp listening'));\n",
        encoding="utf-8",
    )
    (tmp_path / "auth.js").write_text(
        "function authMiddleware(req, res, next) { if (requireAuth(req)) next(); }\n"
        "module.exports = { authMiddleware };\n",
        encoding="utf-8",
    )
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "server.ts").write_text(
        "import { authMiddleware } from '../auth';\n"
        "const app = require('express')();\n"
        "app.use(authMiddleware);\n"
        "app.listen(3000, '0.0.0.0', () => console.log('api listening'));\n",
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    rules_by_file = {f.location.split(":")[0].replace("\\", "/"): f.rule for f in findings}
    assert "api/server.ts" not in rules_by_file
    assert rules_by_file.get("mcp_server.js") == "mcp-transport-no-auth/js-http-transport-unauthenticated"


def test_ts_flags_sse_server_transport_with_no_auth_marker(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        "import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';\n\n"
        "const transport = new SSEServerTransport('/messages', res);\n",
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, mkprofile(tmp_path, features={"mcp", "typescript"}))
    assert any(f.rule == "mcp-transport-no-auth/js-http-transport-unauthenticated" for f in findings)


def test_js_silent_with_loopback_bind(tmp_path: Path) -> None:
    """FP-bait: an explicit loopback bind is exempt, mirroring the Python rule. Carries its own
    MCP signal so the bait reaches the loopback check rather than being silenced one gate earlier
    by the H1 same-file anchor (the M1-class mistake #1058's own review flagged in the sibling PR)."""
    (tmp_path / "server.js").write_text(
        "const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');\n"
        "const express = require('express');\n"
        "const app = express();\n\n"
        "app.listen(8080, 'localhost', () => console.log('listening'));\n",
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert not any(f.rule == "mcp-transport-no-auth/js-http-transport-unauthenticated" for f in findings)


def test_js_silent_with_loopback_bind_behind_nested_call(tmp_path: Path) -> None:
    """FP-bait (H1, #1058 review): a nested call before the host literal
    (`listen(Number(process.env.PORT), "127.0.0.1")`) must still be recognized as a loopback bind
    -- the prior unbounded-paren-free scan stopped at the inner call's own closing paren."""
    (tmp_path / "server.js").write_text(
        "const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');\n"
        "const app = require('express')();\n\n"
        "app.listen(Number(process.env.PORT), '127.0.0.1', () => console.log('listening'));\n",
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert not any(f.rule == "mcp-transport-no-auth/js-http-transport-unauthenticated" for f in findings)


def test_js_silent_with_camelcase_auth_marker(tmp_path: Path) -> None:
    """FP-bait: the JS/TS-idiomatic camelCase auth markers (requireAuth/verifyToken/etc.) that
    the pre-existing Python-oriented marker list did not recognize must silence the finding.
    Carries its own MCP signal so the bait reaches the auth-marker check (see note above)."""
    (tmp_path / "server.js").write_text(
        "const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');\n"
        "const express = require('express');\n"
        "const app = express();\n\n"
        "app.use(requireAuth);\n"
        "app.listen(8080, '0.0.0.0', () => console.log('listening'));\n",
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert not any(f.rule == "mcp-transport-no-auth/js-http-transport-unauthenticated" for f in findings)


def test_js_pragma_suppresses_finding(tmp_path: Path) -> None:
    """H2, #1058 review: the pragma must work via a `//` JS comment, not only `#`."""
    (tmp_path / "server.js").write_text(
        "// security: allow-mcp-transport-no-auth\n"
        "const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');\n"
        "const app = require('express')();\n\n"
        "app.listen(8080, '0.0.0.0', () => console.log('listening'));\n",
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert not any(f.rule == "mcp-transport-no-auth/js-http-transport-unauthenticated" for f in findings)


def test_js_pragma_in_string_does_not_suppress(tmp_path: Path) -> None:
    """The pragma must count only as a COMMENT -- a string merely quoting it must not silence a
    real finding (CLAUDE.md's `comment_view` discipline, #424)."""
    (tmp_path / "server.js").write_text(
        "const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');\n"
        "const note = 'security: allow-mcp-transport-no-auth';\n"
        "const app = require('express')();\n\n"
        "app.listen(8080, '0.0.0.0', () => console.log('listening'));\n",
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert any(f.rule == "mcp-transport-no-auth/js-http-transport-unauthenticated" for f in findings)


def test_js_silent_on_unrelated_listen_call(tmp_path: Path) -> None:
    """FP-bait: a `.listen(` that is not an HTTP listener (an event-bus subscription) in a stdio
    MCP server file must not count as a network transport, even with the MCP signal present.
    Only `app.listen(` and `createServer(` are transport calls."""
    (tmp_path / "unrelated.js").write_text(
        "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n"
        "import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';\n"
        "const server = new McpServer({ name: 'local' });\n"
        "bus.listen('tool-call', (evt) => console.log(evt));\n"
        "await server.connect(new StdioServerTransport());\n",
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert findings == []


# --- round 2 of the #1058 review: the same-file MCP signal must be a server, in code -------------

_JS_RULE = "mcp-transport-no-auth/js-http-transport-unauthenticated"
_PLAIN_EXPRESS = (
    "const app = require('express')();\n"
    "app.listen(3000, '0.0.0.0', () => console.log('api listening'));\n"
)


@pytest.mark.parametrize(
    "lead",
    [
        "// TODO: migrate this API onto McpServer later\n",
        "/* see @modelcontextprotocol/sdk/server/mcp.js for the MCP side */\n",
        "const lbl = 'McpServer';\n",
        "import { Client } from '@modelcontextprotocol/sdk/client/index.js';\n",
    ],
    ids=["line-comment", "block-comment", "string-literal", "sdk-client-import"],
)
def test_js_silent_when_the_mcp_signal_is_not_a_server(tmp_path: Path, lead: str) -> None:
    """FP-bait (round-2 M2): the H1 gate read raw text and accepted the bare package name, so a
    comment, a string, or an MCP CLIENT import next to an ordinary Express API made the API's
    `app.listen(` a CRITICAL. The signal has to be server-side and has to be code."""
    (tmp_path / "server.js").write_text(lead + _PLAIN_EXPRESS, encoding="utf-8")
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert not any(f.rule == _JS_RULE for f in findings)


def test_js_silent_when_the_only_listen_call_is_commented_out(tmp_path: Path) -> None:
    """A stdio MCP server whose old HTTP listener survives only as a comment exposes no port."""
    (tmp_path / "server.js").write_text(
        "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n"
        "const server = new McpServer({ name: 'local' });\n"
        "// app.listen(8080, '0.0.0.0');\n",
        encoding="utf-8",
    )
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert not any(f.rule == _JS_RULE for f in findings)


@pytest.mark.parametrize(
    "lead",
    [
        "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n",
        "import { Server } from '@modelcontextprotocol/sdk/server/index.js';\n",
        "const { McpServer } = require('./mcp-wrapper');\nconst server = new McpServer({ name: 'x' });\n",
    ],
    ids=["server-subpath-import", "low-level-server-import", "wrapped-server-constructor"],
)
def test_js_still_fires_on_a_real_mcp_server_listener(tmp_path: Path, lead: str) -> None:
    """The direction the M2 narrowing trades against: an unauthenticated MCP server that listens
    on a public port still fires, whether the SDK server comes from a subpath import or from a
    local wrapper that only shows up as `new McpServer(`."""
    (tmp_path / "server.js").write_text(lead + _PLAIN_EXPRESS, encoding="utf-8")
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path))
    assert any(f.rule == _JS_RULE for f in findings)


@pytest.mark.parametrize("prefix", _VENDORED_PREFIXES)
def test_vendored_copy_is_never_scanned_but_first_party_still_fires(tmp_path: Path, prefix: str) -> None:
    """#1042: enumerated through the shared walker, not a bare `rglob`. A vendored MCP server that
    binds SSE to 0.0.0.0 inside `.venv/site-packages` raised a CRITICAL against the user's repo; the
    same file in first-party source must still fire."""
    plant = McpTransportNoAuthGuard.canary_plant
    assert plant is not None
    canary = plant.files["mcp_http_server.py"]
    _plant(tmp_path, f"{prefix}/mcp_http_server.py", canary)
    _plant(tmp_path, "app/mcp_http_server.py", canary)
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert {f.location.replace("\\", "/").rsplit(":", 1)[0] for f in findings} == {"app/mcp_http_server.py"}


def test_gitignored_python_file_is_not_scanned_but_a_tracked_neighbour_still_fires(tmp_path: Path) -> None:
    """#1044 review M1: through the shared walker this guard honours `.gitignore`, like every sibling
    Python guard (the old `rglob` did not). Pinned in both directions: the ignored file is silent, a
    tracked file with the same code in the same dir still fires."""
    plant = McpTransportNoAuthGuard.canary_plant
    assert plant is not None
    canary = plant.files["mcp_http_server.py"]
    _plant(tmp_path, ".gitignore", "app/scratch_server.py\n")
    _plant(tmp_path, "app/scratch_server.py", canary)
    _plant(tmp_path, "app/mcp_http_server.py", canary)
    findings = McpTransportNoAuthGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert {f.location.replace("\\", "/").rsplit(":", 1)[0] for f in findings} == {"app/mcp_http_server.py"}


# --- #1055: the JS/TS credits read live code, not the raw text ------------------------------------

_JS_SERVER = (
    "const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');\n"
    "const app = require('express')();\n"
    "{EXTRA}\n"
    "app.listen(8080, '0.0.0.0');\n"
)


def _run_js_server(tmp_path: Path, extra: str) -> list[Finding]:
    (tmp_path / "server.js").write_text(_JS_SERVER.replace("{EXTRA}", extra), encoding="utf-8")
    return McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path))


@pytest.mark.parametrize(
    "extra",
    [
        "// TODO: Authorization not wired yet",                       # a comment (raw-text read)
        "/* requireAuth goes here once the IdP is live */",
        "console.log('TODO: add Bearer auth');",                      # a log string
        "throw new Error(`verifyToken( is not implemented`);",
        "console.log(\"use 'Bearer' tokens\");",                        # quotes that are string content
        "console.log('later: app.listen(8080, \"localhost\")');",      # a loopback hint, not a bind
    ],
)
def test_js_quoted_or_commented_credit_no_longer_silences(tmp_path: Path, extra: str) -> None:
    # The FN direction (#1055): each of these silenced a CRITICAL finding.
    findings = _run_js_server(tmp_path, extra)
    assert [f.rule for f in findings] == ["mcp-transport-no-auth/js-http-transport-unauthenticated"]


@pytest.mark.parametrize(
    "extra",
    [
        "app.use((q, r, n) => (q.get('authorization') || '').startsWith('Bearer ') ? n() : r.end());",
        "app.use((q, r, n) => q.headers['x-api-key'] === KEY ? n() : r.end());",
        "app.use((q, r, n) => q.headers.authorization === `Bearer ${TOKEN}` ? n() : r.sendStatus(401));",
        "app.use(requireAuth);",
        # A real call nested in a `${...}` substitution is code (the shortcut-separating case).
        "app.use((q, r, n) => n(log(`ok ${verifyToken(q.get('x'))}`)));",
        # A quoted copy first on the line must not hide the real marker after it.
        "log('requireAuth pending'); app.use(requireAuth);",
    ],
)
def test_js_real_credit_still_silences(tmp_path: Path, extra: str) -> None:
    assert _run_js_server(tmp_path, extra) == []


def test_js_loopback_bind_after_a_quoted_copy_still_silences(tmp_path: Path) -> None:
    # The quoted copy is itself a loopback match, so a first-hit-only filter would drop it and stop
    # (PR #1126 round-1 L2: the earlier `"0.0.0.0"` copy never matched at all, and proved nothing).
    (tmp_path / "server.js").write_text(
        _JS_SERVER.replace("{EXTRA}\napp.listen(8080, '0.0.0.0');", "")
        + "log('was: app.listen(8080, \"localhost\")'); app.listen(8080, '127.0.0.1');\n",
        encoding="utf-8",
    )
    assert McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path)) == []


def test_js_transport_spelled_in_a_string_does_not_fire(tmp_path: Path) -> None:
    # The sink side: a docs string naming the transport is not a transport.
    (tmp_path / "help.js").write_text(
        "const HELP = 'start it with new SSEServerTransport(\"/messages\", res)';\n", encoding="utf-8"
    )
    assert McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path)) == []


def test_js_generic_listener_spelled_in_a_string_does_not_fire(tmp_path: Path) -> None:
    # The generic `app.listen(` / `createServer(` branch is anchored too (PR #1126 round-1 L2).
    (tmp_path / "server.js").write_text(
        _JS_SERVER.replace("{EXTRA}\napp.listen(8080, '0.0.0.0');", "")
        + "const HELP = 'then call app.listen(8080) or http.createServer(app) to serve';\n",
        encoding="utf-8",
    )
    assert McpTransportNoAuthGuard().run(tmp_path, _mcp_js_prof(tmp_path)) == []


@pytest.mark.parametrize(
    "extra",
    [
        "const { auth } = require('express-oauth2-jwt-bearer'); app.use(auth({ audience: 'x' }));",
        "app.use((q, r, n) => q.headers['x-mcp-api-key'] === K ? n() : r.end());",
        "const k = process.env['MCP_API_KEY'];",
        "const guard = require('./middleware/requireAuth'); app.use(guard);",
    ],
)
def test_js_marker_inside_a_single_token_literal_still_credits(tmp_path: Path, extra: str) -> None:
    # PR #1126 round-1 M2: a package name, a custom header, an env key or a module path is a string
    # by nature, and each credited on main. A literal that is one whitespace-free token holding the
    # marker still credits; prose (a literal with inner spaces) does not.
    assert _run_js_server(tmp_path, extra) == []


def test_js_single_token_log_literal_credits_accepted_trade(tmp_path: Path) -> None:
    # The cost of the M2 rule, pinned so the choice is explicit: a log literal written as ONE
    # hyphenated token is indistinguishable from a header or package name, so it credits.
    assert _run_js_server(tmp_path, "console.log('TODO:add-Bearer-auth');") == []
