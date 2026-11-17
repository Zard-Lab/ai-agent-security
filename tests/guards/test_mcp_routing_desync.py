"""Tests for McpRoutingDesyncGuard — planted-violation + FP-bait."""
from __future__ import annotations

import pytest

from agentsec.guards.mcp_routing_desync import McpRoutingDesyncGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "llm", "python"}, python_dirs=["."])


def test_fires_on_header_routing_without_body_crosscheck(tmp_path: Path) -> None:
    """HIGH: routes on the Mcp-Method header with no cross-check against the JSON-RPC
    body's own method field — the confused-deputy desync shape."""
    (tmp_path / "mcp_gateway.py").write_text(
        "ALLOWED_METHODS = {'tools/list'}\n"
        "\n"
        "\n"
        "def route(request):\n"
        "    mcp_method = request.headers.get('mcp-method')\n"
        "    if mcp_method not in ALLOWED_METHODS:\n"
        "        raise PermissionError('blocked')\n"
        "    return dispatch(request.json())\n",
        encoding="utf-8",
    )
    findings = McpRoutingDesyncGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-routing-desync/header-body-desync" for f in findings)
    hit = next(f for f in findings if f.rule == "mcp-routing-desync/header-body-desync")
    assert hit.severity == "high"


def test_fires_on_ts_header_dispatch(tmp_path: Path) -> None:
    """HIGH: the same header-routing-without-crosscheck shape fires in TypeScript."""
    (tmp_path / "gateway.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/sdk';\n"
        "\n"
        "function handler(req) {\n"
        "  const mcpMethod = req.headers['mcp-method'];\n"
        "  if (ROUTES[mcpMethod]) {\n"
        "    return ROUTES[mcpMethod](req);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpRoutingDesyncGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-routing-desync/header-body-desync" for f in findings)


def test_body_crosscheck_present_is_safe(tmp_path: Path) -> None:
    """FP-bait: a file that reads the header AND asserts it matches the body method (the
    correct guard) must NOT fire."""
    (tmp_path / "mcp_gateway.py").write_text(
        "ALLOWED_METHODS = {'tools/list'}\n"
        "\n"
        "\n"
        "def route(request):\n"
        "    mcp_method = request.headers.get('mcp-method')\n"
        "    body = request.json()\n"
        "    if mcp_method != body.get('method'):\n"
        "        raise PermissionError('header/body method mismatch')\n"
        "    if mcp_method not in ALLOWED_METHODS:\n"
        "        raise PermissionError('blocked')\n"
        "    return dispatch(body)\n",
        encoding="utf-8",
    )
    findings = McpRoutingDesyncGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-routing-desync/header-body-desync" for f in findings)


def test_header_read_but_not_used_for_routing_is_safe(tmp_path: Path) -> None:
    """FP-bait: the header is read but only logged/displayed, never used in a routing or
    authorization decision — no _ROUTING_USE_RE signal."""
    (tmp_path / "mcp_logger.py").write_text(
        "def log_request(request):\n"
        "    mcp_method = request.headers.get('mcp-method')\n"
        "    logger.info('received mcp-method=%s', mcp_method)\n",
        encoding="utf-8",
    )
    findings = McpRoutingDesyncGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-routing-desync/header-body-desync" for f in findings)


def test_comment_mentioning_handler_does_not_count_as_routing_use(tmp_path: Path) -> None:
    """(agentic pre-review M-3): a COMMENT mentioning "handler" must not count as a
    real routing-use signal -- this guard never stripped comments at all, so a header that is
    only logged (never actually routed on) fired purely because of an unrelated comment word."""
    (tmp_path / "mcp_gateway.py").write_text(
        "from mcp.server import Server\n"
        "\n"
        "# The request handler for incoming MCP calls.\n"
        "def log_incoming(request):\n"
        "    mcp_method = request.headers.get('mcp-method')\n"
        "    logger.info('Received Mcp-Method header: %s', mcp_method)\n"
        "    return None\n",
        encoding="utf-8",
    )
    findings = McpRoutingDesyncGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-routing-desync/header-body-desync" for f in findings)


def test_faraway_handler_mention_does_not_count_as_routing_use(tmp_path: Path) -> None:
    """(M-3): a routing-use word far away from the header read (not a comment, real
    code -- an unrelated ROUTES table used by a completely different part of the file) must
    also not count -- the signal is scoped to a window around the header read now, not the
    whole file."""
    padding = "\n".join(f"x{i} = {i}" for i in range(40))
    (tmp_path / "mcp_gateway.py").write_text(
        "from mcp.server import Server\n"
        "\n"
        "def log_incoming(request):\n"
        "    mcp_method = request.headers.get('mcp-method')\n"
        "    logger.info(mcp_method)\n"
        "    return None\n"
        f"{padding}\n"
        "ROUTES = {}\n",
        encoding="utf-8",
    )
    findings = McpRoutingDesyncGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-routing-desync/header-body-desync" for f in findings)


def test_nearby_handler_mention_still_fires(tmp_path: Path) -> None:
    """Still-fires companion: a real routing-use word close to the header read (within the
    window) must still fire."""
    (tmp_path / "mcp_gateway.py").write_text(
        "from mcp.server import Server\n"
        "\n"
        "def route(request):\n"
        "    mcp_method = request.headers.get('mcp-method')\n"
        "    handler = ROUTES[mcp_method]\n"
        "    return handler(request)\n",
        encoding="utf-8",
    )
    findings = McpRoutingDesyncGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-routing-desync/header-body-desync" for f in findings)


def test_no_mcp_context_is_safe(tmp_path: Path) -> None:
    """FP-bait: a file with no MCP context marker at all stays silent even though it
    reads and routes on a similarly-named header."""
    (tmp_path / "generic_gateway.py").write_text(
        "ALLOWED_METHODS = {'GET'}\n"
        "\n"
        "\n"
        "def route(request):\n"
        "    mcp_method = request.headers.get('mcp-method')\n"
        "    if mcp_method not in ALLOWED_METHODS:\n"
        "        raise PermissionError('blocked')\n",
        encoding="utf-8",
    )
    findings = McpRoutingDesyncGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_no_header_read_is_safe(tmp_path: Path) -> None:
    """FP-bait: an MCP-context file that routes purely on the JSON-RPC body's own
    method field (never reads the Mcp-Method header at all) stays silent."""
    (tmp_path / "mcp_gateway.py").write_text(
        "from mcp.server import Server\n"
        "\n"
        "ALLOWED_METHODS = {'tools/list'}\n"
        "\n"
        "\n"
        "def route(request):\n"
        "    body = request.json()\n"
        "    if body.get('method') not in ALLOWED_METHODS:\n"
        "        raise PermissionError('blocked')\n"
        "    return dispatch(body)\n",
        encoding="utf-8",
    )
    findings = McpRoutingDesyncGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "mcp_gateway.py").write_text(
        "ALLOWED_METHODS = {'tools/list'}\n"
        "\n"
        "\n"
        "def route(request):  # security: allow-mcp-routing-desync\n"
        "    mcp_method = request.headers.get('mcp-method')\n"
        "    if mcp_method not in ALLOWED_METHODS:\n"
        "        raise PermissionError('blocked')\n"
        "    return dispatch(request.json())\n",
        encoding="utf-8",
    )
    findings = McpRoutingDesyncGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []



def test_pragma_suppresses_finding_in_ts_file(tmp_path: Path) -> None:
    """PR #923 round-3 M5: the pragma was a `#`-anchored regex, so the `//` comment form a TS
    file has to use never suppressed anything (the H-8 class). Fire-then-silence pair, so the
    test cannot pass by the fixture simply not firing."""
    body = (
        "import {{ McpServer }} from '@modelcontextprotocol/sdk';\n"
        "\n"
        "function handler(req) {{\n"
        "  const mcpMethod = req.headers['mcp-method'];{pragma}\n"
        "  if (ROUTES[mcpMethod]) {{\n"
        "    return ROUTES[mcpMethod](req);\n"
        "  }}\n"
        "}}\n"
    )
    gateway = tmp_path / "gateway.ts"
    gateway.write_text(body.format(pragma=""), encoding="utf-8")
    assert McpRoutingDesyncGuard().run(tmp_path, _mcp_prof(tmp_path)) != []
    gateway.write_text(body.format(pragma="  // security: allow-mcp-routing-desync"), encoding="utf-8")
    assert McpRoutingDesyncGuard().run(tmp_path, _mcp_prof(tmp_path)) == []

def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpRoutingDesyncGuard().applies(prof) is False


def test_guard_applicable_with_mcp_feature(tmp_path: Path) -> None:
    assert McpRoutingDesyncGuard().applies(_mcp_prof(tmp_path)) is True


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "mcp_gateway.py").write_text(
        "ALLOWED_METHODS = {'tools/list'}\n"
        "\n"
        "\n"
        "def route(request):\n"
        "    mcp_method = request.headers.get('mcp-method')\n"
        "    if mcp_method not in ALLOWED_METHODS:\n"
        "        raise PermissionError('blocked')\n"
        "    return dispatch(request.json())\n",
        encoding="utf-8",
    )
    findings = McpRoutingDesyncGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


# --- #1055: JS/TS header reads and cross-checks must be live code ---------------------------------

_JS_GATEWAY = (
    "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n"
    "export function route(req) {\n"
    "  const m = req.headers['mcp-method'];\n"
    "  if (m === 'tools/call') return dispatch(req.body);\n"
    "}\n"
    "{EXTRA}\n"
)


def _run_js(tmp_path: Path, text: str, name: str = "gateway.ts") -> list[str]:
    (tmp_path / name).write_text(text, encoding="utf-8")
    prof = _mcp_prof(tmp_path)
    assert McpRoutingDesyncGuard().applies(prof)
    return [f.location.replace("\\", "/") for f in McpRoutingDesyncGuard().run(tmp_path, prof)]


@pytest.mark.parametrize(
    "extra",
    [
        "log.info('validate_routing pending');",
        "log.info('TODO: msg.method === mcpMethod check');",
        "log.info(`TODO: msg.method === mcpMethod for ${requestId}`);",  # template TEXT
        "throw new Error(\"assert mcp_method matches the body\");",
    ],
)
def test_js_quoted_crosscheck_no_longer_clears(tmp_path: Path, extra: str) -> None:
    # The FN direction (#1055): each of these cleared the finding on main.
    assert _run_js(tmp_path, _JS_GATEWAY.replace("{EXTRA}", extra)) == ["gateway.ts:3"]


@pytest.mark.parametrize(
    "extra",
    [
        "if (msg.method !== mcpMethod) throw new Error('desync');",
        "validate_routing(req);",
        "if (body['method'] !== m) throw new Error('desync');",
        # A header name is a string by nature: the quoted `'mcp-method'` starts this cross-check.
        "if (req.headers['mcp-method'] !== body.method) throw new Error('desync');",
        # A real cross-check nested in a `${...}` substitution is code (the shortcut-separating case).
        "log(`checked ${assertMatch(msg.method === mcpMethod)}`);",
        # A quoted copy first on the line must not hide the real cross-check after it.
        "log('validate_routing pending'); validate_routing(req);",
    ],
)
def test_js_real_crosscheck_still_clears(tmp_path: Path, extra: str) -> None:
    assert _run_js(tmp_path, _JS_GATEWAY.replace("{EXTRA}", extra)) == []


def test_js_single_identifier_literal_crosscheck_credits_accepted_trade(tmp_path: Path) -> None:
    # Accepted trade (#1055): a one-identifier string literal counts, so the header name in
    # `req.headers['mcp-method'] !== body.method` can credit, and so does a one-token log key. It
    # credited on main too, so the rule is never wider than before.
    assert _run_js(tmp_path, _JS_GATEWAY.replace("{EXTRA}", "log.info('validate_routing');")) == []


@pytest.mark.parametrize(
    "line",
    [
        "log.debug('req.headers mcp-method is ignored; we dispatch on body');",
        "const DOC = \"call headers.get('mcp-method') to route\";",
        "const DOC = `route on request.headers mcp-name for ${tenant}`;",
    ],
)
def test_js_header_read_spelled_in_a_string_does_not_fire(tmp_path: Path, line: str) -> None:
    # The FP direction (#1055): a docs string naming the header read is not a read.
    text = "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n" + line + "\n"
    assert _run_js(tmp_path, text) == []


@pytest.mark.parametrize(
    ("body", "line"),
    [
        ("const ROUTES = { 'mcp-method': dispatch };", 2),  # header-map literal key
        ("function route(req) {\n  return dispatch(`${req.headers['mcp-method']}`);\n}", 3),  # in `${...}`
        # A quoted copy first on the line must not hide the real read after it.
        ("log('use headers.get(\"mcp-method\")'); const m = req.headers.get('mcp-method'); dispatch(m);", 2),
        ("const m = process.env['HTTP_MCP_METHOD'];\nif (ROUTES[m]) dispatch(m);", 2),
    ],
)
def test_js_real_header_read_still_fires(tmp_path: Path, body: str, line: int) -> None:
    text = "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n" + body + "\n"
    assert _run_js(tmp_path, text) == [f"gateway.ts:{line}"]


def test_rust_lifetime_keeps_the_plain_read(tmp_path: Path) -> None:
    # `.rs` goes through the JS lexer, where two lifetimes on a line (`&'a str ... ::<'a>`) pair up as
    # a phantom string that masks the header read between them. The #1055 anchor filter is scoped to JS/TS, so this still fires.
    text = (
        "use jsonrpc;\n"
        "fn route<'a>(req: &'a Request) { let m: &'a str = req.headers().get(\"mcp-method\"); dispatch::<'a>(m) }\n"
    )
    assert _run_js(tmp_path, text, name="gateway.rs") == ["gateway.rs:2"]


_OVERLAP = (
    "import { McpServer } from '@modelcontextprotocol/sdk';\n"
    "function h(req) {\n"
    " {QUOTED} const m = req.headers['mcp-method'];\n"
    " if (ROUTES[m]) return 1;\n"
    "}\n"
)


def test_js_quoted_header_read_overlapping_the_real_one_does_not_swallow_it(tmp_path: Path) -> None:
    # PR #1131 round-1 M1: `request.headers ... mcp-method` in the log string greedily runs over the
    # real `req.headers['mcp-method']` read. Under plain `finditer` the dropped quoted match consumed
    # the real one, so the finding went silent; the read must still be visited.
    text = _OVERLAP.replace("{QUOTED}", "log('request.headers mcp-method');")
    assert _run_js(tmp_path, text) == ["gateway.ts:3"]


def test_js_quoted_header_read_alone_still_does_not_fire(tmp_path: Path) -> None:
    # The opposite direction: with the real read removed, the quoted copy alone stays silent.
    text = _OVERLAP.replace("{QUOTED}", "log('request.headers mcp-method');").replace(
        " const m = req.headers['mcp-method'];", " const m = pick(req);"
    )
    assert _run_js(tmp_path, text) == []
