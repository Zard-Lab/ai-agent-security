"""Tests for McpToolgateAsymmetryGuard — planted-violation + FP-bait."""
from __future__ import annotations

import pytest

from agentsec.guards.mcp_toolgate_asymmetry import McpToolgateAsymmetryGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "llm", "python"}, python_dirs=["."])


def test_fires_on_discovery_gated_exec_ungated_python(tmp_path: Path) -> None:
    """HIGH: list_tools() checks ALLOWED_TOOLS, call_tool() has no such gate anywhere
    in its body — CVE-2026-46519's own shape (mcp-server-kubernetes)."""
    (tmp_path / "mcp_kube_server.py").write_text(
        "import os\n"
        "\n"
        "ALLOWED_TOOLS = os.environ.get('ALLOWED_TOOLS', '').split(',')\n"
        "\n"
        "\n"
        "async def list_tools():\n"
        "    return [t for t in ALL_TOOLS if t.name in ALLOWED_TOOLS]\n"
        "\n"
        "\n"
        "async def call_tool(name, arguments):\n"
        "    return await TOOLS[name].run(arguments)\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-toolgate-asymmetry/discovery-exec-mismatch" for f in findings)
    hit = next(f for f in findings if f.rule == "mcp-toolgate-asymmetry/discovery-exec-mismatch")
    assert hit.severity == "high"
    # (agentic pre-review H-7 Medium): this used to carry no line number at all --
    # now anchored at the ungated exec handler itself (line 10, `async def call_tool(...)`).
    assert hit.location.endswith(":10")


def test_fires_on_discovery_gated_exec_ungated_ts(tmp_path: Path) -> None:
    """HIGH: the same asymmetry via setRequestHandler(ListToolsRequestSchema/
    CallToolRequestSchema) also fires in TypeScript."""
    (tmp_path / "server.ts").write_text(
        "import { Server } from '@modelcontextprotocol/sdk/server';\n"
        "\n"
        "const server = new Server();\n"
        "\n"
        "server.setRequestHandler(ListToolsRequestSchema, async () => {\n"
        "  return allTools.filter(t => ALLOWED_TOOLS.includes(t.name));\n"
        "});\n"
        "\n"
        "server.setRequestHandler(CallToolRequestSchema, async (req) => {\n"
        "  return tools[req.params.name].run(req.params.arguments);\n"
        "});\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-toolgate-asymmetry/discovery-exec-mismatch" for f in findings)


def test_gate_in_both_handlers_is_safe(tmp_path: Path) -> None:
    """FP-bait: the same gate applied in BOTH discovery and execution must NOT fire."""
    (tmp_path / "mcp_kube_server.py").write_text(
        "import os\n"
        "\n"
        "ALLOWED_TOOLS = os.environ.get('ALLOWED_TOOLS', '').split(',')\n"
        "\n"
        "\n"
        "async def list_tools():\n"
        "    return [t for t in ALL_TOOLS if t.name in ALLOWED_TOOLS]\n"
        "\n"
        "\n"
        "async def call_tool(name, arguments):\n"
        "    if name not in ALLOWED_TOOLS:\n"
        "        raise PermissionError('blocked')\n"
        "    return await TOOLS[name].run(arguments)\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-toolgate-asymmetry/discovery-exec-mismatch" for f in findings)


def test_mcp_client_wrapper_filtering_its_own_catalogue_is_safe(tmp_path: Path) -> None:
    """(agentic pre-review H-7c): an MCP CLIENT wrapper (using the real SDK's
    ClientSession) that filters its own local tool catalogue has nothing to do with the
    SERVER-side authorization-enforcement gap (CVE-2026-46519) this guard targets -- must not
    fire just because its methods happen to be named list_tools/call_tool, mirroring the
    server's own API shape."""
    (tmp_path / "client_wrapper.py").write_text(
        "from mcp import ClientSession\n"
        "\n"
        "class LocalToolCatalogue:\n"
        "    def __init__(self, session: ClientSession, allowed_tools):\n"
        "        self._session = session\n"
        "        self._allowed_tools = allowed_tools\n"
        "\n"
        "    async def list_tools(self):\n"
        "        result = await self._session.list_tools()\n"
        "        return [t for t in result.tools if t.name in self._allowed_tools]\n"
        "\n"
        "    async def call_tool(self, name, arguments):\n"
        "        return await self._session.call_tool(name, arguments)\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-toolgate-asymmetry/discovery-exec-mismatch" for f in findings)


def test_gateway_with_both_client_and_server_markers_still_fires(tmp_path: Path) -> None:
    """Narrowing safety check (Dean's review, round 2 -- a regression the H-7c fix above
    introduced): a GATEWAY that both proxies an upstream MCP server (imports ClientSession)
    AND implements its own server-side tool-execution surface (Server(...) + @server.call_tool)
    is exactly the CVE-2026-46519 shape -- the client marker alone must not exclude it when a
    server marker is ALSO present."""
    (tmp_path / "gateway.py").write_text(
        "import os\n"
        "from mcp import ClientSession\n"
        "from mcp.server import Server\n"
        "\n"
        "ALLOWED_TOOLS = os.environ.get('ALLOWED_TOOLS', '').split(',')\n"
        "server = Server('proxy-gateway')\n"
        "upstream: ClientSession = connect_upstream()\n"
        "\n"
        "\n"
        "@server.list_tools()\n"
        "async def list_tools():\n"
        "    result = await upstream.list_tools()\n"
        "    return [t for t in result.tools if t.name in ALLOWED_TOOLS]\n"
        "\n"
        "\n"
        "@server.call_tool()\n"
        "async def call_tool(name, arguments):\n"
        "    return await upstream.call_tool(name, arguments)\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-toolgate-asymmetry/discovery-exec-mismatch" for f in findings)



_TS_GATEWAY = (
    "import {{ Client }} from '@modelcontextprotocol/sdk/client/index.js';\n"
    "import {{ ListToolsRequestSchema, CallToolRequestSchema }} from '@modelcontextprotocol/sdk/types.js';\n"
    "{server_setup}"
    "const upstream = new Client({{ name: 'gateway', version: '1.0.0' }});\n"
    "const ALLOWED_TOOLS = (process.env.ALLOWED_TOOLS ?? '').split(',');\n"
    "\n"
    "server.setRequestHandler(ListToolsRequestSchema, async () => {{\n"
    "  const result = await upstream.listTools();\n"
    "  return {{ tools: result.tools.filter((t) => ALLOWED_TOOLS.includes(t.name)) }};\n"
    "}});\n"
    "\n"
    "server.setRequestHandler(CallToolRequestSchema, async (request) => {{\n"
    "  return upstream.callTool(request.params);\n"
    "}});\n"
)


def test_ts_gateway_on_mcpserver_with_a_client_still_fires(tmp_path: Path) -> None:
    """Still-fires (PR #923 round-3 H2): a TS gateway built on the SDK's high-level
    `new McpServer(...)` that also proxies an upstream `new Client(...)` went silent at 30e594a2
    and stayed silent at e6f95e89, because `\\bServer\\s*\\(` cannot match inside `McpServer(`
    and the client marker then excluded the whole file."""
    (tmp_path / "gateway.ts").write_text(
        _TS_GATEWAY.format(server_setup=(
            "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n"
            "const server = new McpServer({ name: 'gateway', version: '1.0.0' });\n"
        )),
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [f.location for f in findings] == ["gateway.ts:13"]


def test_ts_gateway_whose_server_is_built_elsewhere_still_fires(tmp_path: Path) -> None:
    """Still-fires (PR #923 round-3 M1 patch): a `setRequestHandler(CallToolRequestSchema, ...)`
    registration is server-side tool execution whatever the server constructor is called, or
    even when the server object is imported from another module, so it counts as a server
    marker next to a `new Client(...)`."""
    (tmp_path / "gateway.ts").write_text(
        _TS_GATEWAY.format(server_setup="import { server } from './server.js';\n"),
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-toolgate-asymmetry/discovery-exec-mismatch" for f in findings)


@pytest.mark.parametrize(
    ("module_extra", "class_extra", "method_extra"),
    [
        pytest.param("# The remote end runs mcp.server.Server() on its side.\n", "", "", id="comment"),
        pytest.param("", '    """Client for a remote Server() instance."""\n', "", id="docstring"),
        pytest.param("", "", "        conn = self.pool.server('primary')\n", id="lowercase-server-call"),
        pytest.param("STATUS_MSG = 'the remote peer runs Server(x) internally'\n", "", "", id="string"),
    ],
)
def test_client_wrapper_mentioning_a_server_is_still_safe(
    tmp_path: Path, module_extra: str, class_extra: str, method_extra: str
) -> None:
    """FP-bait (PR #923 round-3 M1): the server-marker check ran on raw text and ignored case,
    so a pure `ClientSession` wrapper fired HIGH again at e6f95e89 when a comment or docstring
    described the REMOTE `Server()`, or when it made an ordinary `.server(...)` call. None of
    those is a server in this file."""
    (tmp_path / "client_wrapper.py").write_text(
        "from mcp import ClientSession\n"
        f"{module_extra}"
        "\n"
        "class LocalToolCatalogue:\n"
        f"{class_extra}"
        "    def __init__(self, session: ClientSession, allowed_tools):\n"
        "        self._session = session\n"
        "        self._allowed_tools = allowed_tools\n"
        "\n"
        "    async def list_tools(self):\n"
        f"{method_extra}"
        "        result = await self._session.list_tools()\n"
        "        return [t for t in result.tools if t.name in self._allowed_tools]\n"
        "\n"
        "    async def call_tool(self, name, arguments):\n"
        "        return await self._session.call_tool(name, arguments)\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


@pytest.mark.parametrize(
    "mention",
    [
        pytest.param(
            "// The remote end runs new McpServer(...) with setRequestHandler(CallToolRequestSchema, ...).\n",
            id="comment",
        ),
        pytest.param("const note = 'the gateway runs new McpServer({name: x})';\n", id="string"),
    ],
)
def test_ts_client_wrapper_naming_the_remote_server_is_safe(tmp_path: Path, mention: str) -> None:
    """FP-bait, TS form of round-3 M1: the new `McpServer(` / `setRequestHandler(CallTool...`
    server markers must be read from code with comments AND strings blanked, or a client whose
    comment or string describes what the REMOTE end runs would count as a gateway (the string
    form was measured firing HIGH on the first round-4 draft)."""
    (tmp_path / "client.ts").write_text(
        "import { Client } from '@modelcontextprotocol/sdk/client/index.js';\n"
        f"{mention}"
        "const client = new Client({ name: 'catalogue', version: '1.0.0' });\n"
        "const ALLOWED_TOOLS = ['search'];\n"
        "\n"
        "export async function listTools() {\n"
        "  const result = await client.listTools();\n"
        "  return result.tools.filter((t) => ALLOWED_TOOLS.includes(t.name));\n"
        "}\n"
        "\n"
        "export async function callTool(name: string, args: Record<string, unknown>) {\n"
        "  return client.callTool({ name, arguments: args });\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []

def test_gate_extracted_into_a_helper_function_is_safe(tmp_path: Path) -> None:
    """(agentic pre-review H-7a): the gate check extracted into a named helper and
    called from call_tool -- the refactor a reviewer would naturally recommend for an inline
    check -- must still be recognized as a real gate, one function call away."""
    (tmp_path / "mcp_kube_server.py").write_text(
        "import os\n"
        "\n"
        "ALLOWED_TOOLS = os.environ.get('ALLOWED_TOOLS', '').split(',')\n"
        "\n"
        "\n"
        "def _require_allowed(name):\n"
        "    if name not in ALLOWED_TOOLS:\n"
        "        raise PermissionError('blocked')\n"
        "\n"
        "\n"
        "async def list_tools():\n"
        "    return [t for t in ALL_TOOLS if t.name in ALLOWED_TOOLS]\n"
        "\n"
        "\n"
        "async def call_tool(name, arguments):\n"
        "    _require_allowed(name)\n"
        "    return await TOOLS[name].run(arguments)\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-toolgate-asymmetry/discovery-exec-mismatch" for f in findings)


def test_description_string_mentioning_read_only_does_not_count_as_a_gate(tmp_path: Path) -> None:
    """(agentic pre-review H-7b): a tool's own human-readable description merely
    MENTIONING the word "read-only" as prose must not count as a real gate marker -- only an
    identifier-shaped token (an env-var/config-key name) does."""
    (tmp_path / "mcp_sql_server.py").write_text(
        "async def list_tools():\n"
        "    return [{'name': 'query', 'description': 'Read-only SQL query tool'}]\n"
        "\n"
        "\n"
        "async def call_tool(name, arguments):\n"
        "    return await run_query(arguments['sql'])\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-toolgate-asymmetry/discovery-exec-mismatch" for f in findings)


def test_env_var_name_string_still_counts_as_a_gate(tmp_path: Path) -> None:
    """Still-fires companion: an identifier-shaped string constant (a real env-var/config-key
    name, e.g. inside os.environ.get(...)) must still count as gate evidence."""
    (tmp_path / "mcp_kube_server.py").write_text(
        "import os\n"
        "\n"
        "\n"
        "async def list_tools():\n"
        "    allowed = os.environ.get('ALLOWED_TOOLS', '').split(',')\n"
        "    return [t for t in ALL_TOOLS if t.name in allowed]\n"
        "\n"
        "\n"
        "async def call_tool(name, arguments):\n"
        "    return await TOOLS[name].run(arguments)\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-toolgate-asymmetry/discovery-exec-mismatch" for f in findings)


def test_no_gate_anywhere_is_safe(tmp_path: Path) -> None:
    """FP-bait: a server with no gate control in EITHER handler stays silent — this guard
    flags the asymmetry, not the mere absence of a gate."""
    (tmp_path / "mcp_open_server.py").write_text(
        "async def list_tools():\n"
        "    return ALL_TOOLS\n"
        "\n"
        "\n"
        "async def call_tool(name, arguments):\n"
        "    return await TOOLS[name].run(arguments)\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_no_discovery_gate_is_safe(tmp_path: Path) -> None:
    """FP-bait: a gate present ONLY in exec (not discovery) does not match the
    discovery-gated-but-exec-ungated shape and stays silent."""
    (tmp_path / "mcp_server.py").write_text(
        "import os\n"
        "\n"
        "ALLOWED_TOOLS = os.environ.get('ALLOWED_TOOLS', '').split(',')\n"
        "\n"
        "\n"
        "async def list_tools():\n"
        "    return ALL_TOOLS\n"
        "\n"
        "\n"
        "async def call_tool(name, arguments):\n"
        "    if name not in ALLOWED_TOOLS:\n"
        "        raise PermissionError('blocked')\n"
        "    return await TOOLS[name].run(arguments)\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_gate_in_both_ts_handlers_is_safe(tmp_path: Path) -> None:
    """FP-bait: the TS region-sliced check also stays silent when the gate is applied in
    BOTH the discovery and execution handler regions."""
    (tmp_path / "server.ts").write_text(
        "import { Server } from '@modelcontextprotocol/sdk/server';\n"
        "\n"
        "const server = new Server();\n"
        "\n"
        "server.setRequestHandler(ListToolsRequestSchema, async () => {\n"
        "  return allTools.filter(t => ALLOWED_TOOLS.includes(t.name));\n"
        "});\n"
        "\n"
        "server.setRequestHandler(CallToolRequestSchema, async (req) => {\n"
        "  if (!ALLOWED_TOOLS.includes(req.params.name)) throw new Error('blocked');\n"
        "  return tools[req.params.name].run(req.params.arguments);\n"
        "});\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-toolgate-asymmetry/discovery-exec-mismatch" for f in findings)


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "mcp_kube_server.py").write_text(
        "import os\n"
        "\n"
        "ALLOWED_TOOLS = os.environ.get('ALLOWED_TOOLS', '').split(',')\n"
        "\n"
        "\n"
        "async def list_tools():\n"
        "    return [t for t in ALL_TOOLS if t.name in ALLOWED_TOOLS]\n"
        "\n"
        "\n"
        "async def call_tool(name, arguments):  # security: allow-mcp-toolgate-asymmetry\n"
        "    return await TOOLS[name].run(arguments)\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding_in_ts_file(tmp_path: Path) -> None:
    # (agentic pre-review H-8): the `#`-anchored regex never matched in a `.ts` file,
    # so `// security: allow-...` silently never suppressed anything there.
    (tmp_path / "server.ts").write_text(
        "// security: allow-mcp-toolgate-asymmetry\n"
        "import { Server } from '@modelcontextprotocol/sdk/server';\n"
        "\n"
        "const server = new Server();\n"
        "\n"
        "server.setRequestHandler(ListToolsRequestSchema, async () => {\n"
        "  return allTools.filter(t => ALLOWED_TOOLS.includes(t.name));\n"
        "});\n"
        "\n"
        "server.setRequestHandler(CallToolRequestSchema, async (req) => {\n"
        "  return tools[req.params.name].run(req.params.arguments);\n"
        "});\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpToolgateAsymmetryGuard().applies(prof) is False


def test_guard_applicable_with_mcp_feature(tmp_path: Path) -> None:
    assert McpToolgateAsymmetryGuard().applies(_mcp_prof(tmp_path)) is True


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "mcp_kube_server.py").write_text(
        "import os\n"
        "\n"
        "ALLOWED_TOOLS = os.environ.get('ALLOWED_TOOLS', '').split(',')\n"
        "\n"
        "\n"
        "async def list_tools():\n"
        "    return [t for t in ALL_TOOLS if t.name in ALLOWED_TOOLS]\n"
        "\n"
        "\n"
        "async def call_tool(name, arguments):\n"
        "    return await TOOLS[name].run(arguments)\n",
        encoding="utf-8",
    )
    findings = McpToolgateAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


# --- #1055: a TS/JS gate counts in live code or a one-identifier string, never in prose ----------

_TS_SERVER = (
    "import { Server } from '@modelcontextprotocol/sdk/server';\n"
    "\n"
    "const server = new Server();\n"
    "\n"
    "server.setRequestHandler(ListToolsRequestSchema, async () => {\n"
    "  {DISCOVERY}\n"
    "});\n"
    "\n"
    "server.setRequestHandler(CallToolRequestSchema, async (req) => {\n"
    "  {EXEC}\n"
    "  return tools[req.params.name].run(req.params.arguments);\n"
    "});\n"
)
_GATED_LISTING = "return allTools.filter(t => ALLOWED_TOOLS.includes(t.name));"


def _run_ts(tmp_path: Path, discovery: str, exec_line: str) -> list[str]:
    (tmp_path / "server.ts").write_text(
        _TS_SERVER.replace("{DISCOVERY}", discovery).replace("{EXEC}", exec_line), encoding="utf-8"
    )
    prof = _mcp_prof(tmp_path)
    assert McpToolgateAsymmetryGuard().applies(prof)
    return [f.location.replace("\\", "/") for f in McpToolgateAsymmetryGuard().run(tmp_path, prof)]


@pytest.mark.parametrize(
    "exec_line",
    [
        "console.log('readonly mode is not enforced here');",
        "throw new Error(\"TODO: check ALLOWED_TOOLS before running\");",
        "log.warn(`allow-only list for ${tenant} is not wired up`);",  # template TEXT
    ],
)
def test_ts_prose_gate_in_exec_no_longer_clears(tmp_path: Path, exec_line: str) -> None:
    # The FN direction (#1055): each of these gated the exec handler on main.
    assert _run_ts(tmp_path, _GATED_LISTING, exec_line) == ["server.ts:9"]


@pytest.mark.parametrize(
    "exec_line",
    [
        "if (!ALLOWED_TOOLS.includes(req.params.name)) throw new Error('denied');",
        # An env key is a string by nature: a one-identifier literal still gates (the H-7b rule).
        "if (!process.env['ALLOWED_TOOLS'].split(',').includes(req.params.name)) throw new Error('x');",
        "if (config.get(\"read-only\")) throw new Error('x');",
        # A real gate nested in a `${...}` substitution is code (the shortcut-separating case).
        "log(`gate ${assertAllowed(ALLOWED_TOOLS, req.params.name)}`);",
        # A prose copy first in the region must not hide the real gate after it.
        "log('readonly is enforced below'); if (READ_ONLY) throw new Error('x');",
    ],
)
def test_ts_real_gate_in_exec_still_clears(tmp_path: Path, exec_line: str) -> None:
    assert _run_ts(tmp_path, _GATED_LISTING, exec_line) == []


def test_ts_prose_gate_in_discovery_is_not_a_gate(tmp_path: Path) -> None:
    # The FP direction (#1055): with no real gate anywhere there is no asymmetry, but a prose
    # `'readonly'` in the discovery handler used to count as one and fired HIGH.
    discovery = "console.log('readonly listing for now'); return allTools;"
    assert _run_ts(tmp_path, discovery, "") == []


def test_ts_gate_in_discovery_substitution_still_fires(tmp_path: Path) -> None:
    # The other direction: a real discovery gate nested in a `${...}` still counts, so the
    # ungated exec handler still fires.
    discovery = "log(`listing ${allTools.filter(t => ALLOWED_TOOLS.includes(t.name)).length}`);"
    assert _run_ts(tmp_path, discovery, "") == ["server.ts:9"]
