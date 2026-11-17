"""Tests for McpToolsListUnboundedGuard — planted-violation + FP-bait."""
from __future__ import annotations

import pytest

from agentsec.guards.mcp_tools_list_unbounded import McpToolsListUnboundedGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "llm", "python"}, python_dirs=["."])


def test_fires_on_unbounded_python_aggregation(tmp_path: Path) -> None:
    """HIGH: list_tools() accumulates an upstream JSON response with no bound at all
    anywhere in the file — CVE-2026-84289's own shape (Hermes Agent)."""
    (tmp_path / "mcp_tool_aggregator.py").write_text(
        "import httpx\n"
        "\n"
        "\n"
        "async def list_tools(server_url: str) -> list[dict]:\n"
        "    tools = []\n"
        "    resp = await httpx.get(server_url + '/tools')\n"
        "    for tool in resp.json()['tools']:\n"
        "        tools.append(tool)\n"
        "    return tools\n",
        encoding="utf-8",
    )
    findings = McpToolsListUnboundedGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-tools-list-unbounded/no-catalogue-bound" for f in findings)
    hit = next(f for f in findings if f.rule == "mcp-tools-list-unbounded/no-catalogue-bound")
    assert hit.severity == "high"


def test_fires_on_unbounded_ts_aggregation(tmp_path: Path) -> None:
    """HIGH: the same unbounded-accumulation shape in TS also fires."""
    (tmp_path / "aggregator.ts").write_text(
        "async function listTools(serverUrl: string) {\n"
        "  const tools: any[] = [];\n"
        "  const resp = await fetch(serverUrl + '/tools');\n"
        "  const data = await resp.json();\n"
        "  for (const tool of data.tools) {\n"
        "    tools.push(tool);\n"
        "  }\n"
        "  return tools;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpToolsListUnboundedGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-tools-list-unbounded/no-catalogue-bound" for f in findings)


def test_bounded_with_slice_is_safe(tmp_path: Path) -> None:
    """FP-bait: a slice bound (tools[:200]) anywhere in the file silences the finding."""
    (tmp_path / "mcp_tool_aggregator.py").write_text(
        "import httpx\n"
        "\n"
        "\n"
        "async def list_tools(server_url: str) -> list[dict]:\n"
        "    tools = []\n"
        "    resp = await httpx.get(server_url + '/tools')\n"
        "    for tool in resp.json()['tools']:\n"
        "        tools.append(tool)\n"
        "    return tools[:200]\n",
        encoding="utf-8",
    )
    findings = McpToolsListUnboundedGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tools-list-unbounded/no-catalogue-bound" for f in findings)


def test_bounded_with_length_check_is_safe(tmp_path: Path) -> None:
    """FP-bait: a len(...) comparison bound silences the finding."""
    (tmp_path / "mcp_tool_aggregator.py").write_text(
        "import httpx\n"
        "\n"
        "MAX_TOOLS = 200\n"
        "\n"
        "\n"
        "async def list_tools(server_url: str) -> list[dict]:\n"
        "    tools = []\n"
        "    resp = await httpx.get(server_url + '/tools')\n"
        "    for tool in resp.json()['tools']:\n"
        "        if len(tools) > MAX_TOOLS:\n"
        "            break\n"
        "        tools.append(tool)\n"
        "    return tools\n",
        encoding="utf-8",
    )
    findings = McpToolsListUnboundedGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tools-list-unbounded/no-catalogue-bound" for f in findings)


def test_local_literal_source_is_safe(tmp_path: Path) -> None:
    """FP-bait: a list_tools() built from a local literal (not a remote response) does
    not match the remote-source signal at all."""
    (tmp_path / "static_tools.py").write_text(
        "def list_tools() -> list[dict]:\n"
        "    tools = []\n"
        "    for name in ('add', 'subtract', 'multiply'):\n"
        "        tools.append({'name': name})\n"
        "    return tools\n",
        encoding="utf-8",
    )
    findings = McpToolsListUnboundedGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_static_registry_with_unrelated_json_and_session_calls_is_safe(tmp_path: Path) -> None:
    """(agentic pre-review M-2): an ordinary MCP server with a genuinely STATIC tool
    registry must not fire just because an UNRELATED pydantic model's `.json()` call or an
    unrelated SQLAlchemy `await session.` database query happens to appear elsewhere in the
    same file -- these satisfy the old whole-file "remote source" signal by pure coincidence,
    not because list_tools() itself reads from the wire."""
    (tmp_path / "server.py").write_text(
        "from pydantic import BaseModel\n"
        "\n"
        "class ToolSpec(BaseModel):\n"
        "    name: str\n"
        "\n"
        "STATIC_TOOLS = [ToolSpec(name='a'), ToolSpec(name='b')]\n"
        "\n"
        "def list_tools():\n"
        "    return STATIC_TOOLS\n"
        "\n"
        "def log_registry():\n"
        "    for tool in STATIC_TOOLS:\n"
        "        print(tool.json())\n"
        "\n"
        "async def refresh_session_cache(session):\n"
        "    rows = await session.execute('select 1')\n"
        "    for row in rows:\n"
        "        cache.append(row)\n",
        encoding="utf-8",
    )
    findings = McpToolsListUnboundedGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tools-list-unbounded/no-catalogue-bound" for f in findings)


def test_delegating_list_tools_wrapper_still_fires(tmp_path: Path) -> None:
    """Widening safety check (Dean's review, fast-follow): a THIN `list_tools()` wrapper that
    delegates the actual fetch+accumulate work to a local helper it calls by bare name -- a
    common, realistic shape -- must still fire; the discovery function's own body alone (just a
    `return` of the helper's call) carries neither the remote-source nor the accumulation
    signal."""
    (tmp_path / "mcp_tool_aggregator.py").write_text(
        "import httpx\n"
        "\n"
        "\n"
        "def _fetch_and_accumulate(server_url):\n"
        "    tools = []\n"
        "    resp = httpx.get(server_url + '/tools')\n"
        "    for tool in resp.json()['tools']:\n"
        "        tools.append(tool)\n"
        "    return tools\n"
        "\n"
        "\n"
        "async def list_tools(server_url: str) -> list[dict]:\n"
        "    return _fetch_and_accumulate(server_url)\n",
        encoding="utf-8",
    )
    findings = McpToolsListUnboundedGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-tools-list-unbounded/no-catalogue-bound" for f in findings)



@pytest.mark.parametrize(
    ("list_tools_body", "call_prefix"),
    [
        pytest.param("def list_tools():\n    record_metrics(STATIC_TOOLS)\n", "", id="sync"),
        pytest.param("async def list_tools():\n    await record_metrics(STATIC_TOOLS)\n", "async ", id="awaited"),
    ],
)
def test_static_registry_calling_an_unrelated_batching_helper_is_safe(
    tmp_path: Path, list_tools_body: str, call_prefix: str
) -> None:
    """FP-bait for the one-hop helper resolution (PR #923 round-3 M3): at e6f95e89 every called
    helper's body was joined into `list_tools()`, so a static registry fired HIGH just for
    calling a metrics helper that batches with `for ... append` and posts the batch. A call made
    as a bare statement discards its result, so the catalogue cannot come from it."""
    (tmp_path / "server.py").write_text(
        "import requests\n"
        "\n"
        "STATIC_TOOLS = [{'name': 'search'}, {'name': 'fetch'}]\n"
        "\n"
        f"{call_prefix}def record_metrics(tools):\n"
        "    batch = []\n"
        "    for tool in tools:\n"
        "        batch.append(tool['name'])\n"
        "    requests.post(METRICS_URL, json=batch)\n"
        "\n"
        f"{list_tools_body}"
        "    return STATIC_TOOLS\n",
        encoding="utf-8",
    )
    findings = McpToolsListUnboundedGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


@pytest.mark.parametrize(
    "list_tools_def",
    [
        pytest.param(
            "async def list_tools(server_url: str) -> list[dict]:\n"
            "    tools = await _fetch_and_accumulate(server_url)\n"
            "    return tools\n",
            id="assigned-from-await",
        ),
        pytest.param(
            "async def list_tools(server_url: str) -> list[dict]:\n"
            "    catalogue = []\n"
            "    catalogue.extend(await _fetch_and_accumulate(server_url))\n"
            "    return catalogue\n",
            id="passed-on",
        ),
    ],
)
def test_delegating_list_tools_that_uses_the_result_still_fires(tmp_path: Path, list_tools_def: str) -> None:
    """Still-fires companion for the M3 narrowing: a helper whose result `list_tools()` assigns
    or passes on is where the catalogue comes from, so its body still joins the match."""
    (tmp_path / "mcp_tool_aggregator.py").write_text(
        "import httpx\n"
        "\n"
        "\n"
        "async def _fetch_and_accumulate(server_url):\n"
        "    tools = []\n"
        "    resp = await httpx.get(server_url + '/tools')\n"
        "    for tool in resp.json()['tools']:\n"
        "        tools.append(tool)\n"
        "    return tools\n"
        "\n"
        "\n"
        f"{list_tools_def}",
        encoding="utf-8",
    )
    findings = McpToolsListUnboundedGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-tools-list-unbounded/no-catalogue-bound" for f in findings)


@pytest.mark.parametrize(
    ("kw", "fill", "call"),
    [
        pytest.param("", "        tools.append(tool)\n", "    _fetch_into(tools, server_url)\n", id="append"),
        pytest.param(
            "async ", "        tools.append(tool)\n", "    await _fetch_into(tools, server_url)\n", id="awaited"
        ),
        pytest.param("", "        tools[tool['name']] = tool\n", "    _fetch_into(tools, server_url)\n", id="subscript"),
        pytest.param("", "        tools += [tool]\n", "    _fetch_into(tools, server_url)\n", id="augmented"),
    ],
)
def test_bare_call_to_a_helper_that_fills_the_callers_list_still_fires(
    tmp_path: Path, kw: str, fill: str, call: str
) -> None:
    """Still-fires for the M3 narrowing (PR #923 round-4 review, measured): skipping every
    bare-statement call silenced the out-parameter idiom, where the helper's result is discarded
    because it fills the list the caller passed in. That fired at e6f95e89 and must still fire."""
    (tmp_path / "aggregator.py").write_text(
        "import requests\n"
        "\n"
        f"{kw}def _fetch_into(tools, server_url):\n"
        "    resp = requests.get(server_url + '/tools')\n"
        "    for tool in resp.json()['tools']:\n"
        f"{fill}"
        "\n"
        f"{kw}def list_tools(server_url: str):\n"
        "    tools = []\n"
        f"{call}"
        "    return tools\n",
        encoding="utf-8",
    )
    findings = McpToolsListUnboundedGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-tools-list-unbounded/no-catalogue-bound" for f in findings)

def test_no_discovery_site_is_safe(tmp_path: Path) -> None:
    """FP-bait: a file with a remote fetch + accumulation but no tools/list discovery
    marker at all does not fire — unrelated aggregation code."""
    (tmp_path / "log_fetcher.py").write_text(
        "import httpx\n"
        "\n"
        "\n"
        "async def fetch_logs(url: str) -> list[dict]:\n"
        "    logs = []\n"
        "    resp = await httpx.get(url)\n"
        "    for entry in resp.json()['entries']:\n"
        "        logs.append(entry)\n"
        "    return logs\n",
        encoding="utf-8",
    )
    findings = McpToolsListUnboundedGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "mcp_tool_aggregator.py").write_text(
        "import httpx\n"
        "\n"
        "\n"
        "async def list_tools(server_url: str) -> list[dict]:  # security: allow-mcp-tools-list-unbounded\n"
        "    tools = []\n"
        "    resp = await httpx.get(server_url + '/tools')\n"
        "    for tool in resp.json()['tools']:\n"
        "        tools.append(tool)\n"
        "    return tools\n",
        encoding="utf-8",
    )
    findings = McpToolsListUnboundedGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding_in_ts_file(tmp_path: Path) -> None:
    # (agentic pre-review H-8): the `#`-anchored regex never matched in a `.ts` file,
    # so `// security: allow-...` silently never suppressed anything there.
    (tmp_path / "aggregator.ts").write_text(
        "// security: allow-mcp-tools-list-unbounded\n"
        "async function listTools(serverUrl: string) {\n"
        "  const tools: any[] = [];\n"
        "  const resp = await fetch(serverUrl + '/tools');\n"
        "  const data = await resp.json();\n"
        "  for (const tool of data.tools) {\n"
        "    tools.push(tool);\n"
        "  }\n"
        "  return tools;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpToolsListUnboundedGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpToolsListUnboundedGuard().applies(prof) is False


def test_guard_applicable_with_mcp_feature(tmp_path: Path) -> None:
    assert McpToolsListUnboundedGuard().applies(_mcp_prof(tmp_path)) is True


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "mcp_tool_aggregator.py").write_text(
        "import httpx\n"
        "\n"
        "\n"
        "async def list_tools(server_url: str) -> list[dict]:\n"
        "    tools = []\n"
        "    resp = await httpx.get(server_url + '/tools')\n"
        "    for tool in resp.json()['tools']:\n"
        "        tools.append(tool)\n"
        "    return tools\n",
        encoding="utf-8",
    )
    findings = McpToolsListUnboundedGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


# --- #1055: TS/JS signals and the bound must be live code -----------------------------------------

_TS_AGGREGATOR = (
    "server.setRequestHandler(ListToolsRequestSchema, async () => {\n"
    "  const tools = [];\n"
    "  const resp = await fetch(UPSTREAM);\n"
    "  (await resp.json()).tools.forEach(t => tools.push(t));\n"
    "  {EXTRA}\n"
    "  return { tools };\n"
    "});\n"
)


def _run_ts(tmp_path: Path, text: str) -> list[str]:
    (tmp_path / "aggregator.ts").write_text(text, encoding="utf-8")
    prof = _mcp_prof(tmp_path)
    assert McpToolsListUnboundedGuard().applies(prof)
    return [f.location.replace("\\", "/") for f in McpToolsListUnboundedGuard().run(tmp_path, prof)]


@pytest.mark.parametrize(
    "extra",
    [
        "const E = 'no limit configured';",
        "log.warn(`no limit configured for ${UPSTREAM}`);",  # template TEXT
        "throw new Error(\"truncation is a TODO\");",
        # A query parameter only ASKS the upstream for fewer tools; the upstream still decides.
        "await fetch(UPSTREAM + '/tools?limit=100');",
    ],
)
def test_ts_quoted_bound_no_longer_clears(tmp_path: Path, extra: str) -> None:
    # The FN direction (#1055): each of these cleared the finding on main.
    assert _run_ts(tmp_path, _TS_AGGREGATOR.replace("{EXTRA}", extra)) == ["aggregator.ts:1"]


@pytest.mark.parametrize(
    "extra",
    [
        "if (tools.length > 200) throw new Error('too many tools');",
        "tools.splice(MAX_TOOLS);",
        # An env or config key is a string by nature: a one-identifier literal still bounds.
        "const n = Number(process.env['MAX_TOOLS']);",
        "const opts = { 'limit': 50 };",
        # A real bound nested in a `${...}` substitution is code (the shortcut-separating case).
        "log(`kept ${tools.slice(0, 200).length}`);",
        # A prose copy first on the line must not hide the real bound after it.
        "log('no limit yet'); if (tools.length > 200) throw new Error('x');",
        # A quoted bound that OVERLAPS the real one must not swallow it: the old `finditer` loop let a
        # dropped quoted match consume its span (PR #1131 round 2, L1).
        "const s = 'len(tools'; if (len(tools) > 3) throw new Error('x');",
    ],
)
def test_ts_real_bound_still_clears(tmp_path: Path, extra: str) -> None:
    assert _run_ts(tmp_path, _TS_AGGREGATOR.replace("{EXTRA}", extra)) == []


@pytest.mark.parametrize(
    "text",
    [
        "const DOC = 'listTools( then fetch( then .push( is the pattern';\n",
        # A live discovery site and fetch, but the accumulation is only named in a log string.
        "async function listTools(u) {\n  const r = await fetch(u);\n  log(`then .push( each of ${u}`);\n}\n",
    ],
)
def test_ts_signal_spelled_in_a_string_does_not_fire(tmp_path: Path, text: str) -> None:
    # The FP direction (#1055).
    assert _run_ts(tmp_path, text) == []


def test_ts_signals_in_a_substitution_still_fire(tmp_path: Path) -> None:
    # The remote source and the accumulation sit only inside a `${...}`, which is code.
    text = (
        "async function listTools(u) {\n"
        "  return log(`got ${(await fetch(u).then(r => r.json())).tools.map(t => t.name)}`);\n"
        "}\n"
    )
    assert _run_ts(tmp_path, text) == ["aggregator.ts:1"]


def test_ts_finding_line_is_the_first_live_discovery_site(tmp_path: Path) -> None:
    # The line used to come from the raw text, so a quoted (or commented) copy above won.
    text = "const DOC = \"call listTools( to refresh\";\n" + _TS_AGGREGATOR.replace("{EXTRA}", "")
    assert _run_ts(tmp_path, text) == ["aggregator.ts:2"]


def test_ts_pragma_still_suppresses_a_live_finding(tmp_path: Path) -> None:
    text = _TS_AGGREGATOR.replace("{EXTRA}", "")
    assert _run_ts(tmp_path, text) == ["aggregator.ts:1"]
    assert _run_ts(tmp_path, "// security: allow-mcp-tools-list-unbounded\n" + text) == []
