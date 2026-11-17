"""Tests for McpEnvPlaceholderExfilGuard — planted-violation + FP-bait."""
from __future__ import annotations

import pytest

from agentsec.guards.mcp_env_placeholder_exfil import McpEnvPlaceholderExfilGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "llm", "python"}, python_dirs=["."])


def test_fires_on_python_expandvars_in_mcp_context(tmp_path: Path) -> None:
    """CRITICAL: os.path.expandvars() on a user-supplied MCP server URL — CVE-2026-32625 shape."""
    (tmp_path / "mcp_client.py").write_text(
        "import os\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "def connect(server_url: str) -> str:\n"
        "    return os.path.expandvars(server_url)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)
    hit = next(f for f in findings if f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution")
    assert hit.severity == "critical"


def test_fires_on_python_format_env(tmp_path: Path) -> None:
    """CRITICAL: .format(**os.environ) spreads the whole environment into a template."""
    (tmp_path / "mcp_server_url.py").write_text(
        "import os\n"
        "\n"
        "def resolve(mcp_server_url: str) -> str:\n"
        "    return mcp_server_url.format(**os.environ)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)


def test_marker_label_matches_the_actual_finding_not_a_whole_file_substring(tmp_path: Path) -> None:
    """(agentic pre-review L-4): the marker label used to key off a whole-file
    substring check ("expandvars" in text), not which pattern actually produced the finding --
    a file with a SAFE (literal-argument) expandvars call alongside the REAL finding (a bare-
    variable .format(**os.environ)) used to mislabel the finding's own message as
    "os.path.expandvars" even though expandvars is not the vulnerable call here at all."""
    (tmp_path / "mcp_server.py").write_text(
        "import os\n"
        "\n"
        "LOG_DIR = os.path.expandvars('$HOME/logs')\n"
        "\n"
        "def resolve(mcp_server_url: str) -> str:\n"
        "    return mcp_server_url.format(**os.environ)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution")
    assert "os.environ" in hit.message
    assert "os.path.expandvars" not in hit.message


def test_fires_on_python_format_map_environ(tmp_path: Path) -> None:
    """CRITICAL: .format_map(os.environ) is the same shape as .format(**os.environ)."""
    (tmp_path / "server_config.py").write_text(
        "import os\n"
        "\n"
        "def resolve_mcp_server_url(template: str) -> str:\n"
        "    return template.format_map(os.environ)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)


def test_fires_on_ts_replace_process_env_in_mcp_context(tmp_path: Path) -> None:
    """CRITICAL: TS .replace(/${.../, ...process.env) resolving a placeholder against process.env."""
    (tmp_path / "mcpServerUrl.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/sdk';\n"
        "\n"
        "function resolveServerUrl(serverUrl: string): string {\n"
        "  return serverUrl.replace(/\\$\\{(\\w+)\\}/g, (_, name) => process.env[name] ?? '');\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)


def test_expandvars_static_string_literal_is_safe(tmp_path: Path) -> None:
    """(Dean's review, agentic pre-review H-4): a plain string literal argument is
    fixed at read time and can never vary by caller -- a hardcoded log-directory path is not
    the "resolves a caller-supplied value" vulnerability this guard targets, regardless of
    what env var name happens to appear inside the literal."""
    (tmp_path / "mcp_server.py").write_text(
        "import os\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "LOG_DIR = os.path.expandvars('$HOME/logs')\n"
        "\n"
        "def connect(server_url: str) -> str:\n"
        "    return server_url\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)


def test_format_env_static_template_literal_is_safe(tmp_path: Path) -> None:
    """FP-bait companion for .format(**os.environ): a hardcoded template string can't leak an
    attacker-chosen env var -- only a caller-supplied template could embed {SECRET_NAME}."""
    (tmp_path / "mcp_server.py").write_text(
        "import os\n"
        "\n"
        "def resolve(server_url: str) -> str:\n"
        "    return 'static template with no placeholders'.format(**os.environ)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)


def test_expandvars_bare_variable_still_fires_alongside_a_literal(tmp_path: Path) -> None:
    """Still-fires companion: a literal expandvars() call earlier in the file must not mask a
    genuinely caller-supplied one later in the same file."""
    (tmp_path / "mcp_server.py").write_text(
        "import os\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "LOG_DIR = os.path.expandvars('$HOME/logs')\n"
        "\n"
        "def connect(server_url: str) -> str:\n"
        "    return os.path.expandvars(server_url)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)


def test_no_mcp_context_python_expandvars_is_safe(tmp_path: Path) -> None:
    """FP-bait: os.path.expandvars() in a file with no MCP context marker does not fire —
    the MCP-context gate exists exactly to avoid firing on unrelated env-var expansion."""
    (tmp_path / "path_helpers.py").write_text(
        "import os\n"
        "\n"
        "def resolve_path(template: str) -> str:\n"
        "    return os.path.expandvars(template)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)


def test_bare_variable_with_distant_docstring_only_mcp_signal_is_safe(tmp_path: Path) -> None:
    """Narrowing safety check (Dean's review, round 2): the MCP-context gate used to be
    whole-file, so a bare-variable expandvars() call with NO real connection to MCP still fired
    CRITICAL just because the file's docstring happened to say "MCP" dozens of lines away. The
    marker must now appear within a nearby window of the actual call."""
    padding = "\n".join(f"# unrelated line {i}" for i in range(30))
    (tmp_path / "log_helpers.py").write_text(
        '"""Shared helpers; also used by our MCP integration elsewhere in this repo."""\n'
        "import os\n"
        f"{padding}\n"
        "\n"
        "def resolve_log_path(raw: str) -> str:\n"
        "    return os.path.expandvars(raw)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)


def test_bare_variable_with_nearby_mcp_signal_still_fires(tmp_path: Path) -> None:
    """FP-bait companion for the proximity window itself: an MCP-context marker in the
    ENCLOSING FUNCTION (its own docstring/signature, a realistic distance) must still count —
    the window is proximity, not same-line."""
    (tmp_path / "resolver.py").write_text(
        "import os\n"
        "\n"
        "def connect_mcp_server(raw_url: str) -> str:\n"
        '    """Resolve placeholders in a user-supplied MCP server URL."""\n'
        "    return os.path.expandvars(raw_url)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)


def test_long_handler_in_a_real_server_still_fires(tmp_path: Path) -> None:
    """Still-fires for the proximity window (PR #923 round-3 H1): a real MCP server whose
    `expandvars` call sits deeper than the window into a long `@server.call_tool()` handler
    went silent at e6f95e89, because the only markers were the import and constructor at the
    top. An MCP marker in real code anywhere in the file now counts."""
    body = "".join(f"    step_{i} = prepare({i})\n" for i in range(18))
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "import os\n"
        "\n"
        "server = Server('fetcher')\n"
        "\n"
        "\n"
        "@server.call_tool()\n"
        "async def handle(name, arguments):\n"
        f"{body}"
        "    url = os.path.expandvars(arguments['url'])\n"
        "    return await fetch(url)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [f.location for f in findings] == ["server.py:27"]


def test_real_call_after_an_unrelated_distant_call_fires_on_the_real_one(tmp_path: Path) -> None:
    """Still-fires (PR #923 round-3 H1): only the EARLIEST candidate used to be
    proximity-tested, so an unrelated `expandvars` near the top of the file hid a real one next
    to `server_url` further down. Every candidate is considered now, and the finding anchors on
    the one with MCP context beside it."""
    padding = "".join(f"SETTING_{i} = {i}\n" for i in range(40))
    (tmp_path / "config_loader.py").write_text(
        "import os\n"
        "BASE = os.path.expandvars(base_dir)\n"
        f"{padding}"
        "\n"
        "def connect(cfg):\n"
        "    return os.path.expandvars(cfg['server_url'])\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [f.location for f in findings] == ["config_loader.py:45"]


_TS_FAR_PAD = "".join(f"const setting{i} = {i};\n" for i in range(20))
_TS_ENV_REPLACE = "u.replace(/\\$\\{(\\w+)\\}/g, (_: string, k: string) => process.env[k] ?? '')"


_SDK_FILLER = "".join(f"def step{i}():\n    pass\n\n" for i in range(9))


@pytest.mark.parametrize(
    ("name", "text"),
    [
        pytest.param(
            "client.py",
            '"""Client wrapper for connecting to remote MCP servers."""\n'
            "from mcp import ClientSession\nimport os\n\n" + _SDK_FILLER
            + "def load_cache_dir():\n"
            '    raw = os.environ.get("CACHE_DIR_TEMPLATE", "$HOME/.cache")\n'
            "    return os.path.expandvars(raw)\n",
            id="client-cache-dir-helper",
        ),
        pytest.param(
            "server.py",
            "from mcp.server import Server\nimport os\n\nserver = Server('demo')\n\n"
            "@server.call_tool()\nasync def handle_call(name, arguments):\n    return TOOLS[name].run(arguments)\n\n"
            + _SDK_FILLER
            + "def _plugin_cache_dir(raw: str) -> str:\n    return os.path.expandvars(raw)\n",
            id="server-plugin-dir-helper",
        ),
        pytest.param(
            "server.py",
            "from mcp.server.fastmcp import FastMCP\nimport os\n\n" + _SDK_FILLER
            + "def register(app: FastMCP, raw: str) -> None:\n"
            "    cache = os.path.expandvars(raw)\n\n"
            "    @app.tool()\n"
            "    def ping() -> str:\n"
            "        return cache\n",
            id="factory-registering-a-nested-handler",
        ),
        pytest.param(
            "server.py",
            "import functools\nfrom mcp.server import Server\nimport os\n\nserver = Server('demo')\n\n"
            "@server.call_tool()\nasync def handle_call(name, arguments):\n    return TOOLS[name].run(arguments)\n\n"
            + _SDK_FILLER
            + "@functools.lru_cache(maxsize=None)\ndef _plugin_cache_dir(raw: str) -> str:\n"
            "    return os.path.expandvars(raw)\n",
            id="helper-with-a-non-handler-decorator",
        ),
        pytest.param(
            "server.ts",
            'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
            "const server = new McpServer({ name: 'x', version: '1' });\n"
            "server.tool('ping', {}, async () => ({ content: [] }));\n"
            + _TS_FAR_PAD
            + f"export function resolve(u: string): string {{\n  return {_TS_ENV_REPLACE};\n}}\n",
            id="ts-helper-after-a-handler",
        ),
        pytest.param(
            "server.ts",
            'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
            "const server = new McpServer({ name: 'x', version: '1' });\n"
            + _TS_FAR_PAD
            + f"async function other(u: string) {{\n  return {_TS_ENV_REPLACE};\n}}\n"
            "server.tool('fetch', {}, fetchHandler);\n",
            id="ts-named-function-that-is-not-registered",
        ),
        pytest.param(
            "server.ts",
            'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
            "const server = new McpServer({ name: 'x', version: '1' });\n"
            "async function fetchHandler({ url }) {\n  return url;\n}\n"
            + _TS_FAR_PAD
            + f"export function resolve(u: string): string {{\n  return {_TS_ENV_REPLACE};\n}}\n"
            "server.tool('fetch', {}, fetchHandler);\n",
            id="ts-code-after-a-named-handler-body",
        ),
        pytest.param(
            "server.ts",
            'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
            "const server = new McpServer({ name: 'x', version: '1' });\n"
            "server.tool('fetch', {}, async ({ url }) => {\n"
            "  const opens = /[(]/.test(String(url));\n"
            "  return { ok: opens };\n"
            "});\n"
            + _TS_FAR_PAD
            + f"export function unrelatedHelper(u: string): string {{\n  return {_TS_ENV_REPLACE};\n}}\n",
            id="ts-regex-char-class-in-an-earlier-handler",
        ),
    ],
)
def test_unrelated_call_in_an_sdk_file_outside_any_handler_is_safe(
    tmp_path: Path, name: str, text: str
) -> None:
    """FP-bait for the SDK-use fallback (PR #923 round-4 re-review, High 1, measured): at
    b8f24245 any bare-variable `expandvars` fired CRITICAL in a file that imports the MCP SDK,
    so every MCP client's unrelated cache-dir helper did. The fallback now needs the call to sit
    inside a tool handler; a helper, or a factory that merely registers a nested handler, is not
    one. Beyond the 15-line window, these stay silent."""
    (tmp_path / name).write_text(text, encoding="utf-8")
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_bare_variable_with_distant_comment_only_mcp_signal_is_safe(tmp_path: Path) -> None:
    """FP-bait for the file-wide code-marker widening (PR #923 round-3 H1): a `#` comment that
    says "MCP" is not code, so a distant one must not count any more than a distant docstring."""
    padding = "".join(f"LIMIT_{i} = {i}\n" for i in range(30))
    (tmp_path / "log_helpers.py").write_text(
        "# Shared helpers; also used by our MCP integration elsewhere in this repo.\n"
        "import os\n"
        f"{padding}"
        "\n"
        "def resolve_log_path(raw: str) -> str:\n"
        "    return os.path.expandvars(raw)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_ts_distant_jsdoc_only_mcp_signal_is_safe(tmp_path: Path) -> None:
    """FP-bait, TS form: a JSDoc block that mentions MCP is a comment, not a code marker, so a
    `.replace(...process.env...)` far below it stays silent."""
    padding = "".join(f"const setting{i} = {i};\n" for i in range(40))
    (tmp_path / "paths.ts").write_text(
        "/** Path helpers; the MCP integration lives elsewhere. */\n"
        f"{padding}"
        "export function resolve(u: string): string {\n"
        "  return u.replace(/\\$\\{(\\w+)\\}/g, (_: string, k: string) => process.env[k] ?? '');\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []



def test_low_level_call_tool_decorator_counts_as_sdk_use(tmp_path: Path) -> None:
    """Still-fires: a handler registered with `@server.call_tool()` is MCP SDK use even when the
    server object is imported from a local module (no `from mcp` import in this file), so a call
    deep in that handler keeps its context. The module docstring passes the file-level gate but
    is too far away to count on its own, so the decorator is what makes this fire."""
    body = "".join(f"    step_{i} = prepare({i})\n" for i in range(18))
    (tmp_path / "handlers.py").write_text(
        '"""MCP tool handlers."""\n'
        "import os\n"
        "from .app import server\n"
        "\n"
        "\n"
        "@server.call_tool()\n"
        "async def handle(name, arguments):\n"
        f"{body}"
        "    return os.path.expandvars(arguments['target'])\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)



def test_fastmcp_import_far_above_a_tool_function_still_fires(tmp_path: Path) -> None:
    """Still-fires: a FastMCP server's `from mcp.server.fastmcp import FastMCP` is SDK use
    however far above the call it sits. `@app.tool()` is not the low-level decorator, so the
    import alone carries the context here."""
    padding = "".join(f"SETTING_{i} = {i}\n" for i in range(30))
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "import os\n"
        "\n"
        "app = FastMCP('fetcher')\n"
        f"{padding}"
        "\n"
        "@app.tool()\n"
        "def fetch(url: str) -> str:\n"
        "    return os.path.expandvars(url)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)

_FAR = "".join(f"LIMIT_{i} = {i}\n" for i in range(30))
_FAR_TS = "".join(f"const limit{i} = {i};\n" for i in range(40))
_TS_REPLACE = (
    "export function resolve(u: string): string {\n"
    "  return u.replace(/\\$\\{(\\w+)\\}/g, (_: string, k: string) => process.env[k] ?? '');\n"
    "}\n"
)


@pytest.mark.parametrize(
    ("name", "text"),
    [
        pytest.param(
            "helpers.py",
            'import os\nMSG = "connecting to server_url config"\n' + _FAR
            + "def resolve(raw):\n    return os.path.expandvars(raw)\n",
            id="single-line-string",
        ),
        pytest.param(
            "helpers.py",
            "import os\ndef log_proxy_target(server_url):\n    return server_url.upper()\n" + _FAR
            + "def resolve(raw):\n    return os.path.expandvars(raw)\n",
            id="unrelated-parameter",
        ),
        pytest.param("paths.ts", "const note = 'label: server_url';\n" + _FAR_TS + _TS_REPLACE, id="ts-string"),
    ],
)
def test_distant_marker_that_is_not_sdk_use_is_safe(tmp_path: Path, name: str, text: str) -> None:
    """FP-bait for the file-wide fallback (PR #923 round-4 review, measured): the first round-4
    draft accepted ANY `_MCP_CTX_RE` token outside comments and docstrings, so a single-line
    string or an unrelated helper's parameter named `server_url`, 30+ lines from a bare-variable
    `expandvars`, fired CRITICAL. Only real MCP SDK use counts file-wide now."""
    (tmp_path / name).write_text(text, encoding="utf-8")
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_non_mcp_tool_decorator_without_sdk_use_is_safe(tmp_path: Path) -> None:
    """FP-bait for the handler rule: `@x.tool` is also pydantic-ai's (and others') decorator, so
    a decorated handler only counts when the file really uses the MCP SDK. This file's only MCP
    mention is a distant docstring (enough for the file-level gate, too far for the window)."""
    padding = "".join(f"LIMIT_{i} = {i}\n" for i in range(30))
    (tmp_path / "agent_tools.py").write_text(
        '"""Agent tools; the MCP bridge lives in another package."""\n'
        "import os\n"
        "from pydantic_ai import Agent\n"
        f"{padding}"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "@agent.tool\n"
        "def cache_path(ctx, raw: str) -> str:\n"
        "    return os.path.expandvars(raw)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_handler_decorated_def_with_a_triple_quoted_default_still_fires(tmp_path: Path) -> None:
    """Still-fires: handler decorators are read from the AST, so a triple-quoted default on the
    `def` line cannot hide them (the text-matched span of an earlier draft dropped them)."""
    padding = "".join(f"SETTING_{i} = {i}\n" for i in range(30))
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\nimport os\nserver = Server('x')\n"
        f"{padding}"
        "@server.call_tool()\n"
        'async def handle(name, arguments, mode: str = """fetch"""):\n'
        "    return os.path.expandvars(arguments['url'])\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)



def test_handler_nested_in_a_registration_factory_still_fires(tmp_path: Path) -> None:
    """Still-fires: the INNERMOST function decides. A tool handler defined inside a
    `register(app)` factory is a handler even though the factory around it is not."""
    padding = "".join(f"SETTING_{i} = {i}\n" for i in range(30))
    (tmp_path / "tools.py").write_text(
        "from mcp.server.fastmcp import FastMCP\nimport os\n"
        f"{padding}"
        "def register(app: FastMCP) -> None:\n"
        "    @app.tool()\n"
        "    def fetch(url: str) -> str:\n"
        "        return os.path.expandvars(url)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)


def test_bom_prefixed_server_still_fires_inside_a_long_handler(tmp_path: Path) -> None:
    """Still-fires (#923 round-4 re-review, measured): `read()` keeps a UTF-8 BOM and `ast.parse`
    rejects a str that starts with one, so the handler map came back empty and a BOM-prefixed
    server went silent. The BOM is written as an escape on purpose."""
    body = "".join(f"    step_{i} = prepare({i})\n" for i in range(18))
    (tmp_path / "server.py").write_text(
        "\ufeff"
        "from mcp.server import Server\nimport os\nserver = Server('x')\n\n"
        "@server.call_tool()\nasync def handle(name, arguments):\n"
        f"{body}"
        "    return os.path.expandvars(arguments['url'])\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [f.location for f in findings] == ["server.py:25"]

def _handler_file(n: int, *, with_handler: bool = True) -> str:
    helpers = "".join(f"def helper_{i}(raw_{i}):\n    return os.path.expandvars(raw_{i})\n\n" for i in range(n))
    padding = "".join(f"SETTING_{i} = {i}\n" for i in range(30))
    handler = "@app.tool()\ndef ping() -> str:\n    return 'ok'\n\n" if with_handler else ""
    return "from mcp.server.fastmcp import FastMCP\nimport os\napp = FastMCP('x')\n" + handler + padding + helpers


@pytest.mark.parametrize(("with_handler", "expected_parses"), [(True, 1), (False, 0)])
def test_handler_lines_are_parsed_at_most_once_per_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_handler: bool, expected_parses: int
) -> None:
    """Performance pin (#923 round-4 re-review): an earlier draft re-parsed the module for every
    candidate that missed the window (14s at 400 candidates, against 0.04s before). The handler
    map is built from one parse per file, and no parse at all without a handler decorator."""
    import agentsec.guards.mcp_env_placeholder_exfil as mod
    from agentsec import astutil

    calls: list[int] = []
    real = astutil.safe_ast_parse

    def counting(*args: object, **kwargs: object) -> object:
        calls.append(1)
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(mod, "safe_ast_parse", counting)
    (tmp_path / "server.py").write_text(_handler_file(40, with_handler=with_handler), encoding="utf-8")
    assert McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path)) == []
    assert len(calls) == expected_parses


@pytest.mark.slow
def test_handler_fallback_stays_linear_in_candidates(tmp_path: Path) -> None:
    """Performance pin: a second draft cached the parse but still rescanned every function per
    candidate (`enclosing_function_span`), which measured quadratic with a handler present (30s at
    3200 candidates). The per-candidate check is a set lookup now. Growth ratio, not wall clock
    (tests/_timing.py)."""

    def scan(n: int) -> None:
        root = tmp_path / str(n)
        root.mkdir(exist_ok=True)
        (root / "server.py").write_text(_handler_file(n), encoding="utf-8")
        assert McpEnvPlaceholderExfilGuard().run(root, _mcp_prof(root)) == []

    assert_growth(scan, [400, 800, 1600, 3200], expected="linear")


def test_named_variable_read_is_safe(tmp_path: Path) -> None:
    """FP-bait: reading one named env var by key (not expanding a user-supplied template
    against the whole environment) is the safe, ordinary shape and must not fire."""
    (tmp_path / "mcp_client.py").write_text(
        "import os\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "def connect() -> str:\n"
        "    return os.environ.get('MCP_SERVER_URL', 'http://localhost:8000')\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)


def test_ts_replace_without_process_env_is_safe(tmp_path: Path) -> None:
    """FP-bait: an ordinary .replace() call in an MCP-context file that never reads
    process.env (e.g. a simple string cleanup) must not fire."""
    (tmp_path / "mcpServer.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/sdk';\n"
        "\n"
        "function normalize(serverUrl: string): string {\n"
        "  return serverUrl.replace(/\\/$/, '');\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-env-placeholder-exfil/env-placeholder-resolution" for f in findings)


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "mcp_client.py").write_text(
        "import os\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "def connect(server_url: str) -> str:\n"
        "    return os.path.expandvars(server_url)  # security: allow-mcp-env-placeholder-exfil\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding_in_ts_file(tmp_path: Path) -> None:
    # (agentic pre-review H-8): the `#`-anchored regex never matched in a `.ts` file
    # (`#` is not that language's line-comment marker), so `// security: allow-...` silently
    # never suppressed anything there -- only the undocumented `//# security: ...` form worked.
    (tmp_path / "mcpServerUrl.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/sdk';\n"
        "\n"
        "function resolveServerUrl(serverUrl: string): string {\n"
        "  // security: allow-mcp-env-placeholder-exfil\n"
        "  return serverUrl.replace(/\\$\\{(\\w+)\\}/g, (_, name) => process.env[name] ?? '');\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    (tmp_path / "mcp_client.py").write_text(
        "import os\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "def connect(server_url: str) -> str:\n"
        "    return os.path.expandvars(server_url)\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpEnvPlaceholderExfilGuard().applies(prof) is False


def test_guard_applicable_with_mcp_feature(tmp_path: Path) -> None:
    assert McpEnvPlaceholderExfilGuard().applies(_mcp_prof(tmp_path)) is True


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "mcp_client.py").write_text(
        "import os\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "def connect(server_url: str) -> str:\n"
        "    return os.path.expandvars(server_url)\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_multiline_block_comment_does_not_shift_line_numbers(tmp_path: Path) -> None:
    # (agentic pre-review H-6): the old hand-rolled comment stripper replaced a
    # multi-line `/* ... */` block with a SINGLE space, collapsing the newlines inside it and
    # shifting every subsequent line's reported lineno. strip_js_comments blanks in place
    # (equal length, real newlines preserved), so the reported line must match the source file.
    (tmp_path / "mcpServerUrl.ts").write_text(
        "import { McpServer } from '@modelcontextprotocol/sdk';\n"
        "/*\n"
        " * a long design-note comment\n"
        " * spanning several lines\n"
        " */\n"
        "function resolveServerUrl(serverUrl: string): string {\n"
        "  return serverUrl.replace(/\\$\\{(\\w+)\\}/g, (_, name) => process.env[name] ?? '');\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":7")


def test_ts_env_placeholder_regex_stays_linear_on_a_large_non_matching_file(tmp_path: Path) -> None:
    # (agentic pre-review H-6): the first `[^;]*?` span was unbounded, real
    # quadratic-time blowup on a large `.replace(` call that never reaches the placeholder
    # pattern (measured up to 95s on a 167 KB file before the fix). A growth-ratio assertion
    # (tests/_timing.py) rather than an absolute wall-clock budget, per this project's own
    # timing-budget convention: machine speed cancels out of a ratio, so this can't flake on a
    # slow or loaded box the way a bare `assert elapsed < N` would.
    def scan(size: int) -> None:
        root = tmp_path / str(size)
        root.mkdir(exist_ok=True)
        # Many `.replace(` occurrences with NO semicolon anywhere in the file (`[^;]*?` only
        # stops at a `;` or end of string) and no real `${...process.env}` shape ever appearing
        # -- this is the shape that made the unbounded first span quadratic: EVERY occurrence
        # forces its own long failed lazy scan across the remaining text before giving up.
        unit = ".replace(" + "x" * 40
        body = unit * (size // len(unit))
        (root / "big.ts").write_text(
            "import { McpServer } from '@modelcontextprotocol/sdk'\n" + body,
            encoding="utf-8",
        )
        McpEnvPlaceholderExfilGuard().run(root, _mcp_prof(root))

    assert_growth(scan, [2_000, 8_000, 32_000, 128_000], expected="linear")


# #613: the call splitter read `'''` as three separate quotes, so a triple-quoted literal holding an
# apostrophe split to None, the empty argument read as "not a static literal", and the call fired.
def _expandvars_triple_quoted(tmp_path: Path, arg: str) -> list[str]:
    (tmp_path / "mcp_server.py").write_text(
        "import os\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "def connect(server_url: str) -> str:\n"
        f"    return os.path.expandvars({arg})\n",
        encoding="utf-8",
    )
    return [f.rule for f in McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))]


def test_expandvars_triple_quoted_static_literal_with_an_apostrophe_is_safe(tmp_path: Path) -> None:
    assert _expandvars_triple_quoted(tmp_path, "'''$HOME/the app's logs'''") == []


def test_expandvars_triple_quoted_literal_concatenated_with_a_caller_value_still_fires(
    tmp_path: Path,
) -> None:
    """The direction traded against (Rule 1): the split now resolves, and a literal joined to a
    caller-supplied value is still not static, so it still fires."""
    rules = _expandvars_triple_quoted(tmp_path, "'''$HOME/the app's ''' + server_url")
    assert rules == ["mcp-env-placeholder-exfil/env-placeholder-resolution"]


# --- #1055: a TS/JS `.replace(` candidate counts only when its call and replacer are live code ----

_TS_MCP_IMPORT = "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n"


def _run_ts_line(tmp_path: Path, line: str) -> list[str]:
    (tmp_path / "resolve.ts").write_text(_TS_MCP_IMPORT + line + "\n", encoding="utf-8")
    return [f.location.replace("\\", "/") for f in McpEnvPlaceholderExfilGuard().run(tmp_path, _mcp_prof(tmp_path))]


@pytest.mark.parametrize(
    "line",
    [
        # The whole call spelled out in a docs string (the RCA's CRITICAL FP).
        'const doc = "never do u.replace(/${x}/, () => process.env.X) on a user URL";',
        "const doc = `never do u.replace(/x/, '$\\{X}', () => process.env.X) on a user URL`;",
        # A real call whose only `process.env` is a string, not a read of the environment.
        "const s = u.replace('${HOME}', 'process.env is not read here');",
    ],
)
def test_ts_candidate_spelled_in_a_string_is_safe(tmp_path: Path, line: str) -> None:
    assert _run_ts_line(tmp_path, line) == []


@pytest.mark.parametrize(
    "line",
    [
        "const s = " + _TS_ENV_REPLACE + ";",
        # The real call nested in a `${...}` substitution is code: the shortcut-separating case,
        # which plain `strip_strings=True` would have blanked.
        "const s = `${" + _TS_ENV_REPLACE + "}`;",
        # A quoted copy earlier on the line must not hide the real call after it.
        'log("u.replace(/${x}/, () => process.env.X)"); const s = ' + _TS_ENV_REPLACE + ";",
        # A `'process.env'` string before the real read in the same call must not hide the read.
        "const s = u.replace(/\\$\\{(\\w+)\\}/g, (_, k) => k === 'process.env' ? '' : process.env[k]);",
    ],
)
def test_ts_real_candidate_still_fires(tmp_path: Path, line: str) -> None:
    assert _run_ts_line(tmp_path, line) == ["resolve.ts:2"]


def test_ts_pragma_still_suppresses_a_code_anchored_candidate(tmp_path: Path) -> None:
    line = "const s = " + _TS_ENV_REPLACE + ";"
    assert len(_run_ts_line(tmp_path, line)) == 1
    assert _run_ts_line(tmp_path, line + "  // security: allow-mcp-env-placeholder-exfil") == []
