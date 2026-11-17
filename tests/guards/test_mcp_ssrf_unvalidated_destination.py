"""Tests for McpSsrfUnvalidatedDestinationGuard — planted-violation + FP-bait."""
from __future__ import annotations

from agentsec.guards.mcp_ssrf_unvalidated_destination import McpSsrfUnvalidatedDestinationGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "llm", "python"}, python_dirs=["."])


# ── Rule A: tool-arg-url ──────────────────────────────────────────────────────

def test_fires_on_mcp_tool_url_param_to_requests_get(tmp_path: Path) -> None:
    """HIGH: an @mcp.tool handler's `url` parameter reaches requests.get() unguarded —
    CVE-2026-14748's own shape (mcp-wiki/src/mcp_wiki/server.py)."""
    (tmp_path / "mcp_wiki_server.py").write_text(
        "import requests\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('wiki')\n"
        "\n"
        "\n"
        "@mcp.tool()\n"
        "def fetch_page(url: str) -> str:\n"
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-ssrf-unvalidated-destination/tool-arg-url" for f in findings)
    hit = next(f for f in findings if f.rule == "mcp-ssrf-unvalidated-destination/tool-arg-url")
    assert hit.severity == "high"


def test_fires_on_webhook_param_via_httpx(tmp_path: Path) -> None:
    """HIGH: a webhook-shaped param name reaching an httpx sink also fires."""
    (tmp_path / "notify_tool.py").write_text(
        "import httpx\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('notify')\n"
        "\n"
        "\n"
        "@mcp.tool()\n"
        "def notify(webhook: str, payload: str) -> None:\n"
        "    httpx.post(webhook, json={'msg': payload})\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-ssrf-unvalidated-destination/tool-arg-url" for f in findings)


def test_tool_arg_guarded_is_safe(tmp_path: Path) -> None:
    """FP-bait: a handler that validates the URL before fetching (urlparse/ALLOWED_HOSTS/etc.
    anywhere in the function) must NOT fire."""
    (tmp_path / "mcp_wiki_server.py").write_text(
        "import requests\n"
        "from urllib.parse import urlparse\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('wiki')\n"
        "ALLOWED_HOSTS = {'wiki.example.com'}\n"
        "\n"
        "\n"
        "@mcp.tool()\n"
        "def fetch_page(url: str) -> str:\n"
        "    host = urlparse(url).netloc\n"
        "    if host not in ALLOWED_HOSTS:\n"
        "        raise ValueError('blocked')\n"
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-ssrf-unvalidated-destination/tool-arg-url" for f in findings)


def test_non_url_shaped_param_is_safe(tmp_path: Path) -> None:
    """FP-bait: an @mcp.tool handler whose param names don't look like URLs (e.g. a query
    string) does not fire even though it calls a fetch sink."""
    (tmp_path / "search_tool.py").write_text(
        "import requests\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('search')\n"
        "\n"
        "\n"
        "@mcp.tool()\n"
        "def search(query: str) -> str:\n"
        "    return requests.get('https://search.example.com/api?q=' + query).text\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-ssrf-unvalidated-destination/tool-arg-url" for f in findings)


def test_tainted_url_param_in_unrelated_kwarg_is_safe(tmp_path: Path) -> None:
    """FP-bait (Dean's review): a URL-shaped tool param merely appearing in an
    UNRELATED kwarg (headers=) -- not the fetch destination itself, which is a hardcoded
    literal -- must not fire. The same "any kwarg counts" over-reach PR #423 already fixed
    once for agent_tool_url_fetch_ssrf.py's literal check, reopened here for a different
    reason (an AST-based taint check over ALL args instead of just the destination arg)."""
    (tmp_path / "mcp_wiki_server.py").write_text(
        "import requests\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('wiki')\n"
        "\n"
        "\n"
        "@mcp.tool()\n"
        "def fetch_page(callback: str) -> str:\n"
        "    return requests.get("
        "'https://fixed-internal-endpoint.example.com', "
        "headers={'X-Callback': callback}).text\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-ssrf-unvalidated-destination/tool-arg-url" for f in findings)


def test_still_fires_when_destination_passed_as_url_keyword(tmp_path: Path) -> None:
    """Still-fires companion, other direction: the destination CAN legitimately be passed as
    an explicit `url=` keyword instead of positionally -- must still fire in that shape."""
    (tmp_path / "mcp_wiki_server.py").write_text(
        "import requests\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('wiki')\n"
        "\n"
        "\n"
        "@mcp.tool()\n"
        "def fetch_page(url: str) -> str:\n"
        "    return requests.get(url=url).text\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-ssrf-unvalidated-destination/tool-arg-url" for f in findings)


def test_non_mcp_tool_function_is_safe(tmp_path: Path) -> None:
    """FP-bait: a plain (non-@mcp.tool) function with a `url` param reaching requests.get()
    does not fire — Rule A is scoped to MCP tool handlers specifically."""
    (tmp_path / "helper.py").write_text(
        "import requests\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('wiki')\n"
        "\n"
        "\n"
        "def internal_fetch(url: str) -> str:\n"
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-ssrf-unvalidated-destination/tool-arg-url" for f in findings)


# ── Rule B: config-destination ────────────────────────────────────────────────

def test_fires_on_server_url_config_destination(tmp_path: Path) -> None:
    """HIGH: a config-shaped server_url destination reaches a fetch with no guard anywhere
    in the module — CVE-2026-85666/86122 class."""
    (tmp_path / "mcp_registry.py").write_text(
        "import requests\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('registry')\n"
        "\n"
        "\n"
        "def connect(cfg: dict) -> str:\n"
        "    server_url = cfg['server_url']\n"
        "    return requests.get(server_url).text\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-ssrf-unvalidated-destination/config-destination" for f in findings)
    hit = next(f for f in findings if f.rule == "mcp-ssrf-unvalidated-destination/config-destination")
    assert hit.severity == "high"


def test_fires_on_webhook_url_config_destination(tmp_path: Path) -> None:
    """HIGH: webhook_url is also a recognized config-destination token."""
    (tmp_path / "mcp_webhook.py").write_text(
        "import httpx\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('hooks')\n"
        "\n"
        "\n"
        "def dispatch(cfg: dict) -> None:\n"
        "    webhook_url = cfg['webhook_url']\n"
        "    httpx.post(webhook_url, json={'event': 'ping'})\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-ssrf-unvalidated-destination/config-destination" for f in findings)


def test_config_name_in_unrelated_kwarg_is_safe(tmp_path: Path) -> None:
    """FP-bait (Dean's review): a config-shaped destination name merely appearing
    in an UNRELATED kwarg -- the actual fetch destination is a hardcoded literal -- must not
    fire Rule B either, same over-reach class as Rule A's kwarg fix above."""
    (tmp_path / "mcp_registry.py").write_text(
        "import requests\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('registry')\n"
        "\n"
        "\n"
        "def connect(cfg: dict) -> str:\n"
        "    server_url = cfg['server_url']\n"
        "    return requests.get("
        "'https://fixed-internal-endpoint.example.com', "
        "headers={'X-Origin': server_url}).text\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-ssrf-unvalidated-destination/config-destination" for f in findings)


def test_config_destination_guarded_elsewhere_in_module_is_safe(tmp_path: Path) -> None:
    """FP-bait: a module that DOES call a recognized guard function anywhere (even a
    differently-named validator) does not fire Rule B — the guard-recognition check is
    module-wide, matching the real source's conservative single-pass design."""
    (tmp_path / "mcp_registry.py").write_text(
        "import requests\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('registry')\n"
        "\n"
        "\n"
        "def validate_url(u: str) -> bool:\n"
        "    return True\n"
        "\n"
        "\n"
        "def connect(cfg: dict) -> str:\n"
        "    server_url = cfg['server_url']\n"
        "    if not validate_url(server_url):\n"
        "        raise ValueError('blocked')\n"
        "    return requests.get(server_url).text\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-ssrf-unvalidated-destination/config-destination" for f in findings)


def test_base_url_config_destination_is_safe(tmp_path: Path) -> None:
    """FP-bait: base_url is deliberately excluded from _DEST_TOKENS — it is typically a
    service's own fixed address, not a caller-steerable one (the real source's own
    documented lesson, reverted after firing on a clean fixture)."""
    (tmp_path / "mcp_client.py").write_text(
        "import requests\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('client')\n"
        "\n"
        "\n"
        "class ApiClient:\n"
        "    def __init__(self, base_url: str) -> None:\n"
        "        self.base_url = base_url\n"
        "\n"
        "    def get(self, path: str) -> str:\n"
        "        return requests.get(self.base_url + path).text\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-ssrf-unvalidated-destination/config-destination" for f in findings)


def test_no_mcp_context_is_safe(tmp_path: Path) -> None:
    """FP-bait: a file with no MCP context marker does not fire even with a server_url
    destination reaching a fetch sink."""
    (tmp_path / "generic_client.py").write_text(
        "import requests\n"
        "\n"
        "def connect(cfg: dict) -> str:\n"
        "    server_url = cfg['server_url']\n"
        "    return requests.get(server_url).text\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


# ── Cross-cutting ──────────────────────────────────────────────────────────────

def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "mcp_wiki_server.py").write_text(
        "import requests\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('wiki')\n"
        "\n"
        "\n"
        "@mcp.tool()\n"
        "def fetch_page(url: str) -> str:\n"
        "    return requests.get(url).text  # security: allow-mcp-ssrf-unvalidated-destination\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpSsrfUnvalidatedDestinationGuard().applies(prof) is False


def test_guard_applicable_with_mcp_feature(tmp_path: Path) -> None:
    assert McpSsrfUnvalidatedDestinationGuard().applies(_mcp_prof(tmp_path)) is True


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "mcp_wiki_server.py").write_text(
        "import requests\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('wiki')\n"
        "\n"
        "\n"
        "@mcp.tool()\n"
        "def fetch_page(url: str) -> str:\n"
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )
    findings = McpSsrfUnvalidatedDestinationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []
