from __future__ import annotations

from agentsec.guards.mcp_tool_unverified import McpToolUnverifiedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_mcp_tool_unverified_fires_on_bare_import(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from mcp import ClientSession\n"
        "from mcp.client.stdio import stdio_client\n"
        "server = MCPClient(command='python', args=['server.py'])\n",
        encoding="utf-8",
    )
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mcp-tool-unverified/mcp-server-auto-loaded"
    assert findings[0].severity == "high"
    assert findings[0].check_id == "mcp-tool-unverified"
    assert "OWASP-LLM:LLM03" in findings[0].standards
    assert "OWASP-LLM:LLM01" in findings[0].standards

def test_mcp_tool_unverified_fires_on_mcp_client_construction(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "server = MCPClient(command='python', args=['server.py'])\n",
        encoding="utf-8",
    )
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mcp-tool-unverified/mcp-server-auto-loaded"

def test_mcp_tool_unverified_silent_with_trust_marker_nearby(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "APPROVED_SERVERS = {'mcp://internal.example.com/tools'}\n"
        "if server_url not in APPROVED_SERVERS:\n"
        "    raise ValueError('untrusted MCP server')\n"
        "from mcp import ClientSession\n",
        encoding="utf-8",
    )
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []

def test_mcp_tool_unverified_silent_with_pragma(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "# security: allow-mcp-unverified\n"
        "from mcp import ClientSession  # internal controlled server\n",
        encoding="utf-8",
    )
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []

def test_mcp_tool_unverified_fires_on_json_config_no_trusted(tmp_path: Path) -> None:
    import json
    cfg = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            }
        }
    }
    (tmp_path / "claude_desktop_config.json").write_text(
        json.dumps(cfg), encoding="utf-8"
    )
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mcp-tool-unverified/mcp-server-auto-loaded"
    assert findings[0].severity == "high"

def test_mcp_tool_unverified_silent_on_json_config_trusted(tmp_path: Path) -> None:
    import json
    cfg = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                "trusted": True,
            }
        }
    }
    (tmp_path / "mcp_config.json").write_text(json.dumps(cfg), encoding="utf-8")
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []

def test_mcp_tool_unverified_not_applicable_without_llm_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpToolUnverifiedGuard().applies(prof) is False

def test_mcp_tool_unverified_server_definition_silent(tmp_path: Path) -> None:
    # FP fix: defining an MCP server (FastMCP) does NOT fire — the project is publishing
    # tools, not connecting to an untrusted external server.
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "from mcp import types\n"
        "app = Server('mytools')\n"
        "@app.list_tools()\n"
        "async def list_tools() -> list[types.Tool]:\n"
        "    return [types.Tool(name='search', description='...')]\n",
        encoding="utf-8",
    )
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []

def test_mcp_tool_unverified_fast_mcp_server_silent(tmp_path: Path) -> None:
    # FastMCP() is a server constructor — defining it is not consuming an untrusted server.
    (tmp_path / "tools.py").write_text(
        "from mcp import FastMCP\n"
        "mcp = FastMCP('my-mcp-server')\n"
        "@mcp.tool()\n"
        "def search(query: str) -> str:\n"
        "    return query\n",
        encoding="utf-8",
    )
    assert McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_mcp_tool_unverified_server_plus_client_still_fires(tmp_path: Path) -> None:
    # A file that both defines a server AND connects to a client is ambiguous → fire.
    (tmp_path / "proxy.py").write_text(
        "from mcp.server import Server\n"
        "from mcp.client import ClientSession\n"
        "app = Server('proxy')\n"
        "session = ClientSession(read, write)\n",
        encoding="utf-8",
    )
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "mcp-tool-unverified/mcp-server-auto-loaded" for f in findings)

def test_mcp_tool_unverified_silent_on_non_mcp_client_session(tmp_path: Path) -> None:
    # aiohttp.ClientSession is not an MCP pattern — no from-mcp import, no MCPClient.
    (tmp_path / "service.py").write_text(
        "import aiohttp\n"
        "async def fetch(url: str) -> dict:\n"
        "    async with aiohttp.ClientSession() as session:\n"
        "        async with session.get(url) as resp:\n"
        "            return await resp.json()\n",
        encoding="utf-8",
    )
    assert McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_mcp_tool_unverified_silent_in_llm_framework_repo(tmp_path: Path) -> None:
    # pydantic-ai's _mcp.py implements the MCP protocol — it's the framework source,
    # not an agent consuming external untrusted servers.
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'pydantic-ai'\nversion = '1.0.0'\n",
        encoding="utf-8",
    )
    src = tmp_path / "pydantic_ai"
    src.mkdir()
    (src / "_mcp.py").write_text(
        "from mcp.client.session import ClientSession\n"
        "from mcp import Tool\n"
        "class MCPSession:\n"
        "    async def connect(self) -> None: ...\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"llm", "pydantic-ai"})
    prof.llm_framework = "pydantic-ai"
    assert McpToolUnverifiedGuard().run(tmp_path, prof) == []

def test_mcp_tool_unverified_skips_config_in_nonprod_path(tmp_path: Path) -> None:
    # Test cassettes / fixtures that match the MCP config filename pattern
    # must be ignored — they're test data, not deployed configs.
    cassette = tmp_path / "tests" / "cassettes"
    cassette.mkdir(parents=True)
    (cassette / "test_mcp_servers.yaml").write_text(
        "mcpServers:\n  example:\n    command: npx\n",
        encoding="utf-8",
    )
    assert McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# ── CVE-2025-6514: mcp-remote OAuth URL injection ────────────────────────────

def test_cve6514_fires_on_vulnerable_bare_version(tmp_path: Path) -> None:
    # package.json with mcp-remote at exact vulnerable version 0.1.0
    import json
    pkg = {"dependencies": {"mcp-remote": "0.1.0"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    vuln = [f for f in findings if f.rule == "mcp-tool-unverified/cve-2025-6514-mcp-remote"]
    assert len(vuln) == 1
    assert vuln[0].severity == "critical"
    assert "CVE-2025-6514" in vuln[0].message


def test_cve6514_fires_on_caret_range_in_vulnerable_minor(tmp_path: Path) -> None:
    # ^0.1.5 can only resolve within 0.1.x — still vulnerable
    import json
    pkg = {"dependencies": {"mcp-remote": "^0.1.5"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "mcp-tool-unverified/cve-2025-6514-mcp-remote" and f.severity == "critical"
               for f in findings)


def test_cve6514_fires_on_tilde_range_in_vulnerable_minor(tmp_path: Path) -> None:
    # ~0.0.5 pins to 0.0.x — still vulnerable
    import json
    pkg = {"devDependencies": {"mcp-remote": "~0.0.5"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "mcp-tool-unverified/cve-2025-6514-mcp-remote" and f.severity == "critical"
               for f in findings)


def test_cve6514_fires_on_compound_range_vulnerable_lower_bound(tmp_path: Path) -> None:
    # Regression (#422): compound ranges match neither anchored regex; classify the lower bound.
    import json
    pkg = {"dependencies": {"mcp-remote": ">=0.0.5 <0.2.0"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "mcp-tool-unverified/cve-2025-6514-mcp-remote" and f.severity == "critical"
               for f in findings)


def test_cve6514_compound_range_safe_lower_bound_not_critical(tmp_path: Path) -> None:
    # FP-bait for the lower-bound classification: a safe lower bound must not go critical.
    #
    # UPDATED for the #437 review. This previously asserted the range produced a MEDIUM
    # "ambiguous" finding, on the reasoning that an unclassifiable compound range never
    # returns None. But `>=0.2.0` is not unclassifiable — it is entirely above the vulnerable
    # 0.0.5–0.1.15 band, so silence is the correct answer and the MEDIUM was noise. The cause
    # was `_CVE6514_SAFE_VERSION` being `$`-anchored over PREFIX alternatives, so "minor >= 2"
    # and "major >= 1" could never match a real version string. That same deadness is what
    # made `^1.0.0 || ^2.0.0` — wholly above the band — draw a finding.
    import json
    pkg = {"dependencies": {"mcp-remote": ">=0.2.0 <0.3.0"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    vuln = [f for f in findings if f.rule == "mcp-tool-unverified/cve-2025-6514-mcp-remote"]
    assert vuln == []


def test_cve6514_union_range_above_the_band_is_silent(tmp_path: Path) -> None:
    # Regression (#437 review): `^1.0.0 || ^2.0.0` is wholly above the vulnerable band and was
    # flagged MEDIUM. Both branches are major >= 1.
    import json
    pkg = {"dependencies": {"mcp-remote": "^1.0.0 || ^2.0.0"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [f for f in findings if f.rule == "mcp-tool-unverified/cve-2025-6514-mcp-remote"] == []


def test_cve6514_genuinely_ambiguous_still_medium(tmp_path: Path) -> None:
    # The ambiguous path must survive the widening above: `latest` really can resolve into the
    # vulnerable band, so it stays a MEDIUM rather than becoming silent.
    import json
    pkg = {"dependencies": {"mcp-remote": "latest"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    vuln = [f for f in findings if f.rule == "mcp-tool-unverified/cve-2025-6514-mcp-remote"]
    assert len(vuln) == 1 and vuln[0].severity == "medium"


def test_cve6514_flags_latest_as_medium(tmp_path: Path) -> None:
    # "latest" is ambiguous — flag as MEDIUM, not CRITICAL
    import json
    pkg = {"dependencies": {"mcp-remote": "latest"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    vuln = [f for f in findings if f.rule == "mcp-tool-unverified/cve-2025-6514-mcp-remote"]
    assert len(vuln) == 1
    assert vuln[0].severity == "medium"


def test_cve6514_silent_on_safe_version_caret_0_1_16(tmp_path: Path) -> None:
    # ^0.1.16 is safe — must NOT fire
    import json
    pkg = {"dependencies": {"mcp-remote": "^0.1.16"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "mcp-tool-unverified/cve-2025-6514-mcp-remote" for f in findings)


def test_cve6514_silent_on_safe_version_0_2_0(tmp_path: Path) -> None:
    # 0.2.0 is safe
    import json
    pkg = {"dependencies": {"mcp-remote": "0.2.0"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "mcp-tool-unverified/cve-2025-6514-mcp-remote" for f in findings)


def test_cve6514_silent_on_major_version_2(tmp_path: Path) -> None:
    # 2.0.0 is safe
    import json
    pkg = {"dependencies": {"mcp-remote": "2.0.0"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "mcp-tool-unverified/cve-2025-6514-mcp-remote" for f in findings)


def test_cve6514_silent_when_no_mcp_remote(tmp_path: Path) -> None:
    # package.json with unrelated deps — must NOT fire
    import json
    pkg = {"dependencies": {"react": "^18.0.0", "fastapi": "0.1.0"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "mcp-tool-unverified/cve-2025-6514-mcp-remote" for f in findings)


def test_cve6514_skips_nonprod_package_json(tmp_path: Path) -> None:
    # package.json in a test fixture directory must be ignored
    import json
    fixture_dir = tmp_path / "tests" / "fixtures"
    fixture_dir.mkdir(parents=True)
    pkg = {"dependencies": {"mcp-remote": "0.1.0"}}
    (fixture_dir / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
    findings = McpToolUnverifiedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "mcp-tool-unverified/cve-2025-6514-mcp-remote" for f in findings)

