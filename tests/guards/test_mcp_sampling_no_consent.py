"""Tests for McpSamplingNoConsentGuard — planted-violation + FP-bait."""
from __future__ import annotations

import json

from agentsec.findings import _is_review_finding
from agentsec.guards.mcp_sampling_no_consent import McpSamplingNoConsentGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "llm", "python"}, python_dirs=["."])


# ── Source-side participation ─────────────────────────────────────────────────

def test_fires_on_sampling_handler_with_no_consent_marker(tmp_path: Path) -> None:
    """HIGH (surfacing): a CreateMessageRequestSchema handler with no consent marker
    anywhere in the repo fires."""
    (tmp_path / "sampling_handler.py").write_text(
        "from mcp.server import Server\n"
        "from mcp.types import CreateMessageRequestSchema\n"
        "\n"
        "server = Server('demo')\n"
        "\n"
        "\n"
        "@server.request_handler(CreateMessageRequestSchema)\n"
        "async def handle_sampling(request):\n"
        "    return await server.sampling.create(request)\n",
        encoding="utf-8",
    )
    findings = McpSamplingNoConsentGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-sampling-no-consent/source-participation" for f in findings)
    hit = next(f for f in findings if f.rule == "mcp-sampling-no-consent/source-participation")
    assert hit.severity == "medium"


def test_fires_on_sampling_createmessage_call(tmp_path: Path) -> None:
    """HIGH: a bare sampling/createMessage marker also fires."""
    (tmp_path / "client.py").write_text(
        "def request_completion(session):\n"
        "    return session.request('sampling/createMessage', params={})\n",
        encoding="utf-8",
    )
    findings = McpSamplingNoConsentGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-sampling-no-consent/source-participation" for f in findings)


def test_silent_when_consent_marker_present_anywhere_in_repo(tmp_path: Path) -> None:
    """FP-bait: a consent/elicitation marker ANYWHERE in the repo (a different file)
    silences the finding — the check is repo-wide, not same-file."""
    (tmp_path / "sampling_handler.py").write_text(
        "from mcp.server import Server\n"
        "from mcp.types import CreateMessageRequestSchema\n"
        "\n"
        "server = Server('demo')\n"
        "\n"
        "\n"
        "@server.request_handler(CreateMessageRequestSchema)\n"
        "async def handle_sampling(request):\n"
        "    return await server.sampling.create(request)\n",
        encoding="utf-8",
    )
    (tmp_path / "consent.py").write_text(
        "async def confirmSampling(request) -> bool:\n"
        "    return await ask_user(request)\n",
        encoding="utf-8",
    )
    findings = McpSamplingNoConsentGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-sampling-no-consent/source-participation" for f in findings)


def test_no_sampling_participation_is_safe(tmp_path: Path) -> None:
    """FP-bait: an MCP repo with no sampling markers anywhere stays silent."""
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "mcp = FastMCP('demo')\n"
        "\n"
        "\n"
        "@mcp.tool()\n"
        "def add(a: int, b: int) -> int:\n"
        "    return a + b\n",
        encoding="utf-8",
    )
    findings = McpSamplingNoConsentGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_source_finding(tmp_path: Path) -> None:
    (tmp_path / "sampling_handler.py").write_text(
        "from mcp.server import Server\n"
        "from mcp.types import CreateMessageRequestSchema\n"
        "\n"
        "server = Server('demo')\n"
        "\n"
        "\n"
        "@server.request_handler(CreateMessageRequestSchema)  # security: allow-mcp-sampling-no-consent\n"
        "async def handle_sampling(request):\n"
        "    return await server.sampling.create(request)\n",
        encoding="utf-8",
    )
    findings = McpSamplingNoConsentGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


# ── Config-side declaration ────────────────────────────────────────────────────

def test_fires_on_config_sampling_capability_no_consent(tmp_path: Path) -> None:
    """HIGH: an MCP config declares `sampling` in a server's capabilities with no
    sibling requires_consent/human_in_the_loop flag."""
    cfg = {
        "mcpServers": {
            "demo": {
                "command": "npx",
                "capabilities": ["sampling"],
            }
        }
    }
    (tmp_path / "mcp.json").write_text(json.dumps(cfg), encoding="utf-8")
    findings = McpSamplingNoConsentGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-sampling-no-consent/config-declaration" for f in findings)
    hit = next(f for f in findings if f.rule == "mcp-sampling-no-consent/config-declaration")
    assert hit.severity == "medium"


def test_both_rules_are_review_signals(tmp_path: Path) -> None:
    # #766: neither `surfacing_rule_prefixes` entry had a behavioral pin, so emptying the tuple
    # left the suite green. The checkmeta gate checks the declaration's text, not what it does.
    (tmp_path / "client.py").write_text(
        "def request_completion(session):\n"
        "    return session.request('sampling/createMessage', params={})\n",
        encoding="utf-8",
    )
    cfg = {"mcpServers": {"demo": {"command": "npx", "capabilities": ["sampling"]}}}
    (tmp_path / "mcp.json").write_text(json.dumps(cfg), encoding="utf-8")
    findings = McpSamplingNoConsentGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert {f.rule for f in findings} == {
        "mcp-sampling-no-consent/source-participation",
        "mcp-sampling-no-consent/config-declaration",
    }
    assert all(_is_review_finding(f) for f in findings)


def test_config_sampling_with_requires_consent_is_safe(tmp_path: Path) -> None:
    """FP-bait: requires_consent: true next to the sampling declaration silences it."""
    cfg = {
        "mcpServers": {
            "demo": {
                "command": "npx",
                "capabilities": ["sampling"],
                "requires_consent": True,
            }
        }
    }
    (tmp_path / "mcp.json").write_text(json.dumps(cfg), encoding="utf-8")
    findings = McpSamplingNoConsentGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-sampling-no-consent/config-declaration" for f in findings)


def test_config_no_sampling_capability_is_safe(tmp_path: Path) -> None:
    """FP-bait: a server with no `sampling` in its capabilities list stays silent."""
    cfg = {
        "mcpServers": {
            "demo": {
                "command": "npx",
                "capabilities": ["tools", "resources"],
            }
        }
    }
    (tmp_path / "mcp.json").write_text(json.dumps(cfg), encoding="utf-8")
    findings = McpSamplingNoConsentGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-sampling-no-consent/config-declaration" for f in findings)


# ── Cross-cutting ──────────────────────────────────────────────────────────────

def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpSamplingNoConsentGuard().applies(prof) is False


def test_guard_applicable_with_mcp_feature(tmp_path: Path) -> None:
    assert McpSamplingNoConsentGuard().applies(_mcp_prof(tmp_path)) is True


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "sampling_handler.py").write_text(
        "from mcp.server import Server\n"
        "from mcp.types import CreateMessageRequestSchema\n"
        "\n"
        "server = Server('demo')\n"
        "\n"
        "\n"
        "@server.request_handler(CreateMessageRequestSchema)\n"
        "async def handle_sampling(request):\n"
        "    return await server.sampling.create(request)\n",
        encoding="utf-8",
    )
    findings = McpSamplingNoConsentGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_consent_marker_in_examples_dir_silences_the_repo_wide_finding(tmp_path: Path) -> None:
    # (agentic pre-review H-5, CLAUDE.md rule 4): the repo-wide "no consent gate
    # ANYWHERE" scan used to reuse the nonproduct-filtered file list, so a consent gate
    # demonstrated only in examples/ was invisible to it -- the repo-wide claim never actually
    # read every file it claimed to. A skip must scope where a FINDING may be anchored, not
    # what the repo-wide evidence scan is allowed to read.
    (tmp_path / "sampling_handler.py").write_text(
        "from mcp.server import Server\n"
        "from mcp.types import CreateMessageRequestSchema\n"
        "\n"
        "server = Server('demo')\n"
        "\n"
        "\n"
        "@server.request_handler(CreateMessageRequestSchema)\n"
        "async def handle_sampling(request):\n"
        "    return await server.sampling.create(request)\n",
        encoding="utf-8",
    )
    examples_dir = tmp_path / "examples"
    examples_dir.mkdir()
    (examples_dir / "consent_demo.py").write_text(
        "def confirmSampling(request):\n"
        "    return input('Allow sampling? [y/N] ') == 'y'\n",
        encoding="utf-8",
    )
    findings = McpSamplingNoConsentGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_source_finding_in_ts_file(tmp_path: Path) -> None:
    # Same class of fix as H-8: the `#`-anchored regex never matched in a `.ts` file, so
    # `// security: allow-...` silently never suppressed anything there.
    (tmp_path / "sampling_handler.ts").write_text(
        "// security: allow-mcp-sampling-no-consent\n"
        "import { Server } from '@modelcontextprotocol/sdk/server';\n"
        "\n"
        "const server = new Server();\n"
        "server.setRequestHandler(CreateMessageRequestSchema, async (req) => {\n"
        "  return server.sampling.create(req);\n"
        "});\n",
        encoding="utf-8",
    )
    findings = McpSamplingNoConsentGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []
