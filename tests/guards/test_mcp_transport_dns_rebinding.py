from __future__ import annotations

import pytest

from agentsec.guards.mcp_transport_dns_rebinding import McpTransportDnsRebindingGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "llm", "python"}, python_dirs=["."])


def test_flags_raw_streamable_http_transport_no_allowlist(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server.streamable_http import StreamableHTTPServerTransport\n\n"
        "def main():\n"
        "    transport = StreamableHTTPServerTransport()\n",
        encoding="utf-8",
    )
    findings = McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mcp-transport-dns-rebinding/no-host-allowlist"
    assert findings[0].severity == "critical"


def test_flags_fastmcp_streamable_http_string_transport(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n\n"
        "app = FastMCP('my-server')\n\n"
        "def main():\n"
        "    app.run(transport='streamable-http', port=8080)\n",
        encoding="utf-8",
    )
    findings = McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1


def test_flags_fastmcp_even_with_explicit_loopback_bind(tmp_path: Path) -> None:
    # Unlike the sibling mcp-transport-no-auth guard, a loopback bind is NOT a safe exemption
    # here -- CVE-2026-81102's exact shape (Dash MCP server, bound to loopback, still reachable
    # via a rebound Host header).
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n\n"
        "app = FastMCP('my-server')\n\n"
        "def main():\n"
        "    app.run(transport='streamable-http', host='127.0.0.1', port=8080)\n",
        encoding="utf-8",
    )
    findings = McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 1


def test_fastmcp_stdio_default_does_not_fire(tmp_path: Path) -> None:
    # FP bait: FastMCP constructed but never told to run over a network transport -- stdio is
    # the SDK's own default, no listener to rebind onto.
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n\n"
        "app = FastMCP('my-server')\n\n"
        "def main():\n"
        "    app.run()\n",
        encoding="utf-8",
    )
    assert McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_stays_silent_with_host_allowlist_in_same_file(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "from starlette.middleware.trustedhost import TrustedHostMiddleware\n\n"
        "app = FastMCP('my-server')\n\n"
        "def main():\n"
        "    app.run(transport='streamable-http', port=8080)\n",
        encoding="utf-8",
    )
    assert McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_stays_silent_with_host_allowlist_in_a_different_file(tmp_path: Path) -> None:
    # Project-wide suppression: the transport is set up in one file, the allow-list wired in
    # another -- mirrors the real source's own documented multi-file design.
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n\n"
        "app = FastMCP('my-server')\n\n"
        "def main():\n"
        "    app.run(transport='streamable-http', port=8080)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "ALLOWED_HOSTS = ['localhost', '127.0.0.1']\n",
        encoding="utf-8",
    )
    assert McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_stays_silent_with_host_allowlist_only_in_examples_dir(tmp_path: Path) -> None:
    # (Dean's review, CLAUDE.md rule 4): the allowlist scan used to skip
    # `is_nonproduct_path` files entirely, so a Host-allowlist wired up only in an `examples/`
    # reference file (a real, common place to show "here's how to configure this") was
    # invisible to the project-wide mitigation scan. The skip must bound where a FINDING is
    # anchored, not what the mitigation scan is allowed to read.
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n\n"
        "app = FastMCP('my-server')\n\n"
        "def main():\n"
        "    app.run(transport='streamable-http', port=8080)\n",
        encoding="utf-8",
    )
    examples_dir = tmp_path / "examples"
    examples_dir.mkdir()
    (examples_dir / "configure.py").write_text(
        "ALLOWED_HOSTS = ['localhost', '127.0.0.1']\n",
        encoding="utf-8",
    )
    assert McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_unmitigated_transport_inside_examples_dir_does_not_fire(tmp_path: Path) -> None:
    # Still-fires companion, other direction: an unmitigated transport construction INSIDE
    # examples/ must still NOT become a finding -- only the mitigation-marker SCAN widened to
    # read every file; a finding must still never be anchored in a nonproduct path.
    examples_dir = tmp_path / "examples"
    examples_dir.mkdir()
    (examples_dir / "demo_server.py").write_text(
        "from mcp.server.streamable_http import StreamableHTTPServerTransport\n\n"
        "def main():\n"
        "    transport = StreamableHTTPServerTransport()\n",
        encoding="utf-8",
    )
    assert McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_non_mcp_streamable_http_reference_does_not_fire(tmp_path: Path) -> None:
    # FP bait: an unrelated file mentioning "sse_app" in prose/a different context, no real
    # FastMCP construction at all.
    (tmp_path / "notes.py").write_text(
        "# TODO: consider adding an sse_app( endpoint someday\n"
        "def unrelated():\n"
        "    return 42\n",
        encoding="utf-8",
    )
    assert McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_bare_import_of_streamable_transport_does_not_fire(tmp_path: Path) -> None:
    # (Dean's review): importing the class name alone (never instantiated) used to
    # fire identically to a real construction -- an import statement is not a transport.
    (tmp_path / "server.py").write_text(
        "from mcp.server.streamable_http import StreamableHTTPServerTransport\n\n"
        "def unrelated():\n"
        "    return 42\n",
        encoding="utf-8",
    )
    assert McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_comment_mentioning_streamable_transport_with_call_syntax_does_not_fire(
    tmp_path: Path,
) -> None:
    # a comment naming the class WITH call syntax (`ClassName()`) must not fire either
    # -- proves the fix needs comment-stripping, not just requiring parens, since this text has
    # parens but is not real code.
    (tmp_path / "server.py").write_text(
        "# We used to call StreamableHTTPServerTransport() here, migrated away.\n"
        "def unrelated():\n"
        "    return 42\n",
        encoding="utf-8",
    )
    assert McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_docstring_mentioning_streamable_transport_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        '"""Example: StreamableHTTPServerTransport() sets up the transport."""\n'
        "def unrelated():\n"
        "    return 42\n",
        encoding="utf-8",
    )
    assert McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


@pytest.mark.parametrize(
    "mention",
    [
        'DOC = "see allowed_hosts= for config"\n',
        "HELP = 'wire TrustedHostMiddleware in front of the app'\n",
        "raise SystemExit(f'set ALLOWED_HOSTS before deploying')\n",
        "logger.warning('ALLOWED_HOSTS_NOT_SET')\n",
        "FLAGS = {'ALLOWED_HOSTS_UI_BANNER': False}\n",
    ],
    ids=["allowed-hosts-kwarg", "trusted-host-middleware", "fstring-allowed-hosts",
         "log-key-warning-it-is-unset", "unrelated-flag-key"],
)
def test_allowlist_marker_only_in_a_string_does_not_suppress(tmp_path: Path, mention: str) -> None:
    # PR #917 re-review: the allow-list scan kept single-line strings, so one incidental
    # string ANYWHERE in the project voided a real CRITICAL. A mention is not a middleware, and
    # neither is an identifier-shaped string that merely CONTAINS a marker (a log key warning
    # that the allow-list is unset must not silence the finding it warns about).
    (tmp_path / "server.py").write_text(
        "from mcp.server.streamable_http import StreamableHTTPServerTransport\n\n"
        "def main():\n"
        "    transport = StreamableHTTPServerTransport()\n",
        encoding="utf-8",
    )
    (tmp_path / "docs.py").write_text(mention, encoding="utf-8")
    findings = McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [(f.location, f.severity) for f in findings] == [("server.py:4", "critical")]


@pytest.mark.parametrize(
    "wiring",
    [
        "SETTINGS = {'ALLOWED_HOSTS': os.environ.get('HOSTS', 'localhost').split(',')}\n",
        "MIDDLEWARE = ['starlette.middleware.trustedhost.TrustedHostMiddleware']\n",
        "HOSTS = os.environ['MCP_ALLOWED_HOSTS'].split(',')\n",
        "SECURITY = TransportSecuritySettings(allowed_hosts=os.environ['HOSTS'].split(','))\n",
    ],
    ids=["settings-dict-key", "dotted-middleware-path", "prefixed-env-var", "kwarg-beside-string"],
)
def test_allowlist_wired_through_a_string_key_still_suppresses(tmp_path: Path, wiring: str) -> None:
    # FP bait for the fix above: a string that IS an identifier or dotted path (a settings key,
    # an env-var name, a middleware path) is a reference, not prose, and still counts. The first
    # three have no bare-code marker at all, so they discriminate; blanking every string made
    # each of them a spurious CRITICAL on a protected app.
    (tmp_path / "server.py").write_text(
        "from mcp.server.streamable_http import StreamableHTTPServerTransport\n\n"
        "def main():\n"
        "    transport = StreamableHTTPServerTransport()\n",
        encoding="utf-8",
    )
    (tmp_path / "settings.py").write_text("import os\n\n" + wiring, encoding="utf-8")
    assert McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_single_line_string_mentioning_streamable_transport_does_not_fire(tmp_path: Path) -> None:
    # PR #917 re-review (FP direction): only triple-quoted strings were blanked, so a
    # single-quoted mention with call parens still fired CRITICAL.
    (tmp_path / "notes.py").write_text(
        'NOTE = "StreamableHTTPServerTransport() was the old way"\n',
        encoding="utf-8",
    )
    assert McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_fastmcp_network_selector_only_in_a_string_does_not_fire(tmp_path: Path) -> None:
    # The `transport="..."` value is itself a string, so that scan keeps strings; a match must
    # still START in code. Here the only network selector is inside a help string.
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n\n"
        "app = FastMCP('my-server')\n"
        "USAGE = \"pass transport='sse' to serve over HTTP\"\n\n"
        "def main():\n"
        "    app.run()\n",
        encoding="utf-8",
    )
    assert McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_fastmcp_constructor_only_in_a_string_does_not_fire(tmp_path: Path) -> None:
    # Same rule for the other half of the FastMCP pair: the constructor must be code too.
    (tmp_path / "server.py").write_text(
        "HELP = \"FastMCP('name') is the high-level API\"\n\n"
        "def main(server):\n"
        "    server.run(transport='sse')\n",
        encoding="utf-8",
    )
    assert McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_real_transport_after_a_string_mention_anchors_on_the_real_line(tmp_path: Path) -> None:
    # Still-fires companion for the two narrowings above, with the finding anchored on the
    # real construction rather than on an earlier string that spells the same text.
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n\n"
        "USAGE = \"pass transport='sse' or StreamableHTTPServerTransport()\"\n"
        "app = FastMCP('my-server')\n\n"
        "def main():\n"
        "    app.run(transport=\"sse\")\n",
        encoding="utf-8",
    )
    findings = McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [f.location for f in findings] == ["server.py:7"]
    assert 'transport="sse"' in findings[0].message


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "# security: allow-mcp-dns-rebinding\n"
        "from mcp.server.streamable_http import StreamableHTTPServerTransport\n\n"
        "def main():\n"
        "    transport = StreamableHTTPServerTransport()\n",
        encoding="utf-8",
    )
    assert McpTransportDnsRebindingGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_applies_requires_mcp_and_python_features(tmp_path: Path) -> None:
    guard = McpTransportDnsRebindingGuard()
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is False
    assert guard.applies(mkprofile(tmp_path, features={"mcp", "typescript"})) is False
