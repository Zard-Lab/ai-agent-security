"""Tests for McpServerCardIntegrityGuard — planted-violation + FP-bait."""
from __future__ import annotations

import json

from agentsec.guards.mcp_server_card_integrity import McpServerCardIntegrityGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp"}, python_dirs=["."])


def test_remote_transport_no_auth_required_fires(tmp_path: Path) -> None:
    card = {
        "serverInfo": {"name": "x"},
        "transport": {"type": "https", "endpoint": "https://mcp.example.com"},
        "authentication": {"required": False},
        "signature": "real-sig-abc123",
    }
    d = tmp_path / ".well-known" / "mcp"
    d.mkdir(parents=True)
    (d / "server-card.json").write_text(json.dumps(card), encoding="utf-8")
    findings = McpServerCardIntegrityGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-server-card-integrity/transport-capability-mismatch")
    assert hit.severity == "high"


def test_stdio_transport_with_remote_endpoint_fires(tmp_path: Path) -> None:
    card = {
        "serverInfo": {"name": "x"},
        "transport": {"type": "stdio", "endpoint": "https://mcp.example.com"},
        "signature": "real-sig-abc123",
    }
    (tmp_path / "server-card.json").write_text(json.dumps(card), encoding="utf-8")
    findings = McpServerCardIntegrityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-server-card-integrity/transport-capability-mismatch" for f in findings)


def test_remote_transport_with_auth_required_is_safe(tmp_path: Path) -> None:
    """FP-bait: a remote transport that DOES require auth is safe on this rule."""
    card = {
        "serverInfo": {"name": "x"},
        "transport": {"type": "https", "endpoint": "https://mcp.example.com"},
        "authentication": {"required": True, "schemes": ["oauth2"]},
        "signature": "real-sig-abc123",
    }
    (tmp_path / "server-card.json").write_text(json.dumps(card), encoding="utf-8")
    findings = McpServerCardIntegrityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-server-card-integrity/transport-capability-mismatch" for f in findings)


def test_no_signature_field_fires(tmp_path: Path) -> None:
    card = {"serverInfo": {"name": "x"}, "transport": {"type": "stdio"}}
    (tmp_path / "server-card.json").write_text(json.dumps(card), encoding="utf-8")
    findings = McpServerCardIntegrityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-server-card-integrity/unsigned-card" for f in findings)


def test_placeholder_signature_fires(tmp_path: Path) -> None:
    card = {"serverInfo": {"name": "x"}, "transport": {"type": "stdio"}, "signature": "todo"}
    (tmp_path / "server-card.json").write_text(json.dumps(card), encoding="utf-8")
    findings = McpServerCardIntegrityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-server-card-integrity/unsigned-card" for f in findings)


def test_real_signature_is_safe(tmp_path: Path) -> None:
    """FP-bait: a non-placeholder signature value clears the unsigned-card rule."""
    card = {"serverInfo": {"name": "x"}, "transport": {"type": "stdio"}, "signature": "sig-real-abc123xyz"}
    (tmp_path / "server-card.json").write_text(json.dumps(card), encoding="utf-8")
    findings = McpServerCardIntegrityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-server-card-integrity/unsigned-card" for f in findings)


def test_wildcard_auth_scope_fires(tmp_path: Path) -> None:
    card = {
        "serverInfo": {"name": "x"},
        "transport": {"type": "stdio"},
        "signature": "sig-real-abc123xyz",
        "authentication": {"scopes": ["*"]},
    }
    (tmp_path / "server-card.json").write_text(json.dumps(card), encoding="utf-8")
    findings = McpServerCardIntegrityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-server-card-integrity/overbroad-capability-claim" for f in findings)


def test_narrow_scope_is_safe(tmp_path: Path) -> None:
    """FP-bait: a narrow, specific auth scope is safe."""
    card = {
        "serverInfo": {"name": "x"},
        "transport": {"type": "stdio"},
        "signature": "sig-real-abc123xyz",
        "authentication": {"scopes": ["read:files"]},
    }
    (tmp_path / "server-card.json").write_text(json.dumps(card), encoding="utf-8")
    findings = McpServerCardIntegrityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-server-card-integrity/overbroad-capability-claim" for f in findings)


def test_non_card_json_file_is_ignored(tmp_path: Path) -> None:
    """FP-bait: an ordinary JSON file with no card-shaped fields at all -- ignored."""
    (tmp_path / "package.json").write_text(json.dumps({"name": "x", "version": "1.0.0"}), encoding="utf-8")
    findings = McpServerCardIntegrityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    card = {
        "_note": "security: allow-mcp-server-card-integrity",
        "serverInfo": {"name": "x"},
        "transport": {"type": "https", "endpoint": "https://mcp.example.com"},
        "authentication": {"required": False},
    }
    (tmp_path / "server-card.json").write_text(json.dumps(card), encoding="utf-8")
    findings = McpServerCardIntegrityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_initialize_result_example_is_not_a_server_card(tmp_path: Path) -> None:
    """FP-bait: a plain MCP `initialize` result (protocolVersion + serverInfo + capabilities) is
    what docs pages print to illustrate the handshake; it has no SEP-1649 field."""
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "initialize-example.json").write_text(
        json.dumps({
            "protocolVersion": "2025-11-25",
            "serverInfo": {"name": "demo", "version": "1.0.0"},
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
        }),
        encoding="utf-8",
    )
    assert McpServerCardIntegrityGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_serverinfo_with_transport_or_authentication_is_still_a_card(tmp_path: Path) -> None:
    """The direction traded against: a card at an arbitrary path (not `.well-known/mcp/`) that
    carries `serverInfo` plus a SEP-1649 field is still audited."""
    for i, extra in enumerate(({"transport": {"type": "stdio"}}, {"authentication": {"required": True}})):
        d = tmp_path / f"c{i}"
        d.mkdir()
        (d / "card.json").write_text(json.dumps({"serverInfo": {"name": "x"}, **extra}), encoding="utf-8")
    findings = McpServerCardIntegrityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert {f.location.replace("\\", "/").split(":")[0] for f in findings} == {"c0/card.json", "c1/card.json"}
    assert all(f.rule.endswith("unsigned-card") for f in findings)


def test_card_findings_carry_a_line(tmp_path: Path) -> None:
    (tmp_path / "server-card.json").write_text(
        '{\n  "serverInfo": {"name": "x"},\n  "transport": {"type": "https"},\n'
        '  "authentication": {"required": false}\n}\n',
        encoding="utf-8",
    )
    by_rule = {
        f.rule.split("/")[-1]: f.location.replace("\\", "/")
        for f in McpServerCardIntegrityGuard().run(tmp_path, _mcp_prof(tmp_path))
    }
    assert by_rule["transport-capability-mismatch"] == "server-card.json:4"
    assert by_rule["unsigned-card"] == "server-card.json:2"


def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpServerCardIntegrityGuard().applies(prof) is False


def test_deeply_nested_json_file_does_not_zero_the_guard(tmp_path: Path) -> None:
    """A hostile deep-nesting card-shaped file used to raise RecursionError; the real finding survives."""
    (tmp_path / "deep.json").write_text('{"serverInfo": ' + '[' * 200_000 + ']' * 200_000 + "}", encoding="utf-8")
    card = {
        "serverInfo": {"name": "x"},
        "transport": {"type": "https", "endpoint": "https://mcp.example.com"},
        "authentication": {"required": False},
        "signature": "real-sig-abc123",
    }
    d = tmp_path / ".well-known" / "mcp"
    d.mkdir(parents=True)
    (d / "server-card.json").write_text(json.dumps(card), encoding="utf-8")
    findings = McpServerCardIntegrityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-server-card-integrity/transport-capability-mismatch" for f in findings)
