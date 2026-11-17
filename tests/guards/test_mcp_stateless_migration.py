"""Tests for McpStatelessMigrationGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

from agentsec.findings import _is_review_finding
from agentsec.guards.mcp_stateless_migration import McpStatelessMigrationGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "python"}, python_dirs=["."])


def _with_sdk(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["mcp"]\n', encoding="utf-8",
    )


# ── session-id-reliance ───────────────────────────────────────────────────

def test_session_id_header_reliance_fires(tmp_path: Path) -> None:
    _with_sdk(tmp_path)
    (tmp_path / "server.py").write_text(
        "def handle_request(headers):\n"
        "    session_id = headers.get('Mcp-Session-Id')\n"
        "    return lookup_session(session_id)\n",
        encoding="utf-8",
    )
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-stateless-migration/session-id-reliance")
    assert hit.severity == "high"


def test_no_session_id_reference_is_safe(tmp_path: Path) -> None:
    _with_sdk(tmp_path)
    (tmp_path / "server.py").write_text(
        "def handle_request(headers):\n"
        "    return process(headers)\n",
        encoding="utf-8",
    )
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-stateless-migration/session-id-reliance" for f in findings)


def test_session_id_without_sdk_declared_is_safe(tmp_path: Path) -> None:
    """FP-bait: no manifest declares the MCP SDK -- source-side rules 1/2 stay quiet."""
    (tmp_path / "server.py").write_text(
        "def handle_request(headers):\n"
        "    session_id = headers.get('Mcp-Session-Id')\n"
        "    return lookup_session(session_id)\n",
        encoding="utf-8",
    )
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-stateless-migration/session-id-reliance" for f in findings)


# ── tasks-list-removed ────────────────────────────────────────────────────

def test_tasks_list_literal_fires(tmp_path: Path) -> None:
    _with_sdk(tmp_path)
    (tmp_path / "client.py").write_text(
        "def dispatch(method):\n"
        "    if method == 'tasks/list':\n"
        "        return list_tasks()\n",
        encoding="utf-8",
    )
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-stateless-migration/tasks-list-removed" for f in findings)


def test_tasks_get_is_safe(tmp_path: Path) -> None:
    """FP-bait: tasks/get (still core) must not match the tasks/list pattern."""
    _with_sdk(tmp_path)
    (tmp_path / "client.py").write_text(
        "def dispatch(method):\n"
        "    if method == 'tasks/get':\n"
        "        return get_task()\n",
        encoding="utf-8",
    )
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-stateless-migration/tasks-list-removed" for f in findings)


# ── sticky-routing-dependency ──────────────────────────────────────────────

def test_nginx_ip_hash_with_mcp_mention_fires(tmp_path: Path) -> None:
    (tmp_path / "nginx.conf").write_text(
        "upstream mcp_backend {\n    ip_hash;\n    server 10.0.0.1;\n}\n",
        encoding="utf-8",
    )
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-stateless-migration/sticky-routing-dependency" for f in findings)


def test_nginx_ip_hash_without_mcp_mention_is_safe(tmp_path: Path) -> None:
    """FP-bait: no SDK declared and the manifest never mentions mcp -- silent."""
    (tmp_path / "nginx.conf").write_text(
        "upstream backend {\n    ip_hash;\n    server 10.0.0.1;\n}\n",
        encoding="utf-8",
    )
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_k8s_session_affinity_fires(tmp_path: Path) -> None:
    (tmp_path / "service.yaml").write_text(
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: mcp-server\nspec:\n  sessionAffinity: ClientIP\n",
        encoding="utf-8",
    )
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-stateless-migration/sticky-routing-dependency" for f in findings)


def test_shared_session_store_lookup_fires(tmp_path: Path) -> None:
    _with_sdk(tmp_path)
    (tmp_path / "server.py").write_text(
        "def handle(session_id):\n"
        "    state = session_store[session_id]\n"
        "    return state\n",
        encoding="utf-8",
    )
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-stateless-migration/sticky-routing-dependency" for f in findings)


def test_surfacing_rules_are_review_signals_and_sticky_routing_is_proven(tmp_path: Path) -> None:
    # #766: neither `surfacing_rule_prefixes` entry had a behavioral pin, so emptying the tuple
    # left the suite green. Both directions in one run: the two declared rules are review signals,
    # and the undeclared sticky-routing rule stays proven, so a prefix widened to `mcp-stateless-
    # migration/` fails here too. Review class is report ordering only; severity still gates.
    _with_sdk(tmp_path)
    (tmp_path / "server.py").write_text(
        "def handle_request(headers):\n"
        "    session_id = headers.get('Mcp-Session-Id')\n"
        "    return lookup_session(session_id)\n",
        encoding="utf-8",
    )
    (tmp_path / "client.py").write_text(
        "def dispatch(method):\n"
        "    if method == 'tasks/list':\n"
        "        return list_tasks()\n",
        encoding="utf-8",
    )
    (tmp_path / "nginx.conf").write_text(
        "upstream mcp_backend {\n    ip_hash;\n    server 10.0.0.1;\n}\n",
        encoding="utf-8",
    )
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert {(f.rule, _is_review_finding(f)) for f in findings} == {
        ("mcp-stateless-migration/session-id-reliance", True),
        ("mcp-stateless-migration/tasks-list-removed", True),
        ("mcp-stateless-migration/sticky-routing-dependency", False),
    }


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    _with_sdk(tmp_path)
    (tmp_path / "server.py").write_text(
        "# security: allow-mcp-stateless-migration\n"
        "def handle_request(headers):\n"
        "    session_id = headers.get('Mcp-Session-Id')\n"
        "    return lookup_session(session_id)\n",
        encoding="utf-8",
    )
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_sticky_line_number_is_exact_when_a_blank_line_precedes(tmp_path: Path) -> None:
    """Pins the `^[^\\S\\n]*` anchor: with `^\\s*` the match started on the preceding BLANK line
    (`\\s` eats newlines under MULTILINE), reporting line 2 instead of the `ip_hash;` line 3."""
    (tmp_path / "nginx.conf").write_text(
        "upstream mcp_backend {\n\n    ip_hash;\n    server 10.0.0.1;\n}\n", encoding="utf-8"
    )
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = [f for f in findings if f.rule == "mcp-stateless-migration/sticky-routing-dependency"]
    assert [f.location.replace("\\", "/") for f in hit] == ["nginx.conf:3"]


def test_sticky_cookie_line_number_is_exact_after_blank_lines(tmp_path: Path) -> None:
    (tmp_path / "nginx.conf").write_text(
        "upstream mcp_backend {\n\n\n    sticky cookie srv_id;\n}\n", encoding="utf-8"
    )
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert [f.location.replace("\\", "/") for f in findings] == ["nginx.conf:4"]


def test_generated_wire_types_file_is_skipped(tmp_path: Path) -> None:
    """FP-bait: python-sdk's generated 2025-11-25 wire types carry `tasks/list` legitimately."""
    _with_sdk(tmp_path)
    (tmp_path / "wire.py").write_text(
        '"""Internal wire-shape models for protocol 2025-11-25. Generated; do not edit."""\n'
        'METHOD = "tasks/list"\n',
        encoding="utf-8",
    )
    assert McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


def test_hand_written_tasks_list_still_fires_beside_generated_skip(tmp_path: Path) -> None:
    """The direction traded against: the same content without a generated header still fires,
    and a file that merely says "generated" without `do not edit` is not skipped."""
    _with_sdk(tmp_path)
    (tmp_path / "wire.py").write_text('METHOD = "tasks/list"\n', encoding="utf-8")
    (tmp_path / "other.py").write_text(
        '"""Handlers generated by hand.\n"""\nMETHOD = "tasks/list"\n', encoding="utf-8"
    )
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert len(findings) == 2


def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpStatelessMigrationGuard().applies(prof) is False


def test_deeply_nested_package_json_does_not_crash_the_guard(tmp_path: Path) -> None:
    """A hostile deep `package.json` raised RecursionError out of the SDK probe and the whole guard
    was reported as errored; it must degrade to 'no SDK declared' instead."""
    (tmp_path / "package.json").write_text('{"dependencies": ' + "[" * 200_000 + "]" * 200_000 + "}", encoding="utf-8")
    (tmp_path / "server.py").write_text("session_id = headers.get('Mcp-Session-Id')\n", encoding="utf-8")
    assert McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path)) == []


# ── #424 E6 (#1000): the pragma counts only as a comment, at every rule site ─────────

_SESSION_STORE_TS = (
    "export function handle(sid: string) {\n"
    "  const state = sessions[sid];\n"
    "  return state;\n"
    "}\n"
)
_K8S_SERVICE = (
    "apiVersion: v1\nkind: Service\nmetadata:\n  name: mcp-server\nspec:\n  sessionAffinity: ClientIP\n"
)
_NGINX_IP_HASH = "upstream mcp_backend {\n    ip_hash;\n    server 10.0.0.1;\n}\n"


def _rule_locations(tmp_path: Path) -> list[tuple[str, str]]:
    findings = McpStatelessMigrationGuard().run(tmp_path, _mcp_prof(tmp_path))
    return sorted((f.rule, f.location.replace("\\", "/")) for f in findings)


def test_mcp_stateless_migration_pragma_quoted_in_a_string_does_not_suppress_session_id(
    tmp_path: Path,
) -> None:
    # #424 E6 (#1000): the session-id rule's whole-file opt-out reads the python comment view, so a
    # string literal quoting the pragma is content. Only a real `#` comment (`test_pragma_suppresses_finding`) opts out.
    _with_sdk(tmp_path)
    (tmp_path / "server.py").write_text(
        'HELP = "opt out with # security: allow-mcp-stateless-migration"\n'
        "def handle_request(headers):\n"
        "    session_id = headers.get('Mcp-Session-Id')\n"
        "    return lookup_session(session_id)\n",
        encoding="utf-8",
    )
    assert _rule_locations(tmp_path) == [("mcp-stateless-migration/session-id-reliance", "server.py:3")]


def test_mcp_stateless_migration_pragma_quoted_in_a_string_does_not_suppress_sticky_yaml(
    tmp_path: Path,
) -> None:
    # #424 E6 (#1000): the sticky-routing infra opt-out reads the yaml comment view, so a quoted
    # scalar carrying the pragma is content. Only a real `#` comment (`..._comment_suppresses_sticky_yaml`) opts out.
    (tmp_path / "service.yaml").write_text(
        'description: "opt out with # security: allow-mcp-stateless-migration"\n' + _K8S_SERVICE,
        encoding="utf-8",
    )
    assert _rule_locations(tmp_path) == [("mcp-stateless-migration/sticky-routing-dependency", "service.yaml:7")]


def test_mcp_stateless_migration_pragma_quoted_in_a_string_does_not_suppress_sticky_conf(
    tmp_path: Path,
) -> None:
    # #424 E6 (#1000): nginx.conf reads under the quote-aware hash view, so a quoted directive argument
    # carrying the pragma is content. Only a real `#` comment (`..._comment_suppresses_sticky_conf`) opts out.
    (tmp_path / "nginx.conf").write_text(
        'add_header X-Help "opt out with # security: allow-mcp-stateless-migration";\n' + _NGINX_IP_HASH,
        encoding="utf-8",
    )
    assert _rule_locations(tmp_path) == [("mcp-stateless-migration/sticky-routing-dependency", "nginx.conf:3")]


def test_mcp_stateless_migration_pragma_quoted_in_a_string_does_not_suppress_session_store_ts(
    tmp_path: Path,
) -> None:
    # #424 E6 (#1000): the session-store rule's whole-file opt-out reads the js comment view, so a
    # string literal quoting the pragma is content. Only a real `//` comment (`..._comment_suppresses_session_store_ts`) opts out.
    _with_sdk(tmp_path)
    (tmp_path / "store.ts").write_text(
        'const help = "opt out with // security: allow-mcp-stateless-migration";\n' + _SESSION_STORE_TS,
        encoding="utf-8",
    )
    assert _rule_locations(tmp_path) == [("mcp-stateless-migration/sticky-routing-dependency", "store.ts:3")]


def test_mcp_stateless_migration_pragma_comment_suppresses_sticky_yaml(tmp_path: Path) -> None:
    (tmp_path / "service.yaml").write_text(_K8S_SERVICE, encoding="utf-8")
    assert _rule_locations(tmp_path) == [("mcp-stateless-migration/sticky-routing-dependency", "service.yaml:6")]
    (tmp_path / "service.yaml").write_text(
        "# security: allow-mcp-stateless-migration\n" + _K8S_SERVICE, encoding="utf-8"
    )
    assert _rule_locations(tmp_path) == []


def test_mcp_stateless_migration_pragma_comment_suppresses_sticky_conf(tmp_path: Path) -> None:
    (tmp_path / "nginx.conf").write_text(_NGINX_IP_HASH, encoding="utf-8")
    assert _rule_locations(tmp_path) == [("mcp-stateless-migration/sticky-routing-dependency", "nginx.conf:2")]
    (tmp_path / "nginx.conf").write_text(
        "# security: allow-mcp-stateless-migration\n" + _NGINX_IP_HASH, encoding="utf-8"
    )
    assert _rule_locations(tmp_path) == []


def test_mcp_stateless_migration_pragma_comment_suppresses_session_store_ts(tmp_path: Path) -> None:
    _with_sdk(tmp_path)
    (tmp_path / "store.ts").write_text(_SESSION_STORE_TS, encoding="utf-8")
    assert _rule_locations(tmp_path) == [("mcp-stateless-migration/sticky-routing-dependency", "store.ts:2")]
    (tmp_path / "store.ts").write_text(
        "// security: allow-mcp-stateless-migration\n" + _SESSION_STORE_TS, encoding="utf-8"
    )
    assert _rule_locations(tmp_path) == []
