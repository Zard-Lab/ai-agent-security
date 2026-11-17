from __future__ import annotations

from agentsec.findings import _is_review_finding
from agentsec.guards.mcp_session_id_security import McpSessionIdSecurityGuard
from tests.guards._common import *  # noqa: F401,F403

_MCP_IMPORT = "from mcp.server import Server\n"


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "python"}, python_dirs=["."])


def test_weak_session_id_fires_on_uuid1(tmp_path: Path) -> None:
    (tmp_path / "session.py").write_text(
        _MCP_IMPORT + "import uuid\n\n"
        "def create_session():\n"
        "    session_id = str(uuid.uuid1())\n"
        "    return session_id\n",
        encoding="utf-8",
    )
    findings = McpSessionIdSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-session-id-security/weak-session-id-generation" for f in findings)


def test_weak_session_id_silent_on_reading_the_client_sent_header(tmp_path: Path) -> None:
    """FP-bait (H2, PR #1053 review): reading the client's session id back out of the
    `Mcp-Session-Id` header is the correct, unavoidable streamable-HTTP server pattern, not
    generation from client-controlled input — the former rule 1b that flagged this shape was
    deleted entirely, not narrowed."""
    (tmp_path / "session.py").write_text(
        _MCP_IMPORT + "def resume_session(request):\n"
        "    session_id = request.headers.get('mcp-session-id')\n"
        "    return session_id\n",
        encoding="utf-8",
    )
    findings = McpSessionIdSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-session-id-security/weak-session-id-generation" for f in findings)


def test_weak_session_id_silent_on_uuid4(tmp_path: Path) -> None:
    """FP-bait: uuid4() is cryptographically random — the safe, recommended form — must not
    fire."""
    (tmp_path / "session.py").write_text(
        _MCP_IMPORT + "import uuid\n\n"
        "def create_session():\n"
        "    session_id = str(uuid.uuid4())\n"
        "    return session_id\n",
        encoding="utf-8",
    )
    findings = McpSessionIdSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-session-id-security/weak-session-id-generation" for f in findings)


def test_weak_session_id_silent_without_file_level_mcp_marker(tmp_path: Path) -> None:
    """FP-bait (H2, PR #1053 review), the important one: the same uuid1() shape in a file with
    NO MCP SDK import must not fire, even though the repo-wide StackProfile carries the `mcp`
    feature — an unrelated `web/other.py` in a repo that merely uses MCP elsewhere must not be
    anchored. Mirrors `mcp-oauth-flow-hardening`'s own file-marker scoping."""
    (tmp_path / "web.py").write_text(
        "import uuid\n\n"
        "def create_session():\n"
        "    session_id = str(uuid.uuid1())\n"
        "    return session_id\n",
        encoding="utf-8",
    )
    findings = McpSessionIdSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-session-id-security/weak-session-id-generation" for f in findings)


def test_session_id_as_sole_auth_fires_on_bare_membership_check(tmp_path: Path) -> None:
    (tmp_path / "session.py").write_text(
        _MCP_IMPORT + "def is_authorized(sessions, session_id):\n"
        "    if session_id in sessions:\n"
        "        return True\n"
        "    return False\n",
        encoding="utf-8",
    )
    findings = McpSessionIdSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-session-id-security/session-id-as-sole-authorization" for f in findings)


def test_session_id_as_sole_auth_is_a_medium_surfacing_finding(tmp_path: Path) -> None:
    """Round-2 review M4 (#1053): "sole authorization" asks a human to confirm an architecture, so
    the rule is surfacing. Before this test, dropping `surfacing_rule_prefixes` left the suite green."""
    (tmp_path / "session.py").write_text(
        _MCP_IMPORT + "def is_authorized(sessions, session_id):\n"
        "    if session_id in sessions:\n"
        "        return True\n"
        "    return False\n",
        encoding="utf-8",
    )
    hits = [f for f in McpSessionIdSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
            if f.rule == "mcp-session-id-security/session-id-as-sole-authorization"]
    assert hits
    assert all(f.severity == "medium" and _is_review_finding(f) for f in hits)


def test_weak_session_id_finding_does_not_claim_the_deleted_client_value_detection(tmp_path: Path) -> None:
    """Round-2 review M1 (#1053): rule 1b (session id taken from a client-controlled request value)
    was deleted, so the shipped finding must not tell the user it detected that, and the remediation
    must not tell a streamable-HTTP server to stop reading the client's session header."""
    (tmp_path / "session.py").write_text(
        _MCP_IMPORT + "import uuid\n\n"
        "def create_session():\n"
        "    session_id = str(uuid.uuid1())\n"
        "    return session_id\n",
        encoding="utf-8",
    )
    hits = [f for f in McpSessionIdSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
            if f.rule == "mcp-session-id-security/weak-session-id-generation"]
    assert hits
    for f in hits:
        assert "client-controlled" not in f.message
        assert "client-controlled" not in f.title
        assert "never accept a session identifier value directly from client-supplied" not in f.remediation


def test_session_id_as_sole_auth_silent_with_additional_condition(tmp_path: Path) -> None:
    """FP-bait, the important one: an ANDed additional condition (a real auth check) breaks the
    anchored match — must not fire."""
    (tmp_path / "session.py").write_text(
        _MCP_IMPORT + "def is_authorized(sessions, session_id, user):\n"
        "    if session_id in sessions and user.is_admin:\n"
        "        return True\n"
        "    return False\n",
        encoding="utf-8",
    )
    findings = McpSessionIdSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-session-id-security/session-id-as-sole-authorization" for f in findings)


def test_session_id_as_sole_auth_silent_without_file_level_mcp_marker(tmp_path: Path) -> None:
    """FP-bait (H2, PR #1053 review): the same bare membership check in a file with no MCP SDK
    import must not fire, same file-marker scoping as the weak-generation rule above."""
    (tmp_path / "web.py").write_text(
        "def is_authorized(sessions, session_id):\n"
        "    if session_id in sessions:\n"
        "        return True\n"
        "    return False\n",
        encoding="utf-8",
    )
    findings = McpSessionIdSecurityGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-session-id-security/session-id-as-sole-authorization" for f in findings)


def test_mcp_session_id_security_applies_gate() -> None:
    p = mkprofile(Path("."), features={"python"})
    assert not McpSessionIdSecurityGuard().applies(p)
    p_mcp = mkprofile(Path("."), features={"python", "mcp"})
    assert McpSessionIdSecurityGuard().applies(p_mcp)


def test_mcp_session_id_security_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "session.py").write_text(
        "# security: allow-mcp-session-id-security\n"
        + _MCP_IMPORT
        + "import uuid\n\n"
        "def create_session():\n"
        "    session_id = str(uuid.uuid1())\n"
        "    return session_id\n",
        encoding="utf-8",
    )
    assert McpSessionIdSecurityGuard().run(tmp_path, _mcp_prof(tmp_path)) == []
