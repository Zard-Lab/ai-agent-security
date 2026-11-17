"""Tests for the agent-memory-retention guard (§4)."""
from __future__ import annotations

from agentsec.guards.agent_memory_retention import AgentMemoryRetentionGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "agent-memory-retention/persistent-memory-no-ttl"


def _run(tmp_path: Path):
    return AgentMemoryRetentionGuard().run(tmp_path, _llm_prof(tmp_path))


# ── fires ─────────────────────────────────────────────────────────────────────

def test_agent_memory_retention_fires(tmp_path: Path) -> None:
    """A persistent memory constructor with no TTL -> one MEDIUM finding."""
    (tmp_path / "mem.py").write_text(
        "def build(url):\n"
        "    return RedisChatMessageHistory(session_id='s', url=url)\n",
        encoding="utf-8",
    )
    findings = [f for f in _run(tmp_path) if f.rule == _RULE]
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "medium"
    assert f.check_id == "agent-memory-retention"
    assert f.location == "mem.py:2"
    assert f.standards == ["OWASP-LLM:LLM01", "OWASP-LLM:LLM08", "OWASP:A09", "OWASP-ASI:ASI06"]


def test_agent_memory_retention_ttl_none_fires(tmp_path: Path) -> None:
    """`ttl=None` is LangChain's 'never expire' default — it must still fire."""
    (tmp_path / "mem.py").write_text(
        "h = RedisChatMessageHistory(session_id='s', url='redis://x', ttl=None)\n",
        encoding="utf-8",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_agent_memory_retention_fires_once_per_file(tmp_path: Path) -> None:
    """Two no-TTL constructors in one file -> a single finding (one per file)."""
    (tmp_path / "mem.py").write_text(
        "a = RedisChatMessageHistory(session_id='s', url='redis://x')\n"
        "b = RedisSaver.from_conn_string('redis://y')\n",
        encoding="utf-8",
    )
    assert len([f for f in _run(tmp_path) if f.rule == _RULE]) == 1


# ── silent (FP-bait) ────────────────────────────────────────────────────────────

def test_agent_memory_retention_silent_with_ttl(tmp_path: Path) -> None:
    """`ttl=<int>` present -> silent."""
    (tmp_path / "mem.py").write_text(
        "h = RedisChatMessageHistory(session_id='s', url='redis://x', ttl=86400)\n",
        encoding="utf-8",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_agent_memory_retention_silent_ttl_multiline(tmp_path: Path) -> None:
    """A multi-line constructor with `ttl=` on a continuation line -> silent."""
    (tmp_path / "mem.py").write_text(
        "h = RedisChatMessageHistory(\n"
        "    session_id='s',\n"
        "    url='redis://x',\n"
        "    ttl=3600,\n"
        ")\n",
        encoding="utf-8",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_agent_memory_retention_silent_chained_expire(tmp_path: Path) -> None:
    """A chained `.expire(...)` within the window -> silent."""
    (tmp_path / "mem.py").write_text(
        "h = RedisChatMessageHistory(session_id='s', url='redis://x')\n"
        "h.expire(3600)\n",
        encoding="utf-8",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_agent_memory_retention_silent_non_persistent_ctor(tmp_path: Path) -> None:
    """An in-memory buffer (not a persistent TTL-capable store) is out of scope -> silent."""
    (tmp_path / "mem.py").write_text(
        "from langchain.memory import ConversationBufferMemory\n"
        "m = ConversationBufferMemory()\n",
        encoding="utf-8",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_agent_memory_retention_silent_in_docstring(tmp_path: Path) -> None:
    """A constructor shown as an EXAMPLE in a docstring must not false-fire (triple-quoted
    strings are blanked by strip_python_strings)."""
    (tmp_path / "mem.py").write_text(
        "def build():\n"
        '    """Example:\n'
        "    RedisChatMessageHistory(session_id='s', url='redis://x')\n"
        '    """\n'
        "    return None\n",
        encoding="utf-8",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_agent_memory_retention_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "mem.py").write_text(
        "# security: allow-no-memory-retention\n"
        "h = RedisChatMessageHistory(session_id='s', url='redis://x')\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


# ── a TTL marker in a COMMENT must not silence a real finding (#386 review) ─────

def test_agent_memory_retention_trailing_comment_marker_still_fires(tmp_path: Path) -> None:
    """A TTL marker mentioned in a trailing comment is not real config — must still fire."""
    (tmp_path / "mem.py").write_text(
        "h = RedisChatMessageHistory(session_id='s', url='redis://x')  # ttl=3600 would be nice\n",
        encoding="utf-8",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_agent_memory_retention_following_comment_marker_still_fires(tmp_path: Path) -> None:
    """A `# .expire(...)` comment within the window is not real config — must still fire."""
    (tmp_path / "mem.py").write_text(
        "h = RedisChatMessageHistory(session_id='s', url='redis://x')\n"
        "# .expire(3600) — TODO, not wired yet\n"
        "return h\n",
        encoding="utf-8",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


# ── value-agnostic: any present ttl mechanism silences (verify mechanism, not value) ──

def test_agent_memory_retention_ttl_var_and_zero_silent(tmp_path: Path) -> None:
    """`ttl=<var>` and `ttl=0` both read as configured — the guard verifies the mechanism
    exists, not that the value is appropriate (a documented limitation)."""
    (tmp_path / "a.py").write_text(
        "h = RedisChatMessageHistory(session_id='s', url='redis://x', ttl=cfg_ttl)\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "h = RedisChatMessageHistory(session_id='s', url='redis://x', ttl=0)\n",
        encoding="utf-8",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_agent_memory_retention_redis_write_expiry_silent(tmp_path: Path) -> None:
    """A redis-style write expiry (`ex=`/`px=`) on the same store within the window silences."""
    (tmp_path / "a.py").write_text(
        "h = RedisChatMessageHistory(session_id='s', url='redis://x')\n"
        "h.redis_client.set(key, val, ex=3600)\n",
        encoding="utf-8",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_agent_memory_retention_aliased_import_bypass(tmp_path: Path) -> None:
    """Documented bypass: an aliased/renamed constructor is not matched by the literal-name
    regex (fail-open); locked so a future regex change surfaces here."""
    (tmp_path / "mem.py").write_text(
        "from langchain_community.chat_message_histories import RedisChatMessageHistory as RCMH\n"
        "h = RCMH(session_id='s', url='redis://x')\n",
        encoding="utf-8",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


# ── applies() gate ──────────────────────────────────────────────────────────────

def test_agent_memory_retention_applies_gate(tmp_path: Path) -> None:
    g = AgentMemoryRetentionGuard()
    assert g.applies(mkprofile(tmp_path, features={"llm"})) is True
    assert g.applies(mkprofile(tmp_path, features={"python"})) is False
