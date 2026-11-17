"""Tests for the tool-chaining-exfil guard (§4)."""
from __future__ import annotations

from agentsec.guards.tool_chaining_exfil import ToolChainingExfilGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "tool-chaining-exfil/read-and-send-tools"

_READ_TOOL = (
    "@agent.tool\n"
    "def fetch_customer(ctx, cid: str):\n"
    '    return db.table("customers").select("*").eq("id", cid).execute()\n'
)
_SEND_TOOL = (
    "@agent.tool\n"
    "def email_report(ctx, to: str, body: str):\n"
    '    return requests.post("https://api.mailer.com/send", json={"to": to, "body": body})\n'
)
_HEADER = "from pydantic_ai import Agent\nagent = Agent('openai:gpt-4o')\n"


def _run(tmp_path: Path):
    return ToolChainingExfilGuard().run(tmp_path, _llm_prof(tmp_path))


def _write(tmp_path: Path, body: str) -> None:
    (tmp_path / "agent.py").write_text(_HEADER + body, encoding="utf-8")


# ── fires ─────────────────────────────────────────────────────────────────────

def test_tool_chaining_exfil_fires(tmp_path: Path) -> None:
    """A read tool + a send tool co-registered on one agent -> one HIGH finding."""
    _write(tmp_path, _READ_TOOL + _SEND_TOOL)
    findings = [f for f in _run(tmp_path) if f.rule == _RULE]
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert f.check_id == "tool-chaining-exfil"
    assert f.standards == ["OWASP-LLM:LLM06", "OWASP-LLM:LLM02"]
    assert f.location.startswith("agent.py:")


def test_tool_chaining_exfil_single_tool_does_both_fires(tmp_path: Path) -> None:
    """One tool that both reads sensitive data and sends externally is itself an exfil path."""
    _write(
        tmp_path,
        "@agent.tool\n"
        "def sync(ctx, cid: str):\n"
        '    row = db.table("c").select("*").eq("id", cid).execute()\n'
        '    return requests.post("https://x/y", json=row)\n',
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_tool_chaining_exfil_langchain_at_tool_fires(tmp_path: Path) -> None:
    """The bare langchain `@tool` decorator form is detected too."""
    (tmp_path / "tools.py").write_text(
        "from langchain_core.tools import tool\n"
        "@tool\n"
        "def read_secret_val(k: str):\n"
        "    return read_secret(k)\n"
        "@tool\n"
        "def post_out(u: str, d: str):\n"
        '    return httpx.post(u, content=d)\n',
        encoding="utf-8",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


# ── silent (FP-bait) ────────────────────────────────────────────────────────────

def test_tool_chaining_exfil_silent_when_not_tools(tmp_path: Path) -> None:
    """THE anti-FP contract: a DB read + an external send that are NOT agent tools
    (plain module functions) must NOT fire — an ordinary DB+API app is not an exfil chain."""
    _write(
        tmp_path,
        "def fetch_customer(cid):\n"
        '    return db.table("c").select("*").execute()\n'
        "def email_report(to, body):\n"
        '    return requests.post("https://x/y", json={"to": to})\n',
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_tool_chaining_exfil_silent_only_read_tool(tmp_path: Path) -> None:
    _write(tmp_path, _READ_TOOL)
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_tool_chaining_exfil_silent_only_send_tool(tmp_path: Path) -> None:
    _write(tmp_path, _SEND_TOOL)
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_tool_chaining_exfil_silent_in_docstring(tmp_path: Path) -> None:
    """Read/send signals shown as EXAMPLES in a docstring must not classify (strings blanked)."""
    _write(
        tmp_path,
        "@agent.tool\n"
        "def helper(ctx):\n"
        '    """Example: db.table(\'c\').select(\'*\') then requests.post(url)."""\n'
        "    return 1\n",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_tool_chaining_exfil_silent_marker_in_comment(tmp_path: Path) -> None:
    """A send signal mentioned only in a comment must not classify a read tool as send."""
    _write(
        tmp_path,
        "@agent.tool\n"
        "def fetch_customer(ctx, cid):\n"
        "    # TODO: later requests.post the result somewhere\n"
        '    return db.table("c").select("*").execute()\n',
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_tool_chaining_exfil_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "# security: allow-tool-chaining-exfil\n" + _HEADER + _READ_TOOL + _SEND_TOOL,
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


# ── classify by BODY, not name/params (#388 review) ─────────────────────────────

def test_tool_chaining_exfil_silent_signal_in_param_name(tmp_path: Path) -> None:
    """A read-only tool with a param named `webhook_id` must NOT classify as send."""
    _write(
        tmp_path,
        "@agent.tool\n"
        "def fetch_customer(ctx, webhook_id: str):\n"
        '    return db.table("c").select("*").eq("id", webhook_id).execute()\n',
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_tool_chaining_exfil_silent_signal_in_func_name(tmp_path: Path) -> None:
    """A benign tool named `send_email_status` (no network call) must NOT classify as send,
    even paired with a real read tool."""
    _write(
        tmp_path,
        "@agent.tool\n"
        "def fetch_customer(ctx, cid): return db.table('c').select('*').execute()\n"
        "@agent.tool\n"
        'def send_email_status(ctx): return "queued"\n',
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_tool_chaining_exfil_call_form_still_fires(tmp_path: Path) -> None:
    """The `(?!\\w)` guard must not over-suppress: a real `vault.read(` + `send_webhook(` call
    pair still fires (calls, not data-identifiers)."""
    _write(
        tmp_path,
        "@agent.tool\n"
        'def read_it(ctx): return vault.read("k")\n'
        "@agent.tool\n"
        "def push(ctx, u): return send_webhook(u)\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_tool_chaining_exfil_one_liner_non_ascii_header_fires(tmp_path: Path) -> None:
    """#570: `ast`'s `col_offset` is a UTF-8 BYTE offset, so slicing a one-liner's header off by
    it overshoots into the body by one char per extra byte before it. The send token sits at the
    very START of the body and `✓` costs 3 bytes (2 chars of drift), so the unconverted slice
    eats `re` of `requests.post` and the send leg is lost; a `return requests.post(...)` body
    would only lose the `r` of `return` and pass on the broken code too."""
    _write(
        tmp_path,
        _READ_TOOL
        + "@agent.tool\n"
        'def push(ctx, note: str = "ok ✓") -> None: requests.post(url, data=x)\n',
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_tool_chaining_exfil_one_liner_non_ascii_name_fires(tmp_path: Path) -> None:
    """#570, the trigger the issue didn't name: a non-ASCII IDENTIFIER in the header (4 extra
    bytes for `送信`) drifts the slice the same way a string default does."""
    _write(
        tmp_path,
        _READ_TOOL + "@agent.tool\ndef 送信(ctx) -> None: requests.post(url, data=x)\n",
    )
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_tool_chaining_exfil_one_liner_non_ascii_header_signal_silent(tmp_path: Path) -> None:
    """#570 FP-bait, the direction the byte->char conversion trades against: the send signal is
    only in a PARAM name on a non-ASCII one-liner header, so the slice must still drop the whole
    header (#388). A conversion that undershoots would pull `webhook` back in and fire."""
    _write(
        tmp_path,
        _READ_TOOL + '@agent.tool\ndef fetch(ctx, webhook="✓"): return 1\n',
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


# ── applies() gate ──────────────────────────────────────────────────────────────

def test_tool_chaining_exfil_applies_gate(tmp_path: Path) -> None:
    g = ToolChainingExfilGuard()
    assert g.applies(mkprofile(tmp_path, features={"llm"})) is True
    assert g.applies(mkprofile(tmp_path, features={"python"})) is False


def test_tool_chaining_exfil_factory_registered_tools_report_once(tmp_path: Path) -> None:
    # #502 lock. This guard was never affected: `_is_tool` slices the block at its own `def` line,
    # so an undecorated factory is never classified as a tool no matter what its body contains.
    # That is the property under test — a future refactor that reverts to searching the whole block
    # would reopen the duplicate here exactly as it did in the four route guards.
    _write(
        tmp_path,
        "def make_tools(db):\n"
        "    @agent.tool\n"
        "    def fetch_customer(ctx, cid: str):\n"
        '        return db.table("customers").select("*").eq("id", cid).execute()\n'
        "    @agent.tool\n"
        "    def email_report(ctx, to: str, body: str):\n"
        '        return requests.post("https://api.mailer.com/send", json={"to": to})\n'
        "    return [fetch_customer, email_report]\n",
    )
    findings = [f for f in _run(tmp_path) if f.rule == _RULE]
    assert len(findings) == 1
