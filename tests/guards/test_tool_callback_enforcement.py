"""Tests for the tool-callback-enforcement guard."""
from __future__ import annotations

import pytest

from agentsec.findings import Finding
from agentsec.guards.tool_callback_enforcement import ToolCallbackEnforcementGuard
from tests.guards._common import *  # noqa: F401,F403

# ---------------------------------------------------------------------------
# Rule 1: no-interrupt-before (TC001)
# ---------------------------------------------------------------------------

def test_tc001_agent_executor_no_callback_fires(tmp_path: Path) -> None:
    """AgentExecutor without interrupt/confirm param fires no-interrupt-before."""
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "agent = AgentExecutor(agent=a, tools=tools, verbose=True)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "tool-callback-enforcement/no-interrupt-before" in rules


def test_tc001_agent_executor_multiline_no_callback_fires(tmp_path: Path) -> None:
    """Multi-line AgentExecutor without interrupt param fires."""
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "agent = AgentExecutor(\n"
        "    agent=a,\n"
        "    tools=tools,\n"
        "    verbose=True,\n"
        ")\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "tool-callback-enforcement/no-interrupt-before" in rules


def test_tc001_agent_executor_with_interrupt_before_silent(tmp_path: Path) -> None:
    """AgentExecutor with interrupt_before param stays silent (FP-bait)."""
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "agent = AgentExecutor(agent=a, tools=tools, interrupt_before=['delete_tool'])\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "tool-callback-enforcement/no-interrupt-before" not in rules


def test_tc001_agent_executor_with_before_tool_call_silent(tmp_path: Path) -> None:
    """AgentExecutor with before_tool_call param stays silent (FP-bait)."""
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "agent = AgentExecutor(agent=a, tools=tools, before_tool_call=my_callback)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "tool-callback-enforcement/no-interrupt-before" not in rules


# ── **kwargs-unpacked AgentExecutor construction ──────────────────────────────────

def test_tc001_kwargs_unpack_with_resolved_callbacks_key_silent(tmp_path: Path) -> None:
    """Bug fix: `AgentExecutor(**config)` where `config` is defined in the same function WITH a
    `callbacks` key must NOT fire — the plain window scan can't see a key hidden inside a
    kwargs-unpacked dict, but resolving the dict's own definition can (#the batch C)."""
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "\n"
        "\n"
        "def build_agent(handler):\n"
        "    config = {\n"
        "        'agent': agent,\n"
        "        'tools': tools,\n"
        "        'callbacks': [handler],\n"
        "    }\n"
        "    return AgentExecutor(**config)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "tool-callback-enforcement/no-interrupt-before" for f in findings)


def test_tc001_kwargs_unpack_dict_call_form_with_interrupt_before_silent(tmp_path: Path) -> None:
    """Same resolution, `dict(...)` call form instead of a `{...}` literal."""
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "\n"
        "\n"
        "def build_agent():\n"
        "    config = dict(agent=agent, tools=tools, interrupt_before=['delete_tool'])\n"
        "    return AgentExecutor(**config)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "tool-callback-enforcement/no-interrupt-before" for f in findings)


def test_tc001_kwargs_unpack_resolved_dict_without_confirm_key_fires(tmp_path: Path) -> None:
    """STILL-FIRES: the kwargs dict IS resolved and genuinely carries no confirm-signal key —
    fires with real evidence, same precision a literal call would get."""
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "\n"
        "\n"
        "def build_agent():\n"
        "    config = {\n"
        "        'agent': agent,\n"
        "        'tools': tools,\n"
        "        'verbose': True,\n"
        "    }\n"
        "    return AgentExecutor(**config)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "tool-callback-enforcement/no-interrupt-before" for f in findings)


def test_tc001_kwargs_unpack_unresolvable_source_silent(tmp_path: Path) -> None:
    """FP-BAIT (the actual bug this fix closes): `AgentExecutor(**config)` where `config` is a
    function PARAMETER — its source is not statically resolvable at all. The old fixed-window
    scan found no literal param names in `**config` and always flagged this shape, even though
    the caller may pass a fully-configured, gated dict. Must stay silent (FN-biased default)."""
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "\n"
        "\n"
        "def build_agent(config):\n"
        "    return AgentExecutor(**config)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "tool-callback-enforcement/no-interrupt-before" for f in findings)


def test_tc001_kwargs_unpack_mixed_literal_confirm_still_silent(tmp_path: Path) -> None:
    """A literal confirm kwarg alongside a kwargs-unpack (`AgentExecutor(**base, callbacks=[h])`)
    is already visible to the plain window scan and must stay silent, unaffected by the new
    kwargs-resolution path."""
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "agent = AgentExecutor(**base, callbacks=[handler])\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "tool-callback-enforcement/no-interrupt-before" for f in findings)


def test_tc001_pragma_silences(tmp_path: Path) -> None:
    """Pragma on the file suppresses the finding."""
    (tmp_path / "agent.py").write_text(
        "# security: allow-tool-callback\n"
        "from langchain.agents import AgentExecutor\n"
        "agent = AgentExecutor(agent=a, tools=tools, verbose=True)\n",
        encoding="utf-8",
    )
    assert ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# ---------------------------------------------------------------------------
# Rule 2: destructive-tool-no-confirm (TC004)
# ---------------------------------------------------------------------------

def test_tc004_delete_tool_no_confirm_fires(tmp_path: Path) -> None:
    """@tool function with delete and no confirm fires destructive-tool-no-confirm."""
    (tmp_path / "tools.py").write_text(
        "from langchain.tools import tool\n"
        "\n"
        "\n"
        "@tool\n"
        "def delete_record(record_id: str) -> str:\n"
        '    db.query(f"DELETE FROM records WHERE id={record_id}")\n'
        '    return "deleted"\n',
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "tool-callback-enforcement/destructive-tool-no-confirm" in rules


def test_tc004_drop_tool_no_confirm_fires(tmp_path: Path) -> None:
    """@tool function with 'drop' (e.g. DROP TABLE) and no confirm fires."""
    (tmp_path / "admin.py").write_text(
        "from langchain.tools import tool\n"
        "\n"
        "\n"
        "@tool\n"
        "def drop_table(table_name: str) -> str:\n"
        "    db.execute(f'DROP TABLE {table_name}')\n"
        '    return "done"\n',
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "tool-callback-enforcement/destructive-tool-no-confirm" in rules


def test_tc004_delete_tool_with_confirmed_param_silent(tmp_path: Path) -> None:
    """@tool with delete that checks confirmed param stays silent (FP-bait)."""
    (tmp_path / "tools.py").write_text(
        "from langchain.tools import tool\n"
        "\n"
        "\n"
        "@tool\n"
        "def delete_record(record_id: str, confirmed: bool = False) -> str:\n"
        "    if not confirmed:\n"
        "        return 'Pass confirmed=True to delete'\n"
        '    db.query(f"DELETE FROM records WHERE id={record_id}")\n'
        '    return "deleted"\n',
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "tool-callback-enforcement/destructive-tool-no-confirm" not in rules


def test_tc004_delete_tool_with_approve_silent(tmp_path: Path) -> None:
    """@tool with delete that calls approve() stays silent (FP-bait)."""
    (tmp_path / "tools.py").write_text(
        "from langchain.tools import tool\n"
        "\n"
        "\n"
        "@tool\n"
        "def delete_record(record_id: str) -> str:\n"
        "    require_approval(record_id)\n"
        '    db.query(f"DELETE FROM records WHERE id={record_id}")\n'
        '    return "deleted"\n',
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "tool-callback-enforcement/destructive-tool-no-confirm" not in rules


def test_tc004_non_tool_function_with_delete_silent(tmp_path: Path) -> None:
    """A plain function (not @tool) with delete stays silent."""
    (tmp_path / "service.py").write_text(
        "def delete_record(record_id: str) -> str:\n"
        '    db.query(f"DELETE FROM records WHERE id={record_id}")\n'
        '    return "deleted"\n',
        encoding="utf-8",
    )
    assert ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# ---------------------------------------------------------------------------
# Rule 3: tool-credential-env-access (EXA004)
# ---------------------------------------------------------------------------

def test_exa004_tool_reads_api_key_env_fires(tmp_path: Path) -> None:
    """@tool reading API_KEY from os.environ fires tool-credential-env-access."""
    (tmp_path / "api_tool.py").write_text(
        "import os\n"
        "from langchain.tools import tool\n"
        "\n"
        "\n"
        "@tool\n"
        "def get_api_key() -> str:\n"
        '    return os.environ["OPENAI_API_KEY"]\n',
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "tool-callback-enforcement/tool-credential-env-access" in rules


def test_exa004_tool_reads_secret_env_fires(tmp_path: Path) -> None:
    """@tool reading SECRET from os.environ.get fires tool-credential-env-access."""
    (tmp_path / "auth_tool.py").write_text(
        "import os\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_secret(ctx) -> str:\n"
        "    return os.environ.get('DB_PASSWORD', '')\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "tool-callback-enforcement/tool-credential-env-access" in rules


def test_exa004_non_tool_env_access_silent(tmp_path: Path) -> None:
    """Plain function reading API_KEY stays silent (not a @tool decorator)."""
    (tmp_path / "config.py").write_text(
        "import os\n"
        "\n"
        "\n"
        "def load_config() -> str:\n"
        '    return os.environ["OPENAI_API_KEY"]\n',
        encoding="utf-8",
    )
    assert ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# ---------------------------------------------------------------------------
# Guard-level (applies)
# ---------------------------------------------------------------------------

def test_tool_callback_not_applicable_without_llm_feature() -> None:
    """Guard does not fire on stacks without 'llm' feature."""
    prof = mkprofile(Path("/tmp"), features={"python", "fastapi"})
    assert ToolCallbackEnforcementGuard().applies(prof) is False


# ── FP-bait regressions (review fixes) ───────────────────────────────────────

def test_tc001_is_medium_not_high(tmp_path: Path) -> None:
    """TC001 is advisory MEDIUM (the LangGraph kwargs are not classic AgentExecutor params)."""
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "ex = AgentExecutor(agent=a, tools=t, verbose=True)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "tool-callback-enforcement/no-interrupt-before")
    assert hit.severity == "medium"
    assert "OWASP-LLM:LLM06" in hit.standards


def test_tc001_callbacks_param_silent(tmp_path: Path) -> None:
    """`callbacks=` is the classic LangChain interception hook — must NOT fire."""
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "ex = AgentExecutor(agent=a, tools=t, callbacks=[ApprovalHandler()])\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "tool-callback-enforcement/no-interrupt-before" for f in findings)


def test_tc004_pandas_drop_columns_silent(tmp_path: Path) -> None:
    """`df.drop(columns=...)` is a non-destructive pandas op — must NOT fire (FP-bait)."""
    (tmp_path / "tools.py").write_text(
        "from langchain.tools import tool\n"
        "\n"
        "@tool\n"
        "def tidy(df):\n"
        "    return df.drop(columns=['tmp'])\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "tool-callback-enforcement/destructive-tool-no-confirm" for f in findings)


def test_tc004_list_remove_silent(tmp_path: Path) -> None:
    """`list.remove(x)` is not a destructive DB/file op — must NOT fire (FP-bait)."""
    (tmp_path / "tools.py").write_text(
        "from langchain.tools import tool\n"
        "\n"
        "@tool\n"
        "def drop_item(items, x):\n"
        "    items.remove(x)\n"
        "    return items\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "tool-callback-enforcement/destructive-tool-no-confirm" for f in findings)


def test_tc004_parametrized_tool_decorator_fires(tmp_path: Path) -> None:
    """A parametrized `@tool(...)` decorator is still recognised (decorator regex)."""
    (tmp_path / "tools.py").write_text(
        "from langchain.tools import tool\n"
        "\n"
        "@tool(return_direct=True)\n"
        "def wipe(table_name):\n"
        "    db.execute(f'DROP TABLE {table_name}')\n"
        "    return 'done'\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "tool-callback-enforcement/destructive-tool-no-confirm" for f in findings)


def test_exa004_client_builder_getenv_silent(tmp_path: Path) -> None:
    """A credential CONSUMED to build a client (not returned) must NOT fire (FP-bait)."""
    (tmp_path / "tools.py").write_text(
        "from langchain.tools import tool\n"
        "\n"
        "@tool\n"
        "def ask(q):\n"
        "    client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))\n"
        "    return client.run(q)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "tool-callback-enforcement/tool-credential-env-access" for f in findings)


def test_exa004_getenv_returned_fires(tmp_path: Path) -> None:
    """A credential read via os.getenv and RETURNED fires (os.getenv coverage + return flow)."""
    (tmp_path / "tools.py").write_text(
        "from langchain.tools import tool\n"
        "\n"
        "@tool\n"
        "def get_key():\n"
        "    return os.getenv('OPENAI_API_KEY')\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "tool-callback-enforcement/tool-credential-env-access")
    assert hit.severity == "medium"
    assert "OWASP-LLM:LLM02" in hit.standards


# ---------------------------------------------------------------------------
# Rule 4: explicit-approval-disabled
# ---------------------------------------------------------------------------

def test_explicit_auto_approve_true_fires(tmp_path: Path) -> None:
    """`auto_approve=True` explicitly disables the default approval gate — fires."""
    (tmp_path / "agent.py").write_text(
        "from crewai import Agent\n"
        "agent = Agent(auto_approve=True)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    hit = next(
        f for f in findings if f.rule == "tool-callback-enforcement/explicit-approval-disabled"
    )
    assert hit.severity == "high"
    assert "OWASP-LLM:LLM06" in hit.standards


def test_explicit_human_in_the_loop_false_fires(tmp_path: Path) -> None:
    """`human_in_the_loop=False` explicitly disables the default approval gate — fires."""
    (tmp_path / "agent.py").write_text(
        "from crewai import Agent\n"
        "agent = Agent(human_in_the_loop=False)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "tool-callback-enforcement/explicit-approval-disabled" in rules


def test_explicit_confirm_before_action_false_fires(tmp_path: Path) -> None:
    """`confirm_before_action=False` explicitly disables the default approval gate — fires."""
    (tmp_path / "agent.py").write_text(
        "from crewai import Agent\n"
        "agent = Agent(confirm_before_action=False)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "tool-callback-enforcement/explicit-approval-disabled" in rules


def test_explicit_auto_approve_false_silent(tmp_path: Path) -> None:
    """`auto_approve=False` explicitly KEEPS the safe default — must NOT fire (FP-bait)."""
    (tmp_path / "agent.py").write_text(
        "from crewai import Agent\n"
        "agent = Agent(auto_approve=False)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "tool-callback-enforcement/explicit-approval-disabled" for f in findings
    )


def test_explicit_approval_disabled_pragma_silences(tmp_path: Path) -> None:
    """Pragma on the file suppresses the explicit-approval-disabled finding."""
    (tmp_path / "agent.py").write_text(
        "# security: allow-tool-callback\n"
        "from crewai import Agent\n"
        "agent = Agent(auto_approve=True)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "tool-callback-enforcement/explicit-approval-disabled" for f in findings
    )


def test_tc004_destructive_op_in_following_non_tool_fn_silent(tmp_path: Path) -> None:
    # #423 FP-bait: a destructive op in a FOLLOWING non-@tool helper must NOT be attributed to
    # the @tool function above it (the fixed 30-line window used to cross the boundary).
    (tmp_path / "tools.py").write_text(
        "from langchain.tools import tool\n"
        "\n"
        "@tool\n"
        "def lookup(q: str) -> str:\n"
        "    return db.query(q)\n"
        "\n"
        "def _cleanup():\n"
        "    session.delete(old_row)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "tool-callback-enforcement/destructive-tool-no-confirm" for f in findings
    )


def test_tool_callback_factory_registered_tool_is_not_collapsed(tmp_path: Path) -> None:
    # Regression (#452 review): `iter_functions` did not emit nested defs, so an `@tool`
    # registered inside a factory collapsed into the factory's block and ANY `confirm`-ish token
    # in that factory suppressed it — a local helper, or a distant TODO comment.
    #
    # The suppressing token sits AFTER the tool on purpose. An earlier version of this fixture put
    # `def confirm(x)` above the `@tool`, where the old fixed 30-line FORWARD window never reached,
    # so the test passed on `main` too and proved nothing (#452 re-review, Medium 5). Measured with
    # the token moved below: main → 0 findings, this branch → 1.
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\nimport shutil\n"
        "def make_tools(root):\n"
        "    @tool\n    def wipe_users(p: str) -> str:\n"
        "        shutil.rmtree(p)\n        return 'done'\n"
        "    # TODO: add a confirmation step before wiring this up\n"
        "    return [wipe_users]\n",
        encoding="utf-8",
    )
    assert len(ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))) == 1


def test_tool_callback_factory_setup_code_is_not_the_tool(tmp_path: Path) -> None:
    # FP-bait for the traded-against direction of the nested-def emission (#452 re-review, High 1).
    # `iter_functions` leaves a nested `@tool` inside its enclosing block, so testing the decorator
    # against the WHOLE block promoted the factory itself to a "@tool function": ordinary setup
    # code in the factory body then fired as though the tool had done it. Measured: main → 0,
    # pre-fix branch → 1 HIGH anchored on `def make_tools`.
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\n"
        "def make_tools(db):\n"
        "    db.execute('DELETE FROM audit_log')\n"
        "    @tool\n    def greet(name: str) -> str:\n"
        "        return 'hi'\n"
        "    return [greet]\n",
        encoding="utf-8",
    )
    assert ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_tool_callback_destructive_finding_anchors_on_the_tool_not_the_factory(
    tmp_path: Path,
) -> None:
    # STILL-FIRES + anchor pin. The same whole-block decorator test also moved a REAL finding's
    # location: `out.sort()` returned the enclosing factory first, so a HIGH whose message says
    # "A `@tool`-decorated function performs…" pointed at a `def` carrying no decorator at all.
    # Nothing pinned the anchor, which is why the suite stayed green through it.
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\nimport shutil\n"
        "def make_tools(cfg):\n"
        "    @tool\n    def purge(path: str) -> str:\n"
        "        shutil.rmtree(path)\n        return 'done'\n"
        "    return [purge]\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "tool-callback-enforcement/destructive-tool-no-confirm"
    assert findings[0].location.endswith(":5")     # `def purge`, not `def make_tools` on :3


def test_tool_callback_credential_finding_anchors_on_the_tool_not_the_factory(
    tmp_path: Path,
) -> None:
    # Same pin for the EXA004 arm, which shares the `_own_header` decorator test.
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\nimport os\n"
        "def make_tools(cfg):\n"
        "    @tool\n    def get_key() -> str:\n"
        "        key = os.getenv('OPENAI_API_KEY')\n        return key\n"
        "    return [get_key]\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "tool-callback-enforcement/tool-credential-env-access"
    assert findings[0].location.endswith(":5")     # `def get_key`, not `def make_tools` on :3


def test_tool_callback_backslash_continued_decorator_string_still_fires(tmp_path: Path) -> None:
    # STILL-FIRES against `_own_header`'s stop condition (#452 re-gate). `iter_functions` blanks
    # TRIPLE-quoted strings, but a backslash-continued single-quoted string spans physical lines
    # and survives, so a decorator argument whose continuation line begins `def ` truncated the
    # header before the real `@tool` — and a destructive tool went completely undetected, with
    # no crash and a green suite. Measured 1 -> 0 -> 1.
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\nimport shutil\n"
        "@audit(note='see \\\n"
        "def not_really: this is inside a string')\n"
        "@tool\n"
        "def purge(p: str) -> str:\n"
        "    shutil.rmtree(p)\n"
        "    return 'done'\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "tool-callback-enforcement/destructive-tool-no-confirm"


def test_tool_callback_comment_ending_in_backslash_is_not_a_continuation(tmp_path: Path) -> None:
    # FP-BAIT for the continuation skip (#452 re-gate round 2). A backslash inside a trailing `#`
    # comment is NOT a line continuation in Python. Treating it as one skipped the real `def`,
    # so `_own_header` ran on and swallowed the whole block — re-opening the exact factory false
    # positive the helper exists to prevent, through a comment rather than a string. The
    # destructive op here belongs to the FACTORY, not to the benign nested tool.
    # Measured: 0 (before the skip) -> 1 (with the naive skip) -> 0 (comment-aware).
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\n"
        "@register  # TODO wire up \\\n"
        "def make_tools(db):\n"
        "    db.execute('DELETE FROM audit_log')\n"
        "    @tool\n    def greet(n: str) -> str:\n        return 'hi'\n"
        "    return [greet]\n",
        encoding="utf-8",
    )
    assert ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_tool_callback_comment_backslash_keeps_the_anchor_on_the_tool(tmp_path: Path) -> None:
    # The same trigger, in the direction where a finding is CORRECT: the destructive op is in the
    # nested tool, so it must fire and anchor on the tool rather than the factory. The naive
    # continuation skip moved this anchor from the tool to `def make_tools`.
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\nimport shutil\n"
        "@register  # wire this up later \\\n"
        "def make_tools(cfg):\n"
        "    @tool\n"
        "    def do_it(p: str) -> str:\n"
        "        shutil.rmtree(p)\n"
        "        return 'x'\n"
        "    return [do_it]\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":6")     # `def do_it`, not `def make_tools` on :4


def test_tool_callback_hash_inside_a_decorator_string_is_not_a_comment(tmp_path: Path) -> None:
    # The traded-against direction of using a comment-aware strip: a `#` inside a decorator's
    # STRING argument must not be treated as a comment. If it were, the trailing backslash of a
    # genuinely continued string would be clipped and the header would truncate again.
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\nimport shutil\n"
        "@audit(tag='issue #42: see \\\n"
        "def not_really: still inside the string')\n"
        "@tool\n"
        "def purge(p: str) -> str:\n"
        "    shutil.rmtree(p)\n"
        "    return 'done'\n",
        encoding="utf-8",
    )
    assert len(ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))) == 1


def test_tool_callback_ordinary_backslash_wrapped_decorator_still_fires(tmp_path: Path) -> None:
    # The traded-against direction of that skip: an ordinary backslash-wrapped decorator must
    # still reach its `def`. If the continuation skip ever swallowed the real header, the block
    # would fall back to whole-block matching and the #452 factory false positive would return.
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\nimport shutil\n"
        "@audit(a, \\\n    b)\n"
        "@tool\n"
        "def purge(p: str) -> str:\n"
        "    shutil.rmtree(p)\n"
        "    return 'done'\n",
        encoding="utf-8",
    )
    assert len(ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))) == 1


@pytest.mark.parametrize(("label", "decorator_stack"), [
    # Round 1: a backslash inside a `#` COMMENT is not a line continuation. Reading it as one
    # skipped the block's own `def`, so the header swallowed the nested `@tool` and the factory
    # was promoted.
    ("comment_backslash", "@register  # wire this up later \\\n"),
    # Round 2: the line that CLOSES a backslash-continued string leaves odd quote parity, so the
    # real trailing comment's backslash was read as a continuation. Same promotion, different door.
    # This one survived the round-2 fix and was still live at `eccc4c17`.
    ("string_closing_line", "@register(note='a \\\nb')  # todo \\\n"),
    # Round 4: a decorator whose ARGUMENTS span lines. The indentation early-break truncated the
    # header before the `@tool`.
    ("multiline_decorator_args", "@retry(\n    attempts=3,\n)\n"),
])
def test_tool_callback_factory_is_not_promoted_by_its_decorator(
    tmp_path: Path, label: str, decorator_stack: str
) -> None:
    """FP-BAIT: none of these decorator stacks may promote the FACTORY to a `@tool` function.

    The destructive op is in the factory body and the nested tool is benign, so the correct answer
    is zero findings. Each stack is a shape that produced a real false positive in an earlier round
    of #452 (measured 0 -> 1 -> 0 in every case).
    """
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\n"
        + decorator_stack
        + "def make_tools(db):\n"
        "    db.execute('DELETE FROM audit_log')\n"
        "    @tool\n    def greet(n: str) -> str:\n        return 'hi'\n"
        "    return [greet]\n",
        encoding="utf-8",
    )
    assert ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path)) == []


@pytest.mark.parametrize(("label", "decorator_stack"), [
    ("comment_backslash", "@register  # wire this up later \\\n"),
    ("string_closing_line", "@register(note='a \\\nb')  # todo \\\n"),
    ("multiline_decorator_args", "@retry(\n    attempts=3,\n)\n"),
    # A `#` inside a backslash-continued STRING is not a comment. Clipping there lost the real
    # continuation and truncated the header (round 2), as did getting the escape wrong (round 3).
    ("hash_inside_continued_string", "@audit(tag='issue #42: see \\\ndef fake(): pass \\\nend')\n"),
    ("escaped_quote_in_string", "@audit(n='it\\'s #x \\\ndef y')\n"),
])
def test_tool_callback_real_tool_survives_the_decorator_above_it(
    tmp_path: Path, label: str, decorator_stack: str
) -> None:
    """STILL-FIRES: the traded-against direction of every FP fix above.

    A genuinely destructive `@tool` must keep firing no matter what decorator sits above it. Each
    of these stacks silently LOST the tool in some earlier round: no crash, no warning, green
    suite. That is the failure mode these fixtures exist to make loud.
    """
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\nimport shutil\n"
        + decorator_stack
        + "@tool\n"
        "def purge(p: str) -> str:\n"
        "    shutil.rmtree(p)\n"
        "    return 'done'\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "tool-callback-enforcement/destructive-tool-no-confirm"


# Makes the module unparseable without moving a planted line: a Python 2 print statement, the way
# this shape reaches production (a py2 module, or syntax newer than agentsec's interpreter). It used
# to be a leading BOM, until #1064 taught `safe_ast_parse` to strip one, as CPython does.
_UNPARSEABLE_TAIL = 'print "loaded"\n'


# Unparseable factory modules whose factory block still CARRIES a tool-shaped line when it reaches
# `_own_header`, so header scoping is what keeps the factory from being promoted to a tool (#1066).
# Each maps to (text, the factory's def line). Since #502, `iter_functions` blanks a nested
# registration-decorated `def` out of its enclosing block, which is how the first fixture went
# vacuous; these two survive that blanking for different reasons:
#   nested_tool_class - the blanking covers `def`s only, never a decorated nested class;
#   unclosed_bracket  - the line walker tracks scope only at bracket depth 0, so after `dict(` it
#                       never sees the factory open and does not record `greet` as nested. The open
#                       bracket is also the parse failure, so it needs no `_UNPARSEABLE_TAIL`.
# `nested_tool_anchor` is the unclosed-bracket shape with the destructive op inside the tool.
_FALLBACK_FACTORIES: dict[str, tuple[str, int]] = {
    "nested_tool_class": (
        "from langchain.tools import tool\n"
        "def make_tools(db):\n"
        "    db.execute('DELETE FROM audit_log')\n"
        "    @tool\n    class Greeter:\n        pass\n"
        "    return [Greeter]\n" + _UNPARSEABLE_TAIL,
        2,
    ),
    "unclosed_bracket": (
        "from langchain.tools import tool\n"
        "LEGACY = dict(\n"
        "def make_tools(db):\n"
        "    db.execute('DELETE FROM audit_log')\n"
        "    @tool\n    def greet(n: str) -> str:\n        return 'hi'\n"
        "    return [greet]\n",
        3,
    ),
    "nested_tool_anchor": (
        "from langchain.tools import tool\n"
        "import shutil\n"
        "LEGACY = dict(\n"
        "def make_tools(root):\n"
        "    @tool\n    def purge(p: str) -> str:\n        shutil.rmtree(p)\n        return 'ok'\n"
        "    return [purge]\n",
        4,
    ),
}


@pytest.mark.parametrize("name", ["nested_tool_class", "unclosed_bracket"])
def test_tool_callback_fallback_factory_is_not_promoted(tmp_path: Path, name: str) -> None:
    """The UNPARSEABLE-module path: a factory registering a nested `@tool` is not itself a tool.

    Every test naming `_own_header` used to take the AST path, so replacing its body with
    `return block` - reinstating the factory-promotion bug - left the full suite green (#452 round
    4). The fixture written then killed that mutant, until #502's blanking of registered nested
    defs removed the `@tool` line from the factory block, and it went vacuous (bisected: killed at
    d8226dd3 and 289cd98f, survived from 659a98e6; #1066). These fixtures kill it again: the mutant
    fires `destructive-tool-no-confirm` on the factory's undecorated `def`. The load-bearing test
    below pins the property they depend on, so the next `iter_functions` change cannot void them
    silently.
    """
    text, _ = _FALLBACK_FACTORIES[name]
    (tmp_path / "a.py").write_text(text, encoding="utf-8")
    assert ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_tool_callback_fallback_nested_tool_anchors_on_the_tool(tmp_path: Path) -> None:
    # Traded-against direction for the factory fixtures: the nested tool's own destructive op still
    # fires, once, on the tool's `def` (line 6). The `_own_header` mutant also promotes the factory,
    # giving a second HIGH at line 4 (measured, #1066).
    text, _ = _FALLBACK_FACTORIES["nested_tool_anchor"]
    (tmp_path / "a.py").write_text(text, encoding="utf-8")
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "tool-callback-enforcement/destructive-tool-no-confirm"
    assert findings[0].location.endswith(":6")


def test_tool_callback_fallback_real_tool_still_fires(tmp_path: Path) -> None:
    # Traded-against direction on the same path: a multi-line decorator above a real destructive
    # tool must not lose it. Measured 1 -> 0 -> 1 (#452 round 4).
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\n"
        "@retry(\n    attempts=3,\n)\n"
        "@tool\n"
        "def delete_user(uid: str) -> str:\n"
        "    conn.execute('DELETE FROM users')\n"
        "    return 'ok'\n" + _UNPARSEABLE_TAIL,
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "tool-callback-enforcement/destructive-tool-no-confirm"


def test_tool_callback_fallback_path_is_actually_reached(tmp_path: Path) -> None:
    # Guards the two tests above against becoming vacuous the way their predecessors did: if the
    # fixture ever starts parsing, they silently move to the AST path and stop testing
    # `_own_header` at all. Assert the precondition directly. This test is how #1064 (a leading
    # BOM now parses) was caught moving the old BOM fixture onto the AST path.
    from agentsec.guards.tool_callback_enforcement import _tool_decorated_defs
    assert _tool_decorated_defs("import os\n@tool\ndef f(): pass\n" + _UNPARSEABLE_TAIL) is None
    assert _tool_decorated_defs("import os\n@tool\ndef f(): pass\n") is not None


@pytest.mark.parametrize("name", sorted(_FALLBACK_FACTORIES))
def test_tool_callback_fallback_fixture_makes_own_header_load_bearing(name: str) -> None:
    # Reaching the fallback is not enough: the first factory fixture kept reaching it after #502
    # and still stopped testing `_own_header`, because the factory block no longer held a `@tool`
    # line for the helper to scope out (#1066). Pin, on the SAME text, the property the
    # `return block` mutant needs. If an `iter_functions` change fails this, pick a new fixture;
    # do not delete the check.
    from agentsec.guards.base import iter_functions
    from agentsec.guards.tool_callback_enforcement import (
        _TOOL_DECORATOR,
        _own_header,
        _tool_decorated_defs,
    )
    text, factory_line = _FALLBACK_FACTORIES[name]
    assert _tool_decorated_defs(text) is None
    block = dict(iter_functions(text))[factory_line]
    assert _TOOL_DECORATOR.search(block)
    assert not _TOOL_DECORATOR.search(_own_header(block))


def test_tool_callback_factory_credential_setup_is_not_the_tool(tmp_path: Path) -> None:
    # FP-bait for the EXA004 arm: a credential read and returned by the FACTORY is not the tool
    # leaking it. Same class as `..._factory_setup_code_is_not_the_tool` above.
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\nimport os\n"
        "def make_tools(cfg):\n"
        "    key = os.getenv('OPENAI_API_KEY')\n"
        "    @tool\n    def greet(name: str) -> str:\n"
        "        return 'hi'\n"
        "    return key\n",
        encoding="utf-8",
    )
    assert ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_tool_callback_real_confirmation_inside_the_tool_still_silent(tmp_path: Path) -> None:
    # FP-bait: a confirmation gate INSIDE the tool must still suppress it.
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\nimport shutil\n"
        "def make_tools(root):\n"
        "    @tool\n    def wipe_users(p: str, confirmed: bool = False) -> str:\n"
        "        if not confirmed:\n            return 'Pass confirmed=True'\n"
        "        shutil.rmtree(p)\n"
        "    return [wipe_users]\n",
        encoding="utf-8",
    )
    assert ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_explicit_approval_disabled_silent_ci_config_no_agent_context(tmp_path: Path) -> None:
    """FP regression (#451 review): `auto_approve=True` in a CI/ops config with NO agent-framework
    signal in the file must stay silent — a generic kwarg, not a disabled agent approval gate."""
    (tmp_path / "ci_config.py").write_text(
        "# CI pipeline auto-merge config — nothing to do with LLM agents\n"
        "PIPELINE = dict(auto_approve=True, notify='slack')\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "tool-callback-enforcement/explicit-approval-disabled" for f in findings
    )


def test_explicit_approval_disabled_silent_ops_flag_no_agent_context(tmp_path: Path) -> None:
    """A review-workflow `human_in_the_loop=False` with no agent context is not this finding."""
    (tmp_path / "review.py").write_text(
        "def configure_review():\n"
        "    return {'human_in_the_loop': False}  # dict form: not even the kwarg shape\n"
        "settings = build(human_in_the_loop=False)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "tool-callback-enforcement/explicit-approval-disabled" for f in findings
    )


def test_explicit_approval_disabled_fires_agent_executor_import(tmp_path: Path) -> None:
    """The agent signal can be an import at the top of the file, lines away from the kwarg — a
    multi-line `AgentExecutor(...)` still fires (file-level gate, not same-line)."""
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "executor = AgentExecutor(\n"
        "    agent=agent,\n"
        "    tools=tools,\n"
        "    human_in_the_loop=False,\n"
        ")\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert "tool-callback-enforcement/explicit-approval-disabled" in {f.rule for f in findings}


def test_explicit_approval_disabled_silent_generic_agent_class(tmp_path: Path) -> None:
    """Over-broad FP-bait (#454 review): a plain `class Agent` business object (a sales/CRM record,
    not an LLM agent) with `auto_approve=True` and no framework signal must stay silent."""
    (tmp_path / "records.py").write_text(
        "class Agent:\n"
        "    '''A sales agent record.'''\n"
        "rep = Agent(auto_approve=True)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "tool-callback-enforcement/explicit-approval-disabled" for f in findings
    )


def test_explicit_approval_disabled_fires_autogen_compound_name_via_import(tmp_path: Path) -> None:
    """Too-narrow regression (#454 review): compound framework class names (AutoGen's
    `ConversableAgent`, Semantic Kernel's `ChatCompletionAgent`) don't match a `\\bAgent(` boundary,
    so the gate keys off the name being imported FROM the framework, not the constructor spelling."""
    (tmp_path / "agent.py").write_text(
        "from autogen import ConversableAgent\n"
        "agent = ConversableAgent(name='a', human_in_the_loop=False)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert "tool-callback-enforcement/explicit-approval-disabled" in {f.rule for f in findings}


def test_explicit_approval_disabled_gated_file_still_fires_far_from_import(tmp_path: Path) -> None:
    """Critical regression (#454 review): the file-level gate must inspect the WHOLE file. With the
    old windowed `.search()`+file-`continue`, a disable-kwarg whose only agent signal was a framework
    import far above (outside the 400-char window) went unflagged (zero findings). The AST detector
    resolves the import for the whole module, so distance from the import is irrelevant."""
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        + "# filler\n" * 90
        + "executor = AgentExecutor(agent=a, tools=t, human_in_the_loop=False)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert "tool-callback-enforcement/explicit-approval-disabled" in {f.rule for f in findings}


def test_explicit_approval_disabled_silent_framework_only_in_comment(tmp_path: Path) -> None:
    """FP regression (#454 review): a framework name mentioned only in a comment or docstring must NOT
    satisfy the gate — the search runs on code with strings + comments blanked."""
    (tmp_path / "review_bot.py").write_text(
        "# migration note: we evaluated langchain and crewai before rolling our own\n"
        '"""This module also references autogen in prose, not in code."""\n'
        "settings = dict(human_in_the_loop=False)  # a PR-review-bot flag, not an LLM agent\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "tool-callback-enforcement/explicit-approval-disabled" for f in findings
    )


def test_explicit_approval_disabled_fires_openai_agents_sdk(tmp_path: Path) -> None:
    """The gate covers the OpenAI Agents SDK (`from agents import ...`), not only LangChain (#454)."""
    (tmp_path / "oa.py").write_text(
        "from agents import Agent\nassistant = Agent(auto_approve=True)\n", encoding="utf-8"
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert "tool-callback-enforcement/explicit-approval-disabled" in {f.rule for f in findings}


def test_explicit_approval_disabled_fires_deepagents(tmp_path: Path) -> None:
    """The gate covers `deepagents`, langchain-ai's own deep-agent harness (#454 re-gate F1).

    THE DISCRIMINATING CASE for the third-round widening: this fires at the tip and is silent at
    the parent, because `deepagents` shares no name prefix with any covered root and so was never
    a candidate in either of the two prefix-filtered "forward" audits that preceded it. The FP
    control below is the same shape one character wider — `deepagents_helpers` is an in-house
    module, must stay silent, and pins that the fix widened by IDENTITY and not by prefix."""
    (tmp_path / "da.py").write_text(
        "from deepagents import create_deep_agent\nagent = create_deep_agent(auto_approve=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "inhouse.py").write_text(   # FP-bait: not the framework, must stay silent
        "from deepagents_helpers import build\nb = build(auto_approve=True)\n", encoding="utf-8"
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    approval = [f for f in findings if f.rule == "tool-callback-enforcement/explicit-approval-disabled"]
    assert [f.location for f in approval] == ["da.py:2"]


def test_explicit_approval_disabled_fires_google_adk(tmp_path: Path) -> None:
    """The gate covers Google ADK (`from google.adk import ...`) (#454)."""
    (tmp_path / "g.py").write_text(
        "from google.adk import Agent\nbot = Agent(confirm_before_action=False)\n", encoding="utf-8"
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert "tool-callback-enforcement/explicit-approval-disabled" in {f.rule for f in findings}


# The AST rewrite closes cases the earlier text/regex gate could not (#454 re-reviews).

def test_explicit_approval_disabled_silent_kwarg_only_in_string_literal(tmp_path: Path) -> None:
    """A disable-kwarg that appears only inside a string literal (a docstring code example) is not a
    real call — the AST never sees string contents, so it stays silent (round-4 Critical)."""
    (tmp_path / "agent.py").write_text(
        "from crewai import Agent\n"
        'DOC = "example of the bad pattern: Agent(auto_approve=True)"\n',
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "tool-callback-enforcement/explicit-approval-disabled" for f in findings
    )


def test_explicit_approval_disabled_silent_non_literal_value(tmp_path: Path) -> None:
    """`auto_approve=flag` (a variable, not a literal `True`) is not a proven opt-out — silent."""
    (tmp_path / "agent.py").write_text(
        "from crewai import Agent\n"
        "agent = Agent(auto_approve=flag)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "tool-callback-enforcement/explicit-approval-disabled" for f in findings
    )


def test_explicit_approval_disabled_silent_non_framework_call_in_agent_file(tmp_path: Path) -> None:
    """A `dict(auto_approve=True)` in a file that DOES import an agent framework stays silent — the
    gate is the call TARGET (dict is not a framework constructor), not the file's imports."""
    (tmp_path / "agent.py").write_text(
        "from crewai import Agent\n"
        "agent = Agent(role='helper')\n"
        "unrelated_config = dict(auto_approve=True)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "tool-callback-enforcement/explicit-approval-disabled" for f in findings
    )


def test_explicit_approval_disabled_reports_every_violation(tmp_path: Path) -> None:
    """Every disable-kwarg call is reported at its own line — a violation in one file no longer drops
    the rest, and two in one file both fire (round-4 Critical: the old regex reported one per run)."""
    (tmp_path / "a.py").write_text(
        "from crewai import Agent\nx = Agent(auto_approve=True)\n", encoding="utf-8"
    )
    (tmp_path / "b.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "y = AgentExecutor(human_in_the_loop=False)\n"
        "z = AgentExecutor(confirm_before_action=False)\n",
        encoding="utf-8",
    )
    findings = [
        f for f in ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
        if f.rule == "tool-callback-enforcement/explicit-approval-disabled"
    ]
    locs = {f.location for f in findings}
    assert {"a.py:2", "b.py:2", "b.py:3"} <= locs


# Import-resolution precision (AST-rewrite re-review, #454). The gate keys off actual import
# BINDING, not name coincidence, and matches framework module prefixes (google.adk, not all google.*).

def test_explicit_approval_disabled_silent_name_coincidence_not_import(tmp_path: Path) -> None:
    """A plain local variable that happens to be named like a framework module (`agents`) is not an
    import binding — a call on it must NOT fire, even in a file that imports an unrelated framework."""
    (tmp_path / "svc.py").write_text(
        "from crewai import Crew\n"
        "agents = get_business_agents()\n"
        "agents.bulk_update(auto_approve=True)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "tool-callback-enforcement/explicit-approval-disabled" for f in findings
    )


def test_explicit_approval_disabled_silent_sibling_google_module(tmp_path: Path) -> None:
    """`google.adk` is an agent module but its siblings are not — a `google.cloud` / `google.generativeai`
    call with a coincidental kwarg must stay silent (prefix match, not bare `google`)."""
    (tmp_path / "gc.py").write_text(
        "from google.cloud import bigquery\nc = bigquery.Client(auto_approve=True)\n", encoding="utf-8"
    )
    (tmp_path / "gg.py").write_text(
        "import google.generativeai as genai\ng = genai.GenerativeModel(auto_approve=True)\n", encoding="utf-8"
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "tool-callback-enforcement/explicit-approval-disabled" for f in findings
    )


def test_explicit_approval_disabled_silent_relative_import(tmp_path: Path) -> None:
    """`from .agents import Agent` is the caller's OWN `agents/` package (a relative import), not the
    OpenAI Agents SDK — it must not gate."""
    (tmp_path / "local.py").write_text(
        "from .agents import Agent\na = Agent(auto_approve=True)\n", encoding="utf-8"
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "tool-callback-enforcement/explicit-approval-disabled" for f in findings
    )


def test_explicit_approval_disabled_fires_aliased_and_dotted_and_classmethod(tmp_path: Path) -> None:
    """The positive edge cases all fire (rule 4 emits every match across files): `import crewai as c;
    c.Agent(...)`, plain `import crewai; crewai.Agent(...)`, and a framework classmethod
    `AgentExecutor.from_agent_and_tools(...)`."""
    (tmp_path / "a.py").write_text("import crewai as c\nx = c.Agent(auto_approve=True)\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("import crewai\ny = crewai.Agent(auto_approve=True)\n", encoding="utf-8")
    (tmp_path / "d.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "z = AgentExecutor.from_agent_and_tools(agent=a, human_in_the_loop=False)\n",
        encoding="utf-8",
    )
    locs = {
        f.location for f in ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
        if f.rule == "tool-callback-enforcement/explicit-approval-disabled"
    }
    assert {"a.py:2", "b.py:2", "d.py:2"} <= locs


def test_tool_callback_agent_gate_matches_current_framework_namespaces(tmp_path: Path) -> None:
    # Regression (#454 review): `_is_agent_module` matched only `p` or `p + "."`, so the
    # `<framework>_<suffix>` DISTRIBUTION namespace was unmatched — and that is what the current
    # release lines actually use. AutoGen 0.4+ IS `autogen_agentchat`/`autogen_core`/`autogen_ext`;
    # LangChain 0.2+ IS `langchain_core`/`langchain_community`. The gate recognised the LEGACY
    # `import autogen` package its cited test exercises and nothing else.
    for name, src in (
        ("a.py", "from autogen_agentchat.agents import AssistantAgent\n"
                 "agent = AssistantAgent(name='a', human_in_the_loop=False)\n"),
        ("b.py", "import autogen_core\n"
                 "agent = autogen_core.Agent(name='a', auto_approve=True)\n"),
        ("c.py", "from langchain_core.agents import AgentExecutor\n"
                 "ex = AgentExecutor(agent=a, tools=t, human_in_the_loop=False)\n"),
    ):
        (tmp_path / name).write_text(src, encoding="utf-8")
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len([f for f in findings if "approval" in (f.rule or "")]) == 3


def test_tool_callback_agent_gate_still_excludes_lookalikes(tmp_path: Path) -> None:
    # FP-bait: the `_` form requires the separator, so alembic's `autogenerate` does not match,
    # and a non-framework library passing a same-named kwarg is not an agent call at all.
    from agentsec.guards.tool_callback_enforcement import _is_agent_module

    assert _is_agent_module("autogenerate") is False
    assert _is_agent_module("google.cloud") is False
    assert _is_agent_module("google.generativeai") is False
    (tmp_path / "a.py").write_text(
        "import requests\nr = requests.get('http://x', auto_approve=True)\n", encoding="utf-8"
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [f for f in findings if "approval" in (f.rule or "")] == []


def test_tool_callback_agent_module_membership_is_identity_not_prefix(tmp_path: Path) -> None:
    """INVARIANT: a module is an agent-framework module IFF its top-level import name is EXACTLY
    in `_AGENT_MODULE_ROOTS`, or it is a dotted submodule of one. Never a root + arbitrary suffix.

    Regression (#454 re-review, second pass): the `<name>_<suffix>` rule was made opt-in per
    prefix, which fixed the single reported instance (`agents_directory`) and left the identical
    flaw in the six prefixes it KEPT — every in-house module named after the framework it wraps
    was a HIGH. This test pins the invariant, not a hand-maintained exclusion list.
    """
    # Imports only `_is_agent_module` — a symbol that exists in BOTH the pre- and post-fix guard —
    # so running this against the old module fails on BEHAVIOUR, not on a missing name.
    from agentsec.guards.tool_callback_enforcement import _is_agent_module

    # (a) The concrete false positives, by name. `autogen` is the standard Alembic/Django term
    # (`alembic revision --autogenerate`), and `haystack` is an ordinary English word.
    for lookalike in (
        "langchain_helpers", "autogen_migrations", "haystack_utils", "langchain_utils",
        "crewai_internal", "haystack_search", "langgraph_config", "llama_index_cache",
        "agents_directory", "agents_service", "agents_portal.models", "autogenerate",
        "semantic_kernel_utils", "smolagents_helpers", "pydantic_ai_stubs", "llama_agents_db",
        # a root embedded in, but not equal to, the module name
        "mylangchain", "langchainx", "my_langchain", "notcrewai", "google.adkx",
    ):
        assert _is_agent_module(lookalike) is False, lookalike

    # (b) The same property generatively over the known roots, spelled out literally here so this
    # test stays independent of the container's name: no root + "_" + <ordinary word> may match.
    for root in ("langchain", "langgraph", "crewai", "autogen", "haystack", "llama_index",
                 "llama_agents", "semantic_kernel", "pydantic_ai", "smolagents", "agents"):
        for suffix in ("helpers", "utils", "internal", "config", "cache", "migrations",
                       "search", "client", "wrapper", "shim", "compat", "db", "models"):
            assert _is_agent_module(f"{root}_{suffix}") is False, f"{root}_{suffix}"


def test_tool_callback_agent_module_roots_are_a_closed_enumeration() -> None:
    # Pins the invariant against the container itself: membership is identity + dotted submodule,
    # so no name assembled from a root plus an arbitrary suffix may match unless it IS a root.
    from agentsec.guards.tool_callback_enforcement import _AGENT_MODULE_ROOTS, _is_agent_module

    for root in _AGENT_MODULE_ROOTS:
        assert _is_agent_module(root) is True, root
        assert _is_agent_module(root + ".agents") is True, root
        for sep in ("_", "-", "x", "2"):
            candidate = root + sep + "zzz"
            if candidate in _AGENT_MODULE_ROOTS:
                continue
            assert _is_agent_module(candidate) is False, candidate


def test_tool_callback_in_house_framework_wrappers_stay_silent(tmp_path: Path) -> None:
    # End-to-end (not just `_is_agent_module`): ordinary first-party modules named after the
    # framework they wrap must not produce a HIGH. Each of these fired before the fix.
    for i, module in enumerate((
        "langchain_helpers", "autogen_migrations", "haystack_utils",
        "crewai_internal", "langgraph_config", "llama_index_cache",
    )):
        (tmp_path / f"m{i}.py").write_text(
            f"from {module} import Agent\na = Agent(name='a', auto_approve=True)\n",
            encoding="utf-8",
        )
    # a CRM for human estate agents, no LLM in sight
    (tmp_path / "crm.py").write_text(
        "from agents_directory import Agent\nrep = Agent(name='r', auto_approve=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "svc.py").write_text(
        "import agents_service\ns = agents_service.Agent(auto_approve=True)\n", encoding="utf-8"
    )
    assert [
        f for f in ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
        if "approval" in (f.rule or "")
    ] == []


def test_tool_callback_verified_framework_namespaces_still_fire(tmp_path: Path) -> None:
    """The other direction: every namespace in the set is a real, verified TOP-LEVEL IMPORT NAME.

    Established by reading each distribution's wheel from PyPI (distribution name != import name,
    and this environment cannot pip-install): `haystack-ai` -> `haystack`, `openai-agents` ->
    `agents`, `google-adk` -> `google.adk`, `llama-index-core` -> the `llama_index` namespace,
    `*-haystack` integrations -> `haystack_integrations`. Note `langgraph-checkpoint` /
    `langgraph-prebuilt` install INTO `langgraph` (`langgraph.checkpoint`), so there is no
    top-level `langgraph_checkpoint` to match — the dotted rule covers them.
    """
    from agentsec.guards.tool_callback_enforcement import _is_agent_module

    for real in (
        "langchain", "langchain_core", "langchain_community", "langchain_experimental",
        "langgraph", "langgraph_sdk", "langgraph.prebuilt", "langgraph.checkpoint",
        "crewai", "crewai_tools",
        "autogen", "autogen_core", "autogen_agentchat", "autogen_ext", "autogen_agentchat.agents",
        "haystack", "haystack_integrations", "haystack_integrations.components",
        "llama_index", "llama_index.core", "llama_agents",
        "semantic_kernel", "pydantic_ai", "smolagents", "agents", "google.adk", "google.adk.agents",
    ):
        assert _is_agent_module(real) is True, real

    for name, src in (
        ("a.py", "from langgraph.prebuilt import Agent\na = Agent(auto_approve=True)\n"),
        ("b.py", "from haystack_integrations.components import Agent\n"
                 "b = Agent(human_in_the_loop=False)\n"),
        ("c.py", "from langchain_experimental.autonomous_agents import Agent\n"
                 "c = Agent(confirm_before_action=False)\n"),
    ):
        (tmp_path / name).write_text(src, encoding="utf-8")
    locs = {
        f.location for f in ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
        if "approval" in (f.rule or "")
    }
    assert locs == {"a.py:2", "b.py:2", "c.py:2"}


def test_tool_callback_agent_gate_fires_on_modern_namespaces_end_to_end(tmp_path: Path) -> None:
    # The other half of the opt-in split: the distribution namespaces the fix keeps enabled must
    # still produce findings through the whole guard, not just `_is_agent_module` (#454 re-review).
    for name, src in (
        ("a.py", "import autogen_ext\na = autogen_ext.Agent(name='a', auto_approve=True)\n"),
        ("b.py", "from langchain_community.agents import AgentExecutor\n"
                 "b = AgentExecutor(human_in_the_loop=False)\n"),
        ("c.py", "from crewai_tools import Agent\nc = Agent(confirm_before_action=False)\n"),
    ):
        (tmp_path / name).write_text(src, encoding="utf-8")
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    locs = {f.location for f in findings if "approval" in (f.rule or "")}
    assert locs == {"a.py:2", "b.py:2", "c.py:2"}


def test_tool_callback_disable_value_is_truthiness_not_identity(tmp_path: Path) -> None:
    # Regression (#454 review): the `is True` / `is False` identity check matched only the bool
    # singletons, so `auto_approve=1` and `human_in_the_loop=None` — both ordinary spellings and
    # both disabling — slipped through. The inverse spellings must stay silent.
    (tmp_path / "a.py").write_text(
        "import autogen_core\na = autogen_core.Agent(name='a', auto_approve=1)\n", encoding="utf-8"
    )
    (tmp_path / "b.py").write_text(
        "import autogen_core\nb = autogen_core.Agent(name='b', human_in_the_loop=None)\n",
        encoding="utf-8",
    )
    (tmp_path / "c.py").write_text(   # FP-bait: the gate is ON in both of these
        "import autogen_core\nc = autogen_core.Agent(name='c', auto_approve=0)\n", encoding="utf-8"
    )
    (tmp_path / "d.py").write_text(
        "import autogen_core\nd = autogen_core.Agent(name='d', human_in_the_loop=True)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    hits = {f.location.split(":")[0] for f in findings if "approval" in (f.rule or "")}
    assert hits == {"a.py", "b.py"}


@pytest.mark.parametrize(
    "module",
    [
        # The #454 gate's finding: FIRST-PARTY sibling distributions that install top-level, so the
        # dotted rule never reached them, and the closed enumeration silently dropped them when it
        # replaced the open-prefix rule. Each import name below was read out of the published wheel.
        # `haystack-experimental` is deepset's own second package and ships a human-in-the-loop
        # Agent; the rest are langchain-ai's (`create_supervisor`, `create_swarm`).
        "haystack_experimental",
        "langgraph_supervisor",
        "langgraph_swarm",
        # Second gate round: the forward audit above was itself one batch, not an enumeration. A
        # full forward run over the PyPI simple index found five more first-party siblings meeting
        # the same entry criterion — `langchain_classic` most of all, since it is where LangChain
        # 1.0 moved `AgentExecutor` / `initialize_agent` / `create_react_agent`, the very constructs
        # Rule 1 is built around.
        "langchain_classic",
        "langgraph_bigtool",
        "langgraph_codeact",
        "langgraph_cua",
        "langgraph_reflection",
        # Third gate round: the two rounds above both PREFIX-FILTERED the PyPI index and both
        # called themselves forward audits. A prefix filter is a search strategy, not the entry
        # criterion, and it cannot see a first-party package that shares no prefix with a covered
        # root. `deepagents` is exactly that blind spot — langchain-ai's own deep-agent harness
        # (`deepagents-0.7.2` wheel: top-level `deepagents`, `graph.py:268 def create_deep_agent(`,
        # Repository github.com/langchain-ai/deepagents), satisfying all three clauses and invisible
        # to a `langchain-*`/`langgraph-*` sweep.
        "deepagents",
        # ...and their dotted submodules, via the same rule as the rest of the set.
        "haystack_experimental.components.agents",
        "langgraph_supervisor.supervisor",
        "langchain_classic.agents",
        "deepagents.graph",
    ],
)
def test_tool_callback_first_party_sibling_distributions_are_agent_modules(module: str) -> None:
    from agentsec.guards.tool_callback_enforcement import _is_agent_module

    assert _is_agent_module(module) is True


@pytest.mark.parametrize(
    "module",
    [
        # INVARIANT PIN (deliberately NOT the traded-against test — see the test below).
        # This pins that membership stays IDENTITY, not prefix: a name built from a listed root
        # plus a suffix must never match. Adding entry `E` to an identity set flips truth on
        # exactly `{E} | {E + "." + *}`, so no `<E>_<suffix>` string here can flip when the set
        # GROWS — these params were already False before every addition and will stay False after
        # the next one. That is exactly why this file also carries the collision test below: this
        # one guards the mechanism, and cannot detect a widening's real cost.
        "langgraph_supervisor_utils",
        "haystack_experimental_x",
        "langchain_classic_utils",
        "langgraph_codeact_helpers",
        "langchain_helpers",
        "autogen_migrations",
        "haystack_utils",
        "langchain_mongodb",
        "deepagents_utils",
    ],
)
def test_tool_callback_enumeration_membership_stays_identity_not_prefix(module: str) -> None:
    from agentsec.guards.tool_callback_enforcement import _is_agent_module

    assert _is_agent_module(module) is False


@pytest.mark.parametrize(
    "module", ["langchain_classic", "langgraph_codeact", "langgraph_cua", "deepagents"]
)
def test_tool_callback_enumeration_widening_locks_its_exact_name_collision_cost(
    tmp_path: Path, module: str
) -> None:
    """THE TRADED-AGAINST DIRECTION, for real this time (#454 gate finding 3).

    Adding entry `E` to an identity set changes truth value on exactly `{E} | {E + "." + *}`.
    So the ONLY false-positive class a widening can create is the EXACT-NAME collision: a
    first-party in-house top-level module named exactly `E`, imported absolutely, whose own
    constructor happens to take an agent-shaped disable kwarg. Every entry added to
    `_AGENT_MODULE_ROOTS` buys that surface, and this test measures it instead of asserting it
    away — each case below is a KNOWN, ACCEPTED false positive, pinned so the cost cannot drift
    silently and so a future narrowing has to delete this test on purpose.

    Sized before accepting (GitHub code search, public code, 2026-08-03). NOTE the `filename:`
    qualifier is FUZZY — it matches `hook-langchain_classic.py` too — so the raw total is an
    upper bound and the real count comes from paging the results and keeping only paths whose
    BASENAME is exactly `<module>.py`:

        module                fuzzy total   exact basename
        langchain_classic     221           0   (all PyInstaller hooks / vendored venvs)
        langgraph_codeact       2           2
        langgraph_cua           1           1
        langgraph_bigtool       1           0
        langgraph_reflection    1           0

    ZERO of them co-occur with any of the three disable kwargs. Compare the collisions the set
    already accepts: `agents` (fuzzy 11,116) and `haystack` (fuzzy 896) — two to three orders of
    magnitude larger. The pragma is the escape hatch if a real one shows up in a corpus scan.

    `deepagents` (added in the #454 re-gate) is the largest of the sibling additions and was
    measured the same way before accepting, because "it is first-party, therefore add it" is not
    a cost argument:

        deepagents            115 (fuzzy) / 138 paged   51 exact basename

    But the exact-basename column is itself an upper bound on THIS FP class, which requires a
    TOP-LEVEL module: 50 of the 51 sit nested (`src/agent/backends/deepagents.py`,
    `libs/bog_agents/deepagents.py`), where the import is `…backends.deepagents` and the root is
    the parent package, not `deepagents`. Exactly **1** is a repo-root module
    (`chetanreddyv/wreckcheck/deepagents.py`), and it is an adapter for the real framework, not an
    in-house coincidence. Disable-kwarg co-occurrence over the whole fuzzy set: **0** — the one
    `human_in_the_loop` hit is `demo_deepagents.py`, a fuzzy match demoing the actual framework,
    i.e. a true-positive shape rather than a collision. So the accepted cost of this entry is one
    root-level file, none of which disables approval.
    """
    (tmp_path / f"{module}.py").write_text(   # an in-house module, nothing to do with LangChain
        "class Migrator:\n"
        "    def __init__(self, auto_approve: bool = False) -> None:\n"
        "        self.auto_approve = auto_approve\n",
        encoding="utf-8",
    )
    (tmp_path / "run.py").write_text(
        f"from {module} import Migrator\n\nm = Migrator(auto_approve=True)\n", encoding="utf-8"
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    approval = [f for f in findings if "approval" in (f.rule or "")]
    assert [f.location for f in approval] == ["run.py:3"]
    assert approval[0].severity == "high"


# ---------------------------------------------------------------------------
# Rule 5: trust-config-wildcard-bypass (config-file variant of Rule 4)
# ---------------------------------------------------------------------------

def test_trust_config_wildcard_trusted_commands_fires(tmp_path: Path) -> None:
    """HIGH: trustedCommands set to a wildcard is the AWS Kiro / AWS-2025-019 pattern."""
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "settings.json").write_text(
        '{\n  "kiroAgent.trustedCommands": ["*"]\n}\n', encoding="utf-8"
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "tool-callback-enforcement/trust-config-wildcard-bypass" for f in findings)
    hit = next(f for f in findings
               if f.rule == "tool-callback-enforcement/trust-config-wildcard-bypass")
    assert hit.severity == "high"


def test_trust_config_auto_approve_true_fires(tmp_path: Path) -> None:
    """HIGH: autoApprove: true removes the confirmation gate."""
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "settings.json").write_text(
        '{\n  "autoApprove": true\n}\n', encoding="utf-8"
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "tool-callback-enforcement/trust-config-wildcard-bypass" for f in findings)


def test_trust_config_require_approval_false_fires(tmp_path: Path) -> None:
    """HIGH: requireApproval explicitly set to false is the dangerous direction."""
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        '{\n  "requireApproval": false\n}\n', encoding="utf-8"
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "tool-callback-enforcement/trust-config-wildcard-bypass" for f in findings)


def test_trust_config_require_approval_true_is_safe(tmp_path: Path) -> None:
    """FP-bait: requireApproval: true is safety-hardening (the SAFE direction) -- must not fire."""
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        '{\n  "requireApproval": true\n}\n', encoding="utf-8"
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "tool-callback-enforcement/trust-config-wildcard-bypass" for f in findings)


def test_trust_config_skip_confirmation_false_is_safe(tmp_path: Path) -> None:
    """FP-bait: skipConfirmation: false means confirmation is NOT skipped -- must not fire."""
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "settings.json").write_text(
        '{\n  "skipConfirmation": false\n}\n', encoding="utf-8"
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "tool-callback-enforcement/trust-config-wildcard-bypass" for f in findings)


def test_trust_config_no_settings_file_is_safe(tmp_path: Path) -> None:
    """FP-bait/baseline: no IDE settings file at all -- nothing to fire on."""
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "tool-callback-enforcement/trust-config-wildcard-bypass" for f in findings)


def test_trust_config_pragma_suppresses(tmp_path: Path) -> None:
    """The inline pragma silences the trust-config check too."""
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "settings.json").write_text(
        '{\n  "autoApprove": true\n}\n// security: allow-tool-callback\n', encoding="utf-8"
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "tool-callback-enforcement/trust-config-wildcard-bypass" for f in findings)


def test_tool_callback_factory_registered_tool_reports_once_without_a_confirm_token(
    tmp_path: Path,
) -> None:
    # #502 lock, and a correction to that issue's reading of the sibling test above. #502 claims
    # `test_tool_callback_factory_registered_tool_is_not_collapsed` asserts == 1 only because its
    # fixture carries a `# TODO: add a confirmation step` token that suppresses the factory's copy.
    # Measured both ways: 1 finding with the token, 1 without. This guard decides "is this block a
    # tool?" from the AST's per-function `decorator_list` (`_tool_decorated_defs`), so the
    # undecorated factory is never a candidate and no token is doing that work.
    #
    # The token-suppresses-the-duplicate mechanism the issue describes is real, but it belongs to
    # `upload-no-size-limit` — see `test_upload_no_size_limit_factory_registered_route_reports_once`.
    (tmp_path / "a.py").write_text(
        "from langchain.tools import tool\nimport shutil\n"
        "def make_tools(root):\n"
        "    @tool\n    def wipe_users(p: str) -> str:\n"
        "        shutil.rmtree(p)\n        return 'done'\n"
        "    return [wipe_users]\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":5")     # the tool, not the factory at :3


def test_tool_callback_enforcement_parses_only_when_anchor_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """issue #771: iter_functions runs only when a real anchor is present.

    This guard called iter_functions THREE times per file (one per AST-scanning check). Counter
    installed on THIS guard's own module (the guard does ``from .base import iter_functions`` --
    patching base would measure nothing; review-doctrine Rule 3). The anchor-present half proves
    the spy is wired to the parse path.
    """
    from agentsec.guards import tool_callback_enforcement as mod

    calls = 0
    real = mod.iter_functions

    def spy(
        text: str, *, include_closures: bool = True, filename: str | Path = "<unknown>"
    ) -> list[tuple[int, str]]:
        nonlocal calls
        calls += 1
        return real(text, include_closures=include_closures, filename=filename)

    monkeypatch.setattr(mod, "iter_functions", spy)

    (tmp_path / "noanchor.py").write_text(
        "".join(f"def f{i}(x):\n    return x + {i}\n\n\n" for i in range(15)),
        encoding="utf-8",
    )
    profile = _llm_prof(tmp_path)
    assert ToolCallbackEnforcementGuard().run(tmp_path, profile) == []
    assert calls == 0

    # A destructive @tool triggers the _check_destructive_tool_no_confirm parse path.
    (tmp_path / "tools.py").write_text(
        "import os\n"
        "from langchain.tools import tool\n"
        "@tool\n"
        "def del_it(path):\n"
        "    os.remove(path)\n",
        encoding="utf-8",
    )
    ToolCallbackEnforcementGuard().run(tmp_path, profile)
    assert calls >= 1


# ---------------------------------------------------------------------------
# #425: one finding per call / per @tool, not one per repo
# ---------------------------------------------------------------------------

_TC001 = "tool-callback-enforcement/no-interrupt-before"
_TC004 = "tool-callback-enforcement/destructive-tool-no-confirm"
_CRED = "tool-callback-enforcement/tool-credential-env-access"
# Wider than the 600-char window each AgentExecutor match scans for a confirm param, so a
# guarded call placed after it cannot vouch for the unguarded call above it.
_FAR = ("# " + "-" * 70 + "\n") * 10
_TOOL_HDR = "import os\nimport shutil\nfrom langchain.tools import tool\n"


def _delete_tool(name: str) -> str:
    return (
        f"\n\n@tool\ndef {name}(record_id: str) -> str:\n"
        '    db.query(f"DELETE FROM records WHERE id={record_id}")\n'
        '    return "deleted"\n'
    )


def _leak_tool(name: str) -> str:
    return f"\n\n@tool\ndef {name}() -> str:\n    return os.getenv('OPENAI_API_KEY')\n"


def test_tc001_reports_every_unguarded_executor_call(tmp_path: Path) -> None:
    # Regression for #425: _check_no_interrupt_before returned its first unguarded call from
    # inside the all-files loop, so N unguarded executors reported 1. Each call reports,
    # anchored at its own `AgentExecutor(` line (a black-formatted call at its opening line).
    (tmp_path / "agent_a.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "ex1 = AgentExecutor(agent=a, tools=tools, verbose=True)\n"
        "ex2 = AgentExecutor(\n"
        "    agent=a,\n"
        "    tools=tools,\n"
        ")\n",
        encoding="utf-8",
    )
    (tmp_path / "agent_b.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "ex3 = AgentExecutor(agent=a, tools=tools)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert sorted(f.location for f in findings if f.rule == _TC001) == [
        "agent_a.py:2", "agent_a.py:3", "agent_b.py:2",
    ]


def test_tc001_guarded_executor_after_a_hit_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the #425 widening: calls after the first hit used to be unreachable. A call
    # with `callbacks=`, after an unguarded one in the same file, must not become a finding.
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "ex1 = AgentExecutor(agent=a, tools=tools)\n"
        + _FAR
        + "ex2 = AgentExecutor(agent=a, tools=tools, callbacks=[approval_handler])\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [(f.rule, f.location) for f in findings] == [(_TC001, "agent.py:2")]


def test_tc004_reports_every_destructive_tool(tmp_path: Path) -> None:
    # Regression for #425: _check_destructive_tool_no_confirm returned its first offending tool
    # from inside the all-files loop. Two tools in one file plus one in another: three findings,
    # each at its own `def` line.
    (tmp_path / "tools_a.py").write_text(
        _TOOL_HDR + _delete_tool("delete_record") + _delete_tool("delete_user"), encoding="utf-8"
    )
    (tmp_path / "tools_b.py").write_text(_TOOL_HDR + _delete_tool("delete_order"), encoding="utf-8")
    findings = [
        f for f in ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path)) if f.rule == _TC004
    ]
    assert len(findings) == 3
    assert {f.location for f in findings} == {"tools_a.py:7", "tools_a.py:13", "tools_b.py:7"}


def test_tc004_safe_tools_after_a_hit_stay_silent(tmp_path: Path) -> None:
    # FP-bait for the #425 widening: tools after the first hit used to be unreachable. A
    # destructive tool with a confirmation gate and a plain helper with a delete, after an
    # unconfirmed destructive tool, must not become extra findings.
    (tmp_path / "tools.py").write_text(
        _TOOL_HDR
        + _delete_tool("delete_record")
        + "\n\n@tool\ndef delete_user(user_id: str, confirmed: bool = False) -> str:\n"
        "    if not confirmed:\n"
        "        return 'Pass confirmed=True to delete'\n"
        '    db.query(f"DELETE FROM users WHERE id={user_id}")\n'
        '    return "deleted"\n'
        "\n\ndef cleanup(path: str) -> None:\n"
        "    shutil.rmtree(path)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [(f.rule, f.location) for f in findings] == [(_TC004, "tools.py:7")]


def test_tool_credential_env_reports_every_leaking_tool(tmp_path: Path) -> None:
    # Regression for #425: _check_tool_credential_env returned its first leaking tool from inside
    # the all-files loop. Two tools in one file plus one in another: three findings.
    (tmp_path / "tools_a.py").write_text(
        _TOOL_HDR + _leak_tool("get_key") + _leak_tool("get_other_key"), encoding="utf-8"
    )
    (tmp_path / "tools_b.py").write_text(_TOOL_HDR + _leak_tool("get_key"), encoding="utf-8")
    findings = [
        f for f in ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path)) if f.rule == _CRED
    ]
    assert len(findings) == 3
    assert {f.location for f in findings} == {"tools_a.py:7", "tools_a.py:12", "tools_b.py:7"}


def test_tool_credential_env_one_finding_per_tool_with_two_leaks(tmp_path: Path) -> None:
    # The finding is anchored at the tool's `def` line, so a tool returning two credentials must
    # give exactly one finding, not two at the same location (#425: the `break` after the first).
    (tmp_path / "tools.py").write_text(
        _TOOL_HDR
        + "\n\n@tool\ndef get_keys() -> dict:\n"
        "    key = os.getenv('OPENAI_API_KEY')\n"
        "    token = os.environ['GITHUB_TOKEN']\n"
        "    return {'key': key, 'token': token}\n",
        encoding="utf-8",
    )
    findings = [
        f for f in ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path)) if f.rule == _CRED
    ]
    assert [f.location for f in findings] == ["tools.py:7"]


def test_tool_credential_env_consuming_tool_after_a_hit_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the #425 widening: a tool that consumes the credential in place, after a tool
    # that leaks one, must not become a second finding.
    (tmp_path / "tools.py").write_text(
        _TOOL_HDR
        + _leak_tool("get_key")
        + "\n\n@tool\ndef ask(question: str) -> str:\n"
        "    client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))\n"
        "    return client.chat(question)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [(f.rule, f.location) for f in findings] == [(_CRED, "tools.py:7")]


def test_tool_callback_per_file_pragma_still_scopes_to_its_file(tmp_path: Path) -> None:
    # The pragma is per FILE for these three rules. After #425 a pragma'd file must still
    # contribute nothing while every other file keeps contributing all of its findings.
    body = _TOOL_HDR + _delete_tool("delete_record") + _leak_tool("get_key")
    (tmp_path / "tools_a.py").write_text("# security: allow-tool-callback\n" + body, encoding="utf-8")
    (tmp_path / "tools_b.py").write_text(
        body + "\nfrom langchain.agents import AgentExecutor\nex = AgentExecutor(agent=a, tools=t)\n",
        encoding="utf-8",
    )
    findings = ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))
    assert {f.location.split(":")[0] for f in findings} == {"tools_b.py"}
    assert sorted(f.rule for f in findings) == sorted([_TC001, _TC004, _CRED])


# ── #613: a triple-quoted argument beside the `**kwargs` unpack ─────────────────────────────────
# The call splitter read `'''` as three separate quotes, so an apostrophe inside one left the split
# at None, the `**config` unpack went unseen, and a config that DOES carry `callbacks` fired.


def _tc001_kwargs_beside_triple_quoted_name(tmp_path: Path, config_key: str) -> list[Finding]:
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "\n"
        "\n"
        "def build_agent(handler):\n"
        f"    config = {{'agent': agent, 'tools': tools, '{config_key}': [handler]}}\n"
        "    return AgentExecutor(name='''the team's agent''', **config)\n",
        encoding="utf-8",
    )
    return ToolCallbackEnforcementGuard().run(tmp_path, _llm_prof(tmp_path))


def test_tc001_kwargs_unpack_beside_a_triple_quoted_argument_resolves_callbacks(tmp_path: Path) -> None:
    findings = _tc001_kwargs_beside_triple_quoted_name(tmp_path, "callbacks")
    assert not any(f.rule == "tool-callback-enforcement/no-interrupt-before" for f in findings)


def test_tc001_kwargs_unpack_beside_a_triple_quoted_argument_still_fires_without_confirm(
    tmp_path: Path,
) -> None:
    """The direction traded against (Rule 1): the unpack is now seen, so the dict is resolved, and a
    dict with no confirm-signal key must still fire."""
    findings = _tc001_kwargs_beside_triple_quoted_name(tmp_path, "middleware")
    assert any(f.rule == "tool-callback-enforcement/no-interrupt-before" for f in findings)
