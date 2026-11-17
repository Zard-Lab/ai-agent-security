from __future__ import annotations

import pytest

from agentsec.guards.agent_tool_audit_log import AgentToolAuditLogGuard
from tests.guards._common import *  # noqa: F401,F403


def test_agent_tool_audit_log_no_logging_fires(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent(\'openai:gpt-4o\')\n"
        "@agent.tool\n"
        "def search_web(query: str) -> str:\n"
        "    results = [\'r1\', \'r2\']\n"
        "    return str(results)\n",
        encoding="utf-8",
    )
    findings = AgentToolAuditLogGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "agent-tool-audit-log/missing-tool-log"
    assert findings[0].severity == "medium"

def test_agent_tool_audit_log_with_logger_silent(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "import logging\n"
        "from pydantic_ai import Agent\n"
        "logger = logging.getLogger(__name__)\n"
        "agent = Agent(\'openai:gpt-4o\')\n"
        "@agent.tool\n"
        "def search_web(query: str) -> str:\n"
        "    logger.info(\'tool:search_web query=%s\', query)\n"
        "    return \'result\'\n",
        encoding="utf-8",
    )
    assert AgentToolAuditLogGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_tool_audit_log_logging_module_silent(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "import logging\n"
        "from pydantic_ai import Agent\n"
        "agent = Agent(\'openai:gpt-4o\')\n"
        "@agent.tool\n"
        "def fetch_data(url: str) -> str:\n"
        "    logging.info(\'tool:fetch_data url=%s\', url)\n"
        "    return \'data\'\n",
        encoding="utf-8",
    )
    assert AgentToolAuditLogGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_tool_audit_log_no_tool_silent(tmp_path: Path) -> None:
    (tmp_path / "utils.py").write_text(
        "def process(data: str) -> str:\n"
        "    return data.upper()\n",
        encoding="utf-8",
    )
    assert AgentToolAuditLogGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_tool_audit_log_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "# security: allow-unlogged-tool\n"
        "from pydantic_ai import Agent\n"
        "agent = Agent(\'openai:gpt-4o\')\n"
        "@agent.tool\n"
        "def search(query: str) -> str:\n"
        "    return \'result\'\n",
        encoding="utf-8",
    )
    assert AgentToolAuditLogGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_tool_audit_log_multiple_tools_partial(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "import logging\n"
        "from pydantic_ai import Agent\n"
        "logger = logging.getLogger(__name__)\n"
        "agent = Agent(\'openai:gpt-4o\')\n"
        "@agent.tool\n"
        "def logged_tool(x: str) -> str:\n"
        "    logger.info(\'invoked\')\n"
        "    return x\n"
        "@agent.tool\n"
        "def unlogged_tool(y: str) -> str:\n"
        "    return y\n",
        encoding="utf-8",
    )
    findings = AgentToolAuditLogGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1

def test_agent_tool_audit_log_test_path_silent(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent(\'openai:gpt-4o\')\n"
        "@agent.tool\n"
        "def mock_search(q: str) -> str:\n"
        "    return \'mock\'\n",
        encoding="utf-8",
    )
    assert AgentToolAuditLogGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_tool_audit_log_not_applicable_without_llm(tmp_path: Path) -> None:
    assert AgentToolAuditLogGuard().applies(mkprofile(tmp_path, features={"python"})) is False

def test_agent_tool_audit_log_otel_trace_tool_decorator_silent(tmp_path: Path) -> None:
    # @trace_tool stacked on @agent.tool is a valid OTel audit signal — should not fire.
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('openai:gpt-4o')\n"
        "@agent.tool\n"
        "@trace_tool(name='search_web', attributes={'kind': 'tool'})\n"
        "def search_web(query: str) -> str:\n"
        "    return 'result'\n",
        encoding="utf-8",
    )
    assert AgentToolAuditLogGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_tool_audit_log_otel_tracer_call_silent(tmp_path: Path) -> None:
    # tracer.start_as_current_span() is a valid OTel audit signal — should not fire.
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('openai:gpt-4o')\n"
        "@agent.tool\n"
        "def fetch_data(url: str) -> str:\n"
        "    with tracer.start_as_current_span('fetch_data') as span:\n"
        "        span.set_attribute('url', url)\n"
        "        return 'data'\n",
        encoding="utf-8",
    )
    assert AgentToolAuditLogGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_tool_audit_log_docstring_example_not_a_trigger(tmp_path: Path) -> None:
    # @agent.tool inside a docstring Example: block must not trigger the guard.
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "def register_tools(agent: Agent) -> None:\n"
        '    """\n'
        "    Register all tools on the agent.\n"
        "\n"
        "    Example::\n"
        "\n"
        "        @agent.tool\n"
        "        def my_tool(ctx) -> str:\n"
        "            return 'result'\n"
        '    """\n'
        "    pass\n",
        encoding="utf-8",
    )
    assert AgentToolAuditLogGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_tool_audit_log_mixed_quote_desync_is_known_limitation(tmp_path: Path) -> None:
    # KNOWN LIMITATION (documented in wiki/guards/agent-tool-audit-log.md): the docstring
    # skip is a per-line `count % 2` toggle tracking `\"\"\"` and `'''` independently. An
    # UNbalanced `'''` marker shown inside a `\"\"\"` docstring leaves the single-quote state
    # stuck "open", so a genuinely-unlogged @agent.tool AFTER the docstring is over-skipped.
    # This is a false NEGATIVE (miss), never a false positive — the heuristic errs toward not
    # firing. Pinned here so any future tokenizer hardening is an intentional, visible change.
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "def register(agent: Agent) -> None:\n"
        '    """Register tools.\n'
        "\n"
        "    Example with an inline triple-single-quote marker:\n"
        "        snippet = '''\n"
        '    """\n'
        "\n"
        "    @agent.tool\n"
        "    def real_unlogged_tool(ctx) -> str:\n"
        "        return ctx.deps.do_work()\n",
        encoding="utf-8",
    )
    # Current behavior: the real unlogged tool is NOT flagged (accepted over-skip).
    assert AgentToolAuditLogGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_agent_tool_audit_log_silent_when_signal_outside_old_fixed_window(tmp_path: Path) -> None:
    # the audit signal sits well past the old 30-line look-ahead but is still inside
    # the SAME function body. Before this fix, the padding below would have pushed the log call
    # out of the window and made the guard false-fire on genuinely audited code.
    padding = "\n".join(f"    step_{n} = n + 1" for n in range(35))
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('openai:gpt-4o')\n"
        "@agent.tool\n"
        "def search_web(query: str) -> str:\n"
        f"{padding}\n"
        "    logger.info('tool:search_web query=%s', query)\n"
        "    return 'result'\n",
        encoding="utf-8",
    )
    assert AgentToolAuditLogGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_agent_tool_audit_log_still_fires_when_signal_is_in_a_decorator_stacked_above(
    tmp_path: Path,
) -> None:
    # Directionality regression guard: `@logger.wraps` textually contains `logger.` (the audit
    # signal pattern) but sits ABOVE `@agent.tool`, before the anchor line — the widened
    # look-ahead must start at `@agent.tool` itself (the anchor), not at the enclosing span's
    # true start (which would also swallow decorators stacked above it).
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "@logger.wraps\n"
        "@agent.tool\n"
        "def search_web(query: str) -> str:\n"
        "    results = ['r1', 'r2']\n"
        "    return str(results)\n",
        encoding="utf-8",
    )
    findings = AgentToolAuditLogGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "agent-tool-audit-log/missing-tool-log"



def test_agent_tool_audit_log_parses_only_when_anchor_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """issue #771: iter_functions runs only when an @agent.tool anchor is present.

    Counter installed on THIS guard's own module (the guard does ``from .base import
    iter_functions`` -- patching base would measure nothing; review-doctrine Rule 3). The
    anchor-present half proves the spy is wired to the parse path.
    """
    from agentsec.guards import agent_tool_audit_log as mod

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
    assert AgentToolAuditLogGuard().run(tmp_path, profile) == []
    assert calls == 0

    (tmp_path / "tools.py").write_text(
        "@agent.tool\n"
        "def do_thing(ctx, arg):\n"
        "    return arg\n",
        encoding="utf-8",
    )
    AgentToolAuditLogGuard().run(tmp_path, profile)
    assert calls >= 1
