from __future__ import annotations

from agentsec.guards.agent_tool_overpermission import AgentToolOverpermissionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_agent_tool_overpermission_flags_dangerous_tool_import(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(_DANGEROUS_IMPORT_CODE, encoding="utf-8")
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/dangerous-tool-imported" in rules

def test_agent_tool_overpermission_flags_allow_dangerous_requests(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(_ALLOW_DANGEROUS_CODE, encoding="utf-8")
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/allow-dangerous-requests" in rules

def test_agent_tool_overpermission_flags_subprocess_in_agent_tool(tmp_path: Path) -> None:
    (tmp_path / "agent_tools.py").write_text(_SUBPROCESS_IN_TOOL_CODE, encoding="utf-8")
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/subprocess-in-agent-tool" in rules

def test_agent_tool_overpermission_all_three_in_one_file(tmp_path: Path) -> None:
    (tmp_path / "agent_tools.py").write_text(
        "import subprocess\n"
        "from langchain.tools import ShellTool\n"
        "from langchain_community.agent_toolkits import RequestsToolkit\n"
        "from langchain_community.utilities.requests import TextRequestsWrapper\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "shell_tool = ShellTool()\n"
        "toolkit = RequestsToolkit("
        "    requests_wrapper=TextRequestsWrapper(headers={}),\n"
        "    allow_dangerous_requests=True,\n"
        ")\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "@agent.tool\n"
        "async def run_cmd(ctx, cmd: str) -> str:\n"
        '    result = subprocess.run(["bash", "-c", cmd], capture_output=True)\n'
        "    return result.stdout\n",
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert rules == {
        "agent-tool-overpermission/dangerous-tool-imported",
        "agent-tool-overpermission/allow-dangerous-requests",
        "agent-tool-overpermission/subprocess-in-agent-tool",
    }

def test_agent_tool_overpermission_silent_for_safe_custom_tool(tmp_path: Path) -> None:
    # A custom tool that uses a fixed command allowlist — no dangerous imports.
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "_ALLOWED = {'ls', 'pwd', 'whoami'}\n"
        "\n"
        "@agent.tool\n"
        "async def safe_list(ctx, directory: str) -> str:\n"
        "    import os\n"
        "    return str(os.listdir(directory))\n",
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []

def test_agent_tool_overpermission_silent_for_subprocess_outside_tool(tmp_path: Path) -> None:
    # subprocess call exists but NOT inside a tool — no @agent.tool or BaseTool in the file.
    (tmp_path / "scripts.py").write_text(
        "import subprocess\n"
        "\n"
        "\n"
        "def run_build():\n"
        '    subprocess.run(["make", "build"], check=True)\n',
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/subprocess-in-agent-tool" not in rules

def test_agent_tool_overpermission_pragma_silences_all_checks(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "# security: allow-dangerous-agent-tool\n" + _DANGEROUS_IMPORT_CODE,
        encoding="utf-8",
    )
    assert AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_tool_overpermission_fires_on_python_repl_tool(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from langchain_experimental.tools import PythonREPLTool\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "repl = PythonREPLTool()\n",
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/dangerous-tool-imported" in rules

def test_agent_tool_overpermission_fires_on_langchain_basetool(tmp_path: Path) -> None:
    # BaseTool subclass with subprocess — should fire subprocess-in-agent-tool.
    (tmp_path / "custom_tool.py").write_text(
        "import subprocess\n"
        "from langchain.tools import BaseTool\n"
        "\n"
        "\n"
        "class ShellExecutor(BaseTool):\n"
        '    name = "shell"\n'
        '    description = "Execute shell commands"\n'
        "\n"
        "    def _run(self, cmd: str) -> str:\n"
        '        return subprocess.run(["sh", "-c", cmd], capture_output=True, text=True).stdout\n',
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/subprocess-in-agent-tool" in rules

def test_agent_tool_overpermission_not_applicable_without_llm_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python", "fastapi"})
    assert AgentToolOverpermissionGuard().applies(prof) is False

def test_agent_tool_overpermission_at_most_one_finding_per_rule(tmp_path: Path) -> None:
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text(_DANGEROUS_IMPORT_CODE, encoding="utf-8")
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    dangerous = [f for f in findings if f.rule == "agent-tool-overpermission/dangerous-tool-imported"]
    assert len(dangerous) == 1

def test_agent_tool_overpermission_flags_unscoped_toolkit_load(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from langchain_community.agent_toolkits import GmailToolkit\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "toolkit = GmailToolkit()\n"
        "agent = Agent('openai:gpt-4o', tools=toolkit.get_tools())\n",
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/unscoped-toolkit-load" in rules

def test_agent_tool_overpermission_flags_unscoped_toolkit_load_as_bare_assignment(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from langchain_community.agent_toolkits import SQLDatabaseToolkit\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "toolkit = SQLDatabaseToolkit(db=db, llm=llm)\n"
        "tools = toolkit.get_tools()\n"
        "agent = Agent('openai:gpt-4o', tools=tools)\n",
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/unscoped-toolkit-load" in rules

def test_agent_tool_overpermission_flags_unscoped_toolkit_load_dotted_receiver(tmp_path: Path) -> None:
    # A dotted-attribute receiver (`self.toolkit`) — the common class-based agent-wrapper
    # idiom — is just as unfiltered as a bare name and must fire.
    (tmp_path / "agent.py").write_text(
        "from langchain_community.agent_toolkits import GmailToolkit\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "class MyAgent:\n"
        "    def __init__(self):\n"
        "        self.toolkit = GmailToolkit()\n"
        "        self.agent = Agent('openai:gpt-4o', tools=self.toolkit.get_tools())\n",
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/unscoped-toolkit-load" in rules

def test_agent_tool_overpermission_silent_for_filtered_toolkit_load(tmp_path: Path) -> None:
    # Filtered via a list comprehension — an explicit allowlist, not a bulk load.
    (tmp_path / "agent.py").write_text(
        "from langchain_community.agent_toolkits import GmailToolkit\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "ALLOWED_TOOLS = {'gmail_search', 'gmail_get_message'}\n"
        "toolkit = GmailToolkit()\n"
        "tools = [t for t in toolkit.get_tools() if t.name in ALLOWED_TOOLS]\n"
        "agent = Agent('openai:gpt-4o', tools=tools)\n",
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/unscoped-toolkit-load" not in rules

def test_agent_tool_overpermission_silent_for_sliced_toolkit_load(tmp_path: Path) -> None:
    # Sliced before use — still a form of curation, not a bare bulk load.
    (tmp_path / "agent.py").write_text(
        "from langchain_community.agent_toolkits import GmailToolkit\n"
        "\n"
        "toolkit = GmailToolkit()\n"
        "tools = toolkit.get_tools()[:2]\n",
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/unscoped-toolkit-load" not in rules

def test_agent_tool_overpermission_silent_for_explicit_tool_list(tmp_path: Path) -> None:
    # An explicit, named tool list is exactly the allowlist pattern this item wants.
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o', tools=[search_tool, calculator_tool])\n",
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []

def test_agent_tool_overpermission_flags_wildcard_tools_literal(tmp_path: Path) -> None:
    # A literal `tools=["*"]` grant — an explicit "every tool" configuration, distinct
    # from the dynamic unfiltered-toolkit-load pattern above.
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o', tools=[\"*\"])\n",
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/wildcard-tools-literal" in rules

def test_agent_tool_overpermission_flags_wildcard_tools_literal_single_quote(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o', tools=['*'])\n",
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/wildcard-tools-literal" in rules

def test_agent_tool_overpermission_wildcard_fires_even_with_later_allowlist_kwarg(tmp_path: Path) -> None:
    # Design decision (mirrors unscoped-toolkit-load's line-local, no-cross-statement-
    # lookahead posture): a subsequent allowlist-looking kwarg in the same call does NOT
    # silence the literal wildcard. Unlike `toolkit.get_tools()` (a dynamic call that
    # *could* legitimately be narrowed by a real filter argument the toolkit understands),
    # `tools=["*"]` is a hardcoded string with no library-defined meaning for a sibling
    # kwarg to narrow it — the wildcard is unconditionally "every tool" the moment it's
    # written, so a nearby `allowed_tools=` is not a real mitigation and must not suppress.
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o', tools=[\"*\"], allowed_tools=[\"search\"])\n",
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/wildcard-tools-literal" in rules

def test_agent_tool_overpermission_silent_for_named_tool_list_not_wildcard(tmp_path: Path) -> None:
    # Explicit named list — safe, and must not trip the new wildcard check either.
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o', tools=[\"search\", \"calculator\"])\n",
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []

def test_agent_tool_overpermission_flags_wildcard_tools_dict_colon_form(tmp_path: Path) -> None:
    # The dict/kwarg-colon spelling: `"tools": ["*"]`.
    (tmp_path / "agent.py").write_text(
        "config = {\"tools\": [\"*\"]}\n",
        encoding="utf-8",
    )
    findings = AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-tool-overpermission/wildcard-tools-literal" in rules

def test_agent_tool_overpermission_pragma_silences_wildcard_tools_literal(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "# security: allow-dangerous-agent-tool\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o', tools=[\"*\"])\n",
        encoding="utf-8",
    )
    assert AgentToolOverpermissionGuard().run(tmp_path, _llm_prof(tmp_path)) == []

