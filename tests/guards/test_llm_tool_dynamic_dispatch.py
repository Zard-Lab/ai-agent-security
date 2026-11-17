from __future__ import annotations

from agentsec.guards.llm_tool_dynamic_dispatch import LlmToolDynamicDispatchGuard
from tests.guards._common import *  # noqa: F401,F403

# A same-file LLM/agent-tool signal. The guard's provenance gate requires one before the reflection
# rules fire (so a plain event-bus / visitor / CLI-dispatch idiom in a non-LLM file stays silent).
# The dangerous + silent-logic fixtures carry it; the FP-bait tests below deliberately omit it.
_CTX = (
    "import openai\n"
    "def _agent_step(client, msgs):\n"
    "    return client.chat.completions.create(model='gpt-4o', messages=msgs)\n"
)


def test_llm_tool_dynamic_dispatch_fires_on_globals_dynamic_call(tmp_path: Path) -> None:
    (tmp_path / "dispatch.py").write_text(
        _CTX +
        "def run_tool(tool_name: str, arg: str) -> str:\n"
        "    return globals()[tool_name](arg)\n",
        encoding="utf-8",
    )
    findings = LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-tool-dynamic-dispatch/globals-dynamic-call" in rules


def test_llm_tool_dynamic_dispatch_fires_on_getattr_dynamic_call(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        _CTX +
        "class Agent:\n"
        "    def dispatch(self, action_name: str, arg: str) -> str:\n"
        "        return getattr(self, action_name)(arg)\n",
        encoding="utf-8",
    )
    findings = LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-tool-dynamic-dispatch/getattr-dynamic-call" in rules


def test_llm_tool_dynamic_dispatch_fires_via_tool_marker_without_llm_call(tmp_path: Path) -> None:
    # The provenance gate accepts a tool/agent marker too, not only an LLM SDK call: a @tool-decorated
    # dispatcher with no `*.create(` in-file still fires.
    (tmp_path / "tools.py").write_text(
        "from langchain_core.tools import tool\n"
        "@tool\n"
        "def run(action_name: str, arg: str) -> str:\n"
        "    return getattr(TOOLBOX, action_name)(arg)\n",
        encoding="utf-8",
    )
    findings = LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-tool-dynamic-dispatch/getattr-dynamic-call" in rules


def test_llm_tool_dynamic_dispatch_silent_on_ordinary_reflection_no_llm_context(tmp_path: Path) -> None:
    # FP regression (#451 review): a plain event-bus / dispatch idiom in a file with NO LLM or agent-tool
    # signal must stay silent even in an llm-feature repo — this is ordinary Python, not LLM-tool dispatch.
    (tmp_path / "eventbus.py").write_text(
        "class Bus:\n"
        "    def dispatch(self, event_type: str, payload: dict) -> None:\n"
        "        return getattr(self, f'on_{event_type}')(payload)\n",
        encoding="utf-8",
    )
    findings = LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []


def test_llm_tool_dynamic_dispatch_silent_on_globals_dispatch_no_llm_context(tmp_path: Path) -> None:
    # Same FP class for the globals() form: a plugin loader with no LLM/agent-tool context stays silent.
    (tmp_path / "plugins.py").write_text(
        "def load(plugin_name: str, arg: str) -> str:\n"
        "    return globals()[plugin_name](arg)\n",
        encoding="utf-8",
    )
    findings = LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []


def test_llm_tool_dynamic_dispatch_silent_on_getattr_literal_name(tmp_path: Path) -> None:
    # A hardcoded, literal attribute name -- not attacker-influenceable.
    (tmp_path / "agent.py").write_text(
        _CTX +
        "class Agent:\n"
        "    def dispatch(self, arg: str) -> str:\n"
        "        return getattr(self, 'fixed_method_name')(arg)\n",
        encoding="utf-8",
    )
    findings = LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-tool-dynamic-dispatch/getattr-dynamic-call" not in rules


def test_llm_tool_dynamic_dispatch_silent_on_getattr_stored_not_called(tmp_path: Path) -> None:
    # Looked up but not invoked on this line -- not the dangerous same-line dispatch pattern.
    (tmp_path / "agent.py").write_text(
        _CTX +
        "def resolve(obj, name):\n"
        "    handler = getattr(obj, name)\n"
        "    return handler\n",
        encoding="utf-8",
    )
    findings = LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-tool-dynamic-dispatch/getattr-dynamic-call" not in rules


def test_llm_tool_dynamic_dispatch_silent_on_globals_literal_key(tmp_path: Path) -> None:
    # A hardcoded key -- not attacker-influenceable.
    (tmp_path / "dispatch.py").write_text(
        _CTX +
        "def run() -> str:\n"
        "    return globals()['hardcoded_fn']()\n",
        encoding="utf-8",
    )
    findings = LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-tool-dynamic-dispatch/globals-dynamic-call" not in rules


def test_llm_tool_dynamic_dispatch_silent_on_globals_stored_not_called(tmp_path: Path) -> None:
    (tmp_path / "dispatch.py").write_text(
        _CTX +
        "def resolve(tool_name: str):\n"
        "    fn = globals()[tool_name]\n"
        "    return fn\n",
        encoding="utf-8",
    )
    findings = LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-tool-dynamic-dispatch/globals-dynamic-call" not in rules


def test_llm_tool_dynamic_dispatch_pragma_silences_getattr(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        _CTX +
        "class Agent:\n"
        "    def dispatch(self, action_name: str, arg: str) -> str:\n"
        "        return getattr(self, action_name)(arg)  # security: allow-llm-tool-dynamic-dispatch\n",
        encoding="utf-8",
    )
    assert LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_llm_tool_dynamic_dispatch_pragma_silences_globals(tmp_path: Path) -> None:
    (tmp_path / "dispatch.py").write_text(
        _CTX +
        "def run_tool(tool_name: str, arg: str) -> str:\n"
        "    return globals()[tool_name](arg)  # security: allow-llm-tool-dynamic-dispatch\n",
        encoding="utf-8",
    )
    assert LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_llm_tool_dynamic_dispatch_fires_on_dunder_import_style_module_lookup(tmp_path: Path) -> None:
    # getattr() against an arbitrary module/object (not just `self`) is the same reflection risk.
    (tmp_path / "tools.py").write_text(
        _CTX +
        "import tools_module\n"
        "\n"
        "def call_tool(fn_name: str, *args):\n"
        "    return getattr(tools_module, fn_name)(*args)\n",
        encoding="utf-8",
    )
    findings = LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-tool-dynamic-dispatch/getattr-dynamic-call" in rules


def test_llm_tool_dynamic_dispatch_silent_for_method_named_globals(tmp_path: Path) -> None:
    # `self.globals()[...]` is a custom method, not the builtin -- must not match.
    (tmp_path / "obj.py").write_text(
        _CTX +
        "class Registry:\n"
        "    def dispatch(self, name):\n"
        "        return self.globals()[name]()\n",
        encoding="utf-8",
    )
    findings = LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-tool-dynamic-dispatch/globals-dynamic-call" not in rules


def test_llm_tool_dynamic_dispatch_not_applicable_without_llm_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python", "fastapi"})
    assert LlmToolDynamicDispatchGuard().applies(prof) is False


def test_llm_tool_dynamic_dispatch_applies_with_llm_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"llm", "python"})
    assert LlmToolDynamicDispatchGuard().applies(prof) is True


def test_llm_tool_dynamic_dispatch_silent_for_safe_dispatch_table(tmp_path: Path) -> None:
    # A validated allowlist/dispatch table -- exactly the fix this guard's remediation asks for.
    (tmp_path / "agent.py").write_text(
        _CTX +
        "TOOLS = {'search': search_tool, 'lookup': lookup_tool}\n"
        "\n"
        "def call_tool(name: str, arg: str) -> str:\n"
        "    if name not in TOOLS:\n"
        "        raise KeyError(name)\n"
        "    return TOOLS[name](arg)\n",
        encoding="utf-8",
    )
    findings = LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []


def test_llm_tool_dynamic_dispatch_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # The pragma phrase in a string on the flagged line is not a comment, so it must not suppress (#1040).
    def run(note: str) -> list:
        (tmp_path / "dispatch.py").write_text(
            _CTX +
            "def run_tool(obj, tool_name: str, arg: str) -> str:\n"
            f'    a = globals()[tool_name](arg); _n = "{note}"\n'
            f'    b = getattr(obj, tool_name)(arg); _n = "{note}"\n'
            "    return a + b\n",
            encoding="utf-8",
        )
        findings = LlmToolDynamicDispatchGuard().run(tmp_path, _llm_prof(tmp_path))
        return sorted((f.rule, f.location.rsplit(":", 1)[1]) for f in findings)

    expected = [
        ("llm-tool-dynamic-dispatch/getattr-dynamic-call", "6"),
        ("llm-tool-dynamic-dispatch/globals-dynamic-call", "5"),
    ]
    assert run("neutral") == expected
    assert run("# security: allow-llm-tool-dynamic-dispatch") == expected
