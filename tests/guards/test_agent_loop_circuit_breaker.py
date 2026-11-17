from __future__ import annotations

import ast

import pytest

import agentsec.guards.agent_loop_circuit_breaker as alcb
from agentsec.guards.agent_loop_circuit_breaker import AgentLoopCircuitBreakerGuard
from tests.guards._common import *  # noqa: F401,F403


def test_agent_loop_flags_max_iterations_none(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "executor = AgentExecutor(agent=agent, tools=tools, max_iterations=None)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-loop-circuit-breaker/langchain-no-iteration-limit" in rules

def test_agent_loop_flags_max_iterations_none_multiline(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "executor = AgentExecutor(\n"
        "    agent=agent,\n"
        "    tools=tools,\n"
        "    max_iterations=None,\n"
        ")\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-loop-circuit-breaker/langchain-no-iteration-limit" in rules

def test_agent_loop_flags_max_execution_time_none(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "executor = AgentExecutor(agent=a, tools=t, max_execution_time=None)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-loop-circuit-breaker/langchain-no-time-limit" in rules

def test_agent_loop_silent_for_default_executor(tmp_path: Path) -> None:
    # No max_iterations or max_execution_time kwarg — defaults (15, None) apply.
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "executor = AgentExecutor(agent=agent, tools=tools)\n",
        encoding="utf-8",
    )
    assert AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_loop_silent_for_explicit_limit(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "executor = AgentExecutor(agent=agent, tools=tools, max_iterations=10)\n",
        encoding="utf-8",
    )
    assert AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_loop_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "# security: allow-agent-loop-no-limit\n"
        "from langchain.agents import AgentExecutor\n"
        "executor = AgentExecutor(agent=a, tools=t, max_iterations=None)\n",
        encoding="utf-8",
    )
    assert AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_loop_not_applicable_without_llm_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python", "fastapi"})
    assert AgentLoopCircuitBreakerGuard().applies(prof) is False


# ---------------------------------------------------------------------------
# EXA009 — recursive agent function without depth limit
# ---------------------------------------------------------------------------

def test_recursive_agent_no_depth_fires(tmp_path: Path) -> None:
    """Async recursive function with LLM call and no depth guard must fire."""
    (tmp_path / "agent.py").write_text(
        "async def agent_step(task, memory):\n"
        "    response = await llm.ainvoke(task)\n"
        "    return await agent_step(response, memory)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-loop-circuit-breaker/recursive-no-depth-limit" in rules


def test_recursive_agent_sync_no_depth_fires(tmp_path: Path) -> None:
    """Sync recursive function with LLM call and no depth guard must fire."""
    (tmp_path / "agent.py").write_text(
        "def run_agent(prompt, ctx):\n"
        "    result = llm.invoke(prompt)\n"
        "    return run_agent(result, ctx)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-loop-circuit-breaker/recursive-no-depth-limit" in rules


def test_recursive_agent_with_depth_param_silent(tmp_path: Path) -> None:
    """Recursive function with depth parameter in signature must NOT fire (has guard)."""
    (tmp_path / "agent.py").write_text(
        "async def agent_step(task, memory, depth=0):\n"
        "    if depth >= 10:\n"
        "        return 'max depth reached'\n"
        "    response = await llm.ainvoke(task)\n"
        "    return await agent_step(response, memory, depth + 1)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-loop-circuit-breaker/recursive-no-depth-limit" not in rules


def test_recursive_no_llm_call_silent(tmp_path: Path) -> None:
    """Recursive function without any LLM call must NOT fire."""
    (tmp_path / "utils.py").write_text(
        "def process(items):\n"
        "    if not items:\n"
        "        return []\n"
        "    return [items[0]] + process(items[1:])\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-loop-circuit-breaker/recursive-no-depth-limit" not in rules


def test_recursive_agent_pragma_silences(tmp_path: Path) -> None:
    """Pragma suppresses the recursive-no-depth-limit check."""
    (tmp_path / "agent.py").write_text(
        "# security: allow-agent-loop-no-limit\n"
        "async def agent_step(task, memory):\n"
        "    response = await llm.ainvoke(task)\n"
        "    return await agent_step(response, memory)\n",
        encoding="utf-8",
    )
    assert AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_recursive_agent_max_depth_param_silent(tmp_path: Path) -> None:
    """Recursive function with max_depth parameter must NOT fire."""
    (tmp_path / "agent.py").write_text(
        "def plan(goal, context, max_depth=5):\n"
        "    result = llm.run(goal)\n"
        "    return plan(result, context, max_depth - 1)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-loop-circuit-breaker/recursive-no-depth-limit" not in rules



def test_recursive_entrypoint_main_silent(tmp_path: Path) -> None:
    """An entry-point `main()` invoked at module level via asyncio.run(main()) must NOT fire.

    Regression: the body region used to run to EOF and swallow the module-level
    `asyncio.run(main())` call, so every entry-point main() false-fired HIGH (34 such
    FPs on the flagship). The body is now indentation-bounded.
    """
    (tmp_path / "main.py").write_text(
        "import asyncio\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "async def main():\n"
        "    result = llm.invoke('hello')\n"
        "    print(result)\n"
        "\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    asyncio.run(main())\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "agent-loop-circuit-breaker/recursive-no-depth-limit" for f in findings)


def test_recursive_subprocess_run_not_llm_silent(tmp_path: Path) -> None:
    """A recursive function whose only `.run(` is asyncio/subprocess (not an LLM) must NOT fire."""
    (tmp_path / "retry.py").write_text(
        "import subprocess\n"
        "\n"
        "\n"
        "def retry(cmd):\n"
        "    proc = subprocess.run(cmd)\n"
        "    if proc.returncode:\n"
        "        return retry(cmd)\n"
        "    return proc\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "agent-loop-circuit-breaker/recursive-no-depth-limit" for f in findings)


def test_recursive_agent_level_guard_silent(tmp_path: Path) -> None:
    """A recursive agent bounded by a non-`depth`-named limit (`level`) must NOT fire."""
    (tmp_path / "expand.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def expand(node, level=0):\n"
        "    if level >= 5:\n"
        "        return node\n"
        "    out = llm.invoke(node)\n"
        "    return expand(out, level + 1)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "agent-loop-circuit-breaker/recursive-no-depth-limit" for f in findings)


# ---------------------------------------------------------------------------
# custom-loop-no-iteration-cap — hand-rolled `while True:` agent loop
# ---------------------------------------------------------------------------

def test_custom_loop_no_iteration_cap_fires(tmp_path: Path) -> None:
    """A bare `while True:` loop that calls an LLM with no counter/break must fire."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    while True:\n"
        "        response = llm.invoke(task)\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" in rules


def test_custom_loop_while_1_fires(tmp_path: Path) -> None:
    """`while 1:` is the same unconditional-loop idiom as `while True:` and must fire too."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    while 1:\n"
        "        response = llm.invoke(task)\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" in rules


def test_custom_loop_pydantic_ai_run_sync_fires(tmp_path: Path) -> None:
    """A pydantic-ai style `.run_sync()` loop with no cap must fire (not just LangChain)."""
    (tmp_path / "runner.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    while True:\n"
        "        result = agent.run_sync(task)\n"
        "        task = result.data\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" in rules


def test_custom_loop_repl_input_silent(tmp_path: Path) -> None:
    """FP-bait: an interactive chat REPL (`while True:` + `input()` + LLM call) must NOT
    fire — a human must act between iterations, so injected content cannot cascade
    unattended. Syntactically near-identical to the runaway-loop violation above."""
    (tmp_path / "repl.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def chat():\n"
        "    while True:\n"
        "        user_input = input('> ')\n"
        "        response = llm.invoke(user_input)\n"
        "        print(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_break_guard_silent(tmp_path: Path) -> None:
    """A `while True:` loop with a bounded `break` exit must NOT fire."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    while True:\n"
        "        response = llm.invoke(task)\n"
        "        if response.done:\n"
        "            break\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_counter_guard_silent(tmp_path: Path) -> None:
    """A `while True:` loop bounded by an explicit counter comparison (`turn >= 10`) must
    NOT fire — even without a `break` (it `return`s instead), a real numeric bound check on
    the counter is a genuine circuit breaker."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    turn = 0\n"
        "    while True:\n"
        "        response = llm.invoke(task)\n"
        "        turn += 1\n"
        "        if turn >= 10:\n"
        "            return response\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_unchecked_accumulator_fires(tmp_path: Path) -> None:
    """Regression (review H6): a counter-shaped variable name that is only ever appended to
    (`steps = []`; `steps.append(response)`), never compared against any bound, caps nothing
    and must still fire — the bare keyword previously silenced the finding regardless."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    steps = []\n"
        "    while True:\n"
        "        response = llm.invoke(task)\n"
        "        steps.append(response)\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_inner_for_break_still_fires(tmp_path: Path) -> None:
    """Regression (review H6): a `break` belonging to an INNER `for` loop does not exit the
    outer `while True:` and must not be treated as a bounded exit."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task, items):\n"
        "    while True:\n"
        "        response = llm.invoke(task)\n"
        "        for item in items:\n"
        "            if item.done:\n"
        "                break\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_if_break_still_silent(tmp_path: Path) -> None:
    """A `break` reached through a plain `if` (not a nested loop) still exits the outer
    `while True:` — `if`/`try` don't own their own break scope, only `for`/`while` do."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    while True:\n"
        "        response = llm.invoke(task)\n"
        "        if response.done:\n"
        "            break\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_sqs_worker_silent(tmp_path: Path) -> None:
    """FP-bait (review H6): a message-queue worker blocking on `receive_message(...)` is the
    same 'external event must act between iterations' shape as `queue.get()`/`input()` — must
    NOT fire even though it also calls an LLM per message."""
    (tmp_path / "worker.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_worker(sqs, queue_url):\n"
        "    while True:\n"
        "        msgs = sqs.receive_message(QueueUrl=queue_url)\n"
        "        for msg in msgs.get('Messages', []):\n"
        "            response = llm.invoke(msg['Body'])\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_no_llm_call_silent(tmp_path: Path) -> None:
    """A `while True:` loop with no LLM call at all must NOT fire (e.g. a poll loop)."""
    (tmp_path / "poller.py").write_text(
        "import time\n"
        "\n"
        "\n"
        "def poll():\n"
        "    while True:\n"
        "        check_status()\n"
        "        time.sleep(1)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_pragma_silences(tmp_path: Path) -> None:
    """Pragma suppresses the custom-loop-no-iteration-cap check."""
    (tmp_path / "runner.py").write_text(
        "# security: allow-agent-loop-no-limit\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    while True:\n"
        "        response = llm.invoke(task)\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    assert AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_custom_loop_named_constant_bound_silent(tmp_path: Path) -> None:
    """Regression (round-4 review F1): a loop bounded by a NAMED constant (`turn >= MAX_TURNS`)
    whose exit is `return` rather than `break` must not fire. Requiring a literal digit on the
    right of the comparison made the guard fire HIGH on the *more* disciplined form — naming the
    bound is exactly what this guard's own remediation text asks for."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "MAX_TURNS = 10\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    turn = 0\n"
        "    while True:\n"
        "        response = llm.invoke(task)\n"
        "        turn += 1\n"
        "        if turn >= MAX_TURNS:\n"
        "            return response\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_config_attribute_bound_raise_silent(tmp_path: Path) -> None:
    """Round-4 F1, second shape: the bound lives on a config object (`turn >= self.max_turns`)
    and the loop exits by `raise`, not `return`/`break`. Still a genuine circuit breaker."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "class Runner:\n"
        "    max_turns = 12\n"
        "\n"
        "    def run_agent(self, task):\n"
        "        turn = 0\n"
        "        while True:\n"
        "            response = llm.invoke(task)\n"
        "            turn += 1\n"
        "            if turn >= self.max_turns:\n"
        "                raise RuntimeError('turn cap exceeded')\n"
        "            task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_named_bound_on_accumulator_len_silent(tmp_path: Path) -> None:
    """Round-4 F1, third shape: the accumulator form H6 targeted, but bounded properly —
    `len(steps) >= MAX_TURNS`. The `len(...)` branch needed the same named-RHS widening."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "MAX_TURNS = 10\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    steps = []\n"
        "    while True:\n"
        "        response = llm.invoke(task)\n"
        "        steps.append(response)\n"
        "        if len(steps) >= MAX_TURNS:\n"
        "            return steps\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_nonblocking_subprocess_poll_still_fires(tmp_path: Path) -> None:
    """Regression (round-4 review F2): the human-in-loop carve-out is earned by BLOCKING, so a
    bare `.poll(` token must not grant it — `subprocess.Popen.poll()` is the NON-blocking
    variant by definition and nothing acts between iterations. The direction traded against by
    H6's broker widening."""
    (tmp_path / "runner.py").write_text(
        "import subprocess\n"
        "\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task, proc):\n"
        "    while True:\n"
        "        rc = proc.poll()\n"
        "        response = llm.invoke(task)\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_generic_consume_method_still_fires(tmp_path: Path) -> None:
    """Round-4 F2, second shape: `.consume(` matched ANY method of that name, so an
    `agent.consume(...)` call silenced the guard. Only a receiver-qualified broker consumer
    carries the blocking property that earns the exemption."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task, agent):\n"
        "    while True:\n"
        "        agent.consume(1)\n"
        "        response = llm.invoke(task)\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_kafka_consumer_poll_silent(tmp_path: Path) -> None:
    """The direction traded against by F2's narrowing: a real Kafka worker blocking on
    `consumer.poll(...)` between iterations must STAY silent — that is the broker FP class H6
    existed to close, and tightening `.poll(` must not reopen it."""
    (tmp_path / "worker.py").write_text(
        "from confluent_kafka import Consumer\n"
        "\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "consumer = Consumer({'group.id': 'agents'})\n"
        "\n"
        "\n"
        "def run_worker():\n"
        "    while True:\n"
        "        msg = consumer.poll(timeout=1.0)\n"
        "        if msg is None:\n"
        "            continue\n"
        "        response = llm.invoke(msg.value())\n"
        "        print(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


# ---------------------------------------------------------------------------
# #777 — the bound must be LOOP-INVARIANT, not merely name-shaped
# ---------------------------------------------------------------------------
# Round 4 widened the comparison's right-hand side from a literal digit to any identifier, to
# stop the guard firing HIGH on the three correctly-bounded shapes above. That fixed the FPs but
# made "is this a bound?" a purely lexical question, and `MAX_TURNS` and `last_turn` are the same
# token shape. These six tests pin BOTH directions of that axis: the mutable-bound shapes must
# fire, and the config-attribute shapes the widening existed to protect must stay silent.


def test_custom_loop_mutable_bound_still_fires(tmp_path: Path) -> None:
    """#777, the reported miss: the counter is compared against `last_turn`, which the body
    itself pushes upward every iteration. The comparison is always true, nothing breaks or
    returns, and the loop is genuinely unbounded — but `last_turn` is identifier-shaped, so the
    pre-#777 regex read it as a circuit breaker and went silent."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    turn = 0\n"
        "    last_turn = -1\n"
        "    while True:\n"
        "        turn += 1\n"
        "        response = llm.invoke(task)\n"
        "        if turn >= last_turn:\n"
        "            last_turn = turn\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_self_comparison_still_fires(tmp_path: Path) -> None:
    """#777, degenerate case: the counter compared against ITSELF. `turn >= turn` is a tautology
    that caps nothing, and `turn` is rebound by the body's `turn += 1` besides."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    turn = 0\n"
        "    while True:\n"
        "        turn += 1\n"
        "        response = llm.invoke(task)\n"
        "        if turn >= turn:\n"
        "            pass\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_growing_len_bound_still_fires(tmp_path: Path) -> None:
    """#777, third shape: `turn >= len(history)` where the body appends to `history` every
    iteration, so the bound outruns the counter forever. The pre-#777 regex matched the bare
    token `len` as a named bound (the identifier branch stops at the paren), silencing it."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    turn = 0\n"
        "    history = []\n"
        "    while True:\n"
        "        turn += 1\n"
        "        response = llm.invoke(task)\n"
        "        history.append(response)\n"
        "        if turn >= len(history):\n"
        "            pass\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_config_attribute_dotted_bound_silent(tmp_path: Path) -> None:
    """FP-bait for #777: `turn >= config.max_turns` — a bound on a plain config object, neither
    ALL_CAPS nor `self.`-qualified. This is the shape that rules out narrowing the RHS regex by
    naming convention, and the one the round-4 tests left uncovered (they only pin `self.`).

    Honest about what it proves: this also passes against pre-#777 code, so it is NOT evidence
    that the AST widening works. It is an anchor against the *rejected* naive fix, which fires
    HIGH here. The widening's own evidence is the three `..._still_fires` tests above."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task, config):\n"
        "    turn = 0\n"
        "    while True:\n"
        "        turn += 1\n"
        "        response = llm.invoke(task)\n"
        "        if turn >= config.max_turns:\n"
        "            return response\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_settings_constant_bound_silent(tmp_path: Path) -> None:
    """FP-bait for #777, second shape: `turn >= settings.MAX_TURNS`. The attribute is ALL_CAPS
    but its qualifier is not, so a naive `[A-Z_][A-Z0-9_]*` narrowing fires HIGH here.

    Same caveat as the test above: it passes pre-#777 too, so it anchors the rejected fix rather
    than proving this one."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "from .conf import settings\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    turn = 0\n"
        "    while True:\n"
        "        turn += 1\n"
        "        response = llm.invoke(task)\n"
        "        if turn >= settings.MAX_TURNS:\n"
        "            return response\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_unparseable_file_falls_back_to_regex(tmp_path: Path) -> None:
    """The AST path cannot run on a file that will not parse, so `_has_iteration_cap` degrades to
    the pre-#777 regex rather than losing the suppression entirely. This pins that the fallback
    is actually wired: the file below has a syntax error AFTER a correctly bounded loop, so an
    unwired fallback would report the bounded loop as unbounded.

    Asserting the artifact, not the absence of a crash — a silently-dead fallback would present
    as a normal run."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "MAX_TURNS = 10\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    turn = 0\n"
        "    while True:\n"
        "        response = llm.invoke(task)\n"
        "        turn += 1\n"
        "        if turn >= MAX_TURNS:\n"
        "            return response\n"
        "        task = str(response)\n"
        "\n"
        "\n"
        "def broken(:\n"          # deliberate syntax error - the whole module fails to parse
        "    pass\n",
        encoding="utf-8",
    )
    with pytest.raises(SyntaxError):  # the fixture really is unparseable
        ast.parse((tmp_path / "runner.py").read_text(encoding="utf-8"))

    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_generic_base_case_bound_silent(tmp_path: Path) -> None:
    """Parity bait for #777: the generic `if <var> <op> <number>:` base-case shape, with NO
    counter-shaped name involved, must keep suppressing exactly as it did before the AST change.

    This is the direction the #777 fix traded against. Moving the bound test onto the AST made it
    easy to drop `_LOOP_GUARD`'s literal-only third branch by omission, which would have widened
    the guard onto every `while True:` whose only comparison is a base case — measured: silent
    with the branch preserved, FIRES without it. Whether that shape *deserves* to suppress is a
    separate question from #777; this test pins that #777 did not silently answer it."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task, depth):\n"
        "    while True:\n"
        "        response = llm.invoke(task)\n"
        "        if depth > 5:\n"
        "            return response\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_nested_scope_shadowing_bound_silent(tmp_path: Path) -> None:
    """FP-bait for the #777 AST path: a nested `def` inside the loop body binds a LOCAL named
    `MAX_TURNS`. That shadows the module constant, it does not move it, so the loop is still
    correctly bounded and must stay silent.

    This is the exact false-positive class #772's AST rewrite was reverted for. Collecting
    rebindings with a plain `ast.walk` descends into the nested scope and reads the local as a
    rebind of the bound - measured firing before `_iter_loop_scope` stopped at scope boundaries."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "MAX_TURNS = 10\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    turn = 0\n"
        "    while True:\n"
        "        def describe():\n"
        "            MAX_TURNS = 'local, unrelated'\n"
        "            return MAX_TURNS\n"
        "        turn += 1\n"
        "        response = llm.invoke(task)\n"
        "        if turn >= MAX_TURNS:\n"
        "            return response\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_nested_scope_global_rebind_still_fires(tmp_path: Path) -> None:
    """The other direction of the scope carve-out: a nested `def` that declares `global MAX_TURNS`
    and raises it every iteration REALLY does move the bound, so the loop never terminates and
    must still fire.

    Without this, stopping at scope boundaries would be a silent narrowing - the FP fix above
    would have bought its silence by going blind to a genuine unbounded loop."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "MAX_TURNS = 10\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task):\n"
        "    turn = 0\n"
        "    while True:\n"
        "        def bump():\n"
        "            global MAX_TURNS\n"
        "            MAX_TURNS = MAX_TURNS + 5\n"
        "        bump()\n"
        "        turn += 1\n"
        "        response = llm.invoke(task)\n"
        "        if turn >= MAX_TURNS:\n"
        "            return response\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )

# ---------------------------------------------------------------------------
# Review of #792 — defects found by the agentic pre-review, pinned here
# ---------------------------------------------------------------------------


def test_custom_loop_unrelated_attribute_write_bound_silent(tmp_path: Path) -> None:
    """FP-bait (#792 review H1): a correctly bounded loop that ALSO stores something else on the
    same object. `self.last_response = response` must not disqualify `self.max_turns` as a bound.

    The first cut of `_add_bound_target` added an attribute target's ROOT to the rebound set, so
    any write to any attribute read as a write to the whole object and fired HIGH on this
    entirely ordinary shape. Measured firing before the fix."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "class Runner:\n"
        "    max_turns = 12\n"
        "\n"
        "    def run_agent(self, task):\n"
        "        turn = 0\n"
        "        while True:\n"
        "            turn += 1\n"
        "            response = llm.invoke(task)\n"
        "            self.last_response = response\n"
        "            if turn >= self.max_turns:\n"
        "                return response\n"
        "            task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_bound_attribute_itself_rewritten_still_fires(tmp_path: Path) -> None:
    """The other direction of H1: writing the BOUND's own attribute (`self.max_turns = turn + 5`)
    really does move it, so the loop never terminates and must still fire. Without this, the H1
    fix would have bought its silence by going blind to a genuinely unbounded loop."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "class Runner:\n"
        "    def run_agent(self, task):\n"
        "        turn = 0\n"
        "        while True:\n"
        "            turn += 1\n"
        "            response = llm.invoke(task)\n"
        "            self.max_turns = turn + 5\n"
        "            if turn >= self.max_turns:\n"
        "                pass\n"
        "            task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_match_case_rebinding_bound_still_fires(tmp_path: Path) -> None:
    """#792 review M1: a `match`/`case` capture pattern binds a name, so a bound rebound that way
    is not loop-invariant. `_names_bound_in` handles every other binding form; missing this one
    re-opened the exact #777 class through Python 3.10+ syntax. Measured silent before the fix."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task, resp):\n"
        "    turn = 0\n"
        "    cap = 1\n"
        "    while True:\n"
        "        match resp:\n"
        "            case {'limit': cap}:\n"
        "                pass\n"
        "        turn += 1\n"
        "        response = llm.invoke(task)\n"
        "        if turn >= cap:\n"
        "            pass\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_file_is_parsed_once_regardless_of_loop_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#792 review M2: the AST is built ONCE per file, not once per `while True:` in it.

    Asserts the artifact (the parse count), not a wall-clock threshold, so it cannot go flaky on
    a slow runner. Re-parsing and re-walking the whole module per match is the shape
    that cost `forwarded_header_blind_trust.py` a 9.5x regression; measured 7.4x here on a
    100-loop file before the fix."""
    body = ["from langchain_openai import ChatOpenAI", "llm = ChatOpenAI()", ""]
    for i in range(5):
        body += [
            f"def run_{i}(task):",
            "    while True:",
            "        response = llm.invoke(task)",
            "        task = str(response)",
            "",
        ]
    (tmp_path / "runner.py").write_text("\n".join(body), encoding="utf-8")

    calls: list[str] = []
    real = alcb.safe_ast_parse

    def counting(text: str, filename: object = "<unknown>") -> object:
        calls.append(str(filename))
        return real(text, filename)  # type: ignore[arg-type]

    monkeypatch.setattr(alcb, "safe_ast_parse", counting)
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))

    # All 5 loops are unbounded, so the rule really did evaluate every one of them...
    assert (
        sum(
            f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
        )
        == 5
    )
    # ...yet the file was parsed exactly once.
    assert calls.count(str(tmp_path / "runner.py")) == 1, calls


# #778 — the human-in-loop carve-out qualifies `.poll(`/`.consume(` by receiver NAME, and that
# qualification must be a token test, not a containment one. Three tests each way: a receiver
# that merely CONTAINS a broker word blocks on nothing and must still fire, while a real broker
# receiver (compound, private, or plural) must stay silent — the H6 FP class the qualification
# exists to preserve, and the direction this narrowing trades against.
# ---------------------------------------------------------------------------


def test_custom_loop_substring_channel_receiver_still_fires(tmp_path: Path) -> None:
    """#778 as reported: `channel_name` merely CONTAINS `channel`, and a non-blocking status
    `.poll()` on it acts between iterations no more than `proc.poll()` does. The carve-out was
    written as `\\w*(?:consumer|channel|subscriber)\\w*`, so the trailing `\\w*` swallowed
    `_name` and silenced the guard on a genuinely unbounded loop."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "class R:\n"
        "    def run(self, task):\n"
        "        while True:\n"
        "            self.channel_name.poll()\n"
        "            response = llm.invoke(task)\n"
        "            task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_substring_consumer_prefix_still_fires(tmp_path: Path) -> None:
    """#778, the direction the report did not cover: the LEADING `\\w*` was equally loose, so a
    broker word used as a PREFIX (`consumer_count`, a counter — not a client) earned the
    exemption too. Both sides of the token have to be anchored, not just the trailing one."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task, consumer_count):\n"
        "    while True:\n"
        "        consumer_count.consume()\n"
        "        response = llm.invoke(task)\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_substring_subscriber_receiver_still_fires(tmp_path: Path) -> None:
    """#778, both-sides shape: `my_subscriber_registry` is a registry of subscribers, not a
    subscriber. Containment matched it on both the prefix and the suffix; the token form does
    not, because `subscriber` is followed by `_registry` rather than a word boundary."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task, my_subscriber_registry):\n"
        "    while True:\n"
        "        my_subscriber_registry.poll()\n"
        "        response = llm.invoke(task)\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_compound_kafka_consumer_poll_silent(tmp_path: Path) -> None:
    """FP-bait for #778's narrowing: a COMPOUND broker name is the whole reason the receiver
    qualification was not written as a bare literal. `kafka_consumer.poll(timeout=...)` blocks
    exactly as `consumer.poll(...)` does, so the underscore-delimited prefix must be admitted —
    nothing in the suite pinned this before, which is why a too-tight fix would have passed."""
    (tmp_path / "worker.py").write_text(
        "from confluent_kafka import Consumer\n"
        "\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "kafka_consumer = Consumer({'group.id': 'agents'})\n"
        "\n"
        "\n"
        "def run_worker():\n"
        "    while True:\n"
        "        msg = kafka_consumer.poll(timeout=1.0)\n"
        "        if msg is None:\n"
        "            continue\n"
        "        response = llm.invoke(msg.value())\n"
        "        print(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_private_consumer_attr_poll_silent(tmp_path: Path) -> None:
    """FP-bait for #778's narrowing: a broker client held as a PRIVATE attribute
    (`self._consumer`) is the ordinary way to write a worker class. The leading `_` must not
    cost the exemption — anchoring the token without allowing it would re-open H6 on a real
    Kafka worker."""
    (tmp_path / "worker.py").write_text(
        "from confluent_kafka import Consumer\n"
        "\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "class Worker:\n"
        "    def __init__(self):\n"
        "        self._consumer = Consumer({'group.id': 'agents'})\n"
        "\n"
        "    def run(self):\n"
        "        while True:\n"
        "            msg = self._consumer.poll(1.0)\n"
        "            if msg is None:\n"
        "                continue\n"
        "            response = llm.invoke(msg.value())\n"
        "            print(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_plural_channels_consume_silent(tmp_path: Path) -> None:
    """FP-bait for #778's narrowing: a plural receiver (`self.channels.consume()`) is still a
    broker channel and still blocks. The `s?` in the token form is what keeps it exempt; without
    it the narrowing would trade one FN class for an FP class."""
    (tmp_path / "worker.py").write_text(
        "import pika\n"
        "\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "class Worker:\n"
        "    def __init__(self, connection):\n"
        "        self.channels = connection.channel()\n"
        "\n"
        "    def run(self):\n"
        "        while True:\n"
        "            body = self.channels.consume()\n"
        "            response = llm.invoke(body)\n"
        "            print(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


# ---------------------------------------------------------------------------
# #794: numeric-suffix broker receivers are admitted; alphabetic suffixes still fire
# ---------------------------------------------------------------------------


def test_custom_loop_numbered_kafka_consumer_poll_silent(tmp_path: Path) -> None:
    """FP-bait (#794): a per-partition Kafka consumer held in a NUMBERED variable
    (`kafka_consumer_1`) is the same blocking client as `kafka_consumer`, just disambiguated. The
    numeric-suffix allowance admits it; without it the token's trailing word boundary rejected the
    numeric suffix and fired HIGH on a real broker worker. Must fail against the #793 pattern
    (the discrimination check for this widening)."""
    (tmp_path / "worker.py").write_text(
        "from confluent_kafka import Consumer\n"
        "\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "kafka_consumer_1 = Consumer({'group.id': 'agents'})\n"
        "\n"
        "\n"
        "def run_worker():\n"
        "    while True:\n"
        "        msg = kafka_consumer_1.poll(1.0)\n"
        "        if msg is None:\n"
        "            continue\n"
        "        response = llm.invoke(msg.value())\n"
        "        print(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_numbered_channel_consume_silent(tmp_path: Path) -> None:
    """FP-bait (#794): a numbered broker channel (`channel_2`) blocks exactly as `channel` does.
    Companion to the numbered-consumer case, covering the `channel` token and the `consume` method.
    Must fail against the #793 pattern (the discrimination check for this widening)."""
    (tmp_path / "worker.py").write_text(
        "import pika\n"
        "\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_worker(connection):\n"
        "    channel_2 = connection.channel()\n"
        "    while True:\n"
        "        body = channel_2.consume()\n"
        "        response = llm.invoke(body)\n"
        "        print(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


def test_custom_loop_alpha_suffix_channel_id_still_fires(tmp_path: Path) -> None:
    """#794, the direction the widening trades against: an ALPHABETIC suffix (`channel_id`) is a
    status or identifier, not a broker client, and blocks on nothing. The numeric-suffix allowance
    admits only a trailing underscore-plus-digits, so `channel_id.poll()` still fires. Pins that
    #794 did not re-open the #778 class through the new suffix group."""
    (tmp_path / "runner.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def run_agent(task, channel_id):\n"
        "    while True:\n"
        "        channel_id.poll()\n"
        "        response = llm.invoke(task)\n"
        "        task = str(response)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(
        f.rule == "agent-loop-circuit-breaker/custom-loop-no-iteration-cap" for f in findings
    )


# ── #425: one finding per AgentExecutor(...) call, not one per repo ─────────────────

_ITER_RULE = "agent-loop-circuit-breaker/langchain-no-iteration-limit"
_TIME_RULE = "agent-loop-circuit-breaker/langchain-no-time-limit"


def test_agent_loop_reports_every_unbounded_executor_call(tmp_path: Path) -> None:
    # Regression for #425: both AgentExecutor checks did one `.search` per file and returned
    # the first match from inside the all-files loop, so N unbounded agents reported 1 and
    # an exception on that one hid the rest. Each call must report, anchored at its own
    # `AgentExecutor(` line (a black-formatted call anchors at its opening line).
    (tmp_path / "agent_a.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "ex1 = AgentExecutor(agent=a, tools=t, max_iterations=None, max_execution_time=None)\n"
        "ex2 = AgentExecutor(\n"
        "    agent=a,\n"
        "    tools=t,\n"
        "    max_iterations=None,\n"
        ")\n",
        encoding="utf-8",
    )
    (tmp_path / "agent_b.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "ex3 = AgentExecutor(agent=a, tools=t, max_iterations=None, max_execution_time=None)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    iters = sorted(f.location for f in findings if f.rule == _ITER_RULE)
    times = sorted(f.location for f in findings if f.rule == _TIME_RULE)
    assert iters == ["agent_a.py:2", "agent_a.py:3", "agent_b.py:2"]
    assert times == ["agent_a.py:2", "agent_b.py:2"]


def test_agent_loop_bounded_executor_after_a_hit_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the #425 widening: matches after the first used to be unreachable. A
    # bounded executor and a default one, after an unbounded call in the same file, must
    # not become extra findings now that the scan keeps going.
    (tmp_path / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\n"
        "ex1 = AgentExecutor(agent=a, tools=t, max_iterations=None, max_execution_time=None)\n"
        "ex2 = AgentExecutor(agent=a, tools=t, max_iterations=10, max_execution_time=30)\n"
        "ex3 = AgentExecutor(agent=a, tools=t)\n",
        encoding="utf-8",
    )
    findings = AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path))
    assert sorted((f.rule, f.location) for f in findings) == [
        (_ITER_RULE, "agent.py:2"),
        (_TIME_RULE, "agent.py:2"),
    ]


def test_agent_loop_pragma_in_third_file_silences_every_executor(tmp_path: Path) -> None:
    # The opt-out is repo-wide and must keep seeing every file after the #425 change.
    for name in ("agent_a.py", "agent_b.py"):
        (tmp_path / name).write_text(
            "from langchain.agents import AgentExecutor\n"
            "ex = AgentExecutor(agent=a, tools=t, max_iterations=None, max_execution_time=None)\n",
            encoding="utf-8",
        )
    (tmp_path / "zz_settings.py").write_text("# security: allow-agent-loop-no-limit\n", encoding="utf-8")
    assert AgentLoopCircuitBreakerGuard().run(tmp_path, _llm_prof(tmp_path)) == []
