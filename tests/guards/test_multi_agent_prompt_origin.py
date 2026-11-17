"""Tests for the multi-agent-prompt-origin guard (MAG001–015)."""
from __future__ import annotations

from agentsec.guards.multi_agent_prompt_origin import MultiAgentPromptOriginGuard
from tests.guards._common import *  # noqa: F401,F403


def _guard() -> MultiAgentPromptOriginGuard:
    return MultiAgentPromptOriginGuard()


def _mag_prof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"llm", "python"}, python_dirs=["."])


# ---------------------------------------------------------------------------
# Rule 1 — untagged-relay (HIGH, MAG001/003)
# ---------------------------------------------------------------------------

def test_untagged_relay_fires_direct_chaining(tmp_path: Path) -> None:
    """LLM result variable passed directly to a second LLM invoke — must fire HIGH."""
    (tmp_path / "pipeline.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "\n"
        "\n"
        "def run_pipeline(user_query: str) -> str:\n"
        "    result = client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': user_query}],\n"
        "    )\n"
        "    final = client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': result}],\n"
        "    )\n"
        "    return final.choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _mag_prof(tmp_path))
    relay_findings = [f for f in findings if f.rule == "multi-agent-prompt-origin/untagged-relay"]
    assert len(relay_findings) == 1
    assert relay_findings[0].severity == "high"
    assert "pipeline.py" in relay_findings[0].location


def test_untagged_relay_fires_invoke_chaining(tmp_path: Path) -> None:
    """result passed via invoke(result) pattern — must fire HIGH."""
    (tmp_path / "agent_chain.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def chain(user_query: str) -> str:\n"
        "    result = llm.invoke(user_query)\n"
        "    final = llm.invoke(result)\n"
        "    return final\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _mag_prof(tmp_path))
    relay_findings = [f for f in findings if f.rule == "multi-agent-prompt-origin/untagged-relay"]
    assert len(relay_findings) == 1
    assert relay_findings[0].severity == "high"


def test_untagged_relay_silent_when_sanitized(tmp_path: Path) -> None:
    """Sanitization present between the two LLM calls — must NOT fire Rule 1."""
    (tmp_path / "safe_chain.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def chain(user_query: str) -> str:\n"
        "    result = llm.invoke(user_query)\n"
        "    cleaned = sanitize(result)\n"
        "    final = llm.invoke(cleaned)\n"
        "    return final\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _mag_prof(tmp_path))
    relay_findings = [f for f in findings if f.rule == "multi-agent-prompt-origin/untagged-relay"]
    assert relay_findings == []


def test_untagged_relay_silent_on_subprocess_chaining(tmp_path: Path) -> None:
    """subprocess.run chained into subprocess.run is not an LLM relay — must NOT fire.

    Regression: `_LLM_ASSIGN` used to match any `.run(`/`.create(`, so `subprocess.run`
    chaining false-fired HIGH; Rule 1 is now gated behind an LLM-call signal and the
    bare `run`/`create` verbs are gone.
    """
    (tmp_path / "shell.py").write_text(
        "import subprocess\n"
        "\n"
        "\n"
        "def pipe(cmd: list[str]) -> str:\n"
        "    out = subprocess.run(cmd, capture_output=True)\n"
        "    result = subprocess.run(out.stdout, shell=True)\n"
        "    return result.stdout.decode()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _mag_prof(tmp_path))
    assert [f for f in findings if f.rule == "multi-agent-prompt-origin/untagged-relay"] == []


def test_untagged_relay_silent_on_single_agent_history_loop(tmp_path: Path) -> None:
    """The canonical OpenAI multi-turn loop (append own reply to history) is one agent.

    Regression: `messages.append({"role":"assistant","content": reply.choices[0]...})`
    used to fire HIGH. Rule 1 now requires the forwarded var to be the bare value, so
    attribute-extracted content (`completion.choices[0].message.content`) stays silent.
    """
    (tmp_path / "chat_loop.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "\n"
        "\n"
        "def converse(messages: list) -> list:\n"
        "    completion = client.chat.completions.create(model='gpt-4o', messages=messages)\n"
        "    messages.append(\n"
        "        {'role': 'assistant', 'content': completion.choices[0].message.content})\n"
        "    return messages\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _mag_prof(tmp_path))
    assert [f for f in findings if f.rule == "multi-agent-prompt-origin/untagged-relay"] == []


def test_untagged_relay_silent_with_pragma(tmp_path: Path) -> None:
    """Inline pragma suppresses the finding."""
    (tmp_path / "pipeline.py").write_text(
        "# security: allow-multi-agent-relay\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def chain(user_query: str) -> str:\n"
        "    result = llm.invoke(user_query)\n"
        "    final = llm.invoke(result)\n"
        "    return final\n",
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _mag_prof(tmp_path)) == []


# ---------------------------------------------------------------------------
# Rule 2 — infection-delimiter (MEDIUM, MAG006/011)
# ---------------------------------------------------------------------------

def test_infection_delimiter_fires_on_cascade(tmp_path: Path) -> None:
    """[CASCADE] delimiter in LLM-serving file — must fire MEDIUM."""
    (tmp_path / "relay.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "\n"
        "\n"
        "def forward_task(user_input: str) -> str:\n"
        "    prompt = f'[CASCADE]{user_input}'\n"
        "    response = client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': prompt}],\n"
        "    )\n"
        "    return response.choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _mag_prof(tmp_path))
    delim_findings = [f for f in findings if f.rule == "multi-agent-prompt-origin/infection-delimiter"]
    assert len(delim_findings) == 1
    assert delim_findings[0].severity == "medium"


def test_infection_delimiter_fires_on_angle_brackets(tmp_path: Path) -> None:
    """<<< delimiter in LLM-serving file — must fire MEDIUM."""
    (tmp_path / "handoff.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "def process(task: str) -> str:\n"
        "    msg = f'<<<task>>>{task}'\n"
        "    return llm.invoke(msg)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _mag_prof(tmp_path))
    delim_findings = [f for f in findings if f.rule == "multi-agent-prompt-origin/infection-delimiter"]
    assert len(delim_findings) == 1
    assert delim_findings[0].severity == "medium"


def test_infection_delimiter_silent_without_llm_call(tmp_path: Path) -> None:
    """Infection delimiter in a file with no LLM call — must NOT fire (reduces noise)."""
    (tmp_path / "constants.py").write_text(
        "# Protocol delimiters used by the routing layer\n"
        "CASCADE_START = '[CASCADE]'\n"
        "HANDOFF_MARKER = '[HANDOFF]'\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _mag_prof(tmp_path))
    delim_findings = [f for f in findings if f.rule == "multi-agent-prompt-origin/infection-delimiter"]
    assert delim_findings == []


def test_infection_delimiter_silent_in_docstring(tmp_path: Path) -> None:
    """Delimiter in a docstring — must NOT fire (FP bait)."""
    (tmp_path / "docs.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "\n"
        "\n"
        "def forward(task: str) -> str:\n"
        '    """Forward a task using <<<cascade>>> protocol (example only)."""\n'
        "    return client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': task}],\n"
        "    ).choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _mag_prof(tmp_path))
    delim_findings = [f for f in findings if f.rule == "multi-agent-prompt-origin/infection-delimiter"]
    assert delim_findings == []


# ---------------------------------------------------------------------------
# Rule 3 — unauth-agent-handoff (HIGH, MAG015)
# ---------------------------------------------------------------------------

def test_unauth_handoff_fires_relay_without_auth(tmp_path: Path) -> None:
    """FastAPI route accepts agent_output and calls LLM with no auth check — fires HIGH."""
    (tmp_path / "relay_api.py").write_text(
        "from fastapi import APIRouter\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "router = APIRouter()\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "@router.post('/relay')\n"
        "async def relay_agent(agent_output: str) -> str:\n"
        "    return await llm.ainvoke(agent_output)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _mag_prof(tmp_path))
    handoff_findings = [f for f in findings if f.rule == "multi-agent-prompt-origin/unauth-agent-handoff"]
    assert len(handoff_findings) == 1
    assert handoff_findings[0].severity == "high"
    assert "relay_api.py" in handoff_findings[0].location


def test_unauth_handoff_silent_with_hmac_check(tmp_path: Path) -> None:
    """Route has HMAC verification — must NOT fire Rule 3."""
    (tmp_path / "secure_relay.py").write_text(
        "from fastapi import APIRouter\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "router = APIRouter()\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "@router.post('/relay')\n"
        "async def relay_agent(agent_output: str, signature: str) -> str:\n"
        "    verify_source(agent_output, signature)\n"
        "    return await llm.ainvoke(agent_output)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _mag_prof(tmp_path))
    handoff_findings = [f for f in findings if f.rule == "multi-agent-prompt-origin/unauth-agent-handoff"]
    assert handoff_findings == []


def test_unauth_handoff_silent_with_fastapi_depends_auth(tmp_path: Path) -> None:
    """A relay route gated by a FastAPI auth dependency must NOT fire Rule 3.

    Regression: the auth safe-list missed `Depends(...)`, so the idiomatic
    `user=Depends(get_current_user)` endpoint false-fired HIGH.
    """
    (tmp_path / "auth_relay.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "router = APIRouter()\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "\n"
        "@router.post('/relay')\n"
        "async def relay_agent(agent_output: str, user=Depends(get_current_user)) -> str:\n"
        "    return await llm.ainvoke(agent_output)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _mag_prof(tmp_path))
    assert [f for f in findings if f.rule == "multi-agent-prompt-origin/unauth-agent-handoff"] == []


def test_unauth_handoff_silent_when_no_llm_call(tmp_path: Path) -> None:
    """Route accepts agent_output but makes no LLM call — must NOT fire (FP bait)."""
    (tmp_path / "router.py").write_text(
        "from fastapi import APIRouter\n"
        "\n"
        "router = APIRouter()\n"
        "\n"
        "\n"
        "@router.post('/store')\n"
        "async def store_agent_result(agent_output: str) -> dict:\n"
        "    db.save(agent_output)\n"
        "    return {'status': 'ok'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _mag_prof(tmp_path))
    handoff_findings = [f for f in findings if f.rule == "multi-agent-prompt-origin/unauth-agent-handoff"]
    assert handoff_findings == []


# ---------------------------------------------------------------------------
# Guard-level gates
# ---------------------------------------------------------------------------

def test_multi_agent_prompt_origin_not_applicable_without_llm() -> None:
    """Guard must not apply when 'llm' is not in profile.features."""
    prof = mkprofile(Path("/tmp"), features={"python", "fastapi"})
    assert MultiAgentPromptOriginGuard().applies(prof) is False


def test_multi_agent_prompt_origin_applies_with_llm() -> None:
    """Guard must apply when 'llm' is in profile.features."""
    prof = mkprofile(Path("/tmp"), features={"llm", "python"})
    assert MultiAgentPromptOriginGuard().applies(prof) is True

def test_relay_func_hostile_parenless_file_is_linear(tmp_path: Path) -> None:
    # Regression (issue #419): _RELAY_FUNC's whole-file `[^)]*` spans re-scanned an unbounded
    # paren-free tail from every `async def` candidate — O(n²). The spans are now line-bounded
    # (the llm_output_to_sink design). Actual ~0.1s; quadratic at this size takes minutes.
    import time

    (tmp_path / "hostile.py").write_text(
        "import fastapi\n" + "async def f(x " * 20_000, encoding="utf-8"  # unclosed, one line
    )
    start = time.monotonic()
    findings = _guard().run(tmp_path, _mag_prof(tmp_path))
    assert time.monotonic() - start < 5.0, "unbounded relay-signature scan reintroduced"
    assert [f for f in findings if "unauth-agent-handoff" in f.rule] == []
