"""Tests for the acp-vulnerabilities guard (ACP-047, ACP-072, ACP-079, ACP-082)."""
from __future__ import annotations

from agentsec.guards.acp_vulnerabilities import AcpVulnerabilitiesGuard
from tests.guards._common import *  # noqa: F401,F403


def _acp_prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"python"}, python_dirs=["."])


# ---------------------------------------------------------------------------
# applies() gate
# ---------------------------------------------------------------------------

def test_acp_vulnerabilities_applies_when_acp_import_present(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text(
        "from acp_sdk import Message\n"
        "async def handle(msg: Message):\n"
        "    memory.add(msg.content)\n",
        encoding="utf-8",
    )
    assert AcpVulnerabilitiesGuard().applies(_acp_prof(tmp_path)) is True


def test_acp_vulnerabilities_applies_with_beamlit_import(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "import beamlit\n"
        "agent = beamlit.Agent()\n",
        encoding="utf-8",
    )
    assert AcpVulnerabilitiesGuard().applies(_acp_prof(tmp_path)) is True


def test_acp_vulnerabilities_not_applicable_without_acp_import(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n",
        encoding="utf-8",
    )
    assert AcpVulnerabilitiesGuard().applies(_acp_prof(tmp_path)) is False


# ---------------------------------------------------------------------------
# ACP-047 — MINJA memory injection
# ---------------------------------------------------------------------------

def test_acp_minja_fires_on_unsanitised_handler(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text(
        "from acp_sdk import Message\n"
        "\n"
        "@agent.on_message\n"
        "async def handle(msg: Message):\n"
        "    memory.add(msg.content)\n",
        encoding="utf-8",
    )
    findings = AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "acp-vulnerabilities/minja-memory-injection" in rules


def test_acp_minja_fires_on_message_type_annotation(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text(
        "from acp_sdk import AcpMessage\n"
        "\n"
        "async def process_message(msg: AcpMessage):\n"
        "    store.save(msg.content)\n",
        encoding="utf-8",
    )
    findings = AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "acp-vulnerabilities/minja-memory-injection" in rules


def test_acp_minja_silent_when_sanitised(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text(
        "from acp_sdk import Message\n"
        "\n"
        "@agent.on_message\n"
        "async def handle(msg: Message):\n"
        "    clean_content = sanitize(msg.content)\n"
        "    memory.add(clean_content)\n",
        encoding="utf-8",
    )
    findings = AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "acp-vulnerabilities/minja-memory-injection" not in rules


def test_acp_minja_severity_is_high(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text(
        "from acp_sdk import Message\n"
        "@agent.on_message\n"
        "async def handle(msg: Message):\n"
        "    memory.add(msg.content)\n",
        encoding="utf-8",
    )
    findings = [
        f for f in AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
        if f.rule == "acp-vulnerabilities/minja-memory-injection"
    ]
    assert findings
    assert findings[0].severity == "high"
    assert "OWASP-LLM:LLM01" in findings[0].standards


# ---------------------------------------------------------------------------
# ACP-072 — hot-reload without token invalidation
# ---------------------------------------------------------------------------

def test_acp_hot_reload_fires_on_missing_invalidation(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        "from acp_sdk import Agent\n"
        "\n"
        "def hot_reload(cfg):\n"
        "    agent.config = cfg\n",
        encoding="utf-8",
    )
    findings = AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "acp-vulnerabilities/hot-reload-no-token-invalidation" in rules


def test_acp_hot_reload_fires_via_call_pattern(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        "from acp import Agent\n"
        "\n"
        "def update_system(new_cfg):\n"
        "    hot_reload(new_cfg)\n"
        "    agent.restart()\n",
        encoding="utf-8",
    )
    findings = AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "acp-vulnerabilities/hot-reload-no-token-invalidation" in rules


def test_acp_hot_reload_silent_with_invalidation(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        "from acp_sdk import Agent\n"
        "\n"
        "def hot_reload(cfg):\n"
        "    invalidate_sessions()\n"
        "    agent.config = cfg\n",
        encoding="utf-8",
    )
    findings = AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "acp-vulnerabilities/hot-reload-no-token-invalidation" not in rules


def test_acp_hot_reload_severity_is_high(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        "from acp_sdk import Agent\n"
        "def hot_reload(cfg):\n"
        "    agent.config = cfg\n",
        encoding="utf-8",
    )
    findings = [
        f for f in AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
        if f.rule == "acp-vulnerabilities/hot-reload-no-token-invalidation"
    ]
    assert findings
    assert findings[0].severity == "high"


# ---------------------------------------------------------------------------
# ACP-079 — org-scoped token literal
# ---------------------------------------------------------------------------

def test_acp_org_token_fires_on_literal(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "from acp_sdk import Client\n"
        'org_token = "sk-org-abc123xyz456"\n',
        encoding="utf-8",
    )
    findings = AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "acp-vulnerabilities/org-scoped-token" in rules


def test_acp_org_token_fires_on_workspace_key(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "from beamlit import Workspace\n"
        'workspace_api_key = "wk-abcdefgh12345678"\n',
        encoding="utf-8",
    )
    findings = AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "acp-vulnerabilities/org-scoped-token" in rules


def test_acp_org_token_silent_when_from_env(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "import os\n"
        "from acp_sdk import Client\n"
        'org_token = os.environ["ORG_TOKEN"]\n',
        encoding="utf-8",
    )
    findings = AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "acp-vulnerabilities/org-scoped-token" not in rules


def test_acp_org_token_severity_is_high(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "from acp_sdk import Client\n"
        'organization_secret = "org-secret-1234567890"\n',
        encoding="utf-8",
    )
    findings = [
        f for f in AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
        if f.rule == "acp-vulnerabilities/org-scoped-token"
    ]
    assert findings
    assert findings[0].severity == "high"


# ---------------------------------------------------------------------------
# ACP-082 — unclamped sampling parameters from caller
# ---------------------------------------------------------------------------

def test_acp_sampling_fires_on_unclamped_temperature(tmp_path: Path) -> None:
    (tmp_path / "invoke.py").write_text(
        "from acp_sdk import Message\n"
        "\n"
        "def handle(request):\n"
        "    result = llm.invoke(prompt, temperature=request.temperature)\n"
        "    return result\n",
        encoding="utf-8",
    )
    findings = AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "acp-vulnerabilities/unclamped-sampling-params" in rules


def test_acp_sampling_fires_on_unclamped_max_tokens(tmp_path: Path) -> None:
    (tmp_path / "invoke.py").write_text(
        "from acp_sdk import Message\n"
        "\n"
        "def chat(msg):\n"
        "    return llm.invoke(prompt, max_tokens=msg.max_tokens)\n",
        encoding="utf-8",
    )
    findings = AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "acp-vulnerabilities/unclamped-sampling-params" in rules


def test_acp_sampling_silent_when_clamped(tmp_path: Path) -> None:
    (tmp_path / "invoke.py").write_text(
        "from acp_sdk import Message\n"
        "\n"
        "def handle(request):\n"
        "    result = llm.invoke(prompt, temperature=min(request.temperature, 1.0))\n"
        "    return result\n",
        encoding="utf-8",
    )
    findings = AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "acp-vulnerabilities/unclamped-sampling-params" not in rules


def test_acp_sampling_severity_is_medium(tmp_path: Path) -> None:
    (tmp_path / "invoke.py").write_text(
        "from acp_sdk import Message\n"
        "\n"
        "def handle(request):\n"
        "    result = llm.invoke(prompt, temperature=request.temperature)\n"
        "    return result\n",
        encoding="utf-8",
    )
    findings = [
        f for f in AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
        if f.rule == "acp-vulnerabilities/unclamped-sampling-params"
    ]
    assert findings
    assert findings[0].severity == "medium"


# ---------------------------------------------------------------------------
# Pragma suppression
# ---------------------------------------------------------------------------

def test_acp_pragma_silences_all_rules(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text(
        "# security: allow-acp-vulnerabilities\n"
        "from acp_sdk import Message\n"
        "\n"
        "@agent.on_message\n"
        "async def handle(msg: Message):\n"
        "    memory.add(msg.content)\n"
        "\n"
        'org_token = "sk-org-abc123xyz456"\n',
        encoding="utf-8",
    )
    findings = AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
    assert findings == []


# ---------------------------------------------------------------------------
# check_id and standards
# ---------------------------------------------------------------------------

def test_acp_check_id_is_set(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text(
        "from acp_sdk import Message\n"
        "@agent.on_message\n"
        "async def handle(msg: Message):\n"
        "    memory.add(msg.content)\n",
        encoding="utf-8",
    )
    findings = AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))
    assert all(f.check_id == "acp-vulnerabilities" for f in findings)
    assert all("OWASP-LLM:LLM01" in f.standards for f in findings)


# ---------------------------------------------------------------------------
# PR #220 review — FP/FN regression tests
# ---------------------------------------------------------------------------

def _run(tmp_path: Path) -> list:
    return AcpVulnerabilitiesGuard().run(tmp_path, _acp_prof(tmp_path))


def test_acp_minja_reports_canonical_handler_once(tmp_path: Path) -> None:
    # Decorator + typed-param def is ONE handler — must not double-report (review MUST-FIX 1).
    (tmp_path / "h.py").write_text(
        "from acp_sdk import Message\n\n"
        "@agent.on_message\n"
        "async def handle(msg: Message):\n"
        "    memory.add(msg.content)\n",
        encoding="utf-8",
    )
    assert len([f for f in _run(tmp_path) if "minja" in f.rule]) == 1


def test_acp_minja_not_silenced_by_whitespace_strip(tmp_path: Path) -> None:
    # A plain `.strip()` is not injection sanitisation — must still fire (review MUST-FIX 4).
    (tmp_path / "h.py").write_text(
        "from acp_sdk import Message\n"
        "async def handle(msg: Message):\n"
        "    memory.add(msg.content.strip())\n",
        encoding="utf-8",
    )
    assert len([f for f in _run(tmp_path) if "minja" in f.rule]) == 1


def test_acp_minja_silent_on_list_append_in_unrelated_async_fn(tmp_path: Path) -> None:
    # An async fn with a *-Message-typed param appending to a plain list is not a memory write.
    (tmp_path / "h.py").write_text(
        "from acp_sdk import Client\n"
        "async def send(self, to: WebSocketMessage):\n"
        "    results.append(to)\n",
        encoding="utf-8",
    )
    assert [f for f in _run(tmp_path) if "minja" in f.rule] == []


def test_acp_sampling_fires_despite_unrelated_comparison(tmp_path: Path) -> None:
    # An unrelated `if x < n` nearby must NOT silence the unclamped-sampling finding (FN, MUST-FIX 2).
    (tmp_path / "h.py").write_text(
        "from acp_sdk import Message\n"
        "def f(request):\n"
        "    if len(items) < 10:\n"
        "        pass\n"
        "    temperature = request.temperature\n",
        encoding="utf-8",
    )
    assert len([f for f in _run(tmp_path) if "sampling" in f.rule]) == 1


def test_acp_sampling_silent_when_clamped_same_statement(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "from acp_sdk import Message\n"
        "def f(request):\n"
        "    temperature = min(request.temperature, 1.0)\n",
        encoding="utf-8",
    )
    assert [f for f in _run(tmp_path) if "sampling" in f.rule] == []


def test_acp_hot_reload_not_silenced_by_unrelated_cache_invalidate(tmp_path: Path) -> None:
    # `cache.invalidate('key')` is not a session/token invalidation — must still fire (FN, MUST-FIX 3).
    (tmp_path / "h.py").write_text(
        "from acp_sdk import Agent\n"
        "def reload_config(c):\n"
        "    cache.invalidate('key')\n"
        "    apply(c)\n",
        encoding="utf-8",
    )
    assert len([f for f in _run(tmp_path) if "hot-reload" in f.rule]) == 1


def test_acp_hot_reload_silent_with_session_revocation(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "from acp_sdk import Agent\n"
        "def reload_config(c):\n"
        "    revoke_session(token)\n"
        "    apply(c)\n",
        encoding="utf-8",
    )
    assert [f for f in _run(tmp_path) if "hot-reload" in f.rule] == []


def test_acp_org_token_silent_in_comment(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "from acp_sdk import Client\n"
        "# org_token = 'sk-org-abc123xyz456def'\n",
        encoding="utf-8",
    )
    assert [f for f in _run(tmp_path) if "org-scoped" in f.rule] == []


def test_acp_org_token_standards_are_secret_not_llm(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "from acp_sdk import Client\n"
        "org_token = 'sk-org-abc123xyz456def'\n",
        encoding="utf-8",
    )
    findings = [f for f in _run(tmp_path) if "org-scoped" in f.rule]
    assert findings and findings[0].standards == ["OWASP:A02", "CWE-798"]


def test_acp_applies_false_on_acp_prefixed_unrelated_import(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text("import acpfoo\n", encoding="utf-8")
    assert AcpVulnerabilitiesGuard().applies(_acp_prof(tmp_path)) is False
