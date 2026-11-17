"""Tests for the ansi-escape-llm-output guard.

Covers:
  - ansi-escape-llm-output/unstripped-print (MEDIUM)
"""
from __future__ import annotations

from agentsec.guards.ansi_escape_llm_output import AnsiEscapeLlmOutputGuard
from tests.guards._common import *  # noqa: F401,F403


def _guard() -> AnsiEscapeLlmOutputGuard:
    return AnsiEscapeLlmOutputGuard()


# ---------------------------------------------------------------------------
# applies() gate
# ---------------------------------------------------------------------------

def test_applies_when_llm_feature_present() -> None:
    prof = mkprofile(Path("/tmp"), features={"llm", "python"})
    assert _guard().applies(prof) is True


def test_not_applies_without_llm_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"fastapi", "python"})
    assert _guard().applies(prof) is False


# ---------------------------------------------------------------------------
# ansi-escape-llm-output/unstripped-print (MEDIUM)
# ---------------------------------------------------------------------------

def test_fires_on_unstripped_print(tmp_path: Path) -> None:
    (tmp_path / "cli_tool.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "def main(prompt: str) -> None:\n"
        "    response = agent.run_sync(prompt)\n"
        "    print(response.output)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["ansi-escape-llm-output/unstripped-print"]
    assert findings[0].severity == "medium"


def test_fires_on_click_echo(tmp_path: Path) -> None:
    (tmp_path / "cli_tool.py").write_text(
        "import click\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "def main(prompt: str) -> None:\n"
        "    response = agent.run_sync(prompt)\n"
        "    click.echo(response.output)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "ansi-escape-llm-output/unstripped-print" in {f.rule for f in findings}


def test_fires_on_rich_console_print(tmp_path: Path) -> None:
    (tmp_path / "cli_tool.py").write_text(
        "from rich.console import Console\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "console = Console()\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "def main(prompt: str) -> None:\n"
        "    response = agent.run_sync(prompt)\n"
        "    console.print(response.output)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "ansi-escape-llm-output/unstripped-print" in {f.rule for f in findings}


def test_fires_on_fstring_embedding_llm_var(tmp_path: Path) -> None:
    (tmp_path / "cli_tool.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "def main(prompt: str) -> None:\n"
        "    response = agent.run_sync(prompt)\n"
        "    print(f'Answer: {response.output}')\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "ansi-escape-llm-output/unstripped-print" in {f.rule for f in findings}


# ---------------------------------------------------------------------------
# FP-bait
# ---------------------------------------------------------------------------

def test_fp_bait_strip_ansi_call_present(tmp_path: Path) -> None:
    (tmp_path / "cli_tool.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "def main(prompt: str) -> None:\n"
        "    response = agent.run_sync(prompt)\n"
        "    print(strip_ansi(response.output))\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "ansi-escape-llm-output/unstripped-print" not in {f.rule for f in findings}


def test_fp_bait_ansi_escape_pattern_present(tmp_path: Path) -> None:
    (tmp_path / "cli_tool.py").write_text(
        "import re\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "ANSI_ESCAPE = re.compile(r'\\x1b\\[[0-9;]*[a-zA-Z]')\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "def main(prompt: str) -> None:\n"
        "    response = agent.run_sync(prompt)\n"
        "    clean = ANSI_ESCAPE.sub('', response.output)\n"
        "    print(clean)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "ansi-escape-llm-output/unstripped-print" not in {f.rule for f in findings}


def test_fp_bait_non_llm_sourced_print(tmp_path: Path) -> None:
    (tmp_path / "cli_tool.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "def main() -> None:\n"
        "    status = 'ready'\n"
        "    print(status)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "ansi-escape-llm-output/unstripped-print" not in {f.rule for f in findings}


def test_fp_bait_when_pragma_present(tmp_path: Path) -> None:
    (tmp_path / "cli_tool.py").write_text(
        "# security: allow-ansi-escape-llm-output\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "def main(prompt: str) -> None:\n"
        "    response = agent.run_sync(prompt)\n"
        "    print(response.output)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "ansi-escape-llm-output/unstripped-print" not in {f.rule for f in findings}


def test_fp_bait_print_in_unrelated_function(tmp_path: Path) -> None:
    # `response` is an LLM result in one function and an unrelated print in a DIFFERENT
    # function with a same-named but non-LLM variable must not be tainted by it.
    (tmp_path / "cli_tool.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "def ask(prompt: str):\n"
        "    response = agent.run_sync(prompt)\n"
        "    return response\n"
        "\n"
        "\n"
        "def show_status():\n"
        "    response = 'ok'\n"
        "    print(response)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "ansi-escape-llm-output/unstripped-print" not in {f.rule for f in findings}
