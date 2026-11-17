from __future__ import annotations

from agentsec.guards.system_prompt_leak import SystemPromptLeakGuard
from tests.guards._common import *  # noqa: F401,F403


def test_system_prompt_leak_flags_unfiltered_prompt(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        'agent = Agent("m", system_prompt="You are X. Follow the rules.")\n', encoding="utf-8"
    )
    findings = SystemPromptLeakGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "system-prompt-leak/no-leak-filter"
    assert findings[0].severity == "medium"

def test_system_prompt_leak_silent_with_filter(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        'agent = Agent("m", system_prompt="You are X. Follow the rules.")\n', encoding="utf-8"
    )
    (tmp_path / "filters.py").write_text(
        "def leaks_system_prompt(response, system_prompt, n=12):\n"
        "    return False\n", encoding="utf-8"
    )
    assert SystemPromptLeakGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_system_prompt_leak_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "# security: allow-unfiltered-system-prompt\n"
        'agent = Agent("m", system_prompt="You are X. Follow the rules.")\n', encoding="utf-8"
    )
    assert SystemPromptLeakGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_system_prompt_leak_silent_without_prompt(tmp_path: Path) -> None:
    # an llm app that defines no system prompt has nothing to leak
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        'agent = Agent("m")\n', encoding="utf-8"
    )
    assert SystemPromptLeakGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_system_prompt_leak_not_applicable_without_llm() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert SystemPromptLeakGuard().applies(prof) is False



def test_system_prompt_leak_skips_examples_dir(tmp_path: Path) -> None:
    # §C.2: a prompt literal in reference/example code is not the deployed system prompt.
    d = tmp_path / "examples"
    d.mkdir()
    (d / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        'agent = Agent("m", system_prompt="You are X. Follow the rules.")\n', encoding="utf-8"
    )
    assert SystemPromptLeakGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# --- #484 review (B1/B2): the skip must not void the pragma or the mitigation ------------------

def test_pragma_in_a_nonproduct_path_still_opts_out(tmp_path: Path) -> None:
    # The `is_nonproduct_path` skip sat INSIDE the file-collection loop, and the pragma pass then
    # iterated only the collected files. So a pragma living under `tests/` was never seen and the
    # guard fired at a user who had already suppressed it (#484 review, B1).
    #
    # This is the worst shape in the batch: an FP-reduction change that VOIDS a suppression the user
    # already wrote. The pragma is documented as repo-level, so where it lives cannot matter.
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        'agent = Agent("m", system_prompt="You are X. Follow the rules.")\n', encoding="utf-8"
    )
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_agent.py").write_text(
        "# security: allow-unfiltered-system-prompt\ndef test_x(): ...\n", encoding="utf-8"
    )
    assert SystemPromptLeakGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_leak_filter_in_a_nonproduct_path_still_counts_as_mitigation(tmp_path: Path) -> None:
    # Same root cause, the mitigation half: a leak-filter helper under `e2e/` stopped counting, so
    # the guard fired on a repo that does filter (#484 review, B1). A mitigation is a mitigation
    # wherever it is defined.
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        'agent = Agent("m", system_prompt="You are X. Follow the rules.")\n', encoding="utf-8"
    )
    e2e = tmp_path / "e2e"
    e2e.mkdir()
    (e2e / "helpers.py").write_text(
        "def leaks_system_prompt(response, system_prompt, n=12):\n    return False\n", encoding="utf-8"
    )
    assert SystemPromptLeakGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_pragma_in_an_opted_in_archive_path_still_opts_out(tmp_path: Path) -> None:
    # #484 review, B2: the two guards also inherit the OPT-IN `archive_segments` surface, so opting
    # `old/` into `archive_paths` removed the pragma from view as well. Opting a tree out of scanning
    # must not revoke a suppression the user wrote in it.
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        'agent = Agent("m", system_prompt="You are X. Follow the rules.")\n', encoding="utf-8"
    )
    old = tmp_path / "old"
    old.mkdir()
    (old / "legacy.py").write_text("# security: allow-unfiltered-system-prompt\n", encoding="utf-8")
    prof = _llm_prof(tmp_path)
    prof.archive_segments = frozenset({"old"})
    assert SystemPromptLeakGuard().run(tmp_path, prof) == []


def test_prompt_only_in_a_nonproduct_path_still_does_not_fire(tmp_path: Path) -> None:
    # The other direction (F4): the skip exists because a prompt literal in reference/example/test
    # code is not the deployed app's system prompt (round-2 C.2). Widening the PRAGMA/MITIGATION
    # pass to every file must not also widen the ANCHOR pass, or the original FP comes back.
    examples = tmp_path / "examples"
    examples.mkdir()
    (examples / "demo.py").write_text(
        "from pydantic_ai import Agent\n"
        'agent = Agent("m", system_prompt="You are X. Follow the rules.")\n', encoding="utf-8"
    )
    assert SystemPromptLeakGuard().run(tmp_path, _llm_prof(tmp_path)) == []
