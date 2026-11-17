from __future__ import annotations

from agentsec.guards.input_delimiters import InputDelimitersGuard
from tests.guards._common import *  # noqa: F401,F403


def test_input_delimiters_flags_unwrapped_call(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('m')\n"
        "def handle(user_message):\n"
        "    return agent.run_sync(user_message)\n", encoding="utf-8"
    )
    findings = InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "input-delimiters/unwrapped-user-input"
    assert findings[0].severity == "medium"

def test_input_delimiters_silent_with_wrapping(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('m')\n"
        "def handle(user_message):\n"
        "    prompt = f'<user_input>{user_message}</user_input>'\n"
        "    return agent.run_sync(prompt)\n", encoding="utf-8"
    )
    assert InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_input_delimiters_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent  # security: allow-undelimited-input\n"
        "agent = Agent('m')\n"
        "def handle(user_message):\n"
        "    return agent.run_sync(user_message)\n", encoding="utf-8"
    )
    assert InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_input_delimiters_pragma_phrase_in_a_string_is_neither_pragma_nor_delimiter(tmp_path: Path) -> None:
    # #424 E1: the guard's own pragma phrase contains `delimit` (`allow-UNdelimited-input`), and the
    # mitigation regex's bare `delimit` token read it as delimiter evidence — so quoting the opt-out
    # in a string (help text, a docstring) silenced the file twice over. Now neither half counts:
    # a pragma must be a comment, and `\bdelimit` does not match inside `undelimited`.
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        'HELP = "opt out with `# security: allow-undelimited-input`"\n'
        "agent = Agent('m')\n"
        "def handle(user_message):\n"
        "    return agent.run_sync(user_message)\n", encoding="utf-8"
    )
    assert len(InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path))) == 1

def test_input_delimiters_delimit_helper_still_counts_as_mitigation(tmp_path: Path) -> None:
    # The direction traded against (CLAUDE.md rule 1): a real `delimit_*` wrapping helper is still
    # delimiter evidence under the word-boundaried token.
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('m')\n"
        "def handle(user_message):\n"
        "    return agent.run_sync(delimit_input(user_message))\n", encoding="utf-8"
    )
    assert InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_input_delimiters_silent_without_llm_call(tmp_path: Path) -> None:
    # user input present, but the model is never invoked
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('m')\n"
        "def handle(user_message):\n"
        "    return user_message.upper()\n", encoding="utf-8"
    )
    assert InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_input_delimiters_silent_without_user_input(tmp_path: Path) -> None:
    # the model is invoked, but only with a constant prompt (no user-input token)
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('m')\n"
        "def daily_summary():\n"
        "    return agent.run_sync('Summarize today in one sentence.')\n", encoding="utf-8"
    )
    assert InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_input_delimiters_not_applicable_without_llm() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert InputDelimitersGuard().applies(prof) is False



def test_input_delimiters_skips_alembic_migration_code(tmp_path: Path) -> None:
    # §A.2: LLM-input framing does not apply to migration plumbing — `alembic/` is skipped.
    d = tmp_path / "alembic"
    d.mkdir()
    (d / "env.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('m')\n"
        "def handle(user_message):\n"
        "    return agent.run_sync(user_message)\n", encoding="utf-8"
    )
    assert InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# --- #484 review (B1/B2): the skip must not void the pragma or the mitigation ------------------

def _unwrapped_app(root: Path) -> None:
    (root / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('m')\n"
        "def handle(user_message):\n"
        "    return agent.run_sync(user_message)\n", encoding="utf-8"
    )


def test_pragma_in_a_nonproduct_path_still_opts_out(tmp_path: Path) -> None:
    # The `is_nonproduct_path` skip sat INSIDE the file-collection loop and the pragma pass iterated
    # only the collected files, so a pragma under `tests/` was never seen and the guard fired at a
    # user who had already suppressed it (#484 review, B1).
    _unwrapped_app(tmp_path)
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_agent.py").write_text(
        "# security: allow-undelimited-input\ndef test_x(): ...\n", encoding="utf-8"
    )
    assert InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_delimiter_helper_in_a_nonproduct_path_still_counts_as_mitigation(tmp_path: Path) -> None:
    # The mitigation half: a wrapping helper defined under `e2e/` stopped counting (#484 review).
    _unwrapped_app(tmp_path)
    e2e = tmp_path / "e2e"
    e2e.mkdir()
    (e2e / "helpers.py").write_text(
        "def wrap(user_message):\n"
        "    return f'<user_input>{user_message}</user_input>'\n", encoding="utf-8"
    )
    assert InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_pragma_in_an_opted_in_archive_path_still_opts_out(tmp_path: Path) -> None:
    # #484 review, B2: opting `old/` into `archive_paths` also removed the pragma from view, so an
    # unrelated FP-reduction setting silently revoked a repo-level opt-out.
    _unwrapped_app(tmp_path)
    old = tmp_path / "old"
    old.mkdir()
    (old / "legacy.py").write_text("# security: allow-undelimited-input\n", encoding="utf-8")
    prof = _llm_prof(tmp_path)
    prof.archive_segments = frozenset({"old"})
    assert InputDelimitersGuard().run(tmp_path, prof) == []


def test_user_input_only_in_test_code_does_not_fire(tmp_path: Path) -> None:
    # The direction that keeps `_USER_INPUT` product-scoped (F4). It is a PRECONDITION, not a
    # mitigation: it asks whether the deployed app handles untrusted input at all. Widening the
    # mitigation pass to every file must NOT widen this one, or a product LLM call with no user
    # input starts firing because a test fixture mentions `user_message`.
    # NB the product literal deliberately avoids every `_USER_INPUT` token: `prompt`, `message`,
    # `query`, `request`, `question`, `form`, `payload`, `user_`. A first draft of this test used
    # `'static prompt'` and fired on its own fixture.
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('m')\n"
        "def summarize():\n"
        "    return agent.run_sync('summarize the changelog')\n", encoding="utf-8"
    )
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_agent.py").write_text("def test_x(user_message):\n    return user_message\n", encoding="utf-8")
    assert InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_llm_call_only_in_a_nonproduct_path_still_does_not_fire(tmp_path: Path) -> None:
    # The other FP direction: the anchor stays product-only, so an example script is not the
    # deployed app's LLM call site (round-2 A.2).
    examples = tmp_path / "examples"
    examples.mkdir()
    _unwrapped_app(examples)
    assert InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# --- #717: the bare `.run(` arm anchored on process / event-loop runners ------------------------
# A NARROWING, so both directions are pinned: the runners must stop anchoring AND every real LLM
# call shape must keep anchoring. The measured symptom was a report pointing at `subprocess.run(`
# in a `.claude/` skill reference (a RAG app) and at `uvicorn.run(app, ...)` in the flagship.

def test_process_and_loop_runners_do_not_anchor(tmp_path: Path) -> None:
    # FP-bait: user input is present and nothing is delimited, but the only `.run(` calls in the
    # repo are a subprocess / event-loop / web-server runner. None of them is an LLM call, so there
    # is no call site to anchor and the guard must stay silent.
    (tmp_path / "app.py").write_text(
        "import asyncio, subprocess, uvicorn\n"
        "def handle(user_message):\n"
        "    result = subprocess.run(user_message, shell=True)\n"
        "    asyncio.run(main())\n"
        "    uvicorn.run(app, host='0.0.0.0', port=8001)\n"
        "    return result\n",
        encoding="utf-8",
    )
    assert InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_nested_asyncio_run_does_not_anchor(tmp_path: Path) -> None:
    # `sys.exit(asyncio.run(main()))` — the receiver is still `asyncio`, so the lookbehind must hold
    # inside a nested call too (this exact line is in a script in a RAG app).
    (tmp_path / "app.py").write_text(
        "import asyncio, sys\n"
        "def handle(user_message):\n"
        "    return sys.exit(asyncio.run(main(user_message)))\n",
        encoding="utf-8",
    )
    assert InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_pydantic_ai_agent_run_still_anchors(tmp_path: Path) -> None:
    # The direction traded against: `agent.run(...)` is a REAL pydantic-ai call. Narrowing the arm
    # must not kill it (the flagship's real call site is `title_agent.run(prompt)`).
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "title_agent = Agent('m')\n"
        "async def handle(user_message):\n"
        "    return await title_agent.run(user_message)\n",
        encoding="utf-8",
    )
    findings = InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith("agent.py:4")


def test_openai_completions_create_still_anchors(tmp_path: Path) -> None:
    # The other real shape, and the one the RAG app's corrected anchor lands on.
    (tmp_path / "llm.py").write_text(
        "async def handle(user_message):\n"
        "    return await client.chat.completions.create(messages=user_message)\n",
        encoding="utf-8",
    )
    findings = InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith("llm.py:2")


def test_runner_file_does_not_steal_the_anchor_from_the_real_llm_call(tmp_path: Path) -> None:
    # The RAG-app shape end-to-end: a runner file sorts FIRST and used to win the first-match race,
    # so the report named it instead of the real call site. The anchor must cross to the LLM file.
    (tmp_path / "aaa_runner.py").write_text(
        "import subprocess\n"
        "def check(user_message):\n"
        "    return subprocess.run('pytest -q', shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "zzz_llm.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('m')\n"
        "def handle(user_message):\n"
        "    return agent.run_sync(user_message)\n",
        encoding="utf-8",
    )
    findings = InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith("zzz_llm.py:4"), findings[0].location


def test_suffix_collision_receiver_still_anchors(tmp_path: Path) -> None:
    # #725 review: the runner exclusions must be IDENTIFIER-scoped, not suffix-scoped. Without the
    # `\b` in each lookbehind, any receiver merely ENDING in an excluded word was swallowed, so a
    # genuine LLM call site went silent — a worse failure than the mislocation #717 fixed, because
    # nothing is reported at all (Rule 3: a failure that presents as success).
    (tmp_path / "agent.py").write_text(
        "def handle(user_message):\n"
        "    return my_subprocess.run(user_message)\n",
        encoding="utf-8",
    )
    findings = InputDelimitersGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith("agent.py:2"), findings[0].location


def test_every_runner_receiver_is_still_suppressed(tmp_path: Path) -> None:
    # The direction traded against by adding `\b`: the real runners must ALL still be excluded, so
    # the boundary fix cannot quietly undo the #717 narrowing itself.
    for receiver in (
        "asyncio", "subprocess", "trio", "anyio", "uvicorn",
        "gunicorn", "unittest", "pytest", "nox", "tox",
    ):
        d = tmp_path / receiver
        d.mkdir()
        (d / "app.py").write_text(
            f"def handle(user_message):\n    return {receiver}.run(user_message)\n",
            encoding="utf-8",
        )
        assert InputDelimitersGuard().run(d, _llm_prof(d)) == [], receiver
