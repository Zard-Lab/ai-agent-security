from __future__ import annotations

from agentsec.guards.llm_response_logged import LlmResponseLoggedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_llm_response_logged_flags_run_sync_in_logger(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "logger.info(agent.run_sync(question))\n",
        encoding="utf-8",
    )
    findings = LlmResponseLoggedGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-response-logged/model-output-to-logger" in rules

def test_llm_response_logged_flags_invoke_in_logging(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import logging\n"
        "logging.debug(chain.invoke({'question': q}))\n",
        encoding="utf-8",
    )
    findings = LlmResponseLoggedGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-response-logged/model-output-to-logger" in rules

def test_llm_response_logged_flags_predict_in_logger(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "logger.warning(llm.predict(system_prompt))\n",
        encoding="utf-8",
    )
    findings = LlmResponseLoggedGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-response-logged/model-output-to-logger" in rules

def test_llm_response_logged_silent_for_response_in_variable(tmp_path: Path) -> None:
    # Response captured in variable first — safe pattern (can be redacted before logging).
    (tmp_path / "app.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "response = agent.run_sync(question)\n"
        "logger.info({'status': 'ok'})\n",
        encoding="utf-8",
    )
    assert LlmResponseLoggedGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_response_logged_silent_for_non_llm_log(tmp_path: Path) -> None:
    # Logging a plain string, not a model invoke.
    (tmp_path / "app.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "logger.info('Request received')\n",
        encoding="utf-8",
    )
    assert LlmResponseLoggedGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_response_logged_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "# security: allow-llm-response-log\n"
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "logger.info(agent.run_sync(question))\n",
        encoding="utf-8",
    )
    assert LlmResponseLoggedGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_response_logged_not_applicable_without_llm_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python", "fastapi"})
    assert LlmResponseLoggedGuard().applies(prof) is False



# ── #425: one finding per offending line, not one per repo ─────────────────────────


def test_llm_response_logged_reports_every_offending_line(tmp_path: Path) -> None:
    # Regression for #425: _check_direct_log returned its first hit from inside the
    # all-files loop, so N logged responses reported 1 and an exception on that one hid
    # the rest. Two lines in one file plus one in another must give exactly three.
    (tmp_path / "chat_a.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "logger.info(agent.run_sync(question))\n"
        "logger.debug(chain.invoke({'question': q}))\n",
        encoding="utf-8",
    )
    (tmp_path / "chat_b.py").write_text(
        "import logging\n"
        "logging.warning(llm.predict(system_prompt))\n",
        encoding="utf-8",
    )
    findings = LlmResponseLoggedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 3
    assert {f.location for f in findings} == {"chat_a.py:3", "chat_a.py:4", "chat_b.py:2"}


def test_llm_response_logged_benign_line_after_a_hit_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the #425 widening: lines after the first hit used to be unreachable.
    # A redacted log of a captured response, after a real hit in the same file, must not
    # become a second finding now that the loop keeps going.
    (tmp_path / "chat.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "logger.info(agent.run_sync(question))\n"
        "response = agent.run_sync(question)\n"
        "logger.info({'chars': len(str(response))})\n",
        encoding="utf-8",
    )
    findings = LlmResponseLoggedGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.location for f in findings] == ["chat.py:3"]


def test_llm_response_logged_pragma_in_third_file_silences_all(tmp_path: Path) -> None:
    # The opt-out is repo-wide and must keep seeing every file after the #425 change.
    for name in ("chat_a.py", "chat_b.py"):
        (tmp_path / name).write_text(
            "import logging\nlogger = logging.getLogger(__name__)\nlogger.info(agent.run_sync(q))\n",
            encoding="utf-8",
        )
    (tmp_path / "zz_settings.py").write_text("# security: allow-llm-response-log\n", encoding="utf-8")
    assert LlmResponseLoggedGuard().run(tmp_path, _llm_prof(tmp_path)) == []
