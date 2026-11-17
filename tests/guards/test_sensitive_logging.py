from __future__ import annotations

from agentsec.guards.sensitive_logging import SensitiveLoggingGuard
from tests.guards._common import *  # noqa: F401,F403


def test_sensitive_logging_flags_request_body(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "async def handler(request):\n"
        "    logger.info(await request.json())\n", encoding="utf-8"
    )
    findings = SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "sensitive-logging/request-body-logged"
    assert findings[0].severity == "high"

def test_sensitive_logging_flags_sensitive_field(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def auth(api_key):\n"
        "    logger.warning(f'using key={api_key}')\n", encoding="utf-8"
    )
    findings = SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "sensitive-logging/sensitive-field-logged"
    assert findings[0].severity == "medium"

def test_sensitive_logging_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "async def handler(request):\n"
        "    logger.info(await request.json())  # security: allow-sensitive-log\n", encoding="utf-8"
    )
    assert SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_sensitive_logging_silent_on_safe_log(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def view(uid):\n"
        "    logger.info('user logged in', extra={'id': uid})\n", encoding="utf-8"
    )
    assert SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_sensitive_logging_silent_on_message_word(tmp_path: Path) -> None:
    # a sensitive word inside a plain message string is NOT a logged value (code-view control)
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def view():\n"
        "    logger.info('password reset email sent')\n"
        "    logger.error('invalid password attempt')\n", encoding="utf-8"
    )
    assert SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_sensitive_logging_silent_on_nonf_string_brace(tmp_path: Path) -> None:
    # FP-bait (#424): a `{password}` inside a NON-f string (or a .format template / dict literal)
    # is not a live interpolated value; only f-string interpolations should be harvested.
    (tmp_path / "s.py").write_text(
        "import logging\nlogger = logging.getLogger(__name__)\n"
        'logger.info("template {password} placeholder")\n',
        encoding="utf-8",
    )
    assert SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_sensitive_logging_flags_dict_literal_extra(tmp_path: Path) -> None:
    # The #439 re-gate regression: `extra={"password": pwd}` is the canonical Python
    # structured-logging idiom and it fired on main, but the #424 literal-blanking erased the key
    # before the field markers ran, so the guard went silent on it. Narrowing direction (CLAUDE.md
    # rule 1): the vulnerable case must still fire. Recovered structurally via the trailing `:`,
    # NOT by re-widening the `{…}` scan — the FP-bait tests below pin that distinction.
    (tmp_path / "s.py").write_text(
        "import logging\nlogger = logging.getLogger(__name__)\n"
        'logger.info("event", extra={"password": pwd})\n',
        encoding="utf-8",
    )
    rules = {f.rule for f in SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "sensitive-logging/sensitive-field-logged" in rules


def test_sensitive_logging_silent_on_redacted_dict_value(tmp_path: Path) -> None:
    # FP-bait for the widening above: a CONSTANT value is a redaction, not a leak. Only a live
    # (non-constant) value makes the key a logged secret.
    (tmp_path / "s.py").write_text(
        "import logging\nlogger = logging.getLogger(__name__)\n"
        'logger.info("event", extra={"password": "REDACTED"})\n'
        'logger.info("event", extra={"api_key": None})\n',
        encoding="utf-8",
    )
    assert SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_sensitive_logging_silent_on_dict_written_inside_a_string(tmp_path: Path) -> None:
    # FP-bait for the widening above: dict-LOOKING text inside a plain string literal is prose,
    # not a dict. The outer literal consumes it, so no key/`:` pair is ever reachable.
    (tmp_path / "s.py").write_text(
        "import logging\nlogger = logging.getLogger(__name__)\n"
        'logger.info(\'sample payload: {"password": pwd}\')\n',
        encoding="utf-8",
    )
    assert SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_sensitive_logging_silent_on_docstring_example(tmp_path: Path) -> None:
    # FP-bait (#424): the module docstring has `logger.info(request.body())`; a docstring example
    # must not self-match (strip_python_strings blanks it).
    (tmp_path / "s.py").write_text(
        '"""Do not do logger.info(request.body()) here."""\n'
        "x = 1\n",
        encoding="utf-8",
    )
    assert SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_sensitive_logging_not_applicable_without_python() -> None:
    prof = mkprofile(Path("/tmp"), features={"frontend"})
    assert SensitiveLoggingGuard().applies(prof) is False

def test_sensitive_logging_flags_full_request_headers(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "async def handler(request):\n"
        "    logger.info(request.headers)\n", encoding="utf-8"
    )
    findings = SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "sensitive-logging/request-headers-logged"
    assert findings[0].severity == "high"

def test_sensitive_logging_flags_dict_request_headers(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "async def handler(request):\n"
        "    logger.debug(dict(request.headers))\n", encoding="utf-8"
    )
    findings = SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "sensitive-logging/request-headers-logged"

def test_sensitive_logging_silent_on_single_header_extraction(tmp_path: Path) -> None:
    # FP-bait: pulling one specific, non-sensitive header is a common, lower-risk pattern.
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "async def handler(request):\n"
        "    logger.info(request.headers.get('User-Agent'))\n", encoding="utf-8"
    )
    assert SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []



def _request_body_log(above: str, tail: str) -> str:
    return (
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "async def handler(request):\n"
        f"{above}"
        f"    logger.info(await request.json()){tail}\n"
    )


def test_sensitive_logging_pragma_quoted_in_a_string_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the call's line or the line above is not a comment;
    # neutral run = control.
    for note in ("# reviewed", "# security: allow-sensitive-log"):
        for source in (_request_body_log("", f'; _note = "{note}"'), _request_body_log(f'    _note = "{note}"\n', "")):
            (tmp_path / "h.py").write_text(source, encoding="utf-8")
            assert len(SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path))) == 1, (note, source)


def test_sensitive_logging_pragma_comment_reach_is_the_line_and_the_line_above(tmp_path: Path) -> None:
    # #1040 reach unchanged: a comment on the line above still suppresses; two lines above does not.
    pragma = "    # security: allow-sensitive-log\n"
    for above, n in ((pragma, 0), (pragma + "    x = 1\n", 1)):
        (tmp_path / "h.py").write_text(_request_body_log(above, ""), encoding="utf-8")
        assert len(SensitiveLoggingGuard().run(tmp_path, _fastapi_prof(tmp_path))) == n, above
