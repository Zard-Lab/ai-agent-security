from __future__ import annotations

from agentsec.guards.log_injection import LogInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_log_injection_flags_logger_fstring(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "logger.info(f\"User {request.headers['X-User']} logged in\")\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "log-injection/user-input-in-log"
    assert findings[0].severity == "medium"
    assert "log-injection" in findings[0].check_id

def test_log_injection_flags_logging_query_params(tmp_path: Path) -> None:
    (tmp_path / "api.py").write_text(
        'logging.debug(f"Query: {request.query_params}")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "log-injection/user-input-in-log"

def test_log_injection_silent_safe_variable(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        'logger.info(f"User {user_id} logged in")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert findings == []

def test_log_injection_silent_plain_string(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        'logger.info("Request received")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert findings == []

def test_log_injection_pragma_silences(tmp_path: Path) -> None:
    content = (
        "logger.info(f\"User {request.headers['X-User']} logged in\")\n"
        "# security: allow-log-injection\n"
    )
    (tmp_path / "views.py").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert findings == []

def test_log_injection_applies_gate(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "logger.info(f\"User {request.headers['X-User']} logged in\")\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"java", "fastapi"}, python_dirs=["."])
    assert not LogInjectionGuard().applies(profile)

def test_log_injection_flags_string_concat(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "logging.info(\"User \" + request.headers['X-User'] + \" logged in\")\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "log-injection/user-input-in-log"

def test_log_injection_flags_dot_format(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "logging.info(\"User {}\".format(request.headers['X-User']))\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "log-injection/user-input-in-log"

def test_log_injection_flags_eager_percent_format(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "logging.info(\"User %s\" % request.headers['X-User'])\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "log-injection/user-input-in-log"

def test_log_injection_silent_lazy_percent_format(tmp_path: Path) -> None:
    # Lazy %-style logging (value as a separate positional arg) is the
    # recommended-safe form — the logging module itself defers formatting
    # and callers are not expected to pre-escape it. Must NOT fire.
    (tmp_path / "views.py").write_text(
        "logging.info(\"User %s logged in\", request.headers['X-User'])\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert findings == []

def test_log_injection_silent_safe_dot_format(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        'logging.info("Processed {} items".format(count))\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert findings == []

def test_log_injection_silent_tainted_value_in_lazy_arg(tmp_path: Path) -> None:
    # #395 M7: the eager interp bakes in a SAFE value (region) while the tainted value is passed
    # as a separate LAZY positional arg — the recommended-safe form, must not fire.
    (tmp_path / "views.py").write_text(
        'logging.info("Region " + region + " user %s", request.headers["X-User"])\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert findings == []

def test_log_injection_fires_with_paren_in_message_string(tmp_path: Path) -> None:
    # #395 RM-2: a `)` inside the message's own string literal must not truncate first-arg
    # extraction and drop a real finding — the extractor is quote-aware.
    (tmp_path / "views.py").write_text(
        'logging.info(f"Step 2) verifying user {request.headers[\'X-User\']}")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "log-injection/user-input-in-log"



# ── Extension: @tool-decorated function parameter (CVE-2026-6494 class) ─────────

def test_log_injection_flags_tool_param_fstring(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "@tool\n"
        "def lookup_user(username: str) -> str:\n"
        "    logger.info(f\"Looking up {username}\")\n"
        "    return db.get(username)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "llm"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert any(f.rule == "log-injection/tool-param-in-log" for f in findings)


def test_log_injection_flags_attribute_tool_decorator(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "@agent.tool()\n"
        "def send_email(recipient: str, body: str) -> None:\n"
        "    logging.info(\"Sending to \" + recipient)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "llm"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert any(f.rule == "log-injection/tool-param-in-log" for f in findings)


def test_log_injection_silent_non_tool_function_same_param_name(tmp_path: Path) -> None:
    """FP-bait: an ordinary (non-@tool) function's parameter of the same name must not fire —
    only a function this guard structurally resolved as @tool-decorated is in scope."""
    (tmp_path / "helpers.py").write_text(
        "def lookup_user(username: str) -> str:\n"
        "    logger.info(f\"Looking up {username}\")\n"
        "    return db.get(username)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "llm"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert findings == []


def test_log_injection_silent_tool_function_unrelated_variable(tmp_path: Path) -> None:
    """FP-bait: a variable that is NOT one of the tool function's own parameters must not fire,
    even inside a @tool-decorated function's body."""
    (tmp_path / "tools.py").write_text(
        "@tool\n"
        "def lookup_user(username: str) -> str:\n"
        "    status = 'ok'\n"
        "    logger.info(f\"Lookup finished: {status}\")\n"
        "    return db.get(username)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "llm"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert findings == []


def test_log_injection_silent_tool_param_outside_function_range(tmp_path: Path) -> None:
    """FP-bait: a later, unrelated function using a same-named variable outside the tool
    function's own line range must not fire."""
    (tmp_path / "tools.py").write_text(
        "@tool\n"
        "def lookup_user(username: str) -> str:\n"
        "    return db.get(username)\n"
        "\n"
        "\n"
        "def unrelated(username: str) -> None:\n"
        "    logger.info(f\"unrelated: {username}\")\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "llm"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert findings == []


def test_log_injection_tool_param_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "# security: allow-log-injection\n"
        "@tool\n"
        "def lookup_user(username: str) -> str:\n"
        "    logger.info(f\"Looking up {username}\")\n"
        "    return db.get(username)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "llm"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert findings == []


def test_log_injection_silent_tool_param_name_only_in_fstring_prose(tmp_path: Path) -> None:
    """FP-bait: a parameter name that appears only in the message's literal prose (outside the
    `{...}` fields) is not an interpolated value."""
    (tmp_path / "tools.py").write_text(
        "@tool\n"
        "def f(id):\n"
        "    other = 'x'\n"
        "    logger.info(f\"looking up id for record: {other!r}\")\n"
        "    return 1\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "llm"}, python_dirs=["."])
    assert LogInjectionGuard().run(tmp_path, profile) == []


def test_log_injection_silent_tool_param_name_only_in_concat_literal(tmp_path: Path) -> None:
    """FP-bait: same rule for concatenation, where the parameter name is inside a string literal."""
    (tmp_path / "tools.py").write_text(
        "@tool\n"
        "def f(id):\n"
        "    other = 'x'\n"
        "    logger.info(\"looking up id for \" + other)\n"
        "    return 1\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "llm"}, python_dirs=["."])
    assert LogInjectionGuard().run(tmp_path, profile) == []


def test_log_injection_flags_tool_param_in_fstring_field_with_conversion(tmp_path: Path) -> None:
    """Still fires (the traded-against direction): the parameter is inside a `{...}` field, with
    a conversion, an expression around it, and prose that also mentions another parameter."""
    (tmp_path / "tools.py").write_text(
        "@tool\n"
        "def f(id):\n"
        "    logger.info(f\"other is fine, id={id.strip()!r} for record\")\n"
        "    return 1\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "llm"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert any(f.rule == "log-injection/tool-param-in-log" for f in findings)


def test_log_injection_flags_tool_param_in_format_and_percent_args(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "@tool\n"
        "def f(id, other):\n"
        "    logger.info(\"id is {}\".format(id))\n"
        "    logger.warning(\"id is %s\" % id)\n"
        "    return 1\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "llm"}, python_dirs=["."])
    findings = LogInjectionGuard().run(tmp_path, profile)
    assert sorted(f.location for f in findings if f.rule == "log-injection/tool-param-in-log") == [
        "tools.py:3", "tools.py:4",
    ]
