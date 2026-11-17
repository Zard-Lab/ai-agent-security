from __future__ import annotations

from agentsec.guards.secret_str_serialized import SecretStrSerializedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_secret_str_serialized_flags_dict_serialize(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "from pydantic import BaseModel, SecretStr\n"
        "logger = logging.getLogger(__name__)\n"
        "class UserAuth(BaseModel):\n"
        "    username: str\n"
        "    password: SecretStr\n"
        "def handle(u, p):\n"
        "    auth = UserAuth(username=u, password=p)\n"
        "    logger.info(auth.dict())\n",
        encoding="utf-8",
    )
    findings = SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "secret-str-serialized/serialized-logged"
    assert findings[0].severity == "high"


def test_secret_str_serialized_flags_model_dump_json(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "from pydantic import BaseModel, SecretStr\n"
        "logger = logging.getLogger(__name__)\n"
        "class UserAuth(BaseModel):\n"
        "    password: SecretStr\n"
        "def handle(p):\n"
        "    auth = UserAuth(password=p)\n"
        "    logger.info(auth.model_dump_json())\n",
        encoding="utf-8",
    )
    findings = SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert any(f.rule == "secret-str-serialized/serialized-logged" for f in findings)


def test_secret_str_serialized_flags_dict_call_wrap(tmp_path: Path) -> None:
    # `dict(model_instance)` is the fourth documented unmasking form.
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "from pydantic import BaseModel, SecretStr\n"
        "logger = logging.getLogger(__name__)\n"
        "class UserAuth(BaseModel):\n"
        "    password: SecretStr\n"
        "def handle(p):\n"
        "    auth = UserAuth(password=p)\n"
        "    logger.info(dict(auth))\n",
        encoding="utf-8",
    )
    findings = SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert any(f.rule == "secret-str-serialized/serialized-logged" for f in findings)


def test_secret_str_serialized_flags_bare_instance_print(tmp_path: Path) -> None:
    # The instance itself flowing to a sink (print(), not just logger.*) is case (i) — a
    # different loggers/formatters/structured-logging integration may still serialize it.
    (tmp_path / "h.py").write_text(
        "from pydantic import BaseModel, SecretStr\n"
        "class UserAuth(BaseModel):\n"
        "    password: SecretStr\n"
        "def handle(p):\n"
        "    auth = UserAuth(password=p)\n"
        "    print(auth)\n",
        encoding="utf-8",
    )
    findings = SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "secret-str-serialized/instance-logged"


def test_secret_str_serialized_flags_str_wrapped_instance(tmp_path: Path) -> None:
    # str(instance) — no field access — is still the whole instance flowing to the sink, distinct
    # from str(instance.field), which is the deliberate field-level unmask this guard excludes.
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "from pydantic import BaseModel, SecretStr\n"
        "logger = logging.getLogger(__name__)\n"
        "class UserAuth(BaseModel):\n"
        "    password: SecretStr\n"
        "def handle(p):\n"
        "    auth = UserAuth(password=p)\n"
        "    logger.info(str(auth))\n",
        encoding="utf-8",
    )
    findings = SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert any(f.rule == "secret-str-serialized/instance-logged" for f in findings)


def test_secret_str_serialized_flags_sentry_capture(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import sentry_sdk\n"
        "from pydantic import BaseModel, SecretStr\n"
        "class UserAuth(BaseModel):\n"
        "    password: SecretStr\n"
        "def handle(p):\n"
        "    auth = UserAuth(password=p)\n"
        "    sentry_sdk.capture_message(auth.model_dump())\n",
        encoding="utf-8",
    )
    findings = SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert any(f.rule == "secret-str-serialized/serialized-logged" for f in findings)


def test_secret_str_serialized_silent_when_never_logged(tmp_path: Path) -> None:
    # FP-bait: a SecretStr field that's never logged/serialized at all stays silent.
    (tmp_path / "h.py").write_text(
        "from pydantic import BaseModel, SecretStr\n"
        "class UserAuth(BaseModel):\n"
        "    password: SecretStr\n"
        "def handle(p):\n"
        "    auth = UserAuth(password=p)\n"
        "    return auth\n",
        encoding="utf-8",
    )
    assert SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_secret_str_serialized_silent_without_secretstr_field(tmp_path: Path) -> None:
    # FP-bait: a model with NO SecretStr field stays silent even if serialized and logged.
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "from pydantic import BaseModel\n"
        "logger = logging.getLogger(__name__)\n"
        "class Plain(BaseModel):\n"
        "    username: str\n"
        "def handle(u):\n"
        "    m = Plain(username=u)\n"
        "    logger.info(m.dict())\n",
        encoding="utf-8",
    )
    assert SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_secret_str_serialized_silent_on_explicit_get_secret_value(tmp_path: Path) -> None:
    # FP-bait: an explicit, deliberate field-level unmask (`.get_secret_value()`) is a different,
    # already fairly obvious mistake — not this guard's target.
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "from pydantic import BaseModel, SecretStr\n"
        "logger = logging.getLogger(__name__)\n"
        "class UserAuth(BaseModel):\n"
        "    password: SecretStr\n"
        "def handle(p):\n"
        "    auth = UserAuth(password=p)\n"
        "    logger.info(auth.password.get_secret_value())\n",
        encoding="utf-8",
    )
    assert SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_secret_str_serialized_silent_on_explicit_str_field(tmp_path: Path) -> None:
    # FP-bait, the str() mirror of the test above: str(instance.FIELD) is a deliberate field-level
    # unmask, distinct from str(instance) (which fires — see the bare-instance test above).
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "from pydantic import BaseModel, SecretStr\n"
        "logger = logging.getLogger(__name__)\n"
        "class UserAuth(BaseModel):\n"
        "    password: SecretStr\n"
        "def handle(p):\n"
        "    auth = UserAuth(password=p)\n"
        "    logger.info(str(auth.password))\n",
        encoding="utf-8",
    )
    assert SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_secret_str_serialized_silent_on_message_prose(tmp_path: Path) -> None:
    # FP-bait: the instance var name mentioned inside a plain log MESSAGE string (not a live
    # interpolated value) must not fire — the code-view control.
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "from pydantic import BaseModel, SecretStr\n"
        "logger = logging.getLogger(__name__)\n"
        "class UserAuth(BaseModel):\n"
        "    password: SecretStr\n"
        "def handle(p):\n"
        "    auth = UserAuth(password=p)\n"
        "    logger.info('auth object created successfully')\n",
        encoding="utf-8",
    )
    assert SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_secret_str_serialized_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "from pydantic import BaseModel, SecretStr\n"
        "logger = logging.getLogger(__name__)\n"
        "class UserAuth(BaseModel):\n"
        "    password: SecretStr\n"
        "def handle(p):\n"
        "    auth = UserAuth(password=p)\n"
        "    logger.info(auth.dict())  # security: allow-secret-str-log\n",
        encoding="utf-8",
    )
    assert SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_secret_str_serialized_flags_optional_secretstr_field(tmp_path: Path) -> None:
    # `Optional[SecretStr]` / `SecretStr | None` must still count as a SecretStr-carrying field.
    (tmp_path / "h.py").write_text(
        "import logging\n"
        "from typing import Optional\n"
        "from pydantic import BaseModel, SecretStr\n"
        "logger = logging.getLogger(__name__)\n"
        "class UserAuth(BaseModel):\n"
        "    password: Optional[SecretStr] = None\n"
        "def handle(p):\n"
        "    auth = UserAuth(password=p)\n"
        "    logger.info(auth.model_dump())\n",
        encoding="utf-8",
    )
    findings = SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert any(f.rule == "secret-str-serialized/serialized-logged" for f in findings)


def test_secret_str_serialized_not_applicable_without_python() -> None:
    prof = mkprofile(Path("/tmp"), features={"frontend"})
    assert SecretStrSerializedGuard().applies(prof) is False


def _secret_str_log(above: str, tail: str) -> str:
    return (
        "import logging\n"
        "from pydantic import BaseModel, SecretStr\n"
        "logger = logging.getLogger(__name__)\n"
        "class UserAuth(BaseModel):\n"
        "    password: SecretStr\n"
        "def handle(p):\n"
        "    auth = UserAuth(password=p)\n"
        f"{above}"
        f"    logger.info(auth.dict()){tail}\n"
    )


def test_secret_str_serialized_pragma_quoted_in_a_string_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the call's line or the line above is not a comment;
    # neutral run = control.
    for note in ("# reviewed", "# security: allow-secret-str-log"):
        for source in (_secret_str_log("", f'; _note = "{note}"'), _secret_str_log(f'    _note = "{note}"\n', "")):
            (tmp_path / "h.py").write_text(source, encoding="utf-8")
            findings = SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path))
            assert [f.rule for f in findings] == ["secret-str-serialized/serialized-logged"], (note, source)


def test_secret_str_serialized_pragma_comment_reach_is_the_line_and_the_line_above(tmp_path: Path) -> None:
    # #1040 reach unchanged: a comment on the line above still suppresses; two lines above does not.
    pragma = "    # security: allow-secret-str-log\n"
    for above, n in ((pragma, 0), (pragma + "    x = 1\n", 1)):
        (tmp_path / "h.py").write_text(_secret_str_log(above, ""), encoding="utf-8")
        assert len(SecretStrSerializedGuard().run(tmp_path, _fastapi_prof(tmp_path))) == n, above
