from __future__ import annotations

from agentsec.guards.pydantic_model_construct import PydanticModelConstructGuard
from tests.guards._common import *  # noqa: F401,F403


def test_pydantic_model_construct_flags_model_construct(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "user = User.model_construct(**request_data)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = PydanticModelConstructGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "pydantic-model-construct/model-construct-bypass"
    assert findings[0].severity == "medium"

def test_pydantic_model_construct_flags_construct_v1(tmp_path: Path) -> None:
    (tmp_path / "models.py").write_text(
        'obj = MyModel.construct(name=data["name"])\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = PydanticModelConstructGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "pydantic-model-construct/model-construct-bypass"

def test_pydantic_model_construct_silent_safe_patterns(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text(
        "user = User(**request_data)\n"
        "user = User.model_validate(request_data)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = PydanticModelConstructGuard().run(tmp_path, profile)
    assert findings == []

def test_pydantic_model_construct_pragma_silences_file(tmp_path: Path) -> None:
    content = (
        "user = User.model_construct(**internal_data)  # security: allow-model-construct\n"
    )
    (tmp_path / "trusted.py").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = PydanticModelConstructGuard().run(tmp_path, profile)
    assert findings == []

def test_pydantic_model_construct_applies_gate(tmp_path: Path) -> None:
    guard = PydanticModelConstructGuard()
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"fastapi", "python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"frontend"})) is False
    assert guard.applies(mkprofile(tmp_path, features=set())) is False


def test_pydantic_model_construct_silent_sdk_options_reconstruction(tmp_path: Path) -> None:
    # Real FP (corpus scan, 2026-08-19): openai-python's FinalRequestOptions.construct(...) --
    # SDK-internal request-plumbing, none of the args name untrusted external input.
    (tmp_path / "_base_client.py").write_text(
        "def get(self, path, *, cast_to, options={}):\n"
        '    opts = FinalRequestOptions.construct(method="get", url=path, **options)\n'
        "    return self.request(cast_to, opts)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert PydanticModelConstructGuard().run(tmp_path, profile) == []

def test_pydantic_model_construct_silent_compat_shim_kwargs(tmp_path: Path) -> None:
    # Real FP: langchain_core/tracers/_compat.py -- a pydantic v1/v2 compat shim re-exposing
    # .model_construct() under a stable name for the SDK's own internal callers.
    (tmp_path / "_compat.py").write_text(
        "def run_construct(**kwargs):\n"
        "    return Run.model_construct(**kwargs)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert PydanticModelConstructGuard().run(tmp_path, profile) == []

def test_pydantic_model_construct_silent_response_reconstruction(tmp_path: Path) -> None:
    # Real FP: langchain_openai reconstructing an API RESPONSE object from the provider's
    # own response -- an output/response model, not an input model validating a request.
    (tmp_path / "base.py").write_text(
        "def _parse(resp):\n"
        "    return Response.model_construct(**resp)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert PydanticModelConstructGuard().run(tmp_path, profile) == []

def test_pydantic_model_construct_silent_on_marker_inside_string_value(tmp_path: Path) -> None:
    # Dean's review, High 1: the marker matched inside a quoted STRING VALUE, not just an
    # identifier name -- "database_row" contains the substring "data" with nothing
    # untrusted-input-shaped anywhere in the call.
    (tmp_path / "cfg.py").write_text(
        'cfg = InternalConfig.model_construct(source="database_row", owner="system")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert PydanticModelConstructGuard().run(tmp_path, profile) == []

def test_pydantic_model_construct_still_flags_identifier_in_value_position(tmp_path: Path) -> None:
    # Same shape as the FP-bait above, but the untrusted signal is a genuine Python
    # IDENTIFIER used as a subscript target in the value position, not a string literal --
    # must still fire. Guards against an over-broad fix for the FP above (a "kwarg names
    # only" first attempt at this fix broke exactly this case).
    (tmp_path / "app.py").write_text(
        'user = User.model_construct(name=request_data["name"])\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = PydanticModelConstructGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_pydantic_model_construct_flags_quoted_subscript_key(tmp_path: Path) -> None:
    # #686 fix-commit round, High 1: the untrusted signal named via a QUOTED subscript key
    # (not a bare identifier, unlike the test above) went silent -- `_blank_quoted_strings`
    # blanked every quoted string uniformly with no syntactic-position check, so
    # `row["request_data"]` lost the very substring the marker looks for.
    (tmp_path / "app.py").write_text(
        'user = User.model_construct(**row["request_data"])\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = PydanticModelConstructGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_pydantic_model_construct_flags_quoted_subscript_key_single_quotes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "user = User.model_construct(**d['payload'])\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = PydanticModelConstructGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_pydantic_model_construct_flags_quoted_dict_literal_key(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'user = User.model_construct(**{"data": untrusted})\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = PydanticModelConstructGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_pydantic_model_construct_value_position_string_still_silent(tmp_path: Path) -> None:
    # Still stays silent the OTHER direction: a quoted VALUE (not a key) must not be
    # exempted from blanking just because a bracket happens to sit nearby elsewhere on the
    # line -- guards against an over-broad key-position heuristic reopening the original FP
    # this guard's 2026-08-22 fix closed.
    (tmp_path / "app.py").write_text(
        'cfg = InternalConfig.model_construct(items=[1, 2], source="database_row")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert PydanticModelConstructGuard().run(tmp_path, profile) == []


def test_pydantic_model_construct_skips_nonproduct_path(tmp_path: Path) -> None:
    # A marker-matching call inside a tests/ tree is a test fixture, not product code --
    # matches the class of fix already applied to other guards.
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_models.py").write_text(
        "bad = SystemMessage.model_construct(**request_data)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert PydanticModelConstructGuard().run(tmp_path, profile) == []

def test_pydantic_model_construct_flags_multiline_call(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "user = User.model_construct(\n"
        "    name=request_data[\"name\"],\n"
        "    role=request_data[\"role\"],\n"
        ")\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = PydanticModelConstructGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].location.endswith(":1")

def test_pydantic_model_construct_silent_on_docstring_example(tmp_path: Path) -> None:
    # FP-bait (#424): .model_construct( / .construct( EXAMPLES inside a docstring must not fire
    # (this guard's own module docstring self-matches). strip_python_strings blanks it.
    (tmp_path / "m.py").write_text(
        '"""Dangerous:\n'
        "\n"
        "    user = User.model_construct(**request_data)\n"
        "    obj = MyModel.construct(name=data['name'])\n"
        '"""\n'
        "import pydantic\n",
        encoding="utf-8",
    )
    assert PydanticModelConstructGuard().run(tmp_path, _pyprof(tmp_path)) == []

