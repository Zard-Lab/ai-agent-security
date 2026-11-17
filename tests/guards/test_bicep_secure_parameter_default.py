from __future__ import annotations

from agentsec.guards.bicep_secure_parameter_default import BicepSecureParameterDefaultGuard
from tests.guards._common import *  # noqa: F401,F403


def _bicepprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"bicep"})


def test_bicep_secure_parameter_default_flags_string_literal(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbPassword string = 'hunter2'\n",
        encoding="utf-8",
    )
    findings = BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-secure-parameter-default/hardcoded-literal-default"
    assert findings[0].severity == "high"


def test_bicep_secure_parameter_default_flags_nonempty_object_literal(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbConfig object = { password: 'hunter2' }\n",
        encoding="utf-8",
    )
    findings = BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-secure-parameter-default/hardcoded-literal-default"


def test_bicep_secure_parameter_default_flags_nonempty_array_literal(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbSecrets array = [ 'hunter2' ]\n",
        encoding="utf-8",
    )
    findings = BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-secure-parameter-default/hardcoded-literal-default"


def test_bicep_secure_parameter_default_silent_on_no_default(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbPassword string\n",
        encoding="utf-8",
    )
    assert BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_secure_parameter_default_silent_on_empty_string_default(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbPassword string = ''\n",
        encoding="utf-8",
    )
    assert BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_secure_parameter_default_silent_on_empty_triple_quoted_default(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbPassword string = ''''''\n",
        encoding="utf-8",
    )
    assert BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_secure_parameter_default_silent_on_empty_object_default(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbConfig object = {}\n",
        encoding="utf-8",
    )
    assert BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_secure_parameter_default_silent_on_empty_array_default(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbSecrets array = []\n",
        encoding="utf-8",
    )
    assert BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_secure_parameter_default_silent_on_reference_expression(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "param otherParam string\n"
        "@secure()\n"
        "param dbPassword string = otherParam\n",
        encoding="utf-8",
    )
    assert BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_secure_parameter_default_silent_on_function_call_expression(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbPassword string = newGuid()\n",
        encoding="utf-8",
    )
    assert BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_secure_parameter_default_silent_when_not_secure_decorated(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "param environmentName string = 'production'\n",
        encoding="utf-8",
    )
    assert BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_secure_parameter_default_not_applicable_without_bicep() -> None:
    prof = mkprofile(Path("/tmp"), features={"arm"})
    assert BicepSecureParameterDefaultGuard().applies(prof) is False


# --- multi-line literal defaults (PR #843 review, Medium) -------------------------------------
# `bicep_params()` used to capture only the declaration line, truncating a multi-line default to
# its bare `{`/`[` token -- which is not in _EMPTY_LITERALS, so an empty multi-line placeholder
# fired. Narrowing + widening are both pinned here: the empty placeholder must stay silent AND the
# populated multi-line literal must still fire, with a readable message.

def test_bicep_secure_parameter_default_silent_on_multiline_empty_object_default(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbConfig object = {\n"
        "}\n",
        encoding="utf-8",
    )
    assert BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_secure_parameter_default_silent_on_multiline_empty_array_default(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbSecrets array = [\n"
        "]\n",
        encoding="utf-8",
    )
    assert BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path)) == []


def test_bicep_secure_parameter_default_flags_multiline_object_default(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbConfig object = {\n"
        "  password: 'hunter2'\n"
        "}\n",
        encoding="utf-8",
    )
    findings = BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-secure-parameter-default/hardcoded-literal-default"
    assert findings[0].location.endswith("main.bicep:2")


def test_bicep_secure_parameter_default_flags_multiline_array_default(tmp_path: Path) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbSecrets array = [\n"
        "  'hunter2'\n"
        "]\n",
        encoding="utf-8",
    )
    findings = BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1


def test_bicep_secure_parameter_default_message_flattens_a_multiline_default(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbConfig object = {\n"
        "  password: 'hunter2'\n"
        "}\n",
        encoding="utf-8",
    )
    findings = BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    message = findings[0].message
    # The named value must reach the report, on one line, not as a bare `{` token.
    assert "\n" not in message
    assert "password: 'hunter2'" in message
    assert "hardcoded default value `{`" not in message


def test_bicep_secure_parameter_default_message_elides_a_very_long_default(
    tmp_path: Path,
) -> None:
    body = "\n".join(f"  key{i}: 'value-{i}'" for i in range(40))
    (tmp_path / "main.bicep").write_text(
        f"@secure()\nparam dbConfig object = {{\n{body}\n}}\n",
        encoding="utf-8",
    )
    findings = BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert "..." in findings[0].message
    assert len(findings[0].message) < 700


def test_bicep_secure_parameter_default_still_sees_a_param_after_a_multiline_default(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbConfig object = {\n"
        "  password: 'hunter2'\n"
        "}\n"
        "@secure()\n"
        "param apiKey string = 'sk-live-abc'\n",
        encoding="utf-8",
    )
    findings = BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 2
    assert [f.location.rsplit(":", 1)[1] for f in findings] == ["2", "6"]


def test_bicep_secure_parameter_default_flags_unterminated_multiline_default(
    tmp_path: Path,
) -> None:
    # Malformed source must not raise, and must not lose the hardcoded value it does contain.
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbConfig object = {\n"
        "  password: 'hunter2'\n",
        encoding="utf-8",
    )
    findings = BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert "hunter2" in findings[0].message


def test_bicep_secure_parameter_default_flags_whitespace_only_string_default(
    tmp_path: Path,
) -> None:
    # Whitespace is collapsed for DISPLAY, but inside a string it is content, not formatting --
    # a two-space default is a hardcoded value, not the `''` empty placeholder.
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "param dbPassword string = '  '\n",
        encoding="utf-8",
    )
    assert len(BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path))) == 1


# --- decorator across a comment line (#844): the FN half -- must STILL fire (narrowing) ---------
def test_bicep_secure_parameter_default_flags_literal_when_secure_split_by_a_comment(
    tmp_path: Path,
) -> None:
    # A `//` doc comment between `@secure()` and the param must not hide the hardcoded default.
    (tmp_path / "main.bicep").write_text(
        "@secure()\n"
        "// the production DB password\n"
        "param dbPassword string = 'hunter2'\n",
        encoding="utf-8",
    )
    findings = BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-secure-parameter-default/hardcoded-literal-default"


# --- decorator with a TRAILING comment (#846): the FN half -- must STILL fire (narrowing) --------
def test_bicep_secure_parameter_default_flags_literal_when_secure_has_a_trailing_comment(
    tmp_path: Path,
) -> None:
    # A `//` comment trailing on the `@secure()` line itself must not hide the hardcoded default.
    (tmp_path / "main.bicep").write_text(
        "@secure() // the production DB password\n"
        "param dbPassword string = 'hunter2'\n",
        encoding="utf-8",
    )
    findings = BicepSecureParameterDefaultGuard().run(tmp_path, _bicepprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bicep-secure-parameter-default/hardcoded-literal-default"
