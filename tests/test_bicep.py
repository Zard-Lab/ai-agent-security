"""Regression tests for agentsec/bicep.py — the bicep-* guard foundation."""
from __future__ import annotations

from agentsec.bicep import (
    _MAX_DEFAULT_LINES,
    bicep_outputs,
    bicep_params,
    bicep_resources,
    bicep_user_functions,
    bicepparam_assignments,
)

_SAMPLE = """\
@secure()
param dbPassword string = 'hardcoded-default'

param adminUsername string

@description('storage tier')
param storageTier string = 'Standard'

output dbConnectionString string = 'server=x;password=${dbPassword}'

@secure()
output secretToken string = tokenValue

resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: 'myvm'
  properties: {
    adminUsername: 'hardcoded-admin'
  }
}

resource vmExt 'Microsoft.Compute/virtualMachines/extensions@2023-03-01' = {
  name: 'myext'
  properties: {
    settings: {
      commandToExecute: 'echo hi'
    }
  }
}
"""


def test_resources_extracted_with_correct_types() -> None:
    resources = bicep_resources(_SAMPLE)
    types = {r.resource_type for r in resources}
    assert "Microsoft.Compute/virtualMachines" in types
    assert "Microsoft.Compute/virtualMachines/extensions" in types
    assert len(resources) == 2


def test_resource_block_contains_only_its_own_properties() -> None:
    resources = bicep_resources(_SAMPLE)
    by_type = {r.resource_type: r for r in resources}
    assert "adminUsername" in by_type["Microsoft.Compute/virtualMachines"].block
    assert "commandToExecute" not in by_type["Microsoft.Compute/virtualMachines"].block
    assert "commandToExecute" in by_type["Microsoft.Compute/virtualMachines/extensions"].block


def test_params_extracted_with_decorators_and_defaults() -> None:
    params = bicep_params(_SAMPLE)
    by_name = {p.name: p for p in params}
    assert by_name["dbPassword"].decorators == frozenset({"secure"})
    assert by_name["dbPassword"].default == "'hardcoded-default'"
    assert by_name["adminUsername"].decorators == frozenset()
    assert by_name["adminUsername"].default is None
    assert by_name["storageTier"].decorators == frozenset({"description"})


def test_outputs_extracted_with_decorators() -> None:
    outputs = bicep_outputs(_SAMPLE)
    by_name = {o.name: o for o in outputs}
    assert by_name["dbConnectionString"].decorators == frozenset()
    assert by_name["secretToken"].decorators == frozenset({"secure"})


def test_no_resources_in_ordinary_bicep_file_returns_empty() -> None:
    assert bicep_resources("param x string\noutput y string = x\n") == []


def test_no_params_or_outputs_returns_empty() -> None:
    assert bicep_params("resource r 'Microsoft.Storage/storageAccounts@2021-09-01' = {}\n") == []
    assert bicep_outputs("resource r 'Microsoft.Storage/storageAccounts@2021-09-01' = {}\n") == []


def test_empty_text_returns_empty_lists() -> None:
    assert bicep_resources("") == []
    assert bicep_params("") == []
    assert bicep_outputs("") == []


def test_string_containing_brace_does_not_desync_block_depth() -> None:
    text = (
        "resource r 'Microsoft.Storage/storageAccounts@2021-09-01' = {\n"
        "  name: 'not-a-real-brace-}'\n"
        "  properties: {\n"
        "    supportsHttpsTrafficOnly: true\n"
        "  }\n"
        "}\n"
        "param next string\n"
    )
    resources = bicep_resources(text)
    assert len(resources) == 1
    assert "supportsHttpsTrafficOnly" in resources[0].block
    assert "next" not in resources[0].block


def test_commented_brace_does_not_desync_block_depth() -> None:
    text = (
        "resource r 'Microsoft.Storage/storageAccounts@2021-09-01' = {\n"
        "  // a comment with a stray } brace\n"
        "  name: 'x'\n"
        "}\n"
        "param after string\n"
    )
    resources = bicep_resources(text)
    assert len(resources) == 1
    assert "after" not in resources[0].block


def test_multiple_resources_all_captured() -> None:
    text = (
        "resource a 'Microsoft.Storage/storageAccounts@2021-09-01' = { name: 'a' }\n"
        "resource b 'Microsoft.KeyVault/vaults@2021-06-01-preview' = { name: 'b' }\n"
    )
    resources = bicep_resources(text)
    assert [r.name for r in resources] == ["a", "b"]


# --------------------------------------------------------------------------- #
# .bicepparam assignments (7/7 -- bicep-param-file-insecure-secret-value)
# --------------------------------------------------------------------------- #


def test_bicepparam_assignments_extracted_without_type_annotation() -> None:
    text = (
        "using 'main.bicep'\n\n"
        "param dbPassword = 'hardcoded-value-in-the-params-file'\n"
        "param environmentName = readEnvironmentVariable('ENV_NAME')\n"
        "param apiKey = az.getSecret('mySubscription', 'myRG', 'myVault', 'apiKeySecretName')\n"
    )
    assignments = bicepparam_assignments(text)
    by_name = {a.name: a for a in assignments}
    assert len(assignments) == 3
    assert by_name["dbPassword"].value == "'hardcoded-value-in-the-params-file'"
    assert by_name["environmentName"].value == "readEnvironmentVariable('ENV_NAME')"
    assert by_name["dbPassword"].line == 3


def test_bicepparam_assignments_empty_text_returns_empty_list() -> None:
    assert bicepparam_assignments("") == []


def test_bicepparam_assignments_ignores_using_directive() -> None:
    assignments = bicepparam_assignments("using 'main.bicep'\n")
    assert assignments == []


# --- multi-line param defaults (PR #843 review, Medium) ---------------------------------------
# A default left open at end of line used to be truncated to its bare `{`/`[` opening token, which
# reads as a non-empty literal to bicep-secure-parameter-default. Both directions are asserted:
# the empty multi-line placeholder must parse as empty, the populated one must keep its contents.

def test_multiline_object_default_is_captured_whole_not_truncated() -> None:
    text = "@secure()\nparam dbConfig object = {\n  password: 'hunter2'\n}\n"
    params = bicep_params(text)
    assert len(params) == 1
    assert params[0].default is not None
    assert "password: 'hunter2'" in params[0].default
    assert params[0].default != "{"
    assert params[0].line == 2


def test_multiline_empty_object_default_is_captured_as_an_empty_container() -> None:
    params = bicep_params("@secure()\nparam dbConfig object = {\n}\n")
    assert len(params) == 1
    assert params[0].default is not None
    assert "".join(params[0].default.split()) == "{}"


def test_multiline_array_default_is_captured_whole() -> None:
    params = bicep_params("@secure()\nparam dbSecrets array = [\n  'hunter2'\n]\n")
    assert len(params) == 1
    assert params[0].default is not None
    assert "'hunter2'" in params[0].default


def test_multiline_default_does_not_swallow_the_next_param_declaration() -> None:
    text = (
        "@secure()\n"
        "param first object = {\n"
        "  password: 'hunter2'\n"
        "}\n"
        "@secure()\n"
        "param second string = 'zz'\n"
    )
    by_name = {p.name: p for p in bicep_params(text)}
    assert set(by_name) == {"first", "second"}
    assert by_name["second"].default == "'zz'"
    assert by_name["second"].decorators == frozenset({"secure"})
    assert by_name["second"].line == 6


def test_multiline_default_brace_inside_a_string_does_not_desync_accumulation() -> None:
    text = "param cfg object = {\n  note: 'a } brace in a string'\n}\nparam after string = 'x'\n"
    by_name = {p.name: p for p in bicep_params(text)}
    assert set(by_name) == {"cfg", "after"}
    assert by_name["after"].default == "'x'"


def test_unterminated_multiline_default_returns_what_it_absorbed_without_raising() -> None:
    params = bicep_params("@secure()\nparam dbConfig object = {\n  password: 'hunter2'\n")
    assert len(params) == 1
    assert params[0].default is not None
    assert "hunter2" in params[0].default


def test_unbalanced_default_cannot_swallow_the_rest_of_the_file() -> None:
    # _MAX_DEFAULT_LINES bounds the blast radius of a stray `{` in a malformed file: declarations
    # past the cap must still be found.
    text = (
        "@secure()\nparam a object = {\n"
        + "\n".join(f"  k{i}: 1" for i in range(500))
        + "\nparam later string = 'z'\n"
    )
    by_name = {p.name: p for p in bicep_params(text)}
    assert set(by_name) == {"a", "later"}
    assert by_name["a"].default is not None
    assert by_name["a"].default.count("\n") + 1 == _MAX_DEFAULT_LINES + 1


def test_single_line_defaults_are_unchanged_by_the_accumulator() -> None:
    by_name = {p.name: p for p in bicep_params(_SAMPLE)}
    assert by_name["dbPassword"].default == "'hardcoded-default'"
    assert by_name["storageTier"].default == "'Standard'"
    assert by_name["adminUsername"].default is None


# --- user-defined functions (PR #843 review, Low) ---------------------------------------------

def test_user_functions_are_collected_by_name() -> None:
    text = (
        "func listActiveRegions(env string) array => ['eastus']\n"
        "func buildUrl(host string) string => 'https://${host}'\n"
    )
    assert bicep_user_functions(text) == frozenset({"listActiveRegions", "buildUrl"})


def test_exported_user_function_is_still_collected() -> None:
    text = "@export()\nfunc listActiveRegions(env string) array => ['eastus']\n"
    assert bicep_user_functions(text) == frozenset({"listActiveRegions"})


def test_user_functions_empty_when_none_declared() -> None:
    assert bicep_user_functions(_SAMPLE) == frozenset()



# --- decorator association across comment lines (#844) -----------------------------------------
# `_decorators_above` used to stop at any non-blank line, so a `//` comment between a decorator and
# its declaration silently dropped the decorator -- flipping four bicep-* guards (2 FN + 2 FP). The
# Bicep compiler treats a `//` comment as whitespace, so the decorator still applies. Both trade
# directions are pinned here: the decorator is now seen ACROSS a `//` comment (widening), yet a
# comment neither invents a decorator on an undecorated declaration nor leaks an earlier
# declaration's decorator onto a later one (the narrowing/FP-bait side).

def test_decorator_is_associated_across_a_line_comment() -> None:
    text = "@secure()\n// the production DB password\nparam dbPassword string = 'x'\n"
    assert bicep_params(text)[0].decorators == frozenset({"secure"})


def test_decorator_is_associated_across_a_line_comment_for_outputs() -> None:
    text = "@secure()\n// exported secret\noutput token string = tokenValue\n"
    assert bicep_outputs(text)[0].decorators == frozenset({"secure"})


def test_stacked_decorators_split_by_a_comment_are_both_associated() -> None:
    text = "@description('d')\n// note\n@secure()\nparam p string = 'x'\n"
    assert bicep_params(text)[0].decorators == frozenset({"description", "secure"})


def test_blank_line_between_decorator_and_declaration_is_still_skipped() -> None:
    # Pre-existing behavior must not regress when the comment skip is added.
    assert bicep_params("@secure()\n\nparam p string = 'x'\n")[0].decorators == frozenset({"secure"})


def test_line_comment_above_an_undecorated_param_adds_no_decorator() -> None:
    # FP-bait: a comment must not invent a decorator that was never written.
    assert bicep_params("// just a note\nparam p string = 'x'\n")[0].decorators == frozenset()


def test_comment_does_not_leak_an_earlier_params_decorator_onto_a_later_one() -> None:
    # Leak-bait (the ambiguous case): the intervening `param a` line must still terminate the walk,
    # so `@secure()` above `a` cannot cross the comment onto `b`.
    text = "@secure()\nparam a string = 'x'\n// gap\nparam b string = 'y'\n"
    by_name = {p.name: p.decorators for p in bicep_params(text)}
    assert by_name["a"] == frozenset({"secure"})
    assert by_name["b"] == frozenset()


def test_block_comment_still_breaks_decorator_association() -> None:
    # Documented remaining limit: only `//` line comments are treated as whitespace; a `/* ... */`
    # block comment between a decorator and its declaration still severs the association.
    text = "@secure()\n/* block note */\nparam p string = 'x'\n"
    assert bicep_params(text)[0].decorators == frozenset()


def test_trailing_comment_on_the_decorator_line_is_now_associated() -> None:
    # #846: a `//` comment TRAILING on the decorator's own line is stripped (via `_bicep_code_only`)
    # before the `@name(...)` line match, so the decorator is kept — matching the Bicep compiler,
    # which treats the comment as whitespace. (Was the pinned limit flipped by #845 review.)
    text = "@secure() // sensitive value\nparam p string = 'x'\n"
    assert bicep_params(text)[0].decorators == frozenset({"secure"})


def test_trailing_comment_on_the_decorator_line_is_now_associated_for_outputs() -> None:
    # #846: same as above for `output` declarations (bicep_outputs shares `_decorators_above`).
    text = "@secure() // exported secret\noutput token string = tokenValue\n"
    assert bicep_outputs(text)[0].decorators == frozenset({"secure"})


def test_embedded_slashes_in_a_decorator_string_arg_still_associate() -> None:
    # FP-bait (#846): `_bicep_code_only` empties the single-quoted string CONTENTS before stripping
    # `//`, so a `//` sitting INSIDE a decorator's string argument is not mistaken for a trailing
    # comment and both decorators still associate.
    text = "@metadata('see https://example/docs')\n@secure()\nparam p string = 'x'\n"
    assert bicep_params(text)[0].decorators == frozenset({"metadata", "secure"})


def test_trailing_comment_on_a_non_decorator_line_invents_no_decorator() -> None:
    # FP-bait (#846): stripping trailing `//` before the match must not conjure a decorator on a
    # line that never had one — a bare `param` line with a trailing comment stays undecorated.
    text = "param p string = 'x' // just a note\n"
    assert bicep_params(text)[0].decorators == frozenset()
