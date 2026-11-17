from __future__ import annotations

import pytest

from agentsec.findings import Finding
from agentsec.guards.js_code_injection import JsCodeInjectionGuard
from tests.guards._common import *  # noqa: F401,F403

# --- eval() ---------------------------------------------------------------------------------

def test_flags_eval_template_literal_interpolation(tmp_path: Path) -> None:
    (tmp_path / "calc.js").write_text(
        "eval(`result = ${req.query.formula}`);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsCodeInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-code-injection/eval-dynamic"
    assert findings[0].severity == "critical"


def test_flags_eval_concatenation(tmp_path: Path) -> None:
    (tmp_path / "calc.ts").write_text(
        'eval("result = " + req.body.formula);\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    findings = JsCodeInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-code-injection/eval-dynamic"


def test_flags_eval_local_var_assigned_from_req(tmp_path: Path) -> None:
    # order-independent, file-scoped assign-then-use taint tracking (same convention as
    # js_regex_injection_dos.py)
    (tmp_path / "calc.js").write_text(
        "const formula = req.query.formula;\neval(formula);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsCodeInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-code-injection/eval-dynamic"


def test_silent_on_static_eval(tmp_path: Path) -> None:
    (tmp_path / "calc.js").write_text('eval("2 + 2");\n', encoding="utf-8")
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCodeInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_dynamic_eval_not_from_request(tmp_path: Path) -> None:
    # Adversarial FP-bait: dynamic-LOOKING (not a literal) but NOT derived from req.*/request.*
    # at all -- must stay silent. Confirms the taint-source check actually gates the finding,
    # not just "is this argument non-literal" (which would be far too noisy: eval on trusted,
    # non-request config is a legitimate pattern).
    (tmp_path / "calc.js").write_text(
        "eval(JSON.stringify(safeConfig));\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCodeInjectionGuard().run(tmp_path, profile) == []


# --- MCP tool-call-argument taint (sentrymcp-zaydmulani) ---------------------------

def test_flags_eval_on_mcp_tool_argument(tmp_path: Path) -> None:
    (tmp_path / "calc_tool.js").write_text(
        "server.tool(\"calc\", async (args) => {\n"
        "  return eval(`result = ${args.formula}`);\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript", "mcp"})
    findings = JsCodeInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-code-injection/eval-dynamic"


def test_silent_on_mcp_tool_argument_without_mcp_feature(tmp_path: Path) -> None:
    # FP-bait: the exact same code with NO "mcp" feature declared must stay silent -- confirms
    # the widening is gated on the mcp feature, not a blanket new taint source that would fire on
    # any ordinary JS/TS code using "args"/"params"/"input" as a plain (non-MCP) variable name.
    (tmp_path / "calc_tool.js").write_text(
        "function calc(args) {\n"
        "  return eval(`result = ${args.formula}`);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCodeInjectionGuard().run(tmp_path, profile) == []


def test_flags_new_function_on_mcp_tool_argument(tmp_path: Path) -> None:
    (tmp_path / "calc_tool.js").write_text(
        "server.tool(\"calc\", async (params) => {\n"
        "  const fn = new Function(`return ${params.expr}`);\n"
        "  return fn();\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript", "mcp"})
    findings = JsCodeInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-code-injection/new-function-dynamic"


def test_does_not_catch_aliased_eval_reference(tmp_path: Path) -> None:
    # Known bypass (documented in wiki/guards/js-code-injection.md "Known bypasses"): an
    # aliased reference to eval evades the literal `eval(` spelling this guard matches -- there
    # is no alias-tracking. Kept as an explicit test so the gap stays visible, not silently
    # rediscovered later.
    (tmp_path / "calc.js").write_text(
        "const runIt = eval;\nrunIt(req.query.code);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCodeInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "notes.js").write_text(
        "// Never do: eval(`result = ${req.query.formula}`)\n"
        'eval("2 + 2");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCodeInjectionGuard().run(tmp_path, profile) == []


# --- new Function(...) ------------------------------------------------------------------------

def test_flags_new_function_dynamic_body(tmp_path: Path) -> None:
    (tmp_path / "handler.js").write_text(
        "const fn = new Function(`return ${req.query.expr}`);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsCodeInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-code-injection/new-function-dynamic"
    assert findings[0].severity == "critical"


def test_silent_on_static_new_function(tmp_path: Path) -> None:
    (tmp_path / "handler.js").write_text(
        'const fn = new Function("a", "b", "return a + b");\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCodeInjectionGuard().run(tmp_path, profile) == []


def test_pragma_suppresses_new_function(tmp_path: Path) -> None:
    (tmp_path / "handler.js").write_text(
        "// security: allow-js-code-injection\n"
        "const fn = new Function(`return ${req.query.expr}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCodeInjectionGuard().run(tmp_path, profile) == []


# --- vm.runInContext / runInNewContext / runInThisContext ------------------------------------

def test_flags_vm_run_in_context_dynamic(tmp_path: Path) -> None:
    (tmp_path / "sandbox.js").write_text(
        "const vm = require('vm');\nvm.runInContext(req.body.script, ctx);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsCodeInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-code-injection/vm-run-dynamic"
    assert findings[0].severity == "critical"


def test_flags_vm_run_in_new_context_via_local_var(tmp_path: Path) -> None:
    (tmp_path / "sandbox.js").write_text(
        "const script = request.body.script;\nvm.runInNewContext(script);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsCodeInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-code-injection/vm-run-dynamic"


def test_silent_on_static_vm_run_in_this_context(tmp_path: Path) -> None:
    (tmp_path / "sandbox.js").write_text(
        'vm.runInThisContext("1 + 1");\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCodeInjectionGuard().run(tmp_path, profile) == []


def test_pragma_suppresses_vm_run(tmp_path: Path) -> None:
    (tmp_path / "sandbox.js").write_text(
        "// security: allow-js-code-injection\n"
        "vm.runInContext(req.body.script, ctx);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCodeInjectionGuard().run(tmp_path, profile) == []


# --- require('node-serialize').unserialize(...) -----------------------------------------------

def test_flags_node_serialize_unserialize(tmp_path: Path) -> None:
    (tmp_path / "session.js").write_text(
        "const serialize = require('node-serialize');\n"
        "const obj = serialize.unserialize(req.cookies.profile);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsCodeInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-code-injection/node-serialize-unserialize"
    assert findings[0].severity == "critical"


def test_silent_on_static_node_serialize_unserialize(tmp_path: Path) -> None:
    (tmp_path / "session.js").write_text(
        "const serialize = require('node-serialize');\n"
        'const obj = serialize.unserialize("{}");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCodeInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_unserialize_without_node_serialize_import(tmp_path: Path) -> None:
    # An unrelated function merely named "unserialize" (e.g. a hand-rolled PHP-style helper)
    # must not fire without evidence the file actually imports the node-serialize package.
    (tmp_path / "helper.js").write_text(
        "function unserialize(x) { return x; }\nunserialize(req.query.data);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCodeInjectionGuard().run(tmp_path, profile) == []


def test_pragma_suppresses_node_serialize(tmp_path: Path) -> None:
    (tmp_path / "session.js").write_text(
        "// security: allow-js-code-injection\n"
        "const serialize = require('node-serialize');\n"
        "const obj = serialize.unserialize(req.cookies.profile);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCodeInjectionGuard().run(tmp_path, profile) == []


# --- applies() / path handling -----------------------------------------------------------------

def test_not_applies_without_js_or_ts(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features=set())
    assert not JsCodeInjectionGuard().applies(profile)


def test_applies_with_typescript(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"typescript"})
    assert JsCodeInjectionGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.js").write_text(
        "eval(`result = ${req.query.formula}`);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCodeInjectionGuard().run(tmp_path, profile) == []


# --- #1055: the sink and the taint pass read the anchor mask ---------------------------------------


def _run(tmp_path: Path, src: str) -> list[Finding]:
    (tmp_path / "calc.js").write_text(src, encoding="utf-8")
    return JsCodeInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))


def test_taint_assigned_through_a_template_substitution_is_tracked(tmp_path: Path) -> None:
    # The FN direction (#1055, the :220 trap): plain `strip_strings=True` blanked the substitution,
    # so the variable was never recorded as tainted.
    findings = _run(tmp_path, "const formula = `${req.query.formula}`;\neval(formula);\n")
    assert [f.rule for f in findings] == ["js-code-injection/eval-dynamic"]


def test_substitution_without_request_data_is_not_taint(tmp_path: Path) -> None:
    # FP bait for the taint-pass widening (PR #1126 round-1 L3): the mask keeps `${...}` code, and
    # code that reads no request data is still not a taint source.
    assert _run(tmp_path, "const formula = `${config.formula}`;\neval(formula);\n") == []


def test_request_shaped_label_string_is_still_not_taint(tmp_path: Path) -> None:
    # The direction the :220 change trades against: string TEXT is still blanked for the taint pass.
    assert _run(tmp_path, 'const formula = "req.count: total";\neval(formula);\n') == []


@pytest.mark.parametrize(
    "src",
    [
        'log("never eval(req.query.x) here");\n',
        "const doc = 'new Function(req.body.code) is forbidden';\n",
        "throw new Error(`vm.runInContext(req.body.script, ctx) blocked`);\n",
    ],
)
def test_sink_spelled_in_a_string_does_not_fire(tmp_path: Path, src: str) -> None:
    # The FP direction (#1055): a docs or error string is not a call.
    assert _run(tmp_path, src) == []


@pytest.mark.parametrize(
    ("src", "rule"),
    [
        ("const s = `${eval(req.query.x)}`;\n", "js-code-injection/eval-dynamic"),
        ('log("eval(1)"); eval(req.query.x);\n', "js-code-injection/eval-dynamic"),
        ("log('new Function(x)'); new Function(`return ${req.query.e}`);\n", "js-code-injection/new-function-dynamic"),
    ],
)
def test_real_sink_nested_or_after_a_quoted_copy_still_fires(tmp_path: Path, src: str, rule: str) -> None:
    # A sink in a `${...}` is code (the shortcut-separating case), and a quoted copy first on the
    # line must not hide the real call after it (first-match shadowing, an FN on main).
    assert [f.rule for f in _run(tmp_path, src)] == [rule]


def test_pragma_still_suppresses_an_eval_sink(tmp_path: Path) -> None:
    assert _run(tmp_path, "eval(req.query.x);  // security: allow-js-code-injection\n") == []
