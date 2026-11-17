"""Tests for the code-injection-eval-exec guard.

Covers:
  - code-injection-eval-exec/dynamic-content (HIGH)
"""

from __future__ import annotations

from agentsec.guards.code_injection_eval_exec import CodeInjectionEvalExecGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_bare_variable_eval(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text("def handle(user_input):\n    return eval(user_input)\n", encoding="utf-8")
    findings = CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "code-injection-eval-exec/dynamic-content"
    assert findings[0].severity == "high"


def test_fires_on_fstring_exec(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text("def handle(formula):\n    exec(f'x = {formula}')\n", encoding="utf-8")
    findings = CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "code-injection-eval-exec/dynamic-content"


def test_fires_on_concat(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text("def handle(expr):\n    return eval('2 + ' + expr)\n", encoding="utf-8")
    findings = CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_passes_static_literal(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text("def handle():\n    return eval('2 + 2')\n", encoding="utf-8")
    assert CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_fires_on_concat_with_comma_inside_the_string_literal(tmp_path: Path) -> None:
    # (Dean's review): the first-argument extraction tracked bracket depth
    # only, not string quoting -- a comma INSIDE the string literal (`'a,b'`) was read as a
    # top-level argument separator, truncating the extracted "argument" to the broken
    # fragment `'a` (not dynamic) instead of the real first argument `'a,b' + x` (a
    # concatenation, genuinely dynamic). A real regression: this fired correctly on `main`
    # before the argument-extraction change.
    (tmp_path / "t.py").write_text("def handle(x):\n    return eval('a,b' + x)\n", encoding="utf-8")
    findings = CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_passes_comment_mention(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "# eval(user_input) is dangerous, don't do this\ndef handle():\n    return 1\n", encoding="utf-8"
    )
    assert CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def handle(trusted):\n    return eval(trusted)  # security: allow-eval-exec\n", encoding="utf-8"
    )
    assert CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_attribute_eval_method(tmp_path: Path) -> None:
    # `.eval(...)`/`.exec(...)` as a METHOD on an object (e.g. pandas DataFrame.eval) is not the
    # builtin sink — the `(?<!\.)` lookbehind keeps it silent. (PR #267 review, Major)
    (tmp_path / "t.py").write_text(
        "import pandas as pd\ndef q(df, expr):\n    return df.eval(expr)\n", encoding="utf-8"
    )
    assert CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_docstring_example(tmp_path: Path) -> None:
    # an anti-pattern example inside a docstring must not self-fire (strip_python_strings).
    # (PR #267 review, Critical — guards were self-firing on their own docstrings)
    (tmp_path / "t.py").write_text(
        '"""Bad:\n    return eval(user_input)\n"""\ndef handle():\n    return 1\n', encoding="utf-8"
    )
    assert CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_fires_on_dict_subscript_argument(tmp_path: Path) -> None:
    # CVE-2026-33017 (Langflow unauthenticated RCE) shape: attacker-controlled code
    # extracted via a dict/subscript chain (custom_params.pop("code") in the real advisory)
    # and passed straight to exec(). The quoted subscript KEY previously made this read as
    # a static string literal — a real false negative on the exact CVE's own extraction shape.
    (tmp_path / "t.py").write_text("def handle(node):\n    return exec(node['code'])\n", encoding="utf-8")
    findings = CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "code-injection-eval-exec/dynamic-content"


def test_fires_on_chained_dict_subscript_argument(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def handle(data):\n"
        "    node = data['nodes'][0]\n"
        "    exec_globals = globals().copy()\n"
        "    exec(node['data']['node']['template']['code']['value'], exec_globals)\n",
        encoding="utf-8",
    )
    findings = CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "code-injection-eval-exec/dynamic-content"


def test_passes_static_literal_with_bracket_looking_text(tmp_path: Path) -> None:
    # A genuinely static string that happens to contain bracket-like text must still be
    # recognized as a literal, not misread as a subscript access.
    (tmp_path / "t.py").write_text(
        "def handle():\n    return eval('config[\"debug\"] = False')\n", encoding="utf-8"
    )
    assert CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path)) == []


# --- compile()/__import__()/SymPy parse_expr() sinks (CVE-2026-44717) --------------


def test_sandboxed_eval_with_restricted_builtins_stays_silent(tmp_path: Path) -> None:
    # (Dean's review, agentic pre-review H-3): eval()/exec() with a globals dict
    # restricting __builtins__ to {} is the documented sandboxed-eval idiom -- the fix teams
    # apply to close an earlier eval-exec finding. Firing on the hardened call defeats the
    # guard's own remediation advice.
    (tmp_path / "t.py").write_text(
        "def calculate(expr):\n    return eval(expr, {'__builtins__': {}}, {})\n", encoding="utf-8"
    )
    assert CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_sandboxed_exec_with_none_builtins_stays_silent(tmp_path: Path) -> None:
    # FP-bait companion: __builtins__: None is the other documented sandboxing spelling.
    (tmp_path / "t.py").write_text(
        "def run(code):\n    exec(code, {'__builtins__': None})\n", encoding="utf-8"
    )
    assert CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_unsandboxed_eval_with_unrestricted_globals_still_fires(tmp_path: Path) -> None:
    # Still-fires companion: an ordinary globals dict with no __builtins__ restriction is not
    # the sandboxing idiom and must not be treated as one.
    (tmp_path / "t.py").write_text(
        "def calculate(expr, ctx):\n    return eval(expr, ctx, {})\n", encoding="utf-8"
    )
    findings = CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_compile_with_builtins_restriction_elsewhere_still_fires(tmp_path: Path) -> None:
    # The sandboxing marker is deliberately scoped to eval/exec only -- compile() has no
    # globals/locals parameter at all, so a __builtins__ restriction merely appearing on the
    # same line (e.g. in an unrelated dict literal) must not silence a dynamic compile() call.
    (tmp_path / "t.py").write_text(
        "def run(formula):\n    return compile(formula, '<f>', 'eval'), {'__builtins__': {}}\n",
        encoding="utf-8",
    )
    findings = CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_fires_on_dynamic_compile(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def run_formula(formula: str):\n    code_obj = compile(formula, '<formula>', 'eval')\n",
        encoding="utf-8",
    )
    findings = CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "code-injection-eval-exec/dynamic-content"


def test_fires_on_dynamic_dunder_import(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def load_plugin(module_name: str):\n    return __import__(module_name)\n", encoding="utf-8"
    )
    findings = CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_compile_static_literal_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "def run():\n    return compile('1 + 1', '<string>', 'eval')\n", encoding="utf-8"
    )
    assert CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_fires_on_unpinned_sympy_parse_expr(tmp_path: Path) -> None:
    # CVE-2026-44717 (mcp-calculate-server): an MCP tool handler routes a tool parameter
    # through sympy's parse_expr with no local_dict/global_dict pinning -- SymPy's own docs
    # call this equivalent to eval() on the expression string.
    (tmp_path / "t.py").write_text(
        "from sympy.parsing.sympy_parser import parse_expr\n\n"
        "@mcp.tool()\n"
        "def calculate(expression: str):\n"
        "    return parse_expr(expression)\n",
        encoding="utf-8",
    )
    findings = CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "code-injection-eval-exec/dynamic-content"


def test_sympy_parse_expr_with_dotted_module_path_fires(tmp_path: Path) -> None:
    # The real vulnerable shape is the fully-dotted call -- confirms the sink regex does NOT
    # exclude a leading `.` the way the eval/exec regex deliberately does.
    (tmp_path / "t.py").write_text(
        "import sympy.parsing.sympy_parser as sympy_parser\n\n"
        "def calculate(expression: str):\n"
        "    return sympy_parser.parse_expr(expression)\n",
        encoding="utf-8",
    )
    findings = CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_sympy_parse_expr_with_both_dicts_pinned_stays_silent(tmp_path: Path) -> None:
    # FP bait: the documented-safe form -- both local_dict and global_dict pinned (even to
    # empty dicts) -- must not fire.
    (tmp_path / "t.py").write_text(
        "from sympy.parsing.sympy_parser import parse_expr\n\n"
        "def calculate(expression: str):\n"
        "    return parse_expr(expression, local_dict={}, global_dict={})\n",
        encoding="utf-8",
    )
    assert CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_sympy_parse_expr_with_only_local_dict_still_fires(tmp_path: Path) -> None:
    # FP bait's own inverse: BOTH dicts must be present -- only one pinned is still unsafe
    # per the real source's own detection contract.
    (tmp_path / "t.py").write_text(
        "from sympy.parsing.sympy_parser import parse_expr\n\n"
        "def calculate(expression: str):\n"
        "    return parse_expr(expression, local_dict={})\n",
        encoding="utf-8",
    )
    findings = CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_sympy_parse_expr_static_literal_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "from sympy.parsing.sympy_parser import parse_expr\n\n"
        "def calculate():\n"
        "    return parse_expr('2 + 2')\n",
        encoding="utf-8",
    )
    assert CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_code_injection_eval_exec_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the flagged line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-eval-exec"):
        (tmp_path / "t.py").write_text(
            f'def handle(trusted):\n    eval(trusted); _note = "{note}"\n', encoding="utf-8"
        )
        assert len(CodeInjectionEvalExecGuard().run(tmp_path, _pyprof(tmp_path))) == 1, note
