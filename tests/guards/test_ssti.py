from __future__ import annotations

from agentsec.guards.ssti import SstiGuard
from tests.guards._common import *  # noqa: F401,F403


def test_ssti_flags_render_template_string(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text(
        "from flask import render_template_string\ndef p(name):\n    return render_template_string('Hi ' + name)\n", encoding="utf-8"
    )
    findings = SstiGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ssti/user-input-in-template"
    assert findings[0].severity == "high"

def test_ssti_flags_autoescape_false(tmp_path: Path) -> None:
    (tmp_path / "e.py").write_text("from jinja2 import Environment\nenv = Environment(autoescape=False)\n", encoding="utf-8")
    assert len(SstiGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_ssti_passes_literal_template(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text(
        "from flask import render_template_string\nrender_template_string('<p>static</p>')\n", encoding="utf-8"
    )
    assert SstiGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_ssti_passes_render_template_data(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text(
        "from flask import render_template\ndef p(name):\n    return render_template('p.html', name=name)\n", encoding="utf-8"
    )
    assert SstiGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_ssti_flags_dynamic_first_arg_with_trailing_kwarg(tmp_path: Path) -> None:
    # H7 (FN): a dynamic template as the first positional arg must fire even when a
    # later kwarg is a constant literal — the old whole-line scan missed this.
    (tmp_path / "v.py").write_text(
        "from flask import render_template_string\n"
        "def p(user_input):\n    return render_template_string(user_input, extra=\"value\")\n", encoding="utf-8"
    )
    findings = SstiGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1 and findings[0].rule == "ssti/user-input-in-template"

def test_ssti_silent_literal_first_arg_with_format_kwarg(tmp_path: Path) -> None:
    # H7 (FP): a constant-literal template is safe even if a LATER arg contains a
    # `.format(` token — only the first positional (template) arg decides.
    (tmp_path / "v.py").write_text(
        "from flask import render_template_string\n"
        "render_template_string(\"safe.html\", data=obj.format(x))\n", encoding="utf-8"
    )
    assert SstiGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_ssti_flags_concat_template_with_comma_in_string(tmp_path: Path) -> None:
    # H-3 (FN fix): a comma INSIDE the template string literal must not truncate the first
    # arg — `_first_arg` is now quote-aware, so this real concat SSTI still fires.
    (tmp_path / "v.py").write_text(
        "from flask import render_template_string\n"
        "def p(name):\n    return render_template_string(\"Hello, \" + name)\n", encoding="utf-8"
    )
    findings = SstiGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1 and findings[0].rule == "ssti/user-input-in-template"

def test_ssti_pragma(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text(
        "from flask import render_template_string\ndef p(name):\n"
        "    return render_template_string('Hi ' + name)  # security: allow-ssti\n", encoding="utf-8"
    )
    assert SstiGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_ssti_na_without_python() -> None:
    assert SstiGuard().applies(mkprofile(Path("/tmp"), features={"frontend"})) is False

def test_ssti_flags_raw_template_constructor(tmp_path: Path) -> None:
    (tmp_path / "raw.py").write_text(
        "from jinja2 import Template\n"
        "def render(user_template: str):\n"
        "    return Template(user_template).render()\n",
        encoding="utf-8",
    )
    findings = SstiGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ssti/raw-template-constructor"
    assert findings[0].severity == "high"

def test_ssti_flags_dotted_jinja2_template_ctor(tmp_path: Path) -> None:
    # The module-qualified `jinja2.Template(...)` — the common CVE-2024-41950 shape.
    # Regression for the #306 review: the `(?<!\.)` lookbehind used to exclude this dotted form.
    (tmp_path / "raw.py").write_text(
        "import jinja2\n"
        "def render(user_template: str):\n"
        "    return jinja2.Template(user_template).render()\n",
        encoding="utf-8",
    )
    findings = SstiGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ssti/raw-template-constructor"

def test_ssti_flags_from_string(tmp_path: Path) -> None:
    (tmp_path / "raw.py").write_text(
        "from jinja2 import Environment\n"
        "def render(env: Environment, user_template: str):\n"
        "    return env.from_string(user_template).render()\n",
        encoding="utf-8",
    )
    findings = SstiGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ssti/raw-template-constructor"

def test_ssti_passes_literal_raw_template(tmp_path: Path) -> None:
    (tmp_path / "raw.py").write_text(
        "from jinja2 import Template\n"
        "Template('Hello {{ name }}').render(name='world')\n",
        encoding="utf-8",
    )
    assert SstiGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_ssti_raw_template_pragma(tmp_path: Path) -> None:
    (tmp_path / "raw.py").write_text(
        "from jinja2 import Template\n"
        "def render(user_template: str):\n"
        "    return Template(user_template).render()  # security: allow-ssti\n",
        encoding="utf-8",
    )
    assert SstiGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_ssti_docstring_mentioning_template_ctor_silent(tmp_path: Path) -> None:
    # PR #450 review: prose in a TRIPLE-quoted docstring that names Template(...)/from_string(...)
    # must not fire — strip_python_strings blanks docstrings before scanning.
    (tmp_path / "svc.py").write_text(
        '''def render(x):
    """Internally builds output via jinja2.Template(tpl).render() and env.from_string(s)."""
    return x
''',
        encoding="utf-8",
    )
    assert SstiGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_ssti_trailing_comment_naming_template_ctor_silent(tmp_path: Path) -> None:
    # PR #450 re-review: a TRAILING inline comment naming Template(...) must not fire —
    # comments aren't AST nodes, so strip_python_line_comment drops them before the scan.
    (tmp_path / "svc.py").write_text(
        "def f(x):\n"
        "    y = 1  # briefly: Template(x) / env.from_string(x) is used internally here\n"
        "    return y\n",
        encoding="utf-8",
    )
    assert SstiGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_ssti_fstring_template_still_fires(tmp_path: Path) -> None:
    # regression: a single-line f-string template is dynamic and MUST still fire (docstring
    # blanking only affects triple-quoted strings, not single-line f-strings).
    (tmp_path / "vuln.py").write_text(
        "import jinja2\n"
        "def render(user):\n"
        '    return jinja2.Template(f"Hello {user}").render()\n',
        encoding="utf-8",
    )
    assert len(SstiGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_ssti_literal_template_with_chained_fstring_render_silent(tmp_path: Path) -> None:
    # #423 FP-bait: the TEMPLATE is a literal; the f-string lives in the chained .render() DATA,
    # not the template — so the raw-ctor path must isolate the first arg and stay silent.
    (tmp_path / "raw.py").write_text(
        "import jinja2\n"
        "def render(a, b):\n"
        '    return jinja2.Template("Hello {{name}}").render(name=f"{a} {b}")\n',
        encoding="utf-8",
    )
    assert SstiGuard().run(tmp_path, _pyprof(tmp_path)) == []



def test_ssti_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the flagged line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-ssti"):
        (tmp_path / "v.py").write_text(
            "from flask import render_template_string\ndef p(name):\n"
            f"    return render_template_string('Hi ' + name); _note = \"{note}\"\n", encoding="utf-8"
        )
        assert len(SstiGuard().run(tmp_path, _pyprof(tmp_path))) == 1, note
