from __future__ import annotations

from agentsec.guards.llm_output_html_sink import LlmOutputHtmlSinkGuard
from tests.guards._common import *  # noqa: F401,F403

# A realistic LLM call (the provenance signal the guard now requires in-file). The result flows
# into the HTML sink in each violation fixture.
_LLM = (
    "from openai import OpenAI\n"
    "def _ask(client: OpenAI, prompt: str) -> str:\n"
    "    return client.chat.completions.create(\n"
    "        model='gpt-4o', messages=[{'role': 'user', 'content': prompt}]"
    ").choices[0].message.content\n"
)


def _llm_html_prof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"python", "fastapi", "llm"}, python_dirs=["."])


def test_llm_output_html_sink_markup_variable(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text(
        "from markupsafe import Markup\n" + _LLM +
        "def render(client, prompt):\n"
        "    llm_response = _ask(client, prompt)\n"
        "    return Markup(llm_response)\n",
        encoding="utf-8",
    )
    findings = LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "llm-output-html-sink/model-output-html-rendered"
    assert findings[0].severity == "high"


def test_llm_output_html_sink_html_response_variable(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text(
        "from fastapi.responses import HTMLResponse\n" + _LLM +
        "def render(client, prompt):\n"
        "    ai_output = _ask(client, prompt)\n"
        "    return HTMLResponse(content=ai_output)\n",
        encoding="utf-8",
    )
    findings = LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "llm-output-html-sink/model-output-html-rendered"


def test_llm_output_html_sink_html_response_positional(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text(
        "from fastapi.responses import HTMLResponse\n" + _LLM +
        "def render(client, prompt):\n"
        "    model_text = _ask(client, prompt)\n"
        "    return HTMLResponse(model_text)\n",
        encoding="utf-8",
    )
    findings = LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path))
    assert len(findings) == 1


def test_llm_output_html_sink_mark_safe_variable(tmp_path: Path) -> None:
    """Django's mark_safe() is the same class of sink as Markup()/HTMLResponse()."""
    (tmp_path / "v.py").write_text(
        "from django.utils.safestring import mark_safe\n" + _LLM +
        "def render(client, prompt):\n"
        "    llm_response = _ask(client, prompt)\n"
        "    return mark_safe(llm_response)\n",
        encoding="utf-8",
    )
    findings = LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "llm-output-html-sink/model-output-html-rendered"
    assert findings[0].severity == "high"


def test_llm_output_html_sink_fstring_arg(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text(
        "from markupsafe import Markup\n" + _LLM +
        "def render(client, prompt):\n"
        "    text = _ask(client, prompt)\n"
        '    return Markup(f"<p>{text}</p>")\n',
        encoding="utf-8",
    )
    findings = LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path))
    assert len(findings) == 1


def test_llm_output_html_sink_silent_non_llm_html_response(tmp_path: Path) -> None:
    """The structural FP fix: a dynamic HTMLResponse with NO LLM call in the file (ordinary
    server-rendered HTML) must stay silent, even in an llm-feature repo."""
    (tmp_path / "page.py").write_text(
        "from fastapi.responses import HTMLResponse\n"
        "def page(template, ctx):\n"
        "    return HTMLResponse(content=template.render(ctx))\n",
        encoding="utf-8",
    )
    assert LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path)) == []


def test_llm_output_html_sink_fp_literal_markup(tmp_path: Path) -> None:
    """Markup with a plain string literal must not fire (even with an LLM call in-file)."""
    (tmp_path / "v.py").write_text(
        "from markupsafe import Markup\n" + _LLM +
        'safe = Markup("<b>static label</b>")\n',
        encoding="utf-8",
    )
    assert LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path)) == []


def test_llm_output_html_sink_fp_literal_html_response(tmp_path: Path) -> None:
    """HTMLResponse with a literal string must not fire (even with an LLM call in-file)."""
    (tmp_path / "v.py").write_text(
        "from fastapi.responses import HTMLResponse\n" + _LLM +
        'def health(): return HTMLResponse(content="<html><body>OK</body></html>")\n',
        encoding="utf-8",
    )
    assert LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path)) == []


def test_llm_output_html_sink_fp_literal_mark_safe(tmp_path: Path) -> None:
    """mark_safe with a plain string literal must not fire (even with an LLM call in-file),
    even when assigned to a non-LLM-context name like `static_html`."""
    (tmp_path / "v.py").write_text(
        "from django.utils.safestring import mark_safe\n" + _LLM +
        'static_html = mark_safe("<b>static label</b>")\n',
        encoding="utf-8",
    )
    assert LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path)) == []


def test_llm_output_html_sink_pragma(tmp_path: Path) -> None:
    """Pragma suppresses the finding on that line (the file does call an LLM)."""
    (tmp_path / "v.py").write_text(
        "from fastapi.responses import HTMLResponse\n" + _LLM +
        "def render(client, prompt):\n"
        "    ai_output = _ask(client, prompt)\n"
        "    return HTMLResponse(content=ai_output)  # security: allow-llm-html-sink\n",
        encoding="utf-8",
    )
    assert LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path)) == []


def test_llm_output_html_sink_silent_when_sanitized(tmp_path: Path) -> None:
    # #423 FP-bait: Markup(html.escape(x)) / Markup(bleach.clean(x)) is the guard's OWN
    # recommended remediation — a sanitized argument must not fire.
    (tmp_path / "s.py").write_text(
        "from markupsafe import Markup\n"
        "import html, bleach\n" + _LLM +
        "def render(client, prompt):\n"
        "    resp = _ask(client, prompt)\n"
        "    a = Markup(html.escape(resp))\n"
        "    b = Markup(bleach.clean(resp))\n"
        "    return a, b\n",
        encoding="utf-8",
    )
    assert LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path)) == []

def test_llm_output_html_sink_fires_on_sanitized_prefix_with_concat(tmp_path: Path) -> None:
    # PR #447 review: Markup(html.escape(head) + resp) is a BYPASS — the raw `resp` still reaches
    # the sink. The sanitizer whitelist must require the sanitizer to wrap the WHOLE argument, so
    # a concatenation past the sanitizer still fires.
    (tmp_path / "s.py").write_text(
        "from markupsafe import Markup\n"
        "import html\n" + _LLM +
        "def render(client, prompt, head):\n"
        "    resp = _ask(client, prompt)\n"
        "    return Markup(html.escape(head) + resp)\n",
        encoding="utf-8",
    )
    findings = LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path))
    assert len(findings) == 1

def test_llm_output_html_sink_na_without_llm(tmp_path: Path) -> None:
    assert LlmOutputHtmlSinkGuard().applies(mkprofile(tmp_path, features={"python", "fastapi"})) is False


def test_llm_html_sink_unbalanced_sanitizer_is_not_whitelisted(tmp_path: Path) -> None:
    # Regression (#447 review): the balance walk returned True on an unbalanced call — the
    # sanitizer's parens continuing on the next line — which whitelisted the WHOLE expression.
    # Breaking the call across lines was enough to silence an unsanitised concatenation.
    # Silence-on-indeterminate is the wrong direction for a HIGH XSS rule.
    (tmp_path / "a.py").write_text(
        "from markupsafe import Markup\nimport html\nfrom openai import OpenAI\n"
        "client = OpenAI()\n"
        "def render(q, raw):\n"
        "    r = client.chat.completions.create(model='m', messages=[])\n"
        "    return Markup(html.escape(\n        r.text) + '<b>' + raw)\n",
        encoding="utf-8",
    )
    assert len(LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path))) == 1


def test_llm_html_sink_fully_sanitized_call_still_silent(tmp_path: Path) -> None:
    # FP-bait: a sanitizer that genuinely wraps the whole expression must stay whitelisted.
    (tmp_path / "a.py").write_text(
        "from markupsafe import Markup\nimport html\nfrom openai import OpenAI\n"
        "client = OpenAI()\n"
        "def render(q):\n"
        "    r = client.chat.completions.create(model='m', messages=[])\n"
        "    return Markup(html.escape(r.text))\n",
        encoding="utf-8",
    )
    assert LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path)) == []


def test_llm_html_sink_wrapped_but_closed_sanitizer_stays_silent(tmp_path: Path) -> None:
    # FP-bait (#447 review): the scan is line-based, so a sanitizer call WRAPPED over several
    # lines is unbalanced on its first line — and at ruff's line-length 110 wrapping is routine.
    # Treating "unbalanced" as "not sanitized" flagged the guard's own recommended remediation.
    # The balance check now joins the continuation lines before deciding.
    (tmp_path / "a.py").write_text(
        "from markupsafe import Markup\nimport html, bleach\nfrom openai import OpenAI\n"
        "client = OpenAI()\n"
        "def render(q):\n"
        "    r = client.chat.completions.create(model='m', messages=[])\n"
        "    a = Markup(html.escape(\n        r.text\n    ))\n"
        "    b = Markup(bleach.clean(\n        r.text,\n        tags=['b'],\n    ))\n"
        "    return a, b\n",
        encoding="utf-8",
    )
    assert LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path)) == []


def test_llm_html_sink_wrapped_bypass_over_three_lines_still_fires(tmp_path: Path) -> None:
    # The other direction: joining the continuation lines must not re-open the bypass. The
    # sanitizer closes mid-expression and raw model output is concatenated past it, so the whole
    # argument is NOT sanitized however many lines it spans.
    (tmp_path / "a.py").write_text(
        "from markupsafe import Markup\nimport html\nfrom openai import OpenAI\n"
        "client = OpenAI()\n"
        "def render(q, raw):\n"
        "    r = client.chat.completions.create(model='m', messages=[])\n"
        "    return Markup(html.escape(\n        r.text\n    ) + '<b>' + raw)\n",
        encoding="utf-8",
    )
    assert len(LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path))) == 1


def test_llm_html_sink_bypass_wrapped_one_operand_per_line_still_fires(tmp_path: Path) -> None:
    # THE #447 re-review CRITICAL. The join used to stop the moment the paren depth returned to
    # zero, so `Markup(` alone on its line ended the "logical" argument before it began and the
    # bypass below was silent — a live XSS bypass, while the SAME bypass on one physical line
    # fired. The join now runs to the SINK's own closing paren, so it sees the concatenation
    # however the expression is wrapped. One operand per line is routine at line-length 110.
    (tmp_path / "a.py").write_text(
        "from markupsafe import Markup\nimport html\nfrom openai import OpenAI\n"
        "client = OpenAI()\n"
        "def render(q, raw):\n"
        "    r = client.chat.completions.create(model='m', messages=[])\n"
        "    return Markup(\n"
        "        html.escape(r.text)\n"
        "        + '<b>'\n"
        "        + raw\n"
        "    )\n",
        encoding="utf-8",
    )
    assert len(LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path))) == 1


def test_llm_html_sink_wrapped_sinks_of_every_shape_still_fire(tmp_path: Path) -> None:
    # The same wrapped-argument blindness across the other two sinks and the other dynamic shapes:
    # a raw multi-line `HTMLResponse(content=...)`, a wrapped `mark_safe()` bypass, a wrapped
    # f-string, and a second sink LATER ON THE SAME LINE whose sanitized neighbour used to dismiss
    # the whole line.
    (tmp_path / "a.py").write_text(
        "from markupsafe import Markup\nfrom django.utils.safestring import mark_safe\n"
        "from fastapi.responses import HTMLResponse\nimport html\nfrom openai import OpenAI\n"
        "client = OpenAI()\n"
        "def render(q, raw):\n"
        "    r = client.chat.completions.create(model='m', messages=[])\n"
        "    a = HTMLResponse(\n        content=r.text,\n        status_code=200,\n    )\n"
        "    b = mark_safe(\n        html.escape(r.text)\n        + raw\n    )\n"
        "    c = Markup(\n        f'<b>{r.text}</b>'\n    )\n"
        "    d = Markup(html.escape(r.text)) + Markup(r.text)\n"
        "    return a, b, c, d\n",
        encoding="utf-8",
    )
    findings = LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path))
    assert [f.location.rsplit(":", 1)[1] for f in findings] == ["9", "13", "17", "20"]


def test_llm_html_sink_wrapped_remediation_shapes_stay_silent(tmp_path: Path) -> None:
    # FP-bait for the widened join, in every shape the remediation is actually written in:
    # a `bleach.clean()` with one kwarg per line (the reported 10-line cap would have fired on it),
    # a multi-line `HTMLResponse(content=html.escape(...))` whose `content=` sits on a continuation
    # line, a sanitized value followed by another keyword argument, a literal multi-line response,
    # and parens/`#` inside a string literal (which must not skew the balance).
    (tmp_path / "a.py").write_text(
        "from markupsafe import Markup\nfrom fastapi.responses import HTMLResponse\n"
        "import html, bleach\nfrom openai import OpenAI\n"
        "client = OpenAI()\n"
        "def render(q):\n"
        "    r = client.chat.completions.create(model='m', messages=[])\n"
        "    a = Markup(bleach.clean(\n"
        "        r.text,\n        tags=['b'],\n        attributes={},\n        protocols=['https'],\n"
        "        strip=True,\n        strip_comments=True,\n        css_sanitizer=None,\n"
        "        filters=None,\n    ))\n"
        "    b = HTMLResponse(\n        content=html.escape(r.text),\n        status_code=200,\n    )\n"
        "    c = HTMLResponse(content=html.escape(r.text), status_code=200)\n"
        "    d = HTMLResponse(\n        content='<b>ok</b>',\n        status_code=200,\n    )\n"
        "    e = Markup(  # render (\n        html.escape(r.text + '(#')\n    )\n"
        "    return a, b, c, d, e\n",
        encoding="utf-8",
    )
    assert LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path)) == []


def test_llm_output_html_sink_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the sink line is not a comment; neutral run = control.
    # The string goes BEFORE the sink: the guard reads everything after the sink's `(` to the end of
    # the line as its argument, so a trailing string would read as a literal argument instead.
    for note in ("# reviewed", "# security: allow-llm-html-sink"):
        (tmp_path / "v.py").write_text(
            "from fastapi.responses import HTMLResponse\n" + _LLM +
            "def render(client, prompt):\n"
            "    ai_output = _ask(client, prompt)\n"
            f'    _note = "{note}"; return HTMLResponse(content=ai_output)\n',
            encoding="utf-8",
        )
        assert len(LlmOutputHtmlSinkGuard().run(tmp_path, _llm_html_prof(tmp_path))) == 1, note
