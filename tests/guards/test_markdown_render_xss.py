from __future__ import annotations

from agentsec.guards.markdown_render_xss import MarkdownRenderXssGuard
from tests.guards._common import *  # noqa: F401,F403


def test_markdown_render_xss_flags_streamlit_unsafe_html(tmp_path: Path) -> None:
    (tmp_path / "ui.py").write_text(
        "import streamlit as st\n"
        "\n"
        "answer = get_response()\n"
        "st.markdown(answer, unsafe_allow_html=True)\n",
        encoding="utf-8",
    )
    findings = MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "markdown-render-xss/streamlit-unsafe-html" in rules

def test_markdown_render_xss_flags_unsafe_html_kwarg_reordered(tmp_path: Path) -> None:
    # unsafe_allow_html=True can appear as first arg — still fires.
    (tmp_path / "app.py").write_text(
        "import streamlit as st\n"
        "st.markdown(unsafe_allow_html=True, body=model_output)\n",
        encoding="utf-8",
    )
    findings = MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "markdown-render-xss/streamlit-unsafe-html" in rules

def test_markdown_render_xss_flags_ipython_html(tmp_path: Path) -> None:
    (tmp_path / "notebook.py").write_text(
        "from IPython.display import HTML\n"
        "display(HTML(model_output))\n",
        encoding="utf-8",
    )
    findings = MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "markdown-render-xss/ipython-html-display" in rules

def test_markdown_render_xss_flags_ipython_module_form(tmp_path: Path) -> None:
    (tmp_path / "notebook.py").write_text(
        "import IPython.display\n"
        "IPython.display.HTML(response)\n",
        encoding="utf-8",
    )
    findings = MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "markdown-render-xss/ipython-html-display" in rules

def test_markdown_render_xss_silent_for_safe_streamlit_markdown(tmp_path: Path) -> None:
    # Default (no unsafe_allow_html) is safe — Streamlit strips HTML tags.
    (tmp_path / "ui.py").write_text(
        "import streamlit as st\n"
        "st.markdown(response)\n",
        encoding="utf-8",
    )
    assert MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_markdown_render_xss_silent_for_explicit_false(tmp_path: Path) -> None:
    (tmp_path / "ui.py").write_text(
        "import streamlit as st\n"
        "st.markdown(response, unsafe_allow_html=False)\n",
        encoding="utf-8",
    )
    assert MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_markdown_render_xss_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "ui.py").write_text(
        "# security: allow-markdown-xss\n"
        "import streamlit as st\n"
        "st.markdown(answer, unsafe_allow_html=True)\n",
        encoding="utf-8",
    )
    assert MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_markdown_render_xss_not_applicable_without_llm_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python", "fastapi"})
    assert MarkdownRenderXssGuard().applies(prof) is False

def test_markdown_render_xss_standalone_html_call_silent(tmp_path: Path) -> None:
    # FP fix: standalone HTML( calls outside IPython display context (e.g. argparse help
    # strings) should NOT fire — only IPython.display.HTML() and display(HTML()) are flagged.
    (tmp_path / "cli.py").write_text(
        "import argparse\n"
        "parser = argparse.ArgumentParser()\n"
        "parser.add_argument('--fmt', help='Output as HTML (HTML(...) format)')\n",
        encoding="utf-8",
    )
    assert MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_markdown_render_xss_flags_multiline_streamlit_call(tmp_path: Path) -> None:
    # black-formatted call: the unsafe_allow_html kwarg lands on its own line, so a
    # per-line search never sees the whole pattern. Lineno points at st.markdown(.
    (tmp_path / "ui.py").write_text(
        "import streamlit as st\n"
        "\n"
        "st.markdown(\n"
        "    answer,\n"
        "    unsafe_allow_html=True,\n"
        ")\n",
        encoding="utf-8",
    )
    findings = MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["markdown-render-xss/streamlit-unsafe-html"]
    assert findings[0].location.endswith("ui.py:3")

def test_markdown_render_xss_silent_for_multiline_without_flag(tmp_path: Path) -> None:
    # FP bait: multi-line calls without the flag (or with it explicitly False) stay silent.
    (tmp_path / "ui.py").write_text(
        "import streamlit as st\n"
        "st.markdown(\n"
        "    response,\n"
        ")\n"
        "st.markdown(\n"
        "    other,\n"
        "    unsafe_allow_html=False,\n"
        ")\n",
        encoding="utf-8",
    )
    assert MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_markdown_render_xss_multiline_no_cross_call_bleed(tmp_path: Path) -> None:
    # A completed safe call cannot chain into a later unsafe one ([^)]* stops at the
    # first close paren): only the second call fires, at its own line.
    (tmp_path / "ui.py").write_text(
        "import streamlit as st\n"
        "st.markdown(header)\n"
        "st.markdown(\n"
        "    answer,\n"
        "    unsafe_allow_html=True,\n"
        ")\n",
        encoding="utf-8",
    )
    findings = MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith("ui.py:3")

def test_markdown_render_xss_display_html_still_fires(tmp_path: Path) -> None:
    # Regression: display(HTML(...)) must still be caught after the fix.
    (tmp_path / "nb.py").write_text(
        "from IPython.display import HTML, display\n"
        "display(HTML(model_output))\n",
        encoding="utf-8",
    )
    findings = MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "markdown-render-xss/ipython-html-display" for f in findings)



def test_markdown_xss_commented_out_kwarg_is_silent(tmp_path: Path) -> None:
    # Regression (#437 review): `_STREAMLIT_UNSAFE` spans newlines under DOTALL to reach a
    # wrapped call's kwargs, which let it span into a `#` comment INSIDE that call — so a
    # deliberately commented-out `# unsafe_allow_html=True,` fired HIGH on code that has the
    # flag turned OFF.
    (tmp_path / "app.py").write_text(
        "import streamlit as st\nst.markdown(\n    body,\n    # unsafe_allow_html=True,\n)\n",
        encoding="utf-8",
    )
    assert MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_markdown_xss_wrapped_call_still_fires(tmp_path: Path) -> None:
    # The capability the DOTALL span exists for — a black-formatted call with the flag really on.
    (tmp_path / "app.py").write_text(
        "import streamlit as st\nst.markdown(\n    body,\n    unsafe_allow_html=True,\n)\n",
        encoding="utf-8",
    )
    findings = MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1 and findings[0].rule == "markdown-render-xss/streamlit-unsafe-html"


def test_markdown_render_xss_flags_streamlit_html_call(tmp_path: Path) -> None:
    # st.html() has no unsafe_allow_html opt-in at all — every call is a raw-HTML render.
    (tmp_path / "ui.py").write_text(
        "import streamlit as st\n"
        "\n"
        "answer = get_response()\n"
        "st.html(answer)\n",
        encoding="utf-8",
    )
    findings = MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "markdown-render-xss/streamlit-html-call" in rules


def test_markdown_render_xss_flags_multiline_streamlit_html_call(tmp_path: Path) -> None:
    # black-formatted call: the argument lands on its own line. Lineno points at st.html(.
    (tmp_path / "ui.py").write_text(
        "import streamlit as st\n"
        "\n"
        "st.html(\n"
        "    answer,\n"
        ")\n",
        encoding="utf-8",
    )
    findings = MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["markdown-render-xss/streamlit-html-call"]
    assert findings[0].location.endswith("ui.py:3")


def test_markdown_render_xss_silent_for_st_html_in_docstring(tmp_path: Path) -> None:
    # FP-bait (review M6): a code EXAMPLE inside a docstring must not be mistaken for a live
    # call — `strip_python_strings` blanks triple-quoted content before matching.
    (tmp_path / "ui.py").write_text(
        "import streamlit as st\n"
        "\n"
        "\n"
        "def render_answer(answer: str) -> None:\n"
        '    """Call st.html(answer) to render it as raw HTML if you really need to."""\n'
        "    st.markdown(answer)\n",
        encoding="utf-8",
    )
    findings = MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "markdown-render-xss/streamlit-html-call" not in rules


def test_markdown_render_xss_streamlit_html_call_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "ui.py").write_text(
        "# security: allow-markdown-xss\n"
        "import streamlit as st\n"
        "st.html(answer)\n",
        encoding="utf-8",
    )
    assert MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_markdown_render_xss_silent_for_st_markdown_fp_bait(tmp_path: Path) -> None:
    # FP bait: st.markdown(...) (no unsafe_allow_html) must NOT trip the new st.html()
    # rule — the two APIs share a prefix (`st.`) but the regex requires `html(` directly,
    # so a safe-default st.markdown() call stays silent under the new check too.
    (tmp_path / "ui.py").write_text(
        "import streamlit as st\n"
        "st.markdown(response)\n"
        "st.html_component_registry.get('foo')\n",
        encoding="utf-8",
    )
    assert MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# ── #425 / #586: one ipython-html-display finding per display line, not one per repo ──

_IPY_RULE = "markdown-render-xss/ipython-html-display"


def test_markdown_render_xss_reports_every_ipython_html_display(tmp_path: Path) -> None:
    # Regression for #425 (absorbing #586): _check_ipython_html returned its first hit from
    # inside the all-files loop, so ten notebooks rendering model output as HTML reported
    # one finding. Two lines in one file plus one in another must give exactly three.
    (tmp_path / "nb_a.py").write_text(
        "from IPython.display import HTML, display\n"
        "display(HTML(model_output))\n"
        "display(HTML(summary))\n",
        encoding="utf-8",
    )
    (tmp_path / "nb_b.py").write_text(
        "import IPython.display\n"
        "IPython.display.HTML(response)\n",
        encoding="utf-8",
    )
    findings = [
        f for f in MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path)) if f.rule == _IPY_RULE
    ]
    assert len(findings) == 3
    assert {f.location for f in findings} == {"nb_a.py:2", "nb_a.py:3", "nb_b.py:2"}


def test_markdown_render_xss_benign_display_after_a_hit_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the #425 widening: lines after the first hit used to be unreachable. A
    # Markdown display, a docstring example and an argparse `HTML(` help string, all after a
    # real hit in the same file, must not become extra findings now that the loop keeps going.
    (tmp_path / "nb.py").write_text(
        "from IPython.display import HTML, Markdown, display\n"
        "display(HTML(model_output))\n"
        "display(Markdown(model_output))\n"
        "\n"
        "\n"
        "def show(x: str) -> None:\n"
        '    """Never call display(HTML(x)) on model output."""\n'
        "    parser.add_argument('--fmt', help='Output as HTML (HTML(...) format)')\n",
        encoding="utf-8",
    )
    findings = MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [(f.rule, f.location) for f in findings] == [(_IPY_RULE, "nb.py:2")]


def test_markdown_render_xss_pragma_in_third_file_silences_every_ipython_display(
    tmp_path: Path,
) -> None:
    # The opt-out is repo-wide and must keep seeing every file after the #425 change.
    for name in ("nb_a.py", "nb_b.py"):
        (tmp_path / name).write_text(
            "from IPython.display import HTML, display\ndisplay(HTML(model_output))\n",
            encoding="utf-8",
        )
    (tmp_path / "zz_settings.py").write_text("# security: allow-markdown-xss\n", encoding="utf-8")
    assert MarkdownRenderXssGuard().run(tmp_path, _llm_prof(tmp_path)) == []
