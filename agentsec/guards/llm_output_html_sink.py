"""Guard: LLM output must not flow into an HTML rendering sink (checklist 4-llm-output-sanitized).

The XSS companion to llm-output-to-sink: instead of executing the model's answer,
the app renders it as trusted HTML. Three high-confidence sinks:

  * `Markup(var)` — Jinja2/Werkzeug marks the value as safe, bypassing auto-escaping.
    If `var` is LLM output an attacker steers via prompt injection, they can inject
    arbitrary HTML/JavaScript into every page that renders it.

  * `HTMLResponse(var)` / `HTMLResponse(content=var)` — FastAPI/Starlette sends the
    value verbatim as `Content-Type: text/html`, giving the attacker a full XSS
    primitive in the browser.

  * `mark_safe(var)` — Django's equivalent of `Markup()`: marks the value as
    pre-sanitized so the template engine renders it without auto-escaping. Same
    class of bug when `var` is LLM output. Cross-checked against `llmarmor/llmarmor`'s
    LLM05 rule (`src/llmarmor/rules/llm05_improper_output.py`), which flags this same
    sink for the same reason.

Fires HIGH when any of the three calls receives a non-literal argument (a variable,
f-string, or concatenation — anything whose value the model could influence). Safe
literals (e.g. `Markup("<b>OK</b>")`) are NOT flagged.

Note: `render_template_string(var)` (SSTI) is already covered by the `ssti` guard,
which fires on all Python stacks. This guard adds the XSS/injection path and is
gated on `llm` to focus on model-output handling specifically.

OWASP-LLM:LLM05 (Insecure Output Handling) / OWASP:A03 / CWE-79.
Suppress an audited case with `# security: allow-llm-html-sink` on the line.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

# Jinja2 / Werkzeug safe-mark, FastAPI / Starlette direct HTML response, or Django safe-mark.
_HTML_SINK = re.compile(
    r"\bMarkup\s*\("
    r"|\bHTMLResponse\s*\(\s*(?:content\s*=\s*)?"
    r"|\bmark_safe\s*\("
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-llm-html-sink")

# Provenance gate: only files that actually CALL an LLM can produce model output, so the guard
# scans a file only when it invokes one. Mirrors string-format-injection's _LLM_CALL_DIRECT — the
# proven, FP-safe signal (openai/anthropic SDK create calls). Conservative/FN-biased by design: a
# langchain-only app whose output never passes through a `*.create(` is not flagged (acceptable, the
# project prefers a miss over the FP of flagging ordinary server-rendered HTML).
_LLM_CALL = re.compile(
    r"\b\w+\.chat\.completions\.create\s*\("
    r"|\b\w+\.responses\.create\s*\("
    r"|\b\w+\.messages\.create\s*\(",
    re.IGNORECASE,
)

# Helpers to identify non-literal arguments (borrowed from the ssti guard approach).
_FSTRING = re.compile(r"(?:^|[\s(,=+])[rR]?[fF]['\"]")
_CONCAT = re.compile(r"['\"]\s*\+|\+\s*['\"]|\.format\s*\(|%[sdrfeg]")
# The argument is already run through an HTML sanitizer/escaper — the guard's OWN recommended
# remediation. `Markup(html.escape(x))` / `Markup(bleach.clean(x))` must NOT fire (#423).
_SANITIZED = re.compile(
    r"^\s*(?:markupsafe\.|flask\.|html\.)?escape\s*\("
    r"|^\s*bleach\.clean\s*\("
    r"|^\s*nh3\.clean\s*\(",
    re.IGNORECASE,
)


def _is_dynamic(arg: str) -> bool:
    """True when the argument text is not a plain string literal."""
    a = arg.strip()
    if not a:
        return False
    if _FSTRING.search(a):
        return True
    if "'" not in a and '"' not in a:
        return True
    return bool(_CONCAT.search(a))


# A multi-line `HTMLResponse(\n    content=...)` puts the keyword on a CONTINUATION line, so the
# sink pattern (which consumes `content=` only when it shares the line) never eats it. Strip it
# before the sanitizer match, or the wrapped-but-sanitized form reads as unsanitized.
_CONTENT_KW = re.compile(r"^\s*content\s*=\s*", re.I)


def _is_wholly_sanitized(logical: str, closed: bool) -> bool:
    """True iff the sink's first argument is EXACTLY a sanitizer call — nothing concatenated
    or branched in after it. `Markup(html.escape(x))` is safe, but `Markup(html.escape(x) + raw)`
    is a bypass (raw content still reaches the sink) and must NOT be whitelisted (PR #447 review).

    `logical` is the WHOLE argument expression (see `_logical_arg`); `closed` says whether the
    sink's own `)` was reached before the join budget ran out.
    """
    a = _CONTENT_KW.sub("", logical.lstrip(), count=1)
    if not _SANITIZED.match(a):
        return False
    depth = 0
    started = False
    for j, ch in enumerate(a):
        if ch == "(":
            depth += 1
            started = True
        elif ch == ")":
            depth -= 1
            if started and depth == 0:
                # Only the sink's own closing `)`, a following keyword argument (`,` — e.g.
                # `HTMLResponse(content=html.escape(x), status_code=200)`; the sanitized value is
                # still the whole body), or trailing whitespace may follow. Anything else (`+`,
                # `if`, `%`, `.format`) means unsanitized content reaches the sink too.
                rest = a[j + 1 :].strip()
                return rest == "" or rest[0] in "),"
    # The sanitizer call never closed inside the join budget. If the join was TRUNCATED at the cap
    # we have a prefix, not a verdict: what we could see is a sanitizer call with nothing
    # concatenated onto it, so the recommended remediation is not reported as the vulnerability
    # (#447 re-review — the cap must not manufacture a finding). If the join did close, the parens
    # are unbalanced for some other reason (a quote artifact) and we fall through to `_is_dynamic`.
    return not closed


# How many continuation lines `_logical_arg` will absorb. Deliberately generous: the join now runs
# to the SINK's own closing paren, so it must cover the whole call — e.g. a `bleach.clean()` with a
# kwarg per line. The cap only stops a runaway/never-balancing expression from walking the file.
_MAX_CONTINUATION_LINES = 40


def _split_code(s: str) -> tuple[str, int]:
    """`(code, paren-depth delta)` for one physical line: a trailing `#` comment is dropped and
    parens are counted only OUTSIDE single-line string literals, so neither `# note (` nor
    `Markup("a (b")` can skew the balance the join depends on."""
    out: list[str] = []
    depth = 0
    quote = ""
    i = 0
    while i < len(s):
        ch = s[i]
        if quote:
            if ch == "\\":
                out.append(ch)
                i += 1
                if i < len(s):
                    out.append(s[i])
                    i += 1
                continue
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "#":
            break
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        out.append(ch)
        i += 1
    return "".join(out), depth


def _logical_arg(lines: list[str], idx: int, start: int) -> tuple[str, bool]:
    """The sink's argument as a LOGICAL expression, not one physical line.

    INVARIANT: the guard decides on the sink call's COMPLETE argument — everything between the
    sink's `(` and its matching `)` — however the expression is wrapped. So the join runs until the
    SINK's paren balance closes, never until some inner call happens to balance: stopping at the
    first zero made the decision on a truncated prefix, and

        Markup(                     # depth 0 on this line already -> nothing joined
            html.escape(r.text)
            + external_banner
        )

    was silent while the same bypass on one line fired (#447 re-review). Returns the joined text
    and whether the sink actually closed within `_MAX_CONTINUATION_LINES`.
    """
    code, delta = _split_code(lines[idx][start:])
    parts = [code]
    depth = 1 + delta  # 1 = the sink's own `(`, already consumed by the sink match
    n = idx + 1
    while depth > 0 and n < len(lines) and n - idx <= _MAX_CONTINUATION_LINES:
        code, delta = _split_code(lines[n])
        parts.append(code)
        depth += delta
        n += 1
    return " ".join(p.strip() for p in parts), depth <= 0


class LlmOutputHtmlSinkGuard(Guard):
    id = "llm-output-html-sink"
    title = "LLM output flows into an HTML sink — model-driven XSS"
    area = "AI agent"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `html_output.py` (which `llm-input-size-cap` also trips), so that file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # html_output.py: Markup(llm_response) -> fires llm-output-html-sink.
    canary_plant = CanaryPlant(expects=frozenset({"llm-output-html-sink/model-output-html-rendered"}))

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                text = read(f)
                # Provenance gate: no LLM call in this file -> its HTML sinks aren't model output.
                if not _LLM_CALL.search(text):
                    continue
                out.extend(self._scan(root, f, text))
        return out

    def _fires(self, lines: list[str], idx: int, start: int) -> bool:
        """Does the sink whose `(` ends at `start` on line `idx` receive unsanitized dynamic
        content? Both halves of the question are answered on the LOGICAL argument (`_logical_arg`),
        never on the physical line — that is the whole point of the join."""
        logical, closed = _logical_arg(lines, idx, start)
        if _is_wholly_sanitized(logical, closed):
            return False  # arg is exactly html.escape()/bleach.clean() — the recommended remediation
        return _is_dynamic(logical.rstrip().rstrip(")"))

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        # Strip docstrings so an anti-pattern EXAMPLE in prose (incl. this guard's own
        # docstring, and any target-repo docs) doesn't self-trip the matcher.
        stripped = strip_python_strings(text, filename=f)
        lines = stripped.splitlines()
        # The pragma counts only as a real comment on the line, never quoted in a string there (#1040),
        # numbered on the text walked below (a form feed in a docstring shifts the raw count, #1132).
        pragmas = pragma_line_set(_PRAGMA, stripped, dialect="python")
        for i, line in enumerate(lines, start=1):
            if line.lstrip().startswith("#") or i in pragmas:
                continue
            # EVERY sink on the line, not just the first: `Markup(html.escape(a)) + Markup(raw)`
            # used to be dismissed on the sanitized one. At most one finding per line is emitted
            # (the line is the reported location), so the report shape is unchanged.
            if not any(self._fires(lines, i - 1, m.end()) for m in _HTML_SINK.finditer(line)):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{i}",
                    message=(
                        # NOTE: the first 120 chars are byte-stable vs the shipped (pre-mark_safe)
                        # message so Finding.fingerprint() does not shift for existing baselines
                        # (#451 review). The mark_safe() mention is appended AFTER that window.
                        "Model output is passed to an HTML rendering sink "
                        "(`Markup()` or `HTMLResponse()`). An attacker who steers "
                        "the model via prompt injection can inject arbitrary HTML "
                        "or JavaScript into responses served to users (XSS). "
                        "Django's `mark_safe()` is treated as the same sink class."
                    ),
                    remediation=(
                        "Never mark model output as safe HTML. Use `html.escape()` "
                        "before `Markup()`/`mark_safe()`, or pass the value as plain-text data to a "
                        "Jinja2/Django template (auto-escaping handles it). For HTML responses, "
                        "sanitize with bleach or a strict allowlist before rendering. "
                        "Suppress a reviewed, safe case with `# security: allow-llm-html-sink`."
                    ),
                    rule="llm-output-html-sink/model-output-html-rendered",
                    standards=["OWASP-LLM:LLM05", "OWASP:A03"],
                )
            )
        return out
