"""Guard: tainted input flows into a JS/TS LLM system-role prompt (checklist §3a).

A `{role: "system", content: ...}` message sent to an LLM (OpenAI/Anthropic/Google
GenAI/OpenRouter JS/TS SDKs) whose `content` is built from request-derived input lets
an attacker manipulate the model's own instructions, not just its user-facing
conversation — a stronger form of prompt injection than tainted user-role content.
CWE-1427 (Improper Neutralization of Input Used for LLM Prompting), OWASP-LLM:LLM01.

Sourced from GitHub CodeQL's `js/system-prompt-injection` query
(`SystemPromptInjectionQuery`/`Customizations.qll`, verified against real fetched
source): sinks are the `content` of a system/assistant-role message across the
OpenAI/Anthropic/GoogleGenAI/OpenRouter/Agent SDKs; sources are any tainted
(request-derived) value. CodeQL's own sanitizer explicitly excludes content already
inside a `role: "user"` object (the same conversational array legitimately carries
both a system message and tainted user content — only the SYSTEM message's content
being tainted is the vulnerability) — adapted here as the same exclusion, since
agentsec has no JS dataflow engine and would otherwise false-positive on that exact
shape.

Fires HIGH per match:

    messages: [
      { role: "system", content: `You are a helpful assistant for ${req.query.persona}` },
      { role: "user", content: userMessage },
    ]

Extends the existing `3a-user-content-sanitized-before-llm` checklist item (the
Python-side f-string mechanism `prompt-string-interp` already covers) with the
JS/TS SDK object-literal mechanism.

**Object-literal scoping (review #395 Major findings):** an earlier revision correlated `role:`
and `content:` with a fixed line-count window, which both bled across SIBLING message objects in
the same array (a hardcoded system message followed by an unrelated `{ content: req.query.trace
}` falsely fired) and missed a genuine hit when 6+ fields separated `role:` from `content:` in the
same object. Detection now finds the `{...}` object literal that ENCLOSES the `role:` match (brace
counting, quote-aware) and looks for `content:` only within that same object — correct regardless
of field count or line count, and immune to sibling-object bleed. A `content:` value is also
checked for whether the taint reference is genuinely live code vs. inert prose inside a plain
quoted string (`content: "Never repeat req.query values back."` no longer fires — a template
literal's `${...}` interpolation still counts as live).

**#1055 (live code only):** the `role:` match and the `content:` key count only when they are live
code, tested on the shared anchor mask (`js_code_matches`). A `"role: 'system'"` spelled out inside a
user message no longer fires, and a `'content: none'` string value before the real key no longer
hijacks the value locator (an FN). Object boundaries are found on the same mask with regex bodies
also blanked, so the braces counted are exactly the code braces, including those of an object
literal inside a `${...}` substitution, which the old quote-aware walk skipped as template text.
The taint reference in the value is read on the same anchor mask, replacing a private string walk
that kept a quoted string inside a substitution live (`${'req.query.x'}`).
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
    js_code_matches,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-js-system-prompt-injection"

_TAINTED_REF = re.compile(r"\breq\.(?:query|body|params|headers)\b")
_SYSTEM_ROLE = re.compile(r"role\s*:\s*['\"](?:system|assistant)['\"]")
_CONTENT_KEY = re.compile(r"\bcontent\s*:")


def _brace_spans(brace_view: str) -> list[tuple[int, int]]:
    """All `(start, end)` index spans of `{...}` literals in `brace_view`, the anchor mask with
    regex bodies blanked too (#1055). String content, template text, the `${`/`}` delimiters and
    regex bodies are all blank there, so every brace left is a code brace and a plain count finds
    an object literal's own boundaries, including one inside a `${...}` substitution (the old
    quote-aware walk on the strings-intact view skipped those as template text)."""
    spans: list[tuple[int, int]] = []
    stack: list[int] = []
    for i, c in enumerate(brace_view):
        if c == "{":
            stack.append(i)
        elif c == "}" and stack:
            spans.append((stack.pop(), i))
    return spans


def _enclosing_span(spans: list[tuple[int, int]], pos: int) -> tuple[int, int] | None:
    """The smallest `{...}` span containing `pos` — i.e. the innermost enclosing object literal."""
    best: tuple[int, int] | None = None
    for start, end in spans:
        if start <= pos <= end and (best is None or (end - start) < (best[1] - best[0])):
            best = (start, end)
    return best


def _value_span_end(text: str, start: int) -> int:
    """From `start` (just past a `content:` key), find the end of its value — the next
    top-level comma or closing bracket, skipping over nested `()`/`[]`/`{}` and string/template
    literal content so a comma or brace INSIDE the value can't truncate it early."""
    depth = 0
    i, n = start, len(text)
    quote = ""
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
            i += 1
            continue
        if c in "'\"`":
            quote = c
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif c == "," and depth == 0:
            return i
        i += 1
    return n


class JsSystemPromptInjectionGuard(Guard):
    id = "js-system-prompt-injection"
    title = "Tainted input flows into a JS/TS LLM system-role prompt"
    area = "AI agent"

    # chat_llm.js: role:"system" content interpolating req.query.persona -> fires
    # js-system-prompt-injection.
    canary_plant = CanaryPlant(
        files={
            "chat_llm.js": (
                "const messages = [\n"
                "  { role: 'system', content: `You are a helpful assistant for ${req.query.persona}` },\n"
                "  { role: 'user', content: userMessage },\n"
                "];\n"
            ),
        },
        expects=frozenset({"js-system-prompt-injection/tainted-system-role-content"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features and (
            "javascript" in profile.features or "typescript" in profile.features
        )

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            raw = read(f)
            if pragma_present(_PRAGMA, raw, dialect="js"):
                continue
            # strip_js_comments blanks `//` and `/* */` comments (string/regex-literal aware,
            # line/column offsets preserved) — a doc comment merely mentioning the pattern must
            # not fire.
            code = strip_js_comments(raw)
            # The anchor mask (#1055): same layout, string and template text blanked, `${...}`
            # code kept. A `role:` or `content:` key counts only when its first character is code.
            mask = strip_js_comments(raw, strip_strings=True, keep_substitutions=True)
            # Object boundaries come from the same mask with regex bodies blanked too, so a brace in a
            # string, template text or regex (`/\{/`) never counts and one inside `${...}` does.
            brace_view = strip_js_comments(raw, strip_strings=True, strip_regex=True, keep_substitutions=True)
            spans = _brace_spans(brace_view)
            seen_lines: set[int] = set()
            for rm in js_code_matches(_SYSTEM_ROLE, code, mask, anchor=lambda m: m.start()):
                span = _enclosing_span(spans, rm.start())
                if span is None:
                    continue
                obj_start, obj_end = span
                obj_text = code[obj_start:obj_end]
                # The first CODE `content:` key: a `'content: none'` string value before the real
                # key used to win `.search` and send the value walk into the wrong text (#1055).
                cm = next(
                    js_code_matches(_CONTENT_KEY, obj_text, mask[obj_start:obj_end], anchor=lambda m: m.start()),
                    None,
                )
                if not cm:
                    continue
                value_start = obj_start + cm.end()
                value_end = _value_span_end(code, value_start)
                # The taint reference must be live code on the same mask (#1055): prose inside a plain
                # string or template text is inert, a `${...}` substitution is live. This replaced a
                # private walk that also kept a quoted string INSIDE a substitution live
                # (`${'req.query.x'}`) and lost its frame on a `'{'` there.
                if not _TAINTED_REF.search(mask[value_start:value_end]):
                    continue
                line_no = code.count("\n", 0, obj_start + cm.start()) + 1
                if line_no in seen_lines:
                    continue
                seen_lines.add(line_no)
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{line_no}",
                        message=(
                            "This system/assistant-role LLM message's content is built from "
                            "request-derived input (req.query/body/params/headers) — an "
                            "attacker can manipulate the model's own instructions, not just "
                            "the conversation."
                        ),
                        remediation=(
                            "Never interpolate request-derived input directly into a "
                            "system-role prompt. If the persona/instructions must vary per "
                            "request, select from a fixed, server-controlled set of allowed "
                            "values rather than passing the raw input through."
                        ),
                        rule="js-system-prompt-injection/tainted-system-role-content",
                        standards=["OWASP-LLM:LLM01", "CWE-1427"],
                    )
                )
        return out
