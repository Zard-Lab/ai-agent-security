"""Guard: `text/template` used where `html/template`'s auto-escaping is needed (CWE-79).

Go ships two template packages with an almost identical API — `Must`, `New`, `Parse`,
`ParseFiles`, `Execute`, `ExecuteTemplate` all exist on both — but only one of them does
anything about output safety:

  * `html/template` is context-aware: it inspects where a substitution lands (HTML body,
    an attribute, a `<script>` block, a `href=`) and escapes the value for THAT context.
  * `text/template` does pure string substitution. No escaping, ever, in any context.

Because the two packages are drop-in compatible (both even declare `package template`, so
the identifier at the call site — `template.Must(template.New(...).Parse(...))` — looks
identical either way), the only place the choice is visible is the import line. A
find-and-replace refactor, a copy-pasted example from the wrong doc page, or an import
auto-fix that picks the first `template` match silently downgrades every field in the
template to unescaped string substitution. Any field sourced from a request parameter,
a stored user value, or an LLM/agent response then becomes a straightforward stored or
reflected XSS vector the moment the rendered output is written to an HTTP response body.

Fires HIGH on two independent signals, both requiring an `http.ResponseWriter` reference
in the same file (the strong "this file serves HTTP responses" cue) — see the design doc
for the full scoping rationale:

  * **Signal 1 (primary)** — the file imports `"text/template"`, does NOT also import
    `"html/template"`, and references `http.ResponseWriter` somewhere. A file legitimately
    using both packages for different purposes (text/template for a config/CLI generator,
    html/template for actual page rendering) does not fire on the text/template import
    alone — see "When NOT to flag".
  * **Signal 2 (secondary)** — a `<ident>.Must(<ident>.New(...).Parse...(...))`-style
    construction chain built from the identifier `"text/template"` is bound to, with an
    `.Execute(`/`.ExecuteTemplate(` call and an `http.ResponseWriter` reference nearby in
    the source. Catches the same bug when `html/template` is ALSO imported (so signal 1's
    exclusion doesn't apply) but the specific chain in view is unambiguously text/template.

Both signals require ALL of their conditions together — this guard is deliberately narrow.
`text/template` alone is an extremely common, totally safe pattern (config-file generation,
CLI output, email/text bodies, code generation) and firing on it unconditionally would be
loud and mostly wrong.

Suppress an audited case (e.g. the template's fields are all fixed constants, or the
response is verified non-HTML, like a generated `.txt`/`.csv` download) with
`// security: allow-go-template-html-escaping`. Scoped to what it suppresses: signal 1 fires at
most once per file (the import line), so the pragma may go anywhere in the file; signal 2 can fire
once per handler, so its pragma must be inside THAT handler's own function — one audited handler's
pragma must not silence a different, unaudited handler in the same file (#565 review, Dean).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    go_scan_dirs,
    is_nonproduct_path,
    iter_files,
    read,
    rel,
    strip_go_comments,
)

_PRAGMA = re.compile(r"//\s*security:\s*allow-go-template-html-escaping")

_STANDARDS = ["CWE-79", "OWASP:A03"]

# A `text/template` import line, in either the grouped-import-block form (`    "text/template"`
# or `    alias "text/template"`) or the single-import form (`import "text/template"` /
# `import alias "text/template"`). The trailing `"text/template"` must be the WHOLE quoted path
# so a real, unrelated sibling package like `"text/template/parse"` never matches. The alias
# alternative also accepts Go's blank (`_`) and dot (`.`) import forms so `_text_template_identifier`
# below can tell "no usable identifier" (blank/dot) from "the default package name" (no alias).
_TEXT_TEMPLATE_IMPORT = re.compile(
    r'(?m)^[ \t]*(?:import[ \t]+)?(?:(?P<alias>[A-Za-z_][A-Za-z0-9_]*|\.)[ \t]+)?"text/template"[ \t]*$'
)
# Presence-only: whether `html/template` is imported ANYWHERE in the file — signal 1 does not
# need to know its identifier, only whether the file also has the safe package in scope.
_HTML_TEMPLATE_IMPORT = re.compile(r'"html/template"')

# The strong "this file handles HTTP responses" cue for both signals.
_HTTP_RESPONSE_WRITER = re.compile(r"\bhttp\.ResponseWriter\b")

# `.Execute(` / `.ExecuteTemplate(` — the render call that actually writes escaped-or-not
# output. Matches on either method name; a real `.ExecuteTemplate(w, "name", data)` call is
# just as dangerous as `.Execute(w, data)`.
_EXECUTE_CALL = re.compile(r"\.\s*Execute(?:Template)?\s*\(")

# The `.Parse(...)` / `.ParseFiles(...)` / `.ParseGlob(...)` family — any one of these closes
# out a `Must(New(...)` construction chain into a usable *Template value.
_PARSE_FAMILY = re.compile(r"\.\s*Parse(?:Files|Glob)?\s*\(")

_FUNC_KW = re.compile(r"\bfunc\b")


def _enclosing_function_span(text: str, pos: int) -> tuple[int, int] | None:
    """The `(start, end)` span of the Go function enclosing `pos`, from its `func` keyword
    (so the SIGNATURE — where a `w http.ResponseWriter` parameter lives — is included, not
    just the `{...}` body) through the matching closing brace. None if none can be found.

    Signal 2 needs a "same function" scope to look for the completing `.Parse...(` call, the
    `.Execute(`/`.ExecuteTemplate(` call, and the `http.ResponseWriter` reference — this guard
    has neither an AST nor a control-flow graph, so a fixed-size character window was tried
    first and rejected: it either reached past a short function into its unrelated neighbour
    (a false positive) or fell short of a long one (a false negative), and neither bound is
    correct for every file. Brace-matching from the nearest enclosing `func` is a much closer
    approximation of the real boundary and does not depend on function length at all.

    Walks the `func` keywords before `pos` from closest to farthest, and for each candidate
    brace-counts from its first `{` onward; the first candidate whose body actually SPANS `pos`
    (handles a closure literal that already closed before `pos`, e.g. an inner
    `http.HandleFunc("/x", func(...) {...})` used earlier in an outer function) is the answer.
    Gives up (None) if no candidate's braces balance before EOF — a malformed/truncated file —
    rather than guessing; the caller then does not fire signal 2 for that match.

    A known, accepted limitation: this counts EVERY `{`/`}` in the span, including ones inside a
    string or rune literal (e.g. a template body containing literal braces). The stripped text
    signal 2 runs against has already had `//`/`/* */` comments blanked (not string content), so
    a comment cannot desync the count, but a Go string containing an unbalanced `{`/`}` still
    can. Rare in real handler code; documented in the design doc rather than adding a full
    string-masking pass for one guard."""
    func_positions = [m.start() for m in _FUNC_KW.finditer(text, 0, pos)]
    for func_start in reversed(func_positions):
        brace_open = text.find("{", func_start)
        if brace_open == -1 or brace_open > pos:
            continue
        depth = 0
        i = brace_open
        n = len(text)
        close = -1
        while i < n:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    close = i + 1
                    break
            i += 1
        if close == -1:
            continue  # unbalanced from this candidate — try an earlier enclosing func
        if brace_open <= pos < close:
            return (func_start, close)
    return None


def _text_template_identifier(text: str) -> str | None:
    """The bound identifier for this file's `"text/template"` import, or None if there isn't
    one this guard can key a call-site regex on.

    Go's default package name for `text/template` is `template` (its own package clause is
    `package template` — the exact same name `html/template` uses, which is *why* this bug is
    invisible at the call site). An explicit alias (`tt "text/template"`) overrides that. A
    blank import (`_ "text/template"`) never binds a usable identifier — the package's init
    runs but nothing in this file can call `.Must`/`.New` through it. A dot import
    (`. "text/template"`) binds every exported name unqualified (bare `Must(...)`), which this
    guard does not attempt to detect — rare enough in real code to leave as a documented gap
    rather than adding an ambiguous unqualified-call regex that would also match `html/template`
    dot-imported the same way."""
    m = _TEXT_TEMPLATE_IMPORT.search(text)
    if not m:
        return None
    alias = m.group("alias")
    if alias in ("_", "."):
        return None
    return alias or "template"


class GoTemplateHtmlEscapingGuard(Guard):
    id = "go-template-html-escaping"
    title = "text/template used where html/template's auto-escaping is needed"
    area = "Web & browser"

    # go_template_signal1.go: text/template + http.ResponseWriter, no html/template import ->
    # fires go-template-html-escaping/text-template-http-response.
    # go_template_signal2.go: BOTH text/template (unaliased) and html/template (aliased) imported
    # -> signal 1's dual-import exclusion applies, so this instead fires
    # go-template-html-escaping/text-template-execute-http-response via the unaliased
    # template.Must(template.New(...).Parse(...))...Execute(w, ...) chain in rawPage, which is
    # unambiguously the text/template-bound identifier, not the aliased html/template one.
    # go_template_signal1.go (text/template + http.ResponseWriter, no html/template) ->
    # text-template-http-response. go_template_signal2.go (both packages imported, a
    # text/template-bound Must/New/Parse/Execute chain in an HTTP handler) ->
    # text-template-execute-http-response. Two files because signal 1's own scope
    # deliberately excludes a file that also imports html/template.
    canary_plant = CanaryPlant(
        files={
            "go_template_signal1.go": (
                'package main\n\nimport (\n\t"net/http"\n\t"text/template"\n)\n\n'
                "func handler(w http.ResponseWriter, r *http.Request) {\n"
                '\tt := template.Must(template.New("x").Parse("{{.}}"))\n'
                "\tt.Execute(w, r.URL.Query())\n}\n"
            ),
            "go_template_signal2.go": (
                'package main\n\nimport (\n\thtmltemplate "html/template"\n\t"net/http"\n\t"text/template"\n)\n\n'
                "func safePage(w http.ResponseWriter, data string) {\n"
                '\tt := htmltemplate.Must(htmltemplate.New("safe").Parse("{{.}}"))\n'
                "\tt.Execute(w, data)\n}\n\n"
                "func rawPage(w http.ResponseWriter, data string) {\n"
                '\tt := template.Must(template.New("raw").Parse("{{.}}"))\n'
                "\tt.Execute(w, data)\n}\n"
            ),
        },
        expects=frozenset({
            "go-template-html-escaping/text-template-http-response",
            "go-template-html-escaping/text-template-execute-http-response",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "go" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in go_scan_dirs(root, profile):
            for f in iter_files(d, (".go",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        # Two-view split: the pragma must be checked against the COMMENT-ONLY view — it lives
        # inside a `//` comment, which the stripped view below blanks out, and a string quoting
        # it must not count (#424) — while every pattern match is
        # checked against the STRIPPED view, so a pattern appearing only in a comment (a
        # commented-out import, a doc example) never fires. The pragma is scoped PER FINDING, not
        # the whole file: signal 1 produces at most one file-level finding (the import itself), so
        # a file-wide check is correct there, but signal 2 can produce one finding per handler, and
        # a pragma auditing one handler must not silence every other handler in the same file
        # (#565 review, Dean — reproduced with two handlers, one pragma'd, zero findings).
        raw = read(f)
        stripped = strip_go_comments(raw)
        view = comment_view(raw, "go")  # same length: the pragma is read from comments only (#424)

        out: list[Finding] = []
        has_response_writer = bool(_HTTP_RESPONSE_WRITER.search(stripped))
        if not has_response_writer:
            return out  # neither signal can fire without this cue — skip both scans

        text_import = _TEXT_TEMPLATE_IMPORT.search(stripped)
        # Whether signal 1's CONDITION holds (import shape), independent of whether its finding
        # ends up suppressed — signal 2 still must not re-scan this file's domain when it does.
        signal1_applies = bool(text_import and not _HTML_TEMPLATE_IMPORT.search(stripped))
        if signal1_applies and text_import is not None and not _PRAGMA.search(view):
            lineno = stripped.count("\n", 0, text_import.start()) + 1
            out.append(self._finding(
                root, f, lineno,
                message=(
                    "This file imports text/template and references http.ResponseWriter, "
                    "but text/template performs no output escaping at all — unlike "
                    "html/template's drop-in-compatible API, it does pure string "
                    "substitution. Any template field sourced from a request, a stored "
                    "value, or an LLM/agent response rendered through this package into an "
                    "HTTP response body is a stored or reflected XSS vector (CWE-79)."
                ),
                remediation=(
                    'Change the import to "html/template" — the API is drop-in compatible '
                    "(Must, New, ParseFiles, Execute all match) — so the fix is usually just "
                    "the import line. If this file genuinely needs text/template for a "
                    "non-HTML purpose (a config file, CLI output) that happens to share a "
                    "file with an HTTP handler, split them into separate files so the "
                    "import is unambiguous. Suppress an audited case (e.g. a verified "
                    "non-HTML response like a .txt/.csv download) with "
                    "`// security: allow-go-template-html-escaping`."
                ),
                rule="go-template-html-escaping/text-template-http-response",
            ))

        # Signal 2 only runs when signal 1's condition did not already apply to this file — its
        # purpose is to catch the case signal 1 deliberately excludes (html/template ALSO
        # imported), not to re-scan the same domain a second time.
        if not signal1_applies:
            ident = _text_template_identifier(stripped)
            if ident is not None:
                chain_re = re.compile(
                    re.escape(ident) + r"\.\s*Must\s*\(\s*" + re.escape(ident) + r"\.\s*New\s*\("
                )
                # Every occurrence, each scoped to ITS OWN enclosing function — a file can
                # legitimately have more than one such chain, and one may be the safe config
                # generator while another is the vulnerable handler (see the dual-purpose FP-bait
                # fixture in the tests).
                for chain_match in chain_re.finditer(stripped):
                    span = _enclosing_function_span(stripped, chain_match.start())
                    if span is None:
                        continue
                    window = stripped[span[0]:span[1]]
                    if not (
                        _PARSE_FAMILY.search(window)
                        and _EXECUTE_CALL.search(window)
                        and _HTTP_RESPONSE_WRITER.search(window)
                    ):
                        continue
                    # Pragma scoped to THIS function's own span, read from `view` (comments are
                    # blanked in `stripped`) — `comment_view` preserves length/offsets 1:1, so
                    # the same [start:end) slice lines up in both views. A pragma in a neighbouring
                    # handler must not reach across function boundaries to suppress this one.
                    if _PRAGMA.search(view[span[0]:span[1]]):
                        continue
                    lineno = stripped.count("\n", 0, chain_match.start()) + 1
                    out.append(self._finding(
                        root, f, lineno,
                        message=(
                            "This constructs a template via the text/template-bound "
                            f"identifier `{ident}` (Must/New/Parse) and executes it "
                            "against an http.ResponseWriter in the same function. Even "
                            "though this file also imports html/template elsewhere, THIS "
                            "specific chain resolves to text/template, which performs no "
                            "output escaping — any dynamic field rendered through it into "
                            "the HTTP response is a stored or reflected XSS vector (CWE-79)."
                        ),
                        remediation=(
                            "Route this construction through the html/template "
                            "identifier instead — the API is drop-in compatible, so "
                            "usually only the receiver/import needs to change. If this "
                            "really is a non-HTML response written to the same "
                            "ResponseWriter (unusual, but possible for a text/csv "
                            "download), suppress with "
                            "`// security: allow-go-template-html-escaping` inside THIS "
                            "function — a pragma elsewhere in the file does not reach "
                            "across into a different handler."
                        ),
                        rule="go-template-html-escaping/text-template-execute-http-response",
                    ))
        return out

    def _finding(
        self, root: Path, f: Path, lineno: int, *, message: str, remediation: str, rule: str
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=message,
            remediation=remediation,
            rule=rule,
            standards=list(_STANDARDS),
        )
