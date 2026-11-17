"""Guard: direct DOM XSS sink writes with non-literal values (OWASP:A03, CWE-79/94).

DOM-based XSS occurs when JavaScript writes attacker-controlled data directly into
the DOM via a sink that the browser interprets as HTML. Unlike reflected or stored
XSS, DOM XSS is never sent to the server — it lives entirely in client-side code,
so server-side output encoding cannot stop it.

The six highest-value sinks caught here:

  **innerHTML assignment (HIGH):** Assigning a variable to `element.innerHTML`
  immediately renders it as HTML. If the variable contains user-controlled content
  (URL params, postMessage, fetch responses, user-typed text) the browser parses and
  executes any `<script>`, event handlers, or `javascript:` URIs in the payload.

  **insertAdjacentHTML with variable (HIGH):** `element.insertAdjacentHTML(pos, html)`
  behaves identically to innerHTML at the target position. The position argument
  (beforebegin / afterbegin / beforeend / afterend) is harmless; the second argument
  is the HTML payload and must be sanitized.

  **document.write with variable (HIGH):** `document.write()` writes raw HTML into
  the document during load (or fully re-opens the document when called post-load).
  Passing a variable here is nearly always an XSS risk and is also flagged as a
  performance anti-pattern by browser vendors.

  **eval() with variable (CRITICAL):** `eval(userInput)` executes arbitrary
  JavaScript in the page context. If user input or LLM-generated content reaches
  eval(), an attacker can execute arbitrary code. This is classified as CWE-94
  (code injection) on top of XSS.

  **new Function() with variable (CRITICAL):** `new Function(code)` creates a
  function from a dynamically constructed string and executes it. Functionally
  equivalent to eval() but harder to detect — it bypasses many CSP `unsafe-eval`
  checks applied to eval() but not to Function().

  **setTimeout/setInterval/setImmediate with a string first argument (CRITICAL,
  `dom-xss-sinks/settimeout-string-arg`):** `setTimeout(code, ms)` /
  `setInterval(code, ms)` / `setImmediate(code)` accept a *string* as their first
  argument as a legacy feature — when the first argument is a string rather than a
  function, the engine compiles and runs it exactly like `eval()`. GitHub CodeQL's
  `javascript/ql/src/Security/CWE-094/CodeInjection.ql` treats this
  `EvalJavaScriptSink` form as equivalent to `eval()`. The classic footgun:
  `setTimeout("doSomething(" + userInput + ")", 100)` executes the concatenated
  string as code. The only safe, idiomatic form is passing an actual function or
  arrow-function literal (`setTimeout(() => doSomething(userInput), 100)`) — the
  argument is then a real closure, never re-parsed as a string.

Note: `dangerouslySetInnerHTML` in React JSX is already covered by the
`frontend-xss` guard (frontend-xss/dangerously-set-inner-html) and is intentionally
excluded here to avoid duplicate findings.

  **Broken regex-based sanitizer (HIGH, `dom-xss-sinks/incomplete-sanitization`):**
  A non-global `.replace(pattern, "")` call that strips an HTML/script-tag-shaped
  pattern (e.g. `str.replace("<script>", "")` or `str.replace(/<script>/i, "")`,
  no `g` flag) only removes the *first* occurrence. An attacker bypasses this by
  nesting the tag — `<scr<script>ipt>` survives a single `<script>` removal and
  reassembles into `<script>` once the outer copy is stripped. This checks
  sanitizer *quality*, not sink usage — a value that passed through a broken
  sanitizer like this is still attacker-controlled when it reaches innerHTML,
  document.write(), or any other sink above. `.replaceAll()` and a `/g`-flagged
  regex are not flagged — global removal still is not a real HTML parser, but
  the specific, unambiguous bug this catches is single-occurrence-only stripping.

Safe alternatives:
  - Use `element.textContent = value` (renders as text, never as HTML).
  - Use a vetted sanitizer (DOMPurify) and suppress with the pragma if appropriate.
  - Use framework-idiomatic patterns (React JSX interpolation, Vue `v-text`) that
    escape by default.
  - Never pass user or LLM content to eval() or new Function() — use JSON.parse()
    for data, worker threads or a sandboxed iframe for dynamic code execution.

**Suppress:** add `// security: allow-dom-xss-sink` anywhere in the file to silence
the check file-wide. Use only when you have confirmed a sanitizer is applied before
the sink and the risk is intentionally accepted.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
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

_PRAGMA = "security: allow-dom-xss-sink"

_STANDARDS = ["OWASP:A03", "CWE-79"]
_EVAL_STANDARDS = ["OWASP:A03", "CWE-79", "CWE-94"]

# Pattern 1: innerHTML assigned from something that is NOT an opening quote.
# The negative lookahead skips optional whitespace before checking for a quote, so
# `el.innerHTML = "<p>static</p>"` (space then quote) is excluded correctly.
# The optional `+` covers the compound APPEND form, which injects attacker HTML into the
# document exactly as the plain assignment does and was silently uncovered (#422).
# Matches: el.innerHTML = someVar  |  el.innerHTML=someVar  |  el.innerHTML += someVar
# Skips:   el.innerHTML = "<p>static</p>"  |  el.innerHTML += '<b>static</b>'
# The `(?!=)` excludes an equality COMPARISON (`el.innerHTML === b` / `== b`), whose first `=` would
# otherwise satisfy the assignment match — a false positive (issue #424).
_INNER_HTML = re.compile(r"\.innerHTML\s*\+?=(?!=)(?!\s*[\"'`])")

# Pattern 2: insertAdjacentHTML where the second argument is NOT a string literal.
# Matches: el.insertAdjacentHTML("beforeend", rawHtml)
# Skips:   el.insertAdjacentHTML("beforeend", "<p>safe</p>")
_INSERT_ADJACENT = re.compile(
    r"\.insertAdjacentHTML\s*\(\s*[\"'](?:beforeend|afterbegin|beforebegin|afterend)[\"']\s*,(?!\s*[\"'`])"
)

# Pattern 3: document.write() where the argument is NOT a string literal.
# Matches: document.write(someVar)
# Skips:   document.write("<p>static</p>")
_DOC_WRITE = re.compile(r"\bdocument\.write\s*\((?!\s*[\"'`])")

# Pattern 4: eval() with a non-literal argument (code injection / DOM XSS).
# Matches: eval(userInput)  |  eval(response.text)  |  window.eval(code)
# Skips:   eval("hardcoded string")  |  eval(`hardcoded`)  |  eval()  (empty call, no injection)
# Note: JSON.parse() is NOT a sink — it is the safe alternative and is not flagged.
# The `)` in the exclusion set skips an empty `eval()` (nothing to inject) — mirrors _NEW_FUNCTION
# (issue #424).
_EVAL = re.compile(r"\beval\s*\((?!\s*[\"'`)])")

# Pattern 5: new Function() with a non-literal FIRST argument (equivalent to eval).
# Mirrors _EVAL's negative-lookahead so a purely-literal body is skipped (no FP).
# Matches: new Function(code)
# Skips:   new Function("return 42")  |  new Function("return this")  |  new Function()
#          new Function("a", bodyVar)  — conservative FN (literal first arg), as the project prefers.
# This bypasses CSP unsafe-eval in some configurations and is as dangerous as eval().
_NEW_FUNCTION = re.compile(r"\bnew\s+Function\s*\((?!\s*[\"'`)])")

# Pattern 6: setTimeout/setInterval/setImmediate whose first argument is a STRING passed as
# code. Unlike eval()/new Function() above (where a quoted string is the SAFE form), here a
# string is the VULNERABLE form: passing a string as the first argument makes the engine
# compile-and-run it exactly like eval() (CodeQL's `EvalJavaScriptSink`). This matches the CALL
# only; the whole first argument is then captured with a paren-depth walk (so a multi-line call
# is seen whole) and tested with a POSITIVE "looks like a string/template/concat" signal
# (`_first_arg_is_code_string`). A bare identifier — `setTimeout(handleClick, 300)`, the
# overwhelmingly common named-callback form — is indistinguishable from a variable holding a
# string, so it is NOT flagged: firing on it was a critical false positive (review #395 C2).
# Fires:  setTimeout("alert(" + x + ")", 100)  |  setTimeout(`run(${x})`, 100)
# Skips:  setTimeout(handleClick, 300)  |  setTimeout(() => doStuff(x), 100)
#         setTimeout(function() { doStuff(); }, 100)  |  setInterval(refreshTimer, 1000)
_SET_TIMEOUT_CALL = re.compile(r"\b(?:setTimeout|setInterval|setImmediate)\s*\(")

_SET_TIMEOUT_RULE = "dom-xss-sinks/settimeout-string-arg"

_SINKS: list[tuple[re.Pattern[str], str, str, list[str]]] = [
    (_INNER_HTML, "innerHTML assigned from a variable", "dom-xss-sinks/unsafe-dom-write", list(_STANDARDS)),
    (_INSERT_ADJACENT, "insertAdjacentHTML called with a variable as the HTML payload", "dom-xss-sinks/unsafe-dom-write", list(_STANDARDS)),
    (_DOC_WRITE, "document.write called with a variable", "dom-xss-sinks/unsafe-dom-write", list(_STANDARDS)),
    (_EVAL, "eval() called with a non-literal argument", "dom-xss-sinks/eval-sink", list(_EVAL_STANDARDS)),
    (_NEW_FUNCTION, "new Function() constructed with a non-literal argument", "dom-xss-sinks/new-function-sink", list(_EVAL_STANDARDS)),
]

# Pattern 7: .replace(pattern, "") that strips an HTML/script-tag-shaped pattern but only
# removes the FIRST occurrence — a broken sanitizer, not a sink write. `.replace(` naturally
# excludes `.replaceAll(` (no `(` immediately follows "replace").
_REPLACE_CALL = re.compile(r"\.replace\s*\(")
# The removed pattern "looks like" it targets a REAL HTML tag — not an arbitrary
# `<placeholder>`/`<TOKEN>`-style template marker, which `str.replace("<placeholder>", "")`
# uses benignly and which a bare `<[^<>]*>` false-flagged HIGH (review #395 M). A real tag is
# a known HTML element name (opening or closing, optionally carrying attributes), OR a regex
# char-class wildcard tag-strip (`/<[^>]+>/`, the "strip every tag" form).
_HTML_TAG_NAMES = (
    r"script|img|image|svg|iframe|style|link|object|embed|form|input|button|body|html|head|"
    r"a|area|base|meta|title|marquee|video|audio|source|track|math|details|template|frame|"
    r"frameset|applet|param|div|span|p|br|hr|ul|ol|li|table|td|tr|th|h[1-6]"
)
_TAG_LIKE = re.compile(
    r"<\s*/?\s*(?:" + _HTML_TAG_NAMES + r")\b"   # a known HTML element (opening or closing)
    r"|<\s*/?\s*[.\[]",                           # a regex wildcard tag strip (`<[^>]+>`, `<.*?>`)
    re.IGNORECASE,
)
# A regex literal /pattern/flags — used to check for a missing `g` flag.
_REGEX_LITERAL = re.compile(r"^/(.*)/([a-z]*)$", re.DOTALL)
# A quoted string literal (single, double, or template) spanning the whole argument.
_QUOTED_LITERAL = re.compile(r"""^["'`].*["'`]$""", re.DOTALL)
# The replacement argument is an empty string literal.
_EMPTY_STRING_LITERAL = re.compile(r"""^["'`]\s*["'`]$""")

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")

# Browser automation directories: Playwright/Cypress/Puppeteer scripts deliberately
# manipulate the DOM and legitimately use innerHTML/insertAdjacentHTML as control primitives.
# This is distinct from application code — no user-controlled data flows into these calls.
_BROWSER_AUTO_DIR = re.compile(
    r"(?:^|/)(?:playwright|cypress|puppeteer|selenium|browser[-_]harness|browser[-_]test)(?:/|$)",
    re.IGNORECASE,
)


def _split_top_level_args(
    text: str, open_idx: int, *, track_groups: bool = False, closes: dict[int, int] | None = None
) -> list[str] | None:
    r"""Split a `(...)` call's arguments on top-level commas, from the `(` at open_idx.

    A leading TYPE-PARAMETER list is consumed whole. Depth was tracked only via `(`/`)`, with no
    notion of `<...>`, so the comma inside the idiomatic TSX `<T,>` head was read as the argument
    separator: `args[0]` became the fragment `"<T"`, and the real argument was never inspected.
    Two consequences, and the second is the serious one: the `<T,>` support in `_is_function_literal`
    was DEAD CODE in the real pipeline (its "safe" test passed only because a garbage fragment is
    trivially unflagged), and any dangerous payload behind that head was hidden with no IIFE required
    (#479 agentic gate).

    `track_groups` extends that from the argument's HEAD to its BODY: with it, a comma inside a
    `{...}`/`[...]` group is not an argument separator either. Without it, the whole
    "locate the body structurally" apparatus below is unreachable for any callback whose body
    contains an ordinary top-level comma — an object literal, an array literal, a destructuring, a
    second declarator — because `args[0]` is already truncated mid-body before it is ever
    classified, and the `+`-and-a-quote heuristic then fires CRITICAL on idiomatic React
    (#479 re-gate H1). The same category error as the `<T,>` desync, one level up: *"where is the
    first comma"* is not *"where does the argument end"*.

    `track_groups` is OPT-IN per call site: `_scan_settimeout` needs the body-comma handling and
    passes `track_groups=True`; `_scan_broken_sanitizer` only wants the top-level `.replace()` args
    and leaves it off. It used to carry a load-bearing SAFETY caveat too — "only sound when the caller
    has already blanked string CONTENTS", because a bracket inside a string literal would otherwise
    desync the count. That caveat is GONE: the walk is now itself quote/string-aware. An active
    `'`/`"`/`` ` `` delimiter is tracked; inside one, every char is copied verbatim (`\` escapes
    honored) and NO `( ) { } [ ] < ,` counts as structure — so neither the paren depth nor the group
    counter can be corrupted by a bracket living inside a string, whether the caller pre-blanked or
    not. This is what fixes the two silent misses in #573: a `}` inside a still-open template that
    #542's EOF un-blank restored VERBATIM (the primary), and a `(` inside a raw `.replace()` pattern
    (#574, consolidated here).

    `call_close` is found with `_match_bracket`, which skips literals under the SAME flat
    `'`/`"`/`` ` `` model as this walk. It used to be the shared `matching_close_paren`, which tracks
    `'`/`"` but not the backtick, so the two disagreed about where a template ends: a backtick-quoted
    `.replace()` pattern carrying a stray `)` (`` `<div title=odd) markup>` ``) closed the call inside
    the template and the walk fell through to `None`, silently dropping its `incomplete-sanitization`
    finding (#909 site B). The shared helper is left alone: several of its other callers read Python,
    SQL or Java, where a backtick is not a string delimiter.

    Residual (deliberate): the flat model does not track `${…}` as code, and a regex literal is not a
    literal to it. The timer site scans a copy with regex BODIES blanked (`strip_regex`), so a `'` in
    `/'/g` cannot open a phantom string there. The sanitizer site reads raw text, where it still can,
    and the call then gives up (`None`): a conservative give-up, never a wrong split.

    `closes` is `_paren_closes(text, openers)`, built once per text by a caller that splits many
    calls in it, and answers `call_close` without a scan. An opener it does not hold falls back to
    `_match_bracket`, as does a call without it, at a per-call cost of up to the rest of the file
    (#1138)."""
    # The call's own closing paren, found once. It bounds every inner scan below, so a single
    # unbalanced `<` at an argument start can no longer run a `_match_bracket` search to END OF
    # FILE once per timer match: measured over 800 such calls in a 24 KB file, 528 ms at both
    # `6d0b0fd1` and `fa380941` versus 2.3 ms here (#479 re-gate L1). Unbalanced parens are also
    # rejected up front now, rather than after walking the rest of the file. That search was itself
    # still unbounded, though: an unclosed `(` ran it to end of file once per call, which `closes`
    # answers from one pass instead (#1138).
    call_close = closes.get(open_idx) if closes is not None else None
    if call_close is None:
        call_close = _match_bracket(text, open_idx, "(", ")")
    if call_close == -1:
        return None  # unbalanced parens or an unterminated literal — give up rather than guess
    depth = 0
    group = 0
    # The active `'`/`"`/`` ` `` delimiter while inside a string/template literal, else "". Inside
    # one, every char is copied verbatim and no bracket/comma is counted (string CONTENTS are not
    # code), so the caller no longer has to pre-blank strings for the split to be sound (#573).
    quote = ""
    args: list[str] = []
    current: list[str] = []
    # "The start of an argument" is its first NON-WHITESPACE character, not the byte immediately
    # after the `(` or `,`. Gating on `not current` closed the desync for exactly one whitespace
    # layout — the one the fix's author typed — and prettier wraps a call this long onto its own
    # line as a matter of course, so `setTimeout(\n  <T,>("run(" + u + ")"),\n  100\n)` kept both
    # the desync and the CRITICAL payload it hides (#479 fresh-eyes gate H1).
    arg_is_blank = True
    i = open_idx
    while i <= call_close:
        ch = text[i]
        if quote:
            # Inside a string/template literal: copy verbatim, honor `\` escapes, count no structure.
            current.append(ch)
            if ch == "\\":
                i += 1
                if i <= call_close:
                    current.append(text[i])
                    i += 1
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        # At the start of an argument, a `<` opens a type-parameter list (or JSX), not a
        # comparison — no JS expression may begin with `<`.
        if depth == 1 and arg_is_blank and ch == "<":
            close = _match_bracket(text, i, "<", ">", end=call_close)
            if close != -1:
                current.append(text[i:close + 1])
                arg_is_blank = False
                i = close + 1
                continue
        if ch in "'\"`":
            quote = ch
            current.append(ch)
            arg_is_blank = False
        elif ch == "(":
            depth += 1
            if depth > 1:
                current.append(ch)
                arg_is_blank = False
        elif ch == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(current))
                return args
            current.append(ch)
            arg_is_blank = False
        elif track_groups and ch in "{[":
            group += 1
            current.append(ch)
            arg_is_blank = False
        elif track_groups and ch in "}]":
            group = max(0, group - 1)
            current.append(ch)
            arg_is_blank = False
        elif ch == "," and depth == 1 and group == 0:
            args.append("".join(current))
            current = []
            arg_is_blank = True
        else:
            current.append(ch)
            if not ch.isspace():
                arg_is_blank = False
        i += 1
    # Normally unreachable — the walk returns at `call_close`. It can fall through only when an
    # angle-head consumption skipped over an unmatched paren (`<A(B>` and friends), i.e. on input
    # that is not valid JS. Give up rather than guess, as before.
    return None


def _first_arg_is_code_string(arg: str) -> bool:
    """True iff a setTimeout/setInterval/setImmediate first argument is a STRING passed as code.

    The dangerous, eval-equivalent form is a string/template literal or a string-building
    concatenation (`setTimeout("run(" + x + ")", 100)`, `` setTimeout(`run(${x})`, 100) ``); the
    engine re-parses it as JS. A bare identifier (`setTimeout(handleClick, 300)`) or a
    function/arrow literal is the safe, overwhelmingly common form and must NOT fire — a positive
    "looks like a string" signal, not "isn't a function" (review #395 Critical C2). A variable that
    merely *holds* a string is indistinguishable from one holding a function and is deliberately
    not flagged (a conservative false negative — the project prefers it over a noisy false
    positive on every named-callback timer)."""
    a = arg.strip()
    if not a:
        return False
    if a[0] in "\"'`":  # a string or template literal as the (start of the) first argument
        return True
    # A function/arrow LITERAL is the safe, overwhelmingly common form — and its BODY routinely
    # contains a string concatenation of its own, which the `+`-and-a-quote heuristic below then
    # read as "a string passed as code". `setTimeout(() => { setMsg("Saved " + name); }, 3000)`
    # produced a CRITICAL on ordinary React (#479 review). The callback body is never re-parsed by
    # the engine, so nothing inside it can be an eval-equivalent string sink.
    if _is_function_literal(a):
        return False
    # a string-building concatenation: a `+` OUTSIDE every literal together with a string/template
    # literal. Once the scan kept substitution code (#1055), the `+` of `` `${i + 1}` `` became visible
    # inside a template argument, and `setTimeout(show(`Step ${step + 1}`), 100)` read as a
    # concatenation: a CRITICAL on a function value (PR #1126 round-1 M1).
    return _has_plus_outside_literals(a) and bool(re.search(r"""["'`]""", a))


def _has_plus_outside_literals(arg: str) -> bool:
    """True if `arg` has a `+` that is not inside a `'`/`"`/`` ` `` literal. Literals are skipped
    under the same flat model as the argument walk (`_literal_end`), so a template's `${...}` is part
    of the literal. An unterminated literal ends the search. Total: never raises."""
    i = 0
    stop = len(arg) - 1
    while i <= stop:
        ch = arg[i]
        if ch in "'\"`":
            i = _literal_end(arg, i, stop)
            if i == -1:
                return False
        elif ch == "+":
            return True
        i += 1
    return False


# `function` / `function name` / `function*` as the start of the argument.
_FUNCTION_KEYWORD = re.compile(r"^function\b")
# A single-parameter arrow with no parens: `e => ...`, `_ => ...`. The match END is the index just
# past the `=>`, i.e. exactly where the body begins — the body is never searched for.
_BARE_PARAM_ARROW = re.compile(r"^[A-Za-z_$][\w$]*\s*=>")
# A JS identifier — the optional NAME of a `function` expression.
_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")
# The `async` modifier at the start of the argument, boundaried. A bare `.startswith("async")` also
# ate the prefix of an argument NAMED `async` (a legal JS identifier) or `asyncHandler`, leaving a
# remainder that could then read as a function literal (#479 review). The boundary is whitespace OR
# `(`, not whitespace alone: the compact `async()=>{}` form carries no space, and requiring one would
# stop it being recognized as a function literal — reopening the very D.2 concatenation FP class this
# PR closes. `async` used as a CALLEE (`async(x)`) is still safe: stripping leaves `(x)`, and a
# parenthesized head is only an arrow if `=>` follows its matching close paren.
_ASYNC_MODIFIER = re.compile(r"^async(?=[\s(])")


def _body_consumes_rest(text: str, brace_idx: int) -> bool:
    """True if the `{...}` block starting at `brace_idx` runs to the END of `text`.

    `_is_function_literal` used to return True the moment it recognized a function or arrow HEAD,
    without checking what followed it. An IMMEDIATELY-INVOKED function expression therefore read as a
    safe callback: in `setTimeout(function(){ return "run(" + x + ")"; }(), 100)` the value actually
    passed is the invocation's return value, a built string, i.e. a live code-execution sink. It was
    excluded before the concatenation heuristic ever ran, and it fired correctly on `main` before this
    exclusion existed (#479 agentic gate). Classify the VALUE, not a call-shaped prefix."""
    close = _match_bracket(text, brace_idx, "{", "}")
    if close == -1:
        return False
    return text[close + 1:].strip(" \t\n;") == ""


def _is_function_literal(arg: str) -> bool:
    """True iff `arg` starts a function expression or arrow function — `function () {…}`,
    `() => …`, `(a, b) => …`, `x => …`, and the `async` forms of each.

    **The invariant every branch here obeys: a body is located STRUCTURALLY — by walking the head
    (parameter list, type-parameter list, return-type annotation) to its end — never by searching
    for the first body-SHAPED character.** `text.find("{")` answers "where is the first brace",
    which is a different question from "where does the body start": a `{` occurs inside a
    parameter list (`function ({id}) {…}`, `(o = {a: 1})`, `(o: {a: string})`), inside a
    return-type annotation (`(): {a: string} {…}`, `(x): Record<string, {a: number}> => {…}`) and
    inside an expression body (`() => setState({...})`). Every one of those was mis-read as the
    body, the literal was rejected, and the `+`-and-a-quote heuristic fired **CRITICAL on ordinary
    React** — the exact FP class this guard's D.2 work exists to remove (#479 fresh-eyes gate
    C1/C2, one category error at three sites).

    Positive identification only: a bare identifier (`handleClick`) is NOT matched here, since it
    is handled by the caller's own "looks like a string" test. Total: never raises."""
    a = arg.strip()
    m = _ASYNC_MODIFIER.match(a)
    if m:
        a = a[m.end():].lstrip()
    if _FUNCTION_KEYWORD.match(a):
        return _function_body_ends_argument(a)
    bare = _BARE_PARAM_ARROW.match(a)
    if bare:
        return _arrow_body_is_safe(a[bare.end():])
    # A `.tsx` arrow may lead with a type-parameter list (`<T,>(x: T) => …`). Skip a balanced
    # `<...>` head before looking for the parameter parens (#479 second-pass review).
    if a.startswith("<"):
        close = _match_bracket(a, 0, "<", ">")
        if close == -1:
            return False
        a = a[close + 1:].lstrip()
    if not a.startswith("("):
        return False
    # A parenthesized head is an arrow only if `=>` follows its MATCHING close paren — so a
    # parenthesized expression like `("a" + b)` is not mistaken for a zero-arg arrow.
    close = _match_bracket(a, 0, "(", ")")
    if close == -1:
        return False
    rest = a[close + 1:].lstrip()
    if rest.startswith("=>"):
        return _arrow_body_is_safe(rest[2:])
    # ...or after a TypeScript RETURN-TYPE annotation: `(x: string): void => {…}`.
    if rest.startswith(":"):
        arrow_end = _annotation_arrow_end(rest)
        return arrow_end != -1 and _arrow_body_is_safe(rest[arrow_end:])
    return False


def _annotation_arrow_end(rest: str) -> int:
    """Index just past the `=>` that ENDS a TypeScript return-type annotation, or -1 if there is none.

    `rest` starts at the `:`. The annotation may itself carry parens, brackets, braces and generics
    (`: Promise<void>`, `: ((n) => void)`, `: Record<string, {a: number}>`), so the arrow we want is
    the first `=>` at bracket depth 0. The old code bounded the annotation at the first `{` instead
    — the same "first brace-shaped substring" error — which lost a brace-carrying return type
    (`(x): Record<string, {a: number}> => {…}`) and mis-classified it as a code string. Total:
    never raises."""
    depth = 0
    for i, ch in enumerate(rest):
        if ch in "([{<":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == ">":
            if i and rest[i - 1] == "=":     # an arrow, not a generic close
                if depth == 0:
                    return i + 1
            else:
                depth = max(0, depth - 1)
    return -1


def _arrow_body_is_safe(tail: str) -> bool:
    """True unless the arrow's body is immediately invoked. `tail` is everything AFTER the `=>`.

    The body begins at the first NON-WHITESPACE character of `tail`: a `{` there is a block body,
    which must run to the end of the argument (otherwise something follows it — an invocation, a
    `.call()`, a concatenation tail — and the value passed is not the function). Anything else is
    an EXPRESSION body, which cannot be immediately invoked in this position (`(() => x)()` starts
    with `(` and never reaches here), so it is accepted whatever braces it contains."""
    body = tail.lstrip()
    if not body.startswith("{"):
        return True
    return _body_consumes_rest(tail, len(tail) - len(body))


def _function_body_ends_argument(a: str) -> bool:
    """True iff `a` — which starts with the `function` keyword — is a plain, non-invoked function
    literal, i.e. its BODY block runs to the end of the argument.

    The head is walked structurally: `function` `*`? NAME? `<TypeParams>`? `( params )`. Only then
    does the body search begin, so a brace in the parameter list can no longer be taken for the
    body. Total: never raises."""
    rest = a[len("function"):].lstrip()
    if rest.startswith("*"):                      # a generator: `function* gen() {…}`
        rest = rest[1:].lstrip()
    name = _IDENTIFIER.match(rest)
    if name:                                      # the optional name: `function named() {…}`
        rest = rest[name.end():].lstrip()
    if rest.startswith("<"):                      # a generic head: `function <T>(x: T) {…}`
        close = _match_bracket(rest, 0, "<", ">")
        if close == -1:
            return False
        rest = rest[close + 1:].lstrip()
    if not rest.startswith("("):
        return False
    close = _match_bracket(rest, 0, "(", ")")     # the end of the parameter list
    if close == -1:
        return False
    if not rest[close + 1:].lstrip().startswith(":"):
        # No return-type annotation: the body IS the first `{` after the parameter list, and
        # nothing may follow its matching `}`. Deliberately NOT the group-skipping scan below —
        # scanning on would accept `function(){ return "r(" + x + ")"; }() || {}`, whose trailing
        # `{}` runs to the end while the value passed is the invocation's string. (Found by
        # fuzzing this fix: the general scan reopened an IIFE bypass the tip had closed.)
        brace = rest.find("{", close + 1)
        return brace != -1 and _body_consumes_rest(rest, brace)
    body = _annotation_body_start(rest, close + 1)
    return body != -1 and _body_consumes_rest(rest, body)


# Characters after which a TypeScript type is INCOMPLETE, so a following `{` continues the
# annotation rather than opening the body: the annotation's own `:`, the union/intersection
# operators, an opener, a separator, and the `=` of a `=>` in a function type. After anything else
# (an identifier, `}`, `)`, `]`, `>`) the type is complete and the next `{` at depth 0 is the body.
_TYPE_CONTINUES_AFTER = frozenset(":|&<(,=")


def _annotation_body_start(text: str, start: int) -> int:
    """Index of the `{` that opens the body of a function carrying a RETURN-TYPE annotation, or -1.

    `start` is just past the parameter list's `)`, i.e. at (or before) the annotation's `:`. The
    annotation is walked STRUCTURALLY to its end — the same invariant every other branch here obeys
    — rather than searching for a body-SHAPED group. The predecessor did search
    (*"some `{...}` block at or after start that runs to the end"*), with a stop-at-the-first-paren
    heuristic bolted on to keep the `function (): T {…}() || {}` IIFE bypass closed; that heuristic
    misfired whenever the annotation put a paren between its own brace group and the body, so
    `function (): ({ a: 1 }) {…}` and `function (): (A | { b: 1 }) {…}` were read as sinks and
    fired CRITICAL on valid, sink-free TypeScript (#479 re-gate M1).

    A type literal at the annotation's start, or after `|` / `&` / an opener, is consumed whole; the
    body is the first `{` at bracket depth 0 that follows a COMPLETE type. Total: never raises.
    Known limitation: a word-operator return type (`: keyof { a: 1 }`) reads its type literal as the
    body, since `keyof` ends in an identifier character. That is not a shape that occurs in real
    code, and it fails toward the guard's conservative side — the literal is rejected, not
    accepted."""
    i = start
    depth = 0
    prev = ":"  # nothing consumed yet, so the type is "incomplete" and a `{` here is a type literal
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "{":
            if depth == 0 and prev not in _TYPE_CONTINUES_AFTER:
                return i
            close = _match_bracket(text, i, "{", "}")   # a type literal — consume it whole
            if close == -1:
                return -1
            i = close + 1
            prev = "}"
            continue
        if ch in "([<":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        elif ch == ">":
            if i and text[i - 1] == "=":   # the `=>` of a function type: the type continues
                prev = "="
                i += 1
                continue
            depth = max(0, depth - 1)
        if not ch.isspace():
            prev = ch
        i += 1
    return -1


def _literal_end(text: str, i: int, stop: int) -> int:
    """Index of the delimiter closing the `'`/`"`/`` ` `` literal that opens at `text[i]`, or -1 if it
    is still open at `stop` (inclusive). `\\` escapes the next char. Total: never raises.

    The literal model is FLAT, the same one `_split_top_level_args`' walk uses: a template's `${…}`
    is not tracked as code, so a nested template is handled only because its own backticks pair up.
    One model for both is the point. The close-finder and the walk used to disagree about where a
    backtick literal ends, and that disagreement silently dropped a finding (#909 site B)."""
    quote = text[i]
    j = i + 1
    while j <= stop:
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if ch == quote:
            return j
        j += 1
    return -1


def _match_bracket(text: str, start: int, open_ch: str, close_ch: str, end: int | None = None) -> int:
    """Index of the bracket matching `text[start]`, or -1 if unbalanced. Total: never raises.

    Brackets inside a `'`/`"`/`` ` `` literal are not structure, so each literal is skipped whole
    (`_literal_end`); one still open at the bound makes the match give up (-1), never guess. The
    callers mostly read a `strip_strings` copy, but that copy does not keep string contents blanked:
    #542's EOF cap and #910's parity cap restore literal text verbatim, so a `}` inside
    `"unexpected }"` used to close a callback body early and fire CRITICAL on a function literal
    (#909). For `close_ch == ">"`, the `>` of an `=>` is an arrow, not a generic close (the
    `_annotation_arrow_end` rule): `<T extends () => void,>` ended at the arrow and hid the real
    argument behind a split comma.

    `end` bounds the search at that index INCLUSIVE (default: the end of `text`). An unbalanced
    opener is the pathological input here — the scan then runs to the bound and finds nothing — so
    a caller that already knows the enclosing construct's extent should pass it (#479 re-gate L1)."""
    stop = len(text) - 1 if end is None else min(end, len(text) - 1)
    depth = 0
    i = start
    while i <= stop:
        ch = text[i]
        if ch in "'\"`":
            i = _literal_end(text, i, stop)
            if i == -1:
                return -1
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch and not (close_ch == ">" and i > start and text[i - 1] == "="):
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _paren_closes(text: str, openers: Iterable[int]) -> dict[int, int]:
    """`{opener: _match_bracket(text, opener, "(", ")")}` for every index in `openers` (each a `(`),
    from ONE left-to-right sweep. Total: never raises.

    `_match_bracket` lexes from its opener as CODE, under the flat `_literal_end` model, so where an
    opener sits inside a literal depends on where the lexing started: a `setTimeout(` hit in text
    #542/#910 restored verbatim, or a `.replace(` inside a string of the raw sanitizer view, is code
    to its own search and literal to one started earlier. The sweep therefore follows every lexing
    that is live at once, as TRACKS keyed by lexer state: code, inside a `'`/`"`/`` ` `` literal, or
    just past a `\\` in one. At most seven exist, because two lexings in the same state at the same
    index read everything after it the same way, and they merge. A merge keeps both pending-opener
    stacks aligned at the top (the next `)` either would see closes both tops), so a stack LEVEL is a
    group of openers that close together. A track starts at a queried opener no track reads as code,
    and one with nothing pending is dropped, so the sweep jumps between calls once nothing is open.

    Cost is O(7 x text) plus the merges, which are small-into-large: a merge walks the shorter
    stack, whose levels it consumes, and a group moves only into one at least its own size. The
    per-call `_match_bracket` this replaces scanned to end of file for every opener that never
    closes: 4,000 lines of `setTimeout(f(, 1);` took 14.2 s, and `.replace(` took the same path
    through the sanitizer scan. One literal pass plus a pass per missed opener was not enough either:
    `x.replace("(\\"(` alternates quote parity per line, so every opener was missed by the passes
    before it (11.3 s at 4,000 lines, #1149 review)."""
    out: dict[int, int] = {}
    queries = sorted(set(openers))
    # state -> stack of groups. "" is code, a quote is inside that literal, quote + "\\" is the char
    # after an escape inside it.
    tracks: dict[str, list[list[int]]] = {}
    n = len(text)
    qi = 0
    i = queries[0] if queries else n
    while i < n:
        if qi < len(queries) and queries[qi] == i:
            qi += 1
            tracks.setdefault("", [])  # the queried opener's own lexing starts here, as code
        if not tracks:
            if qi == len(queries):
                break
            i = queries[qi]  # nothing open: skip to the next call
            continue
        ch = text[i]
        moved: dict[str, list[list[int]]] = {}
        for state, stack in tracks.items():
            if state == "":
                new = ch if ch in "'\"`" else ""
                if ch == "(":
                    stack.append([i])
                    out[i] = -1
                elif ch == ")" and stack:
                    for k in stack.pop():
                        out[k] = i
            elif len(state) == 2:
                new = state[0]  # the escaped char, whatever it is
            elif ch == "\\":
                new = state + "\\"
            else:
                new = "" if ch == state else state
            if not stack:
                continue
            other = moved.get(new)
            if other is None:
                moved[new] = stack
                continue
            if len(other) < len(stack):
                other, stack = stack, other
            for d in range(1, len(stack) + 1):
                big, small = other[-d], stack[-d]
                if len(big) < len(small):
                    other[-d], big, small = small, small, big
                big.extend(small)
            moved[new] = other
        tracks = moved
        i += 1
    for k in queries:
        out.setdefault(k, -1)  # defensive: the sweep visits and pushes every queried `(`
    return out


def _is_broken_tag_sanitizer(first_arg: str, second_arg: str) -> bool:
    """True iff `.replace(first_arg, second_arg)` strips a tag-shaped pattern once, not globally."""
    first = first_arg.strip()
    second = second_arg.strip()
    if not _EMPTY_STRING_LITERAL.match(second):
        return False
    if not _TAG_LIKE.search(first):
        return False
    m = _REGEX_LITERAL.match(first)
    if m:
        return "g" not in m.group(2)
    # A quoted string literal first argument is always single-occurrence — .replace() with
    # a plain string (no regex) never repeats, regardless of any flag.
    return bool(_QUOTED_LITERAL.match(first))


class DomXssSinksGuard(Guard):
    id = "dom-xss-sinks"
    title = "DOM XSS sink called with a non-literal value"
    area = "Web & browser"

    # components/UserContent.jsx: innerHTML = userInput -> fires dom-xss-sinks/unsafe-dom-write.
    # components/broken_sanitizer.js: non-global .replace() with a wildcard tag-strip regex ->
    # fires dom-xss-sinks/incomplete-sanitization.
    # Must NOT contain: security: allow-dom-xss-sink pragma, .replaceAll(, or a /g flag.
    # components/eval_runner.js: eval(code) and new Function(code) -> fires dom-xss-sinks/eval-sink
    # and dom-xss-sinks/new-function-sink.
    # Must NOT contain: security: allow-dom-xss-sink pragma.
    # components/UserContent.jsx: div.innerHTML = userInput -> unsafe-dom-write.
    # components/eval_runner.js: eval(code) -> eval-sink, new Function(code) -> new-function-sink.
    canary_plant = CanaryPlant(
        files={
            "components/UserContent.jsx": (
                'function renderContent(userInput) {\n'
                '    const div = document.getElementById("content");\n'
                "    div.innerHTML = userInput;\n"
                "    return div;\n"
                "}\n"
            ),
            "components/broken_sanitizer.js": (
                "function stripTags(userInput) {\n"
                "    return userInput.replace(/<.*?>/i, \"\");\n"
                "}\n"
            ),
            "components/eval_runner.js": (
                "function runUserCode(code) {\n"
                "    eval(code);\n"
                "}\n"
                "function buildFn(code) {\n"
                "    return new Function(code);\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "dom-xss-sinks/unsafe-dom-write",
            "dom-xss-sinks/eval-sink",
            "dom-xss-sinks/new-function-sink",
            "dom-xss-sinks/incomplete-sanitization",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _JS_SUFFIXES):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            if _BROWSER_AUTO_DIR.search(r.replace("\\", "/")):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            # Blank `//` and `/* */` comments (line numbers + columns preserved) so a commented-out
            # or JSDoc-documented sink EXAMPLE doesn't fire (issue #424). A sink spelled out in a
            # string (`"use eval(x) sparingly"`) is not one either: each match's first character is
            # tested on the anchor mask, which keeps `${...}` substitution code live, and every match
            # on the line is tried so a quoted copy cannot hide a real sink after it (#1055).
            code_lines = strip_js_comments(text).splitlines()
            mask_lines = strip_js_comments(text, strip_strings=True, keep_substitutions=True).splitlines()
            for lineno, (line, mask_line) in enumerate(zip(code_lines, mask_lines, strict=True), 1):
                for pattern, detail, rule, standards in _SINKS:
                    if next(js_code_matches(pattern, line, mask_line, anchor=lambda m: m.start()), None):
                        is_eval = rule in (
                            "dom-xss-sinks/eval-sink",
                            "dom-xss-sinks/new-function-sink",
                        )
                        out.append(Finding(
                            check_id=self.id,
                            severity="critical" if is_eval else "high",
                            title=(
                                "JS code-execution sink called with dynamic value"
                                if is_eval
                                else "DOM XSS sink called with a non-literal value"
                            ),
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                f"{detail}. Passing attacker-controlled or LLM-generated "
                                "content to a code-execution sink executes arbitrary "
                                "JavaScript in the page context, enabling full session "
                                "takeover or data exfiltration (CWE-94)."
                                if is_eval else
                                f"{detail}. Writing non-literal HTML into a DOM sink "
                                "interprets any attacker-controlled markup as HTML, enabling "
                                "script execution, event-handler injection, or data exfiltration "
                                "via DOM-based XSS. This is not sent to the server, so "
                                "server-side sanitization does not protect against it."
                            ),
                            remediation=(
                                "Never pass user input or LLM output to eval() or new Function(). "
                                "Use JSON.parse() for data, and a sandboxed iframe or Worker "
                                "for untrusted code execution. "
                                "Suppress with `// security: allow-dom-xss-sink` only after "
                                "confirming the input is strictly controlled."
                                if is_eval else
                                "Replace with `element.textContent = value` to render as plain "
                                "text (never executed as HTML). If HTML rendering is required, "
                                "pass the value through DOMPurify.sanitize() first and add a "
                                "`// security: allow-dom-xss-sink` comment after confirming "
                                "the sanitizer is in place."
                            ),
                            rule=rule,
                            standards=standards,
                        ))
                        break  # one finding per line is enough
            out.extend(self._scan_settimeout(root, f, text))
            out.extend(self._scan_broken_sanitizer(root, f, text))
        return out

    def _scan_settimeout(self, root: Path, f: Path, text: str) -> list[Finding]:
        """Flag setTimeout/setInterval/setImmediate whose first arg is a code string.

        Scans a comment-blanked copy (`strip_js_comments`) so a commented-out example can't
        fire and — unlike the old line-local `line.find("//")` — a URL literal earlier on the
        line (`"http://..."`) is NOT mistaken for a comment that hides a genuine sink (#395 M).
        The whole first argument is captured with a paren-depth walk, so a multi-line call is
        seen whole (#395 Critical C2)."""
        out: list[Finding] = []
        # strip_strings=True blanks string/template CONTENTS (keeping the delimiters) so a `(` or
        # `,` inside the first argument's own string can't unbalance the paren walk and drop a
        # genuine finding (#395 RL-3); `_first_arg_is_code_string` still sees the kept delimiters.
        # strip_regex=True blanks regex BODIES too, which `strip_strings` never did: the `}` of
        # `/}/g` closed a callback body early (a CRITICAL FP on a function literal), and the `'` of
        # `/'/g` opened a phantom string that made the whole call give up (a silent CRITICAL FN, #909).
        # That view (`plain`) is the one every call is classified on, with one exception (#1055): a
        # call that exists only inside a `${...}` substitution is invisible there, since plain
        # `strip_strings` blanks substitution code, which made a nested timer sink a silent CRITICAL
        # FN. Such a call is found and classified on `scan`, the same view with
        # keep_substitutions=True. Using `scan` for EVERY call was wrong: it also exposed the code
        # inside a template ARGUMENT's substitutions, nested templates included, and the `+` there
        # read as a string-building concatenation on a function value (PR #1126 round-1 M1, round-2
        # N1). So the invariant is: a call that is live in `plain` gets exactly `plain`'s verdict.
        # Inside a substitution, `_first_arg_is_code_string` counts only a `+` outside every
        # literal, and regex bodies are not lexed (#543), so `strip_regex` cannot reach them there.
        plain = strip_js_comments(text, strip_strings=True, strip_regex=True)
        scan = strip_js_comments(text, strip_strings=True, strip_regex=True, keep_substitutions=True)
        calls = []
        for m in _SET_TIMEOUT_CALL.finditer(scan):
            live_in_plain = len(plain) == len(scan) and plain[m.start():m.end()] == m.group()
            calls.append((m, live_in_plain))
        # One `_paren_closes` sweep per view answers every call's close, so thousands of unclosed
        # calls stay linear (#1138).
        closes = {
            live: _paren_closes(plain if live else scan, [m.end() - 1 for m, lv in calls if lv == live])
            for live in {lv for _, lv in calls}
        }
        for m, live_in_plain in calls:
            open_idx = m.end() - 1  # index of the "(" the match ended on
            view = plain if live_in_plain else scan
            # track_groups: a comma inside a `{...}`/`[...]` group is never the argument separator
            # (#479 re-gate H1). This does NOT rely on the view being blanked: the #542 EOF cap and
            # the #910 parity cap restore literal text verbatim, so the walk and `_match_bracket` skip
            # literals themselves (#573, #909).
            args = _split_top_level_args(view, open_idx, track_groups=True, closes=closes[live_in_plain])
            if not args or not _first_arg_is_code_string(args[0]):
                continue
            lineno = scan.count("\n", 0, m.start()) + 1
            out.append(Finding(
                check_id=self.id,
                severity="critical",
                title="JS code-execution sink called with dynamic value",
                location=f"{rel(root, f)}:{lineno}",
                message=(
                    "setTimeout/setInterval/setImmediate is called with a string (or a "
                    "string-building concatenation) as its first argument. When the first "
                    "argument is a string rather than a function, the engine compiles and runs "
                    "it exactly like eval(). Passing attacker-controlled or LLM-generated "
                    "content this way executes arbitrary JavaScript in the page context (CWE-94)."
                ),
                remediation=(
                    "Pass an actual function or arrow-function literal "
                    "(`setTimeout(() => doSomething(userInput), 100)`) so the argument is a real "
                    "closure, never re-parsed as a string. Suppress with "
                    "`// security: allow-dom-xss-sink` only after confirming the input is "
                    "strictly controlled."
                ),
                rule=_SET_TIMEOUT_RULE,
                standards=list(_EVAL_STANDARDS),
            ))
        return out

    def _scan_broken_sanitizer(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        calls = list(_REPLACE_CALL.finditer(text))
        closes = _paren_closes(text, [m.end() - 1 for m in calls])  # one sweep for every call (#1138)
        for m in calls:
            open_idx = m.end() - 1  # index of the "(" the match ended on
            args = _split_top_level_args(text, open_idx, closes=closes)
            if not args or len(args) < 2:
                continue
            if not _is_broken_tag_sanitizer(args[0], args[1]):
                continue
            lineno = text.count("\n", 0, m.start()) + 1
            out.append(Finding(
                check_id=self.id,
                severity="high",
                title="Broken regex sanitizer strips only the first tag occurrence",
                location=f"{rel(root, f)}:{lineno}",
                message=(
                    "This .replace() call strips an HTML/script-tag-shaped pattern but only "
                    "removes the first occurrence (no `g` flag, or a plain string literal, "
                    "which is always single-occurrence). An attacker bypasses this by nesting "
                    "the tag — e.g. `<scr<script>ipt>` survives one `<script>` removal and "
                    "reassembles into `<script>` once the outer copy is stripped. A value "
                    "sanitized this way is still attacker-controlled when it reaches a DOM "
                    "sink (innerHTML, document.write(), etc.)."
                ),
                remediation=(
                    "Do not hand-roll HTML sanitization with a regex. Use a vetted sanitizer "
                    "library (DOMPurify) instead. If a global removal is genuinely sufficient "
                    "for this specific use case, use `.replaceAll()` or a `/g`-flagged regex — "
                    "note that even global regex removal is not a full HTML parser and can "
                    "still be bypassed by malformed markup. Suppress with "
                    "`// security: allow-dom-xss-sink` only after confirming a real sanitizer "
                    "is used."
                ),
                rule="dom-xss-sinks/incomplete-sanitization",
                standards=list(_STANDARDS),
            ))
        return out
