---
type: Guard
title: "dom-xss-sinks"
description: "DOM XSS sink called with a non-literal value."
timestamp: "2026-10-20T16:00:00Z"
guard_id: "dom-xss-sinks"
checklist_section: ["6a"]
standards: ["OWASP:A03", "OWASP:CheatSheet"]
---

# DOM XSS sink called with a non-literal value

## Threat

DOM-based XSS (CWE-79, OWASP A03) occurs when a web application writes
attacker-controlled data into a DOM sink that the browser interprets as HTML. Unlike
reflected or stored XSS, the payload never passes through the server, so server-side
output encoding is ineffective. The attack is triggered entirely in the browser using
client-supplied sources (URL fragments, `postMessage`, `fetch` responses, user input).

High-value DOM sinks include `innerHTML`, `insertAdjacentHTML`, and `document.write`.
When called with a non-literal value, these sinks render arbitrary HTML and execute
embedded scripts, event handlers, and `javascript:` URIs under the page origin.

In LLM/agent applications the risk is compounded: model output (often user-influenced
via prompt injection) is a natural source of attacker-controlled HTML, and developers
frequently render that output by writing it directly to `innerHTML`.

## Detection design

**Files scanned:** `.js`, `.jsx`, `.ts`, `.tsx` via `iter_files(root, (".js", ".jsx", ".ts", ".tsx"))`.

**Feature gate:** `applies()` returns `True` when `"frontend"` or `"react"` is in `profile.features`.

**Rule IDs:** `dom-xss-sinks/unsafe-dom-write` (HTML-injection sinks, **`high`**) ·
`dom-xss-sinks/eval-sink` + `dom-xss-sinks/new-function-sink` + `dom-xss-sinks/settimeout-string-arg`
(code-execution sinks, **`critical`**, CWE-94)

Six patterns, one finding per matching line:

| Pattern | Regex | What it catches | Severity |
|---|---|---|---|
| innerHTML sink | `\.innerHTML\s*\+?=(?!=)(?!\s*[\"'\`])` | Assignment **or compound append** from a variable (not a string literal) | high |
| insertAdjacentHTML sink | `\.insertAdjacentHTML\s*\(\s*["'](beforeend\|afterbegin\|beforebegin\|afterend)["']\s*,\s*(?![\"'\`])` | Second argument is a variable | high |
| document.write sink | `\bdocument\.write\s*\(\s*(?![\"'\`])` | Argument is a variable | high |
| eval sink | `\beval\s*\((?!\s*[\"'\`])` | `eval()` argument is non-literal — arbitrary **code execution** | critical |
| new Function sink | `\bnew\s+Function\s*\((?!\s*[\"'\`)])` | `new Function()` first argument is non-literal (CSP `unsafe-eval` bypass) | critical |
| setTimeout/setInterval/setImmediate sink | `\b(?:setTimeout\|setInterval\|setImmediate)\s*\((?!\s*(?:async\s+)?(?:function\b\|\([^()]*\)\s*=>\|[A-Za-z_$][\w$]*\s*=>))` | First argument is not a function/arrow-function literal — a **string-typed argument is compiled and run like `eval()`** | critical |

Negative lookahead `(?![\"'\`])` excludes static string literals (the only values
safe to write without sanitization). Template literals opening with a backtick are
conservatively flagged since they almost always contain interpolation.

The `\+?` on the innerHTML sink covers the **compound append** form, `el.innerHTML += userVar`,
which was silently uncovered (#422). It injects attacker HTML into the document exactly as the plain
assignment does — appending to a node's markup is the same parse, not a lesser one — so the two
spellings carry the same severity. `(?!=)` keeps the comparison operators (`==`, `===`, and now
`+==` cannot arise) out of it, and the literal exclusion applies to both forms alike:
`el.innerHTML += '<b>static</b>'` stays silent.

`dangerouslySetInnerHTML` is excluded — it is already covered by
`frontend-xss/dangerously-set-inner-html`.

### Sixth pattern (2026-07-15): setTimeout/setInterval/setImmediate string-arg code injection

`dom-xss-sinks/settimeout-string-arg` (**`critical`**, CWE-94) closes a documented gap: the
6a checklist item's title has always named `setTimeout(str)` as in-scope, but no guard
pattern implemented it until now. Source: GitHub CodeQL's
`javascript/ql/src/Security/CWE-094/CodeInjection.ql` — its `EvalJavaScriptSink` predicate
treats `setTimeout`/`setInterval`/`setImmediate` called with a string first argument as
equivalent to `eval()`. This is a legacy JS timer-API feature: when the first argument is a
string rather than a function, the engine compiles and executes it exactly like `eval()`.
Classic footgun: `setTimeout("doSomething(" + userInput + ")", 100)` executes the
concatenated string as code.

**This pattern inverts the "quote = safe" convention used by `_EVAL`/`_NEW_FUNCTION`.** For
those two sinks, a leading quote means a hardcoded string literal, which is the *safe* form.
For the timer APIs, a *string* first argument — literal, template, or a string-building
concatenation — is the *vulnerable* form, matching `eslint`'s `no-implied-eval` rule and
CodeQL's own `EvalJavaScriptSink` semantics. Detection is a **positive** signal
(`_first_arg_is_code_string`): the whole first argument is captured with a paren-depth walk,
then flagged only when it is a string/template literal or a `+`-concatenation carrying one.
A **bare identifier** passed directly (`setTimeout(handleClick, 300)`, `setInterval(userCode,
1000)`) is NOT flagged — it is indistinguishable from a named-callback function reference,
and firing on it was a critical false positive (PR #395 C2). A variable that merely holds a
string is a deliberate, documented false negative (the project prefers it over a noisy FP on
every named-callback timer).

This pattern is scanned over a comment-blanked copy (`strip_js_comments`, `strip_strings=True,
strip_regex=True, keep_substitutions=True`) so a commented-out example stays silent, a URL
literal earlier on the line can't be mistaken
for a comment, and a `(`/`,` inside the argument's own string can't unbalance the paren walk.
That copy is where a stray backtick earlier in the file (a CSS-in-JS template missing its closer)
used to pair with the next template's opener and blank the timer sink between them before the
regex ran: 0 findings, clean exit, no skip (#910). The helper now bounds it with a parity cap (an
odd template-delimiter count restores every closed template span), so the sink survives into the
scan. A `setTimeout` spelled out in a template's TEXT is string content and stays silent; one in
a `${...}` substitution is code and fires (#1055). Only such a call is classified on the
substitution-keeping view. Every call that is live outside a substitution is classified on the view
above, exactly as before #1055, because the other view also exposes the code inside a template
ARGUMENT's substitutions: a `+` there (`` setTimeout(show(`Step ${n + 1}`), 100) ``, nested templates
included) read as a string-building concatenation on a function value (PR #1126 rounds 1 and 2).
`test_dom_xss_timer_outside_a_substitution_keeps_the_plain_view_verdict` pins that invariant
differentially. Inside a substitution, the string-building test counts only a `+` outside every
literal.

#### Where an argument ENDS is a structural question too

The body-location invariant (a body is walked to, never searched for) governs
`_is_function_literal`. It applies one level up as well, in `_split_top_level_args`: *"where is
the first comma at paren depth 1"* is not *"where does the argument end"*. A comma inside the
callback's own body — an object literal, an array literal, a destructuring, a second declarator —
truncated `args[0]` mid-body, so the classifier never saw a whole literal and the `+`-and-a-quote
heuristic fired CRITICAL on idiomatic React (#479 re-gate H1). The splitter therefore tracks
`{}`/`[]` groups as well as parens for the timer scan (opt-in via `track_groups=True`; the
sanitizer scan below only needs the top-level `.replace()` args and leaves it off).

The splitter is itself **quote/string-aware**, and this is load-bearing (#573/#574). It tracks an
active `'`/`"`/`` ` `` delimiter and, inside one, copies every char verbatim (honoring `\`
escapes) while counting NO `(){}[]<,` as structure. So a bracket or comma that lives inside a string
literal corrupts neither the paren depth nor the group counter, whether or not the caller
pre-blanked strings. It formerly leaned on the string-blanking for that guarantee, and two silent
false negatives followed when the assumption broke: a `}` inside a string that #542's EOF un-blank
restored VERBATIM desynced the group counter and dropped a live CRITICAL timer sink (#573), and a
`(` inside a raw `.replace()` pattern desynced the paren count and dropped a HIGH broken-sanitizer
finding (#574, consolidated into #573).

#### Every bracket walk skips literals, not just the splitter (#909)

#573 made the splitter's walk literal-aware and left every other walker alone. `_match_bracket`,
which finds a callback's body end, an IIFE tail, a `<…>` head and a parameter list, counted every
`{ } ( ) < >` byte, and the call's closing paren came from the shared `matching_close_paren`, which
tracks `'`/`"` but not the backtick. They trusted the scan copy to have literal contents blanked,
and it does not, in two ways. Regex literal bodies were never blanked, so `/}/g` and `/'/g` reached
the counters in **valid** files. And #542's EOF cap and #910's parity cap restore literal text
verbatim by design. The results ran in both directions:

- a benign callback fired CRITICAL: a `}` in `"unexpected }"`, in `/}/g` or in a revived template
  closed the body early, and the body's own `"x" + m` then read as a code string;
- a real string timer was silently dropped: the `'` of `/'/g` opened a phantom string, so the
  classic `setTimeout("alert('" + m.replace(/'/g, "\\'") + "')")` was never inspected;
- the `<…>` head ended at the `>` of `=>` (`<T extends () => void,>`), or at a `>` inside a restored
  `"a>b"` default, so a top-level comma split the head and hid the argument behind it;
- a backtick `.replace()` pattern with a `)` or an apostrophe (`` `<div title=odd) markup>` ``,
  `` `<p>it's</p>` ``) made the close-finder and the walk disagree, and the HIGH was dropped.

The fix is two layers. `_match_bracket` skips each `'`/`"`/`` ` `` literal whole, under the same
flat model as the splitter's walk, and gives up (-1) on one still open at its bound. For `>` it
ignores the `>` of `=>`. The call's close is found with it too, so the two can no longer disagree.
The shared `matching_close_paren` is unchanged: several of its other callers read Python, SQL or
Java, where a backtick is not a string delimiter. Second, the timer scan asks `strip_js_comments` for
`strip_regex=True`, which blanks regex BODIES (keeping the delimiters and flags). That flag is
opt-in, and not folded into `strip_strings`, which other guards consume.

`strip_regex` turns a regex-vs-division misread from harmless into "the text between two slashes is
gone", so it refuses whenever a misread is possible. It blanks only a regex that closed on its own
line. It never blanks one whose preceding source char rules out a real regex: a string or template
close (the lexer then reads its stale "last paren was `if (…)`" flag, seen on a real `.tsx` file),
a `<` (a JSX closing tag `</b>`), or a bare `>` (JSX text starting with `/`). Without those refusals
the three JSX shapes each deleted a CRITICAL `onClick={() => setTimeout("…" + x)}` sink. Measured
on 10,314 js/ts files (16 corpus repos plus the flagship): the flag blanks regex bodies in 1,431 of
them and deletes no timer call token from any. The timer and sanitizer rules report zero findings
there before and after, so that corpus shows no new FP; it holds no sink to test the FN direction,
which is what the token count and the JSX tests cover. The refusals forgo 23 of 12,135 blanked spans.

What #909 leaves is listed as rows in the two tables below. Its false negatives are give-ups, never
a wrong split, and its false positives need a file that is not valid JS. The sanitizer scan's
comment-blindness is listed there too. It is a separate root cause and fires on valid files.

Every inner scan is also bounded at the call's own closing paren, found once up front. Unbounded,
a single unbalanced `<` at an argument start ran a bracket search to **end of file**, once per
timer match: measured on a 24 KB file of 800 such calls, 528 ms at both `6d0b0fd1` and `fa380941`
(and the whitespace-led spelling newly reached the same cost at the tip, 0.4 ms → 77 ms at k=200).
Bounded, the same input costs 2.3 ms. Such input does not compile, so this is robustness on a
guard that must be total over arbitrary text — generated, templated or half-written files — not a
live exploit path.

### Seventh pattern (2026-07-12): broken regex sanitizer

`dom-xss-sinks/incomplete-sanitization` (**`high`**) checks sanitizer *quality*, not sink
usage: a `.replace(pattern, "")` call that strips an HTML/script-tag-shaped pattern
(`_TAG_LIKE = <[^<>]*>`) but only removes the *first* occurrence — either a regex literal
without a `g` flag, or a plain quoted-string first argument (which is inherently
single-occurrence in JS regardless of flags). An attacker bypasses this by nesting the
tag: `"<scr<script>ipt>".replace("<script>", "")` produces `"<script>"`, reassembling the
very thing the call tried to strip.

Unlike the five sink patterns above (single-line regex), this pattern needs balanced-
paren argument parsing to separate the `.replace()` call's two arguments, so it runs as a
second, whole-file pass (`_scan_broken_sanitizer`) after the per-line sink loop, using the
same `_split_top_level_args` helper style as `insecure_cookies.py`'s `_balanced_args`. This
also means it is not limited to single-line calls — a `.replace()` split across multiple
lines is still caught, since the argument text is walked character-by-character from the
matched `(` rather than `line`-by-`line`.

**Deliberately not flagged:** `.replaceAll()` (the method name itself signals "every
occurrence"), a `/g`-flagged regex (removes every occurrence in one pass — still not a
real HTML parser, but a different, less unambiguous bug than single-occurrence stripping),
and any non-empty replacement (escaping to `&lt;`/`&gt;` is a different, legitimate
technique from stripping).

**Pragma:** if a `// security: allow-dom-xss-sink` comment appears anywhere in a file (a
string literal quoting the phrase does not count, #424), the entire file is skipped. This allows teams to suppress after confirming a sanitizer
is applied.

## Severity rationale

`high` — a successful DOM XSS exploit runs arbitrary JavaScript under the app's
origin: session hijacking, credential theft, exfiltration of any data accessible to
the page, and account takeover. Impact is immediate and requires no server
compromise. In LLM applications the attack surface is enlarged because model output
is a structurally untrusted source developers often pipe directly into innerHTML.

## Known bypasses / false negatives

Since #1055, a sink in the per-line scan counts only when its first character is live code on the anchor mask (`js_code_matches`): `eval(`, `innerHTML =` or `document.write(` spelled out in a docs or error string no longer fires, a real sink inside a `${...}` substitution still does, and a quoted copy first on the line no longer hides the real sink after it. The timer scan now keeps substitution code too (`keep_substitutions=True`). Plain `strip_strings` blanked it, so `` `${setTimeout('run(' + x + ')', 10)}` `` was a silent CRITICAL FN.

| Bypass | Why missed |
|---|---|
| A sink between two substitutions that each hold a `{` or `}` inside a regex or comment | The anchor mask inherits the #543 sub-lexer residual: the pair rebalances the template frame, so the code between them reads as template text and the sink is dropped (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). Inside a substitution a regex body is also not lexed, so `strip_regex` cannot blank it there |
| Multi-line sink: `el.innerHTML =` on one line, `userVar` on the next | Pattern is single-line only; dataflow not tracked |
| Sanitizer result stored in `safeHtml`, then assigned via `innerHTML` | Cannot distinguish sanitized from unsanitized variable |
| `new Function("a", bodyVar)` — literal first arg, dynamic body | Conservative FN: the first-arg lookahead skips a literal-led `new Function`, mirroring `eval`'s literal skip (FP-bias trade-off) |
| `Function(code)` without `new`, `globalThis.Function` | Not matched; the guard targets `eval(` and `new Function(` specifically. (`setTimeout("code")` IS now covered — see `dom-xss-sinks/settimeout-string-arg` above.) |
| Multi-line `setTimeout` call: `setTimeout(` on one line, the code string on the next | Pattern is single-line only; the negative lookahead sees only what follows `(` on the same line |
| `setTimeout(fnHoldingAString, 100)` where a callback LITERAL is passed a string-building body | A function/arrow literal first argument is excluded (#479): its body is never re-parsed by the engine, so a `"a" + b` inside it is not a code string. A genuine string sink hidden inside a callback literal is therefore not reachable by this rule. The exclusion classifies the **value**, not a call-shaped prefix, so an IMMEDIATELY-INVOKED literal (`function(){…}()`, `.call()`, `.bind()()`, a concatenation tail) is not excluded and still fires |
| A first argument whose TYPE ANNOTATION carries a top-level comma inside `<…>` — `setTimeout(function (): Record<string, number> { … }(), 100)`, `setTimeout(function <T, U>(a: T) { … }(), 100)` | The argument splitter consumes a `<…>` head only where an argument STARTS (nothing in JS may begin with `<`, so there it cannot be a comparison). Mid-argument, `<` stays a comparison operator — the alternative would swallow the separator in `setTimeout(() => cmp(a < b, c > d), 100)`. The comma inside the mid-argument generic therefore still splits, and the truncated fragment is not inspected. Pre-existing; a conservative FN on a rare shape, kept in preference to a comparison-shaped FP. **The example must be a `function`-keyword form:** an arrow function cannot be immediately invoked, so the arrow spelling of this row (shipped in the first draft) is a syntax error and was never a reachable shape. Pinned by `test_mid_argument_generic_comma_is_a_known_false_negative` so the row stays testable |
| Sink called via alias (`const w = document.write; w(x)`) | Alias tracking requires dataflow analysis |
| Template literal with only safe interpolation (e.g. `\`<p>${count}</p>\``) | Backtick lookahead flags all template literals conservatively |
| `.replace(new RegExp("<script>"), "")` | The `RegExp` constructor form is not a `/pattern/flags` literal or a quoted string, so `_is_broken_tag_sanitizer` does not recognize it — regex-literal syntax only |
| Sanitizer split across two `.replace()` calls that together strip nested tags | Each individual call may look global/complete in isolation; cross-call reasoning requires dataflow |
| A regex pattern argument holding an unpaired quote: `html.replace(/<a title='/, "")` | The sanitizer scan reads RAW text (comments and regex bodies are not blanked there), so the lone `'` opens a phantom string and the call gives up. A conservative miss, unchanged by #909. A paired quote (`/<p class='x'>/`) still fires. The timer scan is not exposed: it reads a copy with regex bodies blanked |
| A comment inside a `.replace()` call that holds an apostrophe: `html.replace("<script>", /* don't */ "")` | The same raw-text root cause, here as comment-blindness at the sanitizer site: the comment's `'` opens a phantom string and the HIGH is dropped. The fix is to locate structure in a blanked copy and read argument content from the raw text by the same offsets (the `client_side_secret_literal` pattern). Found by the #909 RCA, out of its scope |
| A string timer in a file whose template literal is still open at EOF, with a quote-regex in the call: `setTimeout("run(" + x.replace(/'/g, "") + ")", 0)` after the open backtick | #542's EOF cap restores everything from the open backtick on, regex bodies included, so `strip_regex` cannot blank them there; the regex `'` opens a phantom string and the call gives up. `_match_bracket` does skip string and template literals in that tail, so #909 narrows the exposure to regex bodies. The file is not valid JS |

## False positive scenarios

| Scenario | Example | Why it fires | How to handle |
|---|---|---|---|
| Sanitized value assigned to innerHTML | `el.innerHTML = DOMPurify.sanitize(input)` | Guard sees variable, not sanitizer call | Add `// security: allow-dom-xss-sink` after confirming |
| Static template literal | `el.innerHTML = \`<p>Hello</p>\`` | Backtick is conservatively flagged | Use a regular string literal `"<p>Hello</p>"` |
| Test fixtures that intentionally exercise sinks | `el.innerHTML = testPayload` in `*.test.ts` | Pattern fires in test files too | Add pragma to test file, or accept as documentation of known risky pattern |
| Member method named `eval` | `parser.eval(expr)` | `\beval\s*\(` matches a **whole-word** `eval` member because `\b` matches after the `.` — **intentional**, this is how `window.eval` / `globalThis.eval` are covered. It is narrow: `retrieval(x)` / `medieval(x)` do **not** match. | A non-evaluator method literally named `eval` is rare; add `// security: allow-dom-xss-sink` after confirming it is not the JS evaluator |
| `.replace()` used for a non-HTML purpose that coincidentally matches `<...>` | `str.replace("<unused>", "")` on a config placeholder, not HTML | `_TAG_LIKE` only checks shape, not semantic intent | Add `// security: allow-dom-xss-sink` after confirming the value never reaches a DOM sink |
| `setTimeout`/`setInterval` called with a bare identifier that actually holds a string of code | `setTimeout(userCode, 100)` where `userCode` is a string | Guard cannot distinguish a string-holding identifier from a function reference statically, so a bare identifier is NOT flagged (positive string-signal only) — a deliberate FN to avoid the FP on `setTimeout(handleClick, 300)` | Pass a string only via a visible literal/template/concat (which IS flagged), or refactor to an inline function literal |
| Timer callback with an unbalanced brace in a REGEX in its body, in a file whose template literal is still open at EOF | `setTimeout(function(){ x.replace(/}/g, ""); go("x" + m); }, 100)` after an unterminated backtick | #542's EOF cap restores regex bodies along with everything else from the open backtick on, so `strip_regex` cannot blank the `}`; it closes the body early and the body's own concatenation reads as a code string. In a valid file the same callback is silent (#909). String and template braces in that tail no longer trip it | Fix the unterminated template (the real defect), or add `// security: allow-dom-xss-sink` after confirming the callback is a real function |
| Timer callback whose return-type annotation is a string-literal TYPE carrying a bracket, on the EOF/parity path | `setTimeout((): "{" => { go("x" + m); }, 100)` after an unterminated backtick | `_annotation_arrow_end` and `_annotation_body_start` keep their own depth loops, which do not skip literals (left out of #909 as an optional consistency change). In a valid file the type's contents are blanked and the callback is silent | As above |
| A commented-out broken sanitizer | `// html = html.replace("<script>", "")` | The sanitizer scan reads RAW text, so a `.replace(` inside a comment is split and judged like live code. A separate, pre-existing root cause (comment-blindness, not literal-blindness), found by the #909 RCA and out of its scope; it happens in valid files | Delete the dead code, or add `// security: allow-dom-xss-sink` |

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| 6a-dom-xss-sinks | `uncovered` | `covered` | Guard detects innerHTML / insertAdjacentHTML / document.write with non-literal values in JS/TS files |

## Tests

| Test | Validates |
|---|---|
| `test_dom_xss_settimeout_callback_containing_a_concatenation_is_safe` | FP-bait (#479): a function/arrow literal whose BODY builds a string does not fire — six callback shapes. |
| `test_expression_bodied_and_braced_head_callbacks_are_not_sinks` | FP-bait for the body-location invariant: 25 callback shapes whose brace is in the parameter list, the return-type annotation or the expression body — not the body. |
| `test_ordinary_react_component_stays_silent` | The same class end to end: an ordinary React component with zero real sinks yields zero findings. |
| `test_generic_head_is_consumed_whatever_the_whitespace_layout` | The `<T,>` type-parameter head is consumed at the first NON-WHITESPACE character of an argument, so a prettier-wrapped call cannot desync the splitter and hide the payload. |
| `test_generic_head_gate_does_not_widen_onto_comparisons` | The direction that trades against: a mid-argument `<` is still a comparison — `cmp(a < b, c > d)` and `makeCb<A, B>(q)` stay silent in both layouts. |
| `test_immediately_invoked_function_is_not_a_function_literal` | The narrowing direction: 17 invoked/`.call()`/`.bind()()`/concat-tail shapes are classified by their VALUE and still fire. |
| `test_a_comma_in_the_callback_body_does_not_truncate_the_argument` | FP-bait for the argument BOUNDARY (the same invariant one level up): 40 combinations of five callback heads against eight body statements carrying a top-level comma — object/array literal, two declarators, either destructuring, a generic annotation, a two-argument call. |
| `test_react_component_with_an_object_literal_in_the_callback_stays_silent` | The same class end to end, on the shape the earlier React test happens not to contain. |
| `test_group_tracking_does_not_hide_a_real_timer_sink` | The direction that narrowing trades against: five real sinks still fire CRITICAL, including a code string carrying braces/brackets and one whose brace is UNBALANCED (where `args[0]` now runs to the call's closing paren). |
| `test_group_tracking_is_off_for_the_raw_text_sanitizer_scan` | `track_groups` is off for the sanitizer scan (it needs only the top-level `.replace()` args); the quote-aware splitter (#573/#574) skips a `{` inside a string literal regardless, so both single-occurrence tag-strips fire. |
| `test_return_type_annotation_does_not_make_a_callback_a_sink` | FP-bait for the annotation walk: seven return-type shapes, including the two parenthesised forms the old paren-stop heuristic misread as sinks. |
| `test_annotated_iife_is_still_a_sink` | The direction that trades against, and the reason the heuristic existed: eight annotated IIFE forms (bare and `|| {}`) still fire. |
| `test_mid_argument_generic_comma_is_a_known_false_negative` | Pins the documented FN above as a `function`-keyword shape, so the known-bypass row stays testable and cannot drift back to a spelling that does not compile. |
| `test_match_bracket_honours_its_end_bound` | Every inner scan is bounded at the call's own closing paren, so an unbalanced `<` cannot run a search to end of file once per timer match. |
| `test_dom_xss_settimeout_string_concat_still_fires_after_the_callback_exclusion` | The other direction: a real string-concat sink, incl. a parenthesized one, still fires CRITICAL. |
| `test_dom_xss_sinks_flags_inner_html` | `el.innerHTML = userInput` fires one HIGH finding |
| `test_dom_xss_sinks_flags_insert_adjacent` | `el.insertAdjacentHTML("beforeend", rawHtml)` fires one HIGH finding |
| `test_dom_xss_sinks_flags_document_write` | `document.write(template)` fires one HIGH finding |
| `test_dom_xss_sinks_silent_static_string` | `el.innerHTML = "<p>static</p>"` produces no findings |
| `test_dom_xss_sinks_pragma_silences` | File with pragma produces no findings even when sink pattern is present |
| `test_dom_xss_sinks_not_applies_without_frontend` | Guard returns `[]` when profile lacks `frontend` and `react` features |
| `test_dom_xss_sinks_flags_non_global_regex_tag_strip` | `.replace(/<script>/i, "")` (no `g` flag) fires `incomplete-sanitization` |
| `test_dom_xss_sinks_flags_string_literal_tag_strip` | `.replace("<script>", "")` (plain string, always single-occurrence) fires |
| `test_dom_xss_sinks_silent_global_regex_tag_strip` | `.replace(/<script>/gi, "")` (has `g` flag) stays silent |
| `test_dom_xss_sinks_silent_replace_all` | `.replaceAll("<script>", "")` stays silent |
| `test_dom_xss_sinks_silent_non_tag_replace` | `.replace(",", "")` (no tag shape) stays silent |
| `test_dom_xss_sinks_silent_replace_non_empty_replacement` | `.replace("<script>", "&lt;script&gt;")` (escaping, not stripping) stays silent |
| `test_dom_xss_settimeout_string_concat_fires` | `setTimeout("alert(" + x + ")", 100)` fires one CRITICAL `settimeout-string-arg` finding |
| `test_dom_xss_settimeout_function_literal_safe` | `setTimeout(() => alert(x), 100)` (arrow-function literal) stays silent |
| `test_dom_xss_setinterval_bare_identifier_safe` | `setInterval(userCode, 1000)` (bare identifier) stays silent — indistinguishable from a function reference (PR #395 C2) |
| `test_dom_xss_settimeout_named_callback_safe` | `setTimeout(handleClick, 300)` (named callback) stays silent |
| `test_dom_xss_setimmediate_string_fires` | `setImmediate("runTask()")` (string literal) fires `settimeout-string-arg` |
| `test_dom_xss_settimeout_template_literal_fires` | `` setTimeout(`run(${x})`, 100) `` (template literal) fires CRITICAL |
| `test_dom_xss_settimeout_function_expression_safe` | `setTimeout(function() { doStuff(); }, 100)` (function-keyword literal) stays silent |
| `test_dom_xss_settimeout_comment_silent` | `// avoid patterns like setTimeout(str) in this codebase` (line comment) stays silent |
| `test_dom_xss_settimeout_pragma_suppresses` | File with pragma produces no findings even when a `setTimeout` string-arg sink is present |
| `test_dom_xss_settimeout_sink_fires_despite_upstream_unterminated_template` | #573 primary: an IIFE-return string sink fires CRITICAL even when an unterminated template earlier in the file triggers the EOF un-blank that used to desync the group counter and silently drop it. |
| `test_dom_xss_benign_timer_after_unterminated_template_stays_silent` | #573 FP-bait (widening): an ordinary arrow callback with a comma-bearing string body, placed after an unterminated template, still stays silent. |
| `test_dom_xss_generic_head_string_sink_fires_after_unterminated_template` | #573: the `<T,>` type-parameter-head + string-arg path stays live through the quote-aware rewrite. |
| `test_dom_xss_broken_sanitizer_fires_with_paren_in_pattern` | #574: a `(` inside the `.replace()` pattern (`"(<script>"`) no longer desyncs the paren count — it fires HIGH like its paren-free neighbours. |
| `test_dom_xss_non_tag_paren_replace_stays_silent` | #574 FP-bait (widening): a `(`-bearing but non-tag pattern with a non-empty replacement stays silent. |
| `test_dom_xss_split_honors_escaped_quote_in_replace_pattern` | #573 escape edge: an escaped quote in a `.replace()` pattern (`"a\")b"`) does not close the string early, so the split is not truncated. |
| `test_dom_xss_broken_sanitizer_backtick_paren_pattern_fires` | #909 site B (formerly pinned as a known gap): a `` ` ``-quoted `.replace()` pattern with a stray `)` or an apostrophe fires HIGH like its `'`/`"` twin; pins all three lines by location. |
| `test_dom_xss_backtick_non_tag_replace_with_a_paren_stays_silent` | FP-bait for the site-B widening: a backtick pattern that now splits is still judged by the tag check, so a non-tag one stays silent. |
| `test_settimeout_sink_after_a_stray_template_opener_still_fires` | #910 (FN direction): a timer sink between a stray CSS-in-JS opener and the next template's opener fires one CRITICAL, exactly as the closed-template control does. |
| `test_settimeout_inside_a_closed_template_is_string_content` | FP-bait for the #910 widening: a `setTimeout` inside a template that really closes is string content and stays silent. |
| `test_parity_cap_revive_inside_a_callback_body_no_longer_fires` | Formerly the #910 parity cap's accepted guard-level FP: a callback body holding an unbalanced-brace template on an odd-parity file is now silent (#909); a real code-string sink carrying such a template still fires exactly once. |
| `test_match_bracket_skips_literals_and_arrows` | #909 unit: a bracket inside `'`/`"`/`` ` `` is not structure, `\` escapes the delimiter, an unterminated literal gives up, and the `>` of `=>` does not close a `<…>` head. |
| `test_callback_with_a_brace_inside_a_literal_is_still_a_function_literal` | #909 narrowing: six callbacks that fired CRITICAL on main (a `}` in a body string on the EOF path, a brace in a body regex in a valid file, a regex after `=>`) are silent. |
| `test_iife_with_a_brace_inside_a_literal_still_fires` | The direction that narrowing trades against: four invoked forms carrying a literal brace (two IIFEs, the or-empty-object IIFE bypass, an arrow IIFE) still fire CRITICAL. |
| `test_string_timer_hidden_by_a_literal_or_an_arrow_now_fires` | #909 widening: two quote-regex string timers, a `=>`-constrained generic head and a quoted-default head on the EOF path, each a silent miss on main, fire CRITICAL. |
| `test_benign_neighbours_of_the_909_widening_stay_silent` | FP-bait for that widening: five benign callbacks stay silent. On main several were never classified whole (the split gave up, or cut the `<…>` head short); here each reaches the body classifier, which a mutation of it proves. |
| `test_a_misread_jsx_regex_cannot_blank_a_timer_sink` | The direction `strip_regex` trades against: three JSX shapes the lexer misreads as a regex (after `</`, after a string close, after a bare `>`) keep their CRITICAL timer sink. |
| `test_commented_sink_after_a_brace_in_a_substitution_regex_stays_silent` | #543 FP direction: a `{` in a regex inside a `${…}` no longer keeps the template open, so a commented-out timer or `innerHTML` sink after it stays silent, while the same sink uncommented fires. |
| `test_timer_sink_between_two_brace_regex_substitutions_fires` | #543 FN direction: a timer sink between a `/{/` substitution and a later `/}/` one fires CRITICAL (the pair used to rebalance and blank it). |
| `test_timer_sink_between_two_non_null_divisions_in_substitutions_fires` | #1124 review H2: a TypeScript non-null `x! / 2` inside a `${…}` is division, not a regex, so two such lines cannot swallow their templates' closers and blank the timer sink between them. |

# Citations

[1] agentsec checklist item `6a-dom-xss-sinks` (§6a)
[2] OWASP:A03
[3] OWASP:CheatSheet
