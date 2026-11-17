---
type: Guard
title: "go-template-html-escaping"
description: "text/template used where html/template's auto-escaping is needed."
timestamp: "2026-08-11T11:20:17+08:00"
guard_id: "go-template-html-escaping"
checklist_section: ["3b"]
standards: ["OWASP:A03"]
---

# text/template used where html/template's auto-escaping is needed

_Author — 2026-08-10_

---

## The threat

Go ships two template packages with a near-identical API surface — `Must`, `New`, `Parse`,
`ParseFiles`, `ParseGlob`, `Execute`, `ExecuteTemplate` all exist on both, and both packages
even declare `package template`, so the bound identifier at a call site
(`template.Must(template.New(...).Parse(...))`) looks byte-for-byte identical either way:

  * `html/template` is context-aware: it inspects WHERE a substitution lands (an HTML text
    node, an attribute, a `<script>` block, a `href=`/`src=` URL, a `<style>` block) and
    escapes the value correctly for that specific context.
  * `text/template` is pure string substitution. No escaping, in any context, ever — by
    design, since it is meant for arbitrary non-HTML text output (config files, emails,
    generated source code, CLI output).

WHO reaches this: any attacker who controls a value that flows into a `text/template`
template field that is then rendered to an HTTP response body — a request parameter, a
stored user-submitted value (a display name, a comment, a bio), or an LLM/agent response
included in a rendered page. WHAT privilege: none — this is a reflected or stored XSS
primitive reachable by any unauthenticated party who can influence the templated value and
view (or get a victim to view) the rendered response. WHAT effect: arbitrary JavaScript
execution in the victim's browser session — session/cookie theft, CSRF-token exfiltration,
UI redress, or full account takeover if the response is rendered inside an authenticated
page. CWE-79 (Improper Neutralization of Input During Web Page Generation), OWASP Top 10
A03:2021 (Injection).

## Why this guard fits the stack

The bug is not a typo or an obviously-wrong call — it is invisible at the call site. Every
one of these produces working, compiling Go code with wildly different security properties:

```go
import "text/template"   // <-- the entire bug, on one line, indistinguishable at the call site

func profileHandler(w http.ResponseWriter, r *http.Request) {
    tmpl := template.Must(template.New("profile").Parse(profileHTML))
    tmpl.Execute(w, UserProfile{Bio: r.FormValue("bio")}) // Bio is now unescaped in the response
}
```

Concretely, this shows up from:

  * A **find-and-replace refactor** that changes `"html/template"` to `"text/template"` (or
    vice versa) across a codebase and misses one file, or is applied for the wrong reason
    (e.g. "text/template supports a feature html/template's parser rejected" without
    realizing the safety trade-off).
  * A **copy-pasted example** from a blog post, Stack Overflow answer, or an LLM completion
    that used `text/template` for a *different*, legitimately non-HTML purpose (a CLI tool,
    a code generator) and was adapted into an HTTP handler without updating the import.
  * An **IDE auto-import** picking the first `template` match, which is alphabetically and
    contextually arbitrary between the two packages.

## Detection design

1. **`applies(profile)`** — `"go" in profile.features`. `detect.py` seeds `features` from
   `languages`, and `languages` gains `"go"` whenever a `.go` file is found in the repo, so
   this fires for any repo with Go source, not gated on a specific web framework — the two
   stdlib packages are usable directly with `net/http`, no framework required.
2. **Files scanned** — `go_scan_dirs(root, profile)` (mirrors `python_scan_dirs`) resolved
   against `profile.go_dirs`, then `iter_files(d, (".go",))` under each.
3. **Two-view split** — the comment-only view of the file text is checked for the pragma first (#424;
   the pragma lives inside a `//` comment, which the next step blanks out), THEN `strip_go_comments()` is
   applied and every pattern below runs against that STRIPPED view — so a pattern that
   appears only inside a comment (a commented-out import, a doc example, an old code
   snippet) never fires. Both views share line numbers/offsets because `strip_go_comments`
   blanks rather than deletes.
4. **Signal 1 (primary, rule `go-template-html-escaping/text-template-http-response`)** —
   fires once per file, anchored at the `text/template` import line, when ALL THREE hold:
   the file imports `"text/template"` (matched as the WHOLE quoted import path, so a real
   sibling package like `"text/template/parse"` never matches); the file does NOT also
   import `"html/template"` anywhere; and the file references `http.ResponseWriter`
   anywhere. This is file-level and import-based — it does not care how many places in the
   file execute the template, or whether the construction and the `http.ResponseWriter`
   reference are in the same function. One file, one violated import choice, one finding.
5. **Signal 2 (secondary, rule
   `go-template-html-escaping/text-template-execute-http-response`)** — only runs when
   signal 1 did NOT fire for the file (i.e. `html/template` IS also imported, so signal 1's
   exclusion applies). Resolves the identifier bound to `text/template` (the explicit alias,
   or Go's own default package name `template` if unaliased; a blank `_` or dot `.` import
   binds no usable identifier and is skipped — see "Known bypasses"). For every
   `<ident>.Must(<ident>.New(` occurrence in the file, finds the ENCLOSING Go function by
   walking backward to the nearest `func` keyword whose brace-matched body actually contains
   the match (handling a closure literal, e.g. one passed to `http.HandleFunc`, correctly as
   its own innermost scope) and requires, all inside that one function's signature+body: a
   `.Parse(`/`.ParseFiles(`/`.ParseGlob(` call completing the chain, a
   `.Execute(`/`.ExecuteTemplate(` call, and an `http.ResponseWriter` reference (the function
   signature is included specifically so `w http.ResponseWriter` in the parameter list
   counts). This catches the same bug hiding behind a dual import, scoped tightly enough
   that an unrelated `text/template` usage elsewhere in the same file — even a few lines away
   in a neighbouring short function — does not co-trigger it (see "Detection design notes"
   below for why a fixed-size character window was tried and rejected in favor of this).
6. **Pragma** — `// security: allow-go-template-html-escaping` anywhere in the file
   suppresses ALL findings for that file (checked against the raw pre-strip text).
7. **Severity** — `high` for both signals. **Standards** — `["CWE-79", "OWASP:A03"]`.

### Detection design notes: why function-scoped, not a character window

Signal 2 originally bounded its "same function" check with a fixed character count after the
`Must(New(` match. This was measured against the guard's own test fixtures and rejected: a
window sized to cover one typical handler body reached PAST a short function into an
unrelated neighbouring one in a small file (a false positive — see the "separate purposes"
FP-bait test, which failed under the fixed-window version), while the same window would fall
short inside one long function in a large file (a false negative in the other direction — not
directly measured, but the same arithmetic problem in reverse). Neither a smaller nor a
larger constant fixes both directions at once, because the right bound is "one function," which
has no fixed size. Brace-matching from the nearest enclosing `func` gives the real boundary
instead of an approximation of it, and costs nothing extra: the guard already had a
stripped-comments text to scan.

## When NOT to flag

  * **`text/template` alone, for its intended purpose.** Config-file generation, CLI output,
    generated source code, email/text bodies, log formatting — none of these reference
    `http.ResponseWriter`, so signal 1 and signal 2 both stay silent (`fires` require it).
    This is the overwhelming majority of real `text/template` usage and is exactly what
    scoping on `http.ResponseWriter` exists to exclude.
  * **Both packages imported for their own separate purposes** — `text/template` for a
    non-HTML output path (a config generator, written in its own function far from any HTTP
    handler) and `html/template` for actual page rendering. Signal 1 stays silent by design
    (it excludes any file with `html/template` also imported). Signal 2 also stays silent as
    long as the `text/template` chain's own enclosing function never itself references
    `Execute`+`http.ResponseWriter` — the case validated by
    `test_go_template_html_escaping_silent_when_both_packages_used_for_separate_purposes`.
  * **The correct package, `html/template`, doing the exact same construct-and-serve
    pattern.** Verified directly by
    `test_go_template_html_escaping_silent_on_html_template_correct_package`.
  * **The pattern appearing only in a comment** — a commented-out old import, a doc example —
    never fires, because pattern matching runs against the comment-stripped view.
  * **The pragma** — `// security: allow-go-template-html-escaping` — is for a genuinely
    audited case: every template field is a fixed compile-time constant (never attacker- or
    user-influenced), or the response is verified non-HTML (a `.txt`/`.csv` download written
    through the same `http.ResponseWriter`, where escaping would be actively wrong).

## Tests

| Test | What it checks |
|---|---|
| `test_go_template_html_escaping_fires_on_text_template_with_response_writer` | Signal 1: bare `text/template` import + `http.ResponseWriter` + Execute fires, rule tagged, severity high, CWE-79 present. |
| `test_go_template_html_escaping_fires_on_aliased_text_template_import` | Signal 1 fires identically when the import is aliased (`tt "text/template"`). |
| `test_go_template_html_escaping_silent_on_html_template_correct_package` | FP-bait: the correct package doing the identical construct-and-serve pattern stays silent. |
| `test_go_template_html_escaping_silent_without_response_writer` | FP-bait: `text/template` with no `http.ResponseWriter` anywhere (a CLI/config generator) stays silent. |
| `test_go_template_html_escaping_silent_when_both_packages_used_for_separate_purposes` | FP-bait: dual import, each package used for its own legitimate purpose in its own function, stays silent — the primary test for signal 1's exclusion AND signal 2's function-scoping. |
| `test_go_template_html_escaping_fires_on_direct_chain_when_both_packages_imported` | Signal 2: dual import present (so signal 1 is excluded), but the SPECIFIC chain in the handler function resolves to `text/template` and executes to `http.ResponseWriter` — fires, tagged with the signal-2 rule. |
| `test_go_template_html_escaping_silent_on_pattern_only_in_comment` | FP-bait: the whole pattern written out inside a `//` comment block stays silent (comment-stripped scan). |
| `test_go_template_html_escaping_pragma_silences` | The inline pragma suppresses an otherwise-firing case. |
| `test_go_template_html_escaping_not_applies_without_go` | `applies()` is false without `"go"` in `profile.features`. |

Adversarial cases exercised manually beyond the committed suite (not asserted in CI, recorded
here for the record): a closure literal handler passed to `http.HandleFunc` (signal 1 fires,
unaffected by function scoping); the signal-2 chain living inside a closure nested in an
outer function (correctly scoped to the innermost closure, not the outer function); a raw
string template body containing literal `{{ }}` (balanced, did not desync brace-counting); a
package-level `var` construction with no enclosing function at all (signal 1 still fires,
since it is import-based; signal 2 correctly does NOT fire, since there is no enclosing
function to scope it — see "Known bypasses"); an `http.ResponseWriter`-shaped string embedded
in an unrelated log message (a genuine, documented false-positive direction — see below); and
a deliberately unbalanced brace inside a raw string within the enclosing function (brace
matching fails to close, `_enclosing_function_span` returns `None`, signal 2 fails CLOSED —
a false negative, not a wrong report).

## Known bypasses

  * **A string literal that happens to contain the substring `http.ResponseWriter`** (e.g. a
    log message, an error string, or a doc comment string mentioning the type by name)
    satisfies the `http.ResponseWriter` cue exactly as a real parameter reference would,
    because comment-stripping does not mask string CONTENTS, only `//`/`/* */` comments. This
    is a genuine false-positive direction, reproduced manually (see "Tests" above). Judged
    acceptable: the guard has no Go string-content-masking helper to draw on (unlike Python's
    `strip_python_strings`), building one for this single case was judged disproportionate to
    how rarely a real Go file's string literal contains that exact type name verbatim, and the
    pragma is the escape hatch for the rare case where it does.
  * **Blank (`_ "text/template"`) or dot (`. "text/template"`) imports** bind no identifier
    signal 2 can key a call-site regex on, so a construction chain reached through either form
    is invisible to signal 2. Signal 1 is unaffected (it only checks import PRESENCE, not
    identifier), so the common "single import, HTTP handler in the same file" case is still
    caught; only the narrower dual-import-plus-blank/dot-alias combination evades detection.
  * **Package-level (`var`) construction with no enclosing function** evades signal 2 entirely
    — `_enclosing_function_span` has nothing to scope to. Reproduced manually; judged low-risk
    since `http.ResponseWriter` is essentially always a per-request handler parameter in
    idiomatic Go, never a package-level variable, so this shape is unusual in real code. Signal
    1 still fires for the ordinary single-import case regardless.
  * **Aliasing `Must`/`New`/`Parse`/`Execute` through an intermediate wrapper function** (e.g.
    a local `renderText := func(name, src string) *texttemplate.Template { return
    texttemplate.Must(texttemplate.New(name).Parse(src)) }`, then `renderText(...).Execute(w,
    data)` elsewhere) breaks the direct-chain shape signal 2 matches. No data-flow analysis is
    attempted — this guard is regex + brace-matching, not a type-checker.
  * **Indirect construction across two files** — the `*template.Template` value built in one
    file and executed against `http.ResponseWriter` in another — is invisible to both signals,
    which scan one file at a time with no cross-file linking.
  * **A genuinely unbalanced brace inside a raw string** within the enclosing function (a raw
    string containing a stray `{` with no matching `}`, or vice versa) desyncs the brace
    counter, and `_enclosing_function_span` fails closed (returns `None`) rather than guessing
    a wrong span — a false negative, verified not to mis-scope or crash.

## What this guard does NOT prove

  * **That `html/template` alone is sufficient.** `html/template`'s auto-escaping is
    context-aware but not omniscient — `template.HTML`/`template.JS`/`template.URL`-typed
    values are trusted verbatim and bypass escaping by design; a value cast to one of those
    types from untrusted input reintroduces the exact same XSS this guard is trying to catch,
    using the CORRECT package. This guard has no signal for that (a separate, narrower check).
  * **That the `text/template` output actually reaches an HTML response.** The
    `http.ResponseWriter` cue is a strong correlation, not a certainty — a handler could
    legitimately set `Content-Type: text/plain` or `text/csv` and write non-HTML output
    through the same `ResponseWriter` type. The pragma exists precisely for this residual.
  * **That every field in the template is attacker-influenced.** The guard does not trace
    which specific fields passed to `.Execute()` originate from user/request/LLM input versus
    fixed server-side constants — it flags the PATTERN (unescaped template package + HTTP
    response surface), not a proven-tainted data flow. A template rendering only fully static,
    compile-time-constant data through `text/template` to an HTTP response is technically safe
    but still flagged; that is judged the right trade for a static, syntactic scanner.
  * **That a silent guard means the file has no XSS risk.** Every "Known bypasses" case above
    is a real evasion path a determined (or merely differently-styled) codebase can hit, and
    this guard covers exactly two shapes of one specific root cause (wrong template package
    chosen). It does not replace a broader XSS/output-encoding review of Go HTTP handlers.

# Citations

[1] agentsec checklist item `3b-go-template-html-escaping` (§3b)
[2] OWASP:A03
