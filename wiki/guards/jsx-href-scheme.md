---
type: Guard
title: "jsx-href-scheme"
description: "JSX href/action set to unsanitized dynamic URL (javascript: XSS)."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "jsx-href-scheme"
checklist_section: ["6a"]
standards: ["OWASP:A03"]
---

# JSX href/action set to unsanitized dynamic URL (javascript: XSS)

## Threat

React JSX allows dynamic expressions in HTML attributes via curly-brace syntax:
`<a href={userUrl}>`. If `userUrl` is attacker-controlled, the value can be a
`javascript:` URL. When the user clicks the link (or the browser processes `src`/`action`),
the browser executes the embedded JavaScript in the page's origin context — full access
to cookies, DOM, and storage. This is a classic Stored or Reflected XSS vector (CWE-79).

React protects against static string literal `javascript:` props at render time, but
dynamic expressions (variables, function calls, template expressions) bypass this
protection entirely. The fix is a scheme allowlist check or a dedicated URL sanitizer
before the value reaches the attribute.

## Detection design

Scans all `.jsx` and `.tsx` files. On each line, the guard looks for:

1. A JSX attribute pattern `href={` or `action={` where the opening brace is **not** followed by
   a string literal starting with `http(s)://` or `/`, and **not** followed by a JSX element.
   (`src={` is deliberately excluded: a `javascript:` URL does not execute in `src`, and image
   `src` was the dominant false positive.)

2. The ±3 lines around it do **not** already contain one of the safe-scheme guards
   (listed below).

Both count only when they are **live code** (#1055): the attribute's `{` and each code-shaped
guard's first character are tested with `js_code_matches` on the shared anchor mask
(`strip_js_comments(text, strip_strings=True, keep_substitutions=True)`), so an `href={...}`
spelled out in a docs string does not fire, a `log("TODO sanitize")` does not clear a real sink,
and either one inside a `${...}` substitution still counts. Every attribute on a line is tried,
and each is judged on its own brace value, so a constant first attribute does not hide a dynamic
one after it.

Regex (anchored to the attribute opening):

```python
_DYNAMIC_URL_ATTR = re.compile(
    r"\b(?:href|action)=\{(?!\s*['\"`](?:https?://|/))(?!\s*\(?\s*<)",
    re.IGNORECASE,
)
```

The first negative lookahead `(?!\s*['\"`](?:https?://|/))` prevents the regex from firing when the
expression is a quoted or backtick string literal opening with a safe scheme — those are not
dynamic and are not a threat. The second lookahead `(?!\s*\(?\s*<)` excludes a value that is a
**JSX element or fragment** (`action={<Button/>}`, `href={<>…</>}`), including one wrapped in a
single paren (`action={(<Button/>)}`, the idiomatic Prettier formatting for a multi-line JSX
value): a ReactNode is never a URL string, so no `javascript:` scheme can flow through it (issue
#806). This is a **value-shape** signal, not an element-casing one — a wrapper component that
forwards a URL *variable* to a real anchor (`<NavLink href={userUrl}>`, `<Link href={url}>`), and a
parenthesized *variable* (`href={(userUrl)}`), open with an identifier char rather than `<` and
still fire, so no real sink is silenced.

Safe-guard signals checked in the ±3-line window (any one of these silences the finding):
- code-shaped, live code only (#1055): `startsWith`, `sanitiz…`, `encodeURI`, `new URL(`,
  `.test(`, `isValid…`, `allowlist`, `safeUrl`/`safeHref`/`safeLink`
- a literal `http(s)://` (or a regex's escaped `https:\/\/`). Not anchored: it only ever
  matches inside a string, template or regex body, so anchoring it would drop every hit

One finding per line; pragma silences the whole file.

## Severity rationale

**HIGH.** Successful exploitation is a one-click XSS in the user's browser session with
no server interaction required. The attack surface is any user-controlled string
(API response field, URL param, stored value) passed to `href`/`src`/`action`. Severity
would be CRITICAL if the component renders admin pages or serves privileged users, but
HIGH is the baseline because exploitability is context-dependent.

## Known bypasses / false negatives

| Bypass | Why not caught | Mitigation |
|---|---|---|
| Multi-line JSX attribute (`href={\n  userUrl\n}`) | Guard is line-level; opening brace on line 1 has no value to inspect | Manual review; dataflow analysis |
| URL pre-validated in a parent component or utility function | Guard cannot trace dataflow across function boundaries | Code review; type-safe URL wrapper type |
| Dynamic value composed via template literal (`href={\`/path/${id}\`}`) | Backtick template opens with `/` character inside braces — negative lookahead fires for `'` and `"` only, not backticks | A template starting with `/` is safe; one starting with `${` is a gap — future rule extension |
| Indirect variable assignment (`const url = userInput; <a href={url}>`) | Value flows from a variable; guard sees `href={url}` with no scheme check on that line — this IS caught | N/A (true positive) |
| Wrapped in a custom hook that validates internally | Guard cannot see inside the hook | Suppress with pragma after confirming the hook is safe |
| Guard spelled out in a string (`log("TODO sanitize")`) | Fixed (#1055): code-shaped guards count only as live code. Two literal-tolerant residuals remain: any `http(s)://` literal in the window still clears the finding (it is a literal credit by nature), and JSX text is not a string to the lexer, so `<p>Please sanitize links</p>` still credits. Residual: the anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads as template text and an anchor there is not code (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). A guard there is missed, which errs toward firing; a sink there is missed | Pragma for an audited case |
| JSX element behind a ternary (`action={cond ? <A/> : <B/>}`) or double-parenthesized (`{((<X/>))}`) | The `(?!\s*\(?\s*<)` exclusion inspects only the char after `{` (plus one optional wrapping paren); a ternary opens with the condition and a double paren gets past the single `\(?`, so both still fire | Rare, and also ReactNodes not URLs — residual FPs left deliberately un-narrowed (chasing them risks over-narrowing); add pragma if one surfaces (issue #806) |

## False positive scenarios

| Scenario | Why it fires | Resolution |
|---|---|---|
| `<img src={require("./logo.png")} />` | `require(...)` is a dynamic expression; no scheme guard on line | Add to safe-guard list or use pragma |
| `<a href={routes.HOME}>` where `routes.HOME = "/"` | Variable — guard cannot resolve its value statically | Add `.startsWith("/")` check at usage site or add pragma |
| `<form action={`${API_BASE}/submit`}>` where base is a constant | Backtick template without quoted prefix | If value is always safe, add pragma |
| `<a href={sanitizeUrl(userUrl)}>` | Contains `sanitize` keyword — this is **correctly silenced** | N/A (not a FP) |
| `<Foo action={<Bar/>}>` / `<ComingSoon action={(<Button/>)} />` | `action`/`href` is an author-defined prop on a custom component, valued with a JSX element (ReactNode), bare or single-paren-wrapped — the `(?!\s*\(?\s*<)` lookahead now **correctly silences** it (issue #806) | N/A (not a FP) |

### Safe-const recognition and parameter shadowing

A module-level `const NAME = "literal"` marks `NAME` as safe wherever it is used in that file.
Two refinements bound that, both added while closing real findings:

- **Shadowing.** If the enclosing function or component binds the same name as a parameter, the
  outer const is not what flows into the usage, so the value is treated as caller-controlled and
  still fires. Function declarations and arrow components are both covered, concise-body and
  block-body alike. A destructured parameter shadows via every name it genuinely binds: a plain
  key (`{ homeLink }`), a rename (`{ src: homeLink }` binds `homeLink`, not `src`), a rest element
  (`{ ...homeLink }`), and a nested pattern (`{ a: { homeLink } }`) at any depth.
- **Type annotations are not bindings.** Only the binding half of each parameter is scanned, so an
  inline TypeScript type literal does not count as shadowing:
  `const C = (props: { homeLink: string }) => <a href={homeLink}>` keeps `homeLink` safe, because
  that name is a property *type* and the only binding is `props`. A name appearing in **both**
  halves, `({ homeLink }: { homeLink: string })`, is a real binding and still fires.

**Known gap:** a single unparenthesized arrow parameter (`const C = homeLink => …`) is not scanned
for shadowing, so a prop of that shape is still treated as the safe const. Parenthesize it, or add
a pragma, if that pattern appears in your codebase.

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| `6a-jsx-url-scheme-xss` | `open` | `covered` | Guard detects dynamic href/src/action without scheme validation in JSX/TSX files, with pragma opt-out |

## Tests

| Test | Validates |
|---|---|
| `test_jsx_href_scheme_flags_href_var` | True positive: `<a href={userUrl}>` fires one HIGH finding |
| `test_jsx_href_scheme_flags_href_not_img_src` | Scope: `<a href={...}>` fires but `<img src={...}>` does not (src excluded) |
| `test_jsx_href_scheme_flags_action_var` | True positive: `<form action={redirectUrl}>` fires one HIGH finding |
| `test_jsx_href_scheme_silent_static_href` | False positive guard: static `href="/static/page"` stays silent |
| `test_jsx_href_scheme_silent_https_href` | False positive guard: static `href="https://example.com"` stays silent |
| `test_jsx_href_scheme_silent_sanitize` | False positive guard: `href={sanitizeUrl(userUrl)}` stays silent |
| `test_jsx_href_scheme_pragma_silences` | Pragma: file with pragma does not produce findings |
| `test_jsx_href_scheme_not_applies_no_frontend` | Feature gate: guard skips when profile has no `frontend`/`react` feature |
| `test_jsx_href_scheme_silent_jsx_element_action_prop` | FP guard (#806): `<ComingSoon action={<Button/>} />` (JSX-element value) stays silent |
| `test_jsx_href_scheme_silent_jsx_element_fragment_value` | FP guard (#806): a fragment value `{<>…</>}` stays silent |
| `test_jsx_href_scheme_silent_parenthesized_jsx_value` | FP guard (#806/#814): a single-paren-wrapped JSX value `{(<Button/>)}` stays silent |
| `test_jsx_href_scheme_still_fires_wrapper_component_href_var` | Rule 1: a wrapper component forwarding a URL variable (`<NavLink href={userUrl}>`) still fires |
| `test_jsx_href_scheme_still_fires_parenthesized_url_var` | Rule 1: a parenthesized URL variable `href={(userUrl)}` still fires |
| `test_jsx_href_scheme_quoted_guard_no_longer_clears_the_finding` | #1055: a guard word in a log string or template text no longer silences a real sink |
| `test_jsx_href_scheme_real_guard_or_https_literal_still_clears_the_finding` | #1055: a real guard still silences, including one nested in a `${...}` and one after a quoted copy; the unanchored `https://` literal credit still works |
| `test_jsx_href_scheme_sink_spelled_in_a_string_does_not_fire` | #1055: an `href={...}`/`action={...}` in a string or template text stays silent |
| `test_jsx_href_scheme_real_sink_nested_or_after_another_attribute_still_fires` | #1055: a real attribute fires inside a `${...}`, after a quoted copy, and after a constant first attribute |
| `test_jsx_href_scheme_two_constant_attributes_on_one_line_stay_silent` | #1055 FP bait: each attribute is judged on its own value |
| `test_jsx_href_scheme_pragma_still_suppresses_a_code_anchored_sink` | #1055: the pragma still silences a code-anchored sink |

# Citations

[1] agentsec checklist item `6a-jsx-url-scheme-xss` (§6a)
[2] OWASP:A03
