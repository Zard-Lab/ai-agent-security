---
type: Guard
title: "js-xxe-unsafe-parsing"
description: "XML parsed with libxmljs noent:true (XXE)."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "js-xxe-unsafe-parsing"
checklist_section: ["3a"]
standards: ["OWASP-LLM:LLM03", "OWASP:A05"]
---

# XML parsed with libxmljs noent:true (XXE)

_Author — 2026-08-09_

---

## The threat

An attacker who can supply an XML document that a JS/TS backend parses — a file upload, an API
body, a webhook payload, an imported feed — can smuggle a `DOCTYPE`/entity declaration into it.
If the parser has external-entity expansion enabled, that entity can read arbitrary local files
(`file:///etc/passwd`), reach internal-only network endpoints the app itself can reach (SSRF), or
recursively self-reference to exhaust memory (the "billion laughs" DoS). This is the classic XXE
chain: unauthenticated in, RCE/SSRF/file-disclosure out. Standard: `OWASP:A05` (Security
Misconfiguration), `OWASP-LLM:LLM03` (Supply Chain — an ingested document/tool-output feed is a
common untrusted-XML entry point in an agent stack), `CWE-611`.

The `libxmljs` npm package — the dominant native XML parser in the Node ecosystem (`libxml2`
bindings) — ships with entity expansion **off** by default. The single documented way to turn it
back on is the `noent: true` option to `parseXml`/`parseXmlString`, per GitHub CodeQL's own
`javascript/ql/src/Security/CWE-611/Xxe.ql` rule (the canonical, extensively real-world-observed
JS XXE trigger this guard is sourced from).

## Why it's often introduced

`noent: true` is copy-pasted from libxmljs documentation/Stack Overflow examples that need entity
expansion for a legitimate, TRUSTED-input use case (resolving `&amp;`-style internal entities in
a hand-authored config XML, say) — and the option then ships unchanged when the same parsing code
is later pointed at a user-supplied upload or an external feed:

```js
const libxml = require("libxmljs");
let doc = libxml.parseXml(xmlSrc, { noent: true });   // VULNERABLE if xmlSrc is untrusted
```

vs the safe default:

```js
let doc = libxml.parseXml(xmlSrc);                    // safe — noent defaults to false
```

## Detection design

1. **`applies()` gate** — `"javascript" in profile.features or "typescript" in profile.features`.
   This is the JS/TS extension of the existing `3a-xxe-safe-parsing` checklist item, whose
   `applies_when` today lists only `"python"` (covered by the sibling `xxe-safe` guard against
   `xml.etree`/`lxml`/`defusedxml` imports). Same checklist item, same underlying requirement
   (XML parsed safely), different language and therefore a structurally different detection
   mechanism — an explicit unsafe OPTION rather than an unsafe IMPORT.
2. **Files scanned** — every `.js`/`.jsx`/`.ts`/`.tsx` file under the repo (`iter_files`), same as
   the other JS guards (`js_cors_wildcard.py`, `js_helmet_header_disabled.py`).
3. **Pattern / parse logic** — `strip_js_comments` blanks comments first (so a commented-out
   example can't fire), then for every `parseXml(`/`parseXmlString(` call site (method-call form
   `libxml.parseXml(` or a bare destructured-import form `parseXml(`):
   - the call's full argument list is captured via balanced-paren counting
     (`_call_args_span`) — a whole-call-span scan, not a same-line regex, so a Prettier-formatted
     multi-line options object is seen as one blob (mirrors `js_cors_wildcard.py`'s
     `_cors_config_object` bracket-counting helper and its documented reasoning);
   - the arguments are split at the first TOP-LEVEL comma (`_first_top_level_comma`) to isolate
     everything after the XML-source argument — i.e. where an options object would sit — from
     the source argument itself;
   - `noent\s*:\s*true` (flexible on whitespace, so `noent:true` also matches) is searched for
     only within that isolated region. This is deliberately narrower than "anywhere in the file":
     it is what keeps an unrelated `const noent = true;` elsewhere in the file, or inside the
     call's first (XML-source) argument, from ever matching.
   - only live code counts (#1055). The call's `(` and the `n` of `noent` must be code on the
     shared anchor mask (`strip_js_comments(raw, strip_strings=True, keep_substitutions=True)`,
     tested through `js_code_matches`), which blanks string and template text but keeps `${...}`
     substitution code. A call or option spelled out in a docs or log string does not fire; a call
     nested in a `${...}` still does. Every match is tried, so a quoted copy cannot hide a real
     call or key after it. Both bracket walks (`_call_args_span`, `_first_top_level_comma`) count
     on that same mask, so a `)` or `,` inside a string argument is not structure: before #1055,
     `parseXml(src.replace(')', ''), { noent: true })` ended the walk at the quoted `)` and the
     CRITICAL went silent.
4. **Pragma** — `// security: allow-js-xxe`, checked on the COMMENT-ONLY view of the source line
   the matched `noent: true` resolves to (#424), same convention as the sibling JS guards.
5. **Severity / rule / standards** — fires **CRITICAL** (not the sibling Python guard's `medium`
   — XXE here is a direct RCE/SSRF/file-disclosure-class primitive, not a hardening gap) as
   `js-xxe-unsafe-parsing/libxmljs-noent-true`, standards `["OWASP:A05", "OWASP-LLM:LLM03"]`
   (matching the Python sibling's list, since both guards feed the same checklist item).

## When NOT to flag

- `parseXml(xmlSrc)` with no options argument at all — libxmljs's default (`noent: false`)
  applies, so this is the safe case and must stay silent.
- `parseXml(xmlSrc, { noent: false })` — explicitly safe.
- A `noent: true` that appears only in a comment (documentation, a disabled example) — blanked
  by `strip_js_comments` before matching.
- A call, or a `noent: true`, that appears only inside a string or template text (an error
  message, a docs string, an option VALUE like `{ note: 'noent: true is unsafe' }`), because its anchor
  is not live code on the anchor mask (#1055).
- An unrelated identifier that happens to be named `noent` (a feature flag, a config field) that
  is never passed as an option to a `parseXml`/`parseXmlString` call — the region-scoped search
  (post-first-comma, within the call's own argument list) never sees it.
- A reviewed, intentionally-trusted-input case: suppress the specific line with
  `// security: allow-js-xxe`.

## Tests

| Test | What it checks |
|---|---|
| `test_js_xxe_flags_libxmljs_noent_true` | Planted violation: `parseXml(xmlSrc, { noent: true })` fires CRITICAL at the right line. |
| `test_js_xxe_silent_no_options_object` | FP-bait: `parseXml(xmlSrc)` with no options argument stays silent. |
| `test_js_xxe_silent_noent_false` | FP-bait: `parseXml(xmlSrc, { noent: false })` stays silent. |
| `test_js_xxe_silent_on_commented_pattern` | FP-bait: the pattern inside a `//` comment stays silent. |
| `test_js_xxe_pragma_silences` | A `// security: allow-js-xxe` comment silences a real `noent: true`. |
| `test_js_xxe_not_applies_without_feature` | `applies()` is false with neither `javascript` nor `typescript` in the profile. |
| `test_js_xxe_applies_for_typescript` | Fires identically on a `.ts` file under the `typescript` feature. |
| `test_js_xxe_flags_multiline_options_object` | Adversarial #1: a Prettier-formatted multi-line `{...}` with `noent: true` on its own line still fires. |
| `test_js_xxe_silent_unrelated_noent_variable` | Adversarial #2: an unrelated `const noent = true;` elsewhere in the file, never passed to `parseXml`, stays silent. |
| `test_js_xxe_paren_in_the_source_string_does_not_end_the_call` | #1055: a `)` inside a string argument no longer ends the call walk; the CRITICAL fires. |
| `test_js_xxe_comma_and_paren_in_the_source_string_do_not_split_the_args` | #1055: a `,(` inside the source argument's string no longer desyncs the first-comma walk. |
| `test_js_xxe_paren_in_a_template_source_does_not_end_the_call` | #1055: the same for a `)` in template text. |
| `test_js_xxe_call_inside_a_substitution_still_fires` | #1055 still-fires: a real call nested in `${...}` (plain `strip_strings=True` would lose it). |
| `test_js_xxe_call_spelled_in_a_string_is_silent` | #1055 FP-bait: the whole call in a string or template text stays silent. |
| `test_js_xxe_real_call_after_a_quoted_copy_on_the_line_still_fires` | #1055: a quoted copy first on the line does not shadow the real call. |
| `test_js_xxe_noent_spelled_in_an_option_value_is_silent` | #1055 FP-bait: `noent: true` only inside an option's string value stays silent. |
| `test_js_xxe_real_noent_after_a_quoted_copy_in_the_options_still_fires` | #1055: a quoted `noent: true` first in the options does not shadow the real key. |
| `test_js_xxe_pragma_still_suppresses_after_the_mask_walk` | Rule 4: the pragma still silences a finding only the mask walk can see. |
| `test_js_xxe_regex_literal_paren_is_a_known_limit` | Pinned residual: a `)` inside a regex-literal argument still ends the walk (silent). |

## Known bypasses

- **Variable/config indirection.** `const opts = { noent: true }; libxml.parseXml(xmlSrc, opts);`
  — the option is not a literal at the call site, so the region-scoped regex never sees it. This
  guard, like `xxe-safe.py`, is a same-file PRESENCE check, not taint/def-use tracking.
- **Dynamic/computed option keys.** `libxml.parseXml(xmlSrc, { [key]: true })` where `key`
  evaluates to `"noent"` at runtime is invisible to a static text match.
- **Aliased import indirection beyond the recognized call forms.** A re-exported or renamed
  wrapper around `libxmljs.parseXml` (e.g. `myParser.parse = libxml.parseXml; myParser.parse(x,
  {noent:true})`) is not recognized as a parse call, since detection is anchored on the literal
  `parseXml`/`parseXmlString` token.
- **Brackets inside a regex literal (#1055 residual, pinned).** The anchor mask blanks string
  content but keeps regex-literal bodies as code, so `parseXml(src.replace(/\)/g, ''), { noent:
  true })` still ends the call walk at the regex's `)` and stays silent, exactly as before #1055.
  `test_js_xxe_regex_literal_paren_is_a_known_limit` pins it.
- **Quoted option key.** `parseXml(src, { 'noent': true })` is valid JS and never matched
  `noent\s*:`, before or after #1055 (a separate FN).
- **Inherited anchor-mask limits.** A `{` inside a regex or comment in one `${...}` substitution,
  then a `}` in a later one, rebalances the frame, so code between the two reads as template text
  and a call there is not code (#543, pinned in `test_base.py` by
  `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). Where the
  stripper's parity cap restores a template verbatim, its content counts as code again and the
  walk is exactly the pre-#1055 walk there.
- **A `}`-vs-object-literal regex-vs-comment edge case** inherited from `strip_js_comments`
  itself (documented in `base.py`): a pathological same-line construct combining a block and a
  regex literal could, in principle, misalign comment-stripping on that one line. Not observed in
  practice against libxmljs's own call shape.

## What this guard does NOT prove

- **Scope is deliberately `libxmljs`'s `noent: true` only — not "safe XML parsing in
  JS/TS" in general.** The JS/TS XML-parsing ecosystem has several other popular packages, each
  with its own, DIFFERENT unsafe-option shape that this guard does not attempt to cover:
  `xml2js` (its own entity/processor options), `sax`/`sax-js` (streaming parser, different attack
  surface entirely), `fast-xml-parser` (its own `processEntities`/`allowBooleanAttributes`-style
  option set), and the browser/Node built-in `DOMParser` (no entity-expansion knob to begin with,
  but a different XXE-adjacent surface via external DTD fetches in some environments). This is a
  deliberate, stated precision-over-recall scoping choice — `libxmljs`'s `noent: true` is the
  single dominant, CodeQL-documented, real-world-observed trigger — not an oversight. Extending
  coverage to the other libraries is a natural, tracked future increment, each requiring its own
  guard (or its own detection branch) since the unsafe shapes don't share a common pattern.
- A silent result does not prove the file never parses untrusted XML unsafely by some OTHER
  mechanism (a different library, a shelled-out `xmllint --noent`, a native addon) — only that
  it doesn't do so via this one specific, dominant `libxmljs` option.
- Does not confirm the parsed XML source (`xmlSrc`) is actually attacker-reachable — like the
  Python sibling, this is a pattern-presence check, not a reachability/taint analysis. A
  `noent: true` on a parse call fed only trusted, build-time XML still fires (and should be
  suppressed with the pragma if reviewed as safe).

# Citations

[1] agentsec checklist item `3a-xxe-safe-parsing` (§3a)
[2] OWASP-LLM:LLM03
[3] OWASP:A05
