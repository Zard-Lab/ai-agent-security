---
type: Guard
title: "svg-embedded-script"
description: "No embedded script / event handler / javascript: URI in an SVG file."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "svg-embedded-script"
checklist_section: ["3a"]
standards: ["OWASP:A03"]
---

# No embedded script / event handler / javascript: URI in an SVG file

_Author — 2026-07-12_

---

## The threat

SVG is XML, and the spec permits a `<script>` element and standard event-handler
attributes (`onload`, `onclick`, `onerror`, ...) inside it. Any code path that treats
an SVG as "just an image" — an avatar/logo upload, a generated-diagram asset, an
agent-skill icon bundled into a package — can end up serving attacker-controlled
JavaScript. A browser that renders the SVG inline (direct navigation, `<object>`/
`<embed>`, or an inline paste — `<img src="x.svg">` alone does NOT execute it, but
plenty of real code paths go through one of the ones that do) runs the script with
full access to the hosting page's cookies/DOM/storage: a classic stored-XSS vector
(CWE-79, OWASP:A03) hiding inside a file type most upload-validation logic never
inspects past the magic bytes / extension.

## Why this guard fits the stack

`content-type-magic-bytes` already validates that an uploaded file's declared
Content-Type matches its magic bytes — but a genuinely well-formed SVG file (correct
magic bytes, correct MIME type) can still carry an embedded script; magic-byte
validation cannot see that. This guard closes that specific gap by inspecting SVG
*content*, independent of upload plumbing — so it also catches a malicious SVG
checked into the repo directly (an agent-skill icon asset, a committed logo) without
needing an upload path to exist at all, which is why it applies universally rather
than being gated on a stack feature.

## Detection design

1. **`applies()` gate** — always `True` (mirrors `invisible-unicode`): whether an SVG
   can carry a live script is a property of the file, not of the detected stack.
2. **Files scanned** — every `.svg` file under the repo (`iter_files(root, (".svg",))`),
   read as UTF-8 text with `errors="ignore"`; non-product paths (test fixtures) are
   skipped via `is_nonproduct_path`.
3. **Patterns** — three independent literal markers, each its own rule:
   - `script-element`: `<script` followed by whitespace or `>`.
   - `event-handler-attribute`: an `on<word>=` attribute (`onload=`, `onclick=`, ...).
   - `javascript-uri`: a `javascript:` scheme inside an `href`/`xlink:href` value.
   Each rule fires at most once per file (first match), on the line the marker starts.
4. **Pragma** — `security: allow-svg-embedded-script` anywhere in the file (an HTML
   comment works: `<!-- security: allow-svg-embedded-script -->`) silences the whole
   file, checked before any rule runs. It is a raw-text match: SVG is XML and has a comment
   syntax, but there is no XML comment view yet (#1040 T5), so the phrase in an attribute
   value or a text node also suppresses.
5. **Severity / standards** — all three rules are HIGH,
   `svg-embedded-script/{script-element,event-handler-attribute,javascript-uri}`,
   `OWASP:A03` (checklist item also carries `CWE-79`).

## When NOT to flag

- A plain, static SVG with no `<script>`, no `on*=` attribute, and no `javascript:`
  URI — the overwhelming majority of real SVG assets — stays silent.
- A non-`.svg` file that happens to contain SVG-like markup (a `.html`/`.jsx` file
  embedding an inline `<svg>`) is out of scope for this guard; DOM/JSX-facing script
  injection there is covered by `dom-xss-sinks`/`frontend-xss` instead.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_script_element` | a `<script>` element fires `script-element`, HIGH |
| `test_fires_on_event_handler_attribute` | an `onload=` attribute fires `event-handler-attribute` |
| `test_fires_on_javascript_uri` | a `javascript:` `xlink:href` fires `javascript-uri` |
| `test_passes_plain_svg` | an ordinary static shape SVG stays silent |
| `test_passes_non_svg_file` | the same markup in a non-`.svg` file is out of scope |
| `test_pragma_opt_out` | the file-wide pragma silences all three rules |
| `test_passes_href_without_javascript_scheme` | a normal `https://` `xlink:href` stays silent |

## Known bypasses

- Splitting `<script` across lines/whitespace in a way the literal pattern doesn't
  anticipate (e.g. `<script\n>`), or using a non-standard-but-still-executed variant a
  particular renderer accepts, evades the `script-element` rule.
- Encoding the payload (HTML entities, `&#x6a;avascript:`, mixed case beyond what
  `re.IGNORECASE` covers) can evade all three literal matchers.
- An event handler attribute name outside the fixed `on[a-z]+=` shape (unlikely in
  practice — the HTML/SVG event-handler vocabulary is `on`-prefixed by spec) would
  not match.

## What this guard does NOT prove

A silent result does not prove an SVG is safe to render inline — it only means none
of these three specific literal markers were found. It does not parse the SVG as XML
(so it cannot catch structurally obfuscated or CDATA-wrapped variants a real XML
parser would normalize), does not follow external references (`<use href="...">` to
another malicious SVG), and says nothing about how/whether the application actually
serves the file (inline vs. `Content-Disposition: attachment`, CSP) — the actual
exploitability depends on that serving context, which this guard cannot see.

# Citations

[1] agentsec checklist item `3a-svg-embedded-script` (§3a)
[2] OWASP:A03
