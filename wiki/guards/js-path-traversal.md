---
type: Guard
title: "js-path-traversal"
description: "No path traversal in JS/Node fs calls."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "js-path-traversal"
checklist_section: ["3a"]
standards: ["OWASP:A01"]
---

# No path traversal in JS/Node fs calls

_Author — 2026-07-15_

---

## The threat

A Node `fs` call (`fs.readFile`, `fs.writeFileSync`, `fs.createReadStream`, `fs.unlink`, etc.)
whose path argument is assembled — via template-literal interpolation or `+` string
concatenation — from request-derived data (`req.`/`request.`/`params.`/`query.`/`body.`) lets an
attacker supply a value like `../../etc/passwd` to escape the intended directory. On a read sink
this is arbitrary file disclosure (secrets, source, `.env`); on a write/unlink sink it's
arbitrary file plant or destroy. Reachable by any unauthenticated or authenticated caller who
controls the tainted field — a normal request parameter, no special privilege needed.
CWE-22, OWASP:A01 (Broken Access Control).

## Why this guard fits the stack

`ai-agent-mastery`-shaped apps increasingly ship a Node/Express sidecar (webhook receivers, file
upload/download endpoints, static-asset proxies) alongside the FastAPI backend. Before this guard,
agentsec had a Python-only `path-traversal` guard — zero coverage existed for the identical bug
class on the JS/Node side. The bad pattern is the direct JS analogue of the Python one:

```js
app.get("/download/:filename", (req, res) => {
  fs.readFile(`./uploads/${req.params.filename}`, (err, data) => res.send(data));
});
```

## Detection design

1. **`applies()` gate** — `"javascript" in profile.features or "typescript" in profile.features`
   (same convention as every other JS-scoped guard, e.g. `js_system_prompt_injection.py`,
   `js_client_side_open_redirect.py`).
2. **Files scanned** — `.js`/`.jsx`/`.ts`/`.tsx` via `iter_files`, skipping non-product paths
   (`is_nonproduct_path`, honoring `profile.archive_segments`).
3. **Sink detection** — `fs.<method>(` or `fs.promises.<method>(` for the core Node `fs`
   read/write/stream/rename/delete calls (CodeQL's `FsPathSink` core set, sourced from
   `javascript/ql/src/Security/CWE-022/TaintedPath.ql` + `TaintedPathCustomizations.qll`,
   verified against real fetched source): `readFile[Sync]`, `writeFile[Sync]`,
   `appendFile[Sync]`, `createReadStream`, `createWriteStream`, `unlink[Sync]`, `open[Sync]`,
   `copyFile[Sync]`, `rename[Sync]`, `mkdir[Sync]`, `rmdir[Sync]`, `access[Sync]`, `stat[Sync]`,
   `readdir[Sync]`. Deliberately scoped to this core set only — CodeQL's own query also covers
   `ExpressRenderSink`/`ResolveModuleSink`/headless-browser/prettier sinks, which need more
   context (module resolution, template-engine config) than a regex window can safely capture
   without a real dataflow engine; those are out of scope for this guard.
   `realpath[Sync]` is deliberately **excluded** from the sink list — it's the sanitizing call,
   not a sink.
4. **Taint + assembly check** — the sink's first argument (extracted via a balanced-bracket
   scan, `_first_arg`, same technique as the Python `path_traversal.py`'s helper of the same
   name) must both (a) reference request-derived data (`req.`/`request.`/`params.`/`query.`/
   `body.`) and (b) be *assembled* rather than passed through bare (the sink call's `(` must be
   live code on the anchor mask, #1055, and every live `fs` call on the line is tried, so a
   quoted or static first call cannot hide a tainted one after it; the argument itself is read
   on the strings-intact view, where `${req.params.x}` lives): a template-literal
   interpolation (`` `${req.params.x}` ``) or a `+` concatenation with a string literal on one
   side (`"..." + req.query.x`). A bare reference (`fs.readFile(req.query.path, cb)`) does NOT
   fire — mirrors the Python guard's bare-`open(var)` carve-out (too common/imprecise a signal
   alone).
5. **Safe-pattern-nearby exclusion** — a window of **+/-5 lines** around the sink line is
   checked for a JS containment/normalization marker: `path.resolve(`, `path.normalize(`,
   `path.isAbsolute(`, `path.relative(`, or a separator-boundary-aware `.startsWith(`
   (see the 2026-09-21 update below). If any is present in the window, the finding is
   suppressed. This is wider than the Python `path-traversal` guard's same-line-only `_SAFE`
   check, because JS code idiomatically resolves/validates a path in its own statement a few
   lines away from the sink call, not inline in the call's arguments.

   **2026-09-21 update (fix):** a bare `.startsWith(base)` with no trailing separator
   used to silence the guard unconditionally — but that is exactly the "prefix-match bypass"
   that made Anthropic's own official Filesystem MCP Server exploitable
   (`"/private/tmp/allowed_dir_evil".startsWith("/private/tmp/allowed_dir")` is `true`,
   CVE-2025-53109/53110, "EscapeRoute"). `.startsWith(` now only counts as a marker when its
   own argument shows separator-boundary evidence: `path.sep`, or a literal slash/backslash
   adjacent to a quote/backtick (`base + path.sep`, `base + '/'`, `` `${base}/` ``). A second
   marker, `path.relative(` (between base and target), was added — ported from `sentrymcp`'s
   own `MCPA-PATH-JS-001`/`MCPA-PATH-TS-001` safe_indicators.

   **2026-09-23 update (Dean's review fix):** `path.relative(`'s mere PRESENCE in
   the window is not unconditionally safe after all — nothing stops its result from being
   computed and never examined (`console.log(path.relative(...))` satisfied the marker while
   the sink stayed completely unguarded). It now requires BOTH the call AND a recognized
   escape check on a result somewhere in the same window: `.startsWith('..')`, `.includes('..')`,
   or (2026-09-24, round 2) the split-and-compare idiom `.split(path.sep)[0] === '..'` /
   `!== '..'`. The escape check is not required to be on the SAME `path.relative()` call's
   result, or even the same line — see Known bypasses.

   **#1055 (live code only):** every marker counts only when it is live code, tested with
   `js_code_matches` on the shared anchor mask (`strip_js_comments(text, strip_strings=True,
   keep_substitutions=True)`). The tested character is the marker call's `(`, or the leading `.`
   of a `path.relative()` escape check; the `'/'`, `'..'` and `path.sep` evidence the markers
   compare against is still read on the strings-intact line, where it lives. A marker spelled
   out in a log or error string no longer silences the sink, and a real one inside a `${...}`
   substitution still does.
6. **Suppress pragma** — `// security: allow-js-path-traversal` (checked on the comment-only view, #424,
   both file-wide and per-line — same convention as every other JS guard's `_PRAGMA` handling).
7. **Whole-line `//` comments are blanked** before scanning (line count preserved) so a comment
   merely mentioning the pattern doesn't fire — same convention as
   `js_system_prompt_injection.py` / `js_client_side_open_redirect.py`.
8. **Severity / rule / standards** — fires **HIGH**, `rule = "js-path-traversal/tainted-fs-path"`,
   `standards = ["OWASP:A01", "CWE-22"]`.

## When NOT to flag

- **Fully static path** — `fs.readFile("./config/app.json", cb)` — no tainted reference, silent.
- **Bare tainted reference, no assembly** — `fs.readFile(req.query.path, cb)` — the path is
  passed straight through with no string-building step for the guard to key off; flagging every
  bare reference to `req.*` reaching an `fs` call would be extremely noisy (many apps pass an
  already-validated/allow-listed identifier this way). Silent by design — same trade-off the
  Python guard makes for `open(var)`.
- **A `path.resolve`/`path.normalize`/`path.isAbsolute` call, a separator-boundary-aware
  `.startsWith` containment check, or a `path.relative()` call PLUS a recognized escape check
  on its result, within 5 lines of the sink** — treated as guarded, silent. `.startsWith(` no
  longer silences unconditionally (see the 2026-09-21 the fix above): it must show
  separator-boundary evidence in its own argument to count. `path.relative(` no longer
  silences on mere presence either (see the 2026-09-23 the fix above): it needs a
  `.startsWith('..')`/`.includes('..')`/`.split(path.sep)[0] === '..'` check on a result
  somewhere in the window.
- An audited case → `// security: allow-js-path-traversal`.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_template_literal_interpolation` | `` fs.readFile(`./uploads/${req.params.filename}`, cb) `` fires HIGH |
| `test_flags_concatenation` | `fs.createReadStream("/data/" + req.query.path)` fires |
| `test_flags_write_sink` | `fs.writeFileSync` with a tainted template literal fires |
| `test_silent_with_nearby_path_resolve_check` | a `path.resolve`/`.startsWith` containment check 2 lines above the sink silences it |
| `test_silent_with_nearby_normalize_check` | a `path.normalize` check 1 line after the sink silences it |
| `test_silent_on_fully_static_path` | `fs.readFile("./config/app.json", cb)` stays silent |
| `test_silent_on_bare_tainted_reference` | `fs.readFile(req.query.path, cb)` (no assembly) stays silent |
| `test_silent_on_comment_mentioning_pattern` | a `//` comment showing the bad pattern doesn't fire |
| `test_pragma_suppresses` | `// security: allow-js-path-traversal` silences an otherwise-firing line |
| `test_not_applies_without_js_or_ts` | `applies()` is false with neither feature present |
| `test_applies_with_typescript_only` | `applies()` is true on `typescript` alone (no `javascript` needed) |
| `test_nonproduct_path_skipped` | a finding under a non-product dir (e.g. `examples/`) is dropped |
| `test_naive_startswith_with_no_separator_now_still_fires` | a bare `.startsWith(base)` with no separator no longer silences the guard — fires |
| `test_startswith_with_path_sep_separator_stays_silent` | `.startsWith(baseDir + path.sep)` — real separator-aware check — stays silent |
| `test_startswith_with_literal_slash_separator_stays_silent` | `.startsWith(baseDir + '/')` — literal separator — stays silent |
| `test_startswith_with_template_literal_trailing_slash_stays_silent` | `` .startsWith(`${baseDir}/`) `` — stays silent |
| `test_startswith_nested_call_argument_evidence_still_recognized` | `.startsWith(getBaseDir() + path.sep)` — nested-call argument, real `matching_close_paren` end — stays silent |
| `test_path_relative_check_stays_silent` | `path.relative(base, target).startsWith('..')` PLUS the escape check — stays silent |
| `test_path_relative_merely_logged_still_fires` | `path.relative(...)` merely `console.log`'d, no escape check anywhere — fires |
| `test_path_relative_includes_check_stays_silent` | `path.relative(...).includes('..')` — equally valid escape check — stays silent |
| `test_path_relative_split_sep_check_stays_silent` | (round 2) `path.relative(...).split(path.sep)[0] === '..'` — stays silent |
| `test_path_relative_split_sep_inverse_check_stays_silent` | (round 2) the `!== '..'` inverse form — stays silent |
| `test_path_relative_split_wrong_index_still_fires` | (round 2) `.split(path.sep)[1] === '..'` — wrong index, not a real check — fires |
| `test_quoted_containment_marker_no_longer_clears_the_finding` | (#1055) a marker spelled out in a log string or template text (`path.resolve(`, `path.normalize(`, separator-aware `.startsWith(`, `path.relative(` and its escape check) no longer silences the sink |
| `test_real_containment_marker_still_clears_the_finding` | (#1055) a real marker still silences it, including one nested in a `${...}` and one after a quoted copy on the same line |
| `test_fs_sink_spelled_in_a_string_does_not_fire` | (#1055) an `fs` call spelled out in a string or template text stays silent |
| `test_real_fs_sink_nested_or_after_another_call_still_fires` | (#1055) a real sink fires, including one nested in a `${...}` and one after a quoted or static call on the same line |
| `test_pragma_still_suppresses_a_code_anchored_sink` | (#1055) the per-line pragma still silences a code-anchored sink |

## Known bypasses

- **Assembly through an intermediate variable** — `const p = \`./uploads/${req.params.filename}\`;
  fs.readFile(p, cb);` evades detection: the guard has no dataflow engine, so it cannot connect
  `p`'s assembly to the sink call on a later line (same limitation `js_client_side_open_redirect.py`
  documents for its own single-line window).
- **Containment check further than 5 lines away, or in a shared helper function** — a
  `sanitizePath()` helper defined elsewhere and called by name (not matching the literal
  `path.resolve`/`path.normalize`/`path.isAbsolute`/`.startsWith` markers) is invisible to this
  guard and will still fire (false positive — the pragma covers it).
- **A separator-boundary-aware `.startsWith(` is still not a proven correctness check** — it
  only confirms a separator character appears somewhere in the argument text, not that the
  concatenation is well-formed at every boundary, or that the check is even about path
  containment at all (e.g. `x.startsWith(prefix + '/')` checking something unrelated to a
  file path would still silence a genuine finding in that arrangement) — narrower than the
  pre-fix "any `.startsWith(` at all" gap, but not eliminated.
- **The `path.relative()` escape check isn't tied to the SAME call** (Dean's review, round 2)
  — `_path_relative_is_checked` only requires a `path.relative(` call AND a recognized escape
  check to both appear somewhere in the ±5-line window, not that the check runs on that
  specific call's result. An unrelated `.startsWith('..')`/`.includes('..')` nearby also
  silences a real, unrelated sink. Not fixed: correlating the check to the specific call's
  result needs tracking which variable the call was assigned to, which this guard's window
  scan doesn't do.
- **JS/TS anchoring (#1055).** Marker text inside a string literal used to count as a marker
  (PR #920 review, round 3): `logger.info("hint: use path.resolve(base, p) here")`, a quoted
  separator-aware `.startsWith(`, or a quoted `.split(path.sep)[0] === '..'` silenced a real
  sink within 5 lines. Now the `fs` sink and every marker count only when their anchor (the
  call's `(`, or the escape check's leading `.`) is live code, tested with `js_code_matches` on
  the anchor mask. Blanking strings in the window was **not** the fix and is not what this
  does: the `'..'` and `'/'` evidence the markers rely on lives inside string literals (measured
  on the PR #920 shape matrix, blanking it turns 8 correct containment idioms into HIGH
  findings), so only the anchor is tested and the evidence is read on the strings-intact line.
  A sink spelled out in a docs string no longer fires, a real sink or marker nested in a
  `${...}` still counts, and every sink on a line is tried, so a quoted or static first call no
  longer hides a tainted one after it (a first-match shadowing FN before #1055). Residual: the
  anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one
  `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between
  the two reads as template text and an anchor there is not code (the accepted trade pinned by
  `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). A marker
  there is missed, which errs toward firing; a sink there is missed.
- **Non-`fs.*`-qualified imports** — `const { readFile } = require("fs"); readFile(tainted, cb);`
  (destructured import, called bare without the `fs.` prefix) is not matched — the sink regex
  requires the `fs.`/`fs.promises.` qualifier, mirroring how the design brief scoped the sink
  names.
- **Concatenation without an adjacent string literal** — `basePath + req.query.file` (two bare
  identifiers, no quote adjacent to the `+`) does not match `_CONCAT`; only a literal-adjacent
  `+` fires, matching the Python guard's identical `_CONCAT` trade-off.

## Known false positives

Each shape below is a **correct** containment check that still fires HIGH (measured in the
PR #920 review rounds). Suppress an audited one with `// security: allow-js-path-traversal`.

- **Separator evidence the `.startsWith(` argument scan cannot see.** The evidence must sit
  inside the call's own argument, on the same line, spelled `path.sep` or as a `/`/`\` before
  a closing quote. These idioms fail that: a destructured `sep`
  (`const { sep } = require('path')`, then `startsWith(baseDir + sep)`); `path.posix.sep` or
  `path.win32.sep`; a constant built on an earlier line
  (`const BASE_WITH_SEP = baseDir + path.sep;`, then `startsWith(BASE_WITH_SEP)`); a
  formatter-wrapped call whose argument continues on the next line; and the two-part check
  `t.startsWith(baseDir) && t[baseDir.length] === path.sep`. All of these were silent before
  the 2026-09-21 change, when any `.startsWith(` silenced the guard. They are the price of
  closing the EscapeRoute prefix-match bypass.
- **A template literal with a `)` inside the `.startsWith(` argument.**
  `` t.startsWith(`${baseDir}x)/`) `` fires: the shared `matching_close_paren` helper tracks
  `'` and `"` but not backticks, so the argument is cut at the inner `)` and the trailing `/`
  is never seen. Rare in practice (a variable holding the same text is fine).
- **`path.relative()` escape checks the regex does not recognize.** Only `.startsWith('..')`,
  `.includes('..')` and `.split(path.sep)[0] === '..'`/`!== '..'` count. Loose `==`/`!=`,
  `split('/')[0]`, `split(path.sep).shift()`, destructuring
  (`const [first] = rel.split(path.sep)`, then `first === '..'`) and `split(path.posix.sep)[0]`
  all still fire. These also fired before `path.relative(` became a marker at all.

## What this guard does NOT prove

It flags a `fs.*` call whose path argument is textually assembled from a request-derived
reference with no recognized containment marker nearby. It does not prove the referenced field
is actually attacker-reachable at runtime (a value could be revalidated upstream in middleware
not visible to this file), nor that a present `path.resolve`/`.startsWith` marker is *correctly*
implementing containment — a `.startsWith` check against the wrong base still silences the
finding even after the fix; only the *missing-separator* form of that imprecision was
closed, not every possible misuse. Absence of a finding does not mean the file is free of path
traversal.

## Checklist mapping — recommendation

This guard should **extend `3a-path-traversal-file-serving`** (add `"javascript"`/`"typescript"`
to its `applies_when`, add `"js-path-traversal"` to its `check_ids`) rather than become a new
checklist item. It's the same requirement — CWE-22, OWASP:A01, "path traversal on file
serving/opening" — on a different language surface, the same relationship
`js-client-side-open-redirect` has to its server-side `open-redirect` sibling item. A new item
would fragment coverage reporting for what is, from the checklist's perspective, one requirement
audited across two stacks. (Not applied here — `checklist.json` is out of scope for this change
per the task boundary; left for the follow-up that's allowed to touch it.)

# Citations

[1] agentsec checklist item `3a-path-traversal-file-serving` (§3a)
[2] OWASP:A01
