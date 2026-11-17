---
type: Guard
title: "js-private-file-exposure"
description: "Static-file-serving middleware configured to serve a private directory."
timestamp: "2026-08-09T11:26:13+08:00"
guard_id: "js-private-file-exposure"
checklist_section: ["3a"]
standards: ["CWE-200", "OWASP:A01"]
---

# Static-file-serving middleware configured to serve a private directory

_Author — 2026-08-09_

---

## The threat

Express/connect/`serve-static`/`serve-handler` static-file-serving middleware hands a whole
filesystem directory to any unauthenticated HTTP client with no further access control — anyone
who can reach the server's port can `GET` any file underneath the configured directory. When that
directory is `node_modules`, the project's own source root (`__dirname`), the user's home
directory, or the filesystem root/cwd, the exposure includes `.env` files, `.git` internals,
private dependency source, SSH keys, and application source code. This is CWE-200 (Exposure of
Sensitive Information to an Unauthorized Actor), OWASP:A01 (Broken Access Control) — the access
control failure here is architectural (the server was configured to serve the wrong directory),
not a bypass of an existing control.

Unlike most of this guard's siblings, no request input is involved: the bug is entirely present
in the static middleware CONFIGURATION, at the moment the code runs, independent of anything a
client sends. It requires zero exploitation skill — a single unauthenticated `curl` request finds
whatever the misconfigured directory contains.

## Why it's often introduced

`express.static(__dirname)` is a very natural first thing to type — `__dirname` is *right there*,
and in a tutorial-sized app "serve everything in this folder" looks harmless until the folder also
holds `.env`, `node_modules`, or a `.git` directory. `path.join(__dirname, 'node_modules')` shows
up from debugging ("why won't the browser find this package") or from a build script that never
got cleaned up. `os.homedir()` and a bare `'/'` are rarer but appear in ad hoc local dev tools and
copy-pasted `serve-handler`/`http-server` snippets that were never meant to leave a laptop.

```js
// The whole project root becomes public — .env, .git, and source all download-able
app.use(express.static(__dirname));

// node_modules becomes public — dependency source, install scripts, embedded secrets
app.use(express.static(path.join(__dirname, 'node_modules')));

// serve-handler's `public` OPTION, not a positional argument
require('serve-handler')(req, res, { public: os.homedir() });
```

## Detection design

1. `applies()` gates on `"express" in profile.features`. This is narrower than the broader
   `javascript`/`typescript` gate some sibling guards use (`serve-static`/`serve-handler` are
   technically usable outside Express). Chosen deliberately: the three detected entry points
   (`express.static`/`connect.static`, `serve-static`, `serve-handler`) are overwhelmingly used
   inside an Express (or Express-like connect) app in agentsec's target stack, and gating on
   `express` avoids adding noise to a frontend-only React/TS repo that has neither package.
2. Files scanned: `iter_files(root, (".js", ".jsx", ".ts", ".tsx"))` — the shared JS/TS walk,
   honoring the vendored/build/worktree excludes.
3. Patterns / logic (all via `strip_js_comments`-cleaned text, so a commented-out example never
   fires):
   - `_STATIC_CALL` — `\b(?:express|connect)\.static\s*\(` — matched call's first positional
     argument (via `split_call_args`, balanced-paren aware) is classified.
   - `_SERVE_STATIC_CALL` — `require(...)('serve-static')(...)`, same first-argument
     classification.
   - `_SERVE_HANDLER_CALL` — `require(...)('serve-handler')(...)`; the call's full argument text
     is searched for a `public: <value>` key (`_extract_public_option`, a balanced-depth scan
     stopping at the first top-level comma/closer so a value like `path.join(a, b)` isn't cut at
     its own internal comma), and that value is classified instead of a positional argument.
   - Classification (`_classify_arg`): the trimmed argument expression is checked, in order, for
     (a) being exactly `__dirname` or a same-file alias of it (see below) → `dirname`; (b)
     containing `os.homedir()` anywhere → `homedir`; (c) containing a quoted string literal that
     is or contains `node_modules` anywhere → `node_modules`; (d) being exactly the literal `'/'`,
     `'.'`, or `'./'` → `root_or_cwd`. Anything else → not classified, no finding.
   - Same-file `__dirname` alias tracking: `_DIRNAME_ALIAS` (`const/let/var X = __dirname;`)
     collects identifiers assigned straight from `__dirname` in the same file, so
     `const root = __dirname; app.use(express.static(root));` still classifies as `dirname`. This
     is the ONE indirection hop this guard follows — see Known Bypasses for what is not tracked.
4. Inline opt-out pragma: `// security: allow-js-private-file-exposure`, checked against the
   COMMENT-ONLY view of the source line the finding is anchored to (#424; not a file-wide skip — a pragma on one call must not
   silence an unrelated call elsewhere in the same file).
5. Severity: HIGH for every shape (no softer tier — see "no security-context gate" below). Rule
   ids are per-reason: `js-private-file-exposure/dirname`, `.../node_modules`, `.../homedir`,
   `.../root_or_cwd`. Standards: `["OWASP:A01", "CWE-200"]`.

This guard applies **no security-context gate** and needs none: legitimate static-file serving
always points at a small, purpose-built subdirectory (`public/`, `assets/`, `static/`, `dist/`)
— never at `node_modules`, the bare source root, the home directory, or the filesystem root. The
five dangerous shapes above have no legitimate reading; wherever the pattern appears, it is the
bug (same precision philosophy as other single-shape structural misconfig guards — the pattern
itself IS the bug, no further context needed to know it's wrong).

## When NOT to flag

- `express.static('public')`, `express.static(path.join(__dirname, 'public'))`, or any other
  dedicated subdirectory name — the overwhelmingly normal case, and silent by design (the argument
  classifies as none of the four dangerous shapes).
- A route/mount PATH that happens to contain "node_modules" as a string
  (`app.use('/node_modules_backup', express.static('assets'))`) — the guard only ever inspects the
  static-serving call's OWN argument (or, for `serve-handler`, its `public` option), never the
  outer `app.use(...)`'s mount-path argument, so this never fires.
- A reviewed, intentional case can be suppressed per line with
  `// security: allow-js-private-file-exposure`.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_bare_dirname` | `express.static(__dirname)` fires HIGH, rule `.../dirname` |
| `test_flags_node_modules_string_literal` | `express.static('node_modules')` fires |
| `test_flags_node_modules_via_path_join` | `express.static(path.join(__dirname, 'node_modules'))` fires |
| `test_flags_node_modules_subpackage_via_path_join` | a `node_modules` segment plus a further subpackage segment still fires |
| `test_flags_serve_static_package_dangerous_arg` | the standalone `serve-static` package invoked directly off `require(...)` fires |
| `test_flags_serve_handler_public_option_homedir` | `require('serve-handler')(req, res, { public: os.homedir() })` fires, rule `.../homedir` |
| `test_flags_root_and_cwd_literals` | bare `'/'` and `'.'` literals both fire, rule `.../root_or_cwd` |
| `test_flags_indirect_dirname_alias_same_file` | `const root = __dirname; ...static(root)` — the one same-file indirection hop this guard follows — fires |
| `test_silent_on_named_public_directory` | `express.static('public')` — FP-bait, stays silent |
| `test_silent_on_dirname_subdirectory` | `path.join(__dirname, 'public')` — a real subdirectory, not the bare dir — FP-bait, stays silent |
| `test_silent_when_node_modules_only_in_mount_path_not_served_dir` | `app.use('/node_modules_backup', express.static('assets'))` — adversarial FP-bait on the mount-path argument, stays silent |
| `test_pragma_suppresses` | the inline opt-out pragma silences the finding |
| `test_silent_on_commented_out_violation` | a commented-out call is stripped before matching, stays silent |
| `test_not_applies_without_express` | `applies()` is false without the `express` feature |
| `test_applies_with_express` | `applies()` is true with the `express` feature |

## Known bypasses

- **Multi-hop indirection.** Only ONE hop of same-file `const/let/var X = __dirname;` aliasing is
  tracked. A second hop (`const a = __dirname; const b = a; ...static(b)`), reassignment, object/
  array destructuring, a function returning `__dirname`, or an alias imported from another file
  all evade detection — this is regex/text matching, not real dataflow.
- **Traversal-constructed paths.** `path.resolve('..', '..', 'node_modules')` or any directory
  built through relative-segment traversal rather than a direct literal/`__dirname`-relative form
  is not recognized — the guard only classifies the literal text of the argument expression, it
  does not resolve or simulate path arithmetic. Neither does string concatenation
  (`__dirname + '/node_modules'`) or template-literal construction (`` `${__dirname}/node_modules` ``)
  — only a `path.join(...)`-shaped call (or a bare literal) is examined for a `node_modules`
  substring.
- **Dynamic / runtime-computed values.** An argument built from an environment variable, a config
  file read at startup, or any other runtime computation cannot be classified — the guard only
  sees the literal source text.
- **Non-literal `require()` targets.** `require(pkgNameVariable)` for `serve-static`/
  `serve-handler` is not recognized; only the literal string-argument form is matched (mirroring
  how every other require-based guard in this codebase works).
- **A directory named something else that still resolves to a dangerous target** — e.g. a symlink
  pointing at `node_modules`, or an env var whose runtime value happens to be `/` — is invisible to
  static source analysis by construction.

## What this guard does NOT prove

A clean run does NOT prove the app never serves a private directory — only that no LITERAL call to
`express.static`/`connect.static`/`serve-static`/`serve-handler` in scanned JS/TS source passes one
of the four specific dangerous argument shapes above. It says nothing about:

- Static-serving configured through a non-JS layer (nginx/Apache `alias`/`root` directives, a
  Dockerfile `COPY` into a served directory, a cloud storage bucket policy) — out of scope for a
  JS/TS source guard entirely.
- A directory that is safe today but becomes dangerous later (a `public/` folder into which a
  build step accidentally copies `.env` or `node_modules`).
- Directory listing / `dotfiles` / `index` options on the middleware call itself — this guard only
  evaluates WHICH directory is served, not how permissively it's browsed once served.
- Any of the "known bypasses" above, which a determined (or merely differently-styled) author can
  hit without intending to evade anything.

# Citations

[1] agentsec checklist item `3a-js-private-file-exposure` (§3a)
[2] CWE-200
[3] OWASP:A01
