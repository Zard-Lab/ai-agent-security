---
type: Guard
title: "go-pprof-exposed"
description: "net/http/pprof registered on the default ServeMux."
timestamp: "2026-08-11T11:20:17+08:00"
guard_id: "go-pprof-exposed"
checklist_section: ["6a"]
---

# net/http/pprof registered on the default ServeMux

_Author — Marconi, 2026-08-10_

---

## The threat

```go
import _ "net/http/pprof"
```

Importing `net/http/pprof` purely for its side effect (the blank `_` import
identifier — the package is never referenced by name) runs the package's `init()`,
which registers five profiling endpoints on Go's package-level
`http.DefaultServeMux`: `/debug/pprof/` (the index), `/debug/pprof/cmdline`,
`/debug/pprof/profile`, `/debug/pprof/symbol`, `/debug/pprof/trace` — plus the
individual named profiles it serves through the index (goroutine, heap,
threadcreate, block, mutex). This registration happens automatically, at import
time, with **no call the importing code has to make** — the entire point of the
blank-import idiom is "run my side effects, I don't need the symbols."

If the process ever serves `http.DefaultServeMux` — which happens whenever
`http.ListenAndServe(addr, nil)` / `http.ListenAndServeTLS(addr, cert, key, nil)`
/ `http.Serve(l, nil)` is called with a `nil` handler (the Go stdlib's documented
meaning of `nil` here: "use `http.DefaultServeMux`") — every one of those
endpoints becomes reachable to whoever can reach the listener:

- **`/debug/pprof/cmdline`** and the index page leak process internals: the full
  command line the binary was started with (which can include secrets passed as
  flags), build info, and on-demand goroutine/heap dumps that reveal source file
  paths, function names, and struct layouts — reconnaissance value for an
  attacker mapping the target, and a direct information leak (CWE-215,
  Information Exposure Through Debug Information).
- **`/debug/pprof/profile`** blocks the HTTP request for a caller-controlled
  duration via the `?seconds=N` query parameter (default 30s if omitted) while it
  CPU-profiles the process. A handful of concurrent unauthenticated requests each
  holding a profiling goroutine open for tens of seconds is a trivial DoS lever
  against worker/connection capacity — no exploit needed, just the documented API
  used as designed, against a target it was never meant to be exposed to.

`WHO` reaches this: anyone who can send an HTTP request to the listening port —
no authentication exists for `net/http/pprof`'s endpoints unless the app puts
some in front of them itself. `WHAT privilege`: none required. `WHAT effect`:
information disclosure of process internals up to and including a crude,
repeatable denial-of-service primitive.

## Why it's often introduced

This is a textbook accidental-production-exposure bug, not a deliberate
compromise. A developer wants to profile a running service — the Go team's own
docs (`net/http/pprof` package doc, `go doc net/http/pprof`) show exactly this
one-line blank import as the fastest way to wire it up locally:

```go
import (
    "net/http"
    _ "net/http/pprof"   // added for a local `go tool pprof` session
)

func main() {
    go http.ListenAndServe("localhost:6060", nil)
    // ... the app's real server, maybe on a different port/mux entirely
}
```

The import line is one character (`_`) different from an ordinary import, so it
does not stand out in a diff or a review the way a new dependency or a config
flag would. It is added for local debugging, the debugging session ends, and the
import is simply never removed — it costs nothing to compile, causes no test
failures, and produces no runtime symptom until someone requests
`/debug/pprof/profile` against the production listener. This is a very common,
well-documented Go footgun precisely because the "quick" path and the "unsafe in
prod" path are the same one line of code.

## Detection design

1. `applies()` gate — `"go" in profile.features` (set whenever `detect.py` finds
   at least one `.go` file in the repo; general Go, not framework-gated — the
   blank-import idiom is stdlib, independent of any web framework in use).
2. Scans every `.go` file under `go_scan_dirs(root, profile)` (mirrors
   `python_scan_dirs`'s shape/fallback exactly, on the `go_dirs` profile field).
3. Two views of each file's text, per line:
   - the comment-only view of the line (`comment_view(…, "go")`, #424), checked for the inline pragma;
   - the comment-STRIPPED line (via `strip_go_comments`), checked for the actual
     import pattern — so a `//`-commented-out mention of the import string does
     not fire. `strip_go_comments` blanks comment/string content to spaces while
     preserving `str.splitlines()` boundaries, so the two line lists stay
     index-aligned without a second parse pass.
   - Pattern: `_BLANK_IMPORT = re.compile(r'(?<![\w])_\s*"net/http/pprof"')` — the
     blank identifier `_` immediately followed (optional whitespace) by the
     import path string. This token sequence is valid Go **only** inside an
     import declaration (`_` cannot appear as a bare expression the way
     `_ = "net/http/pprof"` — an assignment — can), so it matches both the
     single-line form (`import _ "net/http/pprof"`) and each spec line inside a
     grouped `import (...)` block (`_ "net/http/pprof"`, no `import` keyword on
     that line) without needing separate handling for the two syntaxes.
4. Inline opt-out: `// security: allow-go-pprof-exposed` on the same line as the
   import (checked per-line against the pre-strip text, mirroring
   `hardcoded_llm_provider_key`'s per-line-not-file-wide pragma scoping).
5. Severity: `high`, unconditionally, on the blank import alone — see the
   judgment call below. Rule id: `go-pprof-exposed/blank-import-default-mux`
   (single rule; no attempt to model gradations of confidence in
   text-only analysis). Standards: `["CWE-215"]`.

### Severity/scope judgment call

The honest, hard question here is whether the blank import alone is enough
signal, or whether the guard should try to confirm the actual exposure condition
(a `nil`-mux `http.ListenAndServe`/`http.Serve` call) before firing HIGH.

**Decision: fire HIGH on the blank import alone, unconditionally.** Two reasons,
in order of how load-bearing each is:

1. **The blank-import form has no legitimate reason to exist once pprof exposure
   is being handled deliberately.** The stdlib-endorsed way to expose pprof
   safely (behind auth, on a loopback-only listener, gated by an environment
   flag) is to import the package by its normal name and call its exported
   handlers explicitly — `pprof.Handler(name)`, `pprof.Index`, `pprof.Profile`,
   `pprof.Cmdline`, `pprof.Symbol`, `pprof.Trace` — mounted on an
   application-owned `*http.ServeMux`. That path requires writing the same
   import either way, and costs nothing extra over the blank form while handing
   the developer control of the mount point and thus the ability to gate it.
   Once a developer needs the underscore, the entire reason is "this package's
   `init()` side effect only" — and `net/http/pprof`'s *only* side effect is
   registering onto `http.DefaultServeMux`. So the presence of the blank form
   specifically (not the package generally) is itself close to a direct
   statement of intent, not just a probabilistic signal.
2. **Static text analysis cannot reliably confirm the `nil`-mux callsite without
   creating a worse false-negative problem.** A guard could try to require a
   same-file `http.ListenAndServe(addr, nil)` (or `Serve`/`ListenAndServeTLS`
   with a nil handler) before firing, to more directly "prove" exposure. That
   was considered and rejected: the serve call is very often in a different file
   from the blank import (a `debug.go`/`profiling.go` helper vs. `main.go`), may
   be wrapped in a small helper function the guard cannot see through, or may
   come from a framework/wrapper that defaults to serving
   `http.DefaultServeMux` without the application ever writing the literal
   token `nil` itself. Gating on a same-file nil-mux call would silently miss
   most real occurrences of this bug — undermining the exact reasoning in (1)
   that the import itself is already close to sufficient.

This is a genuine precision/recall trade, made explicit rather than hidden: it
is possible (though unusual in observed real code) for a file to blank-import
`net/http/pprof` while the binary's *only* HTTP server genuinely never serves
`http.DefaultServeMux` anywhere in the program — e.g. every route in the
codebase is mounted on an explicitly constructed alternate mux, and the pprof
import is simply dead weight that would separately draw an `unused import`-style
lint (though Go doesn't flag blank imports as unused, since that's precisely
what they're for). The guard still fires HIGH in that case. See "What this
guard does NOT prove" below — the guard proves the import exists, not that
`DefaultServeMux` is reachable.

## Why this guard fits the stack

This is the first batch of Go-specific guards built for agentsec (Go scanning
infrastructure — `go_scan_dirs`, `strip_go_comments`, `"go" in profile.features`
— landed on `feat/go-scan-infra` immediately prior to this guard). `net/http` is
the Go stdlib's own HTTP server package, so this pattern is stack-agnostic within
Go: it applies equally to a bare-stdlib service, a `gorilla/mux`/`chi`/`gin` app
that also happens to start a stdlib listener for metrics/health/pprof, or any Go
microservice in a polyglot repo agentsec is auditing. It requires no Go-specific
web framework detection beyond "this repo has Go source" — `net/http/pprof` is
part of the standard library, always available, and the blank-import idiom is
Go-syntax-level, not framework-level.

## When NOT to flag

- A **non-blank** import of `net/http/pprof` (`import "net/http/pprof"` or an
  aliased `import pprof "net/http/pprof"`), used to call its exported handlers
  explicitly and mount them on an application-owned mux
  (`mux.Handle("/internal/debug/pprof/", pprof.Handler("goroutine"))`) — this is
  the legitimate, gated pattern the remediation text recommends, and it never
  matches `_BLANK_IMPORT` (no `_` immediately before the import string).
- The import path string appearing only inside a `//` comment (a TODO, a code
  example in a doc comment) — stripped before the pattern check runs.
- An audited case, suppressed with `// security: allow-go-pprof-exposed` on the
  import line.

## Tests

| Test | What it checks |
|---|---|
| `test_go_pprof_exposed_fires_on_standalone_blank_import` | Positive: `import _ "net/http/pprof"` as a standalone import fires HIGH, correct rule id/standards/line (**verified_by**). |
| `test_go_pprof_exposed_fires_inside_grouped_import_block` | Positive: the same blank import as one spec line inside a grouped `import (...)` block fires, at the correct line number. |
| `test_go_pprof_exposed_silent_on_explicit_handler_mount` | FP-bait: a non-blank `net/http/pprof` import used to explicitly mount `pprof.Handler(...)` on a custom mux → silent. |
| `test_go_pprof_exposed_silent_when_import_string_only_in_comment` | FP-bait: the import string appearing only inside a `//` comment → silent. |
| `test_go_pprof_exposed_pragma_silences` | Suppress pragma on the import line → silent. |
| `test_go_pprof_exposed_not_applies_without_go` | `applies()` gate false without `go` in `profile.features`. |
| `test_go_pprof_exposed_applies_with_go` | `applies()` gate true with `go` in `profile.features`. |

## Known bypasses

- **Dynamic/indirect construction is not applicable here** the way it is for a
  value-carrying guard (there is no literal to obfuscate) — but a determined
  author could still route around detection by moving the registration off the
  textual blank-import idiom entirely: manually calling
  `http.DefaultServeMux.HandleFunc("/debug/pprof/...", pprof.Index)` (etc.) one
  handler at a time using the package's normal (non-blank) import. This guard's
  pattern is specific to the `_` token sequence; it does not attempt to detect
  every possible way pprof's handlers could be manually wired onto
  `http.DefaultServeMux`, since that reintroduces the same "explicit handler
  registration" shape the FP-bait test deliberately treats as the *safe*
  pattern (mounting on a custom mux uses the identical `pprof.Handler(...)`
  call).
- **Multi-line / unusually formatted import specs**: `_BLANK_IMPORT` is a
  same-line regex; an import spec split across physical lines by unusual
  formatting (not something `gofmt` produces, but not impossible to hand-write)
  would not match. Real-world Go source is `gofmt`-formatted near-universally,
  so this is a narrow gap in practice.
- **Build-tag-gated files**: a blank import inside a file behind a
  `//go:build debug` (or legacy `// +build debug`) constraint that is never
  compiled into the production binary still fires — the guard does not parse
  build tags or know which build configuration is "production." This can be a
  false positive in the guard's favor (flags a file that never ships) or exactly
  the bug (flags a file the author *thought* was debug-only but a wildcard
  build/tag configuration includes anyway); either way it is not resolved
  textually.

## What this guard does NOT prove

A finding proves only that a Go source file contains the blank-import token
sequence for `net/http/pprof` — it does **not** prove that:

- `http.DefaultServeMux` is ever actually served (the `ListenAndServe`/`Serve`
  call with a `nil` handler may be in a different file, wrapped in a helper, or
  supplied implicitly by a framework — see the severity/scope judgment call
  above for why the guard fires anyway).
- the listener that eventually serves `http.DefaultServeMux` (if one exists) is
  reachable from outside the host — it could be bound to `localhost` only,
  sitting behind a firewall, or gated by network policy the guard has no
  visibility into.
- the file is even part of the production build (build-tag-gated debug-only
  files are not distinguished — see "Known bypasses").

Conversely, a **silent** run does not prove pprof is not exposed: manual,
piecemeal registration of pprof's handlers onto `http.DefaultServeMux` via a
non-blank import (see "Known bypasses") reaches the same outcome without ever
writing the token sequence this guard looks for.

# Citations

[1] agentsec checklist item `6a-pprof-endpoint-exposed` (§6a)
