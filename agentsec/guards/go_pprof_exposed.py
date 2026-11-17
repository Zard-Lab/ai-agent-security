"""Guard: net/http/pprof registered on the default ServeMux (§6a, new item).

    import _ "net/http/pprof"

Importing `net/http/pprof` purely for its side effect registers five profiling
endpoints (`/debug/pprof/`, `/debug/pprof/cmdline`, `/debug/pprof/profile`,
`/debug/pprof/symbol`, `/debug/pprof/trace`, plus the pprof index it serves for
goroutine/heap/threadcreate/block/mutex profiles) on Go's package-level
`http.DefaultServeMux` — via the package's own `init()`, not a call the importing
code makes explicitly. If that default mux is ever served — the extremely common
`http.ListenAndServe(addr, nil)` idiom (a `nil` handler means "use
`http.DefaultServeMux`"), or any other `http.Serve*` call passed `nil` — every one
of those endpoints becomes reachable to whoever can reach the listener (CWE-215,
Information Exposure Through Debug Information):

  * `/debug/pprof/cmdline` and the index page leak process internals: full command
    line (including any secrets passed as flags), environment-derived build info,
    and goroutine/heap dumps that can reveal source paths, struct field names, and
    in-memory data.
  * `/debug/pprof/profile` blocks the request for a caller-controlled duration
    (default 30s, tunable via `?seconds=N`) while it samples the CPU — a trivial,
    unauthenticated DoS lever: a handful of concurrent requests each holding a
    profiling goroutine open for tens of seconds can exhaust worker capacity.

This is one of the most common accidental-production-exposure bugs in Go services:
a developer adds the blank import for a local `go tool pprof` debugging session,
the service ships, and nothing about the import line looks alarming in review — it
is one word (`_`) different from a completely ordinary import.

Fires on the blank-import statement itself, in EITHER form:

    import _ "net/http/pprof"                 // single import

    import (
        "net/http"
        _ "net/http/pprof"                     // grouped import block
    )

## Severity/scope judgment call

This is static text analysis with no call-graph or cross-file data flow, so the
guard cannot prove the default mux is ever actually served — that would require
following every `http.ListenAndServe`/`http.Serve`/framework call across the
package (and possibly across the binary's `main`, in a different file or even a
different package) to see whether it was ever handed a `nil` handler. That is out
of reach for a portable, dependency-free guard.

Fires HIGH on the blank import alone rather than trying to gate on a same-file
`nil`-mux call. Two reasons:

  1. **The blank-import form only exists to reach `http.DefaultServeMux`.** Go's
     documented, endorsed pattern for exposing pprof *safely* — e.g. behind auth or
     on a private/loopback-only listener — is to import the package normally (no
     underscore) and call its exported handlers explicitly
     (`pprof.Handler(...)`/`pprof.Index`/`pprof.Profile`/etc.) mounted on an
     application-owned `*http.ServeMux`. Once a developer is being deliberate about
     where pprof lives, the blank-import idiom has no purpose left — they already
     have to write the `net/http/pprof` import either way, and the non-blank form
     costs nothing extra while giving them control over the mount point. So seeing
     the blank form specifically is itself a strong signal that pprof was wired in
     via the quick side-effect path, not the deliberate one.
  2. **Trying to require a same-file `nil`-mux call would silently create false
     negatives that undermine the guard's own point.** The `ListenAndServe(addr,
     nil)` call is very often in a different file (`main.go`) from the blank
     import (an `init.go`/`debug.go` off in a subpackage), may be wrapped in a
     helper function, or may come from a framework that serves
     `http.DefaultServeMux` implicitly without the app ever writing `nil` itself.
     A guard that only fires when it can also see the exact `nil` callsite in the
     SAME file would miss most real cases — the opposite of the "the import is the
     bug" reasoning in point 1.

This is a deliberate precision/recall trade documented (not hidden) in "What this
guard does NOT prove" below: it is possible, though unusual in real code, for a
file to blank-import pprof while genuinely never exposing `http.DefaultServeMux`
(e.g. a from-scratch alternate mux is used everywhere and the import is dead
weight some linter would flag separately) — the guard still fires in that case.

Suppress an audited case with `// security: allow-go-pprof-exposed`.
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

_PRAGMA = re.compile(r"//\s*security:\s*allow-go-pprof-exposed")

_STANDARDS = ["CWE-215"]

# The Go blank-import idiom: a bare `_` (the blank identifier — cannot appear as a
# bound value outside an import spec) directly followed by the `net/http/pprof`
# import path. This token sequence is syntactically valid ONLY inside an import
# declaration (single-line `import _ "..."` or one spec line inside a grouped
# `import (...)` block) — `_` cannot be used as an expression on its own the way
# `_ = "net/http/pprof"` (an assignment) can, so no additional "are we inside an
# import statement" context check is needed. The left lookbehind guards against an
# identifier that merely ENDS in `_` immediately followed by the string (not valid
# Go either way, but keeps the pattern honest about what it intends to match).
_BLANK_IMPORT = re.compile(r'(?<![\w])_\s*"net/http/pprof"')


class GoPprofExposedGuard(Guard):
    id = "go-pprof-exposed"
    title = "net/http/pprof registered on the default ServeMux"
    area = "Web setup"

    # go_pprof.go: blank import of net/http/pprof -> fires
    # go-pprof-exposed/blank-import-default-mux.
    canary_plant = CanaryPlant(
        files={
            "go_pprof.go": (
                'package main\n\nimport (\n\t"net/http"\n\t_ "net/http/pprof"\n)\n\n'
                "func main() {\n\thttp.ListenAndServe(\":8080\", nil)\n}\n"
            ),
        },
        expects=frozenset({
            "go-pprof-exposed/blank-import-default-mux",
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
        out: list[Finding] = []
        raw_text = read(f)
        view_lines = comment_view(raw_text, "go").splitlines()  # same length: comments only (#424)
        # Two views of the same file: the pragma is checked against the COMMENT-ONLY view of
        # the line (it lives inside a `//` comment, which stripping would blank out, and a
        # string quoting it must not count, #424), while the actual import pattern is checked against
        # the comment-STRIPPED line (so `// import _ "net/http/pprof"` in a comment
        # does not fire — strip_go_comments blanks comment text but preserves the
        # splitlines() count, so the two line lists stay index-aligned).
        stripped_lines = strip_go_comments(raw_text).splitlines()
        for lineno, view_line in enumerate(view_lines, start=1):
            if _PRAGMA.search(view_line):
                continue
            code_line = stripped_lines[lineno - 1] if lineno - 1 < len(stripped_lines) else ""
            if _BLANK_IMPORT.search(code_line):
                out.append(self._finding(root, f, lineno))
        return out

    def _finding(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "This blank import registers net/http/pprof's profiling endpoints "
                "(/debug/pprof/*) on Go's package-level http.DefaultServeMux as a side "
                "effect of the import itself. If this process ever serves that default "
                "mux (the common `http.ListenAndServe(addr, nil)` idiom, or any "
                "`http.Serve*` call passed a nil handler), those endpoints become "
                "reachable to anyone who can reach the listener — leaking process "
                "internals (command line, goroutine/heap dumps) via /debug/pprof/cmdline "
                "and friends, and offering /debug/pprof/profile as a caller-controlled, "
                "unauthenticated CPU-profile DoS lever (CWE-215)."
            ),
            remediation=(
                "Remove the blank import. If pprof needs to be reachable at all in this "
                "deployment, import net/http/pprof normally (no `_`) and mount its "
                "handlers explicitly on an application-owned *http.ServeMux that is "
                "never the one served to the internet — bind it to localhost/a private "
                "port, or put it behind authentication middleware. Never let "
                "http.DefaultServeMux (the mux this import silently populates) be the "
                "handler passed to a publicly reachable listener. Suppress an audited "
                "case (e.g. a debug binary that is genuinely never deployed) with "
                "`// security: allow-go-pprof-exposed`."
            ),
            rule="go-pprof-exposed/blank-import-default-mux",
            standards=list(_STANDARDS),
        )
