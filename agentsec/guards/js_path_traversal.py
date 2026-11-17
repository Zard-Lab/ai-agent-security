"""Guard: no path traversal in JS/Node `fs` calls (checklist §3a).

Calling a Node `fs` read/write/stream function with a path built from concatenation
or template-literal interpolation of request-derived data — `` fs.readFile(`./uploads/
${req.params.filename}`, cb) `` or `fs.createReadStream("/data/" + req.query.path)` —
lets `filename = "../../etc/passwd"` (or `../../` anywhere in the value) escape the
intended directory and read (or, on a write/unlink sink, plant or destroy) arbitrary
files. CWE-22, OWASP:A01 (Broken Access Control). This is the JS/Node counterpart to
agentsec's existing (Python-side) `path-traversal` guard — a genuinely different code
surface (Node's `fs` module, not `open`/`send_file`), so it is a natural extension of
the same checklist item (`3a-path-traversal-file-serving`) rather than a new one.

Sourced from GitHub CodeQL's `javascript/ql/src/Security/CWE-022/TaintedPath.ql`
(`TaintedPathCustomizations.qll`, verified against real fetched source): the query's
`FsPathSink` covers a broad set of core Node `fs` module calls whose path argument is
tainted, excluding calls already routed through a path-normalization/containment
function. This guard deliberately implements only the `FsPathSink` core read/write/
stream/rename/delete calls — NOT CodeQL's broader `ExpressRenderSink`/
`ResolveModuleSink`/headless-browser/prettier sink zoo, which need more context
(module resolution, template-engine config) than a regex window can safely capture
without a real dataflow engine.

Detection mirrors the Python `path-traversal` guard's "safe pattern nearby" exclusion,
ported to a small window (this guard's window is +/-5 lines, since in JS the
normalize/containment call is idiomatically a separate statement a few lines above or
below the sink — unlike the Python guard's same-line-only check) rather than requiring
the safety marker on the sink's own line: `path.resolve(`, `path.normalize(`,
`path.isAbsolute(`, `path.relative(`, or a genuinely separator-boundary-aware
`.startsWith(` containment check within that window silences the finding.

Fires HIGH per match:

    fs.readFile(`./uploads/${req.params.filename}`, cb);
    // security: allow-js-path-traversal

Fully static paths (`fs.readFile("./config/app.json", cb)`) and paths with no
request-derived reference never fire; a nearby `path.resolve()`/`path.normalize()`/
`path.isAbsolute()`/`path.relative()`/separator-aware-`.startsWith()` check silences a
fire that would otherwise trigger.

**2026-09-21 (fix):** a bare `.startsWith(base)` with no trailing separator used
to silence the guard unconditionally — but that is exactly the "prefix-match bypass" that
made Anthropic's own official Filesystem MCP Server exploitable
(`"/private/tmp/allowed_dir_evil".startsWith("/private/tmp/allowed_dir")` is `true`,
CVE-2025-53109/53110, "EscapeRoute"). `.startsWith(` now only silences the guard when its
own argument shows separator-boundary evidence (`path.sep`, or a literal slash or backslash
separator character adjacent to a quote/backtick — `base + path.sep`, `base + '/'`,
`` `${base}/` ``); `path.relative(`
was added as a second safe marker (ported from sentrymcp's own `MCPA-PATH-JS-001`/
`MCPA-PATH-TS-001` safe_indicators) since it has no equivalent boundary bypass.

**2026-09-23 (Dean's review, 2 fixes):** (1) `path.relative(`'s mere presence
nearby used to silence the guard unconditionally, but nothing about the call itself proves
its result is ever examined — a `console.log(path.relative(...))` line satisfied the marker
while the actual sink stayed completely unguarded. Now requires an escape check somewhere in
the window too (`.startsWith('..')` or `.includes('..')`) — not necessarily on the SAME
`path.relative()` call's result, nor on the same line: an unrelated `.startsWith('..')`
nearby also counts, a known and accepted imprecision (Known bypasses). (2) The
`.startsWith(...)` argument used to be extracted with a `[^)]*` character class, which stops
at the FIRST `)` — so an argument containing its own nested call (the guard's own documented
remediation shape, `.startsWith(path.resolve(baseDir) + path.sep)`) truncated away everything
after that nested call's close-paren, including the real separator-boundary evidence. Now
uses the shared `matching_close_paren` helper (quote- and depth-aware) to find the argument's
true end.

**2026-09-24 (Dean's review, round 2):** `.split(path.sep)[0] === '..'` (and the `!== '..'`
inverse) is a common, correct containment check on `path.relative()`'s result and was flagged
(a false positive) before this fix — the escape-check recognition only covered
`.startsWith`/`.includes` on the result, not the split-and-compare idiom.

**#1055:** the `fs` sink and every containment marker count only when they are live code, tested
on the shared anchor mask (`js_code_matches`): a marker spelled out in a log or error string
(`log.warn('TODO: path.resolve( the target')`) no longer silences a real sink, and a sink spelled
out in a docs string no longer fires. Only the call's `(` (or the escape check's leading `.`) is
tested; the `'/'`, `'..'` and `${...}` evidence the markers and the taint check read stays on the
strings-intact view. Every sink on a line is tried, so a quoted or static first call no longer
hides a tainted one after it.
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
    is_nonproduct_path,
    iter_files,
    js_code_matches,
    matching_close_paren,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-js-path-traversal"

# Core Node `fs` (or `fs.promises`) read/write/stream/rename/delete calls whose first argument
# is a path — CodeQL's `FsPathSink` core set (the read/write/stream calls named in the design
# brief plus their obvious siblings: append/open/copy/rename/mkdir/rmdir/stat/access/readdir).
# `realpath`/`realpathSync` are deliberately EXCLUDED — those are the sanitizing call, not a sink.
_FS_METHODS = (
    r"readFileSync|readFile|writeFileSync|writeFile|appendFileSync|appendFile"
    r"|createReadStream|createWriteStream|unlinkSync|unlink|openSync|open"
    r"|copyFileSync|copyFile|renameSync|rename|mkdirSync|mkdir|rmdirSync|rmdir"
    r"|accessSync|access|statSync|stat|readdirSync|readdir"
)
_FS_SINK = re.compile(rf"\bfs(?:\.promises)?\.(?:{_FS_METHODS})\s*\(")

# Request-derived data references — the exact prefixes named in the design brief.
_TAINTED = re.compile(r"\b(?:req|request|params|query|body)\.")

# String-literal concatenation (`"..." + x` / `x + "..."`) — mirrors path_traversal.py's
# _CONCAT: requires a quote adjacent to the `+`, so two bare variable names concatenated
# together (no literal segment) do not fire — kept deliberately narrow, same as the Python guard.
_CONCAT = re.compile(r"""['"]\s*\+|\+\s*['"]""")

# JS safe-pattern equivalents of the Python guard's `_SAFE` set — a path-normalization or
# explicit containment check. `path.relative(` is handled separately below (see
# `_path_relative_is_checked`): unlike these three, its mere presence proves nothing on its
# own — the containment logic is in what the CALLER does with its result, not the call itself.
_SAFE_JS = re.compile(r"path\.resolve\s*\(|path\.normalize\s*\(|path\.isAbsolute\s*\(")

# `path.relative(base, target)` between base and target is unconditionally SAFE TO TRUST when
# its result is actually checked (the result starts with `..` iff the target escapes the base,
# with no separator-boundary bypass possible, unlike `.startsWith(`, see below) — ported from
# sentrymcp's own `MCPA-PATH-JS-001`/`MCPA-PATH-TS-001` safe_indicators (fetched and verified
# this session). But the call's mere PRESENCE nearby proves nothing: nothing stops
# `path.relative(...)` from being computed and never examined (e.g. `console.log`ed, or used for
# an unrelated display string) while the actual sink stays completely unguarded — found by Dean
# (review). Now requires BOTH the call AND an escape check on ITS result
# (`.startsWith('..')`/`.includes('..')`) to appear somewhere in the window — not necessarily the
# same line, since idiomatically the call is assigned to a variable a line or two before the check.
# The escape check isn't tied to the SAME `path.relative()` call: an unrelated `.startsWith('..')`
# nearby also counts (a known, accepted trade — see the wiki doc's Known bypasses).
#
# **2026-09-24 fix (Dean's review, round 2):** `.split(path.sep)[0] === '..'`/`!== '..'` is a
# common, correct containment check and was flagged (a false positive) before this fix — the
# escape-check regex only recognized `.startsWith`/`.includes` on the result, not the
# split-and-compare idiom.
_RELATIVE_CALL = re.compile(r"path\.relative\s*\(")
_RELATIVE_ESCAPE_CHECK = re.compile(
    r"""\.startsWith\(\s*['"`]\.\.['"`]|\.includes\(\s*['"`]\.\.['"`]"""
    r"""|\.split\(\s*path\.sep\s*\)\s*\[\s*0\s*\]\s*[!=]==\s*['"`]\.\.['"`]"""
)


def _call_paren(m: re.Match[str]) -> int:
    return m.end() - 1


def _path_relative_is_checked(window_lines: list[str], window_mask: list[str]) -> bool:
    # #1055: the call's `(` and the escape check's leading `.` must be live code; the `'..'`
    # literal the check compares against is read on the strings-intact line on purpose.
    rows = list(zip(window_lines, window_mask, strict=True))
    return any(any(js_code_matches(_RELATIVE_CALL, ln, mk, anchor=_call_paren)) for ln, mk in rows) and any(
        any(js_code_matches(_RELATIVE_ESCAPE_CHECK, ln, mk, anchor=lambda m: m.start())) for ln, mk in rows
    )


# `.startsWith(` ALONE does NOT prove the containment check is separator-boundary-aware: a
# naive `p.startsWith(base)` with no trailing separator is exactly the "prefix-match bypass"
# that made Anthropic's own official Filesystem MCP Server exploitable —
# `"/private/tmp/allowed_dir_evil".startsWith("/private/tmp/allowed_dir")` is `true`
# (CVE-2025-53109/53110, "EscapeRoute"; found and deferred, fixed here 2026-09-21).
# Silencing on ANY `.startsWith(` — the guard's original behavior — treated the exploitable
# form as identical to a real, boundary-aware one. Now requires separator-boundary evidence
# INSIDE the `.startsWith(...)` call's own argument: `path.sep`, or a `/`/`\` literal
# adjacent to a quote/backtick (`base + path.sep`, `base + '/'`, `` `${base}/` ``). A
# heuristic — it confirms a separator CHARACTER is present in the argument text, not that the
# concatenation is well-formed at every boundary — disclosed in Known bypasses.
#
# **2026-09-23 fix (Dean's review):** the argument used to be extracted with
# `[^)]*` — stopping at the FIRST `)`, so a `.startsWith(...)` argument containing its OWN
# nested call (the guard's own documented remediation shape,
# `.startsWith(path.resolve(baseDir) + path.sep)`) truncated away everything after that
# nested call's closing paren, including the actual separator-boundary evidence. Now uses
# `matching_close_paren` (quote- and paren-depth-aware, shared with several other guards) to
# find the argument's real end instead of guessing from a character class.
_STARTSWITH_OPEN = re.compile(r"\.startsWith\s*\(")
_SEPARATOR_BOUNDARY_EVIDENCE = re.compile(r"path\.sep|[/\\]['\"`]")


def _startswith_is_separator_aware(line: str, mask_line: str) -> bool:
    # #1055: a `.startsWith(` spelled out in a string is not a check; its argument (and the
    # `'/'` evidence inside it) is still read on the strings-intact line.
    for m in js_code_matches(_STARTSWITH_OPEN, line, mask_line, anchor=_call_paren):
        open_idx = m.end() - 1
        close_idx = matching_close_paren(line, open_idx)
        arg = line[open_idx + 1 : close_idx] if close_idx is not None else line[open_idx + 1 :]
        if _SEPARATOR_BOUNDARY_EVIDENCE.search(arg):
            return True
    return False


# How many lines before/after the sink line count as "nearby" for the safe-pattern check —
# wider than the Python guard's same-line-only check because JS idiomatically resolves/
# validates the path in a separate statement a few lines away, not inline in the sink call.
_SAFE_WINDOW = 5


def _first_arg(text_after_call: str) -> str:
    """Extract just the first argument from the text following an opening paren.

    Same balanced-bracket scan as path_traversal.py's `_first_arg` — stop at the first
    unbalanced `)`/`]`/`}` or a top-level `,`, so a second callback argument or a nested
    call inside the path expression doesn't leak into (or truncate) the extracted arg.
    """
    depth = 0
    for j, ch in enumerate(text_after_call):
        if ch in ("(", "[", "{"):
            depth += 1
        elif ch in (")", "]", "}"):
            if depth == 0:
                return text_after_call[:j].strip()
            depth -= 1
        elif ch == "," and depth == 0:
            return text_after_call[:j].strip()
    return text_after_call.strip()


def _tainted_dynamic(arg: str) -> bool:
    """True iff `arg` references request-derived data AND is assembled (template-literal
    interpolation or `+` concatenation) rather than passed through as a bare reference."""
    if not _TAINTED.search(arg):
        return False
    if "${" in arg:
        return True
    return bool(_CONCAT.search(arg))


class JsPathTraversalGuard(Guard):
    id = "js-path-traversal"
    title = "No path traversal in JS/Node fs calls"
    area = "Files"

    # js_fs_read.js: fs.readFile() with a template-literal path referencing req.params ->
    # fires js-path-traversal.
    canary_plant = CanaryPlant(
        files={
            "js_fs_read.js": (
                "const fs = require('fs');\n"
                "app.get('/uploads/:filename', (req, res) => {\n"
                "  fs.readFile(`./uploads/${req.params.filename}`, (err, data) => res.send(data));\n"
                "});\n"
            ),
        },
        expects=frozenset({"js-path-traversal/tainted-fs-path"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "javascript" in profile.features or "typescript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        # strip_js_comments blanks `//` (including a TRAILING same-line comment, not just a
        # whole-line one) and `/* */` blocks, string/regex-literal aware — the old whole-line-only
        # `^\s*//` check let a trailing comment mentioning an `fs` sink false-fire (#395 H1). Line
        # count/layout are preserved. The comment-only view keeps the inline pragma visible (strip would blank it).
        view_lines = comment_view(text, "js").splitlines()  # same length: comments only (#424)
        lines = strip_js_comments(text).splitlines()
        # The anchor mask (#1055): same layout, string and template text blanked, `${...}` code kept.
        mask_lines = strip_js_comments(text, strip_strings=True, keep_substitutions=True).splitlines()

        for i, (line, mask_line) in enumerate(zip(lines, mask_lines, strict=True)):
            if _PRAGMA in view_lines[i]:
                continue
            # Every live `fs` call on the line is tried (#1055): `.search` stopped at the first
            # one, so a quoted or static copy hid a tainted call after it. The taint check reads
            # the strings-intact argument, where `${req.params.x}` lives.
            if not any(
                _tainted_dynamic(_first_arg(line[m.end():]))
                for m in js_code_matches(_FS_SINK, line, mask_line, anchor=_call_paren)
            ):
                continue
            lo = max(0, i - _SAFE_WINDOW)
            hi = min(len(lines), i + _SAFE_WINDOW + 1)
            window = lines[lo:hi]
            window_mask = mask_lines[lo:hi]
            if any(
                any(js_code_matches(_SAFE_JS, ln, mk, anchor=_call_paren))
                or _startswith_is_separator_aware(ln, mk)
                for ln, mk in zip(window, window_mask, strict=True)
            ) or _path_relative_is_checked(window, window_mask):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{i + 1}",
                    message=(
                        "This Node `fs` call's path argument is assembled from request-"
                        "derived data (req./request./params./query./body.) via template-"
                        "literal interpolation or string concatenation, with no path-"
                        "normalization or containment check nearby — "
                        "`../../etc/passwd` escapes the intended folder and reads (or, on "
                        "a write/unlink sink, plants or destroys) arbitrary files."
                    ),
                    remediation=(
                        "Resolve the final path and assert it stays under a hardcoded "
                        "base directory before the `fs` call: `const p = path.resolve"
                        "(baseDir, name); if (!p.startsWith(path.resolve(baseDir) + "
                        "path.sep)) throw new Error('invalid path');`. "
                        "Suppress an audited case with `// security: allow-js-path-traversal`."
                    ),
                    rule="js-path-traversal/tainted-fs-path",
                    standards=["OWASP:A01", "CWE-22"],
                )
            )
        return out
