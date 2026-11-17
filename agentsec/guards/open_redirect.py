"""Guard: no open redirect from user-controlled input (checklist §3a).

A redirect whose target is built from request input — e.g. the `next` query
param fed straight into a `redirect(...)` sink — lets an attacker send
`?next=https://evil.example` and bounce a victim off your trusted domain
(phishing, OAuth-token theft, filter bypass).
CWE-601 / OWASP:A01. The fix is to redirect only to a vetted internal target:
`url_for("dashboard")`, a path from an allow-list, or a relative path validated
to start with a single `/`.

Fires MEDIUM on a redirect sink whose target **provably derives from untrusted /
request input** — a request accessor directly, a typed FastAPI/Starlette request-data
parameter (`next: str = Query(...)` or `Annotated[str, Query()]`, incl. `Path`/`Body`/
`Form`/`Cookie`/`Header`/`File`), or a variable/f-string/concat that carries one
(intra-file taint) — and is NOT a `url_for(...)` call:

  * Flask / Django — `redirect(...)`;
  * Starlette / FastAPI — `RedirectResponse(...)`;
  * Django — `HttpResponseRedirect(...)`.

This is provenance, not pattern-presence: a redirect to an internal/vetted value
(`redirect(dest)` where `dest` is a function param, or a `url_for(...)`-derived
variable) does NOT fire — that was the F2/B8 auto-exclude-noise the old
bare-variable heuristic emitted (issue #90). A static literal (`redirect("/home")`)
does not fire either. Suppress an audited case with `# security: allow-open-redirect`.

Lexing: the file is tokenized (stdlib `tokenize`) and the character spans of every
string literal and comment are blanked before analysis — so a request accessor or a
sink that appears as *text* inside a string, a comment, or a docstring code-example
(incl. multi-line strings) is never mistaken for code, while f-string *interpolations*
(`f"{request.args['n']}"`) are kept as the code they are. On a syntactically invalid
file it degrades to a best-effort raw scan (never raises).

Limitations: taint is tracked **intra-file** only; a **multi-line call** whose sink and
target sit on different physical lines is not matched (line-oriented match). Instance-attribute
taint is not tracked: `self.q = request.args.get(...)` followed by `redirect(self.q)` is a
false negative, because the taint model keys on BARE names and `self`/`cls` are deliberately
excluded (tainting `self` made every `redirect(self.anything)` in the file fire). The
recognized untrusted sources are the explicit request accessors in `_UNTRUSTED` and the
FastAPI request-data parameter markers (`Query`/`Path`/`Body`/`Form`/`Cookie`/`Header`/
`File`); broaden them if a framework's accessor or marker is missing.
"""
from __future__ import annotations

import ast
import re
import tokenize
from collections import deque
from io import StringIO
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, python_scan_dirs, read, rel

_SINK = re.compile(r"\b(?:redirect|RedirectResponse|HttpResponseRedirect)\s*\(")
_PRAGMA = re.compile(r"#\s*security:\s*allow-open-redirect")

# Untrusted / request-derived sources. Explicit accessors (not a bare `request.`)
# so `request.method` etc. don't count. Covers Flask/Django (`request.args/form/
# values/GET/POST/json/get_json/data/cookies/headers`), Starlette/FastAPI
# `.query_params`, and Django class-based views (`self.request.`).
_UNTRUSTED = re.compile(
    r"\brequest\s*\.\s*(?:args|form|values|GET|POST|json|get_json|data|cookies|headers|query_params)\b"
    r"|\.\s*query_params\b"
    r"|\bself\s*\.\s*request\s*\."
)
_WORD = re.compile(r"[A-Za-z_]\w*")
# Augmented assignment: `NAME <op>= rhs` (e.g. `path += request.args["s"]`).
_AUG = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?:\+|-|\*|/|//|%|@|&|\||\^|>>|<<|\*\*)=(?!=)\s*(.+)$")
_WALRUS_HEAD = re.compile(r"([A-Za-z_]\w*)\s*:=\s*")

# FastAPI/Starlette request-data parameter markers. A route parameter whose default is one
# of these — `next: str = Query(...)` — or whose `Annotated[...]` metadata carries one —
# `next: Annotated[str, Query()]` — IS request input, so its name is an untrusted taint
# source even though it never appears as `name = request.X` (issue #296: a typed Query/Path/
# Body param is the most common FastAPI redirect-target source). Deliberately NOT Depends/
# Security (those inject a dependency's return — often a *validated* value like the
# authenticated user). A plain typed param with no marker (`dest: str`) is left alone —
# tainting those would reintroduce the #90 internal-param false positive.
#
# Recognition is gated on the marker name actually being imported FROM fastapi/starlette in
# this file (#296 round-5 review): the names collide with common stdlib/ORM constructors
# (`pathlib.Path`, `sqlalchemy.orm.Query`), so a `Path(...)`/`Query(...)` parameter default
# in a file that never imports the framework must NOT be read as a request binding.
_MARKERS = frozenset({"Query", "Path", "Body", "Form", "Cookie", "Header", "File"})
_DEF = re.compile(r"\bdef\s+[A-Za-z_]\w*\s*\(")
_DEFAULT_CALL = re.compile(r"^([A-Za-z_]\w*)\s*\(")
_NAME_ONLY = re.compile(r"^[A-Za-z_]\w*$")


def _is_framework_module(module: str) -> bool:
    return module in ("fastapi", "starlette") or module.startswith(("fastapi.", "starlette."))


def _blank_strings_and_comments(text: str) -> list[str]:
    """Overwrite the character spans of every STRING / COMMENT / f-string-literal token
    with spaces so string content and comments (incl. multi-line strings) can never be
    mis-read as code, while f-string *interpolation* code and the exact column layout are
    preserved. Best-effort: on a tokenize error (a syntactically invalid file) the raw
    lines are returned rather than raising."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    try:
        toks = list(tokenize.generate_tokens(StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError, RecursionError, MemoryError):
        return lines  # unparseable / too-complex -> best-effort raw scan (#370)
    blank_types = {tokenize.STRING, tokenize.COMMENT}
    for _name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"):  # PEP 701, py3.12+
        _t = getattr(tokenize, _name, None)
        if _t is not None:
            blank_types.add(_t)
    grid = [list(ln) for ln in lines]
    for tok in toks:
        if tok.type in blank_types:
            (sr, sc), (er, ec) = tok.start, tok.end
            for r in range(sr, er + 1):
                if r - 1 >= len(grid):
                    break
                row = grid[r - 1]
                lo = sc if r == sr else 0
                hi = ec if r == er else len(row)
                for c in range(lo, min(hi, len(row))):
                    row[c] = " "
    return ["".join(row) for row in grid]


def _walruses(code: str) -> list[tuple[str, str]]:
    """(target, value) for each `name := <value>` on a line, value captured with bracket
    balance to its own enclosing close (a nested call before the untrusted ref isn't
    truncated at the first `)`)."""
    out: list[tuple[str, str]] = []
    for m in _WALRUS_HEAD.finditer(code):
        depth = 0
        j = m.end()
        n = len(code)
        while j < n:
            c = code[j]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif c == "," and depth == 0:
                break
            j += 1
        out.append((m.group(1), code[m.end():j]))
    return out


def _refs_name(name: str, text: str) -> bool:
    """True if `name` appears in `text` as a standalone variable reference — NOT an
    attribute member (`obj.name`), a keyword-arg name (`name=`), or part of a longer
    identifier (`user_name`). Stops a tainted name from colliding with an unrelated
    `.name`/`name=`."""
    return re.search(r"(?<![.\w])" + re.escape(name) + r"(?![\w=])", text) is not None


# Every standalone identifier reference in a piece of code (same boundary rule as `_refs_name`:
# not `.attr`, not a `kw=` name, not part of a longer identifier). Used to precompute an
# assignment's referenced names ONCE so the taint fixpoint is set-membership, not a regex per
# tainted name per pass (which was O(n^3) on a long assignment chain — #296 final review).
_STANDALONE_REF = re.compile(r"(?<![.\w])([A-Za-z_]\w*)(?![\w=])")


def _split_top_level_eq(line: str) -> list[str]:
    """Split on `=` at bracket depth 0, excluding comparisons (`==`/`!=`/`<=`/`>=`),
    augmented (`+=`), and walrus (`:=`). (Strings are already blanked upstream.)"""
    parts: list[str] = []
    depth = 0
    start = 0
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "=" and depth == 0:
            nxt = line[i + 1] if i + 1 < n else ""
            if nxt == "=" or (line[i - 1] if i > 0 else "") in "=!<>+-*/%&|^@~:":
                if nxt == "=":
                    i += 1  # step over the second '=' of '=='
            else:
                parts.append(line[start:i])
                start = i + 1
        i += 1
    parts.append(line[start:])
    return parts


def _assign_targets(line: str) -> tuple[list[str], str] | None:
    """(target-names, value-expr) for a simple / annotated / chained (`a = b = v`) /
    tuple (`a, b = v`) / augmented (`x += v`) assignment, else None."""
    m = _AUG.match(line)
    if m:
        return [m.group(1)], m.group(2)
    segs = _split_top_level_eq(line)
    if len(segs) < 2:
        return None
    target_text = "".join(segs[:-1]).split(":", 1)[0]  # all-but-last are targets; drop annotation
    # Drop `self`/`cls`: for `self.q = request.args.get(...)`, _WORD.findall("self.q") yields
    # ["self", "q"], and tainting `self` made EVERY `redirect(self.anything)` in the file fire (#423).
    # KNOWN LIMITATION (PR #450 review): the taint model keys on BARE names, so the attribute
    # itself (`self.q`) is not tracked — a genuinely tainted `self.q = request...` followed by
    # `redirect(self.q)` is a false negative. Accepted: the broad `self`-taint FP it replaces was
    # worse; instance-attribute dataflow is out of scope for this line-level heuristic.
    targets = [w for w in _WORD.findall(target_text) if w not in ("self", "cls")]
    return targets, segs[-1]


def _split_top_level_commas(sig: str) -> list[str]:
    """Split a signature's parameter list on commas at bracket depth 0, so a comma inside
    an annotation (`Dict[str, int]`) or a default call doesn't split one parameter in two."""
    out: list[str] = []
    depth = 0
    start = 0
    for i, c in enumerate(sig):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(sig[start:i])
            start = i + 1
    out.append(sig[start:])
    return out


def _imported_markers(raw: str, *, filename: str | Path = "<unknown>") -> set[str]:
    """Names bound in this file to a fastapi/starlette request-data marker (`Query`/`Path`/…),
    resolved with real import semantics via `ast`. A name is a marker iff its LAST binding in
    source order is `from fastapi[.x] | starlette[.x] import <Marker>[ as name]`. Using the AST
    (rather than a regex over import lines) makes aliases (`Query as Q` → the bound name `Q`),
    import order / last-binding-wins shadowing, `;`-chained imports, and parenthesized or
    `\\`-continued lists all correct — the class of edge cases that regex approximations kept
    leaking (#296 review rounds 5-6). Relative imports (`from . import …`) are never framework.
    Degrades to `set()` on a syntactically invalid file (never raises)."""
    tree = safe_ast_parse(raw, filename=filename)
    if tree is None:
        return set()
    froms = [n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    froms.sort(key=lambda n: (n.lineno, n.col_offset))
    binding: dict[str, bool] = {}  # bound name -> resolves to a framework request-data marker
    for node in froms:
        module = "" if node.level else (node.module or "")  # a relative import is never the framework
        fw = _is_framework_module(module)
        for alias in node.names:
            binding[alias.asname or alias.name] = fw and alias.name in _MARKERS
    return {name for name, is_marker in binding.items() if is_marker}


def _fastapi_param_sources(lines: list[str], raw: str, *, filename: str | Path = "<unknown>") -> set[str]:
    """Names of parameters that are FastAPI/Starlette request-data bindings — a `def`
    signature parameter whose default is a framework marker call (`Query()/Path()/Body()/
    Form()/Cookie()/Header()/File()`), or whose `Annotated[...]` metadata carries one. Such a
    parameter IS request input, so its name seeds the taint set (issue #296). Only names bound
    to a framework marker count (`_imported_markers`, resolved from `raw` via AST); combined
    with the `def`-signature scoping this keeps a `pathlib.Path(...)` / SQLAlchemy `Query(...)`
    default from being misread as a request binding. Signature scan runs on the string/comment-
    blanked `lines`."""
    markers = _imported_markers(raw, filename=filename)
    if not markers:
        return set()
    # A marker CALL anywhere in the annotation means it is `Annotated[..., Query()]` metadata
    # (a bare `Marker(...)` never appears in a normal type annotation). Searching for the call
    # directly — instead of `Annotated\[[^\]]*…` — is agnostic to nested generics like
    # `Annotated[Optional[str], Query()]`, whose inner `]` the old bracket-bounded regex could
    # not cross (#296 final review).
    marker_call = re.compile(r"\b(?:" + "|".join(re.escape(m) for m in sorted(markers)) + r")\s*\(")
    text = "\n".join(lines)
    seeds: set[str] = set()
    for dm in _DEF.finditer(text):
        depth = 0
        i = dm.end() - 1  # positioned on the signature's opening '('
        n = len(text)
        while i < n:
            c = text[i]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        for param in _split_top_level_commas(text[dm.end():i]):
            segs = _split_top_level_eq(param)
            name_annot = segs[0]
            default = segs[-1].strip() if len(segs) > 1 else ""
            name = name_annot.split(":", 1)[0].strip()
            if not _NAME_ONLY.match(name):
                continue
            call = _DEFAULT_CALL.match(default)
            annotated_marker = "Annotated" in name_annot and marker_call.search(name_annot) is not None
            if (call and call.group(1) in markers) or annotated_marker:
                seeds.add(name)
    return seeds


def _tainted_vars(lines: list[str], raw: str, *, filename: str | Path = "<unknown>") -> set[str]:
    """Names assigned (anywhere in the file) from an untrusted source, transitively.

    Fixpoint over the file's assignments (simple / annotated / chained / tuple / augmented
    / walrus): a name is tainted if the value it is assigned from names an untrusted request
    accessor or an already-tainted name. Seeded with FastAPI/Starlette request-data
    parameters (`_fastapi_param_sources`, issue #296) so a typed `Query`/`Path`/`Body` param
    and anything derived from it taint too. Operates on string/comment-blanked lines (`raw` is
    the unblanked source, used only for AST import resolution). Over-tainting only ever makes
    the guard fire. Each assignment's direct-untrusted flag and referenced names are computed
    ONCE up front, then propagation is a worklist over a `referenced-name -> assignments` index,
    so tainting a name only re-examines the assignments that could newly taint. This is O(V+E)
    and **order-independent** — a forward OR a reverse-order assignment chain both converge
    linearly (the old regex-per-tainted-name-per-pass form was O(n^3); a plain in-place sweep is
    still O(n^2) on a reverse-order chain — #296 final review + re-review)."""
    prepared: list[tuple[list[str], bool, set[str]]] = []
    for line in lines:
        at = _assign_targets(line)
        pairs = ([at] if at else []) + [([name], value) for name, value in _walruses(line)]
        for targets, value in pairs:
            prepared.append((targets, _UNTRUSTED.search(value) is not None, set(_STANDALONE_REF.findall(value))))
    ref_index: dict[str, list[int]] = {}  # a referenced name -> the assignments that reference it
    for idx, (_targets, _direct, refs) in enumerate(prepared):
        for r in refs:
            ref_index.setdefault(r, []).append(idx)
    tainted: set[str] = set(_fastapi_param_sources(lines, raw, filename=filename))
    work: deque[str] = deque(tainted)
    for targets, direct, _refs in prepared:  # assignments tainted by a direct request accessor
        if direct:
            for t in targets:
                if t not in tainted:
                    tainted.add(t)
                    work.append(t)
    while work:  # a newly-tainted name taints the targets of every assignment referencing it
        for idx in ref_index.get(work.popleft(), ()):
            for t in prepared[idx][0]:
                if t not in tainted:
                    tainted.add(t)
                    work.append(t)
    return tainted


_URL_FOR_CALL = re.compile(r"(?:[\w.]+\.)?\burl_for\s*\(")


def _blank_url_for_calls(a: str) -> str:
    """Replace every `url_for(...)` call span with a space. `url_for` builds a vetted internal
    path, so untrusted input *inside* its arguments is not an open-redirect risk — only untrusted
    that survives OUTSIDE a url_for call is judged: a concatenation (`url_for('x') + request…`),
    or a transform on the result (`url_for(…).lower()`), or a bare tainted target. Bracket-matched;
    an unbalanced (multi-line) call keeps the remainder verbatim. Single forward pass, O(n) — the
    search resumes past each blanked span rather than restarting from the start (#296 final review
    + re-reviews: this replaced a substring test, then a whole-target test that mis-fired on a
    trailing `.lower()`, then an O(n^2) repeated-search-from-start form)."""
    out: list[str] = []
    pos = 0
    n = len(a)
    while pos < n:
        m = _URL_FOR_CALL.search(a, pos)
        if not m:
            out.append(a[pos:])
            break
        out.append(a[pos : m.start()])  # text before this url_for call, kept as-is
        depth = 0
        close = -1
        j = m.end() - 1  # url_for's `(`
        while j < n:
            c = a[j]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth == 0:
                    close = j
                    break
            j += 1
        if close == -1:  # unbalanced (multi-line) -> keep the remainder verbatim and stop
            out.append(a[m.start() :])
            break
        out.append(" ")  # the blanked url_for(...) span
        pos = close + 1
    return "".join(out)


def _untrusted_target(arg: str, tainted: set[str]) -> bool:
    """True if the redirect target derives from untrusted input. (`arg` is already
    string/comment-blanked, so a literal `"…request.args…"` reads as empty. `url_for(...)` call
    spans are blanked first — untrusted inside a vetted internal path is not an open redirect.)"""
    a = _blank_url_for_calls(arg.strip())
    if not a.strip():
        return False
    if _UNTRUSTED.search(a):  # a request accessor directly in the (non-url_for) target expression
        return True
    return any(_refs_name(t, a) for t in tainted)  # a tainted variable reference (not .name / name=)


_URL_KW = frozenset({"url", "to", "location", "redirect_to"})


def _sink_targets(line: str, paren: int) -> list[str]:
    """The redirect-target expressions in a sink call on this line: the first POSITIONAL
    argument, plus any keyword argument whose name is a redirect target (`url`/`to`/`location`/
    `redirect_to`). So `RedirectResponse(status_code=302, url=request.query_params['n'])` is
    inspected, not just the first argument (#296 final review — a target in a later or keyword
    argument used to be missed). Line-oriented: the sink call's argument span is taken up to its
    matching close paren (bracket-aware, so a nested `redirect(url_for(...))` is not truncated);
    a missing close (a multi-line call) degrades to the rest of the line."""
    depth = 0
    end = len(line)
    for i in range(paren, len(line)):
        c = line[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                end = i
                break
    inner = line[paren + 1 : end]
    args: list[str] = []
    depth = 0
    start = 0
    for idx, ch in enumerate(inner):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(inner[start:idx])
            start = idx + 1
    args.append(inner[start:])
    targets: list[str] = []
    positional_taken = False
    for arg in args:
        segs = _split_top_level_eq(arg)
        if len(segs) == 1:  # positional argument
            if not positional_taken:
                targets.append(segs[0])
                positional_taken = True
        elif segs[0].strip() in _URL_KW:  # a redirect-target keyword argument
            targets.append(segs[-1])
    return targets


class OpenRedirectGuard(Guard):
    id = "open-redirect"
    title = "No open redirect from user input"
    area = "Network requests"

    # redirect.py: redirect to a bare request-derived variable -> open-redirect.
    canary_plant = CanaryPlant(
        files={
            "redirect.py": (
                "from flask import redirect, request\n\n\n"
                "def go():\n    next_url = request.args.get(\"name\")\n    return redirect(next_url)\n"
            ),
        },
        expects=frozenset({"open-redirect/user-controlled-target"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        raw = read(f)
        blanked = _blank_strings_and_comments(raw)
        # The pragma counts only as a real comment on the line, never quoted in a string there
        # (#1040); the view keeps the tail RAW past a tokenize error, which is the old fallback.
        # It is split as the lexer splits (on "\n" alone, never `splitlines`), so a form feed
        # cannot shift the line numbers apart.
        view = comment_view(raw.replace("\r\n", "\n").replace("\r", "\n"), "python")
        pragma_lines = {i for i, vline in enumerate(view.split("\n"), start=1) if _PRAGMA.search(vline)}
        tainted = _tainted_vars(blanked, raw, filename=f)
        out: list[Finding] = []
        for i, line in enumerate(blanked, start=1):
            if i in pragma_lines:
                continue
            m = _SINK.search(line)
            if m and any(_untrusted_target(t, tainted) for t in _sink_targets(line, m.end() - 1)):
                out.append(Finding(
                    check_id=self.id,
                    severity="medium",
                    title="Redirect target built from user input (open redirect)",
                    location=f"{rel(root, f)}:{i}",
                    message=(
                        "This redirect target derives from request / untrusted input with no "
                        "allow-list — an attacker can set it to an external URL and bounce a "
                        "victim off your trusted domain (phishing, OAuth-token theft)."
                    ),
                    remediation=(
                        "Redirect only to a vetted internal target: `url_for(...)`, an allow-listed "
                        "path, or a relative path validated to start with a single `/`. Suppress an "
                        "audited case with `# security: allow-open-redirect`."
                    ),
                    rule="open-redirect/user-controlled-target",
                    standards=["OWASP:A01"],
                ))
        return out
