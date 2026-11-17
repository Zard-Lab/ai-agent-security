"""Guard: no path traversal in file serving / opening (checklist §3a).

Serving or opening a file at a path built from user input — `send_file("/data/" +
name)` or `open(base + name)` — lets `name = "../../etc/passwd"` escape the intended
directory and read (or, on write, plant) arbitrary files. The fix is to resolve the
final path and assert it stays within a hardcoded base dir (`Path(base).joinpath(
name).resolve().is_relative_to(base)`), or use a vetted `safe_join`/`secure_filename`.
CWE-22 / CWE-98. Closes (as a guard) checklist item `3a-path-traversal-file-serving`.

Fires HIGH on a file sink whose path argument is dynamic (concat / f-string /
`os.path.join` with a variable) and that carries no safety marker on the line:
  * serving sinks — `send_file`, `send_from_directory`, `FileResponse`;
  * `open(` built via concat / f-string / `os.path.join`.

Fires MEDIUM on a `Path(` constructor with an f-string / concat argument (Rule C) —
construction is one step removed from a file operation; `settings.`/`config.`
interpolations are exempt.

Fires CRITICAL when an LLM call result is used directly as a file path (Rule A /
MEDUSA-OUTPUT-PATH-001): the model output is attacker-controllable via prompt injection. Checked
sinks include `open`/`Path`/the serving sinks above, and destructive file-mutation sinks
`shutil.copy2?`/`copytree`/`move`/`rmtree` and `os.remove`/`unlink`/`rmdir`/`rename` — an
LLM-tainted path reaching one of these overwrites or deletes an attacker-chosen file rather than
just reading one.

(`load_prompt` / `load_prompt_from_config` traversal is owned by the dedicated
`langchain-load-prompt-traversal` guard — this guard does not duplicate it.)

Suppress an audited case with `# security: allow-path-traversal`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_SERVE = re.compile(r"\b(?:send_file|send_from_directory|FileResponse)\s*\(")
_OPEN = re.compile(r"\bopen\s*\(")
_SAFE = re.compile(
    r"\.resolve\s*\(|is_relative_to|safe_join|secure_filename|realpath|werkzeug\.utils"
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-path-traversal")

_FSTRING = re.compile(r"(?:^|[\s(,=+])[rR]?[fF]['\"]")
_CONCAT = re.compile(r"['\"]\s*\+|\+\s*['\"]")
# The multi-arg os.path.join(...) argument list (up to the first `)`).
_JOIN_ARGS = re.compile(r"os\.path\.join\s*\(([^)]*,[^)]*)")
# App-internal path ROOTS that are not request-derived: a config/instance attribute
# (`settings.X` / `config.X` / `conf.` / `cfg.` / `app.X` / `self.X`) or an ALL-CAPS module
# constant (`BASE_DIR`). Blanked out of the join args before the bare-variable check, so
# `os.path.join(BASE_DIR, "x")` / `os.path.join(settings.DATA_DIR, "x")` are NOT flagged, while
# a lowercase local like `os.path.join(user_dir, "x")` still is (PR #444 re-review; mirrors the
# Path() Rule-C `_CONFIG_ATTR` carve-out and langchain_load_prompt's `_CONST_ARG`).
_TRUSTED_PATH_ROOT = re.compile(
    r"\b(?:settings|config|conf|cfg|app|self)\s*\.\s*\w+"
    r"|\b[A-Z][A-Z0-9_]*\b"
)
# A bare identifier (a variable / attribute base) left in the args after string literals AND
# trusted roots are blanked. If any survives, a join component is a non-literal, non-app-internal
# value (a user-controllable dir or file).
_BARE_IDENT = re.compile(r"[A-Za-z_]\w*")
# A trusted CONTINUATION component: a join argument after the base dir that is, on its own,
# an ALL-CAPS module constant (`CONFIG_SUBDIR`). Deliberately narrower than
# `_TRUSTED_PATH_ROOT` and matched with `fullmatch`, not `search`:
#   * `self.`/`config.`/`app.` attributes are EXCLUDED here. An attribute is the absence of
#     information about a value's source, and `os.path.join(UPLOAD_DIR, self.filename)` with
#     `self.filename` straight off `request.args.get()` is the exact false negative the
#     first-argument-only rule was introduced to fix (#444 review).
#   * `fullmatch` means the WHOLE argument must be the constant, so `MY_CONST + user_input`
#     does not pass as trusted on the strength of the constant it contains.
_TRUSTED_JOIN_SEGMENT = re.compile(r"[A-Z][A-Z0-9_]*")
# Names the file binds to a request/user source. Such a name is NOT a trusted root however it
# is spelled: an ALL-CAPS `USERFILE = request.args.get("f")` looks exactly like a module
# constant. `_tainted_names` below walks each STATEMENT and binds every target that precedes a
# request source in it, across all three binding forms (assignment chain: plain, annotated,
# augmented and tuple; plus walrus and for-target). One literal pattern per form rather than a
# generated family or a nested-quantifier chain: a regex assembled from variables, or a
# quantified group inside a quantifier, is exactly the shape `redos/regex-injection` flags, and
# agentsec audits itself. Same-file binding only, which is the limit of a regex guard, as is
# multi-hop flow (`d = request.get_json()` then `SUB = d["p"]`). The residual exposure needs a
# name that is BOTH ALL-CAPS and holding request data; every conventionally-spelled local is
# still covered by the bare-variable rule.
#
# The taint scan runs per STATEMENT, not per physical line. A line can carry several assignment
# targets, and binding only the first one is how a request-sourced name kept its "trusted
# constant" reading past the base-dir position (#440-batch gate, 2026-08-02): `SUB += request…`
# never matched at all, `SUB = OTHER = request…` bound only `SUB`, and `x = 1; SUB = request…`
# bound only `x`. All three silenced a genuine traversal.
#
# The invariant: EVERY name bound to a request-sourced value is tainted, not just the first
# `=`-target on the physical line.
#
# That invariant rests on two PARTITIONS (source into statements, and a statement's head into
# targets), and each must be taken over the code's STRUCTURE, never over raw text (#444 gate,
# 2026-08-03). Both were text splits, and both silently un-tainted a name the previous
# line-based regex had caught:
#   * statements: `str.split` on a bare `;` cut `SUB = RAW.split(';')[0] + request…` in half,
#     stranding the target in a fragment with no `=`. `strip_python_strings` does NOT make this
#     safe: it blanks TRIPLE-quoted content only (`base.py`), as this file already notes at the
#     `os.path.join` arm. So in-literal `;` `,` `=` are masked (`_mask_literal_punctuation`)
#     FIRST. That also removes the mirror-image FALSE POSITIVE: `msg = 'x;SUB = request…'` used
#     to split into a fragment that read as a real binding of `SUB`.
#   * targets: `str.split(",")` shredded a subscripted annotation, so `SUB: dict[str, str] = …`
#     produced the non-target piece `" str] "`, and the `break` discarded the whole chain. So the
#     target list is split on TOP-LEVEL commas only (`_split_top_level_commas`), the same
#     bracket-depth rule the `os.path.join` argument list has always used.
# Known residual limits, ALL of them shared with the pre-rewrite regex (measured: no delta at
# either commit, so they are disclosed here rather than fixed under a regression fix). A
# statement is still bounded by a PHYSICAL newline, which cuts both ways: a parenthesised or
# backslash-continued RHS taints nothing (`SUB = (\n    request.args.get('d')\n)`), and a
# continuation line inside a call still reads as an assignment, so `emit(\n    CONFIG_SUB,
#  val=request.args.get('d'),\n)` over-taints `CONFIG_SUB`. Also: `with open(...) as SUB:`
# binds nothing, and an ALL-CAPS function parameter is not a binding this scan can see.
_REQUEST_SOURCE = re.compile(
    r"\b(?:request|req|flask\.request)\s*\.|\b(?:query_params|path_params)\b"
    r"|\b(?:args|form|params|query|body|files|cookies|headers)\s*\[|\binput\s*\("
)
# ONE step of a leading assignment chain: `A = `, `A, B = `, `A: T = `, `A += `. Applied
# repeatedly from the start of the statement, so `A = B = ` binds both. Deliberately NOT a single
# `(?:…)+` chain regex: that nests a quantifier inside a quantified group, the catastrophic-
# backtracking shape agentsec's own `redos` guard flags — and did flag, on this fix's first draft.
# A Python-side loop is linear by construction and needs no such pattern.
#
# Anchored at statement start (the original's intent) so a keyword argument
# (`f(path=request.args["p"])`) does not bind `path`. `(?!=)` keeps `==` out; `!=`/`<=`/`>=`
# cannot match, since `!`, `<` and `>` are not augmented-assignment operators here.
_ASSIGN_OP = re.compile(r"(?<![=!<>])(?://|\*\*|>>|<<|[-+*/%&|^@])?=(?!=)")
# One assignment target: a plain identifier, optionally annotated (`A: str`, `A: dict[str, str]`).
# Matched against a single TOP-LEVEL-comma-separated piece, so it carries no quantified group of
# its own; the annotation tail is `[^=]*` because a subscripted annotation may contain anything
# except the `=` that ends the target list.
_SINGLE_TARGET = re.compile(r"[ \t]*[A-Za-z_]\w*[ \t]*(?::[^=]*)?\Z")
_WALRUS_TARGET = re.compile(r"\(\s*(?P<walrus>[A-Za-z_]\w*)\s*:=\s*")
# The `for` target list, captured whole and split in Python. The comma-separated form is NOT
# expressed as `(?:,\s*\w+)*` — that nests a quantifier in a quantified group, the shape the
# `redos` guard is meant to catch (measured on #676, it currently does not; #675 tracks making
# it flag exactly this class).
# The capture MUST start on `[^\s=]` and MUST stay bounded (#676, the #674 shape): `[^\n=]*?`
# still contained the space, so it overlapped both neighbouring `\s+` runs and a bare `for`
# followed by a long whitespace run was partitioned combinatorially before the absent ` in `
# failed (2.3s at 2,000 chars, non-terminating at 8,000; the statement split above is
# line-bounded but uncapped). The disjoint first character removes the blow-up — `[^\s=]`, not
# `[^\s]`, so a leading `=` stays outside the capture language exactly as before. `{0,200}`
# caps residual work: a target list longer than 201 chars is not one we mine (a deliberate
# trade, pinned at the boundary by its test).
_LOOP_TARGET = re.compile(r"\bfor\s+(?P<loop>[^\s=][^\n=]{0,200}?)\s+in\s")
# Statement separators: a newline, or a `;` joining two statements on one line. Applied to
# literal-blanked source ONLY. A bare `;` inside `RAW.split(';')` is not a statement boundary,
# and `strip_python_strings` leaves single-line literals intact, so it cannot make this safe.
_STATEMENT_SPLIT = re.compile(r"[;\n]")
# A single-line string literal WITH its optional r/b/f/u prefix. Blanked before the statement
# split (so a `;` or `,` inside a literal is not read as code punctuation) and again before the
# os.path.join arm (so a static literal's identifier chars, or a leftover raw-string prefix, is
# not mistaken for a bare-variable path component, #423). Cannot span a newline by construction,
# so it can never mis-pair across lines the way a docstring-delimiter regex can.
_STR_LITERAL = re.compile(
    r'[rRbBfFuU]{0,2}(?:"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\')'
)
# The structural punctuation the two partitions read. Inside a literal it is DATA, not syntax, so
# it is neutralised there, but only it. Deleting the whole literal (the obvious move) also
# deletes an interpolated request source: `SUB = f"{request.args.get('d')}"` is a real binding and
# an f-string body is code. Masking to a space is the narrow form: it keeps the literal's width
# and every other character, so the source stays visible and neighbouring tokens stay separated.
_LITERAL_PUNCT = re.compile(r"[;,=]")


def _mask_literal_punctuation(src: str) -> str:
    """Blank `;` `,` `=` that sit INSIDE a single-line string literal (see `_LITERAL_PUNCT`)."""
    return _STR_LITERAL.sub(lambda m: _LITERAL_PUNCT.sub(" ", m.group(0)), src)


def _split_top_level_commas(text: str) -> list[str]:
    """Split `text` on commas at bracket depth 0.

    The one definition of "split a comma-separated list" in this module. A nested call's,
    subscript's or annotation's own commas are not top-level separators, so
    `SUB: dict[str, str]` is ONE assignment target and `os.path.join(f(a, b), c)` has TWO
    arguments. Depth is clamped at 0 so an unbalanced closer cannot disable splitting for the
    rest of the string (the function stays total on arbitrary target-repo text).
    """
    pieces: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            pieces.append(text[start:i])
            start = i + 1
    pieces.append(text[start:])
    return pieces


def _tainted_names(src: str) -> frozenset[str]:
    """Every name in `src` bound to a request-sourced value.

    Per statement rather than per physical line, covering all three binding forms: an assignment
    chain (including augmented and multi-target), a walrus, and a `for` target. Only targets
    appearing BEFORE the request source in the statement are bound, so names on the source's own
    right-hand side are never mistaken for targets.
    """
    names: set[str] = set()
    # Neutralise in-literal punctuation FIRST: statement and target boundaries are properties of
    # the code, and a `;`/`,`/`=` inside a literal is none of those.
    for stmt in _STATEMENT_SPLIT.split(_mask_literal_punctuation(src)):
        found = _REQUEST_SOURCE.search(stmt)
        if not found:
            continue
        head = stmt[: found.start()]
        # Walk the leading `A = B = ` chain: each `=` operator closes a target list, and the chain
        # ends at the first segment that is not one. Splitting on the operator and validating each
        # comma-separated piece keeps every pattern quantifier-free, so nothing here can backtrack.
        pos = 0
        for op in _ASSIGN_OP.finditer(head):
            pieces = _split_top_level_commas(head[pos : op.start()])
            if not all(_SINGLE_TARGET.fullmatch(piece) for piece in pieces):
                break  # not a target list — the assignment chain has ended
            names.update(piece.split(":")[0].strip() for piece in pieces)
            pos = op.end()
        for pattern, group in ((_WALRUS_TARGET, "walrus"), (_LOOP_TARGET, "loop")):
            for m in pattern.finditer(head):
                pieces = _split_top_level_commas(m.group(group))
                if all(_SINGLE_TARGET.fullmatch(piece) for piece in pieces):
                    names.update(piece.split(":")[0].strip() for piece in pieces)
    return frozenset(names)

# Rule C: Path() constructor with dynamic arg (f-string / concat only — bare variables
# are too common in tooling code; only assembled strings are flagged).
_PATH_CTOR = re.compile(r"\bPath\s*\(")

# Config-attribute interpolation in a Path() arg — `settings.DATA_DIR` / `config.x` /
# `conf.` / `cfg.` are app-internal config, not request-derived; exempt from Rule C
# (mirrors the langchain-load-prompt guard's _CONFIG_ATTR carve-out).
_CONFIG_ATTR = re.compile(r"\b(?:settings|config|conf|cfg|app\.config)\s*\.", re.IGNORECASE)

# Rule A: LLM call result assigned to a variable (MEDUSA-OUTPUT-PATH-001). LLM-specific:
# bare `.create(`/`.generate(`/`.complete(` (ORM/SDK) are accepted only on an LLM-shaped
# receiver; `.invoke`/`.ainvoke`/`.run_sync` and the OpenAI/Anthropic create forms are
# matched directly. Excludes subprocess/asyncio.
_LLM_RESULT = re.compile(
    r"(\w+)\s*=\s*(?:await\s+)?(?:"
    r"[\w.]*\.(?:invoke|ainvoke|run_sync)\s*\("
    r"|\b(?:llm|agent|chain|model|client|graph)\w*\.(?:run|arun|generate|complete)\s*\("
    r"|[\w.]*chat\.completions\.create\s*\("
    r"|[\w.]*\.messages\.create\s*\("
    r")"
)

# File sinks checked in Rule A pass-2. Widened (llm-seclint's LlmPathTraversalRule,
# verified against real source) beyond read/serve sinks to destructive file-mutation sinks:
# an LLM-tainted path reaching `shutil.copy*/move/rmtree` or `os.remove/unlink/rmdir/rename`
# is the SAME traversal risk one step further — read-or-plant becomes overwrite-or-delete.
_FILE_SINKS = re.compile(
    r"\b(?:open|send_file|send_from_directory|FileResponse|Path"
    r"|shutil\.(?:copy2?|copytree|move|rmtree)|os\.(?:remove|unlink|rmdir|rename))\s*\("
)


def _dynamic_path(arg: str, tainted: frozenset[str] = frozenset()) -> bool:
    a = arg.strip()
    if not a:
        return False
    if _FSTRING.search(a):
        return True
    if _CONCAT.search(a):
        return True
    # os.path.join arm. Blank single-line string literals first so a fully static join
    # (os.path.join("data", "x.txt"), whose literals contain identifier chars) is not read
    # as dynamic (#423). But a bare-variable component that survives blanking IS dynamic,
    # including a variable DIRECTORY with a static filename: os.path.join(var, "static.txt")
    # can still traverse if `var` is user-controlled (PR #444 review). strip_python_strings
    # only blanks TRIPLE-quoted strings, so single-line ones survive up to here.
    m = _JOIN_ARGS.search(_STR_LITERAL.sub("", a))
    if not m:
        return False
    # Drop the app-internal ROOT: the base-dir argument, plus any LEADING RUN of trusted
    # components that follows it. Blanking trusted-looking tokens across the WHOLE argument
    # list (the original form) meant one anywhere silenced the call, so
    # `os.path.join(UPLOAD_DIR, self.filename)` with `self.filename` straight off
    # `request.args.get()` went silent, as did the `config.`/`app.`/ALL-CAPS variants
    # (#444 review). Restricting it to the first argument alone then false-positived on a
    # legitimate 3-argument join whose app-internal constant sits in the middle,
    # `os.path.join(BASE_DIR, CONFIG_SUBDIR, "report.txt")` (#423). The leading run splits
    # the difference: everything up to the first argument that is not recognisably
    # app-internal is exempt, and that argument and everything after it is still checked.
    # The continuation vocabulary (`_TRUSTED_JOIN_SEGMENT`) is deliberately narrower than
    # the base-dir one: an ALL-CAPS constant only, never an attribute, and never a name
    # this file assigns from request data.
    arg_list = m.group(1)
    head, sep, tail = _split_first_join_arg(arg_list)
    args = _blank_trusted_root(head, tainted) + sep + _drop_trusted_leading_run(tail, tainted)
    return bool(_BARE_IDENT.search(args))


def _blank_trusted_root(first_arg: str, tainted: frozenset[str]) -> str:
    """Blank the app-internal base-dir vocabulary out of the FIRST join argument.

    A name the file assigns from request data is kept (not blanked): `USERFILE =
    request.args.get("f")` is user input whatever its casing says."""
    return _TRUSTED_PATH_ROOT.sub(
        lambda m: m.group(0) if m.group(0) in tainted else "", first_arg
    )


def _drop_trusted_leading_run(rest: str, tainted: frozenset[str]) -> str:
    """Drop the leading run of trusted components from the post-base-dir arguments.

    Returns the remaining argument text, starting at the first component that is not a
    recognised app-internal constant (or a blanked string literal). That component and
    every argument after it stay under the bare-variable check."""
    while rest.strip():
        nxt, sep, tail = _split_first_join_arg(rest)
        if not _is_trusted_component(nxt, tainted):
            return rest
        if not sep:
            return ""
        rest = tail
    return rest


def _is_trusted_component(arg: str, tainted: frozenset[str]) -> bool:
    a = arg.strip()
    if not a:
        # An already-blanked string literal: static, so the run continues through it.
        return True
    if a in tainted:
        return False
    return _TRUSTED_JOIN_SEGMENT.fullmatch(a) is not None


def _split_first_join_arg(arg_list: str) -> tuple[str, str, str]:
    """Split a join argument list into (first_arg, separator, rest), bracket-aware.

    A nested call's own commas must not be mistaken for the top-level split point, so this
    defers to `_split_top_level_commas`, the module's single definition of that rule, shared
    with the assignment-target split (#444 gate: the target split had its own naive `,` split
    and got it wrong). Returns the whole string as `first` when there is no top-level comma
    (a single-argument join). Re-joining the tail with `,` is exact: a top-level separator is
    always the single character that was removed."""
    first, *rest = _split_top_level_commas(arg_list)
    if not rest:
        return arg_list, "", ""
    return first, ",", ",".join(rest)


def _first_arg(text_after_open: str) -> str:
    """Extract just the first argument from the text that follows an opening paren.

    Takes the substring up to the first unbalanced `)` or `,`, stripping trailing
    whitespace.  This avoids a too-broad match when docstrings contain patterns like
    `load_prompt(path) and ...` where the text after `)` is not Python.
    """
    depth = 0
    for j, ch in enumerate(text_after_open):
        if ch in ("(", "[", "{"):
            depth += 1
        elif ch in (")", "]", "}"):
            if depth == 0:
                return text_after_open[:j].strip()
            depth -= 1
        elif ch == "," and depth == 0:
            return text_after_open[:j].strip()
    return text_after_open.strip()


class PathTraversalGuard(Guard):
    id = "path-traversal"
    title = "No path traversal in file serving / opening"
    area = "Files"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # llm_file_path.py: LLM invoke result used directly as the path argument to open() ->
    # fires path-traversal/llm-output-as-path (CRITICAL, MEDUSA-OUTPUT-PATH-001).
    # The build_path() function assembles a Path() from an f-string (no config-attr,
    # no safety marker) -> fires path-traversal/path-constructor (MEDIUM, Rule C).
    # Must NOT contain: security: allow-path-traversal (pragma silences guard).
    # Must NOT contain: .resolve() / is_relative_to / safe_join (safety markers silence guard).
    # Must NOT contain: settings. / config. before the Path f-string (would exempt Rule C).
    # send_file on a concatenated path -> path traversal (fires path-traversal).
    canary_plant = CanaryPlant(
        files={
            "llm_file_path.py": (
                "from pathlib import Path\n"
                "from langchain_openai import ChatOpenAI\n"
                "\n"
                "llm = ChatOpenAI()\n"
                "\n"
                "\n"
                "def fetch_doc(query: str) -> str:\n"
                "    response = llm.invoke(query)\n"
                '    return open(response, "r").read()\n'
                "\n"
                "\n"
                "def build_path(base: str, name: str) -> Path:\n"
                '    return Path(f"{base}/{name}")\n'
            ),
            "serve.py": (
                "from flask import send_file\n\n\n"
                "def download(name: str):\n    return send_file(\"/data/\" + name)\n"
            ),
        },
        expects=frozenset({
            "path-traversal/unsanitized-path",
            "path-traversal/llm-output-as-path",
            "path-traversal/path-constructor",
        }),
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
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
                out.extend(self._scan_llm_paths(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        # Strip triple-quoted docstrings so patterns inside them don't fire (e.g.
        # the load_prompt examples in langchain_load_prompt.py's module docstring).
        src = strip_python_strings(read(f), filename=f)
        # The pragma counts only as a real comment on the line, never quoted in a string there
        # (#1040), numbered on the lines walked below (a form feed in a docstring shifts the raw
        # count, #1132).
        pragmas = pragma_line_set(_PRAGMA, src, dialect="python")
        # Names this file assigns from request/user input. They are never trusted join
        # roots, however constant-looking they are spelled (`USERFILE = request.args...`).
        tainted = _tainted_names(src)
        for i, line in enumerate(src.splitlines(), start=1):
            if line.lstrip().startswith("#") or i in pragmas or _SAFE.search(line):
                continue
            hit = False
            rule = "path-traversal/unsanitized-path"
            severity: Severity = "high"
            title = "File path built from untrusted input (path traversal)"
            message = (
                "This path is assembled from a variable with no base-directory check "
                "— `../../etc/passwd` escapes the intended folder and reads (or, on "
                "write, plants) arbitrary files."
            )
            remediation = (
                "Resolve the final path and assert it stays under a hardcoded base "
                "(`p = Path(base).joinpath(name).resolve(); assert "
                "p.is_relative_to(base)`), or use `safe_join`/`secure_filename`. "
                "Suppress with `# security: allow-path-traversal`."
            )

            m = _SERVE.search(line)
            if m and _dynamic_path(line[m.end():].rstrip().rstrip(")"), tainted):
                hit = True
            if not hit:
                o = _OPEN.search(line)
                if o and _dynamic_path(line[o.end():].rstrip().rstrip(")"), tainted):
                    hit = True
            # NB: load_prompt traversal is owned by the dedicated `langchain-load-prompt-traversal`
            # guard (which is more precise — it exempts settings./config. attrs, Path(...), and
            # literal os.path.join, and has a multi-line containment look-back). This guard does
            # not duplicate it.
            # Rule C: Path() constructor with f-string / concat argument (MEDIUM — construction
            # is one step removed from a file operation).
            if not hit:
                pc = _PATH_CTOR.search(line)
                if pc:
                    first = _first_arg(line[pc.end():])
                    # Only fire on assembled (f-string / concat) args, not bare variables —
                    # bare `Path(var)` is idiomatic in CLI/tool code and generates too much noise.
                    # Exempt config-attribute interpolation (settings./config.) — app-internal
                    # path assembly, not request-derived.
                    if _dynamic_path(first, tainted) and not _CONFIG_ATTR.search(first):
                        hit = True
                        rule = "path-traversal/path-constructor"
                        severity = "medium"
                        title = "Path() constructed from dynamic argument (path traversal risk)"
                        message = (
                            "`Path()` is called with an assembled argument (f-string / concat) "
                            "— if the interpolated values are user- or LLM-supplied they can "
                            "introduce `../../` traversal sequences (CWE-22). Construction alone "
                            "is one step from a file operation, hence MEDIUM."
                        )
                        remediation = (
                            "Resolve and assert containment before any file operation: "
                            "`p = Path(base).joinpath(name).resolve(); "
                            "assert p.is_relative_to(base)`. "
                            "Suppress with `# security: allow-path-traversal`."
                        )
            if hit:
                out.append(
                    Finding(
                        check_id=self.id,
                        severity=severity,
                        title=title,
                        location=f"{rel(root, f)}:{i}",
                        message=message,
                        remediation=remediation,
                        rule=rule,
                        standards=["OWASP:A01"],
                    )
                )
        return out

    def _scan_llm_paths(self, root: Path, f: Path) -> list[Finding]:
        """Rule A (MEDUSA-OUTPUT-PATH-001): two-pass per-file scan.

        Pass 1 collects variable names assigned from LLM call results
        (invoke / generate / complete / ainvoke / arun / create).
        Pass 2 checks whether any of those variables (or their .content / .text /
        ["content"] proxies) appear as arguments to file-sink calls.
        """
        out: list[Finding] = []
        # Strip docstrings to avoid matching examples in module-level documentation.
        src = strip_python_strings(read(f), filename=f)
        lines = src.splitlines()
        # Both passes honour a pragma only as a real comment on the line (#1040), numbered on these
        # lines (a form feed in a docstring shifts the raw count, #1132).
        pragmas = pragma_line_set(_PRAGMA, src, dialect="python")

        # Pass 1: collect LLM-result variable names with the line(s) they're assigned on.
        llm_var_lines: dict[str, list[int]] = {}
        for idx, line in enumerate(lines):
            if idx + 1 in pragmas:
                continue
            for m in _LLM_RESULT.finditer(line):
                llm_var_lines.setdefault(m.group(1), []).append(idx)

        if not llm_var_lines:
            return out

        def _same_block(assign_idx: int, sink_idx: int) -> bool:
            # The sink is in the same function/block as the assignment iff no non-blank
            # column-0 line sits strictly between them (a col-0 line means we left the
            # enclosing function), so a `response` from an LLM in one function and an
            # unrelated `open(response)` in another do not associate.
            for k in range(assign_idx + 1, sink_idx):
                ln = lines[k]
                if ln.strip() and len(ln) - len(ln.lstrip()) == 0:
                    return False
            return True

        # Pass 2: look for those vars inside file-sink call arguments, scoped to the
        # function in which the variable was assigned from an LLM call.
        for i, line in enumerate(lines, start=1):
            sink_idx = i - 1
            if i in pragmas or _SAFE.search(line):
                continue
            sink = _FILE_SINKS.search(line)
            if not sink:
                continue
            arg_region = line[sink.end():]
            matched = False
            for var, assign_idxs in llm_var_lines.items():
                vp = re.compile(
                    r"\b" + re.escape(var) + r"\b"
                    r'(?:\.(?:content|text)|\[(?:"content"|\'content\')\])?'
                )
                if not vp.search(arg_region):
                    continue
                if any(a < sink_idx and _same_block(a, sink_idx) for a in assign_idxs):
                    matched = True
                    break
            if matched:
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="critical",
                        title="LLM call result used as file path (MEDUSA-OUTPUT-PATH-001)",
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "LLM call result used directly as a file path. "
                            "The model output is attacker-controllable via prompt injection "
                            "— a crafted input can make the LLM emit ../../etc/passwd or "
                            "any attacker-chosen path."
                        ),
                        remediation=(
                            "Never use model output as a file path without containment. "
                            "Resolve and assert: `p = Path(base).joinpath(llm_out).resolve(); "
                            "assert p.is_relative_to(base)`. "
                            "Suppress with `# security: allow-path-traversal`."
                        ),
                        rule="path-traversal/llm-output-as-path",
                        standards=["OWASP:A01", "OWASP-LLM:LLM02"],
                    )
                )
        return out
