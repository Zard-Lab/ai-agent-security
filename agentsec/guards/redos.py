"""Guard: no catastrophic-backtracking regex (ReDoS) (checklist §3a).

A regex with a nested quantifier — `(a+)+`, `(.*)*`, `(\\d+)*` — can take
exponential time on a crafted input, hanging the worker that evaluates it (CWE-1333,
regular-expression denial of service). On a request-handling path one such pattern
plus one malicious string pins a CPU core.

Flags a `re.` call (or a `re`-style pattern) whose pattern literal contains a group
ending in `+`/`*` that is itself immediately quantified by `+`/`*`. Fires MEDIUM.
Suppress an audited (bounded-input) case with `# security: allow-redos` on the line.

Also flags regex INJECTION (CWE-730/CWE-943, distinct bug class from the backtracking
check above): a `re.*` call whose PATTERN argument is itself built from untrusted input
(f-string, concatenation, `.format()`) without `re.escape()` on the tainted portion. An
attacker-controlled pattern can match/reject arbitrary strings regardless of whether it
also happens to backtrack. Same suppression pragma covers both sub-checks. An interpolated
name counts as untrusted unless it is an ALL_CAPS constant or the file's AST proves every
binding of it is a literal, a literal composition, or `re.escape(...)` (`_clean_bindings`).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import NamedTuple

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    split_call_args,
    strip_python_line_comment,
    strip_python_strings,
)

_RE_CALL = re.compile(r"\bre\.(?:compile|match|search|fullmatch|sub|subn|findall|finditer|split)\s*\(")
# A group re-quantified by +/* whose inner quantifier is at an OVERLAP boundary: immediately before
# the closing `)` (`(a+)+`, `(\w+)+`, `(.*)*`, `(\s*\w+)+`) OR immediately before a top-level `|`
# (`(a+|b)+` — a quantifier ending one alternate branch is equally catastrophic, PR #439 review).
# Group-final/branch-final is required (issue #424): a quantifier EARLIER in a fixed sequence
# (`(foo+bar)*`, where required literals follow) is benign/linear and must NOT match.
# An overlapping inner quantifier is `+`, `*`, or an open-ended `{n,}` — the three forms that
# let one iteration consume what the next could have. Factored out because the branch-final case
# below originally accepted only `[+*]`, so `(a{2,}|b)+` regressed out of detection while the
# group-final `(a{2,})+` stayed in — catastrophic backtracking confirmed on the missed form,
# doubling per two added characters (#439 review).
_INNER_QUANT = r"(?:[+*]|\{\d+,\})"
_NESTED = re.compile(
    r"\([^()]*" + _INNER_QUANT + r"\)[+*]"
    r"|\([^()]*" + _INNER_QUANT + r"\|[^()]*\)[+*]"
)
# A repeated group is LINEAR-safe (not ReDoS) when each iteration is anchored by a REQUIRED literal
# separator at its start, so iterations cannot overlap: `(?:\.\d+)*`, `(\s+[A-Z][a-z]+)+`,
# `([a-z]+-[a-z]+)+`. Catastrophic shapes start the unit with a quantified class or an alternation —
# `(a+)+`, `(\w+)+`, `(a|ab)*` — and are NOT matched here, so they still fire. The `(?![*?])` after
# the separator excludes an OPTIONAL separator (`(\s*\w+)+`), which would NOT anchor iterations.
# The anchor does NOT have to be the group's FIRST element. `(?:\s*\.\s*\w+)*` is linear-safe:
# the `\s*` is optional, but the `\.` after it is still REQUIRED, so every iteration must consume
# it and iterations still cannot overlap. Requiring position 1 flagged that shape as catastrophic
# when measurement shows it is flat linear (415 -> 6415 chars costs 0.145 -> 0.963 ms, versus
# `(a+)+$` doubling per added character). `_OPTIONAL_PREFIX` therefore allows a run of optional
# atoms before the required separator, and nothing else: an atom that is itself optional cannot
# anchor, which is what the `(?![*?])` after the separator continues to enforce (#439 re-review).
_OPTIONAL_PREFIX = r"(?:(?:\\[sSwWdD]|\[[^\]]*\]|\\.)[*?])*"
_DISJOINT_SAFE = re.compile(
    r"\((?:\?:)?" + _OPTIONAL_PREFIX + r"(?:\\s|\\\.|[-_/:,])\+?(?![*?])[^()|]*\)[+*]"
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-redos")

# Regex-injection: the PATTERN argument (not the subject string) built from untrusted
# input — an f-string, a `+` concatenation with a variable, or a `.format(` call — right
# at the call site. Interprocedural (pattern built on an earlier line, then passed via a
# variable) is a known, accepted limitation of a single-line static heuristic, same class
# of gap already documented elsewhere in this codebase for regex-based guards.
_DYNAMIC_PATTERN_ARG = re.compile(
    r"""\bre\.(?:compile|match|search|fullmatch|sub|subn|findall|finditer|split)\s*\(\s*"""
    r"""(?:"""
    r"""f['"]"""  # f-string: re.compile(f"...")
    r"""|(?:['"][^'"]*['"]|\w[\w.\[\]]*)\s*\+\s*(?:['"][^'"]*['"]|\w[\w.\[\]]*)"""  # concat: "..." + x  or  x + "..."
    r"""|['"][^'"]*['"]\s*\.\s*format\s*\("""  # .format(): "...".format(x)
    r""")"""
)
_RE_ESCAPE = re.compile(r"\bre\.escape\s*\(")

# Regex-injection only matters when the interpolated pattern portion is actually attacker-
# controlled. Without a taint check the rule fired on config-driven pattern COMPOSITION
# (`re.compile(BASE_PATTERN + "$")`, `re.compile(f"^.{{1,{MAX_LEN}}}$")` — module constants),
# the batch's single largest FP source (#395 H2). An ALL_CAPS name is treated as a constant by
# convention. (Deliberately broader than reusing `log_injection._USER_INPUT`, whose request-shaped
# allow-list would MISS the canary's own `user_input` and a plain param `u` — both genuinely
# tainted; a constant-exclusion superset keeps those firing.)
#
# Name case alone read idiomatic literals as taint: a lowercase module literal (`date_expr`) and a
# class literal read through `self.` (celery's `self._range`) both fired, as did a name bound to
# `re.escape(...)` on the line above (#689): 7 of 11 measured real-world findings (#688). So a
# name is also clean when the file's own AST proves it: see `_clean_bindings`.
_CONSTANT_IDENT = re.compile(r"^[A-Z_][A-Z0-9_]*$")
# A dotted name (`date_expr`, `self._range`, `auth_call.pattern`). Linear: each repetition needs a
# literal `.`, which `\w` cannot match.
_CHAIN = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")
# A literal closes on its OWN quote char, so `"'"` or `f"{d['k']}"` cannot pair across code and
# swallow a receiver or operand (#1020 M1). Linear: the two alternatives inside each `*` start on
# disjoint chars (a backslash, or anything else but the quote).
_FSTRING_LITERAL = re.compile(r"""f("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')""")
_STRING_LITERAL = re.compile(r"""(?:rf|fr|f|r|b)?(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')""")
# Identifiers that are call machinery, not an interpolated value.
_NON_VALUE_IDENTS = frozenset({"re", "format", "escape"})
_SELF_HEADS = frozenset({"self", "cls"})
# A call or attribute that can bind a name or attribute without a visible binding node. Its presence
# anywhere in the file switches resolution off, exactly like a star import.
_DYNAMIC_NAMESPACE_CALLS = frozenset({"setattr", "globals", "locals", "vars", "exec"})
_DYNAMIC_NAMESPACE_ATTRS = frozenset({"__dict__", "__setattr__"})


class _Bindings(NamedTuple):
    """What `_clean_bindings` proved clean in one file."""

    names: frozenset[str]
    # (first line, last line, clean attributes) per class, for resolving `self.X` / `cls.X`
    class_attrs: tuple[tuple[int, int, frozenset[str]], ...]

    def attrs_at(self, lineno: int) -> frozenset[str]:
        """Clean attributes of the innermost class whose span holds `lineno` (none outside a class)."""
        best: tuple[int, frozenset[str]] | None = None
        for first, last, attrs in self.class_attrs:
            if first <= lineno <= last and (best is None or first > best[0]):
                best = (first, attrs)
        return best[1] if best else frozenset()


_NO_BINDINGS = _Bindings(frozenset(), ())


def _is_re_escape(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "escape"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "re"
    )


def _unseen_binding(node: ast.AST) -> bool:
    """True iff `node` can bind a name or attribute this resolver cannot see."""
    if isinstance(node, ast.ImportFrom):
        return any(a.name == "*" for a in node.names)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in _DYNAMIC_NAMESPACE_CALLS
    if not isinstance(node, ast.Attribute):
        return False
    # `sys.modules[__name__].x = v` rebinds a module name through the module object; any
    # `sys.modules` reference counts, so an alias (`mod = sys.modules[__name__]`) is covered too
    is_sys_modules = node.attr == "modules" and isinstance(node.value, ast.Name) and node.value.id == "sys"
    return is_sys_modules or node.attr in _DYNAMIC_NAMESPACE_ATTRS


def _simple_binding(node: ast.AST) -> tuple[ast.Name, ast.expr] | None:
    """`(target, value)` for a single-name `x = v`, `x: T = v` or `(x := v)`, else None."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0], node.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
        return node.target, node.value
    if isinstance(node, ast.NamedExpr):
        return node.target, node.value
    return None


def _opaque_bindings(node: ast.AST) -> list[str]:
    """Names `node` binds without an `ast.Name` store: a parameter, a def/class, an import, an
    `except ... as`, a match capture."""
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
        a = node.args
        params = [p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg) if p is not None]
        return params if isinstance(node, ast.Lambda) else [*params, node.name]
    if isinstance(node, ast.ClassDef):
        return [node.name]
    if isinstance(node, ast.Import | ast.ImportFrom):
        return [(a.asname or a.name).split(".")[0] for a in node.names]
    if isinstance(node, ast.ExceptHandler | ast.MatchAs | ast.MatchStar):
        return [node.name] if node.name else []
    if isinstance(node, ast.MatchMapping):
        return [node.rest] if node.rest else []
    return []


def _value_deps(node: ast.expr) -> set[str] | None:
    """The names `node` needs to be clean to be clean itself, or None if it can never be clean.

    A clean value is a str/int literal, `re.escape(...)`, an ALL_CAPS name (the sink rule's own
    convention), or an f-string / `+` composition of clean values. Iterative, so a deeply nested
    concatenation in a hostile file cannot exhaust the recursion limit."""
    deps: set[str] = set()
    stack: list[ast.expr] = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, ast.Constant):
            if not isinstance(n.value, str | int):
                return None
        elif isinstance(n, ast.Name):
            if not _CONSTANT_IDENT.match(n.id):
                deps.add(n.id)
        elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            stack += (n.left, n.right)
        elif isinstance(n, ast.JoinedStr):
            stack += n.values
        elif isinstance(n, ast.FormattedValue):
            stack.append(n.value)
            if n.format_spec is not None:
                stack.append(n.format_spec)
        elif not _is_re_escape(n):
            return None
    return deps


def _clean_bindings(tree: ast.AST | None) -> _Bindings:
    """The names, and per-class `self.`/`cls.` attributes, this file binds only to clean values.

    A name is clean iff it has at least one binding and EVERY binding of it anywhere in the module
    is a single-name `=`, `: T =` or `:=` of a clean value (see `_value_deps`). Any other binding
    makes it dirty: a parameter, a loop/with/comprehension target, unpacking, augassign, `del`, a
    def/class, an import, `except ... as`, a match capture. Bindings are unioned across all scopes,
    so a name that is a literal in one function and a parameter in another stays dirty (it fails
    closed: some FPs, never a cleared taint). A star import or a dynamic namespace write
    (`setattr`, `globals()`, `locals()`, `vars()`, `exec`, `__dict__`, `__setattr__`, any
    `sys.modules` reference) anywhere switches it off.

    An attribute `X` is clean inside class `C` iff `X` is a clean name, has a plain (unannotated)
    `X = ...` in `C`'s own body, is never annotated in ANY class body (a dataclass/pydantic/attrs
    field default is constructor-supplied, and an inherited `__init__` still sets it), and is never
    an attribute store/del target anywhere in the file (`self.X = p`, `obj.X = v`). Not modelled: a
    subclass or a write in ANOTHER module."""
    if tree is None:
        return _NO_BINDINGS
    values: dict[str, list[ast.expr]] = {}
    simple_targets: set[int] = set()        # id() of the Name nodes that are simple-binding targets
    name_stores: list[ast.Name] = []
    dirty: set[str] = set()
    annotated: set[str] = set()
    attr_stored: set[str] = set()
    classes: list[tuple[int, int, set[str]]] = []
    for node in ast.walk(tree):
        if _unseen_binding(node):
            return _NO_BINDINGS
        binding = _simple_binding(node)
        if binding is not None:
            target, value = binding
            values.setdefault(target.id, []).append(value)
            simple_targets.add(id(target))
        dirty.update(_opaque_bindings(node))
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store | ast.Del):
            name_stores.append(node)
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store | ast.Del):
            attr_stored.add(node.attr)
        elif isinstance(node, ast.ClassDef):
            plain: set[str] = set()
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    plain.update(t.id for t in stmt.targets if isinstance(t, ast.Name))
                elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    annotated.add(stmt.target.id)
            classes.append((node.lineno, node.end_lineno or node.lineno, plain))
    dirty.update(n.id for n in name_stores if id(n) not in simple_targets)

    # Least fixpoint by dependency counting: a name turns clean once every name its values need is
    # clean. Linear, so a long assignment chain in a hostile file cannot slow-DoS the scan. A cycle
    # (`a = a + "x"`) or a dependency on a dirty or unbound name never resolves: it stays dirty.
    waiting: dict[str, int] = {}
    dependents: dict[str, list[str]] = {}
    for name, vals in values.items():
        if name in dirty:
            continue
        needs: set[str] = set()
        for v in vals:
            deps = _value_deps(v)
            if deps is None:
                break
            needs |= deps
        else:
            waiting[name] = len(needs)
            for dep in needs:
                dependents.setdefault(dep, []).append(name)
    ready = [name for name, count in waiting.items() if count == 0]
    clean: set[str] = set()
    while ready:
        name = ready.pop()
        clean.add(name)
        for dependent in dependents.get(name, ()):
            waiting[dependent] -= 1
            if waiting[dependent] == 0:
                ready.append(dependent)

    class_attrs = tuple(
        (first, last, frozenset(n for n in plain if n in clean and n not in annotated and n not in attr_stored))
        for first, last, plain in classes
    )
    return _Bindings(frozenset(clean), class_attrs)


def _chain_is_clean(chain: str, clean: frozenset[str], clean_attrs: frozenset[str]) -> bool:
    parts = chain.split(".")
    if len(parts) == 1 and parts[0] in clean:
        return True
    if len(parts) == 2 and parts[0] in _SELF_HEADS and parts[1] in clean_attrs:
        return True
    # Any other chain (`auth_call.pattern`, `obj.pat`) is clean only if every part is call machinery
    # or an ALL_CAPS constant, the rule before bindings were resolved.
    return all(p in _NON_VALUE_IDENTS or _CONSTANT_IDENT.match(p) for p in parts)


def _fstring_fields(body: str) -> list[str] | None:
    """The top-level `{field}` texts of an f-string body, or None when a field cannot be read.

    `{{`/`}}` escapes are literal text, a nested format-spec field stays inside its parent
    (`u:{W}`), and a quoted span inside a field is skipped, so its braces don't count (`'}' + u`).
    None means the line scan lost the field: one left open (a same-quote string inside it, legal
    since 3.12, closed the literal early), a stray `}`, or an unterminated quote inside a field."""
    fields: list[str] = []
    depth = start = i = 0
    while i < len(body):
        ch = body[i]
        if depth == 0:
            if body[i:i + 2] in ("{{", "}}"):
                i += 1
            elif ch == "}":
                return None
            elif ch == "{":
                depth, start = 1, i + 1
        elif ch in "'\"":
            i = body.find(ch, i + 1)
            if i < 0:
                return None
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if not depth:
                fields.append(body[start:i])
        i += 1
    return None if depth else fields


def _code_chains(text: str) -> list[str] | None:
    """The dotted names `text` reads as code, or None if an f-string field in it cannot be read.

    An f-string's fields are read recursively (a nested f-string's own fields count), then every
    string literal is blanked and the names left over are collected, so a quoted key (`d['name']`)
    is never read as a name. Bounded: each level is a strict substring of the one above it."""
    chains: list[str] = []
    for fm in _FSTRING_LITERAL.finditer(text):
        fields = _fstring_fields(fm.group(1)[1:-1])
        if fields is None:
            return None
        for field in fields:
            inner = _code_chains(field)
            if inner is None:
                return None
            chains += inner
    chains += _CHAIN.findall(_STRING_LITERAL.sub(" ", text))
    return chains


def _pattern_is_tainted(line: str, open_idx: int, clean: frozenset[str], clean_attrs: frozenset[str]) -> bool:
    """True iff the PATTERN argument of the call whose `(` is at `open_idx` interpolates a name
    not proven clean.

    Collects the dotted names in its f-string `{field}`s and its non-string-literal `+`/`.format()`
    operands (`_code_chains`); one gates the finding unless `_chain_is_clean` clears it against the
    file's `clean` names and the enclosing class's `clean_attrs`. An f-string whose field cannot be
    read is tainted outright."""
    # Bound the scan to the pattern argument. A trailing comment or unrelated same-line code can't
    # smuggle in a spurious "tainted" identifier and defeat the constant-exclusion (#395 RM-1), and
    # neither can the SUBJECT string, which is a variable in nearly every match/sub/findall call:
    # scanning every argument made `re.match(BASE + "$", value)` fire (#688). A multi-line call (no
    # close paren on this line) falls back to the rest of the line — the guard is single-line-scoped,
    # so that residual is pre-existing.
    arglist = split_call_args(line, open_idx)
    chains = _code_chains(arglist[0] if arglist else line[open_idx + 1:])
    return chains is None or any(not _chain_is_clean(c, clean, clean_attrs) for c in chains)


def _regex_injection_is_tainted(line: str, clean: frozenset[str], clean_attrs: frozenset[str]) -> bool:
    """True iff some `re.<method>(` call on the line has a dynamically-built pattern argument
    (`_DYNAMIC_PATTERN_ARG`) that interpolates a name not proven clean (`_pattern_is_tainted`).

    Each such call is checked on its own pattern, so a constant first call cannot clear a dynamic
    second one (`re.match(BASE, s) and re.match(f"{u}", s)`, #1020 H1). A call written in a trailing
    comment is not code, so the comment is cut first (string-aware: a `#` in a literal stays). The
    cut's string mask cannot read a same-quote nested f-string (`f"{d["#"]}"`, 3.12) and would clip
    real code at its `#`, so a line holding an f-string `_fstring_fields` cannot read is not cut."""
    code = strip_python_line_comment(line)
    unreadable = (_fstring_fields(fm.group(1)[1:-1]) is None for fm in _FSTRING_LITERAL.finditer(line))
    if code != line and any(unreadable):
        code = line
    return any(
        _pattern_is_tainted(code, m.end() - 1, clean, clean_attrs)
        for m in _RE_CALL.finditer(code)
        if _DYNAMIC_PATTERN_ARG.match(code, m.start())
    )


class RedosGuard(Guard):
    id = "redos"
    title = "No catastrophic-backtracking regex (ReDoS)"
    area = "Code safety"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # nested-quantifier regex -> fires redos/nested-quantifier;
    # pattern built from an f-string, unescaped -> fires redos/regex-injection.
    canary_plant = CanaryPlant(
        files={
            "validate.py": (
                "import re\n\n"
                "MATCH = re.compile(r\"(a+)+@\")\n\n"
                "def build_matcher(user_input):\n"
                "    return re.compile(f\"^{user_input}$\")\n"
            ),
        },
        expects=frozenset({"redos/nested-quantifier", "redos/regex-injection"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def _verbose_pattern_hits(self, tree: ast.AST | None) -> dict[int, None]:
        """Line numbers of triple-quoted patterns passed straight to an `re.` call.

        Blanking triple-quoted CONTENT stops a docstring EXAMPLE firing, but a `re.VERBOSE`
        pattern is triple-quoted by convention and is real code — it was blanked along with
        the prose and stopped being scanned at all (#439 review). Resolved on the AST so a
        triple-quote inside a docstring can never be mistaken for one, and keyed by line so
        the line scan below cannot double-report it."""
        if tree is None:
            return {}
        hits: dict[int, None] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and fn.value.id == "re"):
                continue
            if not node.args:
                continue
            arg = node.args[0]
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                continue
            if _NESTED.search(arg.value) and not _DISJOINT_SAFE.search(arg.value):
                hits[node.lineno] = None
        return hits

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                raw = read(f)
                # Blank triple-quoted docstring/template CONTENT so a `re.compile(r"(a+)+")`
                # EXAMPLE in a docstring doesn't fire (issue #424). Single-line pattern literals in
                # real `re.` calls are left intact, so detection is unaffected.
                stripped_text = strip_python_strings(raw, filename=f)
                stripped = stripped_text.splitlines()
                # Every check below honours the pragma only as a real comment on the line, never
                # the phrase in a string there (#1040). The set is numbered on the stripped text:
                # the stripper blanks a form feed inside a triple-quoted string, which `splitlines()`
                # counts as a break and `ast` does not, so the raw count drifts below one; the
                # stripped lines agree with the line scan and with the AST pass's linenos (#1132).
                pragmas = pragma_line_set(_PRAGMA, stripped_text, dialect="python")
                # One parse serves the verbose-pattern pass and the binding resolution; the
                # bindings are resolved only once a file actually has a dynamic-pattern sink.
                tree = safe_ast_parse(raw, filename=f)
                bindings: _Bindings | None = None
                for lineno in self._verbose_pattern_hits(tree):
                    if lineno in pragmas:
                        continue
                    if lineno <= len(stripped) and _NESTED.search(stripped[lineno - 1]):
                        continue          # the line scan below already reports this one
                    out.append(self._finding(root, f, lineno))
                for i, line in enumerate(stripped, start=1):
                    if len(line) > 2000:
                        # _NESTED below is O(n²) on line length; skip a pathologically long
                        # line so a hostile target file can't slow-DoS the scan itself.
                        continue
                    if line.lstrip().startswith("#") or i in pragmas:
                        continue
                    if _RE_CALL.search(line) and _NESTED.search(line) and not _DISJOINT_SAFE.search(line):
                        out.append(self._finding(root, f, i))
                    if not _DYNAMIC_PATTERN_ARG.search(line):
                        continue
                    if bindings is None:
                        bindings = _clean_bindings(tree)
                    if (
                        _regex_injection_is_tainted(line, bindings.names, bindings.attrs_at(i))
                        and not _RE_ESCAPE.search(line)
                        and i not in pragmas
                    ):
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="medium",
                                title="Regex pattern built from untrusted input",
                                location=f"{rel(root, f)}:{i}",
                                message=(
                                    "The regex pattern itself (not just the subject string) is built "
                                    "from an f-string, concatenation, or .format() call. An attacker who "
                                    "controls that input controls what the regex matches or rejects — "
                                    "a distinct bug class from catastrophic backtracking."
                                ),
                                remediation=(
                                    "Wrap the untrusted portion in `re.escape()` before it reaches the "
                                    "pattern, or build the pattern from a fixed set of literal choices. "
                                    "Suppress an audited case with `# security: allow-redos`."
                                ),
                                rule="redos/regex-injection",
                                standards=["OWASP:A03"],
                            )
                        )
        return out

    def _finding(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title="Regex with a nested quantifier (ReDoS risk)",
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "This pattern nests a quantifier inside a quantified group, so a "
                "crafted input can force exponential backtracking and hang the "
                "process evaluating it."
            ),
            remediation=(
                "Rewrite without nested quantifiers (e.g. possessive/atomic groups "
                "or a simpler pattern), cap input length, or use a timeout. Suppress "
                "a bounded-input case with `# security: allow-redos`."
            ),
            rule="redos/nested-quantifier",
            standards=["OWASP:A05"],
        )
