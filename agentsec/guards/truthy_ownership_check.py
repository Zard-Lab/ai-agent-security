"""Guard: an ownership-scoping filter is applied only when its own value is truthy, so a
falsy (``None``/empty-string) caller identity silently skips the scope instead of being
rejected (checklist §2b).

The bug shape (CVE-2026-55255, Langflow, actively exploited for credential harvesting — see
Help Net Security's 2026-07-08 report): a lookup helper conditionally narrows a query to the
caller's own rows —

    if user_id:
        query = query.filter(Flow.user_id == user_id)
    flow = query.first()

— but never REJECTS when ``user_id`` is falsy. ``if user_id:`` is true for a real caller id and
false for ``None``/``""``/``0`` alike, so the ONE case that most needs scoping (no confirmed
caller identity) is exactly the case where the filter is skipped and the query runs UNSCOPED —
returning/operating on every row instead of failing closed. The correct pattern rejects instead
of falling through: ``if user_id is None: raise ...`` (or an unconditional filter with no
guard at all). This is a general Python/SQLAlchemy/FastAPI/Supabase-py class, not
Langflow-specific — confirmed by grepping this project's own guards for the same shape:
``rls_update_privileged_column.py`` uses ``is not None`` (the safe form) and ``bola.py`` has no
truthy-vs-None logic at all, so neither already covers this.

**Detection (AST, function-scoped):** every function is analysed through the WHOLE-FILE AST, in
one pass over the outermost functions' subtrees, so methods, async methods and functions nested
in a method are covered, every `lineno` is already the file's own, and each `if` is seen once
(issue #1065). The guard used to re-parse each block `iter_functions` cut out of the file. A
method's block keeps its indentation, so that parse raised `IndentationError` and every method was
skipped with no notice; only a column-0 `def` was ever analysed. Re-parsing the blocks survives
only as the fallback for a file that does not parse as a whole, dedented first (`textwrap.dedent`
cannot help a block with any column-0 line, such as a multi-line string's closing quotes, so the
fallback keeps that blind spot). `iter_functions` still supplies the blocks the privileged-route
check below reads. The finding fires on:
  * an ``ast.If`` whose test is a BARE name/attribute (`if user_id:` / `if self.user_id:`) —
    never a `None`/`is not None`/comparison test, which are the CORRECT patterns and must stay
    silent;
  * the tested name/attribute matches an ownership-identity pattern (``user_id``, ``owner_id``,
    ``tenant_id``, ``org_id``, ``account_id``, ``current_user_id``, or a bare ``owner``/
    ``tenant``);
  * the if-body applies a query-scoping call referencing that SAME name — ``.filter(``/
    ``.filter_by(``/``.where(``/``.eq(``/``.match(`` (the last two cover Supabase-py's own
    filter-builder DSL) whose arguments mention the ownership name;
  * the ``If`` node has NO ``orelse``, or an ``orelse`` whose own last statement does not
    terminate (no ``raise``/``return`` — reuses the same "last statement decides" heuristic
    `stripe_webhook.py`'s Rule 2 already established for this codebase, `_stmt_terminates`).

Partial coverage, like `bola`: this proves the STRUCTURAL shape (a conditional scope with no
rejecting else), not that the unscoped path is actually reachable with a real caller in
production — a human confirms. Severity **medium** (PR #742 review, Major 1: originally shipped
`high`, scored above `bola`'s own `medium` on the strength of the active-exploitation precedent —
but the review's own reproduction showed the real gap is precision, not impact. An ordinary
optional UI filter (`if owner_id: q = q.filter(...)` on a search endpoint with no security
boundary implied) is AST-IDENTICAL to the CVE-2026-55255 shape: whether the truthy filter is a
security boundary or a convenience narrowing is not expressible in the code the guard reads, and
2 of 3 findings in the review's own realistic fixture were exactly this false positive (still 2 of
3 after #808, whose suppression needs a privileged route; that fixture's helpers have none). `bola`
carries the same "partial coverage, human confirms" framing at `medium`; this rule's finding does
not look meaningfully more certain than `bola`'s own, so it does not earn a severity above it).

**Route-level privileged auth is consulted** (issue #808): a flagged `if` inside a FastAPI route
handler that carries a recognized PRIVILEGED (admin) auth dependency (`AUTH_CALL_PRIVILEGED` — an
admin/role/scope `Depends(...)` or a `...AdminDep`-style alias, in the block `iter_functions`
hands us) is suppressed, because the handler is already authorized to see every row so the truthy
filter is scope refinement, not the access boundary. The suppression covers the route's whole line
span, from its first decorator to the end of its block, so it also covers a helper defined inside
the route (#1065). Deliberately PRIVILEGED-only: a plain
`Depends(get_current_user)` per-user route that truthy-skips its own per-user scope IS a real
cross-user IDOR and still fires. This closed the flagship's admin audit-log/feedback search FPs.

**Residual known false positive, disclosed rather than silently accepted**: an optional,
non-security filter in a function with NO visible auth context (a bare data-access helper, or a
route with no recognized privileged dependency) is still AST-IDENTICAL to the CVE-2026-55255 shape
and still fires — the guard genuinely cannot tell a convenience narrowing from a security boundary
without an authz signal to lean on. `test_truthy_ownership_check_optional_ui_filter_look_alike_still_fires`
pins that bare-function case (no route, no auth) as the honest boundary of what #808 could close.

Suppress an audited function with `# security: allow-truthy-ownership-check`.
"""
from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    AUTH_CALL_PRIVILEGED,
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-truthy-ownership-check"
_STANDARDS = ["OWASP:A01"]

# A FastAPI/Starlette route decorator on the function block. Mirrors `bola.py`'s regex of the same
# name. Used only to gate the privileged-auth suppression below to actual route handlers, so a plain
# data-access helper (the guard's own canary shape `get_flow_by_id`) is never suppressed by it.
_ROUTE_DECORATOR = re.compile(r"@\s*[\w.]+\.(?:get|post|put|patch|delete)\s*\(")

# The ownership-identity name shapes this guard's `if <name>:` test must match. Anchored to the
# FULL name (not a boundaried-stem search over free text like bola's `_AUTH`) since the AST
# already isolates the exact identifier the `if` tests — no risk of matching an unrelated
# `if scope:`/`if role:` mention elsewhere in the function.
_OWNERSHIP_NAME = re.compile(
    r"^(?:current_)?(?:user|owner|tenant|org(?:anization)?|account)(?:_id)?$", re.IGNORECASE
)

def _dotted_name(node: ast.expr) -> str | None:
    """The dotted string of a bare `Name` or `Attribute` chain (`user_id` / `self.user_id`), or
    `None` for anything else (a call, a comparison, a subscript — not a bare truthy test)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _last_component(dotted: str) -> str:
    return dotted.rsplit(".", 1)[-1]


def _stmt_terminates(stmt: ast.stmt) -> bool:
    """True if this statement definitely rejects rather than falling through — mirrors
    `stripe_webhook.py`'s `_stmt_terminates` (same "last statement decides" heuristic, deliberately
    not a full CFG solver): a `raise`, a `return`, or an `if`/`else` whose every branch does."""
    if isinstance(stmt, ast.Raise | ast.Return):
        return True
    if isinstance(stmt, ast.If):
        if not stmt.orelse:
            return False
        return _stmt_terminates(stmt.body[-1]) and _stmt_terminates(stmt.orelse[-1])
    return False


def _rejects(node: ast.If) -> bool:
    """True if this `if <ownership>:` has an else branch that itself rejects (so the falsy path
    is safe). No `orelse` at all means the falsy path silently falls through — not safe."""
    return bool(node.orelse) and _stmt_terminates(node.orelse[-1])


def _scopes_by_name(body: list[ast.stmt], name: str) -> bool:
    """True if some statement in `body` calls a scoping method whose own argument list mentions
    `name` (the last dotted component, e.g. `user_id` out of `self.user_id`) — a text search over
    the body's own unparsed source is deliberately avoided (would re-open the exact regex-vs-AST
    gap `stripe_webhook.py`'s Rule 2 was built to close); instead each call's arguments are
    inspected directly."""
    target = _last_component(name)
    for stmt in body:
        for node in ast.walk(stmt):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr not in ("filter", "filter_by", "where", "eq", "match"):
                continue
            for arg in (*node.args, *(kw.value for kw in node.keywords)):
                if isinstance(arg, ast.Name) and arg.id == target:
                    return True
                if isinstance(arg, ast.Attribute) and arg.attr == target:
                    return True
                if isinstance(arg, ast.Constant) and arg.value == target:
                    return True  # supabase-py `.eq("user_id", user_id)` — column name as a string
                if isinstance(arg, ast.Compare):  # SQLAlchemy `.filter(Model.user_id == user_id)`
                    for sub in ast.walk(arg):
                        if isinstance(sub, ast.Name) and sub.id == target:
                            return True
    return False


def _unguarded_in(fn: ast.AST) -> list[tuple[int, str]]:
    """(lineno, ownership-name) pairs for every `if <ownership>:` under `fn` whose body scopes a
    query by that same name and whose falsy path does not reject. `lineno` is in `fn`'s own tree's
    numbering."""
    out: list[tuple[int, str]] = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.If):
            continue
        name = _dotted_name(node.test)
        if name is None or not _OWNERSHIP_NAME.match(_last_component(name)):
            continue
        if not _scopes_by_name(node.body, name):
            continue
        if _rejects(node):
            continue
        out.append((node.lineno, name))
    return out


def _unguarded_in_functions(tree: ast.AST) -> list[tuple[int, str]]:
    """`_unguarded_in` over every function in a whole-file `tree`, at the file's own line numbers.

    Walks only the OUTERMOST functions' subtrees, which contain every nested function, so each `if`
    is visited once. That is the same set of `if`s as walking each block `iter_functions` emits:
    on a file that parses it emits every `def`, at any depth, closures included. A `def` is
    always a statement, so expressions are not searched for one."""
    out: list[tuple[int, str]] = []
    stack = [tree]
    while stack:
        node = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            out.extend(_unguarded_in(node))
        elif not isinstance(node, ast.expr):
            stack.extend(ast.iter_child_nodes(node))
    return out


def _unguarded_in_block(block: str, *, filename: str | Path = "<unknown>") -> list[tuple[int, str]]:
    """`_unguarded_in` over `block` parsed on its own, for a file with no whole-file AST. Line
    numbers are relative to the block. Dedented first so a method's block can parse. Returns `[]`
    when it still does not: the file's own syntax error may sit in this block, and
    `textwrap.dedent` is a no-op on a block with any line at column 0 (a multi-line string's
    closing quotes, a backslash continuation)."""
    tree = safe_ast_parse(textwrap.dedent(block), filename=filename)
    return [] if tree is None else _unguarded_in(tree)


class TruthyOwnershipCheckGuard(Guard):
    id = "truthy-ownership-check"
    title = "Ownership-scoping filter skipped on a falsy caller id (possible IDOR)"
    area = "Login & access"  # authz/IDOR class, same bucket as bola.py
    # Surfacing, like `bola` (#766): the finding is a structural shape a human confirms, not a
    # proven bug (see the residual false positive in the module docstring). This ranks it below a
    # proven finding of the same severity and counts it as a review signal; `--fail-on` still
    # reads the severity alone.
    surfacing = True

    # a lookup helper that conditionally scopes by user_id but never rejects a falsy one ->
    # fires truthy-ownership-check/unguarded-truthy-scope.
    canary_plant = CanaryPlant(
        files={
            "flow_lookup.py": (
                "def get_flow_by_id(session, flow_id, user_id=None):\n"
                "    query = session.query(Flow).filter(Flow.id == flow_id)\n"
                "    if user_id:\n"
                "        query = query.filter(Flow.user_id == user_id)\n"
                "    return query.first()\n"
            ),
        },
        expects=frozenset({"truthy-ownership-check/unguarded-truthy-scope"}),
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
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                out.extend(self._scan_file(root, f, text))
        return out

    def _scan_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        # Functions are analysed through the whole-file AST (issue #1065), never by re-parsing a
        # block `iter_functions` cut out of the file: a method's block keeps its indentation, so
        # that parse failed and every method was skipped. Only a file that does not parse as a
        # whole falls back to the blocks, below.
        tree = safe_ast_parse(text, filename=f)
        # Keyed by line, because in the fallback `iter_functions` emits a nested function AND every
        # function enclosing it, and both blocks contain the nested one's `if`.
        hits: dict[int, str] = {} if tree is None else dict(_unguarded_in_functions(tree))
        suppressed: list[tuple[int, int]] = []
        for def_lineno, block in iter_functions(text, filename=f):
            block_start = self._block_start_line(block, def_lineno)
            # A route handler gated by a recognized PRIVILEGED (admin) auth dependency is already
            # authorized to see every row, so a truthy `if user_id:` inside it is scope refinement
            # (an optional search filter), not the access-control boundary this guard flags — issue
            # #808, the flagship's admin audit-log/feedback search endpoints. Consult only
            # AUTH_CALL_PRIVILEGED, not any auth: a plain-authenticated per-user route (bare
            # `Depends(get_current_user)`) that truthy-skips its per-user scope IS a real cross-user
            # IDOR and must still fire. The `_ROUTE_DECORATOR` gate keeps a non-route helper (the
            # canary's `get_flow_by_id`) unsuppressed regardless of what its body mentions.
            #
            # Suppressed by the route's whole line span, not by skipping its block: the AST pass
            # above never reads blocks. It reaches the route's `if`s through the route's own node
            # or through any function enclosing it (a factory that registers the route still holds
            # it in its node, though `iter_functions` blanks it out of the factory's block, #502).
            # In the fallback, a helper defined inside the route arrives as a block of its own,
            # with no route decorator on it.
            if _ROUTE_DECORATOR.search(block) and AUTH_CALL_PRIVILEGED.search(block):
                suppressed.append((block_start, block_start + len(block.splitlines()) - 1))
                continue
            if tree is None:
                for rel_lineno, name in _unguarded_in_block(block, filename=f):
                    hits.setdefault(block_start + rel_lineno - 1, name)
        return [
            self._finding(root, f, lineno, name)
            for lineno, name in sorted(hits.items())
            if not any(lo <= lineno <= hi for lo, hi in suppressed)
        ]

    @staticmethod
    def _block_start_line(block: str, def_lineno: int) -> int:
        """1-based line where `block` starts in the source — mirrors
        `webhook_signature_not_verified.py`'s own helper of the same name/shape."""
        lines_before_def = 0
        for ln in block.splitlines():
            if re.match(r"[ \t]*(?:async[ \t]+)?def[ \t]", ln):
                break
            lines_before_def += 1
        return def_lineno - lines_before_def

    def _finding(self, root: Path, f: Path, lineno: int, name: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                f"`if {name}:` guards a query-scoping filter on `{name}`, but there is no "
                f"corresponding rejection when `{name}` is falsy (`None`/empty/`0`). The ONE case "
                f"that most needs scoping — no confirmed caller identity — is the case where the "
                f"filter is silently skipped, so the query runs unscoped and can return or modify "
                f"every row instead of only the caller's own (CVE-2026-55255's exact shape)."
            ),
            remediation=(
                f"Reject instead of falling through: `if {name} is None: raise ...` (or "
                f"`return None`/404) before the query runs, or apply the `{name}` filter "
                f"unconditionally so there is no falsy path to skip it. Suppress an audited case "
                f"with `# {_PRAGMA}`."
            ),
            rule="truthy-ownership-check/unguarded-truthy-scope",
            standards=list(_STANDARDS),
        )
