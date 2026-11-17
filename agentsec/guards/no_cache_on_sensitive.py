"""Guard: auth/sensitive response route without Cache-Control: no-store (OWASP:A05 / ASVS 14.3.2).

Browsers and intermediate proxies cache HTTP responses unless the server explicitly
instructs them not to. A response from ``/me``, ``/profile``, ``/token``, ``/auth``,
``/payment``, etc. that omits ``Cache-Control: no-store`` (or ``no-cache``) will be
cached by the browser. On a shared device (library computer, hotel kiosk, colleague's
laptop), the next user can retrieve the previous user's profile, session token, or
billing details directly from the browser cache — no credentials required.

This is explicitly called out in OWASP ASVS 14.3.2 ("Verify that HTTP response headers
do not expose sensitive information that could be cached in an intermediate proxy").

Detectable pattern (MEDIUM):

  **``missing-no-store``** — a FastAPI route decorator whose path starts with a
  sensitive prefix (``/me``, ``/profile``, ``/user``, ``/account``, ``/token``,
  ``/auth``, ``/payment``, ``/billing``, ``/subscription``, ``/invoice``, ``/wallet``,
  ``/admin``, ``/secret``) and whose enclosing function (
  ``enclosing_function_span()`` — a 30-line fallback window when no enclosing function is
  found) contains no ``Cache-Control``, ``no-store``, or ``no-cache`` signal.

**Middleware coverage (#899).** A route is also covered when a *registered* middleware writes
``Cache-Control: no-store`` (or ``no-cache``) on every response: an ``@<app>.middleware("http")``
function, or the ``dispatch`` / ``__call__`` of a class (or a ``dispatch=`` function) passed to
``add_middleware(...)`` / ``Middleware(...)``. The header name and value must be constants (a
same-file module- or class-level constant counts), and the write must land on the response the
middleware returns (or the message a raw-ASGI send wrapper it hands to the app forwards). It must
not sit in a loop, a ``match`` case, an ``else`` branch, an ``except`` handler, an uncalled or
merely-called helper, or under a condition or early exit other than a protocol-type, method or
response header-presence check. No other Cache-Control write or removal may sit anywhere in
the middleware, and the middleware must not hand the response or its headers to a call pass 1
cannot see into (a helper may overwrite the header). A registration inside an ``if`` is not
proof (#473). Coverage is scoped to the top-level directory the middleware is registered in (a
root-level file covers the whole tree), and middleware in a non-product file (tests, examples)
covers nothing.

**Why MEDIUM?** The impact depends on whether the endpoint returns genuinely sensitive
data (high for a ``/me`` returning PII or a ``/token`` returning a JWT; lower for a
generic ``/admin`` health page). The exploit requires physical or session access to the
victim's device, so it is not remotely exploitable without that precondition.

**Suppress:** add ``# security: allow-cacheable-response`` anywhere in a file to
silence this check for that file. Use when the route deliberately returns public data
and caching is an intentional performance optimization.
"""
from __future__ import annotations

import ast
import re
from collections.abc import Callable, Iterator
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    conditional_nodes,
    enclosing_function_span,
    is_http_middleware,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    middleware_scope,
    pragma_present,
    python_scan_dirs,
    read,
    registered_names,
    rel,
    strip_python_strings,
)

_PRAGMA = "security: allow-cacheable-response"

_STANDARDS = ["ASVS:14.3.2", "OWASP:A05"]

# Matches a FastAPI route decorator whose path starts with a sensitive prefix.
# The sensitive-path stems must end at a SEGMENT boundary — a `/`, or the end of the path.
# Without one, `[^'"]*` let a stem bleed into an unrelated word: `/metrics`, `/messages` and
# `/media/{id}` all matched the `me` stem and `/authors` matched `auth`, so four ordinary routes
# drew a finding (#437 review). `s?` keeps the plural spellings (`/users`, `/tokens`,
# `/payments`) that the stems are obviously meant to cover.
_SENSITIVE_STEMS = (
    r"me|profile|user|account|token|auth|payment|billing|subscription|invoice|wallet|admin|secret"
)
_ROUTE = re.compile(
    r"""@(?:app|router)\.(?:get|post|put|delete|patch)\(['"]"""
    r"""(/(?:""" + _SENSITIVE_STEMS + r""")s?(?=['"]|/)[^'"]*)['"]\s*[,)]""",
    re.IGNORECASE,
)

# Cache-control directive signals.
_CACHE_CTRL = re.compile(r"[Cc]ache.?[Cc]ontrol|no.store|no.cache", re.IGNORECASE)

_WINDOW = 30  # lines after the decorator to scan for a cache-control signal

# --- Pass 1 (#899): a registered middleware that sets no-store on every response ---------------
# Unlike the route-level `_CACHE_CTRL` token search, a blanket suppression demands a real header
# WRITE by CODE: a constant `Cache-Control` name with a constant `no-store`/`no-cache` value, onto
# the response the middleware hands back. A mention in prose, a comment, an unsafe value (`public,
# max-age=3600`) or a write onto some other object proves nothing.
_HEADER_NAME = re.compile(r"cache-control", re.IGNORECASE)
_NO_STORE_VALUE = re.compile(r"no-store|no-cache", re.IGNORECASE)
_HEADER_TEXT = re.compile(r"cache.?control", re.IGNORECASE)
# Only files mentioning the header (a middleware body), a middleware (a registration) or a
# middleware-shaped definition are parsed, so pass 1 does not AST-parse the whole tree (#771). The
# last two alternatives are not about writes: they make sure a directory's OWN definition of a
# registered name is seen even when its file never says `middleware` (a bare raw-ASGI class), so
# a same-named no-store class elsewhere is not lent to it.
_PASS1_PREFILTER = re.compile(
    _HEADER_TEXT.pattern + r"|middleware|call_next|def\s+(?:__call__|dispatch)\b", re.IGNORECASE
)
# A condition or early exit around the write is NOT proof unless it does not depend on which route
# answered: raw ASGI's `scope["type"]` / `message["type"] == "http.response.start"`, a
# request-method check, or a Cache-Control presence test on the response (`_is_presence_check`)
# that lets a route set its own value. Anything else (a path check, a status check, a settings
# flag, a helper call, a header VALUE test) keeps the route firing: the noisy direction, never the
# fail-open one.
_BENIGN_CONDITION = re.compile(r"""['"](?:type|method)['"]|\.method\b|http\.response\.start""", re.IGNORECASE)
_PATH_SCOPED = re.compile(r"path|url|route|endpoint", re.IGNORECASE)
_MIDDLEWARE_METHODS = frozenset({"dispatch", "__call__"})
# Header-container methods that write (`MutableHeaders.append/setdefault/update`, a raw-ASGI header
# list's `append/extend/insert`) or remove. A read such as `.get(k, "no-store")` is neither.
_WRITE_METHODS = frozenset({"__setitem__", "setdefault", "append", "update", "extend", "insert"})
_REMOVE_METHODS = frozenset({"pop", "__delitem__"})
# Calls that return a live reference into their receiver (`message.setdefault("headers", [])`), so
# a write through the result still lands on the receiver. Any other call builds a new object.
_VIEW_METHODS = frozenset({"setdefault", "get"})
# What hands the response's headers to other code: the sink itself or its header container. A
# scalar read off it (`response.status_code`) cannot change the header. `MutableHeaders(...)`
# only builds a view, so passing a sink to it is not a hand-off (#954 R2-C1).
_HEADER_CONTAINERS = frozenset({"headers", "raw_headers", "raw"})
_VIEW_CONSTRUCTORS = frozenset({"MutableHeaders"})
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_LOOPS = (ast.For, ast.AsyncFor, ast.While)
_CONDITIONS = (ast.If, ast.IfExp, ast.While, ast.Match)
_NOT_ON_THE_MAIN_PATH = (*_SCOPES, ast.ExceptHandler)
_ALWAYS_CONDITIONAL = (*_LOOPS, ast.Match, ast.ExceptHandler)

_Env = dict[str, ast.expr]
_PairTest = Callable[[ast.AST, ast.AST, _Env], bool]


def _tail(node: ast.AST) -> str | None:
    """The last name of a `Name` / `Attribute` chain (`SecurityHeaders`, `mw.SecurityHeaders`)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _root(node: ast.AST) -> str | None:
    """The variable `node` is a live view into: `response` for `response.headers["X"]`, `message`
    for `message.setdefault("headers", [])`. Any other call (`Response()`, `.copy()`) makes a new
    object, so it has no root."""
    while not isinstance(node, ast.Name):
        if isinstance(node, ast.Attribute | ast.Subscript):
            node = node.value
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _VIEW_METHODS
        ):
            node = node.func.value
        else:
            return None
    return node.id


def _file_constants(tree: ast.AST) -> _Env:
    """Module- and class-level `NAME = <literal>` bindings, so a header dict or value kept in a
    constant (`SECURITY_HEADERS = {...}`, `NO_STORE = "no-store"`) resolves in the same file."""
    body = list(getattr(tree, "body", []))
    stmts = [*body, *(s for c in body if isinstance(c, ast.ClassDef) for s in c.body)]
    out: _Env = {}
    for s in stmts:
        if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
            out[s.targets[0].id] = s.value
        elif isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name) and s.value is not None:
            out[s.target.id] = s.value
    return out


def _const(node: ast.AST, env: _Env) -> str | None:
    """A string/bytes constant, following one hop through a same-file constant name."""
    name = _tail(node)
    if name is not None:
        node = env.get(name, node)
    if isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
        v = node.value
        return v.decode("latin-1") if isinstance(v, bytes) else v
    return None


def _is_header(node: ast.AST, env: _Env) -> bool:
    k = _const(node, env)
    return k is not None and _HEADER_NAME.fullmatch(k.strip()) is not None


def _is_no_store(node: ast.AST, env: _Env) -> bool:
    v = _const(node, env)
    return v is not None and _NO_STORE_VALUE.search(v) is not None


def _pair_is_no_store(key: ast.AST, value: ast.AST, env: _Env) -> bool:
    return _is_header(key, env) and _is_no_store(value, env)


def _pair_is_other(key: ast.AST, value: ast.AST, env: _Env) -> bool:
    """A Cache-Control pair whose value is anything but a constant no-store (`public`, a variable)."""
    return _is_header(key, env) and not _is_no_store(value, env)


def _has_pair(node: ast.AST, env: _Env, pair: _PairTest, *, resolve: bool = True) -> bool:
    """A header literal holding a pair `pair` accepts: a `{name: value}` dict, a `(name, value)`
    2-tuple (raw ASGI), or a list/tuple/concatenation of those. With `resolve`, a bare name is
    followed once to a same-file constant (and never again, so `A = [A]` cannot loop)."""
    if resolve and isinstance(node, ast.Name | ast.Attribute):
        target = env.get(_tail(node) or "")
        return target is not None and _has_pair(target, env, pair, resolve=False)
    if isinstance(node, ast.Dict):
        return any(
            k is not None and pair(k, v, env) for k, v in zip(node.keys, node.values, strict=True)
        )
    if isinstance(node, ast.Tuple) and len(node.elts) == 2 and pair(node.elts[0], node.elts[1], env):
        return True
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return any(_has_pair(e, env, pair, resolve=resolve) for e in node.elts)
    if isinstance(node, ast.Starred):
        return _has_pair(node.value, env, pair, resolve=resolve)
    if isinstance(node, ast.BinOp):
        return _has_pair(node.left, env, pair, resolve=resolve) or _has_pair(
            node.right, env, pair, resolve=resolve
        )
    return False


def _own_nodes(fn: ast.AST) -> Iterator[ast.AST]:
    """Every node of `fn`'s body, without descending into a nested def, lambda or class: their
    bodies run only when something calls them."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _SCOPES):
            stack.extend(ast.iter_child_nodes(node))


def _sinks(fn: ast.FunctionDef | ast.AsyncFunctionDef, *, callback: bool) -> set[str]:
    """Names whose headers reach the client: a name `fn` returns (`return response`) or, for a raw
    ASGI send wrapper, the message it is handed; plus a name bound to a live view of one (`headers
    = response.headers`, `MutableHeaders(scope=message)`). A name bound more than once is not a
    sink: `response = JSONResponse(...)` after the write returns a different object."""
    own = list(_own_nodes(fn))
    stores: dict[str, int] = {}
    for n in own:
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            stores[n.id] = stores.get(n.id, 0) + 1
    if callback:
        params = [*fn.args.posonlyargs, *fn.args.args]
        out = {a.arg for a in params if a.arg not in ("self", "cls") and a.arg not in stores}
    else:
        out = {
            n.value.id for n in own
            if isinstance(n, ast.Return) and isinstance(n.value, ast.Name) and stores.get(n.value.id, 0) <= 1
        }
    views = [
        (n.targets[0].id, n.value) for n in own
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
    ]
    grew = True
    while grew:
        grew = False
        for name, value in views:
            if name not in out and stores.get(name, 0) <= 1 and _is_view(value, out):
                out.add(name)
                grew = True
    return out


def _is_view(value: ast.AST, sinks: set[str]) -> bool:
    if _root(value) in sinks:
        return True
    return (
        isinstance(value, ast.Call)
        and _tail(value.func) == "MutableHeaders"
        and any(_root(a) in sinks for a in [*value.args, *(k.value for k in value.keywords)])
    )


def _is_presence_check(test: ast.AST, env: _Env, sinks: set[str]) -> bool:
    """A test of whether the RESPONSE already carries Cache-Control, the deny-by-default shape that
    lets a route set its own value: `"cache-control" not in response.headers`, or a
    `response.headers.get("cache-control")` truth / `is None` test. A test of the header's VALUE,
    or of a request header, is not one."""
    if isinstance(test, ast.Compare):
        if all(isinstance(op, ast.In | ast.NotIn) for op in test.ops):
            return _is_header(test.left, env) and all(_root(c) in sinks for c in test.comparators)
        if all(isinstance(op, ast.Is | ast.IsNot) for op in test.ops) and all(
            isinstance(c, ast.Constant) and c.value is None for c in test.comparators
        ):
            return _is_presence_check(test.left, env, sinks)
        return False
    return (
        isinstance(test, ast.Call)
        and isinstance(test.func, ast.Attribute)
        and test.func.attr == "get"
        and bool(test.args)
        and _is_header(test.args[0], env)
        and _root(test.func.value) in sinks
    )


def _benign(test: ast.AST, env: _Env, sinks: set[str]) -> bool:
    """A condition that does not depend on which route answered (see `_BENIGN_CONDITION`). Every
    operand of an `and`/`or` must be benign on its own: `request.method == "GET" and is_sensitive`
    would otherwise pass on the method check and hide the path decision behind the alias."""
    if isinstance(test, ast.BoolOp):
        return all(_benign(v, env, sinks) for v in test.values)
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _benign(test.operand, env, sinks)
    if _is_presence_check(test, env, sinks):
        return True
    src = ast.unparse(test)
    return _BENIGN_CONDITION.search(src) is not None and _PATH_SCOPED.search(src) is None


def _exits(stmt: ast.stmt) -> bool:
    """`stmt` can leave its block: a `return` / `raise`, or a `continue` / `break` outside a loop
    of its own. One inside an `except` handler (only error responses skip what follows) or a
    nested def does not count."""

    def walk(node: ast.AST, in_loop: bool) -> bool:
        if isinstance(node, ast.Return | ast.Raise):
            return True
        if isinstance(node, ast.Continue | ast.Break):
            return not in_loop
        if isinstance(node, _NOT_ON_THE_MAIN_PATH):
            return False
        inner = in_loop or isinstance(node, _LOOPS)
        return any(walk(c, inner) for c in ast.iter_child_nodes(node))

    return walk(stmt, False)


def _skips_rest(stmt: ast.stmt, env: _Env, sinks: set[str]) -> bool:
    """A statement after `stmt` in the same block is not on every path when `stmt` can leave the
    block early. The one early exit that does not depend on the route is a benign `if` with no
    `else` and no further condition inside (`if scope["type"] != "http": ...; return`)."""
    if not _exits(stmt):
        return False
    return not (
        isinstance(stmt, ast.If)
        and not stmt.orelse
        and _benign(stmt.test, env, sinks)
        and not any(isinstance(n, _CONDITIONS) for s in stmt.body for n in ast.walk(s))
    )


def _on_every_path(
    body: list[ast.stmt], env: _Env, sinks: set[str], match: Callable[[ast.AST], bool]
) -> bool:
    """Some node in `body` satisfies `match` on a path every execution takes: not inside a nested
    def / lambda / class, a loop body (it may run zero times), a `match` case, an `else` branch, a
    non-benign `if` or ternary, or an `except` handler (that write covers only the error
    responses), and not after a statement that can leave the block early (`_skips_rest`)."""

    def seq(items: list[ast.AST], scoped: bool) -> bool:
        for item in items:
            if visit(item, scoped):
                return True
            if isinstance(item, ast.stmt) and _skips_rest(item, env, sinks):
                scoped = True
        return False

    def visit(node: ast.AST, scoped: bool) -> bool:
        if not scoped and match(node):
            return True
        if isinstance(node, _SCOPES):
            return False
        if isinstance(node, ast.If):
            inside = scoped or not _benign(node.test, env, sinks)
            return (
                visit(node.test, scoped)
                or seq(list(node.body), inside)
                or seq(list(node.orelse), True)
            )
        if isinstance(node, _ALWAYS_CONDITIONAL):
            scoped = True
        elif isinstance(node, ast.IfExp):
            scoped = scoped or not _benign(node.test, env, sinks)
        for _field, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                if visit(value, scoped):
                    return True
            elif isinstance(value, list) and seq([v for v in value if isinstance(v, ast.AST)], scoped):
                return True
        return False

    return seq(list(body), False)


def _write_method_on_sink(node: ast.AST, sinks: set[str]) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _WRITE_METHODS
        and _root(node.func.value) in sinks
    )


def _applies_each_pair(loop: ast.For | ast.AsyncFor, env: _Env, sinks: set[str]) -> bool:
    """The loop body writes the pair it iterates onto a sink on every iteration: `h[k] = v`,
    `h.setdefault(k, v)` / `h.append(k, v)`, `raw.append((k, v))`, or `raw.append(pair)`. A body
    that logs the pair, filters it, or writes it elsewhere applies nothing."""
    t = loop.target

    def is_name(n: ast.AST, name: str) -> bool:
        return isinstance(n, ast.Name) and n.id == name

    if isinstance(t, ast.Tuple) and len(t.elts) == 2:
        k, v = t.elts
        if not (isinstance(k, ast.Name) and isinstance(v, ast.Name)):
            return False
        key, value = k.id, v.id

        def applies(node: ast.AST) -> bool:
            if isinstance(node, ast.Assign):
                return is_name(node.value, value) and any(
                    isinstance(tg, ast.Subscript) and _root(tg) in sinks and is_name(tg.slice, key)
                    for tg in node.targets
                )
            if not (isinstance(node, ast.Call) and _write_method_on_sink(node, sinks)):
                return False
            a = node.args
            return (len(a) >= 2 and is_name(a[0], key) and is_name(a[1], value)) or any(
                isinstance(x, ast.Tuple) and len(x.elts) == 2
                and is_name(x.elts[0], key) and is_name(x.elts[1], value)
                for x in a
            )

    elif isinstance(t, ast.Name):
        pair_name = t.id

        def applies(node: ast.AST) -> bool:
            return (
                _write_method_on_sink(node, sinks)
                and isinstance(node, ast.Call)
                and any(is_name(x, pair_name) for x in node.args)
            )

    else:
        return False
    return _on_every_path(loop.body, env, sinks, applies)


def _is_no_store_write(node: ast.AST, env: _Env, sinks: set[str]) -> bool:
    """`node` itself writes `Cache-Control: no-store` onto a sink (see `_sinks`):
    `h["Cache-Control"] = "no-store"`, `h.setdefault(k, v)` / `MutableHeaders.append(k, v)`, a
    header literal passed to a write method (`h.update({...})`, `raw_headers.append((b"cache-control",
    b"no-store"))`) or assigned into a subscript (`message["headers"] = [..., pair]`), or a `for`
    loop that writes each pair of a header constant (`for k, v in SECURITY_HEADERS.items(): h[k] =
    v`)."""
    if isinstance(node, ast.Assign):
        return any(
            isinstance(t, ast.Subscript)
            and _root(t) in sinks
            and (_pair_is_no_store(t.slice, node.value, env) or _has_pair(node.value, env, _pair_is_no_store))
            for t in node.targets
        )
    if isinstance(node, ast.AugAssign):
        return (
            isinstance(node.target, ast.Subscript)
            and _root(node.target) in sinks
            and _has_pair(node.value, env, _pair_is_no_store)
        )
    if isinstance(node, ast.Call):
        if not _write_method_on_sink(node, sinks):
            return False
        if len(node.args) >= 2 and _pair_is_no_store(node.args[0], node.args[1], env):
            return True
        return any(
            _has_pair(a, env, _pair_is_no_store) for a in [*node.args, *(k.value for k in node.keywords)]
        )
    if isinstance(node, ast.For | ast.AsyncFor):
        it = node.iter
        if isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute) and it.func.attr == "items":
            it = it.func.value
        return _has_pair(it, env, _pair_is_no_store) and _applies_each_pair(node, env, sinks)
    return False


def _overrides(fn: ast.AST, env: _Env) -> bool:
    """`fn` (nested defs included) also writes Cache-Control with anything but a constant no-store
    value, or removes it: that write may be the one the client sees, so the no-store write proves
    nothing (`h["Cache-Control"] = "public"` after it, `del h["Cache-Control"]`,
    `h.pop("cache-control")`, a header literal or constant carrying another value)."""
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign) and any(
            isinstance(t, ast.Subscript) and _pair_is_other(t.slice, n.value, env) for t in n.targets
        ):
            return True
        if isinstance(n, ast.Delete) and any(
            isinstance(t, ast.Subscript) and _is_header(t.slice, env) for t in n.targets
        ):
            return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.args and _is_header(n.args[0], env):
            if n.func.attr in _REMOVE_METHODS:
                return True
            if n.func.attr in _WRITE_METHODS and len(n.args) >= 2 and not _is_no_store(n.args[1], env):
                return True
        if isinstance(n, ast.Dict | ast.Tuple) and _has_pair(n, env, _pair_is_other, resolve=False):
            return True
        if (
            isinstance(n, ast.Name | ast.Attribute)
            and isinstance(n.ctx, ast.Load)
            and _has_pair(n, env, _pair_is_other)
        ):
            return True
    return False


def _exposes(arg: ast.AST, sinks: set[str], env: _Env) -> bool:
    """`arg` is a sink or a sink's header container (`response`, `response.headers`,
    `message["headers"]`), so the callee it is passed to can rewrite the header. A subscript's key
    may be a literal or a same-file constant, followed one hop (`message[HEADERS_KEY]`)."""
    if isinstance(arg, ast.Name):
        return arg.id in sinks
    if _root(arg) not in sinks:
        return False
    if isinstance(arg, ast.Attribute):
        return arg.attr in _HEADER_CONTAINERS
    return isinstance(arg, ast.Subscript) and _const(arg.slice, env) in _HEADER_CONTAINERS


def _hands_off(fn: ast.AST, sinks: set[str], forwards: frozenset[str], env: _Env) -> bool:
    """`fn` (nested defs included) passes a sink to a call pass 1 cannot see into
    (`finalize_headers(response)`, `self._finalize(response)`, an imported helper): that code may
    overwrite the header, so the no-store write proves nothing (#954 R2-C1). Neither a view
    constructor (`MutableHeaders(scope=message)`) nor raw ASGI's forward of the message to a
    callable the enclosing middleware was handed (`await send(message)`, `forwards`) is a
    hand-off."""
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call) or _tail(n.func) in _VIEW_CONSTRUCTORS:
            continue
        if isinstance(n.func, ast.Name) and n.func.id in forwards:
            continue
        if any(_exposes(a, sinks, env) for a in [*n.args, *(k.value for k in n.keywords)]):
            return True
    return False


def _params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    return frozenset(a.arg for a in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs])


def _writes_no_store(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    env: _Env,
    *,
    callback: bool = False,
    forwards: frozenset[str] = frozenset(),
) -> bool:
    """`fn` writes no-store onto a sink on every call: directly, or inside a nested def it hands to
    the framework as a callback on every call (raw ASGI's `send_wrapper`, passed to
    `self.app(scope, receive, send_wrapper)`). A nested def that is only called, or never used,
    earns nothing: the call may be conditional, and pass 1 does not follow calls. For the same
    reason a sink handed to such a call voids the write (`_hands_off`). `forwards` are the
    parameters of the enclosing middleware (raw ASGI's `send`)."""
    sinks = _sinks(fn, callback=callback)
    passed: set[str] = set()

    def match(node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            passed.update(a.id for a in [*node.args, *(k.value for k in node.keywords)] if isinstance(a, ast.Name))
        return _is_no_store_write(node, env, sinks)

    if _on_every_path(fn.body, env, sinks, match):
        return not _hands_off(fn, sinks, forwards, env)
    return any(
        _writes_no_store(n, env, callback=True, forwards=forwards | _params(fn))
        for n in _own_nodes(fn)
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name in passed
    )


def _covers_every_response(fn: ast.FunctionDef | ast.AsyncFunctionDef, env: _Env) -> bool:
    """`fn` is a middleware body that leaves `Cache-Control: no-store` on every response."""
    return _writes_no_store(fn, env) and not _overrides(fn, env)


def _no_store_middleware_scopes(root: Path, sources: list[tuple[Path, str]]) -> set[str]:
    """Pass 1: the scopes (see `middleware_scope`) covered by a registered middleware that writes
    `Cache-Control: no-store` on every response. `sources` are the product files that passed
    `_PASS1_PREFILTER`. Total: an unparseable file contributes no coverage."""
    covered: set[str] = set()
    registrations: list[tuple[str, str]] = []  # (middleware name, scope it is registered in)
    no_store_defs: dict[str, set[str]] = {}  # name -> scopes of definitions that write no-store
    all_defs: dict[str, set[str]] = {}  # name -> scopes of every definition with that name
    for f, text in sources:
        tree = safe_ast_parse(text, filename=f)
        if tree is None:
            continue
        scope = middleware_scope(root, f)
        env = _file_constants(tree)
        conditional = conditional_nodes(tree)
        # A file that never names the header cannot hold the write; it may still register.
        writes_possible = _HEADER_TEXT.search(text) is not None
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and id(node) not in conditional:
                registrations.extend((name, scope) for name in registered_names(node))
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                all_defs.setdefault(node.name, set()).add(scope)
                if not writes_possible:
                    continue
                if isinstance(node, ast.ClassDef):
                    bodies: list[ast.FunctionDef | ast.AsyncFunctionDef] = [
                        m for m in node.body
                        if isinstance(m, ast.FunctionDef | ast.AsyncFunctionDef)
                        and m.name in _MIDDLEWARE_METHODS
                    ]
                else:
                    bodies = [node]
                if not any(_covers_every_response(b, env) for b in bodies):
                    continue
                no_store_defs.setdefault(node.name, set()).add(scope)
                if (
                    not isinstance(node, ast.ClassDef)
                    and id(node) not in conditional
                    and any(is_http_middleware(d) for d in node.decorator_list)
                ):
                    covered.add(scope)
    for name, scope in registrations:
        homes = no_store_defs.get(name, set())
        # Prefer the definition in the registering scope; with none there, the name is imported
        # from elsewhere (a shared `libs/` package) and any no-store definition of it counts.
        if scope in homes or (homes and scope not in all_defs.get(name, set())):
            covered.add(scope)
    return covered


class NoCacheOnSensitiveGuard(Guard):
    id = "no-cache-on-sensitive"
    title = "Sensitive route response missing Cache-Control: no-store (ASVS 14.3.2)"
    area = "Web setup"

    # profile_routes.py: @router.get('/me') with no Cache-Control/no-store in 30 lines ->
    # fires no-cache-on-sensitive/missing-no-store (MEDIUM).
    # Must NOT contain: security: allow-cacheable-response (pragma silences file).
    # Must NOT contain: Cache-Control, no-store, no-cache (within 30 lines of route).
    canary_plant = CanaryPlant(
        files={
            "profile_routes.py": (
                "from fastapi import APIRouter\n"
                "\n"
                "router = APIRouter()\n"
                "\n"
                "\n"
                "@router.get('/me')\n"
                "async def get_profile(current_user: dict):\n"
                "    return current_user\n"
            ),
        },
        expects=frozenset({
            "no-cache-on-sensitive/missing-no-store",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "fastapi" in profile.features and "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        if not self.applies(profile):
            return []
        # CLAUDE.md rule 4: the pragma skip below gates only where a finding may be ANCHORED, not
        # what pass 1 reads, so a pragma'd `main.py` still contributes its middleware. The
        # non-product skip is different in kind: a test or example app's middleware never runs in
        # front of the product's routes, so it is no coverage source, and counting it would fail
        # open (`app/tests/conftest.py` would silence all of `app/`).
        sources: list[tuple[Path, str]] = []
        found: list[tuple[str, list[Finding]]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                raw = read(f)
                if _PASS1_PREFILTER.search(raw):
                    sources.append((f, raw))
                if pragma_present(_PRAGMA, raw, dialect="python"):
                    continue
                text = strip_python_strings(raw, filename=f)
                if not _ROUTE.search(text):
                    continue
                hits = self._check_file(root, f, text)
                if hits:
                    found.append((middleware_scope(root, f), hits))
        if not found:
            return []
        # Pass 2 is resolved first, so a repo with no uncovered sensitive route never pays for
        # pass 1's AST parse.
        covered = _no_store_middleware_scopes(root, sources)
        if "" in covered:
            return []
        return [hit for scope, hits in found if scope not in covered for hit in hits]

    def _check_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = text.splitlines()
        # Computed once per file, not per match: enclosing_function_span() re-parses the AST on
        # every call otherwise, which measures ~900x slower over a many-function file (found in the
        # #685 review).
        funcs = iter_functions(text, filename=f)
        for i, line in enumerate(lines):
            m = _ROUTE.search(line)
            if not m:
                continue
            path = m.group(1)
            # look ahead to the END of the enclosing function first (a Cache-Control
            # signal can sit further down than any fixed window reaches), falling back to the
            # fixed window only when no enclosing function is found.
            span = enclosing_function_span(text, i + 1, functions=funcs)
            if span is not None:
                window = "\n".join(lines[i : span[1]])
            else:
                window_end = min(i + _WINDOW + 1, len(lines))
                window = "\n".join(lines[i:window_end])
            if _CACHE_CTRL.search(window):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=f"Sensitive route `{path}` response has no Cache-Control: no-store header",
                    location=f"{rel(root, f)}:{i + 1}",
                    message=(
                        f"The route `{path}` handles auth or user-sensitive data but "
                        "its handler contains no `Cache-Control`, `no-store`, "
                        "or `no-cache` directive. Without `Cache-Control: no-store` the browser "
                        "will cache the response. On a shared device, the next user can retrieve "
                        "the previous user's profile, session token, or billing data directly "
                        "from the browser cache without any credentials — violating ASVS 14.3.2."
                    ),
                    remediation=(
                        "Add `Cache-Control: no-store` to the response headers for this route, e.g.: "
                        "`response.headers['Cache-Control'] = 'no-store'` or by returning "
                        "`Response(..., headers={'Cache-Control': 'no-store'})`. "
                        "For broad coverage, register a middleware that sets `no-store` on EVERY "
                        "response (deny-by-default, e.g. only when `cache-control` is not already "
                        "in the response headers, so a public route can opt out); a middleware "
                        "that sets it only for some paths is not recognised as coverage. "
                        "Suppress with `# security: allow-cacheable-response` when the route "
                        "returns only public, non-sensitive data and caching is intentional."
                    ),
                    rule="no-cache-on-sensitive/missing-no-store",
                    standards=list(_STANDARDS),
                )
            )
        return out
