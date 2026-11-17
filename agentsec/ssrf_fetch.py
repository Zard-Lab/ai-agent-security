"""Shared "is this call an outbound HTTP fetch" classifier for the SSRF guards.

`ssrf-redirect-bypass` and `ssrf-dns-rebind-toctou` both look for "a URL validator, then a fetch on
the same URL". Their first cut treated ANY attribute call named `.get` / `.put` / `.post` / `.send`
as the fetch, which fired on `config.get("key")` and `response.headers.get(...)` — real repos
(fastmcp's own SSRF-safe fetcher included) produced only false positives that way. A fetch must:

  * be called on a client-shaped receiver: a name carrying `requests` / `httpx` / `aiohttp` /
    `urllib` / `session` / `client` / `http` / `curl` / `opener` in any dotted segment
    (`self._client.get`, `requests.get`, `session.post`), or a name bound in the same file to a
    client constructor (`with httpx.AsyncClient() as c: c.get(url)`); AND
  * take a non-literal target: a call whose URL argument is a string literal is not fetching the
    caller's validated URL (`session.get("user_id")` reads a dict), so it is not the shape.

`urlopen(...)` / `urlretrieve(...)` / `fetch(...)` called bare are fetches by name alone.

Known residual, disclosed: a dict-like receiver that happens to be client-shaped and is indexed by a
variable (`session.get(key)` on a Flask `session`) still reads as a fetch.

`httpx_follows_no_redirects` models the one library default that differs from `requests`: httpx
does NOT follow redirects unless `follow_redirects=True` is passed, so an httpx call with neither the
call-level nor the client-level opt-in is not a redirect bypass. `requests` and `aiohttp` follow by
default and are unaffected.
"""
from __future__ import annotations

import ast
import re

FETCH_ATTRS = frozenset({
    "get", "post", "put", "delete", "patch", "head", "request", "urlopen", "urlretrieve", "fetch",
    "send", "stream",
})
_BARE_FETCH = frozenset({"urlopen", "urlretrieve", "fetch"})
_CLIENT_TOKENS = ("requests", "httpx", "aiohttp", "urllib", "session", "client", "http", "curl", "opener")
_CLIENT_CTOR_RE = re.compile(
    r"(?:^|\.)(?:\w*Session|\w*Client|PoolManager|HTTPS?Connection|build_opener|session)$"
)
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})
_URL_KWARGS = frozenset({"url", "uri", "request"})

Bindings = dict[str, list[ast.Call]]


def dotted(node: ast.AST) -> str | None:
    """`a.b.c` for a Name/Attribute chain, `f()` suffixes a call in the chain, None otherwise."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Call):
        base = dotted(node.func)
        return f"{base}()" if base else None
    return None


def client_bindings(tree: ast.AST) -> Bindings:
    """`{dotted target name -> [constructor calls bound to it]}` for every
    `x = Client(...)` / `self.x = Client(...)` / `with Client(...) as x` in `tree`."""
    out: Bindings = {}

    def bind(target: ast.AST, value: ast.AST | None) -> None:
        if not isinstance(value, ast.Call):
            return
        ctor = dotted(value.func)
        name = dotted(target)
        if ctor and name and _CLIENT_CTOR_RE.search(ctor):
            out.setdefault(name, []).append(value)

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                bind(t, node.value)
        elif isinstance(node, ast.AnnAssign):
            bind(node.target, node.value)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    bind(item.optional_vars, item.context_expr)
    return out


def _client_shaped(recv: str, bindings: Bindings) -> bool:
    if recv in bindings:
        return True
    return any(tok in seg.lower() for seg in recv.replace("()", "").split(".") for tok in _CLIENT_TOKENS)


def _url_argument(call: ast.Call) -> ast.expr | None:
    """The expression that names the fetch target: the first positional argument (after a leading
    HTTP-method literal, `requests.request("GET", url)`), else a `url=`-style keyword."""
    positional = list(call.args)
    if (
        positional
        and isinstance(positional[0], ast.Constant)
        and isinstance(positional[0].value, str)
        and positional[0].value.upper() in _HTTP_METHODS
    ):
        positional = positional[1:]
    if positional:
        return positional[0]
    for kw in call.keywords:
        if kw.arg in _URL_KWARGS:
            return kw.value
    return None


def is_http_fetch(call: ast.Call, bindings: Bindings) -> bool:
    """True if `call` looks like an outbound HTTP fetch of a non-literal target."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id in _BARE_FETCH and _url_argument(call) is not None
    if not isinstance(func, ast.Attribute) or func.attr not in FETCH_ATTRS:
        return False
    recv = dotted(func.value)
    if recv is None or not _client_shaped(recv, bindings):
        return False
    target = _url_argument(call)
    if target is None:
        return False
    return not (isinstance(target, ast.Constant) and isinstance(target.value, str))


def _enables_redirects(call: ast.Call) -> bool:
    """`follow_redirects=<anything but a literal False>` on this call."""
    for kw in call.keywords:
        if kw.arg == "follow_redirects":
            return not (isinstance(kw.value, ast.Constant) and kw.value.value is False)
    return False


def _is_httpx_ctor(call: ast.Call) -> bool:
    name = dotted(call.func) or ""
    return name.startswith("httpx.") and bool(_CLIENT_CTOR_RE.search(name))


def _explicit_follow_redirects_false(call: ast.Call) -> bool:
    """True only when `call` EXPLICITLY sets `follow_redirects=False` -- never merely absent.
    For a recognized `httpx.*` constructor, ABSENT means httpx's own documented default (does not
    follow), which `_enables_redirects` already models. For an unrecognized name -- an
    httpx-API-compatible client under its own module name (fastmcp's `httpx2`, a vendored fork,
    a test double) -- we cannot assume that library's default, so only an explicit, literal
    `False` counts as evidence."""
    for kw in call.keywords:
        if kw.arg == "follow_redirects":
            return isinstance(kw.value, ast.Constant) and kw.value.value is False
    return False


def httpx_follows_no_redirects(call: ast.Call, bindings: Bindings) -> bool:
    """True when `call` is an httpx (or httpx-API-compatible) request that will NOT follow
    redirects: neither this call nor the client it is made on opts in with
    `follow_redirects=True`, and either the client is a recognized `httpx.*` constructor (httpx's
    own default applies) or it explicitly disables redirects itself."""
    func = call.func
    if not isinstance(func, ast.Attribute) or _enables_redirects(call):
        return False
    recv_node = func.value
    recv = dotted(recv_node)
    if recv is None:
        return False
    if recv == "httpx":  # module-level `httpx.get(...)`
        return True
    if isinstance(recv_node, ast.Call):  # `httpx.Client(...).get(...)` or a compatible client
        return (
            _is_httpx_ctor(recv_node) or _explicit_follow_redirects_false(recv_node)
        ) and not _enables_redirects(recv_node)
    ctors = bindings.get(recv)
    if not ctors:
        return False
    return all(
        (_is_httpx_ctor(c) or _explicit_follow_redirects_false(c)) and not _enables_redirects(c)
        for c in ctors
    )
