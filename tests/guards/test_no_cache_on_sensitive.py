from __future__ import annotations

import pytest

from agentsec.guards.no_cache_on_sensitive import NoCacheOnSensitiveGuard
from tests.guards._common import *  # noqa: F401,F403


def test_no_cache_on_sensitive_fires(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n@router.get('/me')\nasync def get_me():\n    return {}\n",
        encoding="utf-8",
    )
    findings = NoCacheOnSensitiveGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert any(f.rule == "no-cache-on-sensitive/missing-no-store" for f in findings)

def test_no_cache_on_sensitive_cache_control_silences(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n@router.get('/me')\nasync def get_me():\n"
        "    headers = {'Cache-Control': 'no-store'}\n    return {}\n",
        encoding="utf-8",
    )
    assert NoCacheOnSensitiveGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_no_cache_on_sensitive_pragma_silences(tmp_path: Path) -> None:
    # The file-wide opt-out still stops a finding being anchored in its file after #899 moved the
    # pragma check behind pass 1's read.
    (tmp_path / "routes.py").write_text(
        "# security: allow-cacheable-response\n"
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n@router.get('/me')\nasync def get_me():\n    return {}\n",
        encoding="utf-8",
    )
    assert NoCacheOnSensitiveGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_no_cache_on_sensitive_kwarg_after_path_fires(tmp_path: Path) -> None:
    # Regression (#422): a kwarg after the path must not defeat the route match.
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
        "@router.get('/me', response_model=dict)\nasync def get_me():\n    return {}\n",
        encoding="utf-8",
    )
    findings = NoCacheOnSensitiveGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert any(f.rule == "no-cache-on-sensitive/missing-no-store" for f in findings)

def test_no_cache_on_sensitive_public_path_with_kwarg_silent(tmp_path: Path) -> None:
    # FP-bait for the widened match: a non-sensitive path with a kwarg stays silent.
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
        "@router.get('/items', response_model=list)\nasync def list_items():\n    return []\n",
        encoding="utf-8",
    )
    assert NoCacheOnSensitiveGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_no_cache_on_sensitive_docstring_example_silent(tmp_path: Path) -> None:
    # Precision fix: a route decorator inside a docstring example should not fire.
    (tmp_path / "docs.py").write_text(
        '"""API examples.\n'
        "\n"
        "Sensitive routes need cache headers:\n"
        "\n"
        "    @app.get('/me')\n"
        "    async def get_me():\n"
        "        return db.query(User).first()\n"
        '"""\n',
        encoding="utf-8",
    )
    assert NoCacheOnSensitiveGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []



def test_no_cache_sensitive_stems_need_a_segment_boundary(tmp_path: Path) -> None:
    # Regression (#437 review): the stem alternation had no segment boundary and `[^'"]*` let a
    # stem bleed into an unrelated word — `/metrics`, `/messages` and `/media/{id}` all matched
    # the `me` stem and `/authors` matched `auth`, so four ordinary routes drew a finding.
    body = "from fastapi import APIRouter\nrouter = APIRouter()\n"
    for i, path in enumerate(("/metrics", "/messages", "/media/{id}", "/authors", "/metadata")):
        body += f"@router.get('{path}')\ndef h{i}(): return {{}}\n"
    (tmp_path / "routes.py").write_text(body, encoding="utf-8")
    assert NoCacheOnSensitiveGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_no_cache_sensitive_real_paths_and_plurals_still_fire(tmp_path: Path) -> None:
    # The boundary must not cost the real signal, including the plural spellings the stems are
    # obviously meant to cover.
    paths = ("/me", "/users/{id}", "/auth/login", "/tokens", "/account", "/admin/panel", "/payments")
    body = "from fastapi import APIRouter\nrouter = APIRouter()\n"
    for i, path in enumerate(paths):
        body += f"@router.get('{path}')\ndef h{i}(): return {{}}\n"
    (tmp_path / "routes.py").write_text(body, encoding="utf-8")
    assert len(NoCacheOnSensitiveGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))) == len(paths)


def test_no_cache_sensitive_silent_on_nonproduct_path(tmp_path: Path) -> None:
    # Corpus-scan FP: `fastapi/fastapi`'s own `docs_src/` tutorials (already in the
    # shared `is_nonproduct_path` list) over-fired this guard 96 times on one repo — the guard
    # never called `is_nonproduct_path` at all before this fix.
    d = tmp_path / "docs_src"
    d.mkdir()
    (d / "routes.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n@router.get('/me')\nasync def get_me():\n    return {}\n",
        encoding="utf-8",
    )
    assert NoCacheOnSensitiveGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_no_cache_sensitive_still_fires_at_a_normal_path(tmp_path: Path) -> None:
    # Direction traded against (CLAUDE.md rule 1): a sibling non-product directory must not
    # silence the same violation shape at an ordinary path.
    (tmp_path / "docs_src").mkdir()
    (tmp_path / "docs_src" / "routes.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n@router.get('/me')\nasync def get_me():\n    return {}\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n@router.get('/me')\nasync def get_me():\n    return {}\n",
        encoding="utf-8",
    )
    findings = NoCacheOnSensitiveGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert any(f.location.startswith("app.py") for f in findings)
    assert not any(f.location.startswith("docs_src") for f in findings)


def test_no_cache_sensitive_silent_when_signal_outside_old_fixed_window(tmp_path: Path) -> None:
    # the Cache-Control signal sits well past the old 30-line look-ahead but is still
    # inside the SAME function body. Before this fix, the padding below would have pushed the
    # header out of the window and made the guard false-fire on genuinely safe code.
    padding = "\n".join(f"    step_{n} = n\n" for n in range(35))
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter, Response\n"
        "router = APIRouter()\n"
        "\n"
        "@router.get('/me')\n"
        "async def get_me(response: Response):\n"
        f"{padding}"
        "    response.headers['Cache-Control'] = 'no-store'\n"
        "    return {}\n",
        encoding="utf-8",
    )
    assert NoCacheOnSensitiveGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_no_cache_sensitive_still_fires_when_signal_is_in_a_decorator_stacked_above(
    tmp_path: Path,
) -> None:
    # Directionality regression guard: `@no_store_wrapper` textually matches the `no.store`
    # signal pattern but sits ABOVE `@router.get('/me')`, before the anchor line — the widened
    # look-ahead must start at the matched route decorator itself, not the enclosing span's true
    # start (which would also swallow decorators stacked above it).
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@no_store_wrapper\n"
        "@router.get('/me')\n"
        "async def get_me():\n"
        "    return {}\n",
        encoding="utf-8",
    )
    findings = NoCacheOnSensitiveGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "no-cache-on-sensitive/missing-no-store"


# --- #899: a registered middleware that sets no-store on every response covers the routes ---------

_SENSITIVE_ROUTE = (
    "from fastapi import APIRouter\n"
    "router = APIRouter()\n"
    "\n"
    "@router.get('/users/me')\n"
    "async def read_me():\n"
    "    return {'email': 'a@b.c'}\n"
)


def _http_middleware(body: str) -> str:
    """A `main.py` with an `@app.middleware("http")` function whose post-response body is `body`."""
    return (
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n"
        "\n"
        '@app.middleware("http")\n'
        "async def security_headers(request: Request, call_next):\n"
        "    response = await call_next(request)\n"
        f"{body}"
        "    return response\n"
    )


_NO_STORE = '    response.headers["Cache-Control"] = "no-store"\n'

_BASE_HTTP_MIDDLEWARE_CLASS = (
    "from starlette.middleware.base import BaseHTTPMiddleware\n"
    "\n"
    "class NoStoreHeaders(BaseHTTPMiddleware):\n"
    "    async def dispatch(self, request, call_next):\n"
    "        response = await call_next(request)\n"
    '        response.headers.setdefault("Cache-Control", "no-store")\n'
    "        return response\n"
)

_REGISTER_NO_STORE_HEADERS = (
    "from fastapi import FastAPI\n"
    "from app.middleware.headers import NoStoreHeaders\n"
    "app = FastAPI()\n"
    "app.add_middleware(NoStoreHeaders)\n"
)


def _tree(root: Path, files: dict[str, str]) -> list:
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return NoCacheOnSensitiveGuard().run(root, _fastapi_nodirs_prof(root))


def test_no_cache_sensitive_silent_under_same_file_http_middleware(tmp_path: Path) -> None:
    # #899 case 1: the middleware and the route share one file.
    route = "\n@app.get('/users/me')\nasync def read_me():\n    return {'email': 'a@b.c'}\n"
    assert _tree(tmp_path, {"main.py": _http_middleware(_NO_STORE) + route}) == []


def test_no_cache_sensitive_silent_under_cross_file_http_middleware(tmp_path: Path) -> None:
    # #899 case 2 (multi-file): middleware in the root `main.py`, the route in `routes/users.py`.
    # A root-level file's middleware covers the whole tree.
    files = {"main.py": _http_middleware(_NO_STORE), "routes/users.py": _SENSITIVE_ROUTE}
    assert _tree(tmp_path, files) == []


def test_no_cache_sensitive_silent_under_registered_base_http_middleware(tmp_path: Path) -> None:
    # #899 case 3 (multi-file, cross-file registration): the class is defined in one file,
    # registered in another, and covers a route in a third, all under `app/`.
    files = {
        "app/middleware/headers.py": _BASE_HTTP_MIDDLEWARE_CLASS,
        "app/main.py": _REGISTER_NO_STORE_HEADERS,
        "app/routes/users.py": _SENSITIVE_ROUTE,
    }
    assert _tree(tmp_path, files) == []


def test_no_cache_sensitive_silent_under_raw_asgi_middleware(tmp_path: Path) -> None:
    # #899 case 4: raw ASGI appends the bytes header pair inside a nested `send_wrapper`, under a
    # `message["type"]` check. That check is protocol plumbing, not path scoping.
    asgi = (
        "from fastapi import FastAPI\n"
        "\n"
        "class NoStoreASGI:\n"
        "    def __init__(self, app):\n"
        "        self.app = app\n"
        "\n"
        "    async def __call__(self, scope, receive, send):\n"
        '        if scope["type"] != "http":\n'
        "            await self.app(scope, receive, send)\n"
        "            return\n"
        "\n"
        "        async def send_wrapper(message):\n"
        '            if message["type"] == "http.response.start":\n'
        '                message.setdefault("headers", []).append((b"cache-control", b"no-store"))\n'
        "            await send(message)\n"
        "\n"
        "        await self.app(scope, receive, send_wrapper)\n"
        "\n"
        "app = FastAPI()\n"
        "app.add_middleware(NoStoreASGI)\n"
    )
    assert _tree(tmp_path, {"main.py": asgi, "routes/users.py": _SENSITIVE_ROUTE}) == []


def test_no_cache_sensitive_silent_under_header_dict_middleware(tmp_path: Path) -> None:
    # #899 case 5: several headers set at once from a dict literal.
    body = (
        "    response.headers.update({\n"
        '        "X-Frame-Options": "DENY",\n'
        '        "Cache-Control": "no-store, max-age=0",\n'
        "    })\n"
    )
    assert _tree(tmp_path, {"main.py": _http_middleware(body), "routes/users.py": _SENSITIVE_ROUTE}) == []


def test_no_cache_sensitive_silent_under_module_constant_header_dict(tmp_path: Path) -> None:
    # #899 case 14 (the RCA's optional extension): the header dict is a module-level constant,
    # applied by `update()` or by a loop over `.items()`.
    const = 'SECURITY_HEADERS = {"X-Frame-Options": "DENY", "Cache-Control": "no-store"}\n\n'
    for body in (
        "    response.headers.update(SECURITY_HEADERS)\n",
        "    for name, value in SECURITY_HEADERS.items():\n        response.headers[name] = value\n",
        "    for name, value in SECURITY_HEADERS.items():\n        response.headers.setdefault(name, value)\n",
    ):
        (tmp_path / "main.py").write_text(const + _http_middleware(body), encoding="utf-8")
        assert _tree(tmp_path, {"routes/users.py": _SENSITIVE_ROUTE}) == [], body


@pytest.mark.parametrize(
    "body",
    [
        "    for name, value in SECURITY_HEADERS.items():\n        print(name, value)\n",
        '    for name, value in SECURITY_HEADERS.items():\n        if name == "Cache-Control":\n'
        "            continue\n        response.headers[name] = value\n",
        '    for name, value in SECURITY_HEADERS.items():\n        if name.lower() != "cache-control":\n'
        "            response.headers[name] = value\n",
        "    for name, value in SECURITY_HEADERS.items():\n        other.headers[name] = value\n",
    ],
    ids=["body-ignores-pair", "continue-skips-header", "filtered-header", "other-object"],
)
def test_no_cache_sensitive_still_fires_when_header_loop_does_not_apply_no_store(
    tmp_path: Path, body: str
) -> None:
    # #954 C4: iterating a header constant that holds no-store proves nothing unless the loop body
    # writes each pair onto the returned response on every iteration.
    const = 'SECURITY_HEADERS = {"X-Frame-Options": "DENY", "Cache-Control": "no-store"}\n\n'
    files = {"main.py": const + _http_middleware(body), "routes/users.py": _SENSITIVE_ROUTE}
    assert [f.location.replace("\\", "/") for f in _tree(tmp_path, files)] == ["routes/users.py:4"]


@pytest.mark.parametrize(
    "body",
    [
        '    headers = response.headers\n    headers["Cache-Control"] = "no-store"\n',
        _NO_STORE + '    response.headers["X-Frame-Options"] = "DENY"\n',
        '    if not response.headers.get("cache-control"):\n    ' + _NO_STORE,
        '    if request.method == "OPTIONS":\n        return response\n' + _NO_STORE,
        # #954 R2-C1 FP-bait: calls that never receive the response or its headers cannot undo
        # the write; a scalar read off the response and a method called on it are not hand-offs.
        _NO_STORE + '    logger.info("served %s", request.url.path)\n'
        "    record_metrics(request, response.status_code)\n"
        '    response.set_cookie("seen", "1")\n',
    ],
    ids=["header-view-alias", "other-header-alongside", "get-presence-check", "method-early-exit",
         "unrelated-calls"],
)
def test_no_cache_sensitive_silent_under_equivalent_no_store_shapes(tmp_path: Path, body: str) -> None:
    # #954, rule 1 for the round-1 tightening: ordinary no-store shapes still cover the route.
    assert _tree(tmp_path, {"main.py": _http_middleware(body), "routes/users.py": _SENSITIVE_ROUTE}) == []


_FINALIZE_HELPER = (
    "\n"
    "def finalize_headers(target):\n"
    '    target["Cache-Control"] = "public, max-age=86400"\n'
)


@pytest.mark.parametrize(
    "call",
    [
        "    finalize_headers(response)\n",
        "    finalize_headers(response.headers)\n",
        "    if is_static_asset(request):\n        finalize_headers(response)\n",
        "    await audit.finalize(request, response=response)\n",
    ],
    ids=["sibling-helper", "headers-to-helper", "conditional-helper", "keyword-to-imported"],
)
def test_no_cache_sensitive_still_fires_when_response_is_handed_to_an_unseen_call(
    tmp_path: Path, call: str
) -> None:
    # #954 R2-C1: pass 1 does not follow calls, so a helper handed the response after the
    # no-store write may overwrite it (here `finalize_headers` sets `public`). The credit is void.
    main = _http_middleware(_NO_STORE + call) + _FINALIZE_HELPER
    files = {"main.py": main, "routes/users.py": _SENSITIVE_ROUTE}
    assert [f.location.replace("\\", "/") for f in _tree(tmp_path, files)] == ["routes/users.py:4"]


def test_no_cache_sensitive_still_fires_when_dispatch_hands_response_to_a_method(tmp_path: Path) -> None:
    # #954 R2-C1: the same hand-off through a method on the middleware class.
    cls = _BASE_HTTP_MIDDLEWARE_CLASS.replace(
        "        return response\n",
        "        self._finalize(response)\n        return response\n"
        "\n"
        "    def _finalize(self, response):\n"
        '        response.headers["Cache-Control"] = "public, max-age=86400"\n',
    )
    files = {
        "app/middleware/headers.py": cls,
        "app/main.py": _REGISTER_NO_STORE_HEADERS,
        "app/routes/users.py": _SENSITIVE_ROUTE,
    }
    assert [f.location.replace("\\", "/") for f in _tree(tmp_path, files)] == ["app/routes/users.py:4"]


@pytest.mark.parametrize("key", ['"headers"', "HEADERS_KEY"], ids=["literal-key", "constant-key"])
def test_no_cache_sensitive_still_fires_when_asgi_headers_are_handed_off(tmp_path: Path, key: str) -> None:
    # #954 R3-H1: a raw-ASGI send wrapper hands `message["headers"]` to a helper after the
    # no-store append. The key resolves through a same-file constant like every other literal.
    asgi = (
        "from fastapi import FastAPI\n"
        'HEADERS_KEY = "headers"\n'
        "\n"
        "class NoStoreASGI:\n"
        "    def __init__(self, app):\n"
        "        self.app = app\n"
        "\n"
        "    async def __call__(self, scope, receive, send):\n"
        "        async def send_wrapper(message):\n"
        '            if message["type"] == "http.response.start":\n'
        f'                message[{key}].append((b"cache-control", b"no-store"))\n'
        f"                finalize(message[{key}])\n"
        "            await send(message)\n"
        "\n"
        "        await self.app(scope, receive, send_wrapper)\n"
        "\n"
        "def finalize(raw_headers):\n"
        '    raw_headers.append((b"cache-control", b"public"))\n'
        "\n"
        "app = FastAPI()\n"
        "app.add_middleware(NoStoreASGI)\n"
    )
    files = {"main.py": asgi, "routes/users.py": _SENSITIVE_ROUTE}
    assert [f.location.replace("\\", "/") for f in _tree(tmp_path, files)] == ["routes/users.py:4"]


@pytest.mark.parametrize(
    ("key", "other"),
    [('"headers"', '"status"'), ("HEADERS_KEY", "STATUS_KEY")],
    ids=["literal-key", "constant-key"],
)
def test_no_cache_sensitive_silent_when_asgi_non_header_field_is_handed_off(
    tmp_path: Path, key: str, other: str
) -> None:
    # #954 R5-M1, rule 1 for the R3-H1 widening: the sibling above with the helper handed
    # `message["status"]` instead. Only a key resolving to a header container is a hand-off, so
    # this stays silent; an over-eager `_exposes` (any subscript, or any constant key) fires here.
    asgi = (
        "from fastapi import FastAPI\n"
        "from app.metrics import record_status\n"
        'HEADERS_KEY = "headers"\n'
        'STATUS_KEY = "status"\n'
        "\n"
        "class NoStoreASGI:\n"
        "    def __init__(self, app):\n"
        "        self.app = app\n"
        "\n"
        "    async def __call__(self, scope, receive, send):\n"
        "        async def send_wrapper(message):\n"
        '            if message["type"] == "http.response.start":\n'
        f'                message[{key}].append((b"cache-control", b"no-store"))\n'
        f"                record_status(message[{other}])\n"
        "            await send(message)\n"
        "\n"
        "        await self.app(scope, receive, send_wrapper)\n"
        "\n"
        "app = FastAPI()\n"
        "app.add_middleware(NoStoreASGI)\n"
    )
    assert _tree(tmp_path, {"main.py": asgi, "routes/users.py": _SENSITIVE_ROUTE}) == []


def test_no_cache_sensitive_silent_under_raw_asgi_mutable_headers(tmp_path: Path) -> None:
    # #954: Starlette's `MutableHeaders(scope=message)` is a view of the forwarded message.
    asgi = (
        "from fastapi import FastAPI\n"
        "from starlette.datastructures import MutableHeaders\n"
        "\n"
        "class NoStoreASGI:\n"
        "    def __init__(self, app):\n"
        "        self.app = app\n"
        "\n"
        "    async def __call__(self, scope, receive, send):\n"
        "        async def send_wrapper(message):\n"
        '            if message["type"] == "http.response.start":\n'
        "                headers = MutableHeaders(scope=message)\n"
        '                headers.append("Cache-Control", "no-store")\n'
        "            await send(message)\n"
        "\n"
        "        await self.app(scope, receive, send_wrapper)\n"
        "\n"
        "app = FastAPI()\n"
        "app.add_middleware(NoStoreASGI)\n"
    )
    assert _tree(tmp_path, {"main.py": asgi, "routes/users.py": _SENSITIVE_ROUTE}) == []


@pytest.mark.parametrize(
    "condition",
    [
        '"cache-control" not in response.headers',
        # Every operand benign: a compound condition stays benign.
        '"cache-control" not in response.headers and request.method == "GET"',
    ],
)
def test_no_cache_sensitive_silent_under_deny_by_default_middleware(tmp_path: Path, condition: str) -> None:
    # The shape the remediation recommends: no-store unless the route already set its own value.
    # A header-presence check is not path scoping.
    body = f"    if {condition}:\n    " + _NO_STORE
    assert _tree(tmp_path, {"main.py": _http_middleware(body), "routes/users.py": _SENSITIVE_ROUTE}) == []


def test_no_cache_sensitive_silent_under_dispatch_function_middleware(tmp_path: Path) -> None:
    # Starlette's function form: `add_middleware(BaseHTTPMiddleware, dispatch=fn)`.
    main = (
        "from fastapi import FastAPI\n"
        "from starlette.middleware.base import BaseHTTPMiddleware\n"
        "\n"
        "async def no_store(request, call_next):\n"
        "    response = await call_next(request)\n"
        f"{_NO_STORE}"
        "    return response\n"
        "\n"
        "app = FastAPI()\n"
        "app.add_middleware(BaseHTTPMiddleware, dispatch=no_store)\n"
    )
    assert _tree(tmp_path, {"main.py": main, "routes/users.py": _SENSITIVE_ROUTE}) == []


def test_no_cache_sensitive_middleware_in_pragma_file_still_covers(tmp_path: Path) -> None:
    # #899 test 13, CLAUDE.md rule 4: the pragma only stops findings being ANCHORED in its file.
    # Pass 1 still reads that file, so its middleware still covers the route in another file.
    main = "# security: allow-cacheable-response\n" + _http_middleware(_NO_STORE)
    assert _tree(tmp_path, {"main.py": main, "routes/users.py": _SENSITIVE_ROUTE}) == []


@pytest.mark.parametrize(
    "body",
    [
        # #899 case 6: an unsafe value set globally is not coverage.
        '    response.headers["Cache-Control"] = "public, max-age=3600"\n',
        # #899 case 7: no-store only under a path condition.
        '    if request.url.path.startswith("/api"):\n    ' + _NO_STORE,
        # #899 case 9: a negated path allow-list stays firing in v1 (the conservative direction).
        '    if not request.url.path.startswith("/static"):\n    ' + _NO_STORE,
        # A path-scoped early exit scopes every write after it.
        '    if not request.url.path.startswith("/api"):\n        return response\n' + _NO_STORE,
        # A condition that is not a protocol / method / header-presence check is not proof.
        "    if response.status_code >= 400:\n    " + _NO_STORE,
        # A benign operand must not carry a path decision hidden behind an alias.
        '    if request.method == "GET" and is_sensitive:\n    ' + _NO_STORE,
        # A write in an `except` handler covers only the error responses.
        "    try:\n        pass\n    except Exception:\n    " + _NO_STORE,
        # #899 case 11: the middleware exists only in prose.
        '    """Sets response.headers["Cache-Control"] = "no-store" on every response."""\n'
        '    # response.headers["Cache-Control"] = "no-store"\n',
        # #954 C1: a nested helper that is never called, or called only under a flag.
        "    def _unused():\n    " + _NO_STORE,
        "    def add_no_store():\n    " + _NO_STORE + "    if settings.STRICT:\n        add_no_store()\n",
        # #954 C2: the header lands on a response the middleware does not return.
        '    other = Response()\n    other.headers["Cache-Control"] = "no-store"\n',
        # #954 C3: a later write or removal wins over the no-store write.
        _NO_STORE + '    response.headers["Cache-Control"] = "public, max-age=3600"\n',
        _NO_STORE + '    del response.headers["Cache-Control"]\n',
        _NO_STORE + '    response.headers.pop("cache-control", None)\n',
        # The returned name is rebound after the write, so the written response is not returned.
        _NO_STORE + "    response = JSONResponse({})\n",
        # A loop body may run zero times: `for` is a condition on its iterable.
        "    for _ in sensitive_matches(request):\n    " + _NO_STORE,
        # Naming the header in a condition is not the presence check that makes it benign.
        '    if response.headers.get("cache-control") == "private":\n    ' + _NO_STORE,
    ],
    ids=["unsafe-value", "path-scoped", "negated-allow-list", "path-early-exit", "status-check",
         "benign-and-alias", "except-only", "prose-only", "uncalled-helper", "flag-called-helper",
         "other-response", "overwritten-later", "deleted-later", "popped-later", "response-rebound",
         "loop-body", "header-value-condition"],
)
def test_no_cache_sensitive_still_fires_when_middleware_is_not_proof(tmp_path: Path, body: str) -> None:
    # Rule 1: every direction the #899 narrowing traded against keeps firing.
    findings = _tree(tmp_path, {"main.py": _http_middleware(body), "routes/users.py": _SENSITIVE_ROUTE})
    assert [f.location.replace("\\", "/") for f in findings] == ["routes/users.py:4"]


@pytest.mark.parametrize(
    "registration",
    ["app.add_middleware(middleware_class=NoStoreHeaders)\n", "app = FastAPI(middleware=[Middleware(cls=NoStoreHeaders)])\n"],
    ids=["add-middleware-keyword", "middleware-list-keyword"],
)
def test_no_cache_sensitive_silent_under_keyword_registered_middleware(tmp_path: Path, registration: str) -> None:
    # #1016 review M1: `registered_names` is shared, and Starlette's keyword spelling of the class
    # argument (`middleware_class=` / `cls=`) is the same registration as the positional one.
    main = _REGISTER_NO_STORE_HEADERS.replace("app.add_middleware(NoStoreHeaders)\n", registration)
    files = {
        "app/middleware/headers.py": _BASE_HTTP_MIDDLEWARE_CLASS,
        "app/main.py": "from starlette.middleware import Middleware\n" + main,
        "app/routes/users.py": _SENSITIVE_ROUTE,
    }
    assert _tree(tmp_path, files) == []


def test_no_cache_sensitive_still_fires_under_keyword_registered_middleware_that_is_not_proof(
    tmp_path: Path,
) -> None:
    # The direction the keyword credit trades against: reading the keyword only finds the class;
    # its body must still prove no-store. A `public` cache header proves nothing.
    files = {
        "app/middleware/headers.py": _BASE_HTTP_MIDDLEWARE_CLASS.replace('"no-store"', '"public, max-age=60"'),
        "app/main.py": _REGISTER_NO_STORE_HEADERS.replace(
            "app.add_middleware(NoStoreHeaders)", "app.add_middleware(middleware_class=NoStoreHeaders)"
        ),
        "app/routes/users.py": _SENSITIVE_ROUTE,
    }
    assert [f.location.replace("\\", "/") for f in _tree(tmp_path, files)] == ["app/routes/users.py:4"]


def test_no_cache_sensitive_still_fires_when_middleware_class_is_not_registered(tmp_path: Path) -> None:
    # #899 case 8: the class writes no-store but nothing passes it to `add_middleware`.
    files = {"app/middleware/headers.py": _BASE_HTTP_MIDDLEWARE_CLASS, "app/routes/users.py": _SENSITIVE_ROUTE}
    assert [f.location.replace("\\", "/") for f in _tree(tmp_path, files)] == ["app/routes/users.py:4"]


def test_no_cache_sensitive_still_fires_when_registration_is_conditional(tmp_path: Path) -> None:
    # A middleware registered only when a setting is on is not proof (the #473 rule): flip the
    # setting and every sensitive route is cacheable.
    main = (
        "from fastapi import FastAPI\n"
        "from app.middleware.headers import NoStoreHeaders\n"
        "from app.config import settings\n"
        "app = FastAPI()\n"
        "if settings.SECURITY_HEADERS:\n"
        "    app.add_middleware(NoStoreHeaders)\n"
    )
    files = {
        "app/middleware/headers.py": _BASE_HTTP_MIDDLEWARE_CLASS,
        "app/main.py": main,
        "app/routes/users.py": _SENSITIVE_ROUTE,
    }
    assert [f.location.replace("\\", "/") for f in _tree(tmp_path, files)] == ["app/routes/users.py:4"]


def test_no_cache_sensitive_middleware_covers_only_its_own_top_level_dir(tmp_path: Path) -> None:
    # #899 case 10 (monorepo): `app_a/` registers the middleware, `app_b/` does not.
    files = {
        "app_a/main.py": _http_middleware(_NO_STORE),
        "app_a/routes.py": _SENSITIVE_ROUTE,
        "app_b/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        "app_b/routes.py": _SENSITIVE_ROUTE,
    }
    assert [f.location.replace("\\", "/") for f in _tree(tmp_path, files)] == ["app_b/routes.py:4"]


@pytest.mark.parametrize(
    "app_b_definition",
    [
        _BASE_HTTP_MIDDLEWARE_CLASS.replace(
            '        response.headers.setdefault("Cache-Control", "no-store")\n',
            '        response.headers["X-Frame-Options"] = "DENY"\n',
        ),
        # A bare raw-ASGI class whose file never says `middleware` or `cache-control` must still
        # be seen as app_b's own definition.
        "class NoStoreHeaders:\n"
        "    def __init__(self, app):\n"
        "        self.app = app\n"
        "\n"
        "    async def __call__(self, scope, receive, send):\n"
        "        await self.app(scope, receive, send)\n",
    ],
    ids=["base-http-no-header", "raw-asgi-no-header"],
)
def test_no_cache_sensitive_same_named_middleware_resolves_per_dir(
    tmp_path: Path, app_b_definition: str
) -> None:
    # Two apps each define and register their OWN `NoStoreHeaders`; only app_a's writes no-store.
    # The name match must not lend app_a's definition to app_b's registration.
    register = "from fastapi import FastAPI\napp = FastAPI()\napp.add_middleware(NoStoreHeaders)\n"
    files = {
        "app_a/headers.py": _BASE_HTTP_MIDDLEWARE_CLASS,
        "app_a/main.py": register,
        "app_a/routes.py": _SENSITIVE_ROUTE,
        "app_b/headers.py": app_b_definition,
        "app_b/main.py": register,
        "app_b/routes.py": _SENSITIVE_ROUTE,
    }
    assert [f.location.replace("\\", "/") for f in _tree(tmp_path, files)] == ["app_b/routes.py:4"]


def test_no_cache_sensitive_shared_lib_middleware_covers_the_registering_dir(tmp_path: Path) -> None:
    # A class defined in a shared package covers the app that registers it, not the one that
    # doesn't.
    register = (
        "from fastapi import FastAPI\nfrom libs.headers import NoStoreHeaders\n"
        "app = FastAPI()\napp.add_middleware(NoStoreHeaders)\n"
    )
    files = {
        "libs/headers.py": _BASE_HTTP_MIDDLEWARE_CLASS,
        "svc_a/main.py": register,
        "svc_a/routes.py": _SENSITIVE_ROUTE,
        "svc_b/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        "svc_b/routes.py": _SENSITIVE_ROUTE,
    }
    assert [f.location.replace("\\", "/") for f in _tree(tmp_path, files)] == ["svc_b/routes.py:4"]


@pytest.mark.parametrize("conftest", ["tests/conftest.py", "app/tests/conftest.py"])
def test_no_cache_sensitive_test_only_middleware_does_not_cover(tmp_path: Path, conftest: str) -> None:
    # #899 case 13: a test app's middleware never runs in front of the product routes, including
    # a `tests/` tree nested inside the app's own top-level directory.
    files = {conftest: _http_middleware(_NO_STORE), "app/routes/users.py": _SENSITIVE_ROUTE}
    assert [f.location.replace("\\", "/") for f in _tree(tmp_path, files)] == ["app/routes/users.py:4"]
