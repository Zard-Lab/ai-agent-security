from __future__ import annotations

import pytest

from agentsec.guards.websocket_no_auth import WebsocketNoAuthGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def test_websocket_no_auth_flags_bare_endpoint(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        '@app.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "websocket-no-auth/websocket-without-auth-dep"
    assert findings[0].severity == "high"

def test_websocket_no_auth_flags_router_decorator(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        '@router.websocket("/chat")\n'
        "async def chat_ws(websocket: WebSocket):\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "websocket-no-auth/websocket-without-auth-dep"

def test_websocket_no_auth_silent_with_depends(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        '@app.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket, user: User = Depends(get_current_user)):\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert findings == []

def test_websocket_no_auth_silent_with_security(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        '@app.websocket("/secure-ws")\n'
        "async def secure_ws(websocket: WebSocket, token: str = Security(verify_token)):\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert findings == []

def test_websocket_no_auth_silent_with_inline_httpbearer(tmp_path: Path) -> None:
    # `Depends(HTTPBearer())` used to read as unauthenticated — no `_AUTH_NAME` stem is
    # a substring of `HTTPBearer` (confirmed by reading `_AUTH_SEGMENT_STEMS`/`_AUTH_PREFIX_STEMS`
    # directly). Closed with a conservative allowlist of FastAPI's own security-scheme class
    # names, not a stem widening (`AUTH_CALL_NAMED`, base.py).
    (tmp_path / "main.py").write_text(
        '@app.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket, creds=Depends(HTTPBearer())):\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert findings == []


def test_websocket_no_auth_silent_with_module_level_security_scheme_var(tmp_path: Path) -> None:
    # the 2nd confirmed FN shape: the class name is instantiated once, at module level,
    # and referenced by variable name at the Depends() call site — the class name itself never
    # appears there. `security_scheme_var_names`/`auth_call_named_with_aliases` resolve it.
    (tmp_path / "main.py").write_text(
        "bearer_scheme = HTTPBearer()\n\n"
        '@app.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket, creds=Depends(bearer_scheme)):\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert findings == []


def test_websocket_no_auth_fires_when_alias_var_is_not_a_security_scheme(tmp_path: Path) -> None:
    # FP-bait for the alias resolver above: a module-level variable bound to something that is
    # NOT one of the closed security-scheme classes must not be mistaken for one just because its
    # name happens to be plausible-sounding — `security_scheme_var_names` is exact-class-matched,
    # not name-heuristic.
    (tmp_path / "main.py").write_text(
        "bearer_scheme = get_db()\n\n"
        '@app.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket, db=Depends(bearer_scheme)):\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_websocket_no_auth_alias_resolution_does_not_cross_files(tmp_path: Path) -> None:
    # fix-round review, Critical 1 shape (a): file_a.py legitimately binds
    # `bearer_scheme` to a real security scheme; file_b.py's OWN `bearer_scheme` is an unrelated
    # DB dependency, reused as a genuinely unauthenticated WS route's Depends() argument. The
    # SAME common variable name in two unrelated files must not let file_a's binding authorize
    # file_b's route — a stronger discriminator than a name that's never a scheme anywhere (which
    # would pass identically even with the whole alias feature deleted).
    (tmp_path / "file_a.py").write_text(
        "from fastapi import APIRouter, Depends, WebSocket\n"
        "from fastapi.security import HTTPBearer\n"
        "bearer_scheme = HTTPBearer()\n"
        "router = APIRouter()\n"
        "\n"
        '@router.websocket("/ws-a")\n'
        "async def ws_a(websocket: WebSocket, creds=Depends(bearer_scheme)):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    (tmp_path / "file_b.py").write_text(
        "from fastapi import APIRouter, Depends, WebSocket\n"
        "bearer_scheme = get_db()\n"
        "router = APIRouter()\n"
        "\n"
        '@router.websocket("/ws-b")\n'
        "async def ws_b(websocket: WebSocket, db=Depends(bearer_scheme)):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    locations = {f.location for f in findings}
    assert any("file_b.py" in loc for loc in locations), (
        "file_b's route uses its OWN non-scheme bearer_scheme and must still fire"
    )
    assert not any("file_a.py" in loc for loc in locations), (
        "file_a's route is genuinely authed and must stay silent"
    )


def test_websocket_no_auth_fp_bait_auto_error_disabled_scheme_still_fires(tmp_path: Path) -> None:
    # fix-round review, Critical 2: `auto_error=False` schemes don't enforce. Both the
    # inline and module-variable shapes must still fire.
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, WebSocket\n"
        "from fastapi.security import HTTPBearer\n"
        "optional_scheme = HTTPBearer(auto_error=False)\n"
        "\n"
        '@app.websocket("/ws-inline")\n'
        "async def ws_inline(websocket: WebSocket, creds=Depends(HTTPBearer(auto_error=False))):\n"
        "    await websocket.accept()\n"
        "\n"
        '@app.websocket("/ws-var")\n'
        "async def ws_var(websocket: WebSocket, creds=Depends(optional_scheme)):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert len(findings) == 2, f"expected both routes to fire, got: {findings}"


def test_websocket_no_auth_fp_bait_auto_error_disabled_multiline_still_fires(tmp_path: Path) -> None:
    # (Dean, review): the ORIGINAL bounded-lookahead exclusion could not see past a
    # newline or a nested paren inside its own fixed-width window, so a multi-line
    # Depends(HTTPBearer(...)) call -- or one with a nested call before auto_error -- silently
    # read as ENFORCING and silenced the route. Both shapes here must still fire.
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, WebSocket\n"
        "from fastapi.security import HTTPBearer\n"
        "optional_scheme = HTTPBearer(\n"
        "    auto_error=False,\n"
        ")\n"
        "\n"
        '@app.websocket("/ws-multiline")\n'
        "async def ws_multiline(websocket: WebSocket, creds=Depends(HTTPBearer(\n"
        "    auto_error=False,\n"
        "))):\n"
        "    await websocket.accept()\n"
        "\n"
        '@app.websocket("/ws-nested-paren")\n'
        "async def ws_nested(websocket: WebSocket, creds=Depends(HTTPBearer(scheme_name=str(\"x\"), auto_error=False))):\n"
        "    await websocket.accept()\n"
        "\n"
        '@app.websocket("/ws-var")\n'
        "async def ws_var(websocket: WebSocket, creds=Depends(optional_scheme)):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert len(findings) == 3, f"expected all 3 routes to fire, got: {findings}"


def test_websocket_no_auth_enforcing_scheme_that_mentions_auto_error_stays_silent(tmp_path: Path) -> None:
    # #764 FP-bait: each scheme ENFORCES; the flag only appears in a comment, a string or a nested
    # call's own kwarg. The raw-span search blanked all three, so every route here fired.
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, WebSocket\n"
        "from fastapi.security import HTTPBearer\n"
        "bearer_scheme = HTTPBearer(  # don't set auto_error=False here\n"
        ")\n"
        "\n"
        '@app.websocket("/ws-var")\n'
        "async def ws_var(websocket: WebSocket, creds=Depends(bearer_scheme)):\n"
        "    await websocket.accept()\n"
        "\n"
        '@app.websocket("/ws-string")\n'
        'async def ws_string(websocket: WebSocket, creds=Depends(HTTPBearer(description="set auto_error=False to opt out"))):\n'
        "    await websocket.accept()\n"
        "\n"
        '@app.websocket("/ws-nested")\n'
        "async def ws_nested(websocket: WebSocket, creds=Depends(HTTPBearer(scheme_name=describe(auto_error=False)))):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert WebsocketNoAuthGuard().run(tmp_path, profile) == []


def test_websocket_no_auth_disabled_scheme_behind_a_comment_still_fires(tmp_path: Path) -> None:
    # #764, the direction traded against: a comment line ahead of a REAL `auto_error=False` must
    # not hide it. Splitting the raw text into arguments put the comment and the kwarg in one
    # argument and read this scheme as enforcing. Both shapes must fire.
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, WebSocket\n"
        "from fastapi.security import HTTPBearer\n"
        "bearer_scheme = HTTPBearer(\n"
        "    # optional auth for the public feed\n"
        "    auto_error=False,\n"
        ")\n"
        "\n"
        '@app.websocket("/ws-var")\n'
        "async def ws_var(websocket: WebSocket, creds=Depends(bearer_scheme)):\n"
        "    await websocket.accept()\n"
        "\n"
        '@app.websocket("/ws-inline")\n'
        "async def ws_inline(websocket: WebSocket, creds=Depends(HTTPBearer(  # don't require one\n"
        "    auto_error=False))):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert len(findings) == 2, f"expected both routes to fire, got: {findings}"


def test_websocket_no_auth_fires_with_only_a_rate_limiter(tmp_path: Path) -> None:
    # `Depends(RateLimiter(...))` used to read as an auth signal purely from the
    # Depends(...) wrapper's presence — a WebSocket route with only rate-limiting and zero real
    # auth check must still fire.
    (tmp_path / "main.py").write_text(
        '@app.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket, rl: None = Depends(RateLimiter(times=5, seconds=60))):\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "websocket-no-auth/websocket-without-auth-dep"

def test_websocket_no_auth_fires_with_router_level_rate_limiter(tmp_path: Path) -> None:
    # router level — mirrors `test_fires_when_router_level_dependency_is_a_rate_limiter`
    # in the auth-dependency-not-applied suite. A router mounted with only a RateLimiter must not
    # read as authed for every WebSocket route on it.
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi_limiter.depends import RateLimiter\n"
        "router = APIRouter(dependencies=[Depends(RateLimiter(times=5, seconds=60))])\n"
        "\n"
        '@router.websocket("/chat")\n'
        "async def chat_ws(websocket: WebSocket):\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "websocket-no-auth/websocket-without-auth-dep"

def test_websocket_no_auth_silent_with_rate_limiter_alongside_real_auth(tmp_path: Path) -> None:
    # The direction the NAMED-auth tightening traded against (Rule 1): rate-limit AND authenticate the same
    # WebSocket route. The RateLimiter must not cancel out the real auth dependency next to it.
    (tmp_path / "main.py").write_text(
        '@app.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket, "
        "rl: None = Depends(RateLimiter(times=2, seconds=5)), "
        "user: User = Depends(get_current_user)):\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert findings == []

def test_wrapper_hidden_auth_dep_is_known_limitation(tmp_path: Path) -> None:
    # KNOWN LIMITATION (documented on `AUTH_DEPENDS_SIGNAL` in guards/base.py) — the same residual
    # gap pinned in the auth-dependency-not-applied suite, reproduced here because both guards
    # share `AUTH_CALL_NAMED`. An auth callable behind a non-auth-named wrapper is not recognized,
    # so this correctly-authed WebSocket route FIRES. Pinned so a future widening is intentional
    # and visible; it needs the real argument resolver (the tail), not a wider regex.
    (tmp_path / "main.py").write_text(
        "import functools\n"
        '@app.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket, "
        "user: User = Depends(functools.partial(require_role, 'admin'))):\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "websocket-no-auth/websocket-without-auth-dep"


def test_websocket_no_auth_pragma_silences(tmp_path: Path) -> None:
    content = (
        '@app.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    pass\n"
        "# security: allow-websocket-no-auth\n"
    )
    (tmp_path / "main.py").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = WebsocketNoAuthGuard().run(tmp_path, profile)
    assert findings == []

def test_websocket_no_auth_not_fastapi(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert WebsocketNoAuthGuard().applies(profile) is False

def test_websocket_no_auth_query_param_token_silent(tmp_path: Path) -> None:
    # Precision fix: token passed via Query() is a recognized auth pattern for WebSockets
    # (Bearer header is unavailable during the WS handshake on many clients).
    (tmp_path / "ws.py").write_text(
        "from fastapi import APIRouter, WebSocket, Query\n"
        "@router.websocket('/ws')\n"
        "async def endpoint(websocket: WebSocket, token: str = Query(None)):\n"
        "    validate_token(token)\n", encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"}, python_dirs=["."])
    assert WebsocketNoAuthGuard().run(tmp_path, profile) == []

def test_websocket_no_auth_multiline_sig_with_depends_silent(tmp_path: Path) -> None:
    # Multi-line signatures: Depends on the 3rd line (beyond the 1-line window that
    # the old guard scanned) must now be caught.
    (tmp_path / "ws.py").write_text(
        "@app.websocket('/ws')\n"
        "async def endpoint(\n"
        "    websocket: WebSocket,\n"
        "    user: User = Depends(get_current_user),\n"
        "):\n"
        "    pass\n", encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"}, python_dirs=["."])
    assert WebsocketNoAuthGuard().run(tmp_path, profile) == []



# --- Cross-file router-level auth resolution (backlog #3b) -------------------------------------

_WS_RULE = "websocket-no-auth/websocket-without-auth-dep"


def _ws_rules(tmp_path: Path) -> set[str]:
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    return {f.rule for f in WebsocketNoAuthGuard().run(tmp_path, profile)}


def test_cross_file_include_with_auth_dep_suppresses_ws(tmp_path: Path) -> None:
    # A bare-signature WS route in routes/chat.py, authed cross-file by main.py's
    # `include_router(chat.router, dependencies=[Depends(get_current_user)])`.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "chat.py").write_text(
        "from fastapi import APIRouter, WebSocket\n"
        "router = APIRouter()\n"
        "\n"
        '@router.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import chat\n"
        "app = FastAPI()\n"
        "app.include_router(chat.router, dependencies=[Depends(get_current_user)])\n",
        encoding="utf-8",
    )
    assert _WS_RULE not in _ws_rules(tmp_path)


def test_same_file_router_construct_deps_suppresses_ws(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "from fastapi import APIRouter, Depends, WebSocket\n"
        "router = APIRouter(dependencies=[Depends(get_current_user)])\n"
        "\n"
        '@router.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    assert _WS_RULE not in _ws_rules(tmp_path)


def test_cross_file_include_without_deps_still_fires_ws(tmp_path: Path) -> None:
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "chat.py").write_text(
        "from fastapi import APIRouter, WebSocket\n"
        "router = APIRouter()\n"
        "\n"
        '@router.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from routes import chat\n"
        "app = FastAPI()\n"
        "app.include_router(chat.router, prefix='/api')\n",
        encoding="utf-8",
    )
    assert _WS_RULE in _ws_rules(tmp_path)


def test_custom_named_router_var_is_matched_ws(tmp_path: Path) -> None:
    # Proves the generalized `_WS_DECORATOR` regex captures a non-app/router var name. The custom
    # `chat_router` is authed same-file at construction, so the WS route is suppressed — which is
    # only possible if the decorator's var was captured and matched against the authed router set.
    (tmp_path / "chat.py").write_text(
        "from fastapi import APIRouter, Depends, WebSocket\n"
        "chat_router = APIRouter(dependencies=[Depends(get_current_user)])\n"
        "\n"
        '@chat_router.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    assert _WS_RULE not in _ws_rules(tmp_path)


def test_custom_named_router_var_unprotected_still_fires_ws(tmp_path: Path) -> None:
    # Same custom var, but NO router-level deps -> the generalized regex must still FLAG it (the
    # broadening from `@(?:app|router)` must not silently pass a custom-named bare WS route).
    (tmp_path / "chat.py").write_text(
        "from fastapi import APIRouter, WebSocket\n"
        "chat_router = APIRouter()\n"
        "\n"
        '@chat_router.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    assert _WS_RULE in _ws_rules(tmp_path)


def test_cross_file_protection_is_per_router_not_whole_file_ws(tmp_path: Path) -> None:
    # #473 HIGH 1: two routers in one module, only `admin_router` mounted with auth. The
    # resolver used to mark the whole `chat` STEM protected, silencing the bare WS route on
    # the unauthed sibling. Protection is per-router: this must still fire.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "chat.py").write_text(
        "from fastapi import APIRouter, WebSocket\n"
        "admin_router = APIRouter()\n"
        "public_router = APIRouter()\n"
        "\n"
        '@public_router.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import chat\n"
        "app = FastAPI()\n"
        "app.include_router(chat.admin_router, dependencies=[Depends(get_current_user)])\n"
        "app.include_router(chat.public_router)\n",
        encoding="utf-8",
    )
    assert _WS_RULE in _ws_rules(tmp_path)


def test_cross_file_protection_applies_to_the_named_router_ws(tmp_path: Path) -> None:
    # Pair to the above: the WS route sits on the router that IS mounted with auth, so
    # per-router resolution must still suppress (the narrowing must not become "never counts").
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "chat.py").write_text(
        "from fastapi import APIRouter, WebSocket\n"
        "admin_router = APIRouter()\n"
        "public_router = APIRouter()\n"
        "\n"
        '@admin_router.websocket("/ws")\n'
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import chat\n"
        "app = FastAPI()\n"
        "app.include_router(chat.admin_router, dependencies=[Depends(get_current_user)])\n"
        "app.include_router(chat.public_router)\n",
        encoding="utf-8",
    )
    assert _WS_RULE not in _ws_rules(tmp_path)


# --- #872: the decorator's own `dependencies=[...]` (bare factory AND the wrapped forms) ------------
# The signature window starts on the line AFTER the decorator, so the decorator's own
# `dependencies=[...]` was never read: a bare `requires_authenticated()` there (the #859 shape) and
# even a wrapped `Depends(get_current_user)` on a one-line decorator fired HIGH. The guard now reads
# that list through the shared `route_deps_carry_auth`, with the file's `auth_call` OR the curated
# bare-factory matcher. Each silent case has a still-fires partner (Rule 1).


def _ws_locations(tmp_path: Path) -> list[str]:
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    return [f.location for f in WebsocketNoAuthGuard().run(tmp_path, profile) if f.rule == _WS_RULE]


def test_fp_bait_ws_per_route_bare_auth_factory_dependency(tmp_path: Path) -> None:
    """The issue's repro (the fix): a bare auth factory in the decorator's own deps list, plain and
    module-qualified, is real auth."""
    (tmp_path / "ws.py").write_text(
        "@router.websocket('/ws', dependencies=[requires_authenticated()])\n"
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n"
        "\n"
        "@router.websocket('/ws2', dependencies=[_auth.requires_authenticated()])\n"
        "async def ws_other(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    assert _ws_locations(tmp_path) == []


def test_fp_bait_ws_wrapped_auth_dependency_on_the_decorator(tmp_path: Path) -> None:
    """The wider gap the RCA found: the WRAPPED forms every other route guard accepts were invisible
    here too when they sat in the decorator, because the decorator line is never in the window."""
    (tmp_path / "ws.py").write_text(
        "@router.websocket('/ws', dependencies=[Depends(get_current_user)])\n"
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n"
        "\n"
        "@app.websocket('/ws2', dependencies=[Depends(HTTPBearer())])\n"
        "async def ws_other(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    assert _ws_locations(tmp_path) == []


def test_fp_bait_ws_per_route_bare_auth_factory_alongside_a_non_auth_dependency(tmp_path: Path) -> None:
    """The multi-element list: a non-auth dep FIRST, the factory SECOND. The whole list is read."""
    (tmp_path / "ws.py").write_text(
        "@router.websocket('/ws', dependencies=[get_db(), requires_authenticated()])\n"
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    assert _ws_locations(tmp_path) == []


def test_ws_fires_when_decorator_dependency_is_not_auth(tmp_path: Path) -> None:
    """The direction traded against (Rule 1), bare AND wrapped: no curated stem and no
    auth-named callable in the list, so all four routes still fire."""
    (tmp_path / "ws.py").write_text(
        "@router.websocket('/a', dependencies=[get_db()])\n"
        "async def a(websocket: WebSocket):\n"
        "    await websocket.accept()\n"
        "\n"
        "@router.websocket('/b', dependencies=[RateLimiter(times=5, seconds=60)])\n"
        "async def b(websocket: WebSocket):\n"
        "    await websocket.accept()\n"
        "\n"
        "@router.websocket('/c', dependencies=[Depends(RateLimiter(times=5))])\n"
        "async def c(websocket: WebSocket):\n"
        "    await websocket.accept()\n"
        "\n"
        "@router.websocket('/d', dependencies=[Depends(get_db)])\n"
        "async def d(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    assert len(_ws_locations(tmp_path)) == 4


def test_ws_commented_out_decorator_deps_do_not_exempt(tmp_path: Path) -> None:
    """Dead text (#532 / #871): a COMMENTED-OUT factory above the decorator's live `[get_db()]` must
    not fake protection. The file is comment-blanked once before any decorator is read."""
    (tmp_path / "ws.py").write_text(
        "@router.websocket(\n"
        "    '/ws',\n"
        "    # dependencies=[requires_authenticated()],  # removed during a refactor\n"
        "    dependencies=[get_db()],\n"
        ")\n"
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    assert len(_ws_locations(tmp_path)) == 1


def test_ws_bare_auth_factory_recognition_is_scoped_to_the_deps_list(tmp_path: Path) -> None:
    """Scoping: the factory CALLED in the handler body (inside the signature window, even)
    is not an applied dependency, so that route still fires; the authed sibling stays silent."""
    (tmp_path / "ws.py").write_text(
        "@router.websocket('/ws', dependencies=[requires_authenticated()])\n"
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n"
        "\n"
        "@router.websocket('/ws2')\n"
        "async def ws_other(websocket: WebSocket):\n"
        "    requires_authenticated()  # called, never applied as a dependency\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    assert _ws_locations(tmp_path) == ["ws.py:5"]  # ws_other's decorator line


def test_ws_multiline_decorator_deps_beyond_the_signature_window(tmp_path: Path) -> None:
    """A multi-line decorator whose deps sit more than 3 lines below the `@` line, so the signature
    window cannot reach them by accident: the auth factory is read from the decorator span itself,
    and the `get_db()` twin still fires (exactly the second route)."""
    (tmp_path / "ws.py").write_text(
        "@router.websocket(\n"
        "    '/ws',\n"
        "    name='chat',\n"
        "    include_in_schema=False,\n"
        "    dependencies=[requires_authenticated()],\n"
        ")\n"
        "async def chat(websocket: WebSocket):\n"
        "    await websocket.accept()\n"
        "\n"
        "@router.websocket(\n"
        "    '/ws2',\n"
        "    name='feed',\n"
        "    include_in_schema=False,\n"
        "    dependencies=[get_db()],\n"
        ")\n"
        "async def feed(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    assert _ws_locations(tmp_path) == ["ws.py:10"]  # feed's decorator line


def test_ws_decorator_offsets_survive_a_form_feed_line(tmp_path: Path) -> None:
    """The guard numbers lines with `splitlines()`, which also breaks on `\\x0c` (a form-feed page
    separator, still found in older Python). The decorator's offset must come from the SAME split:
    an offset counted by `\\n` alone drifts one line per form feed, misses the authed decorator's
    `(` and fires it. Exactly the unauthed route fires."""
    (tmp_path / "ws.py").write_text(
        "import fastapi\n"
        "\x0c\n"
        "@router.websocket('/ws', dependencies=[requires_authenticated()])\n"
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n"
        "\n"
        "@router.websocket('/ws2')\n"
        "async def ws_other(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    assert len(_ws_locations(tmp_path)) == 1


@pytest.mark.slow
def test_ws_decorator_deps_scan_stays_linear(tmp_path: Path) -> None:
    """Hostile input: every decorator leaves its `(` unbalanced, so `matching_close_paren` walks to
    the end of whatever text it is handed. Handed the rest of the file per decorator, that was
    O(k*n): measured 3.0s at 500 decorators and 185s at 4,000 (x4 per doubling), against 0.1s and
    0.7s with each decorator's text bounded to the next websocket decorator. Growth CLASS is the
    assertion, not wall clock."""
    sizes = [400, 800, 1600, 3200]
    roots = {}
    for n in sizes:
        root = tmp_path / f"n{n}"
        root.mkdir()
        (root / "ws.py").write_text(
            "".join(
                f"@router.websocket('/ws{k}', dependencies=[get_db()\n"
                f"async def ws{k}(websocket: WebSocket):\n"
                "    pass\n"
                for k in range(n)
            ),
            encoding="utf-8",
        )
        roots[n] = root

    found: dict[int, int] = {}

    def scan(n: int) -> None:
        profile = mkprofile(roots[n], features={"python", "fastapi"}, python_dirs=["."])
        found[n] = len(WebsocketNoAuthGuard().run(roots[n], profile))

    assert_growth(scan, sizes, expected="linear")
    # ...and every route still fires, so a guard that stopped matching cannot pass as "fast".
    assert found == {n: n for n in sizes}, found


# --- #613: a triple-quoted decorator argument holding an apostrophe -------------------------------
# The decorator span is resolved by `route_deps_carry_auth`, whose walk used to read `'''` as three
# separate quotes. The apostrophe left it "inside a string" to the end of the window, the span was
# unresolvable, and a real auth list in the decorator went unread, so the route fired.


def test_fp_bait_ws_decorator_deps_after_a_triple_quoted_name(tmp_path: Path) -> None:
    (tmp_path / "ws.py").write_text(
        "@router.websocket('/ws', name='''the client's feed''', dependencies=[Depends(get_current_user)])\n"
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    assert _ws_locations(tmp_path) == []


def test_ws_triple_quoted_name_does_not_let_the_span_reach_the_body(tmp_path: Path) -> None:
    """The direction traded against (Rule 1): with the span resolved, an auth-shaped
    `dependencies=[...]` in the handler BODY is still outside it, so the route still fires."""
    (tmp_path / "ws.py").write_text(
        "@router.websocket('/ws', name='''the client's feed''')\n"
        "async def ws_endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n"
        "    await websocket.send_text('hello')\n"
        "    await websocket.send_text('again')\n"
        "    cfg = dict(dependencies=[Depends(get_current_user)])\n",
        encoding="utf-8",
    )
    assert _ws_locations(tmp_path) == ["ws.py:1"]
