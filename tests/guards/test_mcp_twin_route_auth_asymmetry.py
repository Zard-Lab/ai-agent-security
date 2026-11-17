"""Tests for McpTwinRouteAuthAsymmetryGuard — planted-violation + FP-bait."""
from __future__ import annotations

import pytest

from agentsec.guards.mcp_twin_route_auth_asymmetry import McpTwinRouteAuthAsymmetryGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "python"}, python_dirs=["."])


def test_unauthed_sibling_route_fires(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI()\n\n"
        "@app.post('/mcp')\n"
        "def mcp_handler(user=Depends(auth)):\n"
        "    return handle(user)\n\n"
        "@app.post('/mcp_message')\n"
        "def mcp_message_handler():\n"
        "    return handle(None)\n",
        encoding="utf-8",
    )
    findings = McpTwinRouteAuthAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-twin-route-auth-asymmetry/unauthed-sibling")
    assert hit.severity == "high"
    assert "/mcp_message" in hit.message


def test_both_routes_authenticated_is_safe(tmp_path: Path) -> None:
    """FP-bait: both sibling routes carry the same auth dependency — no asymmetry."""
    (tmp_path / "server.py").write_text(
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI()\n\n"
        "@app.post('/mcp')\n"
        "def mcp_handler(user=Depends(auth)):\n"
        "    return handle(user)\n\n"
        "@app.post('/mcp_message')\n"
        "def mcp_message_handler(user=Depends(auth)):\n"
        "    return handle(user)\n",
        encoding="utf-8",
    )
    findings = McpTwinRouteAuthAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_neither_route_authenticated_is_out_of_scope(tmp_path: Path) -> None:
    """FP-bait: no authenticated anchor at all -- that's mcp-transport-no-auth's scope,
    not an asymmetry between siblings."""
    (tmp_path / "server.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n"
        "@app.post('/mcp')\n"
        "def mcp_handler():\n"
        "    return handle()\n\n"
        "@app.post('/mcp_message')\n"
        "def mcp_message_handler():\n"
        "    return handle()\n",
        encoding="utf-8",
    )
    findings = McpTwinRouteAuthAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_single_route_no_sibling_is_safe(tmp_path: Path) -> None:
    """FP-bait: only one MCP route in the file -- no sibling to compare against."""
    (tmp_path / "server.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n"
        "@app.post('/mcp')\n"
        "def mcp_handler():\n"
        "    return handle()\n",
        encoding="utf-8",
    )
    findings = McpTwinRouteAuthAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_express_unauthed_sibling_fires(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        "app.post('/mcp', authMw, (req, res) => { handle(req); });\n"
        "app.post('/mcp_message', (req, res) => { handle(req); });\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"mcp", "typescript"}, python_dirs=["."])
    findings = McpTwinRouteAuthAsymmetryGuard().run(tmp_path, prof)
    assert any(f.rule == "mcp-twin-route-auth-asymmetry/unauthed-sibling" for f in findings)


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "# security: allow-mcp-twin-route-auth-asymmetry\n"
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI()\n\n"
        "@app.post('/mcp')\n"
        "def mcp_handler(user=Depends(auth)):\n"
        "    return handle(user)\n\n"
        "@app.post('/mcp_message')\n"
        "def mcp_message_handler():\n"
        "    return handle(None)\n",
        encoding="utf-8",
    )
    findings = McpTwinRouteAuthAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpTwinRouteAuthAsymmetryGuard().applies(prof) is False


# --------------------------------------------------------------------------- PR #963 review round
_ROUTES = (
    "@app.post('/mcp')\n"
    "def mcp_handler():\n"
    "    return handle()\n\n"
    "@app.post('/mcp_message')\n"
    "def mcp_message_handler(user=Depends(get_current_user)):\n"
    "    return handle(user)\n"
)


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _rules(root: Path) -> list[str]:
    return [f.rule for f in McpTwinRouteAuthAsymmetryGuard().run(root, _mcp_prof(root))]


_FIRES = ["mcp-twin-route-auth-asymmetry/unauthed-sibling"]


def test_app_wide_auth_middleware_covers_the_route(tmp_path: Path) -> None:
    """FP-bait: auth registered as app-wide middleware protects `/mcp` too."""
    _write(tmp_path, {"server.py": (
        "app = FastAPI()\napp.add_middleware(AuthMiddleware)\n\n" + _ROUTES
    )})
    assert _rules(tmp_path) == []


def test_without_the_middleware_the_same_routes_still_fire(tmp_path: Path) -> None:
    _write(tmp_path, {"server.py": "app = FastAPI()\n\n" + _ROUTES})
    assert _rules(tmp_path) == _FIRES


def test_middleware_registered_in_another_file_covers_routes_multi_file(tmp_path: Path) -> None:
    """Multi-file fixture: the middleware lives in `main.py`, the routes in `routes/mcp.py`."""
    _write(tmp_path, {
        "main.py": "from routes import mcp\napp = FastAPI()\napp.add_middleware(JWTAuthMiddleware)\n",
        "routes/mcp.py": "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
        + _ROUTES.replace("@app.", "@router."),
    })
    assert _rules(tmp_path) == []


def test_auth_named_http_middleware_function_covers_the_route(tmp_path: Path) -> None:
    _write(tmp_path, {"server.py": (
        "app = FastAPI()\n\n@app.middleware('http')\nasync def auth_middleware(request, call_next):\n"
        "    return await call_next(request)\n\n" + _ROUTES
    )})
    assert _rules(tmp_path) == []


def test_commented_out_middleware_does_not_count(tmp_path: Path) -> None:
    """Narrowing pin: a commented-out registration is not protection."""
    _write(tmp_path, {"server.py": (
        "app = FastAPI()\n# app.add_middleware(AuthMiddleware)\n\n" + _ROUTES
    )})
    assert _rules(tmp_path) == _FIRES


@pytest.mark.parametrize(
    "dead",
    [
        'DOC = "register it with app.add_middleware(AuthMiddleware)"\n',
        "DOC = \"@app.middleware('http') async def auth_gate(request, call_next): ...\"\n",
        'DOC = """\nx\n"""  # the "old" wiring: app.add_middleware(AuthMiddleware)\n',
        # #1017 review, High 1: the literal text around a multi-row replacement field
        'DOC = f"app.add_middleware(AuthMiddleware) {\n    name\n} tail"\n',
    ],
    ids=["one-line-string", "http-middleware-in-string", "triple-quote-closing-line",
         "multirow-fstring"],
)
def test_middleware_quoted_in_dead_text_does_not_count(tmp_path: Path, dead: str) -> None:
    """#538: a one-line string, or a comment on a docstring's closing line, used to read as app-wide
    auth and skip every Python route this guard checks."""
    _write(tmp_path, {"server.py": "app = FastAPI()\n" + dead + "\n" + _ROUTES})
    assert _rules(tmp_path) == _FIRES


def test_live_middleware_beside_a_string_that_names_it_still_counts(tmp_path: Path) -> None:
    """FP-bait for the #538 anchor check: the string is skipped, the live registration is not."""
    _write(tmp_path, {"server.py": (
        "app = FastAPI()\n"
        'DOC = "app.add_middleware(AuthMiddleware) is how auth is wired"\n'
        "app.add_middleware(AuthMiddleware)\n\n" + _ROUTES
    )})
    assert _rules(tmp_path) == []


def test_non_auth_middleware_does_not_count(tmp_path: Path) -> None:
    """Narrowing pin: CORS, session-cookie and author-named middleware are not auth gates."""
    _write(tmp_path, {"server.py": (
        "app = FastAPI()\napp.add_middleware(CORSMiddleware)\napp.add_middleware(SessionMiddleware)\n"
        "app.add_middleware(AuthorBannerMiddleware)\n\n" + _ROUTES
    )})
    assert _rules(tmp_path) == _FIRES


def test_router_level_dependency_covers_the_route(tmp_path: Path) -> None:
    """FP-bait: `dependencies=[Depends(auth)]` on the router authenticates every route on it."""
    _write(tmp_path, {"server.py": (
        "router = APIRouter(dependencies=[Depends(get_current_user)])\n\n"
        + _ROUTES.replace("@app.", "@router.")  # `/mcp` carries no marker of its own
        + "\napp.include_router(router)\n"
    )})
    assert _rules(tmp_path) == []


def test_bare_router_with_the_same_routes_still_fires(tmp_path: Path) -> None:
    """Narrowing pin for the router-level resolver: no router-level dependency, so `/mcp` is open."""
    _write(tmp_path, {"server.py": (
        "router = APIRouter()\n\n" + _ROUTES.replace("@app.", "@router.") + "\napp.include_router(router)\n"
    )})
    assert _rules(tmp_path) == _FIRES


def test_router_mounted_with_auth_from_another_file_multi_file(tmp_path: Path) -> None:
    """Multi-file fixture: `main.py` mounts `mcp.router` with an auth dependency, so the bare
    `/mcp` handler in `routes/mcp.py` is protected and nothing fires."""
    routes = "from fastapi import APIRouter\nrouter = APIRouter()\n\n" + _ROUTES.replace("@app.", "@router.")
    _write(tmp_path, {
        "main.py": "from routes import mcp\napp = FastAPI()\n"
        "app.include_router(mcp.router, dependencies=[Depends(get_current_user)])\n",
        "routes/mcp.py": routes,
    })
    assert _rules(tmp_path) == []


def test_router_mounted_bare_from_another_file_still_fires_multi_file(tmp_path: Path) -> None:
    """Narrowing pin for the multi-file resolver: the same layout mounted WITHOUT auth fires."""
    routes = "from fastapi import APIRouter\nrouter = APIRouter()\n\n" + _ROUTES.replace("@app.", "@router.")
    _write(tmp_path, {
        "main.py": "from routes import mcp\napp = FastAPI()\napp.include_router(mcp.router)\n",
        "routes/mcp.py": routes,
    })
    assert _rules(tmp_path) == _FIRES


def test_express_global_auth_before_routes_covers_them(tmp_path: Path) -> None:
    _write(tmp_path, {"server.ts": (
        "app.use(authMw);\n"
        "app.post('/mcp', (req, res) => { handle(req); });\n"
        "app.post('/mcp_message', authMw, (req, res) => { handle(req); });\n"
    )})
    assert _rules(tmp_path) == []


def test_express_global_auth_after_a_route_does_not_cover_it(tmp_path: Path) -> None:
    """Narrowing pin: Express middleware only guards routes registered AFTER it, so the earlier
    `/mcp` is the open twin of the (now globally authed) `/mcp_message`."""
    _write(tmp_path, {"server.ts": (
        "app.post('/mcp', (req, res) => { handle(req); });\n"
        "app.use(authMw);\n"
        "app.post('/mcp_message', (req, res) => { handle(req); });\n"
    )})
    assert _rules(tmp_path) == _FIRES


def test_express_route_before_global_auth_fires_against_authed_sibling(tmp_path: Path) -> None:
    _write(tmp_path, {"server.ts": (
        "app.post('/mcp', (req, res) => { handle(req); });\n"
        "app.use(authMw);\n"
        "app.post('/mcp_message', (req, res) => { handle(req); });\n"
        "app.post('/mcp_msg', authMw, (req, res) => { handle(req); });\n"
    )})
    assert _rules(tmp_path) == _FIRES


def test_stacked_and_multiline_decorators_still_reach_the_def(tmp_path: Path) -> None:
    """Regression pin for the rewritten extractor: decorators between the route and the `def`
    (one multi-line) and a signature with a nested call before the auth dependency."""
    _write(tmp_path, {"server.py": (
        "app = FastAPI()\n\n"
        "@app.post('/mcp')\n"
        "@limiter.limit(\n    '5/minute'\n)\n"
        "async def mcp_handler(db=Depends(get_db), user=Depends(get_current_user)):\n"
        "    return handle(user)\n\n"
        "@app.post('/mcp_message')\n"
        "@log_calls\n"
        "def mcp_message_handler():\n"
        "    return handle(None)\n"
    )})
    assert _rules(tmp_path) == _FIRES


@pytest.mark.slow
def test_extractors_stay_linear_on_unterminated_decorators(tmp_path: Path) -> None:
    """Performance pin (regression of the quadratic-to-exponential DOTALL regexes): decorators that
    never reach a `def`. Growth ratio, not wall clock (tests/_timing.py)."""
    shapes = {
        "open_call": "@app.post('/mcp'\n",
        "stacked": "@app.post('/mcp')\n@x\n",
        "no_def": "@app.post('/mcp')\n@x(\n",
    }
    for name, unit in shapes.items():

        def scan(n: int, unit: str = unit, name: str = name) -> None:
            root = tmp_path / f"{name}{n}"
            root.mkdir(exist_ok=True)
            (root / "server.py").write_text(unit * n, encoding="utf-8")
            assert _rules(root) == []

        # Halved from [250..2000] on 2026-10-23: the no-`_SPAN` and no-`_MAX_DECORATORS` mutants still
        # read quadratic at these sizes (ratios ~3.4-3.9 per x2 step).
        assert_growth(scan, [125, 250, 500, 1000], expected="linear")


def test_express_extractor_stays_linear_on_unclosed_route_lines(tmp_path: Path) -> None:
    """Performance pin: `_EXPRESS_LINE_RE`'s `[^;]+?\\)` measured ~2.4 s at 20K chars (x4 per
    doubling) on route lines with no closing paren."""

    def scan(n: int) -> None:
        root = tmp_path / str(n)
        root.mkdir(exist_ok=True)
        (root / "server.ts").write_text("app.get('/mcp', x " * n, encoding="utf-8")
        assert _rules(root) == []

    assert_growth(scan, [250, 500, 1000, 2000], expected="linear")


# ── #424 E6 (#1000): the pragma counts only as a real comment, in the file's own grammar ──
# The pragma site only decides which `/mcp` files become finding CANDIDATES, so every fixture below
# puts the pragma text in the same file the finding anchors in.

_PY_TWIN = (
    "from fastapi import FastAPI, Depends\n"
    "app = FastAPI()\n\n"
    "@app.post('/mcp')\n"
    "def mcp_handler(user=Depends(auth)):\n"
    "    return handle(user)\n\n"
    "@app.post('/mcp_message')\n"
    "def mcp_message_handler():\n"
    "    return handle(None)\n"
)
_TS_TWIN = (
    "app.post('/mcp', authMw, (req, res) => { handle(req); });\n"
    "app.post('/mcp_message', (req, res) => { handle(req); });\n"
)


def _anchored(root: Path, name: str, text: str) -> list[tuple[str, str]]:
    (root / name).write_text(text, encoding="utf-8")
    return [
        (f.rule, f.location.replace("\\", "/").split(":")[0])
        for f in McpTwinRouteAuthAsymmetryGuard().run(root, _mcp_prof(root))
    ]


def test_mcp_twin_route_auth_asymmetry_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): the candidate filter reads the comment-only view, so a Python string quoting
    # the pragma is content; only a real `#` comment (`test_pragma_suppresses_finding`) opts out.
    text = 'HELP = "opt out with # security: allow-mcp-twin-route-auth-asymmetry"\n' + _PY_TWIN
    assert _anchored(tmp_path, "server.py", text) == [(_FIRES[0], "server.py")]


@pytest.mark.parametrize("marker", ["//", "#"], ids=["slash-form", "hash-form"])
def test_mcp_twin_route_auth_asymmetry_pragma_quoted_in_a_string_does_not_suppress_ts(
    tmp_path: Path, marker: str
) -> None:
    # #424 E6 (#1000): D2 widened the pragma to `//`, so a TS string quoting either comment form must
    # stay content (the CLAUDE.md rule-1 test for that widening).
    text = f'const help = "opt out with {marker} security: allow-mcp-twin-route-auth-asymmetry";\n' + _TS_TWIN
    assert _anchored(tmp_path, "server.ts", text) == [(_FIRES[0], "server.ts")]


def test_mcp_twin_route_auth_asymmetry_ts_slash_comment_pragma_suppresses(tmp_path: Path) -> None:
    # #424 E6 (#1000) D2: TS comments are `//`, and the old `#`-only regex never saw one, so the
    # documented opt-out could not be written in a .ts file at all.
    assert _anchored(tmp_path, "server.ts", _TS_TWIN) == [(_FIRES[0], "server.ts")]
    text = "// security: allow-mcp-twin-route-auth-asymmetry\n" + _TS_TWIN
    assert _anchored(tmp_path, "server.ts", text) == []


# #613: the decorator span walk read `'''` as three separate quotes, so an apostrophe inside a
# triple-quoted decorator argument left the span unresolvable and the route was DROPPED, so its
# unauthenticated twin was never compared against the authed one.
def _twin_with_triple_quoted_summary(tmp_path: Path, message_handler_sig: str) -> list[str]:
    (tmp_path / "server.py").write_text(
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI()\n\n"
        "@app.post('/mcp_message', summary='''the agent's channel''')\n"
        f"def mcp_message_handler({message_handler_sig}):\n"
        "    return handle(None)\n\n"
        "@app.post('/mcp')\n"
        "def mcp_handler(user=Depends(auth)):\n"
        "    return handle(user)\n",
        encoding="utf-8",
    )
    return [f.location for f in McpTwinRouteAuthAsymmetryGuard().run(tmp_path, _mcp_prof(tmp_path))]


def test_unauthed_twin_with_a_triple_quoted_decorator_argument_fires(tmp_path: Path) -> None:
    assert _twin_with_triple_quoted_summary(tmp_path, "") == ["server.py:4"]


def test_authed_twin_with_a_triple_quoted_decorator_argument_is_safe(tmp_path: Path) -> None:
    # FP-bait for the widening above: once the route is kept, its own auth marker must be read.
    assert _twin_with_triple_quoted_summary(tmp_path, "user=Depends(auth)") == []
