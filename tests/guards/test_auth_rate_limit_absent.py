from __future__ import annotations

import pytest

from agentsec.guards.auth_rate_limit_absent import AuthRateLimitAbsentGuard
from tests.guards._common import *  # noqa: F401,F403


def test_auth_rate_limit_absent_login_path_fires(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.post('/login')\n"
        "async def authenticate_user(creds: dict) -> dict:\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = AuthRateLimitAbsentGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "auth-rate-limit-absent/no-rate-limit"
    assert findings[0].severity == "medium"

def test_auth_rate_limit_absent_function_name_fires(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.post('/session')\n"
        "async def login(creds: dict) -> dict:\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = AuthRateLimitAbsentGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "auth-rate-limit-absent/no-rate-limit"

def test_auth_rate_limit_absent_reset_password_path_fires(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.post('/reset-password')\n"
        "async def reset(creds: dict) -> dict:\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = AuthRateLimitAbsentGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_auth_rate_limit_absent_slowapi_silences(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "from slowapi import Limiter\n"
        "router = APIRouter()\n"
        "@router.post('/login')\n"
        "async def login(creds: dict) -> dict:\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert AuthRateLimitAbsentGuard().run(tmp_path, profile) == []

def test_auth_rate_limit_absent_limiter_decorator_silences(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@limiter.limit('5/minute')\n"
        "@router.post('/login')\n"
        "async def login(creds: dict) -> dict:\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert AuthRateLimitAbsentGuard().run(tmp_path, profile) == []

def test_auth_rate_limit_absent_non_sensitive_route_silent(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/products')\n"
        "async def list_products() -> dict:\n"
        "    return {'items': []}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert AuthRateLimitAbsentGuard().run(tmp_path, profile) == []

def test_auth_rate_limit_absent_tokens_resource_silent(tmp_path: Path) -> None:
    # "/tokens" (a resource listing) must not match the "/token" keyword — \b anchors it.
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/tokens')\n"
        "async def list_api_tokens() -> dict:\n"
        "    return {'items': []}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert AuthRateLimitAbsentGuard().run(tmp_path, profile) == []

def test_auth_rate_limit_absent_token_path_fires(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.post('/oauth/token')\n"
        "async def issue_token(creds: dict) -> dict:\n"
        "    return {'access_token': '...'}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = AuthRateLimitAbsentGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_auth_rate_limit_absent_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "# security: allow-unrated-auth-endpoint\n"
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.post('/login')\n"
        "async def login(creds: dict) -> dict:\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert AuthRateLimitAbsentGuard().run(tmp_path, profile) == []

def test_auth_rate_limit_absent_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"java", "fastapi"})
    assert AuthRateLimitAbsentGuard().applies(profile) is False

def test_auth_rate_limit_absent_applies_with_python() -> None:
    profile = mkprofile(Path("/tmp"), features={"python", "fastapi"})
    assert AuthRateLimitAbsentGuard().applies(profile) is True


# --- #472: rate limiting wired in another file (multi-file fixtures) ---------------------------
# The route file below carries no rate-limiting signal of its own; `main.py` wires the control.

_AUTH_ROUTE = (
    "from fastapi import APIRouter\n"
    "router = APIRouter()\n"
    "@router.post('/login')\n"
    "async def login(body: dict) -> dict:\n"
    "    return {}\n"
)
_MAIN_HEAD = (
    "from fastapi import Depends, FastAPI\n"
    "from fastapi_limiter.depends import RateLimiter\n"
    "from slowapi import Limiter\n"
    "from slowapi.middleware import SlowAPIMiddleware\n"
    "from slowapi.util import get_remote_address\n"
    "from routes import auth\n"
)
_LIMITS = "limiter = Limiter(key_func=get_remote_address, default_limits=['100/minute'])\n"
_SLOWAPI = _LIMITS + "app = FastAPI()\napp.state.limiter = limiter\napp.add_middleware(SlowAPIMiddleware)\n"
_RL_DEP = "[Depends(RateLimiter(times=5, seconds=60))]"


def _tree(root: Path, files: dict[str, str]) -> list[str]:
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    profile = mkprofile(root, features={"python", "fastapi"}, python_dirs=["."])
    return [f.location.replace("\\", "/") for f in AuthRateLimitAbsentGuard().run(root, profile)]


@pytest.mark.parametrize(
    "main",
    [
        _SLOWAPI + "app.include_router(auth.router)\n",
        "limiter = Limiter(key_func=get_remote_address, application_limits=['1000/hour'])\n"
        "app = FastAPI()\napp.add_middleware(SlowAPIMiddleware)\napp.include_router(auth.router)\n",
        "from starlette.middleware import Middleware\n" + _LIMITS
        + "app = FastAPI(middleware=[Middleware(SlowAPIMiddleware)])\napp.include_router(auth.router)\n",
        f"app = FastAPI()\napp.include_router(auth.router, dependencies={_RL_DEP})\n",
        f"_rl = {_RL_DEP}\napp = FastAPI()\napp.include_router(auth.router, dependencies=_rl)\n",
        "app = FastAPI()\napp.include_router(auth.router, dependencies=[Depends(deps.check_rate_limit)])\n",
        f"app = FastAPI(dependencies={_RL_DEP})\napp.include_router(auth.router)\n",
        f"_rl = {_RL_DEP}\napp = FastAPI(dependencies=_rl)\napp.include_router(auth.router)\n",
    ],
    ids=[
        "slowapi-default-limits", "slowapi-application-limits", "slowapi-middleware-list",
        "include-router-dependency", "include-router-dependency-var", "include-router-own-dependency",
        "app-dependency", "app-dependency-var",
    ],
)
def test_auth_rate_limit_absent_silent_when_main_py_wires_rate_limiting(tmp_path: Path, main: str) -> None:
    # #472: the idiomatic layout wires rate limiting once, in `main.py`. Before the fix every
    # auth route under `routes/` fired anyway, because the guard read only the route's own file.
    assert _tree(tmp_path, {"main.py": _MAIN_HEAD + main, "routes/auth.py": _AUTH_ROUTE}) == []


def test_auth_rate_limit_absent_silent_when_limiter_lives_in_a_sibling_module(tmp_path: Path) -> None:
    # The `Limiter` and the middleware only have to share a top-level directory, not a file.
    files = {
        "app/core/limiter.py": "from slowapi import Limiter\n" + _LIMITS,
        "app/main.py": (
            "from fastapi import FastAPI\nfrom slowapi.middleware import SlowAPIMiddleware\n"
            "from app.core.limiter import limiter\nfrom app.routes import auth\n"
            "app = FastAPI()\napp.state.limiter = limiter\napp.add_middleware(SlowAPIMiddleware)\n"
            "app.include_router(auth.router)\n"
        ),
        "app/routes/auth.py": _AUTH_ROUTE,
    }
    assert _tree(tmp_path, files) == []


def test_auth_rate_limit_absent_pragma_in_main_still_contributes_its_wiring(tmp_path: Path) -> None:
    # CLAUDE.md rule 4: the pragma gates where a finding is anchored, not what pass 1 reads.
    main = "# security: allow-unrated-auth-endpoint\n" + _MAIN_HEAD + _SLOWAPI
    assert _tree(tmp_path, {"main.py": main, "routes/auth.py": _AUTH_ROUTE}) == []


@pytest.mark.parametrize(
    "main",
    [
        "app = FastAPI()\napp.include_router(auth.router)\n",
        # slowapi needs BOTH halves, with limits on.
        "limiter = Limiter(key_func=get_remote_address)\n"
        "app = FastAPI()\napp.add_middleware(SlowAPIMiddleware)\napp.include_router(auth.router)\n",
        _LIMITS + "app = FastAPI()\napp.include_router(auth.router)\n",
        "limiter = Limiter(key_func=get_remote_address, default_limits=[])\n"
        "app = FastAPI()\napp.add_middleware(SlowAPIMiddleware)\napp.include_router(auth.router)\n",
        "limiter = Limiter(key_func=get_remote_address, default_limits=['1/second'], enabled=False)\n"
        "app = FastAPI()\napp.add_middleware(SlowAPIMiddleware)\napp.include_router(auth.router)\n",
        "limiter = Limiter(key_func=get_remote_address, default_limits=['1/second'], enabled=settings.RL)\n"
        "app = FastAPI()\napp.add_middleware(SlowAPIMiddleware)\napp.include_router(auth.router)\n",
        "limiter = Limiter(key_func=get_remote_address, default_limits=['1/second'], auto_check=False)\n"
        "app = FastAPI()\napp.add_middleware(SlowAPIMiddleware)\napp.include_router(auth.router)\n",
        # A registration that may not run, or does not run at all.
        _LIMITS + "app = FastAPI()\nif settings.RL:\n    app.add_middleware(SlowAPIMiddleware)\n"
        "app.include_router(auth.router)\n",
        _LIMITS + "app = FastAPI()\n# app.add_middleware(SlowAPIMiddleware)\napp.include_router(auth.router)\n",
        # The #473 router rules, inherited.
        f"app = FastAPI()\napp.include_router(auth.router, dependencies={_RL_DEP})\n"
        "app.include_router(auth.router, prefix='/v2')\n",
        f"app = FastAPI()\nif settings.RL:\n    app.include_router(auth.router, dependencies={_RL_DEP})\n",
        "app = FastAPI()\napp.include_router(auth.router, dependencies=[Depends(get_current_user)])\n",
        f"app = FastAPI()\n# app.include_router(auth.router, dependencies={_RL_DEP})\napp.include_router(auth.router)\n",
        # A dependency whose name only contains the letters, not the stem.
        "app = FastAPI(dependencies=[Depends(moderate_limit)])\napp.include_router(auth.router)\n",
    ],
    ids=[
        "no-control", "middleware-without-limits", "limits-without-middleware", "empty-limits",
        "limiter-disabled", "limiter-enabled-by-setting", "limiter-auto-check-off",
        "conditional-middleware", "commented-out-middleware", "dual-mount", "conditional-mount",
        "auth-only-dependency", "commented-out-mount", "non-rate-limit-dependency",
    ],
)
def test_auth_rate_limit_absent_still_fires_when_main_py_wiring_is_not_proof(
    tmp_path: Path, main: str
) -> None:
    # Rule 1, the direction #472 trades against: each `main.py` names a rate-limit control
    # without proving it limits `/login`, so the route keeps firing.
    files = {"main.py": _MAIN_HEAD + main, "routes/auth.py": _AUTH_ROUTE}
    assert _tree(tmp_path, files) == ["routes/auth.py:3"]


def test_auth_rate_limit_absent_still_fires_on_an_exempt_route_under_global_limits(tmp_path: Path) -> None:
    # slowapi's middleware never limits an `@<limiter>.exempt` route. The limiter is imported under
    # a name the same-file signal does not read (`@limiter.exempt` would match `@\w*limiter`).
    route = (
        "from fastapi import APIRouter\nfrom main import lim\nrouter = APIRouter()\n"
        "@router.post('/login')\n@lim.exempt\nasync def login(body: dict) -> dict:\n    return {}\n"
    )
    main = (
        _MAIN_HEAD + "lim = Limiter(key_func=get_remote_address, default_limits=['100/minute'])\n"
        "app = FastAPI()\napp.state.limiter = lim\napp.add_middleware(SlowAPIMiddleware)\n"
        "app.include_router(auth.router)\n"
    )
    assert _tree(tmp_path, {"main.py": main, "routes/auth.py": route}) == ["routes/auth.py:4"]


def test_auth_rate_limit_absent_still_fires_when_only_a_test_app_wires_rate_limiting(tmp_path: Path) -> None:
    # A test app's wiring never runs in front of the product's routes.
    files = {"tests/conftest.py": _MAIN_HEAD + _SLOWAPI, "routes/auth.py": _AUTH_ROUTE}
    assert _tree(tmp_path, files) == ["routes/auth.py:3"]


def test_auth_rate_limit_absent_still_fires_when_another_app_wires_rate_limiting(tmp_path: Path) -> None:
    # Monorepo: `svc_a/`'s global limits do not cover `svc_b/`'s routes, while a root-level
    # `main.py` (the earlier silent cases) covers the whole tree.
    files = {
        "svc_a/main.py": _MAIN_HEAD + _SLOWAPI,
        "svc_a/routes/auth.py": _AUTH_ROUTE,
        "svc_b/routes/auth_b.py": _AUTH_ROUTE,
    }
    assert _tree(tmp_path, files) == ["svc_b/routes/auth_b.py:3"]


def test_auth_rate_limit_absent_still_fires_on_a_stem_collision(tmp_path: Path) -> None:
    # Two `auth.py` modules: `include_router(auth.router, ...)` cannot say which one it mounts.
    files = {
        "main.py": _MAIN_HEAD + f"app = FastAPI()\napp.include_router(auth.router, dependencies={_RL_DEP})\n",
        "routes/auth.py": _AUTH_ROUTE,
        "v2/auth.py": _AUTH_ROUTE,
    }
    assert sorted(_tree(tmp_path, files)) == ["routes/auth.py:3", "v2/auth.py:3"]


def test_auth_rate_limit_absent_router_credit_is_per_router(tmp_path: Path) -> None:
    # A rate-limited mount of `auth.router` covers that router's routes only, not another receiver
    # in the same file. The guard reads only `@router.` / `@app.` decorators (a pre-existing scope
    # limit), so the uncovered receiver here is an `app`.
    route = _AUTH_ROUTE + (
        "app = FastAPI()\n@app.post('/register')\nasync def register(body: dict) -> dict:\n    return {}\n"
    )
    main = _MAIN_HEAD + f"app = FastAPI()\napp.include_router(auth.router, dependencies={_RL_DEP})\n"
    assert _tree(tmp_path, {"main.py": main, "routes/auth.py": route}) == ["routes/auth.py:7"]


def test_auth_rate_limit_absent_unparseable_main_gives_no_coverage(tmp_path: Path) -> None:
    # An unparseable `main.py` contributes no slowapi scope and raises nothing.
    files = {"main.py": _MAIN_HEAD + _SLOWAPI + "def broken(:\n", "routes/auth.py": _AUTH_ROUTE}
    assert _tree(tmp_path, files) == ["routes/auth.py:3"]
