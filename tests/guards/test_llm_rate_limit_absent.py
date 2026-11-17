from __future__ import annotations

import pytest

from agentsec.guards.llm_rate_limit_absent import LLMRateLimitAbsentGuard
from tests.guards._common import *  # noqa: F401,F403


def test_llm_rate_limit_absent_no_limiter_fires(tmp_path: Path) -> None:
    _llm_route_no_limit(tmp_path)
    findings = LLMRateLimitAbsentGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "llm-rate-limit-absent/no-rate-limit"
    assert findings[0].severity == "medium"

def test_llm_rate_limit_absent_slowapi_silences(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "import openai\n"
        "from fastapi import APIRouter\n"
        "from slowapi import Limiter\n"
        "router = APIRouter()\n"
        "client = openai.OpenAI()\n"
        "@router.post(\'/chat\')\n"
        "async def chat(q: str) -> dict:\n"
        "    r = client.chat.completions.create(model=\'gpt-4o\', messages=[], max_tokens=500)\n"
        "    return {\'answer\': r.choices[0].message.content}\n",
        encoding="utf-8",
    )
    assert LLMRateLimitAbsentGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_rate_limit_absent_limiter_decorator_silences(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "import openai\n"
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "client = openai.OpenAI()\n"
        "@limiter.limit(\'10/minute\')\n"
        "@router.post(\'/chat\')\n"
        "async def chat(q: str) -> dict:\n"
        "    r = client.chat.completions.create(model=\'gpt-4o\', messages=[], max_tokens=500)\n"
        "    return {\'answer\': r.choices[0].message.content}\n",
        encoding="utf-8",
    )
    assert LLMRateLimitAbsentGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_rate_limit_absent_no_route_silent(tmp_path: Path) -> None:
    (tmp_path / "llm.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def answer(q: str) -> str:\n"
        "    r = client.chat.completions.create(model=\'gpt-4o\', messages=[], max_tokens=500)\n"
        "    return r.choices[0].message.content\n",
        encoding="utf-8",
    )
    assert LLMRateLimitAbsentGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_rate_limit_absent_no_llm_silent(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.post(\'/data\')\n"
        "async def data() -> dict:\n"
        "    return {\'ok\': True}\n",
        encoding="utf-8",
    )
    assert LLMRateLimitAbsentGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_rate_limit_absent_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "# security: allow-unrated-llm-endpoint\n"
        "import openai\n"
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "client = openai.OpenAI()\n"
        "@router.post(\'/chat\')\n"
        "async def chat(q: str) -> dict:\n"
        "    r = client.chat.completions.create(model=\'gpt-4o\', messages=[], max_tokens=500)\n"
        "    return {\'answer\': r.choices[0].message.content}\n",
        encoding="utf-8",
    )
    assert LLMRateLimitAbsentGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_rate_limit_absent_rate_limiter_class_silences(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "import openai\n"
        "from fastapi import APIRouter, Depends\n"
        "from fastapi_limiter.depends import RateLimiter\n"
        "router = APIRouter()\n"
        "client = openai.OpenAI()\n"
        "@router.post(\'/chat\')\n"
        "async def chat(q: str, _: None = Depends(RateLimiter(times=10, seconds=60))) -> dict:\n"
        "    r = client.chat.completions.create(model=\'gpt-4o\', messages=[], max_tokens=500)\n"
        "    return {\'answer\': r.choices[0].message.content}\n",
        encoding="utf-8",
    )
    assert LLMRateLimitAbsentGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_rate_limit_absent_get_route_fires(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "import openai\n"
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "client = openai.OpenAI()\n"
        "@router.get(\'/chat\')\n"
        "async def chat(q: str) -> dict:\n"
        "    r = client.chat.completions.create(model=\'gpt-4o\', messages=[{\'role\': \'user\', \'content\': q}], max_tokens=500)\n"
        "    return {\'answer\': r.choices[0].message.content}\n",
        encoding="utf-8",
    )
    findings = LLMRateLimitAbsentGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "llm-rate-limit-absent/no-rate-limit"



# --- #472: rate limiting wired in another file (multi-file fixtures) ---------------------------
# The route file below carries no rate-limiting signal of its own; `main.py` wires the control.

_CHAT_ROUTE = (
    "import openai\n"
    "from fastapi import APIRouter\n"
    "router = APIRouter()\n"
    "client = openai.OpenAI()\n"
    "@router.post('/chat')\n"
    "async def chat(q: str) -> dict:\n"
    "    r = client.chat.completions.create(model='gpt-4o', messages=[], max_tokens=500)\n"
    "    return {'answer': r.choices[0].message.content}\n"
)
_MAIN_HEAD = (
    "from fastapi import Depends, FastAPI\n"
    "from fastapi_limiter.depends import RateLimiter\n"
    "from slowapi import Limiter\n"
    "from slowapi.middleware import SlowAPIMiddleware\n"
    "from slowapi.util import get_remote_address\n"
    "from routes import chat\n"
)
_LIMITS = "limiter = Limiter(key_func=get_remote_address, default_limits=['100/minute'])\n"
_SLOWAPI = _LIMITS + "app = FastAPI()\napp.state.limiter = limiter\napp.add_middleware(SlowAPIMiddleware)\n"
_RL_DEP = "[Depends(RateLimiter(times=5, seconds=60))]"


def _tree(root: Path, files: dict[str, str]) -> list[str]:
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return [f.location.replace("\\", "/") for f in LLMRateLimitAbsentGuard().run(root, _llm_prof(root))]


@pytest.mark.parametrize(
    "main",
    [
        _SLOWAPI + "app.include_router(chat.router)\n",
        "limiter = Limiter(key_func=get_remote_address, application_limits=['1000/hour'])\n"
        "app = FastAPI()\napp.add_middleware(SlowAPIMiddleware)\napp.include_router(chat.router)\n",
        f"app = FastAPI()\napp.include_router(chat.router, dependencies={_RL_DEP})\n",
        f"_rl = {_RL_DEP}\napp = FastAPI()\napp.include_router(chat.router, dependencies=_rl)\n",
        f"app = FastAPI(dependencies={_RL_DEP})\napp.include_router(chat.router)\n",
    ],
    ids=[
        "slowapi-default-limits", "slowapi-application-limits", "include-router-dependency",
        "include-router-dependency-var", "app-dependency",
    ],
)
def test_llm_rate_limit_absent_silent_when_main_py_wires_rate_limiting(tmp_path: Path, main: str) -> None:
    # #472: rate limiting wired once in `main.py` covers the LLM route in `routes/chat.py`.
    assert _tree(tmp_path, {"main.py": _MAIN_HEAD + main, "routes/chat.py": _CHAT_ROUTE}) == []


def test_llm_rate_limit_absent_pragma_in_main_still_contributes_its_wiring(tmp_path: Path) -> None:
    # CLAUDE.md rule 4: the pragma gates where a finding is anchored, not what pass 1 reads.
    main = "# security: allow-unrated-llm-endpoint\n" + _MAIN_HEAD + _SLOWAPI
    assert _tree(tmp_path, {"main.py": main, "routes/chat.py": _CHAT_ROUTE}) == []


@pytest.mark.parametrize(
    "main",
    [
        "app = FastAPI()\napp.include_router(chat.router)\n",
        "limiter = Limiter(key_func=get_remote_address)\n"
        "app = FastAPI()\napp.add_middleware(SlowAPIMiddleware)\napp.include_router(chat.router)\n",
        _LIMITS + "app = FastAPI()\napp.include_router(chat.router)\n",
        "limiter = Limiter(key_func=get_remote_address, default_limits=['1/second'], enabled=False)\n"
        "app = FastAPI()\napp.add_middleware(SlowAPIMiddleware)\napp.include_router(chat.router)\n",
        _LIMITS + "app = FastAPI()\nif settings.RL:\n    app.add_middleware(SlowAPIMiddleware)\n"
        "app.include_router(chat.router)\n",
        f"app = FastAPI()\napp.include_router(chat.router, dependencies={_RL_DEP})\n"
        "app.include_router(chat.router, prefix='/v2')\n",
        f"app = FastAPI()\nif settings.RL:\n    app.include_router(chat.router, dependencies={_RL_DEP})\n",
        "app = FastAPI()\napp.include_router(chat.router, dependencies=[Depends(get_current_user)])\n",
    ],
    ids=[
        "no-control", "middleware-without-limits", "limits-without-middleware", "limiter-disabled",
        "conditional-middleware", "dual-mount", "conditional-mount", "auth-only-dependency",
    ],
)
def test_llm_rate_limit_absent_still_fires_when_main_py_wiring_is_not_proof(
    tmp_path: Path, main: str
) -> None:
    # Rule 1, the direction #472 trades against: each `main.py` names a rate-limit control
    # without proving it limits `/chat`, so the file keeps firing.
    files = {"main.py": _MAIN_HEAD + main, "routes/chat.py": _CHAT_ROUTE}
    assert _tree(tmp_path, files) == ["routes/chat.py:7"]


def test_llm_rate_limit_absent_still_fires_when_one_route_receiver_is_uncovered(tmp_path: Path) -> None:
    # The finding is per file and does not resolve which route reaches the LLM call, so a
    # rate-limited `chat.router` mount does not cover a file that also serves routes on `app`.
    route = _CHAT_ROUTE + "app = FastAPI()\n@app.post('/complete')\nasync def complete(q: str) -> dict:\n"
    route += "    return {}\n"
    main = _MAIN_HEAD + f"app = FastAPI()\napp.include_router(chat.router, dependencies={_RL_DEP})\n"
    assert _tree(tmp_path, {"main.py": main, "routes/chat.py": route}) == ["routes/chat.py:7"]


_TWO_ROUTERS_HEAD = (
    "import openai\n"
    "from fastapi import APIRouter\n"
    "router = APIRouter()\n"
    "chat_router = APIRouter()\n"
    "client = openai.OpenAI()\n"
    "@router.get('/health')\n"
    "async def health() -> dict:\n"
    "    return {}\n"
)
_LLM_HANDLER = (
    "async def chat(q: str) -> dict:\n"
    "    r = client.chat.completions.create(model='gpt-4o', messages=[], max_tokens=500)\n"
    "    return {'answer': r.choices[0].message.content}\n"
)
# The LLM route sits on `chat_router`, a name the candidate gate (`_ROUTE_DECORATOR`) does not read,
# registered by decorator or by `add_api_route`. The location is the LLM call's line.
_TWO_ROUTERS = {
    "decorator": (_TWO_ROUTERS_HEAD + "@chat_router.post('/chat')\n" + _LLM_HANDLER, 11),
    "add-api-route": (
        _TWO_ROUTERS_HEAD + _LLM_HANDLER + "chat_router.add_api_route('/chat', chat, methods=['POST'])\n",
        10,
    ),
    "websocket-route": (_TWO_ROUTERS_HEAD + "@chat_router.websocket_route('/chat')\n" + _LLM_HANDLER, 11),
    # The route is read from the syntax tree, not the line: spacing and line breaks do not hide it.
    "multiline-spaced-decorator": (
        _TWO_ROUTERS_HEAD + "@ chat_router .post(\n    '/chat',\n)\n" + _LLM_HANDLER, 13
    ),
    # A decorator applied by hand registers the route just as `@chat_router.post` does.
    "hand-applied-decorator": (_TWO_ROUTERS_HEAD + _LLM_HANDLER + "chat_router.post('/chat')(chat)\n", 10),
}


@pytest.mark.parametrize("shape", sorted(_TWO_ROUTERS))
def test_llm_rate_limit_absent_still_fires_when_an_uncovered_router_has_any_name(
    tmp_path: Path, shape: str
) -> None:
    # #1007 review H1: covering `router` must not withdraw the file's finding while the LLM route
    # sits on another router, whatever that router is called and however the route is registered.
    route, line = _TWO_ROUTERS[shape]
    main = _MAIN_HEAD + (
        f"app = FastAPI()\napp.include_router(chat.router, dependencies={_RL_DEP})\n"
        "app.include_router(chat.chat_router)\n"
    )
    assert _tree(tmp_path, {"main.py": main, "routes/chat.py": route}) == [f"routes/chat.py:{line}"]


@pytest.mark.parametrize("shape", sorted(_TWO_ROUTERS))
def test_llm_rate_limit_absent_silent_when_every_router_of_any_name_is_covered(
    tmp_path: Path, shape: str
) -> None:
    # The FP-bait neighbour of the test above: with BOTH routers mounted rate-limited, every route
    # in the file is covered, so the router-level credit still holds for a non-`router` name.
    route, _ = _TWO_ROUTERS[shape]
    main = _MAIN_HEAD + (
        f"app = FastAPI()\napp.include_router(chat.router, dependencies={_RL_DEP})\n"
        f"app.include_router(chat.chat_router, dependencies={_RL_DEP})\n"
    )
    assert _tree(tmp_path, {"main.py": main, "routes/chat.py": route}) == []


# Registrations the receiver scan cannot attribute to a plain router name: a route table passed as
# `routes=`, a mutation of a router's `.routes`, a dotted receiver (`common.router` is another
# module's router, not this file's covered `router`), a receiver reached by subscript or call, and
# a file that does not parse. The location is the LLM call's line.
_UNATTRIBUTED = {
    "routes-table": (
        _TWO_ROUTERS_HEAD + _LLM_HANDLER
        + "chat_router = APIRouter(\n    routes=[Route('/chat', chat, methods=['POST'])],\n)\n",
        10,
    ),
    "routes-append": (
        _TWO_ROUTERS_HEAD + _LLM_HANDLER + "chat_router.routes.append(Route('/chat', chat, methods=['POST']))\n",
        10,
    ),
    "dotted-receiver": (
        _TWO_ROUTERS_HEAD + _LLM_HANDLER
        + "from routes import common\ncommon.router.add_api_route('/chat', chat, methods=['POST'])\n",
        10,
    ),
    "subscript-receiver": (
        _TWO_ROUTERS_HEAD + "routers = {'chat': chat_router}\n@routers['chat'].post('/chat')\n" + _LLM_HANDLER,
        12,
    ),
    "call-receiver": (
        _TWO_ROUTERS_HEAD + "def get_router() -> APIRouter:\n    return chat_router\n"
        "@get_router().post('/chat')\n" + _LLM_HANDLER,
        13,
    ),
    "unparseable": (_TWO_ROUTERS_HEAD + _LLM_HANDLER + "chat_router.add_api_route('/chat', chat\n", 10),
    # A `routes=` table handed to a project's own helper, not only to a router or app constructor.
    "routes-table-helper": (
        _TWO_ROUTERS_HEAD + _LLM_HANDLER
        + "from common import PREBUILT_ROUTES, attach_routes\nattach_routes(chat_router, routes=PREBUILT_ROUTES)\n",
        10,
    ),
    # `public` gets a copy of the covered `router`'s routes and may be mounted without the limit:
    # a `.routes` VALUE is still a hand-off, which is why `get_openapi` is exempt by callee, not by
    # the shape of what it is passed.
    "routes-copied-to-another-router": (
        _TWO_ROUTERS_HEAD + "@router.post('/chat')\n" + _LLM_HANDLER + "public = APIRouter(routes=router.routes)\n",
        11,
    ),
}
_BOTH_COVERED = _MAIN_HEAD + (
    f"app = FastAPI()\napp.include_router(chat.router, dependencies={_RL_DEP})\n"
    f"app.include_router(chat.chat_router, dependencies={_RL_DEP})\n"
)


@pytest.mark.parametrize("shape", sorted(_UNATTRIBUTED))
def test_llm_rate_limit_absent_still_fires_when_a_route_registration_is_unattributable(
    tmp_path: Path, shape: str
) -> None:
    # #1007 review rounds 2 and 3: the router-level credit is only as good as the receiver set, so a
    # file registering a route the scan cannot attribute gets none, even with every router it
    # names mounted rate-limited (fail closed; each shape here is rare in a FastAPI app).
    route, line = _UNATTRIBUTED[shape]
    assert _tree(tmp_path, {"main.py": _BOTH_COVERED, "routes/chat.py": route}) == [f"routes/chat.py:{line}"]


@pytest.mark.parametrize(
    ("route", "main"),
    [
        # A bare import of `Route` and a static-files mount register no route on another receiver.
        (
            "from starlette.routing import Route\n" + _TWO_ROUTERS["decorator"][0]
            + "router.mount('/static', StaticFiles(directory='static'))\n",
            _BOTH_COVERED,
        ),
        # A router variable that happens to be NAMED `routes` is an ordinary receiver.
        (
            _TWO_ROUTERS["decorator"][0].replace("chat_router", "routes"),
            _BOTH_COVERED.replace("chat.chat_router", "chat.routes"),
        ),
        # FastAPI's documented operation-id recipe only READS a router's `.routes`.
        (
            _TWO_ROUTERS["decorator"][0] + "from fastapi.routing import APIRoute\n"
            "for route in router.routes:\n    if isinstance(route, APIRoute):\n"
            "        route.operation_id = route.name\n",
            _BOTH_COVERED,
        ),
        # A `.routes` length log, a parameter named `routes`, and a dict-dispatch call that is
        # shaped like a hand-applied decorator but carries no path.
        (
            _TWO_ROUTERS["decorator"][0] + "import logging\n"
            "logging.info('%d routes', len(chat_router.routes))\n"
            "def debug_dump(routes=None) -> None:\n    print(routes)\n"
            "handlers = {'x': print}\nhandlers.get('x')('payload')\n",
            _BOTH_COVERED,
        ),
        # FastAPI's documented "Extending OpenAPI" recipe passes `routes=` to `get_openapi`, which
        # only reads them to build the schema.
        (
            _TWO_ROUTERS["decorator"][0] + "from fastapi.openapi.utils import get_openapi\n"
            "from main import app\ndef custom_openapi() -> dict:\n"
            "    return get_openapi(title='API', version='1.0.0', routes=app.routes)\n",
            _BOTH_COVERED,
        ),
    ],
    ids=[
        "route-import-and-static-mount", "router-named-routes", "operation-id-recipe", "routes-reads",
        "get-openapi-recipe",
    ],
)
def test_llm_rate_limit_absent_silent_when_routes_are_only_read_or_mentioned(
    tmp_path: Path, route: str, main: str
) -> None:
    # The FP-bait neighbour of the test above: nothing here registers a route outside the scan.
    assert _tree(tmp_path, {"main.py": main, "routes/chat.py": route}) == []


def test_llm_rate_limit_absent_still_fires_on_an_exempt_route_under_global_limits(tmp_path: Path) -> None:
    # slowapi's middleware never limits an `@<limiter>.exempt` route. The limiter is imported under
    # a name the same-file signal does not read (`@limiter.exempt` would match `@\w*limiter`).
    route = _CHAT_ROUTE.replace(
        "@router.post('/chat')\n", "@router.post('/chat')\n@lim.exempt\n"
    ).replace("router = APIRouter()\n", "from main import lim\nrouter = APIRouter()\n")
    main = (
        _MAIN_HEAD + "lim = Limiter(key_func=get_remote_address, default_limits=['100/minute'])\n"
        "app = FastAPI()\napp.state.limiter = lim\napp.add_middleware(SlowAPIMiddleware)\n"
        "app.include_router(chat.router)\n"
    )
    assert _tree(tmp_path, {"main.py": main, "routes/chat.py": route}) == ["routes/chat.py:9"]


def test_llm_rate_limit_absent_still_fires_when_only_a_test_app_wires_rate_limiting(tmp_path: Path) -> None:
    # A test app's wiring never runs in front of the product's routes.
    files = {"tests/conftest.py": _MAIN_HEAD + _SLOWAPI, "routes/chat.py": _CHAT_ROUTE}
    assert _tree(tmp_path, files) == ["routes/chat.py:7"]


def test_llm_rate_limit_absent_still_fires_when_another_app_wires_rate_limiting(tmp_path: Path) -> None:
    # Monorepo: `svc_a/`'s global limits do not cover `svc_b/`'s routes.
    files = {
        "svc_a/main.py": _MAIN_HEAD + _SLOWAPI,
        "svc_a/routes/chat.py": _CHAT_ROUTE,
        "svc_b/routes/chat_b.py": _CHAT_ROUTE,
    }
    assert _tree(tmp_path, files) == ["svc_b/routes/chat_b.py:7"]
