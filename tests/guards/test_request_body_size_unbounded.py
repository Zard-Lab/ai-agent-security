from __future__ import annotations

from agentsec.guards.request_body_size_unbounded import RequestBodySizeUnboundedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_request_body_size_unbounded_fires_on_post(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "from fastapi import APIRouter\n"
        "from pydantic import BaseModel\n"
        "router = APIRouter()\n"
        "class CreateUser(BaseModel):\n"
        "    name: str\n"
        "@router.post('/users')\n"
        "async def create_user(body: CreateUser):\n"
        "    return {'name': body.name}\n",
        encoding="utf-8",
    )
    findings = RequestBodySizeUnboundedGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "request-body-size-unbounded/no-size-check"
    assert findings[0].severity == "medium"


def test_request_body_size_unbounded_fires_on_put_and_patch(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "from fastapi import APIRouter\n"
        "from pydantic import BaseModel\n"
        "router = APIRouter()\n"
        "class UpdateUser(BaseModel):\n"
        "    name: str\n"
        "@router.put('/users/{id}')\n"
        "async def update_user(id: str, body: UpdateUser):\n"
        "    return {'id': id}\n"
        "@router.patch('/users/{id}')\n"
        "async def patch_user(id: str, body: UpdateUser):\n"
        "    return {'id': id}\n",
        encoding="utf-8",
    )
    findings = RequestBodySizeUnboundedGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert len(findings) == 2


def test_request_body_size_unbounded_silent_on_uploadfile_only(tmp_path: Path) -> None:
    # FP-bait: an UploadFile-typed route is upload-no-size-limit's target, out of scope here
    # regardless of size checks.
    (tmp_path / "h.py").write_text(
        "from fastapi import APIRouter, UploadFile\n"
        "router = APIRouter()\n"
        "@router.post('/upload')\n"
        "async def upload(file: UploadFile):\n"
        "    data = await file.read()\n"
        "    return {'n': len(data)}\n",
        encoding="utf-8",
    )
    assert RequestBodySizeUnboundedGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_request_body_size_unbounded_silent_when_size_check_present(tmp_path: Path) -> None:
    # FP-bait: an explicit size check present in the route silences it.
    (tmp_path / "h.py").write_text(
        "from fastapi import APIRouter, HTTPException\n"
        "from pydantic import BaseModel\n"
        "router = APIRouter()\n"
        "class CreateUser(BaseModel):\n"
        "    name: str\n"
        "MAX_BODY_SIZE = 1_000_000\n"
        "@router.post('/users')\n"
        "async def create_user(request, body: CreateUser):\n"
        "    if int(request.headers.get('content-length', 0)) > MAX_BODY_SIZE:\n"
        "        raise HTTPException(413)\n"
        "    return {'name': body.name}\n",
        encoding="utf-8",
    )
    assert RequestBodySizeUnboundedGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_request_body_size_unbounded_silent_when_size_middleware_registered(tmp_path: Path) -> None:
    # FP-bait: a size/limit-named ASGI middleware registered via app.add_middleware applies to
    # the whole file.
    (tmp_path / "h.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "from pydantic import BaseModel\n"
        "from myapp.middleware import RequestSizeLimitMiddleware\n"
        "app = FastAPI()\n"
        "app.add_middleware(RequestSizeLimitMiddleware, max_size=1_000_000)\n"
        "router = APIRouter()\n"
        "class CreateUser(BaseModel):\n"
        "    name: str\n"
        "@router.post('/users')\n"
        "async def create_user(body: CreateUser):\n"
        "    return {'name': body.name}\n",
        encoding="utf-8",
    )
    assert RequestBodySizeUnboundedGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_request_body_size_unbounded_silent_without_body_model_param(tmp_path: Path) -> None:
    # FP-bait: a route with only primitive-typed / query-default params has no request-body model.
    (tmp_path / "h.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.post('/ping')\n"
        "async def ping(q: str = ''):\n"
        "    return {'q': q}\n",
        encoding="utf-8",
    )
    assert RequestBodySizeUnboundedGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_request_body_size_unbounded_silent_on_depends_param(tmp_path: Path) -> None:
    # FP-bait: a capitalized type defaulted to Depends(...) is a dependency, not a request body.
    (tmp_path / "h.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "class Settings:\n"
        "    pass\n"
        "def get_settings():\n"
        "    return Settings()\n"
        "@router.post('/ping')\n"
        "async def ping(settings: Settings = Depends(get_settings)):\n"
        "    return {}\n",
        encoding="utf-8",
    )
    assert RequestBodySizeUnboundedGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_request_body_size_unbounded_silent_on_get_route(tmp_path: Path) -> None:
    # FP-bait: GET has no conventional request body; a Pydantic type used only in a return
    # annotation must not fire.
    (tmp_path / "h.py").write_text(
        "from fastapi import APIRouter\n"
        "from pydantic import BaseModel\n"
        "router = APIRouter()\n"
        "class Item(BaseModel):\n"
        "    name: str\n"
        "@router.get('/items')\n"
        "async def list_items() -> list[Item]:\n"
        "    return []\n",
        encoding="utf-8",
    )
    assert RequestBodySizeUnboundedGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_request_body_size_unbounded_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "h.py").write_text(
        "from fastapi import APIRouter\n"
        "from pydantic import BaseModel\n"
        "router = APIRouter()\n"
        "# security: allow-unbounded-request-body\n"
        "class CreateUser(BaseModel):\n"
        "    name: str\n"
        "@router.post('/users')\n"
        "async def create_user(body: CreateUser):\n"
        "    return {'name': body.name}\n",
        encoding="utf-8",
    )
    assert RequestBodySizeUnboundedGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_request_body_size_unbounded_silent_on_nonproduct_path(tmp_path: Path) -> None:
    d = tmp_path / "tests"
    d.mkdir()
    (d / "h.py").write_text(
        "from fastapi import APIRouter\n"
        "from pydantic import BaseModel\n"
        "router = APIRouter()\n"
        "class CreateUser(BaseModel):\n"
        "    name: str\n"
        "@router.post('/users')\n"
        "async def create_user(body: CreateUser):\n"
        "    return {'name': body.name}\n",
        encoding="utf-8",
    )
    assert RequestBodySizeUnboundedGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_request_body_size_unbounded_not_applicable_without_fastapi() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert RequestBodySizeUnboundedGuard().applies(prof) is False
