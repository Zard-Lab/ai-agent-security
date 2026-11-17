from __future__ import annotations

from agentsec.guards.request_model_extra_forbid import RequestModelExtraForbidGuard
from tests.guards._common import *  # noqa: F401,F403


def test_request_model_extra_forbid_flags_model(tmp_path: Path) -> None:
    # over-postable: default extra + the body spread onto a record (the mass-assignment sink).
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\nfrom pydantic import BaseModel\n"
        "router = APIRouter()\n\nclass NewUser(BaseModel):\n    name: str\n\n"
        "@router.post('/u')\nasync def create(body: NewUser):\n    db.save(User(**body.model_dump()))\n", encoding="utf-8"
    )
    findings = RequestModelExtraForbidGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "request-model-extra-forbid/missing-forbid"
    assert "NewUser" in findings[0].title

def test_request_model_extra_forbid_no_spread_sink_not_flagged(tmp_path: Path) -> None:
    # T1 precision: default extra="ignore" strips unknowns; with NO spread sink there is no
    # over-posting — must be silent (this was the dominant flagship false positive, ~33 of them).
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\nfrom pydantic import BaseModel\n"
        "router = APIRouter()\n\nclass NewUser(BaseModel):\n    name: str\n\n"
        "@router.post('/u')\nasync def create(body: NewUser):\n    return {'ok': body.name}\n", encoding="utf-8"
    )
    assert RequestModelExtraForbidGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_request_model_extra_forbid_flags_extra_allow(tmp_path: Path) -> None:
    # extra="allow" is the genuinely-unsafe config — flag it even without a spread sink.
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\nfrom pydantic import BaseModel, ConfigDict\n"
        "router = APIRouter()\n\nclass NewUser(BaseModel):\n"
        '    model_config = ConfigDict(extra="allow")\n    name: str\n\n'
        "@router.post('/u')\nasync def create(body: NewUser):\n    return body\n", encoding="utf-8"
    )
    findings = RequestModelExtraForbidGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1 and "NewUser" in findings[0].title

def test_request_model_extra_forbid_passes_with_forbid(tmp_path: Path) -> None:
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\nfrom pydantic import BaseModel, ConfigDict\n"
        "router = APIRouter()\n\nclass NewUser(BaseModel):\n"
        "    model_config = ConfigDict(extra=\"forbid\")\n    name: str\n", encoding="utf-8"
    )
    assert RequestModelExtraForbidGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_request_model_extra_forbid_ignores_non_route_file(tmp_path: Path) -> None:
    # a model with no FastAPI route in the file -> not a request body, silent
    (tmp_path / "schemas.py").write_text("from pydantic import BaseModel\nclass X(BaseModel):\n    a: int\n", encoding="utf-8")
    assert RequestModelExtraForbidGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_request_model_extra_forbid_pragma(tmp_path: Path) -> None:
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter  # security: allow-extra-fields\n"
        "from pydantic import BaseModel\nrouter = APIRouter()\nclass X(BaseModel):\n    a: int\n", encoding="utf-8"
    )
    assert RequestModelExtraForbidGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_request_model_extra_forbid_skips_response_models(tmp_path: Path) -> None:
    # response-shaped models (…Response / …Out) are not request bodies -> no over-posting.
    # Mirrors the 9_Agent_SaaS flagship FP on `PaymentIntentResponse`.
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\nfrom pydantic import BaseModel\n"
        "router = APIRouter()\n\n"
        "class AgentRequest(BaseModel):\n    query: str\n\n"
        "class PaymentIntentResponse(BaseModel):\n    client_secret: str\n\n"
        "class UserOut(BaseModel):\n    id: str\n\n"
        "@router.post('/a')\nasync def ask(body: AgentRequest):\n    db.save(Q(**body.model_dump()))\n", encoding="utf-8"
    )
    findings = RequestModelExtraForbidGuard().run(tmp_path, _fastapi_prof(tmp_path))
    titles = " ".join(f.title for f in findings)
    assert "AgentRequest" in titles
    assert "PaymentIntentResponse" not in titles and "UserOut" not in titles
    assert len(findings) == 1

def test_request_model_extra_forbid_unbound_model_not_flagged(tmp_path: Path) -> None:
    # The flagship dashboard FP: a route file whose models are never a request body
    # (a GET endpoint returning DTOs) -> nothing flagged.
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\nfrom pydantic import BaseModel\n"
        "router = APIRouter()\n\nclass DpiSummary(BaseModel):\n    score: int\n\n"
        "@router.get('/d')\nasync def dash():\n    db.save(Row(**form.model_dump()))\n    return {}\n", encoding="utf-8"
    )
    # a spread sink IS present in the file, but DpiSummary is never a request body -> still silent.
    assert RequestModelExtraForbidGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_request_model_extra_forbid_nested_request_model_flagged(tmp_path: Path) -> None:
    # A BaseModel used as a field of a bound body model is also an over-posting sink
    # (extra="forbid" does not cascade) -> both flagged.
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\nfrom pydantic import BaseModel\n"
        "router = APIRouter()\n\nclass Inner(BaseModel):\n    a: int\n\n"
        "class Outer(BaseModel):\n    inner: Inner\n\n"
        "@router.post('/o')\nasync def h(body: Outer):\n    db.save(Row(**body.model_dump()))\n", encoding="utf-8"
    )
    names = {f.title.split("`")[1] for f in RequestModelExtraForbidGuard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert names == {"Inner", "Outer"}

def test_request_model_extra_forbid_response_field_model_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\nfrom pydantic import BaseModel\n"
        "router = APIRouter()\n\nclass Sub(BaseModel):\n    a: int\n\n"
        "class Resp(BaseModel):\n    s: Sub\n\n"
        "@router.get('/r', response_model=Resp)\nasync def h():\n    db.save(Row(**form.model_dump()))\n    return {}\n", encoding="utf-8"
    )
    assert RequestModelExtraForbidGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_request_model_extra_forbid_depends_param_not_a_body(tmp_path: Path) -> None:
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter, Depends\nfrom pydantic import BaseModel\n"
        "router = APIRouter()\n\nclass User(BaseModel):\n    id: str\n\n"
        "@router.get('/m')\nasync def me(user: User = Depends(get_user)):\n"
        "    db.save(Row(**form.model_dump()))\n    return user\n", encoding="utf-8"
    )
    assert RequestModelExtraForbidGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_request_model_extra_forbid_na_without_fastapi(tmp_path: Path) -> None:
    assert RequestModelExtraForbidGuard().applies(mkprofile(tmp_path, features={"python"})) is False

def test_request_model_extra_forbid_only_basemodel(tmp_path: Path) -> None:
    # a plain class (not a BaseModel) in a route file -> not flagged
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\nclass Helper:\n    pass\n", encoding="utf-8"
    )
    assert RequestModelExtraForbidGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_param_lists_unclosed_paren_input_is_linear() -> None:
    # Regression (issue #419): _param_lists rescanned to EOF for EVERY def when a paren
    # was left unclosed — O(n²), reproduced at n=1000/2000/4000 with a ~4× doubling
    # ratio (0.25s/0.98s/3.3s). The paren-pairing pass is linear; a quadratic form
    # would blow this budget by orders of magnitude.
    import time

    from agentsec.guards.request_model_extra_forbid import _param_lists

    hostile = "def foo(\n" * 8000  # every def's '(' unclosed
    start = time.monotonic()
    assert _param_lists(hostile) == []      # unclosed -> no param list (unchanged behavior)
    assert time.monotonic() - start < 1.0, "quadratic EOF rescan reintroduced"
    # balanced defs still parse, including nested defaults
    assert _param_lists("def f(a: int = Query(5), b: str = 'x'):\n") == ["a: int = Query(5), b: str = 'x'"]
