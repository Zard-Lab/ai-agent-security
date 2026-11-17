from __future__ import annotations

import pytest

from agentsec.detect import detect
from agentsec.findings import Finding
from agentsec.guards.error_response_info_leak import ErrorResponseInfoLeakGuard
from tests.guards._common import *  # noqa: F401,F403


def test_error_info_leak_str_exception_fires(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import HTTPException\n"
        "async def handler(item_id: int) -> dict:\n"
        "    try:\n"
        "        return {\'id\': item_id}\n"
        "    except Exception as e:\n"
        "        raise HTTPException(status_code=500, detail=str(e))\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    rules = [f.rule for f in findings]
    assert "error-info-leak/exception-str-in-detail" in rules

def test_error_info_leak_repr_exception_fires(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import HTTPException\n"
        "async def handler() -> dict:\n"
        "    try:\n"
        "        return {}\n"
        "    except Exception as e:\n"
        "        raise HTTPException(status_code=500, detail=repr(e))\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    rules = [f.rule for f in findings]
    assert "error-info-leak/exception-str-in-detail" in rules

def test_error_info_leak_traceback_fires(tmp_path: Path) -> None:
    # the traceback var actually reaches the response (detail=) -> real leak.
    (tmp_path / "app.py").write_text(
        "import traceback\n"
        "from fastapi import HTTPException\n"
        "async def handler() -> dict:\n"
        "    try:\n"
        "        return {}\n"
        "    except Exception:\n"
        "        tb = traceback.format_exc()\n"
        '        raise HTTPException(status_code=500, detail=f"failed: {tb}")\n',
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    rules = [f.rule for f in findings]
    assert "error-info-leak/traceback-in-response" in rules

def test_error_info_leak_traceback_to_logger_silent(tmp_path: Path) -> None:
    # T1b precision: the traceback is captured and LOGGED (Slack/OTel/logger), the response is a
    # generic string — `tb` never reaches a response sink, so this must be silent (was a FP).
    (tmp_path / "app.py").write_text(
        "import traceback, logging\n"
        "from fastapi import HTTPException\n"
        "logger = logging.getLogger(__name__)\n"
        "async def handler() -> dict:\n"
        "    try:\n"
        "        return {}\n"
        "    except Exception:\n"
        "        tb = traceback.format_exc()\n"
        "        logger.error(tb)\n"
        '        raise HTTPException(status_code=500, detail="Internal server error")\n',
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_error_info_leak_4xx_validation_echo_silent(tmp_path: Path) -> None:
    # T1b precision: a 4xx echoes a developer-raised validation message — intentional, not an
    # internal leak. Only 5xx (or default) returns an unhandled exception. (Was a FP.)
    (tmp_path / "app.py").write_text(
        "from fastapi import HTTPException\n"
        "async def handler(x: int) -> dict:\n"
        "    try:\n"
        "        return validate(x)\n"
        "    except ValueError as e:\n"
        "        raise HTTPException(status_code=400, detail=str(e))\n",
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_error_info_leak_5xx_still_fires(tmp_path: Path) -> None:
    # ...but the same str(e) on a 5xx is a real internal leak and MUST still fire (no FN).
    (tmp_path / "app.py").write_text(
        "from fastapi import HTTPException\n"
        "async def handler(x: int) -> dict:\n"
        "    try:\n"
        "        return work(x)\n"
        "    except Exception as e:\n"
        "        raise HTTPException(status_code=503, detail=str(e))\n",
        encoding="utf-8",
    )
    rules = [f.rule for f in ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))]
    assert "error-info-leak/exception-str-in-detail" in rules

def test_error_info_leak_safe_detail_silent(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import HTTPException\n"
        "async def handler() -> dict:\n"
        "    try:\n"
        "        return {}\n"
        "    except Exception:\n"
        "        raise HTTPException(status_code=500, detail=\'An error occurred\')\n",
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_error_info_leak_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "# security: allow-detailed-errors\n"
        "from fastapi import HTTPException\n"
        "async def handler() -> dict:\n"
        "    try:\n"
        "        return {}\n"
        "    except Exception as e:\n"
        "        raise HTTPException(status_code=500, detail=str(e))\n",
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_error_info_leak_no_exception_silent(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def process(data: dict) -> dict:\n"
        "    return {\'result\': data.get(\'key\', \'default\')}\n",
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_error_info_leak_test_path_silent(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_app.py").write_text(
        "from fastapi import HTTPException\n"
        "def test_handler():\n"
        "    try:\n"
        "        pass\n"
        "    except Exception as e:\n"
        "        raise HTTPException(status_code=500, detail=str(e))\n",
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_error_info_leak_fstring_exception_fires(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import HTTPException\n"
        "async def handler() -> dict:\n"
        "    try:\n"
        "        return {}\n"
        "    except Exception as e:\n"
        "        raise HTTPException(status_code=500, detail=f\'Error: {e}\')\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    rules = [f.rule for f in findings]
    assert "error-info-leak/exception-str-in-detail" in rules

def test_error_info_leak_fastapi_status_constant_silent(tmp_path: Path) -> None:
    # Precision fix: FastAPI's status.HTTP_422_UNPROCESSABLE_ENTITY is a 4xx constant —
    # the guard should not fire even though status_code isn't a bare 3-digit literal.
    (tmp_path / "app.py").write_text(
        "from fastapi import HTTPException, status\n"
        "async def handler() -> dict:\n"
        "    try:\n"
        "        return validate()\n"
        "    except ValueError as e:\n"
        "        raise HTTPException(\n"
        "            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,\n"
        "            detail=str(e),\n"
        "        )\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert not any(f.rule == "error-info-leak/exception-str-in-detail" for f in findings)

def test_error_info_leak_positional_4xx_silent(tmp_path: Path) -> None:
    # Positional status code form: HTTPException(400, str(e)) — 4xx, should not fire.
    (tmp_path / "app.py").write_text(
        "from fastapi import HTTPException\n"
        "async def handler() -> dict:\n"
        "    try:\n"
        "        return parse()\n"
        "    except ValueError as e:\n"
        "        raise HTTPException(400, detail=str(e))\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert not any(f.rule == "error-info-leak/exception-str-in-detail" for f in findings)

def test_error_info_leak_named_http_constant_5xx_still_fires(tmp_path: Path) -> None:
    # status.HTTP_500_INTERNAL_SERVER_ERROR is a 5xx constant — should still fire.
    (tmp_path / "app.py").write_text(
        "from fastapi import HTTPException, status\n"
        "async def handler() -> dict:\n"
        "    try:\n"
        "        return query_db()\n"
        "    except Exception as e:\n"
        "        raise HTTPException(\n"
        "            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,\n"
        "            detail=str(e),\n"
        "        )\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert any(f.rule == "error-info-leak/exception-str-in-detail" for f in findings)

def test_error_info_leak_except_block_json_response_dict_fires(tmp_path: Path) -> None:
    # str(e) reaching the response through a JSONResponse dict literal, not an HTTPException
    # detail= kwarg — invisible to rule #1, this is exactly the gap rule #4 closes.
    (tmp_path / "app.py").write_text(
        "from fastapi.responses import JSONResponse\n"
        "async def handler():\n"
        "    try:\n"
        "        return work()\n"
        "    except Exception as e:\n"
        "        return JSONResponse({\"error\": str(e)}, status_code=500)\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert any(f.rule == "error-info-leak/except-block-response-leak" for f in findings)

def test_error_info_leak_except_block_bare_return_dict_fires(tmp_path: Path) -> None:
    # A bare-dict error return inside a real FastAPI handler (the file carries HTTP context:
    # a fastapi import + a route decorator) is a genuine HTTP leak and must still fire. The
    # bare-dict-return sink is only honored when the file has HTTP-handler context — see the
    # tool-return FP-bait test below for the non-HTTP case that must stay silent.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/x')\n"
        "async def handler():\n"
        "    try:\n"
        "        return work()\n"
        "    except Exception as exc:\n"
        '        return {"detail": f"{exc}"}\n',
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert any(f.rule == "error-info-leak/except-block-response-leak" for f in findings)

def test_error_info_leak_llm_tool_return_no_http_context_silent(tmp_path: Path) -> None:
    # Precision fix (a RAG app's rag/tools.py, 5 FPs): an LLM/agent tool-helper returns the
    # {"ok": False, "error": ...exc...} tool-result shape. The file has NO HTTP-handler context
    # (no fastapi/starlette import, route decorator, JSONResponse, HTTPException, or status_code),
    # so this bare-dict return is NOT an HTTP response leak and must stay silent. The exception →
    # LLM-tool-result-context leak is a real, different finding, owned by the llm-tool-result-leak
    # guard — not error-info-leak.
    #
    # The function is named the way a real tool is named (for what it DOES), never `*_tool` — a
    # `*_tool` name here would let the guard pass this test on the function-name signal alone and
    # certify nothing about the shape it claims to be about.
    (tmp_path / "tools.py").write_text(
        "async def search_documents(query: str) -> dict:\n"
        "    try:\n"
        "        return await run_search(query)\n"
        "    except Exception as exc:\n"
        '        return {"ok": False, "error": f"search failed: {exc}"}\n',
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_error_info_leak_flask_bare_return_dict_fires(tmp_path: Path) -> None:
    # The guard's applies() gate is generic `python`, so Flask handlers are in scope too. A Flask
    # route (`@app.route`) returning a bare error dict is a real HTTP leak — the file's flask import
    # + `.route` decorator provide HTTP context, so it must still fire (no regression vs pre-tune).
    (tmp_path / "views.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/x')\n"
        "def handler():\n"
        "    try:\n"
        "        return work()\n"
        "    except Exception as exc:\n"
        '        return {"error": f"{exc}"}\n',
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert any(f.rule == "error-info-leak/except-block-response-leak" for f in findings)

def test_error_info_leak_mixed_route_and_tool_file_flags_both(tmp_path: Path) -> None:
    # Documented tradeoff: _HTTP_CONTEXT is file-level, so a tool helper colocated with a real route
    # in the same file still flags (the file has HTTP context). Accepted for now — favour catching the
    # real HTTP leak; the tool-return case is claimed precisely by the llm-tool-result-leak guard (PR2).
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.get('/x')\n"
        "async def route_handler():\n"
        "    try:\n"
        "        return work()\n"
        "    except Exception as exc:\n"
        '        return {"error": f"{exc}"}\n'
        "async def tool_helper(q):\n"
        "    try:\n"
        "        return run(q)\n"
        "    except Exception as exc:\n"
        '        return {"error": f"{exc}"}\n',
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert sum(f.rule == "error-info-leak/except-block-response-leak" for f in findings) == 2

def test_error_info_leak_except_block_assign_then_sink_fires(tmp_path: Path) -> None:
    # two-step (one hop): str(e) assigned to a local var, that var reaches the sink directly.
    (tmp_path / "app.py").write_text(
        "from fastapi.responses import JSONResponse\n"
        "async def handler():\n"
        "    try:\n"
        "        return work()\n"
        "    except Exception as e:\n"
        "        msg = str(e)\n"
        "        return JSONResponse({\"error\": msg}, status_code=500)\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert any(f.rule == "error-info-leak/except-block-response-leak" for f in findings)

def test_error_info_leak_except_block_4xx_echo_silent(tmp_path: Path) -> None:
    # same 4xx-is-intentional exemption as rule #1, applied to the new sink shape.
    (tmp_path / "app.py").write_text(
        "from fastapi.responses import JSONResponse\n"
        "async def handler():\n"
        "    try:\n"
        "        return validate()\n"
        "    except ValueError as e:\n"
        "        return JSONResponse({\"error\": str(e)}, status_code=400)\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert not any(f.rule == "error-info-leak/except-block-response-leak" for f in findings)

def test_error_info_leak_except_block_bare_return_no_dict_silent(tmp_path: Path) -> None:
    # FP-bait (the real bug this guard hit during self-audit): a bare `return str(e)` or a
    # non-HTTP-shaped return is ordinary Python (CLI tools, internal helpers), not a response
    # sink — must not fire just because a `return` statement is nearby.
    (tmp_path / "runner.py").write_text(
        "def run_subprocess():\n"
        "    try:\n"
        "        return do_work()\n"
        "    except OSError as e:\n"
        "        return -1, '', str(e)\n",
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_error_info_leak_except_block_internal_dataclass_return_silent(tmp_path: Path) -> None:
    (tmp_path / "runner.py").write_text(
        "def run():\n"
        "    try:\n"
        "        return do_work()\n"
        "    except Exception as e:\n"
        "        return RunnerResult('id', available=True, error=f'{type(e).__name__}: {e}')\n",
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_error_info_leak_except_block_logger_only_silent(tmp_path: Path) -> None:
    # FP-bait: the exception is only logged, never reaches a response sink.
    (tmp_path / "app.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "async def handler():\n"
        "    try:\n"
        "        return work()\n"
        "    except Exception as e:\n"
        "        logger.error(str(e))\n"
        "        return {\"status\": \"error\"}\n",
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_error_info_leak_except_block_no_double_report_with_detail_kwarg(tmp_path: Path) -> None:
    # detail=str(e) inside an except block must fire ONLY the original rule, not also rule #4.
    (tmp_path / "app.py").write_text(
        "from fastapi import HTTPException\n"
        "async def handler():\n"
        "    try:\n"
        "        return work()\n"
        "    except Exception as e:\n"
        "        raise HTTPException(status_code=500, detail=str(e))\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    rules = [f.rule for f in findings]
    assert rules.count("error-info-leak/exception-str-in-detail") == 1
    assert "error-info-leak/except-block-response-leak" not in rules



# ---------------------------------------------------------------------------------------------
# The repo-level ("this is a web app") half of the HTTP-context gate — tested through REAL
# `detect()`, never `mkprofile`.
#
# This whole block used to hand-build `StackProfile.features` with `mkprofile(..., features={
# "fastapi", ...})`. That is precisely why it certified a gate that could not work: the shipped
# gate was `{"fastapi","flask","django"} & profile.features`, and `detect()` NEVER puts "flask" or
# "django" in `features` — it routes them into `profile.uncovered_stacks`, "never into
# profile.features", by design. Litestar / aiohttp / Django REST are not detected at all. Every
# test below therefore constructs a real repo on disk and runs the real detector over it, and the
# framework ones ASSERT the feature set really is missing the framework — so a future gate that
# leans on `features` again fails here instead of passing while production stays silent.
# ---------------------------------------------------------------------------------------------

_SERVICE_LEAK = (
    "def load_user(uid):\n"
    "    try:\n"
    "        return db_fetch(uid)\n"
    "    except Exception as e:\n"
    "        return {'detail': str(e)}\n"
)


def _real_scan(root: Path, files: dict[str, str]) -> tuple[StackProfile, list]:
    """Write `files` into `root`, fingerprint it with the REAL `detect()`, run the guard on the
    profile detection actually produced, and hand back both so a test can assert on the profile
    as well as the findings."""
    root.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    prof = detect(root)
    return prof, ErrorResponseInfoLeakGuard().run(root, prof)


def test_error_info_leak_flask_service_layer_fires_under_real_detect(tmp_path: Path) -> None:
    # Regression (#468 review, HIGH 1): a thin Flask route over a SERVICE layer, where the leak
    # lives in the service module and that module carries no framework token at all.
    prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "flask==3.0.0\nrequests==2.32.0\n",
        "app.py": (
            "from flask import Flask, jsonify\n"
            "from service import load_user\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/u/<uid>')\n"
            "def u(uid):\n"
            "    return jsonify(load_user(uid))\n"
        ),
        "service.py": _SERVICE_LEAK,
    })
    # The load-bearing half: detection really does keep Flask OUT of `features`, so a gate that
    # tested `"flask" in profile.features` could never fire here no matter what the tests said.
    assert "flask" not in prof.features
    assert prof.backend_framework is None
    assert "flask" in prof.uncovered_stacks
    assert [f.rule for f in findings] == ["error-info-leak/except-block-response-leak"]


def test_error_info_leak_django_service_layer_fires_under_real_detect(tmp_path: Path) -> None:
    # Same as above for Django (#468 review, HIGH 1) — also routed to `uncovered_stacks`.
    prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "Django==5.0\n",
        "urls.py": "from django.urls import path\nfrom views import v\nurlpatterns = [path('u/', v)]\n",
        "service.py": _SERVICE_LEAK,
    })
    assert "django" not in prof.features
    assert "django" in prof.uncovered_stacks
    assert [f.rule for f in findings] == ["error-info-leak/except-block-response-leak"]


@pytest.mark.parametrize(
    ("name", "requirement", "app_src"),
    [
        ("litestar", "litestar==2.8.0\n", "from litestar import Litestar, get\nfrom service import load_user\n"),
        ("aiohttp", "aiohttp==3.9.5\n", "from aiohttp import web\nfrom service import load_user\n"),
        ("drf", "djangorestframework==3.15\n",
         "from rest_framework.decorators import api_view\nfrom service import load_user\n"),
    ],
)
def test_error_info_leak_other_frameworks_service_layer_fires_under_real_detect(
    tmp_path: Path, name: str, requirement: str, app_src: str
) -> None:
    # Regression (#468 review, HIGH 2): Litestar, aiohttp and Django REST were named as the
    # frameworks the widening covered, but only the in-file `_HTTP_CONTEXT` token list was
    # extended — they are in neither the feature set nor `uncovered_stacks`, so the repo-level
    # fallback could not reach a service module that carries no token of its own.
    prof, findings = _real_scan(tmp_path / name, {
        "requirements.txt": requirement,
        "app.py": app_src,
        "service.py": _SERVICE_LEAK,
    })
    assert not ({"fastapi", "flask", "django"} & prof.features)
    assert [f.rule for f in findings] == ["error-info-leak/except-block-response-leak"]


def test_error_info_leak_rest_success_envelope_does_not_disqualify_a_service(tmp_path: Path) -> None:
    # Regression (#468 review, HIGH 3): `{"ok": True|False}` was listed as LLM-tool-module
    # evidence, but it is an ordinary REST success-envelope convention. A FastAPI service module
    # returning `{"ok": True, "data": …}` on success and `{"detail": str(e)}` on exception was
    # classified as a tool module — and it was the SOLE disqualifying signal in the file, so a
    # genuine leak went unreported on this guard's own primary target framework.
    prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "fastapi==0.111.0\nuvicorn\n",
        "main.py": (
            "from fastapi import FastAPI\n"
            "from service import load_user\n"
            "app = FastAPI()\n"
            "app.add_api_route('/u', load_user)\n"
        ),
        "service.py": (
            "def load_user(uid):\n"
            "    try:\n"
            "        data = db_fetch(uid)\n"
            '        return {"ok": True, "data": data}\n'
            "    except Exception as e:\n"
            '        return {"detail": str(e)}\n'
        ),
    })
    assert "fastapi" in prof.features
    assert [f.rule for f in findings] == ["error-info-leak/except-block-response-leak"]


def test_error_info_leak_bespoke_tool_dispatch_stays_silent_under_real_detect(tmp_path: Path) -> None:
    # FP-bait, and the reason the gate is not simply "the repo is a web app": a bespoke tool
    # dispatch table has NO registration syntax at all. This is the exact RAG-app `rag/tools.py`
    # shape the narrowing was introduced for, and it must stay silent inside a real FastAPI repo.
    #
    # The function is named `search_documents`, i.e. for WHAT IT DOES — the way real tool functions
    # are named. This test previously named it `search_tool`, which made it VACUOUS for the property
    # it claims: the guard passed it on the `def \w*_tool\(` name signal alone, so when the
    # `{"ok": <bool>}` envelope was dropped from the tool-module evidence the founding false
    # positive reopened for every realistically-named tool and this test still went green
    # (#468 re-review, regression #1). The envelope is the load-bearing signal here and it is now
    # matched per-sink-line (`_TOOL_RESULT_ENVELOPE`), not file-wide.
    _prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "fastapi==0.111.0\n",
        "main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        "rag/tools.py": (
            "def search_documents(q):\n"
            "    try:\n"
            '        return {"ok": True, "hits": go(q)}\n'
            "    except Exception as exc:\n"
            '        return {"ok": False, "error": f"search failed: {exc}"}\n'
        ),
    })
    assert findings == []


@pytest.mark.parametrize(
    ("name", "err_return"),
    [
        ("reversed_keys", '        return {"error": f"search failed: {exc}", "ok": False}\n'),
        ("single_quotes", "        return {'ok': False, 'error': str(exc)}\n"),
        ("message_key", '        return {"ok": False, "message": str(exc)}\n'),
    ],
)
def test_error_info_leak_tool_result_envelope_spellings_stay_silent(
    tmp_path: Path, name: str, err_return: str
) -> None:
    # The envelope signal must not be defeated by key order, quote style, or which of the
    # detail/error/message keys carries the text — none of those change what the value IS.
    _prof, findings = _real_scan(tmp_path / name, {
        "requirements.txt": "fastapi==0.111.0\n",
        "main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        "rag/tools.py": (
            "def fetch_chunks(q):\n"
            "    try:\n        return run(q)\n"
            "    except Exception as exc:\n" + err_return
        ),
    })
    assert findings == []


def test_error_info_leak_unrelated_ok_flag_does_not_suppress_the_leak(tmp_path: Path) -> None:
    # The tool-result envelope is matched on the SINK LINE, never file-wide — this is what makes it
    # strictly safer than the file-level `{"ok": <bool>}` signal it replaces. A service module with
    # an unrelated `{"ok": False, "reason": …}` return elsewhere would have been classified a tool
    # module wholesale by the file-level form, silencing the genuine `{"detail": str(e)}` leak below.
    _prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "fastapi==0.111.0\n",
        "main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        "service.py": (
            "def feature_flag(name):\n"
            '    if not enabled(name):\n        return {"ok": False, "reason": "disabled"}\n'
            '    return {"ok": True}\n'
            "\n" + _SERVICE_LEAK
        ),
    })
    assert [f.rule for f in findings] == ["error-info-leak/except-block-response-leak"]


def test_error_info_leak_envelope_in_a_comment_does_not_suppress_the_leak(tmp_path: Path) -> None:
    # Self-attack on the envelope rule: the sink is matched on the line's CODE, not its comment, so
    # a developer note that merely QUOTES the old tool-result shape cannot exempt a real leak.
    _prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "flask==3.0.0\n",
        "app.py": "from flask import Flask\napp = Flask(__name__)\n",
        "service.py": (
            "def load_user(uid):\n"
            "    try:\n        return db_fetch(uid)\n"
            "    except Exception as e:\n"
            '        return {"detail": str(e)}  # legacy shape was {"ok": False, "error": ...}\n'
        ),
    })
    assert [f.rule for f in findings] == ["error-info-leak/except-block-response-leak"]


def test_error_info_leak_json_response_with_envelope_still_fires(tmp_path: Path) -> None:
    # The envelope exemption applies ONLY to the bare-dict branch. An explicit `JSONResponse(...)`
    # is HTTP-response machinery by construction, so `{"ok": False}` inside one proves nothing.
    _prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "fastapi==0.111.0\n",
        "main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        "api/h.py": (
            "from fastapi.responses import JSONResponse\n"
            "async def handler():\n"
            "    try:\n        return work()\n"
            "    except Exception as e:\n"
            '        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)\n'
        ),
    })
    assert [f.rule for f in findings] == ["error-info-leak/except-block-response-leak"]


def test_error_info_leak_registered_tool_module_stays_silent_under_real_detect(tmp_path: Path) -> None:
    # FP-bait: the registered (`@tool`) tool module inside a web-app repo. The repo-level fallback
    # must not reach it either.
    _prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "fastapi==0.111.0\nlangchain==0.2.0\n",
        "main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        "agent/toolbox.py": (
            "from langchain_core.tools import tool\n\n"
            "@tool\n"
            "def lookup(q: str) -> dict:\n"
            "    try:\n        return do(q)\n"
            "    except Exception as e:\n"
            '        return {"error": str(e)}\n'
        ),
    })
    assert findings == []


def test_error_info_leak_aiohttp_client_only_repo_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the widening itself: aiohttp is both a server AND one of the most common async
    # HTTP *clients*. An agent repo that merely CALLS APIs must not read as a web app and drag
    # every bare-dict error return into scope, so the repo-level signal requires `aiohttp.web`.
    _prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "aiohttp==3.9.5\nopenai==1.30\n",
        "agent/fetch.py": (
            "import aiohttp\n\n"
            "async def grab(url):\n"
            "    async with aiohttp.ClientSession() as s:\n"
            "        return await s.get(url)\n"
        ),
        "agent/dispatch.py": (
            "def handle(name, args):\n"
            "    try:\n        return REGISTRY[name](**args)\n"
            "    except Exception as e:\n"
            '        return {"error": str(e)}\n'
        ),
    })
    assert findings == []


def test_error_info_leak_aiohttp_server_repo_fires(tmp_path: Path) -> None:
    # The other side of the same coin: the SAME package used as a server is a web app, so the
    # service-layer leak fires. Pairs with the client-only test above to prove the signal
    # discriminates on `aiohttp.web` rather than on the dependency name.
    _prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "aiohttp==3.9.5\n",
        "app.py": "from aiohttp import web\napp = web.Application()\n",
        "service.py": _SERVICE_LEAK,
    })
    assert [f.rule for f in findings] == ["error-info-leak/except-block-response-leak"]


def test_error_info_leak_flask_tuple_status_4xx_stays_silent(tmp_path: Path) -> None:
    # FP-bait for a class the widening newly makes REACHABLE: now that Flask/Django repos are in
    # scope, the `return body, 4xx` tuple convention has to get the same intentional-client-message
    # exemption the `status_code=4xx` and positional `HTTPException(4xx, …)` spellings already get.
    # Without it the single most common Flask error idiom reads as an unhandled-internal leak.
    _prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "flask==3.0.0\n",
        "app.py": "from flask import Flask\napp = Flask(__name__)\n",
        "service.py": (
            "def parse(payload):\n"
            "    try:\n        return validate(payload)\n"
            "    except ValueError as e:\n"
            '        return {"detail": str(e)}, 400\n'
        ),
    })
    assert findings == []


def test_error_info_leak_flask_tuple_status_5xx_still_fires(tmp_path: Path) -> None:
    # …and the 5xx tuple is still a leak, so the exemption above is a 4xx rule, not a blanket
    # "any trailing integer disables the check".
    _prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "flask==3.0.0\n",
        "app.py": "from flask import Flask\napp = Flask(__name__)\n",
        "service.py": (
            "def parse(payload):\n"
            "    try:\n        return validate(payload)\n"
            "    except Exception as e:\n"
            '        return {"detail": str(e)}, 500\n'
        ),
    })
    assert [f.rule for f in findings] == ["error-info-leak/except-block-response-leak"]


def test_error_info_leak_non_web_repo_is_unaffected(tmp_path: Path) -> None:
    # FP-bait safety net: the repo-level half of the gate needs a web framework somewhere, so a
    # pure CLI/agent project is untouched by the widening. (Non-discriminating for the gate change
    # itself — it passed before too — but it is the invariant the whole fallback rests on.)
    _prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "click==8.1\n",
        "helper.py": _SERVICE_LEAK,
    })
    assert findings == []


def test_error_info_leak_status_code_comparison_is_not_http_context(tmp_path: Path) -> None:
    # Regression (#468 review): `status_code\s*=` matched the COMPARISON `status_code ==`, so any
    # LLM tool calling an HTTP API acquired FILE-local "HTTP context" and re-admitted the bare-dict
    # branch. The repo here has no web framework at all, so the file-local token is the only path
    # to a finding — which is what keeps this test discriminating for the `(?!=)` anchor.
    _prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "httpx==0.27\n",
        "t.py": (
            "import httpx\n"
            "def fetch_tool(q):\n"
            "    r = httpx.get(q)\n"
            "    if r.status_code == 200:\n        pass\n"
            "    try:\n        return do()\n"
            "    except Exception as e:\n        return {'detail': str(e)}\n"
        ),
    })
    assert findings == []


# ---------------------------------------------------------------------------------------------
# "Is this repo a web app" must be answered from CODE, not from prose. `_is_web_app_repo` ORs one
# boolean across every scanned file, so a single file that merely MENTIONS a framework — in a
# docstring, an ADR note, a prompt template, or a comment — used to make every other file in the
# repo an HTTP handler (#468 re-review, regression #2).
# ---------------------------------------------------------------------------------------------

_AGENT_LEAK = (
    "def process(raw):\n"
    "    try:\n"
    "        return build(raw)\n"
    "    except Exception as e:\n"
    '        return {"detail": str(e)}\n'
)


def test_error_info_leak_framework_in_a_docstring_is_not_a_web_app(tmp_path: Path) -> None:
    # Regression (#468 re-review, HIGH 2): an ADR docstring recording a design that was REJECTED
    # (`aiohttp.web.Application()`) matched `_WEB_FRAMEWORK_IMPORT` against raw file text, so a
    # pure agent repo became a web app and its non-HTTP `{"detail": str(e)}` return was reported as
    # an HTTP leak. The repo below is an aiohttp CLIENT: the only `aiohttp.web` in it is prose.
    _prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "aiohttp==3.9.5\nopenai==1.30\n",
        "agent/tool.py": (
            '"""ADR: we rejected running a server here.\n'
            "Rejected: app = aiohttp.web.Application()\n"
            '"""\n'
            "import aiohttp\n\n"
            "async def call():\n"
            "    async with aiohttp.ClientSession() as s:\n        pass\n"
        ),
        "agent/service.py": _AGENT_LEAK,
    })
    assert findings == []


def test_error_info_leak_framework_in_a_comment_is_not_a_web_app(tmp_path: Path) -> None:
    # Same hazard one line down: `#` comments are stripped too. Spelled with `aiohttp.web.` because
    # that alternative is the one that matches mid-line — an `# from flask import …` comment never
    # satisfied the `^(?:from|import)` anchor, so it would not discriminate.
    _prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "aiohttp==3.9.5\nopenai==1.30\n",
        "agent/notes.py": (
            "# rejected design: app = aiohttp.web.Application()  <- we do not serve HTTP\n"
            "def helper():\n    return 1\n"
        ),
        "agent/service.py": _AGENT_LEAK,
    })
    assert findings == []


def test_error_info_leak_framework_in_a_prompt_template_is_not_a_web_app(tmp_path: Path) -> None:
    # The same hole by a SECOND route, found by attacking the docstring fix: `detect()` sets the
    # "fastapi" feature from a bare substring test over every file's text, and `_is_web_app_repo`
    # took `"fastapi" in profile.features` as its first disjunct — short-circuiting past the strip
    # entirely. A prompt template that shows the model some FastAPI code made the agent repo a web
    # app. The feature short-circuit is gone; the import regex over stripped code is the only path.
    prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "openai==1.30\n",
        "agent/prompts.py": (
            'SYSTEM = """You are a code assistant. Example answer:\n'
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            '"""\n'
        ),
        "agent/service.py": _AGENT_LEAK,
    })
    # The load-bearing half: detection really does report "fastapi" for this repo, so a gate that
    # trusts the feature set cannot stay silent here no matter what the rest of the guard does.
    assert "fastapi" in prof.features
    assert findings == []


@pytest.mark.parametrize(
    ("name", "app_src"),
    [
        ("from_web", "from aiohttp import web\napp = web.Application()\n"),
        ("from_aiohttp_web", "from aiohttp.web import Application\napp = Application()\n"),
        ("import_aiohttp_web", "import aiohttp.web\napp = aiohttp.web.Application()\n"),
    ],
)
def test_error_info_leak_aiohttp_server_import_spellings_fire(
    tmp_path: Path, name: str, app_src: str
) -> None:
    # The flip side of stripping prose: every spelling of a REAL aiohttp server import still makes
    # the repo a web app, so the service-layer leak fires. `from aiohttp.web import …` and
    # `import aiohttp.web` were not covered before.
    _prof, findings = _real_scan(tmp_path / name, {
        "requirements.txt": "aiohttp==3.9.5\n",
        "app.py": app_src,
        "service.py": _SERVICE_LEAK,
    })
    assert [f.rule for f in findings] == ["error-info-leak/except-block-response-leak"]


def test_error_info_leak_bom_prefixed_entrypoint_is_still_a_web_app(tmp_path: Path) -> None:
    # A Windows-authored entrypoint carries a UTF-8 BOM, and `read()` decodes as plain utf-8, so it
    # survives glued to line 1 and breaks the `^(?:from|import)` anchor. Found by attacking the
    # removal of the feature short-circuit, which had been masking it for FastAPI (and never for
    # Flask — this repo was a pre-existing false negative).
    _prof, findings = _real_scan(tmp_path, {
        "requirements.txt": "flask==3.0.0\n",
        "app.py": "\ufeff" + "from flask import Flask\napp = Flask(__name__)\n",
        "service.py": _SERVICE_LEAK,
    })
    assert [f.rule for f in findings] == ["error-info-leak/except-block-response-leak"]


# --- Express/JS (codeql js/stack-trace-exposure) ---

def test_error_info_leak_applies_on_express() -> None:
    assert ErrorResponseInfoLeakGuard().applies(mkprofile(Path("/tmp"), features={"express"})) is True


def test_error_info_leak_js_message_fires(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/x', (req, res) => {\n"
        "  try {\n"
        "    doWork();\n"
        "  } catch (e) {\n"
        "    res.status(500).json({ error: e.message });\n"
        "  }\n"
        "});\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "error-info-leak/exception-in-http-response"
    assert findings[0].severity == "high"


def test_error_info_leak_ts_unknown_catch_annotation_fires(tmp_path: Path) -> None:
    # #548 review High 5: TypeScript's OWN default under
    # `useUnknownInCatchVariables` types every catch binding `unknown` unless annotated `any` —
    # `catch (e: unknown)` is the idiomatic TS spelling, not an unusual one. The old `_JS_CATCH`
    # regex only matched a bare `\w+` catch binding, so this coverage gap existed on `.ts`/`.tsx`
    # files despite them being listed in `_JS_SUFFIXES` as covered.
    (tmp_path / "app.ts").write_text(
        "app.get('/x', (req, res) => {\n"
        "  try {\n"
        "    doWork();\n"
        "  } catch (e: unknown) {\n"
        "    res.status(500).json({ error: String(e) });\n"
        "  }\n"
        "});\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "error-info-leak/exception-in-http-response"


def test_error_info_leak_js_stack_fires(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/x', (req, res) => {\n"
        "  try {\n"
        "    doWork();\n"
        "  } catch (err) {\n"
        "    res.send(err.stack);\n"
        "  }\n"
        "});\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "error-info-leak/exception-in-http-response"


def test_error_info_leak_js_template_literal_fires(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/x', (req, res) => {\n"
        "  try {\n"
        "    doWork();\n"
        "  } catch (e) {\n"
        "    res.status(500).json({ error: `Failed: ${e}` });\n"
        "  }\n"
        "});\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1


def test_error_info_leak_js_4xx_validation_echo_silent(tmp_path: Path) -> None:
    # FP-bait: a 4xx response echoing the exception message is an intentional validation-error
    # echo (the developer raised it), not an unhandled-internal leak.
    (tmp_path / "app.js").write_text(
        "app.post('/x', (req, res) => {\n"
        "  try {\n"
        "    validate(req.body);\n"
        "  } catch (e) {\n"
        "    res.status(400).json({ error: e.message });\n"
        "  }\n"
        "});\n",
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_error_info_leak_js_logger_only_silent(tmp_path: Path) -> None:
    # FP-bait: the exception only reaches a logger, never an HTTP response sink.
    (tmp_path / "app.js").write_text(
        "app.get('/x', (req, res) => {\n"
        "  try {\n"
        "    doWork();\n"
        "  } catch (e) {\n"
        "    console.error(e.message);\n"
        "    res.status(500).json({ error: 'Internal server error' });\n"
        "  }\n"
        "});\n",
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_error_info_leak_js_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "// security: allow-detailed-errors\n"
        "app.get('/x', (req, res) => {\n"
        "  try {\n"
        "    doWork();\n"
        "  } catch (e) {\n"
        "    res.status(500).json({ error: e.message });\n"
        "  }\n"
        "});\n",
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_error_info_leak_traceback_direct_sink_spaced_equals_fires(tmp_path: Path) -> None:
    # Regression (#422/#437): the direct sink with a spaced `=` (`detail = traceback.format_exc()`)
    # was missed because a `\b` after the alternation cannot match between `=` and a space.
    (tmp_path / "app.py").write_text(
        "import traceback\n"
        "from fastapi import HTTPException\n"
        "async def handler() -> dict:\n"
        "    try:\n"
        "        return {}\n"
        "    except Exception:\n"
        "        raise HTTPException(status_code=500, detail = traceback.format_exc())\n",
        encoding="utf-8",
    )
    findings = ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    rules = [f.rule for f in findings]
    assert "error-info-leak/traceback-in-response" in rules


def test_error_info_leak_traceback_assigned_to_returner_var_silent(tmp_path: Path) -> None:
    # FP-bait for the `return\b` arm: a variable merely CONTAINING `return` is not the
    # return statement (`return\b` fails inside `returner`), and the value only goes to
    # a logger, so this must stay silent.
    (tmp_path / "app.py").write_text(
        "import traceback, logging\n"
        "logger = logging.getLogger(__name__)\n"
        "async def handler() -> dict:\n"
        "    try:\n"
        "        return {}\n"
        "    except Exception:\n"
        "        returner = traceback.format_exc()\n"
        "        logger.error(returner)\n",
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_error_leak_local_crash_dump_is_not_a_response_leak(tmp_path: Path) -> None:
    # Regression (#437 review): the `content\s*=` arm matched a bare LOCAL assignment, not just
    # the `Response(content=…)` kwarg — and because that check short-circuits the flow analysis,
    # a crash dump written to disk was reported as an HTTP response leak.
    (tmp_path / "a.py").write_text(
        "from pathlib import Path\n"
        "import traceback\n"
        "def dump(e):\n"
        "    content = traceback.format_exc()\n"
        "    Path('/var/log/crash.txt').write_text(content, encoding='utf-8')\n",
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


def test_error_leak_real_response_kwargs_still_fire(tmp_path: Path) -> None:
    # The kwarg-position anchor must keep both genuine sinks.
    (tmp_path / "a.py").write_text(
        "import traceback\n"
        "from fastapi import HTTPException\n"
        "def h():\n"
        "    raise HTTPException(status_code=500, detail=traceback.format_exc())\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "import traceback\n"
        "from fastapi import Response\n"
        "def h():\n"
        "    return Response(content=traceback.format_exc())\n",
        encoding="utf-8",
    )
    assert len(ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))) == 2


def test_error_info_leak_traceback_kwarg_on_a_continuation_line_fires(tmp_path: Path) -> None:
    # Regression (#587 review, Critical 1): the kwarg-position anchor was tested against the
    # physical line, so `black`/`ruff format` output — every kwarg of an over-long call on its own
    # continuation line, with the `,` at the end of the PREVIOUS line — stopped being reported.
    # This is the ordinary formatting of the exact shape the rule exists to catch.
    (tmp_path / "app.py").write_text(
        "import traceback\n"
        "from fastapi import HTTPException\n"
        "async def handler() -> dict:\n"
        "    try:\n"
        "        return {}\n"
        "    except Exception:\n"
        "        raise HTTPException(\n"
        "            status_code=500,\n"
        "            detail=traceback.format_exc(),\n"
        "        )\n",
        encoding="utf-8",
    )
    rules = [f.rule for f in ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))]
    assert "error-info-leak/traceback-in-response" in rules


def test_error_info_leak_response_content_kwarg_wrapped_fires(tmp_path: Path) -> None:
    # The same shape on the `content=` arm, wrapped after the opening paren rather than after a
    # comma — the other character the kwarg test accepts.
    (tmp_path / "app.py").write_text(
        "import traceback\n"
        "from fastapi import Response\n"
        "def h():\n"
        "    return Response(\n"
        "        content=traceback.format_exc()\n"
        "    )\n",
        encoding="utf-8",
    )
    rules = [f.rule for f in ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))]
    assert "error-info-leak/traceback-in-response" in rules


def test_error_leak_multiline_local_crash_dump_is_still_not_a_leak(tmp_path: Path) -> None:
    # FP-bait for that fix: crossing newlines must not re-admit the bare LOCAL assignment. Walking
    # back from `content` here lands on `:` (the end of the def line), not on a `(` or `,` — even
    # though parens appear on earlier lines.
    (tmp_path / "a.py").write_text(
        "from pathlib import Path\n"
        "import traceback\n"
        "def dump(\n"
        "    e,\n"
        "):\n"
        "    content = traceback.format_exc()\n"
        "    Path('/var/log/crash.txt').write_text(content, encoding='utf-8')\n",
        encoding="utf-8",
    )
    assert ErrorResponseInfoLeakGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []


# --- #1055: a JS/TS gate, sink, exception use or 4xx exemption counts only when it is live code ----

_JS_CATCH_HANDLER = (
    "app.get('/x', async (req, res) => {\n"
    "  try {\n"
    "    await doWork();\n"
    "  } catch (e) {\n"
    "    {SINK}\n"
    "  }\n"
    "});\n"
)


def _run_js_catch(tmp_path: Path, sink: str, handler: str = _JS_CATCH_HANDLER) -> list[Finding]:
    (tmp_path / "app.js").write_text(handler.replace("{SINK}", sink), encoding="utf-8")
    prof = mkprofile(tmp_path, features={"javascript", "node", "express"})
    guard = ErrorResponseInfoLeakGuard()
    assert guard.applies(prof)
    return guard.run(tmp_path, prof)


@pytest.mark.parametrize(
    "sink",
    [
        "res.status(500).json({ error: e.message, hint: 'status: 400 for bad input' });",
        "res.status(500).json({ error: e.message, hint: `retry with .status(400) for ${id}` });",
    ],
)
def test_error_info_leak_js_quoted_4xx_no_longer_exempts_a_5xx_leak(tmp_path: Path, sink: str) -> None:
    # The FN direction (#1055): a 4xx spelled out in a hint string used to exempt a real 5xx leak.
    findings = _run_js_catch(tmp_path, sink)
    assert [f.rule for f in findings] == ["error-info-leak/exception-in-http-response"]
    assert findings[0].location.replace("\\", "/").endswith("app.js:5")


@pytest.mark.parametrize(
    "sink",
    [
        "res.status(400).json({ error: e.message });",
        # The real 4xx nested in a `${...}` substitution is code: the shortcut-separating case, which
        # plain `strip_strings=True` would have blanked.
        "res.json({ error: e.message, s: `${res.status(400)}` });",
        # A quoted copy earlier on the line must not decide for the real key after it.
        "res.json({ hint: 'status: 400', error: e.message, status: 400 });",
    ],
)
def test_error_info_leak_js_real_4xx_still_exempts(tmp_path: Path, sink: str) -> None:
    assert _run_js_catch(tmp_path, sink) == []


@pytest.mark.parametrize(
    "sink",
    [
        "res.status(500).json({ error: 'see e.message in the logs' });",
        "log.info('res.json(e.message) would leak the error');",
        "log.error('res.json failed:', e.message);",
        "log.info(`res.send(${id}) must not echo e.stack`);",
    ],
)
def test_error_info_leak_js_quoted_sink_or_use_stays_silent(tmp_path: Path, sink: str) -> None:
    # The FP direction (#1055): a sink or exception use spelled out in a string is not one.
    assert _run_js_catch(tmp_path, sink) == []


@pytest.mark.parametrize(
    "sink",
    [
        "res.status(500).send(`failed: ${e.message}`);",
        "res.status(500).send(`failed: ${ e }`);",
        # A quoted copy earlier on the line must not hide the real use or sink after it.
        "res.status(500).json({ a: 'e.message', b: e.stack });",
        "log('res.x'); res.status(500).json({ b: e.stack });",
    ],
)
def test_error_info_leak_js_real_sink_still_fires(tmp_path: Path, sink: str) -> None:
    findings = _run_js_catch(tmp_path, sink)
    assert [f.rule for f in findings] == ["error-info-leak/exception-in-http-response"]


def test_error_info_leak_js_catch_in_a_string_is_not_a_catch(tmp_path: Path) -> None:
    handler = _JS_CATCH_HANDLER.replace("} catch (e) {", "} finally { log('catch (e) {'); }")
    assert _run_js_catch(tmp_path, "res.status(500).json({ error: e.message });", handler) == []


def test_error_info_leak_js_quoted_catch_does_not_shadow_the_real_one(tmp_path: Path) -> None:
    # `.search` took the quoted `catch (e)` first, bound `e`, and missed the real `err` use.
    handler = _JS_CATCH_HANDLER.replace(
        "} catch (e) {", "} finally { log('catch (e) {'); } try { x(); } catch (err) {"
    )
    findings = _run_js_catch(tmp_path, "res.status(500).json({ error: err.message });", handler)
    assert [f.rule for f in findings] == ["error-info-leak/exception-in-http-response"]


def test_error_info_leak_js_pragma_still_suppresses_a_code_anchored_leak(tmp_path: Path) -> None:
    sink = "res.status(500).send(`failed: ${e.message}`);"
    # Both directions (PR #1131 round-1 L1): the shape fires without the pragma, so the silence below
    # is the pragma's doing.
    assert len(_run_js_catch(tmp_path, sink, _JS_CATCH_HANDLER)) == 1
    handler = "// security: allow-detailed-errors\n" + _JS_CATCH_HANDLER
    assert _run_js_catch(tmp_path, sink, handler) == []
