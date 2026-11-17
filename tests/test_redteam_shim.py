"""Unit tests for the shipped generic red-team adapter (redteam-shim.py).

The shim is a scaffold installed into target repos (run via `uv run`, which pulls
fastapi/httpx). It is NOT part of the agentsec package, so we stub the web deps and
load it by path to test its pure request/response-translation logic.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from typing import Any

import pytest

_COMPONENTS = Path(__file__).resolve().parents[1] / "agentsec" / "ci" / "components"
_GARAK_SHIM = _COMPONENTS / "garak" / "files" / "scripts" / "redteam-shim.py"
_PROMPTFOO_SHIM = _COMPONENTS / "promptfoo" / "files" / "scripts" / "redteam-shim.py"


def _load_shim() -> Any:
    """Import redteam-shim.py with fastapi/httpx stubbed (so no web deps needed)."""
    fastapi = types.ModuleType("fastapi")

    class _App:
        def __init__(self, *a: Any, **k: Any) -> None: ...
        def get(self, *a: Any, **k: Any):  # noqa: ANN202
            return lambda f: f
        def post(self, *a: Any, **k: Any):  # noqa: ANN202
            return lambda f: f

    fastapi.FastAPI = _App  # type: ignore[attr-defined]
    fastapi.Request = object  # type: ignore[attr-defined]
    responses = types.ModuleType("fastapi.responses")
    responses.PlainTextResponse = object  # type: ignore[attr-defined]
    sys.modules.update({"fastapi": fastapi, "fastapi.responses": responses,
                        "httpx": types.ModuleType("httpx")})
    spec = importlib.util.spec_from_file_location("redteam_shim", _GARAK_SHIM)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


shim = _load_shim()


def test_components_ship_identical_shim() -> None:
    assert _GARAK_SHIM.read_bytes() == _PROMPTFOO_SHIM.read_bytes()


def test_extract_raw() -> None:
    assert shim.extract_reply("hello world", "raw") == "hello world"


def test_extract_json_path() -> None:
    body = '{"choices":[{"message":{"content":"hi there"}}]}'
    assert shim.extract_reply(body, "json:choices.0.message.content") == "hi there"


def test_extract_ndjson_complete_picks_final_chunk() -> None:
    stream = '\n'.join([
        '{"text":"par"}',
        '{"text":"partial answer"}',
        '{"text":"the full answer","complete":true}',
    ])
    assert shim.extract_reply(stream, "ndjson-complete:text") == "the full answer"


def test_extract_ndjson_complete_error_fallback() -> None:
    stream = '\n'.join(['{"text":"x"}', '{"text":"","error":"blocked","complete":true}'])
    assert shim.extract_reply(stream, "ndjson-complete:text") == "blocked"


def test_extract_ndjson_last_line() -> None:
    stream = '{"out":"a"}\n{"out":"b"}'
    assert shim.extract_reply(stream, "ndjson:out") == "b"


def test_build_body_raw_when_no_template() -> None:
    json_obj, raw = shim.build_body("attack", template="")
    assert json_obj is None and raw == "attack"


def test_build_body_renders_template_and_escapes_prompt() -> None:
    tmpl = '{"query":"{{prompt}}","request_id":"{{uuid}}","session_id":"{{uuid}}"}'
    obj, raw = shim.build_body('say "hi"\nnow', template=tmpl)
    assert raw is None
    assert obj["query"] == 'say "hi"\nnow'  # quotes + newline survive JSON round-trip
    # each {{uuid}} is a distinct value
    assert obj["request_id"] != obj["session_id"]


def test_interpolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHIM_X_TOKEN", "secret123")
    assert shim._interpolate_env("Bearer ${SHIM_X_TOKEN}") == "Bearer secret123"
    assert shim._interpolate_env("${SHIM_MISSING_VAR}") == ""
