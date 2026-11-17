from __future__ import annotations

from agentsec.guards.websocket_origin import WebsocketOriginGuard
from tests.guards._common import *  # noqa: F401,F403


def test_websocket_origin_fires_no_check(tmp_path: Path) -> None:
    (tmp_path / "ws.py").write_text(
        "from fastapi import WebSocket\n"
        "async def endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi", "python"}, python_dirs=["."])
    findings = WebsocketOriginGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "websocket-origin/accept-without-origin-check"
    assert findings[0].severity == "high"
    assert "OWASP:A01" in findings[0].standards
    assert "CWE-346" in findings[0].standards

def test_websocket_origin_fires_no_check_sync(tmp_path: Path) -> None:
    (tmp_path / "ws.py").write_text(
        "from fastapi import WebSocket\n"
        "def endpoint(websocket: WebSocket):\n"
        "    websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = WebsocketOriginGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "websocket-origin/accept-without-origin-check"

def test_websocket_origin_silent_with_origin_variable(tmp_path: Path) -> None:
    (tmp_path / "ws.py").write_text(
        "from fastapi import WebSocket\n"
        "async def endpoint(websocket: WebSocket):\n"
        '    origin = websocket.headers.get("origin")\n'
        "    if origin not in ALLOWED_ORIGINS:\n"
        "        await websocket.close(code=1008)\n"
        "        return\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi", "python"}, python_dirs=["."])
    findings = WebsocketOriginGuard().run(tmp_path, profile)
    assert findings == []

def test_websocket_origin_silent_with_headers_bracket(tmp_path: Path) -> None:
    (tmp_path / "ws.py").write_text(
        "from fastapi import WebSocket\n"
        "async def endpoint(websocket: WebSocket):\n"
        '    origin = websocket.headers["origin"]\n'
        "    if origin not in ALLOWED:\n"
        "        return\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"}, python_dirs=["."])
    findings = WebsocketOriginGuard().run(tmp_path, profile)
    assert findings == []

def test_websocket_origin_fires_when_only_original_substring_present(tmp_path: Path) -> None:
    # H9 (FN): a bare "origin" substring must not count as an origin check — a handler
    # whose only pre-accept line is `original_state = ...` has NO validation and must fire.
    (tmp_path / "ws.py").write_text(
        "from fastapi import WebSocket\n"
        "async def endpoint(websocket: WebSocket):\n"
        "    original_state = load_original_state()\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi", "python"}, python_dirs=["."])
    findings = WebsocketOriginGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "websocket-origin/accept-without-origin-check"

def test_websocket_origin_silent_with_snakecase_origin_check(tmp_path: Path) -> None:
    # H-1 (FP fix): snake_case / constant origin checks must NOT fire — `validate_origin`,
    # `check_origin`, `origin_header`, `ALLOWED_ORIGINS` are the dominant Python convention.
    # \borigin\b wrongly rejected them (it treats `_` as a word char); origin(?![a-rt-z]) fixes it.
    for body in (
        "    if not validate_origin(websocket):\n        return\n",
        "    check_origin(websocket)\n",
        '    if websocket.headers.get("x") not in ALLOWED_ORIGINS:\n        return\n',
        "    origin_header = websocket.headers.get('sec-websocket-origin')\n"
        "    if origin_header not in ALLOWED:\n        return\n",
    ):
        (tmp_path / "ws.py").write_text(
            "from fastapi import WebSocket\n"
            "async def endpoint(websocket: WebSocket):\n"
            f"{body}"
            "    await websocket.accept()\n",
            encoding="utf-8",
        )
        profile = mkprofile(tmp_path, features={"fastapi", "python"}, python_dirs=["."])
        assert WebsocketOriginGuard().run(tmp_path, profile) == [], body

def test_websocket_origin_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "ws.py").write_text(
        "# security: allow-websocket-no-origin\n"
        "from fastapi import WebSocket\n"
        "async def endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi", "python"}, python_dirs=["."])
    findings = WebsocketOriginGuard().run(tmp_path, profile)
    assert findings == []

def test_websocket_origin_silent_when_check_outside_old_fixed_window(tmp_path: Path) -> None:
    # the origin check sits well past the old 10-line look-back but is still inside
    # the SAME enclosing function. Before this fix, the padding below would have pushed the
    # check out of the window and made the guard false-fire on genuinely safe code.
    padding = "\n".join(f"    log.info('setup step {n}')" for n in range(15))
    (tmp_path / "ws.py").write_text(
        "from fastapi import WebSocket\n"
        "async def endpoint(websocket: WebSocket):\n"
        '    origin = websocket.headers.get("origin")\n'
        "    if origin not in ALLOWED_ORIGINS:\n"
        "        await websocket.close(code=1008)\n"
        "        return\n"
        f"{padding}\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi", "python"}, python_dirs=["."])
    assert WebsocketOriginGuard().run(tmp_path, profile) == []


def test_websocket_origin_still_fires_when_check_is_after_accept(tmp_path: Path) -> None:
    # Directionality regression guard: an origin check performed AFTER accept() has already run
    # is too late — the widened look-back must stay look-BACK only, never search forward.
    (tmp_path / "ws.py").write_text(
        "from fastapi import WebSocket\n"
        "async def endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n"
        '    origin = websocket.headers.get("origin")\n'
        "    if origin not in ALLOWED_ORIGINS:\n"
        "        await websocket.close(code=1008)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi", "python"}, python_dirs=["."])
    findings = WebsocketOriginGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "websocket-origin/accept-without-origin-check"


def test_websocket_origin_module_level_call_still_uses_window_fallback(tmp_path: Path) -> None:
    # A call with no enclosing function (module-level script code) must still fall back to the
    # original fixed window, not silently stop scanning.
    (tmp_path / "ws.py").write_text(
        "from fastapi import WebSocket\n"
        "websocket = get_ws()\n"
        "websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi", "python"}, python_dirs=["."])
    findings = WebsocketOriginGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "websocket-origin/accept-without-origin-check"


def test_websocket_origin_applies_python_feature(tmp_path: Path) -> None:
    guard = WebsocketOriginGuard()
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"fastapi"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"fastapi", "python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"react", "supabase"})) is False


def test_websocket_origin_silent_on_nonproduct_path(tmp_path: Path) -> None:
    # Corpus-scan FP: `fastapi/fastapi`'s own `docs_src/` tutorials (already in the
    # shared `is_nonproduct_path` list) over-fired this guard — never called before this fix.
    d = tmp_path / "docs_src"
    d.mkdir()
    (d / "ws.py").write_text(
        "from fastapi import WebSocket\n"
        "async def endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi", "python"}, python_dirs=["."])
    assert WebsocketOriginGuard().run(tmp_path, profile) == []


def test_websocket_origin_still_fires_at_a_normal_path(tmp_path: Path) -> None:
    # Direction traded against (CLAUDE.md rule 1): a sibling non-product directory must not
    # silence the same violation shape at an ordinary path.
    (tmp_path / "docs_src").mkdir()
    (tmp_path / "docs_src" / "ws.py").write_text(
        "from fastapi import WebSocket\n"
        "async def endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from fastapi import WebSocket\n"
        "async def endpoint(websocket: WebSocket):\n"
        "    await websocket.accept()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi", "python"}, python_dirs=["."])
    findings = WebsocketOriginGuard().run(tmp_path, profile)
    assert any(f.location.startswith("app.py") for f in findings)
    assert not any(f.location.startswith("docs_src") for f in findings)

