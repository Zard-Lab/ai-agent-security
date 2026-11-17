from __future__ import annotations

from agentsec.guards.security_headers import SecurityHeadersGuard
from tests.guards._common import *  # noqa: F401,F403


def test_security_headers_flags_missing_middleware(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n", encoding="utf-8"
    )
    findings = SecurityHeadersGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "security-headers/no-security-headers-middleware"
    assert findings[0].severity == "low"

def test_security_headers_silent_when_headers_set(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.middleware.base import BaseHTTPMiddleware\n"
        "app = FastAPI()\n"
        "\n"
        "\n"
        "class HeadersMiddleware(BaseHTTPMiddleware):\n"
        "    async def dispatch(self, request, call_next):\n"
        "        resp = await call_next(request)\n"
        '        resp.headers["Strict-Transport-Security"] = "max-age=63072000"\n'
        "        return resp\n", encoding="utf-8"
    )
    assert SecurityHeadersGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_security_headers_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()  # security: allow-missing-security-headers\n", encoding="utf-8"
    )
    assert SecurityHeadersGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_security_headers_not_applicable_without_fastapi() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert SecurityHeadersGuard().applies(prof) is False

def test_security_headers_silent_when_fastapi_only_in_docs_src(tmp_path: Path) -> None:
    # FastAPI() only in a docs_src/ tutorial file — library/framework repo, not a product app.
    docs = tmp_path / "docs_src"
    docs.mkdir()
    (docs / "tutorial.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    assert SecurityHeadersGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_security_headers_silent_when_fastapi_only_in_tests(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    assert SecurityHeadersGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

