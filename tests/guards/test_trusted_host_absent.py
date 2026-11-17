from __future__ import annotations

from agentsec.guards.trusted_host_absent import TrustedHostAbsentGuard
from tests.guards._common import *  # noqa: F401,F403


def test_trusted_host_absent_fires(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text('from fastapi import FastAPI\napp = FastAPI()\n', encoding="utf-8")
    findings = TrustedHostAbsentGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "trusted-host-absent/no-trusted-host-middleware"
    assert findings[0].severity == "medium"

def test_trusted_host_absent_middleware_present_silent(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text('from fastapi import FastAPI\napp = FastAPI()\n', encoding="utf-8")
    (tmp_path / "middleware.py").write_text('from starlette.middleware.trustedhost import TrustedHostMiddleware\n', encoding="utf-8")
    assert TrustedHostAbsentGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_trusted_host_absent_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        '# security: allow-no-trusted-host\nfrom fastapi import FastAPI\napp = FastAPI()\n',
        encoding="utf-8",
    )
    assert TrustedHostAbsentGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_trusted_host_absent_no_app_silent(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text('from fastapi import APIRouter\nrouter = APIRouter()\n', encoding="utf-8")
    assert TrustedHostAbsentGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_trusted_host_absent_silent_when_app_only_in_tests(tmp_path: Path) -> None:
    # app = FastAPI() only in a test mock server — library repo, not a product app.
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "mock_server.py").write_text('from fastapi import FastAPI\napp = FastAPI()\n', encoding="utf-8")
    assert TrustedHostAbsentGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

def test_trusted_host_absent_silent_when_app_only_in_examples(tmp_path: Path) -> None:
    examples_dir = tmp_path / "examples"
    examples_dir.mkdir()
    (examples_dir / "demo.py").write_text('from fastapi import FastAPI\napp = FastAPI()\n', encoding="utf-8")
    assert TrustedHostAbsentGuard().run(tmp_path, _fastapi_nodirs_prof(tmp_path)) == []

