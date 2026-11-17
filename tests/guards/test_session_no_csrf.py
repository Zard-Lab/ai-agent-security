from __future__ import annotations

from agentsec.guards.session_no_csrf import SessionNoCsrfGuard
from tests.guards._common import *  # noqa: F401,F403


def test_session_no_csrf_fires(tmp_path: Path) -> None:
    # True positive: SessionMiddleware present, no CSRF protection anywhere.
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from starlette.middleware.sessions import SessionMiddleware\n"
        "app = FastAPI()\n"
        "SECRET_KEY = 'changeme'\n"
        "app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)\n",
        encoding="utf-8",
    )
    findings = SessionNoCsrfGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "session-no-csrf/session-middleware-without-csrf"
    assert findings[0].severity == "high"
    assert "main.py" in findings[0].location
    assert "OWASP:A01" in findings[0].standards
    assert "CWE-352" in findings[0].standards

def test_session_no_csrf_silent_csrf_present(tmp_path: Path) -> None:
    # False positive guard: SessionMiddleware in one file, CSRFMiddleware in another.
    (tmp_path / "main.py").write_text(
        "from starlette.middleware.sessions import SessionMiddleware\n"
        "app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)\n",
        encoding="utf-8",
    )
    (tmp_path / "middleware.py").write_text(
        "from starlette_csrf import CSRFMiddleware\n"
        "app.add_middleware(CSRFMiddleware)\n",
        encoding="utf-8",
    )
    assert SessionNoCsrfGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_session_no_csrf_pragma_silences(tmp_path: Path) -> None:
    # Pragma path: allow-no-csrf in any file silences the check repo-wide.
    (tmp_path / "main.py").write_text(
        "from starlette.middleware.sessions import SessionMiddleware\n"
        "app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)  # security: allow-no-csrf\n",
        encoding="utf-8",
    )
    assert SessionNoCsrfGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_session_no_csrf_applies_gate() -> None:
    # applies() returns False for a profile with no python/fastapi features.
    prof = mkprofile(Path("/tmp"), features={"frontend", "react"})
    assert SessionNoCsrfGuard().applies(prof) is False
    assert SessionNoCsrfGuard().run(Path("/tmp"), prof) == []

def test_session_no_csrf_no_session_silent(tmp_path: Path) -> None:
    # Baseline: no SessionMiddleware anywhere; guard stays silent.
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n",
        encoding="utf-8",
    )
    assert SessionNoCsrfGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_session_no_csrf_finding_location(tmp_path: Path) -> None:
    # Location in the emitted finding points to the file:line with SessionMiddleware.
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "app.add_middleware(SessionMiddleware, secret_key='sk')\n",
        encoding="utf-8",
    )
    findings = SessionNoCsrfGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location == "app.py:3"


# --- Express/JS (codeql js/missing-token-validation) ---

def test_session_no_csrf_applies_on_express() -> None:
    assert SessionNoCsrfGuard().applies(mkprofile(Path("/tmp"), features={"express"})) is True


def test_session_no_csrf_js_fires(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const session = require('express-session');\n"
        "app.use(session({ secret: 'changeme' }));\n",
        encoding="utf-8",
    )
    findings = SessionNoCsrfGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "session-no-csrf/session-middleware-without-csrf"
    assert findings[0].severity == "high"


def test_session_no_csrf_js_silent_csrf_present(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const session = require('express-session');\n"
        "app.use(session({ secret: 'changeme' }));\n",
        encoding="utf-8",
    )
    (tmp_path / "middleware.js").write_text(
        "const csurf = require('csurf');\n"
        "app.use(csurf());\n",
        encoding="utf-8",
    )
    assert SessionNoCsrfGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_session_no_csrf_js_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const session = require('express-session');  // security: allow-no-csrf\n"
        "app.use(session({ secret: 'changeme' }));\n",
        encoding="utf-8",
    )
    assert SessionNoCsrfGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_session_no_csrf_js_no_session_silent(tmp_path: Path) -> None:
    # FP-bait: an Express app with no session middleware at all has nothing to check.
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n",
        encoding="utf-8",
    )
    assert SessionNoCsrfGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []

