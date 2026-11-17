from __future__ import annotations

from agentsec.guards.header_injection import HeaderInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_direct_header_from_request_header(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "def h(response, request):\n"
        "    response.headers['X-Custom'] = request.headers['X-Injected']\n",
        encoding="utf-8",
    )
    findings = HeaderInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "header-injection/user-input-in-header"
    assert findings[0].severity == "medium"

def test_flags_header_from_query_params(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "def h(response, request):\n"
        "    response.headers['X-Trace'] = request.query_params['v']\n",
        encoding="utf-8",
    )
    assert len(HeaderInjectionGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_silent_when_newlines_stripped(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "def h(response, request):\n"
        "    response.headers['X-Custom'] = request.headers['X-Injected'].replace('\\n', '')\n",
        encoding="utf-8",
    )
    assert HeaderInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_silent_on_static_value(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "def h(response):\n"
        "    response.headers['X-Custom'] = 'static-value'\n",
        encoding="utf-8",
    )
    assert HeaderInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_silent_on_trusted_request_state(tmp_path: Path) -> None:
    # FP-bait (review #395 M finding): request.state/request.app are trusted, server-set
    # attributes, not attacker-controlled input.
    (tmp_path / "views.py").write_text(
        "def h(response, request):\n"
        "    response.headers['X-Trace'] = request.state.trace_id\n",
        encoding="utf-8",
    )
    assert HeaderInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_silent_on_trusted_request_app(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "def h(response, request):\n"
        "    response.headers['X-App-Version'] = request.app.version\n",
        encoding="utf-8",
    )
    assert HeaderInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_silent_on_read_direction(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "def h(request):\n"
        "    value = request.headers['X-User']\n"
        "    return value\n",
        encoding="utf-8",
    )
    assert HeaderInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "# security: allow-header-injection\n"
        "def h(response, request):\n"
        "    response.headers['X-Custom'] = request.headers['X-Injected']\n",
        encoding="utf-8",
    )
    assert HeaderInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_silent_on_outgoing_header_dict_value(tmp_path: Path) -> None:
    # #395 H3: a bare `headers[` on the RHS is an OUTGOING/default header dict, not a request
    # source — must not fire.
    (tmp_path / "views.py").write_text(
        "def h(response, other_response):\n"
        "    response.headers['X-Trace'] = other_response.headers['X-Trace']\n",
        encoding="utf-8",
    )
    assert HeaderInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_silent_on_len_wrapped_body(tmp_path: Path) -> None:
    # #395 H3: a `len(...)`-wrapped source is an int (no CRLF possible) — must not fire.
    (tmp_path / "views.py").write_text(
        "def h(response, body):\n"
        "    response.headers['Content-Length'] = str(len(body))\n",
        encoding="utf-8",
    )
    assert HeaderInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_silent_on_nested_len_call(tmp_path: Path) -> None:
    # #395 RL-2: `str(len(body()))` — a len(...) with a nested call — is still an int, must not fire.
    (tmp_path / "views.py").write_text(
        "def h(response, body):\n"
        "    response.headers['Content-Length'] = str(len(body()))\n",
        encoding="utf-8",
    )
    assert HeaderInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_fires_when_only_name_sanitized(tmp_path: Path) -> None:
    # #395 M5: sanitizing the header NAME must not be credited to the tainted VALUE.
    (tmp_path / "views.py").write_text(
        "def h(response, request):\n"
        "    response.headers[name.replace('\\n', '')] = request.headers['X-Injected']\n",
        encoding="utf-8",
    )
    assert len(HeaderInjectionGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_na_without_python() -> None:
    assert HeaderInjectionGuard().applies(mkprofile(Path("/tmp"), features={"frontend"})) is False
