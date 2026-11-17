from __future__ import annotations

from agentsec.guards.unauthenticated_file_download import UnauthenticatedFileDownloadGuard
from tests.guards._common import *  # noqa: F401,F403


def test_unauthenticated_file_download_fires_on_fileresponse(tmp_path: Path) -> None:
    (tmp_path / "exports.py").write_text(
        "@router.get('/exports/{export_id}')\n"
        "def download_export(export_id: str):\n"
        "    path = get_export_path(export_id)\n"
        "    return FileResponse(path)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    findings = UnauthenticatedFileDownloadGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "unauthenticated-file-download/no-auth-signal"
    assert findings[0].severity == "high"


def test_unauthenticated_file_download_fires_on_streamingresponse(tmp_path: Path) -> None:
    # The second FastAPI file sink (StreamingResponse). Flask's send_file/send_from_directory were
    # dropped in #307 — unreachable under the fastapi-only applies() gate.
    (tmp_path / "files.py").write_text(
        "@app.get('/files/{filename}')\n"
        "def get_file(filename: str):\n"
        "    return StreamingResponse(open(f'/data/{filename}', 'rb'))\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    findings = UnauthenticatedFileDownloadGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_unauthenticated_file_download_fires_with_only_a_db_dependency(tmp_path: Path) -> None:
    # Regression (#307): a bare non-auth `Depends(get_db)` must NOT be read as an auth signal — a
    # realistic download route with only a DB session and no auth must still fire.
    (tmp_path / "exports.py").write_text(
        "@router.get('/exports/{export_id}')\n"
        "def download(export_id: str, db: Session = Depends(get_db)):\n"
        "    return FileResponse(get_path(db, export_id))\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    findings = UnauthenticatedFileDownloadGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "unauthenticated-file-download/no-auth-signal"


def test_unauthenticated_file_download_silent_with_auth_dependency(tmp_path: Path) -> None:
    # FP-bait: an auth dependency is wired in — must stay silent.
    (tmp_path / "exports.py").write_text(
        "@router.get('/exports/{export_id}')\n"
        "def download_export(export_id: str, current_user=Depends(get_current_user)):\n"
        "    path = get_export_path(export_id)\n"
        "    return FileResponse(path)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert UnauthenticatedFileDownloadGuard().run(tmp_path, profile) == []


def test_unauthenticated_file_download_silent_with_security_scheme_class(tmp_path: Path) -> None:
    # fix-round review, Medium: the router-level checks already recognized
    # `Depends(HTTPBearer())` via `AUTH_CALL_NAMED`, but the per-route signal was still built from
    # the narrower `AUTH_DEP_SIGNAL` directly, so this route-level shape was missed.
    (tmp_path / "exports.py").write_text(
        "@router.get('/exports/{export_id}')\n"
        "def download_export(export_id: str, creds=Depends(HTTPBearer())):\n"
        "    path = get_export_path(export_id)\n"
        "    return FileResponse(path)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert UnauthenticatedFileDownloadGuard().run(tmp_path, profile) == []


def test_unauthenticated_file_download_fires_with_disabled_scheme_multiline(tmp_path: Path) -> None:
    # (Dean, review): a `Depends(HTTPBearer(auto_error=False))` scheme does not
    # enforce, so a route relying only on it is still unauthenticated -- and the original
    # bounded-lookahead exclusion could not see `auto_error=False` on a LATER line of a
    # multi-line constructor call, so it silently read the disabled scheme as real auth.
    (tmp_path / "exports.py").write_text(
        "@router.get('/exports/{export_id}')\n"
        "def download_export(export_id: str, creds=Depends(HTTPBearer(\n"
        "    auto_error=False,\n"
        "))):\n"
        "    path = get_export_path(export_id)\n"
        "    return FileResponse(path)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    findings = UnauthenticatedFileDownloadGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "unauthenticated-file-download/no-auth-signal"


def test_unauthenticated_file_download_silent_when_the_scheme_only_mentions_auto_error(tmp_path: Path) -> None:
    # #764 FP-bait: this scheme ENFORCES; the flag is only named in a comment warning against it.
    # The raw-span search blanked it, so the authenticated download fired. Inline shape only:
    # this guard does not resolve variable-bound scheme aliases (a documented, separate gap).
    (tmp_path / "exports.py").write_text(
        "@router.get('/exports/{export_id}')\n"
        "def download_export(export_id: str, creds=Depends(HTTPBearer(  # do NOT set auto_error=False\n"
        "))):\n"
        "    path = get_export_path(export_id)\n"
        "    return FileResponse(path)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert UnauthenticatedFileDownloadGuard().run(tmp_path, profile) == []


def test_unauthenticated_file_download_fires_with_disabled_scheme_behind_a_comment(tmp_path: Path) -> None:
    # #764, the direction traded against: a comment line ahead of a REAL `auto_error=False` must
    # not make the disabled scheme read as auth.
    (tmp_path / "exports.py").write_text(
        "@router.get('/exports/{export_id}')\n"
        "def download_export(export_id: str, creds=Depends(HTTPBearer(\n"
        "    # optional: public exports\n"
        "    auto_error=False,\n"
        "))):\n"
        "    path = get_export_path(export_id)\n"
        "    return FileResponse(path)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    findings = UnauthenticatedFileDownloadGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "unauthenticated-file-download/no-auth-signal"


def test_unauthenticated_file_download_silent_no_id_in_path(tmp_path: Path) -> None:
    # FP-bait: a static route with no id/name path param is out of scope.
    (tmp_path / "static.py").write_text(
        "@router.get('/logo.png')\n"
        "def logo():\n"
        "    return FileResponse('/assets/logo.png')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert UnauthenticatedFileDownloadGuard().run(tmp_path, profile) == []


def test_unauthenticated_file_download_silent_no_file_sink(tmp_path: Path) -> None:
    # FP-bait: a normal JSON-returning route with an id param is bola's territory, not this guard's.
    (tmp_path / "users.py").write_text(
        "@router.get('/users/{user_id}')\n"
        "def get_user(user_id: str):\n"
        "    return db.query(User).get(user_id)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert UnauthenticatedFileDownloadGuard().run(tmp_path, profile) == []


def test_unauthenticated_file_download_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "exports.py").write_text(
        "@router.get('/exports/{export_id}')\n"
        "def download_export(export_id: str):\n"
        "    # security: allow-unauthenticated-file-download\n"
        "    path = get_export_path(export_id)\n"
        "    return FileResponse(path)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert UnauthenticatedFileDownloadGuard().run(tmp_path, profile) == []


def test_unauthenticated_file_download_not_applies_without_fastapi(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"})
    assert UnauthenticatedFileDownloadGuard().applies(profile) is False


def test_unauthenticated_file_download_fires_on_multiline_decorator(tmp_path: Path) -> None:
    # Regression (#302 review): a multi-line route decorator — the common FastAPI shape with
    # response_class=/status_code= kwargs — must still be seen as a file-serving route.
    (tmp_path / "exports.py").write_text(
        "@router.get(\n"
        "    '/exports/{export_id}',\n"
        "    response_class=FileResponse,\n"
        ")\n"
        "def download_export(export_id: str):\n"
        "    path = get_export_path(export_id)\n"
        "    return FileResponse(path)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    findings = UnauthenticatedFileDownloadGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "unauthenticated-file-download/no-auth-signal"


def test_unauthenticated_file_download_silent_on_docstring_mention(tmp_path: Path) -> None:
    # Regression (#302 review): a docstring/example merely mentioning `FileResponse(...)` must
    # not fire (iter_functions blanks triple-quoted strings before the scan).
    (tmp_path / "exports.py").write_text(
        "@router.get('/exports/{export_id}')\n"
        "def describe_export(export_id: str):\n"
        '    """Return metadata. The download route uses FileResponse(path) elsewhere."""\n'
        "    return {'id': export_id}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert UnauthenticatedFileDownloadGuard().run(tmp_path, profile) == []


def test_unauthenticated_file_download_silent_with_aliased_auth_dependency(tmp_path: Path) -> None:
    # Regression (#307 flagship): a real admin log-stream route is auth-gated via a DI alias
    # (`_admin = AdminReadDep`), not an inline Depends() — must stay silent.
    (tmp_path / "logs.py").write_text(
        "@router.get('/api/admin/logs/{service}')\n"
        "def stream_logs(service: str, _admin=AdminReadDep):\n"
        "    return StreamingResponse(_log_stream(service))\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert UnauthenticatedFileDownloadGuard().run(tmp_path, profile) == []


def test_unauthenticated_file_download_silent_with_403_check(tmp_path: Path) -> None:
    # FP-bait: no Depends() but an explicit 403 path is present — treated as reviewed.
    (tmp_path / "exports.py").write_text(
        "@router.get('/exports/{export_id}')\n"
        "def download_export(export_id: str, request: Request):\n"
        "    if not is_valid_session(request):\n"
        "        raise HTTPException(403)\n"
        "    path = get_export_path(export_id)\n"
        "    return FileResponse(path)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert UnauthenticatedFileDownloadGuard().run(tmp_path, profile) == []


def test_unauthenticated_file_download_ignores_body_fstring_brace_on_query_route(tmp_path: Path) -> None:
    # Regression (#307 Medium): a `{...}` in a body f-string must NOT satisfy the "URL path
    # parameter" precondition. This route takes only a query param (no `{...}` in the decorator URL),
    # so it is out of scope even though its body builds a filename with an f-string brace.
    (tmp_path / "exports.py").write_text(
        "@router.get('/report')\n"
        "def report(name: str):\n"
        "    return FileResponse(f'reports/report_{name}.pdf')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert UnauthenticatedFileDownloadGuard().run(tmp_path, profile) == []


# --- Cross-file router-level auth resolution (backlog #3b) -------------------------------------

def _dl_rules(tmp_path: Path) -> set[str]:
    profile = mkprofile(tmp_path, features={"fastapi"})
    return {f.rule for f in UnauthenticatedFileDownloadGuard().run(tmp_path, profile)}


def test_cross_file_include_with_auth_dep_suppresses_download_route(tmp_path: Path) -> None:
    # A bare `router = APIRouter()` download route in routes/exports.py, authed cross-file by
    # main.py's `include_router(exports.router, dependencies=[Depends(get_current_user)])`.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "exports.py").write_text(
        "from fastapi import APIRouter\n"
        "from fastapi.responses import FileResponse\n"
        "router = APIRouter()\n"
        "\n"
        "@router.get('/exports/{export_id}')\n"
        "def download(export_id: str):\n"
        "    return FileResponse(get_export_path(export_id))\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import exports\n"
        "app = FastAPI()\n"
        "app.include_router(exports.router, dependencies=[Depends(get_current_user)])\n",
        encoding="utf-8",
    )
    assert "unauthenticated-file-download/no-auth-signal" not in _dl_rules(tmp_path)


def test_cross_file_include_with_variable_auth_dep_suppresses(tmp_path: Path) -> None:
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "exports.py").write_text(
        "from fastapi import APIRouter\n"
        "from fastapi.responses import FileResponse\n"
        "router = APIRouter()\n"
        "\n"
        "@router.get('/exports/{export_id}')\n"
        "def download(export_id: str):\n"
        "    return FileResponse(get_export_path(export_id))\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import exports\n"
        "app = FastAPI()\n"
        "_auth = [Depends(get_current_user)]\n"
        "app.include_router(exports.router, dependencies=_auth)\n",
        encoding="utf-8",
    )
    assert "unauthenticated-file-download/no-auth-signal" not in _dl_rules(tmp_path)


def test_cross_file_include_without_deps_still_fires(tmp_path: Path) -> None:
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "exports.py").write_text(
        "from fastapi import APIRouter\n"
        "from fastapi.responses import FileResponse\n"
        "router = APIRouter()\n"
        "\n"
        "@router.get('/exports/{export_id}')\n"
        "def download(export_id: str):\n"
        "    return FileResponse(get_export_path(export_id))\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from routes import exports\n"
        "app = FastAPI()\n"
        "app.include_router(exports.router, prefix='/api')\n",
        encoding="utf-8",
    )
    assert "unauthenticated-file-download/no-auth-signal" in _dl_rules(tmp_path)


def test_cross_file_protection_is_stem_specific(tmp_path: Path) -> None:
    # Protecting exports.router must NOT suppress an unrelated, unprotected public.py download route.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "exports.py").write_text(
        "from fastapi import APIRouter\n"
        "from fastapi.responses import FileResponse\n"
        "router = APIRouter()\n"
        "@router.get('/exports/{export_id}')\n"
        "def dl(export_id: str):\n    return FileResponse(get_path(export_id))\n",
        encoding="utf-8",
    )
    (tmp_path / "routes" / "public.py").write_text(
        "from fastapi import APIRouter\n"
        "from fastapi.responses import FileResponse\n"
        "router = APIRouter()\n"
        "@router.get('/public/{doc_id}')\n"
        "def pub(doc_id: str):\n    return FileResponse(get_path(doc_id))\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import exports, public\n"
        "app = FastAPI()\n"
        "app.include_router(exports.router, dependencies=[Depends(get_current_user)])\n"
        "app.include_router(public.router)\n",
        encoding="utf-8",
    )
    findings = [
        f for f in UnauthenticatedFileDownloadGuard().run(tmp_path, mkprofile(tmp_path, features={"fastapi"}))
        if f.rule == "unauthenticated-file-download/no-auth-signal"
    ]
    assert len(findings) == 1 and "public.py" in findings[0].location


def test_router_level_non_auth_db_dependency_still_fires(tmp_path: Path) -> None:
    # Issue #307 at the ROUTER level: a bare `Depends(get_db)` router-level dependency is NOT auth,
    # so a download route on that router must STILL fire. Regression for the #3b review — the shared
    # resolver must use AUTH_CALL_NAMED here.
    (tmp_path / "exports.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi.responses import FileResponse\n"
        "router = APIRouter(dependencies=[Depends(get_db)])\n"
        "\n"
        "@router.get('/exports/{export_id}')\n"
        "def download(export_id: str):\n"
        "    return FileResponse(get_export_path(export_id))\n",
        encoding="utf-8",
    )
    assert "unauthenticated-file-download/no-auth-signal" in _dl_rules(tmp_path)


def test_cross_file_include_with_non_auth_db_dependency_still_fires(tmp_path: Path) -> None:
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "exports.py").write_text(
        "from fastapi import APIRouter\n"
        "from fastapi.responses import FileResponse\n"
        "router = APIRouter()\n"
        "@router.get('/exports/{export_id}')\n"
        "def download(export_id: str):\n    return FileResponse(get_export_path(export_id))\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import exports\n"
        "app = FastAPI()\n"
        "app.include_router(exports.router, dependencies=[Depends(get_db)])\n",
        encoding="utf-8",
    )
    assert "unauthenticated-file-download/no-auth-signal" in _dl_rules(tmp_path)


def test_cross_file_protection_is_per_router_not_whole_file(tmp_path: Path) -> None:
    # #473 HIGH 1: two routers in one module, only `admin_router` mounted with auth. The
    # resolver used to mark the whole `exports` STEM protected, silencing the unauthenticated
    # download on the sibling router. Protection is per-router: this must still fire.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "exports.py").write_text(
        "from fastapi import APIRouter\n"
        "from fastapi.responses import FileResponse\n"
        "admin_router = APIRouter()\n"
        "public_router = APIRouter()\n"
        "\n"
        "@public_router.get('/exports/{export_id}')\n"
        "def download(export_id: str):\n"
        "    return FileResponse(get_export_path(export_id))\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import exports\n"
        "app = FastAPI()\n"
        "app.include_router(exports.admin_router, dependencies=[Depends(get_current_user)])\n"
        "app.include_router(exports.public_router)\n",
        encoding="utf-8",
    )
    assert "unauthenticated-file-download/no-auth-signal" in _dl_rules(tmp_path)


def test_cross_file_protection_applies_to_the_named_router(tmp_path: Path) -> None:
    # Pair to the above: the download route sits on the router that IS mounted with auth,
    # so per-router resolution must still suppress.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "exports.py").write_text(
        "from fastapi import APIRouter\n"
        "from fastapi.responses import FileResponse\n"
        "admin_router = APIRouter()\n"
        "public_router = APIRouter()\n"
        "\n"
        "@admin_router.get('/exports/{export_id}')\n"
        "def download(export_id: str):\n"
        "    return FileResponse(get_export_path(export_id))\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import exports\n"
        "app = FastAPI()\n"
        "app.include_router(exports.admin_router, dependencies=[Depends(get_current_user)])\n"
        "app.include_router(exports.public_router)\n",
        encoding="utf-8",
    )
    assert "unauthenticated-file-download/no-auth-signal" not in _dl_rules(tmp_path)


def test_unauthenticated_download_factory_registered_route_reports_once(tmp_path: Path) -> None:
    # Issue #502: the factory's block contains the nested route's decorator, so `_ROUTE_PATH`
    # matched the factory too and one route was reported twice.
    (tmp_path / "files.py").write_text(
        "from fastapi import APIRouter\n"
        "from fastapi.responses import FileResponse\n"
        "def make_router():\n"
        "    router = APIRouter()\n"
        "    @router.get('/files/{name}')\n"
        "    def download(name: str):\n"
        "        return FileResponse(f'/data/{name}')\n"
        "    return router\n",
        encoding="utf-8",
    )
    findings = UnauthenticatedFileDownloadGuard().run(tmp_path, mkprofile(tmp_path, features={"fastapi"}))
    assert len(findings) == 1
    assert findings[0].location.endswith(":6")     # the route, not the factory at :3

def test_unauthenticated_download_factory_registered_authed_route_silent(tmp_path: Path) -> None:
    # FP-bait: a factory-registered download route that DOES carry an auth dependency stays silent.
    (tmp_path / "files.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi.responses import FileResponse\n"
        "def make_router():\n"
        "    router = APIRouter()\n"
        "    @router.get('/files/{name}')\n"
        "    def download(name: str, user=Depends(get_current_user)):\n"
        "        return FileResponse(f'/data/{name}')\n"
        "    return router\n",
        encoding="utf-8",
    )
    assert UnauthenticatedFileDownloadGuard().run(tmp_path, mkprofile(tmp_path, features={"fastapi"})) == []


def test_unauthenticated_file_download_nested_sibling_route_does_not_cover_the_outer(
    tmp_path: Path,
) -> None:
    # Rule 1 lock on the WIDENING #502's fix causes (#605 gate, Medium-1). The inner route's auth
    # used to leak into the outer's scanned block, so an unauthenticated file download reported
    # nothing. Measured origin/main -> 0 findings, HEAD -> 1 at the outer.
    (tmp_path / "files.py").write_text(
        "@app.get('/files/{filename}')\n"
        "def get_file_outer(filename: str):\n"
        "    @app.get('/other/{filename}')\n"
        "    def get_file_inner(filename: str, user=Depends(get_current_user)):\n"
        "        return FileResponse(f'/data/{filename}')\n"
        "    return FileResponse(f'/data/{filename}')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    findings = UnauthenticatedFileDownloadGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].location.endswith(":2")     # the OUTER route


def test_unauthenticated_file_download_outer_route_auth_does_not_cover_a_nested_sibling(
    tmp_path: Path,
) -> None:
    # FP-bait mirror: auth on the outer, and the finding lands on the inner that really has none.
    (tmp_path / "files.py").write_text(
        "@app.get('/files/{filename}')\n"
        "def get_file_outer(filename: str, user=Depends(get_current_user)):\n"
        "    @app.get('/other/{filename}')\n"
        "    def get_file_inner(filename: str):\n"
        "        return FileResponse(f'/data/{filename}')\n"
        "    return FileResponse(f'/data/{filename}')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    findings = UnauthenticatedFileDownloadGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].location.endswith(":4")     # the INNER route


# --- #872: per-route `dependencies=[<bare factory()>]` (the #859 shape, in this guard) -------------
# A returns-nothing auth guard attached un-wrapped in the route's own `dependencies=[...]` is real
# auth, but `_AUTH_SIGNAL` only knows the `Depends()`/`Security()`-wrapped shapes, so a correctly
# authed download route fired HIGH. The guard now reads the decorator's own list through the same
# scoped reader as `auth-dependency-not-applied` (`route_deps_carry_auth` + the curated
# `PER_ROUTE_AUTH_FACTORY`). Each silent case below has a still-fires partner (Rule 1).

_DL_RULE = "unauthenticated-file-download/no-auth-signal"


def _dl_findings(tmp_path: Path) -> list[str]:
    findings = UnauthenticatedFileDownloadGuard().run(tmp_path, mkprofile(tmp_path, features={"fastapi"}))
    return [f.location for f in findings if f.rule == _DL_RULE]


def test_fp_bait_per_route_bare_auth_factory_dependency(tmp_path: Path) -> None:
    """The issue's repro (the fix): a bare auth factory in the route's own `dependencies=[...]`, plain
    and module-qualified, is recognized as auth and the route stays silent."""
    (tmp_path / "exports.py").write_text(
        "from fastapi import APIRouter\n"
        "from .security import auth as _auth, requires_authenticated\n"
        "router = APIRouter()\n"
        "\n"
        "@router.get('/exports/{export_id}', dependencies=[requires_authenticated()])\n"
        "def download_export(export_id: str):\n"
        "    return FileResponse(get_export_path(export_id))\n"
        "\n"
        "@router.get('/reports/{report_id}', dependencies=[_auth.requires_authenticated()])\n"
        "def download_report(report_id: str):\n"
        "    return FileResponse(get_report_path(report_id))\n",
        encoding="utf-8",
    )
    assert _dl_findings(tmp_path) == []


def test_fp_bait_per_route_bare_auth_factory_alongside_a_non_auth_dependency(tmp_path: Path) -> None:
    """The realistic shape: a multi-line decorator carrying an ordinary comment, a non-auth dep
    FIRST and the factory SECOND. Pins that the whole list is read and that comment-blanking does not
    eat the live auth or shift the decorator offset (`<open>` group)."""
    (tmp_path / "exports.py").write_text(
        "@router.get(\n"
        "    '/exports/{export_id}',  # signed exports only\n"
        "    dependencies=[get_db(), requires_authenticated()],\n"
        ")\n"
        "def download_export(export_id: str):\n"
        "    return FileResponse(get_export_path(export_id))\n",
        encoding="utf-8",
    )
    assert _dl_findings(tmp_path) == []


def test_fires_when_per_route_dependency_is_a_bare_non_auth_call(tmp_path: Path) -> None:
    """The direction traded against (Rule 1): a bare non-auth call in the same slot
    carries no curated auth stem, so BOTH routes still fire."""
    (tmp_path / "exports.py").write_text(
        "@router.get('/exports/{export_id}', dependencies=[get_db()])\n"
        "def download_export(export_id: str):\n"
        "    return FileResponse(get_export_path(export_id))\n"
        "\n"
        "@router.get('/reports/{report_id}', dependencies=[RateLimiter(times=5, seconds=60)])\n"
        "def download_report(report_id: str):\n"
        "    return FileResponse(get_report_path(report_id))\n",
        encoding="utf-8",
    )
    assert len(_dl_findings(tmp_path)) == 2


def test_commented_out_per_route_deps_does_not_exempt(tmp_path: Path) -> None:
    """Dead text (#532 / #871): a COMMENTED-OUT factory above the route's live `[get_db()]` must not
    fake protection. A false negative here would pass an unauthenticated download route."""
    (tmp_path / "exports.py").write_text(
        "@router.get(\n"
        "    '/exports/{export_id}',\n"
        "    # dependencies=[requires_authenticated()],  # removed during a refactor\n"
        "    dependencies=[get_db()],\n"
        ")\n"
        "def download_export(export_id: str):\n"
        "    return FileResponse(get_export_path(export_id))\n",
        encoding="utf-8",
    )
    assert len(_dl_findings(tmp_path)) == 1


def test_per_route_bare_auth_factory_recognition_is_scoped_to_the_deps_list(tmp_path: Path) -> None:
    """Scoping: the bare-name match counts only INSIDE the decorator's list. The factory
    CALLED in a handler body is not an applied dependency, so that route still fires, and the
    authed sibling in the same file resolves on its own."""
    (tmp_path / "exports.py").write_text(
        "@router.get('/exports/{export_id}', dependencies=[requires_authenticated()])\n"
        "def download_export(export_id: str):\n"
        "    return FileResponse(get_export_path(export_id))\n"
        "\n"
        "@router.get('/reports/{report_id}')\n"
        "def download_report(report_id: str):\n"
        "    requires_authenticated()  # called, never applied as a dependency\n"
        "    return FileResponse(get_report_path(report_id))\n",
        encoding="utf-8",
    )
    assert _dl_findings(tmp_path) == ["exports.py:6"]  # download_report's `def` line


def test_unauthenticated_file_download_pragma_quoted_in_a_string_in_the_route_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string in the route block is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-unauthenticated-file-download"):
        (tmp_path / "exports.py").write_text(
            "@router.get('/exports/{export_id}')\n"
            "def download_export(export_id: str):\n"
            f'    _note = "{note}"\n'
            "    path = get_export_path(export_id)\n"
            "    return FileResponse(path)\n",
            encoding="utf-8",
        )
        profile = mkprofile(tmp_path, features={"fastapi"})
        assert len(UnauthenticatedFileDownloadGuard().run(tmp_path, profile)) == 1, note
