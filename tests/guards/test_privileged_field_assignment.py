from __future__ import annotations

import pytest

from agentsec.guards.privileged_field_assignment import PrivilegedFieldAssignmentGuard
from tests.guards._common import *  # noqa: F401,F403


def test_privileged_field_assignment_fires_on_role_copy(tmp_path: Path) -> None:
    (tmp_path / "users.py").write_text(
        "@router.post('/users/{user_id}')\n"
        "def promote(user_id: str, body: UpdateUserRequest):\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n"
        "    db.commit()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    findings = PrivilegedFieldAssignmentGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "privileged-field-assignment/unchecked-privilege-write"
    assert findings[0].severity == "critical"


def test_privileged_field_assignment_fires_on_setattr_is_admin(tmp_path: Path) -> None:
    (tmp_path / "accounts.py").write_text(
        "@app.put('/accounts/{id}')\n"
        "def update_account(id: str, payload: AccountUpdate):\n"
        "    acct = get_account(id)\n"
        "    setattr(acct, 'is_admin', payload.is_admin)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    findings = PrivilegedFieldAssignmentGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert "is_admin" in findings[0].message


def test_privileged_field_assignment_fires_with_only_a_db_dependency(tmp_path: Path) -> None:
    # Regression (#307): a bare non-auth `Depends(get_db)` must NOT suppress — a privileged-field
    # write whose only dependency is a DB session and has no privilege check must still fire.
    (tmp_path / "users.py").write_text(
        "@router.post('/users/{user_id}')\n"
        "def promote(user_id: str, body: UpdateUserRequest, db=Depends(get_db)):\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    findings = PrivilegedFieldAssignmentGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "privileged-field-assignment/unchecked-privilege-write"


def test_privileged_field_assignment_silent_with_privilege_check(tmp_path: Path) -> None:
    # FP-bait: the caller's own privilege IS checked before the write — must stay silent.
    (tmp_path / "users.py").write_text(
        "@router.post('/users/{user_id}')\n"
        "def promote(user_id: str, body: UpdateUserRequest, current_user=Depends(get_current_user)):\n"
        "    if not current_user.is_admin:\n"
        "        raise HTTPException(403)\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert PrivilegedFieldAssignmentGuard().run(tmp_path, profile) == []


def test_privileged_field_assignment_silent_on_unrelated_field(tmp_path: Path) -> None:
    # FP-bait: a normal, non-privileged field copy must not fire.
    (tmp_path / "users.py").write_text(
        "@router.post('/users/{user_id}')\n"
        "def update_name(user_id: str, body: UpdateUserRequest):\n"
        "    user = get_user(user_id)\n"
        "    user.name = body.name\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert PrivilegedFieldAssignmentGuard().run(tmp_path, profile) == []


def test_privileged_field_assignment_silent_on_mass_assignment_shape(tmp_path: Path) -> None:
    # Scope-partition FP-bait: a full-dict splat is `mass-assignment`'s pattern, not this
    # guard's — this guard requires a NAMED field-to-field copy.
    (tmp_path / "users.py").write_text(
        "@router.post('/users/{user_id}')\n"
        "def update_user(user_id: str, body: UpdateUserRequest):\n"
        "    for field, value in body.dict().items():\n"
        "        setattr(user, field, value)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert PrivilegedFieldAssignmentGuard().run(tmp_path, profile) == []


def test_privileged_field_assignment_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "users.py").write_text(
        "@router.post('/users/{user_id}')\n"
        "def promote(user_id: str, body: UpdateUserRequest):\n"
        "    # security: allow-privileged-field-assignment\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert PrivilegedFieldAssignmentGuard().run(tmp_path, profile) == []


def test_privileged_field_assignment_not_applies_without_fastapi(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"})
    assert PrivilegedFieldAssignmentGuard().applies(profile) is False


def test_privileged_field_assignment_fires_on_multiline_decorator(tmp_path: Path) -> None:
    # Regression (#301 review): a multi-line route decorator — the common FastAPI shape with
    # status_code=/response_model= kwargs — must still be seen as a state-changing route.
    (tmp_path / "users.py").write_text(
        "@router.post(\n"
        "    '/users/{user_id}',\n"
        "    status_code=201,\n"
        ")\n"
        "def promote(user_id: str, body: UpdateUserRequest):\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    findings = PrivilegedFieldAssignmentGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "privileged-field-assignment/unchecked-privilege-write"


def test_privileged_field_assignment_silent_on_docstring_mention(tmp_path: Path) -> None:
    # Regression (#301 review): a docstring/example merely MENTIONING the pattern must not fire
    # (iter_functions blanks triple-quoted strings before the scan).
    (tmp_path / "users.py").write_text(
        "@router.post('/users/{user_id}')\n"
        "def promote(user_id: str, body: UpdateUserRequest):\n"
        '    """Update a user. Never write user.role = body.role without an admin check."""\n'
        "    user = get_user(user_id)\n"
        "    user.name = body.name\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert PrivilegedFieldAssignmentGuard().run(tmp_path, profile) == []


def test_privileged_field_assignment_silent_get_route(tmp_path: Path) -> None:
    # Not a state-changing route — GET handlers are out of scope for this guard.
    (tmp_path / "users.py").write_text(
        "@router.get('/users/{user_id}')\n"
        "def read_user(user_id: str, body: UpdateUserRequest):\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    assert PrivilegedFieldAssignmentGuard().run(tmp_path, profile) == []


# --- Cross-file router-level auth resolution (backlog #3b) -------------------------------------

def _pfa_rules(tmp_path: Path) -> set[str]:
    profile = mkprofile(tmp_path, features={"fastapi"})
    return {f.rule for f in PrivilegedFieldAssignmentGuard().run(tmp_path, profile)}


_RULE = "privileged-field-assignment/unchecked-privilege-write"


def test_cross_file_include_with_admin_dep_suppresses(tmp_path: Path) -> None:
    # A privileged-field write in routes/admin.py, gated cross-file by main.py's
    # `include_router(admin.router, dependencies=[Depends(require_admin)])`.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/users/{uid}')\n"
        "def update_user(uid: int, body: UserIn):\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "app = FastAPI()\n"
        "app.include_router(admin.router, dependencies=[Depends(require_admin)])\n",
        encoding="utf-8",
    )
    assert _RULE not in _pfa_rules(tmp_path)


def test_cross_file_include_with_variable_admin_dep_suppresses(tmp_path: Path) -> None:
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/users/{uid}')\n"
        "def update_user(uid: int, body: UserIn):\n"
        "    setattr(user, 'is_admin', body.is_admin)\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "app = FastAPI()\n"
        "_admin = [Depends(require_admin)]\n"
        "app.include_router(admin.router, dependencies=_admin)\n",
        encoding="utf-8",
    )
    assert _RULE not in _pfa_rules(tmp_path)


def test_cross_file_include_without_deps_still_fires(tmp_path: Path) -> None:
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/users/{uid}')\n"
        "def update_user(uid: int, body: UserIn):\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from routes import admin\n"
        "app = FastAPI()\n"
        "app.include_router(admin.router, prefix='/api')\n",
        encoding="utf-8",
    )
    assert _RULE in _pfa_rules(tmp_path)


def test_cross_file_protection_is_stem_specific(tmp_path: Path) -> None:
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.post('/a/{uid}')\ndef a(uid: int, body: UserIn):\n    user.role = body.role\n",
        encoding="utf-8",
    )
    (tmp_path / "routes" / "public.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.post('/p/{uid}')\ndef p(uid: int, body: UserIn):\n    acct.is_admin = body.is_admin\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin, public\n"
        "app = FastAPI()\n"
        "app.include_router(admin.router, dependencies=[Depends(require_admin)])\n"
        "app.include_router(public.router)\n",
        encoding="utf-8",
    )
    findings = [
        f for f in PrivilegedFieldAssignmentGuard().run(tmp_path, mkprofile(tmp_path, features={"fastapi"}))
        if f.rule == _RULE
    ]
    assert len(findings) == 1 and "public.py" in findings[0].location


def test_router_level_non_auth_db_dependency_still_fires(tmp_path: Path) -> None:
    # Issue #307 at the ROUTER level: a bare `Depends(get_db)` router-level dependency is NOT auth,
    # so a privileged-field write on that router must STILL fire (mirrors the function-level #307
    # test). Regression for the #3b review — the shared resolver must use AUTH_CALL_NAMED here.
    (tmp_path / "admin.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter(dependencies=[Depends(get_db)])\n"
        "\n"
        "@router.post('/users/{uid}')\n"
        "def set_role(uid: int, body: UserIn):\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    assert _RULE in _pfa_rules(tmp_path)


def test_cross_file_include_with_non_auth_db_dependency_still_fires(tmp_path: Path) -> None:
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.post('/users/{uid}')\ndef set_role(uid: int, body: UserIn):\n    user.role = body.role\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "app = FastAPI()\n"
        "app.include_router(admin.router, dependencies=[Depends(get_db)])\n",
        encoding="utf-8",
    )
    assert _RULE in _pfa_rules(tmp_path)


def test_cross_file_protection_is_per_router_not_whole_file(tmp_path: Path) -> None:
    # #473 HIGH 1: two routers in ONE module — `admin_router` mounted WITH auth,
    # `public_router` mounted WITHOUT. The cross-file resolver used to mark the whole
    # `admin` STEM protected, so the authed sibling silenced a CRITICAL privileged-field
    # write on the unauthed router. Protection is per-router: this must still fire.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\n"
        "admin_router = APIRouter()\n"
        "public_router = APIRouter()\n"
        "\n"
        "@public_router.post('/users/{uid}')\n"
        "def update_user(uid: int, body: UserIn):\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "app = FastAPI()\n"
        "app.include_router(admin.admin_router, dependencies=[Depends(require_admin)])\n"
        "app.include_router(admin.public_router)\n",
        encoding="utf-8",
    )
    assert _RULE in _pfa_rules(tmp_path)


def test_cross_file_protection_applies_to_the_named_router(tmp_path: Path) -> None:
    # The other half of the pair: same two-router module, but the router the route is
    # actually ON is the one mounted with auth. Per-router resolution must still SUPPRESS —
    # narrowing to per-router must not degrade into "cross-file auth never counts".
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\n"
        "admin_router = APIRouter()\n"
        "public_router = APIRouter()\n"
        "\n"
        "@admin_router.post('/users/{uid}')\n"
        "def update_user(uid: int, body: UserIn):\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "app = FastAPI()\n"
        "app.include_router(admin.admin_router, dependencies=[Depends(require_admin)])\n"
        "app.include_router(admin.public_router)\n",
        encoding="utf-8",
    )
    assert _RULE not in _pfa_rules(tmp_path)


# --- #473 review §2: protection must be unconditional and unambiguous --------------------------

_ADMIN_ROUTE = (
    "from fastapi import APIRouter\n"
    "router = APIRouter()\n"
    "\n"
    "@router.post('/users/{uid}')\n"
    "def update_user(uid: int, body: UserIn):\n"
    "    user.role = body.role\n"
)


def test_dual_mount_with_a_bare_include_still_fires(tmp_path: Path) -> None:
    # The same router mounted twice — once with auth, once bare. Every route stays reachable
    # unauthenticated through the bare mount, so the authed mount is not protection.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(_ADMIN_ROUTE, encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "app = FastAPI()\n"
        "app.include_router(admin.router, dependencies=[Depends(require_admin)])\n"
        "app.include_router(admin.router, prefix='/public')\n",
        encoding="utf-8",
    )
    assert _RULE in _pfa_rules(tmp_path)


def test_conditional_mount_is_not_protection(tmp_path: Path) -> None:
    # `if settings.ENABLE_AUTH:` — flip the setting and the routes are exposed, so a mount that
    # is not guaranteed to run cannot silence a CRITICAL privilege write.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(_ADMIN_ROUTE, encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "app = FastAPI()\n"
        "if settings.ENABLE_AUTH:\n"
        "    app.include_router(admin.router, dependencies=[Depends(require_admin)])\n"
        "else:\n"
        "    app.include_router(admin.router)\n",
        encoding="utf-8",
    )
    assert _RULE in _pfa_rules(tmp_path)


def test_unconditional_single_mount_still_suppresses(tmp_path: Path) -> None:
    # Control for the two above: one unconditional authed mount must still suppress, so the
    # narrowing can't collapse into "cross-file auth never counts".
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(_ADMIN_ROUTE, encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "app = FastAPI()\n"
        "app.include_router(admin.router, dependencies=[Depends(require_admin)])\n",
        encoding="utf-8",
    )
    assert _RULE not in _pfa_rules(tmp_path)


def test_authentication_only_router_dep_does_not_suppress(tmp_path: Path) -> None:
    # `Depends(get_current_user)` proves the caller is logged in, not that they may WRITE a role.
    # This guard is about privilege escalation, so only a privilege-checking dependency counts —
    # the same reasoning that kept `bola` out of the router-level work.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(_ADMIN_ROUTE, encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "app = FastAPI()\n"
        "app.include_router(admin.router, dependencies=[Depends(get_current_user)])\n",
        encoding="utf-8",
    )
    assert _RULE in _pfa_rules(tmp_path)


def test_feature_flagged_router_construction_still_fires(tmp_path: Path) -> None:
    # The constructor half of "protection must be UNCONDITIONAL" (#473 full gate), asserted on the
    # finding rather than on the resolver: a router BUILT under an auth feature flag, with the
    # else-branch rebinding the same name to a bare router, protects nothing when the flag is off.
    # The include spelling of exactly this was already caught; the construction spelling returned
    # zero findings for a CRITICAL `user.role = body.role` write.
    (tmp_path / "admin.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "if settings.ENABLE_ADMIN_AUTH:\n"
        "    router = APIRouter(dependencies=[Depends(require_admin)])\n"
        "else:\n"
        "    router = APIRouter()\n"
        "\n"
        "@router.post('/users/{uid}')\n"
        "def update_user(uid: int, body: UserIn):\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    assert _RULE in _pfa_rules(tmp_path)


def test_unconditional_router_construction_still_suppresses(tmp_path: Path) -> None:
    # THE DIRECTION TRADED AGAINST for the test above. The ordinary module-level construction is
    # the common case and must keep suppressing, or the narrowing would have turned every
    # router-level admin dependency into a false positive.
    (tmp_path / "admin.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter(dependencies=[Depends(require_admin)])\n"
        "\n"
        "@router.post('/users/{uid}')\n"
        "def update_user(uid: int, body: UserIn):\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    assert _pfa_rules(tmp_path) == set()


def test_stem_collision_drops_protection_for_both_modules(tmp_path: Path) -> None:
    # Two product modules named admin.py. The resolver keys on the file STEM, so it cannot tell
    # which one `admin.router` refers to — an authed mount of one would silence the other. An
    # ambiguous stem is dropped entirely, so BOTH still fire.
    (tmp_path / "routes").mkdir()
    (tmp_path / "v2").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(_ADMIN_ROUTE, encoding="utf-8")
    (tmp_path / "v2" / "admin.py").write_text(_ADMIN_ROUTE, encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "app = FastAPI()\n"
        "app.include_router(admin.router, dependencies=[Depends(require_admin)])\n",
        encoding="utf-8",
    )
    locations = {
        f.location.split(":")[0]
        for f in PrivilegedFieldAssignmentGuard().run(tmp_path, mkprofile(tmp_path, features={"fastapi"}))
    }
    assert locations == {str(Path("routes") / "admin.py"), str(Path("v2") / "admin.py")}


def test_same_file_dual_mount_with_a_bare_include_still_fires(tmp_path: Path) -> None:
    # Same rule one file down: a same-file authed include is undone by a second bare include of
    # the same router. (A router-level dep on the CONSTRUCTOR is not — FastAPI applies those on
    # every mount, so no later include can undo them; covered by the construct-deps tests.)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends, FastAPI\n"
        "router = APIRouter()\n"
        "app = FastAPI()\n"
        "\n"
        "@router.post('/users/{uid}')\n"
        "def update_user(uid: int, body: UserIn):\n"
        "    user.role = body.role\n"
        "\n"
        "app.include_router(router, dependencies=[Depends(require_admin)])\n"
        "app.include_router(router, prefix='/public')\n",
        encoding="utf-8",
    )
    assert _RULE in _pfa_rules(tmp_path)


def test_privileged_field_factory_registered_route_reports_once(tmp_path: Path) -> None:
    # Issue #502: the factory's block contains the nested route's decorator, so `_ROUTE_DECORATOR`
    # matched the factory too and one route was reported twice — at CRITICAL, on a `def` that is
    # not a route.
    (tmp_path / "users.py").write_text(
        "def make_router():\n"
        "    router = APIRouter()\n"
        "    @router.post('/users/{user_id}')\n"
        "    def promote(user_id: str, body: UpdateUserRequest):\n"
        "        user = get_user(user_id)\n"
        "        user.role = body.role\n"
        "        db.commit()\n"
        "    return router\n",
        encoding="utf-8",
    )
    findings = PrivilegedFieldAssignmentGuard().run(tmp_path, mkprofile(tmp_path, features={"fastapi"}))
    assert len(findings) == 1
    assert findings[0].location.endswith(":4")     # the route, not the factory at :1

def test_privileged_field_factory_registered_checked_route_silent(tmp_path: Path) -> None:
    # FP-bait: a factory-registered route whose privileged write IS admin-checked stays silent.
    (tmp_path / "users.py").write_text(
        "def make_router():\n"
        "    router = APIRouter()\n"
        "    @router.post('/users/{user_id}')\n"
        "    def promote(user_id: str, body: UpdateUserRequest, admin=Depends(require_admin)):\n"
        "        user = get_user(user_id)\n"
        "        user.role = body.role\n"
        "        db.commit()\n"
        "    return router\n",
        encoding="utf-8",
    )
    assert PrivilegedFieldAssignmentGuard().run(tmp_path, mkprofile(tmp_path, features={"fastapi"})) == []


def test_privileged_field_assignment_nested_sibling_route_does_not_cover_the_outer(
    tmp_path: Path,
) -> None:
    # Rule 1 lock on the WIDENING #502's fix causes (#605 gate, Medium-1). Same shape as the
    # auth-dependency lock: the inner route's `Depends(...)` used to sit inside the outer's scanned
    # block and read as the outer's own auth, hiding a real privileged-field write.
    # Measured origin/main -> 0 findings, HEAD -> 1 at the outer.
    (tmp_path / "accounts.py").write_text(
        "@app.put('/accounts/{id}')\n"
        "def update_outer(id: str, payload: AccountUpdate):\n"
        "    @app.put('/other/{id}')\n"
        "    def update_inner(id: str, payload: AccountUpdate, user=Depends(get_current_user)):\n"
        "        return None\n"
        "    acct = get_account(id)\n"
        "    acct.is_admin = payload.is_admin\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    findings = PrivilegedFieldAssignmentGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert "is_admin" in findings[0].message


def test_privileged_field_assignment_outer_route_auth_does_not_cover_a_nested_sibling(
    tmp_path: Path,
) -> None:
    # FP-bait mirror: with the auth on the outer and the privileged write on the INNER, the inner
    # is still reported. Pins that the blanking did not start moving findings around.
    (tmp_path / "accounts.py").write_text(
        "@app.put('/accounts/{id}')\n"
        "def update_outer(id: str, payload: AccountUpdate, user=Depends(get_current_user)):\n"
        "    @app.put('/other/{id}')\n"
        "    def update_inner(id: str, payload: AccountUpdate):\n"
        "        acct = get_account(id)\n"
        "        acct.is_admin = payload.is_admin\n"
        "    return None\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"})
    findings = PrivilegedFieldAssignmentGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert "is_admin" in findings[0].message


# --- #872: per-route `dependencies=[<bare factory()>]` (the #859 shape, in this guard) -------------
# A returns-nothing PRIVILEGE guard attached un-wrapped in the route's own `dependencies=[...]` is a
# real privilege check, but `_AUTH_SIGNAL` only knew the wrapped shapes plus two literal names, so
# `requires_system_write_role()` fired CRITICAL while `require_admin()` passed by accident. The guard
# now reads the decorator's list with the PRIVILEGE matcher (`PER_ROUTE_PRIV_FACTORY`): the list
# entry's return value is discarded, so the handler cannot check privilege itself and the slot is
# held to the router level's standard. Each silent case has a still-fires partner (Rule 1).


def _pfa_findings(tmp_path: Path) -> list[str]:
    findings = PrivilegedFieldAssignmentGuard().run(tmp_path, mkprofile(tmp_path, features={"fastapi"}))
    return [f.location for f in findings if f.rule == _RULE]


def test_fp_bait_per_route_bare_privilege_factory_dependency(tmp_path: Path) -> None:
    """The issue's repro (the fix): a bare privilege factory in the route's own deps list, including
    the `requires_admin()` spelling the old literal `require_admin` substring missed by one letter."""
    (tmp_path / "users.py").write_text(
        "@router.post('/users/{user_id}', dependencies=[requires_system_write_role()])\n"
        "def update_user(user_id: str, body: UserUpdate):\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n"
        "\n"
        "@router.patch('/accounts/{account_id}', dependencies=[_auth.requires_admin()])\n"
        "def update_account(account_id: str, payload: AccountUpdate):\n"
        "    acct = get_account(account_id)\n"
        "    setattr(acct, 'is_admin', payload.is_admin)\n",
        encoding="utf-8",
    )
    assert _pfa_findings(tmp_path) == []


def test_fp_bait_per_route_bare_privilege_factory_alongside_a_non_auth_dependency(tmp_path: Path) -> None:
    """The realistic shape: a multi-line decorator with an ordinary comment, a non-auth dep FIRST and
    the privilege factory SECOND. The whole list is read; the comment does not shift the offset."""
    (tmp_path / "users.py").write_text(
        "@router.put(\n"
        "    '/users/{user_id}',  # admin console only\n"
        "    dependencies=[get_db(), requires_admin()],\n"
        ")\n"
        "def update_user(user_id: str, body: UserUpdate):\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    assert _pfa_findings(tmp_path) == []


def test_fires_when_per_route_dependency_is_a_bare_non_auth_call(tmp_path: Path) -> None:
    """The direction traded against (Rule 1): a bare non-auth call in the deps list
    carries no privilege stem, so BOTH routes still fire CRITICAL."""
    (tmp_path / "users.py").write_text(
        "@router.post('/users/{user_id}', dependencies=[get_db()])\n"
        "def update_user(user_id: str, body: UserUpdate):\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n"
        "\n"
        "@router.put('/staff/{user_id}', dependencies=[RateLimiter(times=5, seconds=60)])\n"
        "def update_staff(user_id: str, body: UserUpdate):\n"
        "    user = get_user(user_id)\n"
        "    user.is_staff = body.is_staff\n",
        encoding="utf-8",
    )
    assert len(_pfa_findings(tmp_path)) == 2


def test_fires_when_per_route_dependency_is_authentication_only(tmp_path: Path) -> None:
    """The strictness choice (#872): an authentication-only factory proves the caller is logged in,
    not that they may grant a role. It must still fire, exactly as a router-level
    `Depends(get_current_user)` does (`test_authentication_only_router_dep_does_not_suppress`)."""
    (tmp_path / "users.py").write_text(
        "@router.post('/users/{user_id}', dependencies=[requires_authenticated()])\n"
        "def update_user(user_id: str, body: UserUpdate):\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    assert len(_pfa_findings(tmp_path)) == 1


def test_commented_out_per_route_deps_does_not_exempt(tmp_path: Path) -> None:
    """Dead text (#532 / #871): a COMMENTED-OUT privilege factory above the route's live
    `[get_db()]` must not fake protection. A false negative here is a CRITICAL escalation passed."""
    (tmp_path / "users.py").write_text(
        "@router.post(\n"
        "    '/users/{user_id}',\n"
        "    # dependencies=[requires_system_write_role()],  # removed during a refactor\n"
        "    dependencies=[get_db()],\n"
        ")\n"
        "def update_user(user_id: str, body: UserUpdate):\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    assert len(_pfa_findings(tmp_path)) == 1


def test_per_route_bare_privilege_factory_recognition_is_scoped_to_the_deps_list(tmp_path: Path) -> None:
    """Scoping: the factory CALLED in a handler body is not an applied dependency, so that
    route still fires, while the deps-list sibling in the same file stays silent on its own."""
    (tmp_path / "users.py").write_text(
        "@router.post('/users/{user_id}', dependencies=[requires_system_write_role()])\n"
        "def update_user(user_id: str, body: UserUpdate):\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n"
        "\n"
        "@router.post('/accounts/{user_id}')\n"
        "def update_account(user_id: str, body: UserUpdate):\n"
        "    requires_system_write_role()  # called, never applied as a dependency\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    assert _pfa_findings(tmp_path) == ["users.py:7"]  # update_account's `def` line


@pytest.mark.parametrize(
    "dep",
    [
        "log_admin_access()",
        "audit_role_change()",
        "RoleCache()",
        "get_scope_filter()",
        "get_permissions_cache()",
        "track_permission_use()",
        "load_staff_directory()",
        "_audit.log_superuser_action()",
    ],
)
def test_fires_when_per_route_dependency_only_names_a_privilege_noun(tmp_path: Path, dep: str) -> None:
    """#1041 round-1 review (R1-M1): a privilege WORD in a bare deps-list call is not a privilege
    CHECK. An audit, cache or lookup dependency that merely names `admin` / `role` / `scope` /
    `permission` / `staff` / `superuser` must not silence a CRITICAL escalation, so the bare
    privilege factory has to name a guard (a leading guard verb, or a `_required` / `_only`
    suffix), the way the curated #859 auth factory leaves out the ambiguous stems. Every one of
    these fired before #872 and must still fire."""
    (tmp_path / "users.py").write_text(
        f"@router.post('/users/{{user_id}}', dependencies=[{dep}])\n"
        "def update_user(user_id: str, body: UserUpdate):\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    assert _pfa_findings(tmp_path) == ["users.py:2"]


@pytest.mark.parametrize(
    "dep",
    [
        "requires_admin()",
        "_auth.requires_system_write_role()",
        "_requires_admin()",
        "require_role('admin')",
        "ensure_superuser()",
        "has_permission('users:write')",
        "check_scopes('users:admin')",
        "verify_admin()",
        "is_staff()",
        "enforce_role('admin')",
        "allow_roles(['admin'])",
        "admin_required()",
        "role_required('admin')",
        "staff_member_required()",
        "superuser_only()",
    ],
)
def test_fp_bait_per_route_bare_privilege_guard_spellings(tmp_path: Path, dep: str) -> None:
    """The direction R1-M1's tightening trades against (Rule 1): the guard-shaped privilege
    factories, a leading guard verb or a `_required` / `_only` suffix, keep the route silent,
    including a leading underscore and a dotted module prefix."""
    (tmp_path / "users.py").write_text(
        f"@router.post('/users/{{user_id}}', dependencies=[{dep}])\n"
        "def update_user(user_id: str, body: UserUpdate):\n"
        "    user = get_user(user_id)\n"
        "    user.role = body.role\n",
        encoding="utf-8",
    )
    assert _pfa_findings(tmp_path) == []


def test_privileged_field_assignment_pragma_quoted_in_a_string_in_the_route_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string in the route block is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-privileged-field-assignment"):
        (tmp_path / "users.py").write_text(
            "@router.post('/users/{user_id}')\n"
            "def promote(user_id: str, body: UpdateUserRequest):\n"
            f'    _note = "{note}"\n'
            "    user = get_user(user_id)\n"
            "    user.role = body.role\n",
            encoding="utf-8",
        )
        profile = mkprofile(tmp_path, features={"fastapi"})
        assert len(PrivilegedFieldAssignmentGuard().run(tmp_path, profile)) == 1, note
