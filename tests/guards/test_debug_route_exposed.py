from __future__ import annotations

from agentsec.guards.debug_route_exposed import DebugRouteExposedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_debug_route_exposed_flags_debug_segment(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        '@app.get("/debug/dump-config")\n'
        "def dump():\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = DebugRouteExposedGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "debug-route-exposed/debug-or-internal-path-segment"
    assert findings[0].severity == "medium"


def test_debug_route_exposed_flags_underscore_internal_prefix(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        '@router.post("/_internal/reset-cache")\n'
        "async def reset():\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = DebugRouteExposedGuard().run(tmp_path, profile)
    assert len(findings) >= 1


def test_debug_route_exposed_flags_whole_internal_segment(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        '@router.get("/internal/health")\n'
        "def health():\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = DebugRouteExposedGuard().run(tmp_path, profile)
    assert len(findings) >= 1


def test_debug_route_exposed_flags_legacy_hyphenated_compound(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        '@app.get("/legacy-api/v1/orders")\n'
        "def orders():\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = DebugRouteExposedGuard().run(tmp_path, profile)
    assert len(findings) >= 1


def test_debug_route_exposed_flags_dunder_debug(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        '@app.get("/__debug__/toolbar")\n'
        "def toolbar():\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = DebugRouteExposedGuard().run(tmp_path, profile)
    assert len(findings) >= 1


def test_debug_route_exposed_flags_websocket_decorator(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        '@app.websocket("/debug/ws")\n'
        "async def ws():\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = DebugRouteExposedGuard().run(tmp_path, profile)
    assert len(findings) >= 1


def test_debug_route_exposed_flags_multiline_decorator(tmp_path: Path) -> None:
    # Path literal on a continuation line — decorator has tags=/response_model= before
    # the closing paren, the shape real FastAPI route decorators routinely use.
    (tmp_path / "routes.py").write_text(
        "@app.get(\n"
        '    "/debug/dump",\n'
        '    tags=["debug"],\n'
        ")\n"
        "def dump():\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = DebugRouteExposedGuard().run(tmp_path, profile)
    assert len(findings) >= 1


def test_debug_route_exposed_silent_on_unrelated_path(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        '@app.get("/testimonials")\n'
        "def testimonials():\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert DebugRouteExposedGuard().run(tmp_path, profile) == []


def test_debug_route_exposed_silent_on_substring_without_boundary(tmp_path: Path) -> None:
    # "apiinternal" / "legacyimport" are single unbroken path words — no keyword TOKEN is
    # present, only a raw substring, which must not fire.
    (tmp_path / "main.py").write_text(
        '@app.get("/apiinternal")\n'
        "def a():\n"
        "    pass\n"
        '@app.get("/legacyimport")\n'
        "def b():\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert DebugRouteExposedGuard().run(tmp_path, profile) == []


def test_debug_route_exposed_silent_on_internal_business_compound(tmp_path: Path) -> None:
    # FP-bait: "internal_notes" is a legitimate CRM-style feature name, not a route naming
    # itself as internal-only. "internal" is strict-only (must be the WHOLE segment) so this
    # compound must stay silent — the exact false positive caught during adversarial testing.
    (tmp_path / "main.py").write_text(
        '@app.get("/users/{user_id}/internal_notes")\n'
        "def notes():\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert DebugRouteExposedGuard().run(tmp_path, profile) == []


def test_debug_route_exposed_pragma_silences(tmp_path: Path) -> None:
    content = (
        '@app.get("/debug/dump-config")\n'
        "def dump():\n"
        "    pass\n"
        "# security: allow-debug-route-exposed\n"
    )
    (tmp_path / "main.py").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert DebugRouteExposedGuard().run(tmp_path, profile) == []


def test_debug_route_exposed_not_fastapi(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert DebugRouteExposedGuard().applies(profile) is False


def test_debug_route_exposed_unbalanced_paren_in_string_does_not_spill(tmp_path: Path) -> None:
    # PR #452 review: an UNBALANCED `(` inside a decorator's description=/summary= string used to
    # throw off the raw paren count and let the fold spill into the NEXT decorator's path,
    # producing a misattributed duplicate (2 findings). String-aware counting yields exactly 1.
    (tmp_path / "main.py").write_text(
        '@app.get(\n'
        '    description="See (details",\n'
        ')\n'
        '@app.get("/debug/dump")\n'
        "def dump():\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = DebugRouteExposedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].location.endswith(":4")  # the real debug decorator, not the misattributed line 1


def test_debug_route_exposed_unbalanced_paren_in_triple_quoted_string_does_not_spill(tmp_path: Path) -> None:
    # PR #452 re-review: a TRIPLE-quoted (multi-line) description= kwarg with an unbalanced `(`
    # must also not spill — the fold blanks triple-quoted strings (strip_python_strings), not
    # just single-line ones.
    (tmp_path / "main.py").write_text(
        '@app.get(\n'
        '    description="""See (X\n'
        '    more details""",\n'
        ')\n'
        '@app.get("/debug/dump")\n'
        "def dump():\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = DebugRouteExposedGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].location.endswith(":5")


def test_debug_route_exposed_skips_nonproduct_path(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_routes.py").write_text(
        '@app.get("/debug/dump-config")\n'
        "def dump():\n"
        "    pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert DebugRouteExposedGuard().run(tmp_path, profile) == []


def test_debug_route_comment_paren_does_not_break_the_fold(tmp_path: Path) -> None:
    # Regression (#452 review): the continuation fold counted parens on a string-blanked but NOT
    # comment-stripped copy, so an unbalanced `(` inside a `#` comment in a wrapped decorator
    # threw the depth off and the route path was never matched.
    (tmp_path / "r.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.get(\n"
        "    # internal only (see RFC 7231 sec 4\n"
        "    '/debug/vars',\n"
        ")\n"
        "def dv(): return {}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert len(DebugRouteExposedGuard().run(tmp_path, profile)) == 1


def test_debug_route_pragma_is_still_honored(tmp_path: Path) -> None:
    # FP-bait: the pragma is ITSELF a comment, so comment-stripping the fold copy must not
    # break the suppression, which is read from the raw line.
    (tmp_path / "r.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n"
        "@router.get('/debug/vars')  # security: allow-debug-route-exposed\n"
        "def dv(): return {}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert DebugRouteExposedGuard().run(tmp_path, profile) == []
