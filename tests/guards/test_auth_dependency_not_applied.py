"""Tests for the auth-dependency-not-applied guard.

Covers:
  - auth-dependency-not-applied/no-auth-dependency (high)
"""
from __future__ import annotations

import pytest

from agentsec.guards.auth_dependency_not_applied import AuthDependencyNotAppliedGuard
from agentsec.guards.base import matching_close_paren
from tests.guards._common import *  # noqa: F401,F403


def _guard() -> AuthDependencyNotAppliedGuard:
    return AuthDependencyNotAppliedGuard()


def _fastapi_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"fastapi", "python"}, python_dirs=["."])


def test_applies_when_fastapi_feature_present() -> None:
    prof = mkprofile(Path("/tmp"), features={"fastapi", "python"})
    assert _guard().applies(prof) is True


def test_not_applies_without_fastapi_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert _guard().applies(prof) is False


def test_fires_on_state_changing_route_with_no_auth(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(user_id: int):\n"
        "    db.delete(user_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules
    assert findings[0].severity == "high"


def test_fp_bait_route_level_depends(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(user_id: int, current_user: User = Depends(get_current_user)):\n"
        "    db.delete(user_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_fp_bait_inline_httpbearer(tmp_path: Path) -> None:
    # `Depends(HTTPBearer())` used to read as unauthenticated — no `_AUTH_NAME` stem is
    # a substring of `HTTPBearer` (confirmed by reading `_AUTH_SEGMENT_STEMS`/`_AUTH_PREFIX_STEMS`
    # directly). Closed with a conservative allowlist of FastAPI's own security-scheme class
    # names, not a stem widening (`AUTH_CALL_NAMED`, base.py).
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi.security import HTTPBearer\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(user_id: int, creds=Depends(HTTPBearer())):\n"
        "    db.delete(user_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_fp_bait_module_level_security_scheme_var(tmp_path: Path) -> None:
    # the 2nd confirmed FN shape: the class name is instantiated once, at module level,
    # and referenced by variable name at the Depends() call site — the class name itself never
    # appears there. `security_scheme_var_names`/`auth_call_named_with_aliases` resolve it.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi.security import HTTPBearer\n"
        "router = APIRouter()\n"
        "bearer_scheme = HTTPBearer()\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(user_id: int, creds=Depends(bearer_scheme)):\n"
        "    db.delete(user_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_fires_when_alias_var_is_not_a_security_scheme(tmp_path: Path) -> None:
    # FP-bait for the alias resolver above: a module-level variable bound to something that is
    # NOT one of the closed security-scheme classes must not be mistaken for one just because its
    # name happens to be plausible-sounding — `security_scheme_var_names` is exact-class-matched,
    # not name-heuristic.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "bearer_scheme = get_db()\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(user_id: int, db=Depends(bearer_scheme)):\n"
        "    db.delete(user_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_alias_resolution_does_not_cross_files(tmp_path: Path) -> None:
    # fix-round review, Critical 1 shape (a): file_a.py legitimately binds
    # `bearer_scheme` to a real security scheme; file_b.py's OWN `bearer_scheme` is an unrelated
    # DB dependency, reused as a genuinely unauthenticated route's Depends() argument. The SAME
    # common variable name in two unrelated files must not let file_a's binding authorize
    # file_b's route — a stronger discriminator than a name that's never a scheme anywhere (which
    # would pass identically even with the whole alias feature deleted).
    (tmp_path / "file_a.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi.security import HTTPBearer\n"
        "bearer_scheme = HTTPBearer()\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/a/action')\n"
        "def action_a(item_id: int, creds=Depends(bearer_scheme)):\n"
        "    db.delete(item_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    (tmp_path / "file_b.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "bearer_scheme = get_db()\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(user_id: int, db=Depends(bearer_scheme)):\n"
        "    db.delete(user_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    locations = {f.location for f in findings}
    assert any("file_b.py" in loc for loc in locations), (
        "file_b's route uses its OWN non-scheme bearer_scheme and must still fire"
    )
    assert not any("file_a.py" in loc for loc in locations), (
        "file_a's route is genuinely authed and must stay silent"
    )


def test_fp_bait_auto_error_disabled_scheme_still_fires(tmp_path: Path) -> None:
    # fix-round review, Critical 2: `auto_error=False` is FastAPI's own idiom for "this
    # scheme does not enforce" — the dependency returns None instead of raising, so the route
    # stays unauthenticated. Both the inline and module-variable shapes must still fire.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi.security import HTTPBearer\n"
        "router = APIRouter()\n"
        "optional_scheme = HTTPBearer(auto_error=False)\n"
        "\n"
        "@router.post('/admin/delete-inline')\n"
        "def delete_inline(item_id: int, creds=Depends(HTTPBearer(auto_error=False))):\n"
        "    db.delete(item_id)\n"
        "    return {'status': 'deleted'}\n"
        "\n"
        "@router.post('/admin/delete-var')\n"
        "def delete_var(item_id: int, creds=Depends(optional_scheme)):\n"
        "    db.delete(item_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    locations = {f.location for f in findings}
    assert len(findings) == 2, f"expected both routes to fire, got: {locations}"


def test_fp_bait_auto_error_disabled_multiline_still_fires(tmp_path: Path) -> None:
    # (Dean, review): a bounded single-line lookahead cannot see auto_error on a LATER
    # line of a multi-line Depends(HTTPBearer(...)) call, or past a nested paren before it on the
    # same line — both shapes silently read as enforcing before this fix. Must still fire.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi.security import HTTPBearer\n"
        "router = APIRouter()\n"
        "optional_scheme = HTTPBearer(\n"
        "    auto_error=False,\n"
        ")\n"
        "\n"
        "@router.post('/admin/delete-multiline')\n"
        "def delete_multiline(item_id: int, creds=Depends(HTTPBearer(\n"
        "    auto_error=False,\n"
        "))):\n"
        "    db.delete(item_id)\n"
        "    return {'status': 'deleted'}\n"
        "\n"
        "@router.post('/admin/delete-nested-paren')\n"
        "def delete_nested(item_id: int, creds=Depends(HTTPBearer(scheme_name=str('x'), auto_error=False))):\n"
        "    db.delete(item_id)\n"
        "    return {'status': 'deleted'}\n"
        "\n"
        "@router.post('/admin/delete-var')\n"
        "def delete_var(item_id: int, creds=Depends(optional_scheme)):\n"
        "    db.delete(item_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    locations = {f.location for f in findings}
    assert len(findings) == 3, f"expected all 3 routes to fire, got: {locations}"


# An unclosed paren at EOF: the file has no token stream, so `blank_disabled_security_schemes`
# has no code view and takes its raw path (#764). The route regexes still read the file.
_UNTOKENIZABLE_TAIL = "\nlegacy_cfg = (\n"

# The trigger for an UNRESOLVABLE span on that raw path. Neither call walker knows `#`, so the
# apostrophe in the call's own comment opens a string the later quotes never balance. Before #613
# these tests used an odd quote inside a triple-quoted description, which the raw walk now reads
# as one span (`test_raw_path_stray_quote_*` below), so it resolves.
_COMMENT_APOSTROPHE = "  # the client's bearer token"


def _raw_scheme_span_is_unresolvable(app: Path) -> bool:
    """Precondition for the unresolvable-span tests: the first scheme's span really is unresolvable
    to the raw walk (Python mode, as `blank_disabled_security_schemes` runs it), so each test is on
    the arm it names rather than passing for some other reason."""
    text = app.read_text(encoding="utf-8")
    return matching_close_paren(text, text.index("HTTPBearer(") + len("HTTPBearer"), python=True) is None


def test_unresolvable_scheme_span_does_not_erase_later_routes(tmp_path: Path) -> None:
    # #761 review: when a security-scheme call's span cannot be resolved, the blanking pass used
    # to fall back to end-of-file. The auto_error search then covered the whole remainder of the
    # file and, on a hit anywhere in it, blanked from the constructor to EOF -- so every route
    # below vanished from the guard's view and NOTHING fired. A silent false negative, the same
    # direction this guard exists to close.
    #
    # Here `required_auth` is ENFORCING (no auto_error at all); the apostrophe in its comment
    # desyncs the shared quote tracking (`_COMMENT_APOSTROPHE`). The only disabled scheme is the
    # unrelated one on the last line before the tail.
    #
    # #764: the comment alone no longer leaves the span unresolvable, because a constructor in
    # tokenizable code is resolved on the code view with its comments blanked. The unclosed
    # `legacy_cfg = (` tail makes the file untokenizable, so the raw path this test is about runs.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi.security import HTTPBearer\n"
        "router = APIRouter()\n"
        f"required_auth = HTTPBearer({_COMMENT_APOSTROPHE}\n"
        '    description="""Bearer token. Press Authorize to continue.""",\n'
        ")\n"
        "\n"
        "@router.post('/admin/wipe')\n"
        "def wipe_everything():\n"
        "    db.wipe()\n"
        "    return {'status': 'wiped'}\n"
        "\n"
        "public_probe = HTTPBearer(auto_error=False)\n"
        f"{_UNTOKENIZABLE_TAIL}",
        encoding="utf-8",
    )
    assert _raw_scheme_span_is_unresolvable(tmp_path / "app.py")
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    locations = {f.location for f in findings}
    assert len(findings) == 1, f"the unauthed route must still be reported, got: {locations}"


def test_unresolvable_scheme_span_does_not_swallow_a_pragma(tmp_path: Path) -> None:
    # The same fallback also erased any inline pragma inside the blanked span. A suppression the
    # user wrote must keep working (CLAUDE.md Rule 4).
    #
    # Asserting only "pragma'd route stays silent" would prove NOTHING here: under the old
    # fallback the whole file was blanked, so that route was silent too, for the opposite reason.
    # So the file carries a SECOND unauthed route with no pragma. The pair is what discriminates:
    # one silent, one firing, means the file is genuinely visible and the pragma is what silenced
    # the first. Under the bug both vanish and the second assertion fails. The untokenizable tail
    # keeps the span on the raw path (#764), as in the test above.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi.security import HTTPBearer\n"
        "router = APIRouter()\n"
        f"required_auth = HTTPBearer({_COMMENT_APOSTROPHE}\n"
        '    description="""Bearer token. Press Authorize to continue.""",\n'
        ")\n"
        "\n"
        "@router.post('/admin/wipe')\n"
        "def wipe_everything():\n"
        "    # security: allow-unauthenticated-route\n"
        "    db.wipe()\n"
        "    return {'status': 'wiped'}\n"
        "\n"
        "@router.post('/admin/purge')\n"
        "def purge_everything():\n"
        "    db.purge()\n"
        "    return {'status': 'purged'}\n"
        "\n"
        "public_probe = HTTPBearer(auto_error=False)\n"
        f"{_UNTOKENIZABLE_TAIL}",
        encoding="utf-8",
    )
    assert _raw_scheme_span_is_unresolvable(tmp_path / "app.py")
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    locations = {f.location for f in findings}
    # The pragma'd route is silenced BY THE PRAGMA...
    assert not any("wipe_everything" in f.location for f in findings), locations
    # ...while its unpragma'd neighbour still fires, proving the file was never blanked away.
    assert len(findings) == 1, f"the unpragma'd route must still fire, got: {locations}"


def _scheme_app(
    tmp_path: Path,
    *,
    stray_quote: bool,
    disabled: bool,
    tokenizable: bool = True,
    comment_quote: bool = False,
) -> Path:
    # `bearer_scheme` deliberately carries NO auth stem (`auth|token|scope|role|user|...`), so the
    # security-scheme machinery is the ONLY thing that can make the route read as authenticated.
    # A name like `optional_auth` would match `_AUTH_NAME` directly and the fixture would prove
    # nothing about the blanking pass.
    #
    # `stray_quote` puts one odd quote in the triple-quoted description. Before #613 that desynced
    # the raw quote tracking; the raw walk now reads the description as one span, so it resolves.
    # `comment_quote` adds `_COMMENT_APOSTROPHE` to the call, which still desyncs the raw walk.
    # Since #764 either one matters only on the raw path, so pair it with `tokenizable=False`.
    desc = 'Press "Authorize' if stray_quote else "Press Authorize"
    flag = "    auto_error=False,\n" if disabled else ""
    comment = _COMMENT_APOSTROPHE if comment_quote else ""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi.security import HTTPBearer\n"
        "router = APIRouter()\n"
        f"bearer_scheme = HTTPBearer({comment}\n"
        f'    description="""Bearer. {desc} to sign in.""",\n'
        f"{flag}"
        ")\n"
        "\n"
        "@router.post('/admin/wipe')\n"
        "def wipe_everything(creds=Depends(bearer_scheme)):\n"
        "    db.wipe()\n"
        "    return {'status': 'wiped'}\n"
        f"{'' if tokenizable else _UNTOKENIZABLE_TAIL}",
        encoding="utf-8",
    )
    return tmp_path


def test_unresolvable_span_with_a_disabled_scheme_still_fires(tmp_path: Path) -> None:
    # THE point of the pass. `auto_error=False` returns None instead of raising 401, so this route
    # runs unauthenticated. Its span is unresolvable, and an earlier revision of this fix skipped
    # such calls entirely -- which left the disabled scheme in the text, reading as a proven auth
    # signal, and the guard went SILENT on a genuinely unauthenticated state-changing route
    # (#761 re-review). Blanking the constructor token is what closes it.
    root = _scheme_app(tmp_path, stray_quote=False, disabled=True, tokenizable=False, comment_quote=True)
    assert _raw_scheme_span_is_unresolvable(root / "app.py")
    findings = _guard().run(root, _fastapi_prof(root))
    assert len(findings) == 1, f"disabled scheme + unresolvable span must fire, got: {findings}"


def test_unresolvable_span_with_an_enforcing_scheme_also_fires_accepted_cost(tmp_path: Path) -> None:
    # The direction traded against, pinned so it is deliberate and visible rather than a surprise.
    # When the span cannot be resolved we cannot read `auto_error`, so an ENFORCING scheme is
    # treated as unproven too and its route surfaces. That is a false positive, and it is the
    # side this guard family chose in writing: "a false negative is worse than the residual false
    # positive ... which the pragma covers" (`_AUTH_DECORATOR` note), "over-firing is the safe
    # direction" (design docs). If this ever flips to silence, the disabled case above flips too.
    # Since #764 the cost is paid only on the raw path (a file the tokenizer rejects), and since
    # #613 only for a desync the raw walk still has: a quote in a comment, not in a triple-quoted
    # string (see the stray-quote tests below).
    root = _scheme_app(tmp_path, stray_quote=False, disabled=False, tokenizable=False, comment_quote=True)
    assert _raw_scheme_span_is_unresolvable(root / "app.py")
    findings = _guard().run(root, _fastapi_prof(root))
    assert len(findings) == 1, f"unresolvable span surfaces the route by design, got: {findings}"


def test_resolvable_span_with_an_enforcing_scheme_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the widening above: the ordinary case, where the span resolves and the scheme
    # enforces, must stay silent. If this fires, the widening has leaked past unresolvable spans
    # and every enforcing security scheme in the wild now over-reports.
    root = _scheme_app(tmp_path, stray_quote=False, disabled=False)
    assert _guard().run(root, _fastapi_prof(root)) == []


def test_resolvable_span_with_a_disabled_scheme_still_fires(tmp_path: Path) -> None:
    # the original case, unchanged by the re-review fix. Guards the blanking pass proper.
    root = _scheme_app(tmp_path, stray_quote=False, disabled=True)
    assert len(_guard().run(root, _fastapi_prof(root))) == 1


def test_stray_quote_in_a_tokenizable_file_no_longer_surfaces_an_enforcing_scheme(tmp_path: Path) -> None:
    # #764: in an ordinary (tokenizable) file the #613 stray quote is inside a string the code view
    # has blanked, so the span resolves and an ENFORCING scheme is read as the auth it is. Before
    # #764 this was the "accepted cost" false positive above, paid even when the file parsed.
    root = _scheme_app(tmp_path, stray_quote=True, disabled=False)
    assert _guard().run(root, _fastapi_prof(root)) == []


def test_stray_quote_in_a_tokenizable_file_still_fires_when_disabled(tmp_path: Path) -> None:
    # The direction traded against: resolving the span must not lose the disabled case. Under the
    # stray quote the scheme used to be caught by the token-only arm; it is now caught by its own
    # `auto_error=False` argument, and its route must still fire.
    root = _scheme_app(tmp_path, stray_quote=True, disabled=True)
    assert len(_guard().run(root, _fastapi_prof(root))) == 1


def test_raw_path_stray_quote_no_longer_surfaces_an_enforcing_scheme(tmp_path: Path) -> None:
    # #613, the raw path (no token stream, so no code view). The stray quote sits inside a
    # triple-quoted description, which the raw walk now reads as one span, so the span resolves
    # and the ENFORCING scheme reads as the auth it is. Before #613 this span was unresolvable and
    # the token-only arm surfaced the route: the "accepted cost" false positive above.
    root = _scheme_app(tmp_path, stray_quote=True, disabled=False, tokenizable=False)
    assert not _raw_scheme_span_is_unresolvable(root / "app.py")
    assert _guard().run(root, _fastapi_prof(root)) == []


def test_raw_path_stray_quote_still_fires_when_disabled(tmp_path: Path) -> None:
    # The direction traded against (Rule 1): resolving the raw span must not lose the disabled
    # case. The scheme is now caught by the `auto_error=False` inside its own span, not by the
    # token-only arm, and its route must still fire.
    root = _scheme_app(tmp_path, stray_quote=True, disabled=True, tokenizable=False)
    assert not _raw_scheme_span_is_unresolvable(root / "app.py")
    assert len(_guard().run(root, _fastapi_prof(root))) == 1


# #764: ENFORCING schemes whose argument span merely mentions the flag. Each was blanked by the
# raw-span search, so the guard reported a correctly authenticated route.
_SCHEME_MENTIONS_THE_FLAG = {
    "comment": "HTTPBearer(  # do NOT set auto_error=False here\n)",
    "apostrophe-comment": "HTTPBearer(  # don't set auto_error=False here\n)",
    "string": 'HTTPBearer(description="set auto_error=False for optional auth")',
    "nested-call": "HTTPBearer(scheme_name=describe(auto_error=False))",
}
# The direction traded against: a comment next to a REAL `auto_error=False`. The raw-text
# `split_call_args` fix suggested on #764 reads the leading-comment shape as enforcing (the comment
# and the kwarg are one argument), which silenced exactly this route.
_DISABLED_BEHIND_A_COMMENT = {
    "leading-comment": "HTTPBearer(\n    # optional auth for the public feed\n    auto_error=False,\n)",
    "apostrophe-comment": "HTTPBearer(  # don't require a token\n    auto_error=False)",
}


def _wipe_app(tmp_path: Path, scheme: str, *, inline: bool) -> Path:
    binding = "" if inline else f"bearer_scheme = {scheme}\n"
    dep = f"Depends({scheme})" if inline else "Depends(bearer_scheme)"
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi.security import HTTPBearer\n"
        "router = APIRouter()\n"
        f"{binding}"
        "\n"
        "@router.post('/admin/wipe')\n"
        f"def wipe_everything(creds={dep}):\n"
        "    db.wipe()\n"
        "    return {'status': 'wiped'}\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.mark.parametrize("inline", [False, True], ids=["variable", "inline"])
@pytest.mark.parametrize(
    "scheme", list(_SCHEME_MENTIONS_THE_FLAG.values()), ids=list(_SCHEME_MENTIONS_THE_FLAG)
)
def test_enforcing_scheme_that_mentions_auto_error_stays_silent(
    tmp_path: Path, scheme: str, inline: bool
) -> None:
    root = _wipe_app(tmp_path, scheme, inline=inline)
    assert _guard().run(root, _fastapi_prof(root)) == []


@pytest.mark.parametrize("inline", [False, True], ids=["variable", "inline"])
@pytest.mark.parametrize(
    "scheme", list(_DISABLED_BEHIND_A_COMMENT.values()), ids=list(_DISABLED_BEHIND_A_COMMENT)
)
def test_disabled_scheme_behind_a_comment_still_fires(tmp_path: Path, scheme: str, inline: bool) -> None:
    root = _wipe_app(tmp_path, scheme, inline=inline)
    assert len(_guard().run(root, _fastapi_prof(root))) == 1


# ── Depends(RateLimiter(...)) is not an auth signal ─────────────────────────────

def test_fires_when_only_dependency_is_a_rate_limiter(tmp_path: Path) -> None:
    """A route whose only Depends(...) wraps a non-auth-named callable (RateLimiter) must still
    fire — before this fix, ANY Depends(...) read as "has an auth signal" regardless of what it
    actually wraps, silencing a genuinely unauthenticated route."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi_limiter.depends import RateLimiter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/delete-user', dependencies=[Depends(RateLimiter(times=5, seconds=60))])\n"
        "def delete_user(user_id: int):\n"
        "    db.delete(user_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_fires_when_router_level_dependency_is_a_rate_limiter(tmp_path: Path) -> None:
    """Same gap, router-level: a router mounted with only a RateLimiter dependency must not
    read as authed for every route on it (the wider blast radius #473's own router-level
    resolver introduced for this exact loose-signal class)."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi_limiter.depends import RateLimiter\n"
        "router = APIRouter(dependencies=[Depends(RateLimiter(times=5, seconds=60))])\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(user_id: int):\n"
        "    db.delete(user_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_fp_bait_rate_limiter_alongside_a_real_auth_dependency(tmp_path: Path) -> None:
    """The direction the NAMED-auth tightening traded against (Rule 1): rate-limit AND authenticate the same
    route — the realistic production shape, and the exact place an over-broad narrowing would
    break correctly-authed code. The RateLimiter must not cancel out the real auth dependency
    sharing its `dependencies=[...]` list."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi_limiter.depends import RateLimiter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/delete-user', dependencies=["
        "Depends(RateLimiter(times=2, seconds=5)), Depends(get_current_user)])\n"
        "def delete_user(user_id: int):\n"
        "    db.delete(user_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_fp_bait_router_level_rate_limiter_alongside_a_real_auth_dependency(tmp_path: Path) -> None:
    """Same combined shape at the router level, where a mistake silences EVERY route on the
    router rather than one (the blast radius that made that hole worth closing)."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "from fastapi_limiter.depends import RateLimiter\n"
        "router = APIRouter(dependencies=["
        "Depends(RateLimiter(times=2, seconds=5)), Depends(require_admin)])\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(user_id: int):\n"
        "    db.delete(user_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_wrapper_hidden_auth_dep_is_known_limitation(tmp_path: Path) -> None:
    # KNOWN LIMITATION (documented on `AUTH_DEPENDS_SIGNAL` in guards/base.py): the auth stem is
    # only recognized in the FIRST token after `Depends(`, because the `[\w.]*` prefix cannot cross
    # a `(` or a `[`. A real auth callable behind a non-auth-named wrapper is therefore missed and
    # these correctly-authed routes FIRE — a false positive, pinned here so a future widening is an
    # intentional, visible change rather than a silent behavior swap.
    #
    # This is the accepted COST SIDE of NAMED auth, not a regression: both shapes were silent before
    # it only because ANY `Depends(...)` counted as auth — the very hole that let a route carrying
    # nothing but `Depends(RateLimiter(...))` read as authenticated. Closing it needs the real
    # argument resolver (the open tail), NOT a wider regex: matching an auth stem anywhere
    # inside the wrapper would silence `Depends(get_db(user_scoped=True))`.
    (tmp_path / "app.py").write_text(
        "import functools\n"
        "from fastapi import APIRouter, Depends\n"
        "from dependency_injector.wiring import Provide\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/delete-user', "
        "dependencies=[Depends(functools.partial(require_role, 'admin'))])\n"
        "def delete_user(user_id: int):\n"
        "    db.delete(user_id)\n"
        "    return {'status': 'deleted'}\n"
        "\n"
        "@router.post('/admin/ban-user', "
        "dependencies=[Depends(Provide[Container.auth_service])])\n"
        "def ban_user(user_id: int):\n"
        "    db.ban(user_id)\n"
        "    return {'status': 'banned'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


# --- #859: per-route `dependencies=[<bare factory()>]` and explicit public-marker decorators ------
# Sub-fix A: a returns-nothing auth guard attached un-wrapped in a route's OWN `dependencies=[...]`
# (`dependencies=[requires_authenticated()]`) is real auth, but is not `Depends()`/`Security()`-
# wrapped so the shared `auth_signal` missed it and the route over-fired at HIGH. Sub-fix B: an
# explicit `@auth.public` marker is a deliberate public declaration, honored like the pragma.


def test_fp_bait_per_route_bare_auth_factory_dependency(tmp_path: Path) -> None:
    """#859 sub-fix A (the fix): a bare auth-FACTORY call inside the route's own
    `dependencies=[...]` — the idiomatic returns-nothing FastAPI guard, not `Depends()`-wrapped —
    is recognized as auth and the route stays silent."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "from .security import auth as _auth, requires_system_write_role\n"
        "api_router = APIRouter()\n"
        "\n"
        "@api_router.post('/agent/simulate', dependencies=[_auth.requires_authenticated()])\n"
        "def simulate(payload: dict):\n"
        "    return {'ok': True}\n"
        "\n"
        "@api_router.put('/agent/config', dependencies=[requires_system_write_role()])\n"
        "def write_config(payload: dict):\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_fp_bait_per_route_bare_auth_factory_alongside_a_non_auth_dependency(tmp_path: Path) -> None:
    """The multi-element list (Rule 1, the realistic shape): a non-auth dep FIRST, the bare auth
    factory SECOND. A top-level comma inside `[...]` would truncate a paren-only splitter, so this
    pins that the whole list is bracket-balance-scanned and the real auth is not lost."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "from .deps import get_pagination\n"
        "from .security import requires_authenticated\n"
        "api_router = APIRouter()\n"
        "\n"
        "@api_router.post('/agent/simulate', "
        "dependencies=[get_pagination(), requires_authenticated()])\n"
        "def simulate(payload: dict):\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_fires_when_per_route_dependency_is_a_bare_non_auth_call(tmp_path: Path) -> None:
    """#859 sub-fix A, the direction traded against (Rule 1): a BARE, un-wrapped
    non-auth call in `dependencies=[...]` (`get_db()`, `RateLimiter(...)`) carries no curated auth
    stem and must STILL fire. This is the exact false-negative hole a too-broad bare matcher would
    reopen — here at the per-route site the fix newly reads."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "from fastapi_limiter.depends import RateLimiter\n"
        "from .deps import get_db\n"
        "api_router = APIRouter()\n"
        "\n"
        "@api_router.post('/admin/delete-user', dependencies=[get_db()])\n"
        "def delete_user(user_id: int):\n"
        "    return {'status': 'deleted'}\n"
        "\n"
        "@api_router.delete('/admin/purge', dependencies=[RateLimiter(times=5, seconds=60)])\n"
        "def purge():\n"
        "    return {'status': 'purged'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    locations = [f.location for f in findings if f.rule == "auth-dependency-not-applied/no-auth-dependency"]
    # BOTH bare non-auth routes must fire — neither is silenced by the new deps-list recognition.
    assert len(locations) == 2


def test_per_route_bare_auth_factory_recognition_is_scoped_to_the_deps_list(tmp_path: Path) -> None:
    """The scoping guard: the permissive bare-name match only counts INSIDE a
    `dependencies=[...]` list. A `requires_authenticated()` called in the route BODY (not the deps
    list) is not an applied dependency and must NOT silence the route; a sibling route with a real
    per-route deps guard in the same file still resolves independently (route-scoped)."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "from .security import requires_authenticated\n"
        "api_router = APIRouter()\n"
        "\n"
        "@api_router.post('/agent/simulate', dependencies=[requires_authenticated()])\n"
        "def simulate(payload: dict):\n"
        "    return {'ok': True}\n"
        "\n"
        "@api_router.post('/admin/delete-user')\n"
        "def delete_user(user_id: int):\n"
        "    # a mention in the body is not an APPLIED dependency\n"
        "    if not requires_authenticated():\n"
        "        raise RuntimeError\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    locations = [f.location for f in findings if f.rule == "auth-dependency-not-applied/no-auth-dependency"]
    # The deps-list route is silent; the body-mention route (no applied dep) still fires — exactly one,
    # and it is the delete_user route (located by its `def` line), NOT the authed simulate route.
    src = (tmp_path / "app.py").read_text(encoding="utf-8").splitlines()
    delete_user_def_line = next(i for i, ln in enumerate(src, start=1) if ln.startswith("def delete_user"))
    assert locations == [f"app.py:{delete_user_def_line}"]


def test_fp_bait_public_marker_decorator(tmp_path: Path) -> None:
    """#859 sub-fix B (the fix): an explicit public-marker decorator (`@auth.public`,
    `@app.allow_anonymous`) is a deliberate "unauthenticated by design" declaration and is honored
    like the `# security: allow-unauthenticated-route` pragma."""
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "from .security import auth\n"
        "app = FastAPI()\n"
        "\n"
        "@app.post('/api/auth/password/reset')\n"
        "@auth.public\n"
        "def reset_password_route(payload: dict):\n"
        "    return {'sent': True}\n"
        "\n"
        "@app.post('/newsletter/subscribe')\n"
        "@app.allow_anonymous\n"
        "def subscribe(email: str):\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_public_word_in_path_or_handler_name_still_fires(tmp_path: Path) -> None:
    """The direction traded against for sub-fix B (Rule 1): `public` is a MARKER, never a name or
    path exemption. A route at `/public/...`, a handler named `public_upload`, and a
    `@public_router.post(...)` decorator (whole-token match only) must all still fire without an
    explicit marker."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "public_router = APIRouter()\n"
        "\n"
        "@public_router.post('/public/upload')\n"
        "def public_upload(f: bytes):\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_commented_out_per_route_deps_does_not_exempt(tmp_path: Path) -> None:
    """#859 review (dead-code doctrine, #532 per-route counterpart): a COMMENTED-OUT
    `dependencies=[requires_authenticated()]` sitting above the route's real
    `dependencies=[get_db()]` must NOT fake protection. The deps scan blanks line-comments first
    (`blank_line_comments`), so the leftmost live `dependencies=[` — the get_db() one — is what is
    scanned, and the genuinely-unauthenticated route still fires. A false negative here would
    silently pass an unauthenticated state-changing route (the unsafe direction)."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "from .deps import get_db\n"
        "api_router = APIRouter()\n"
        "\n"
        "@api_router.post(\n"
        "    '/admin/delete-user',\n"
        "    # dependencies=[requires_authenticated()]  # removed during a refactor\n"
        "    dependencies=[get_db()],\n"
        ")\n"
        "def delete_user(user_id: int):\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_live_per_route_deps_with_a_decorator_comment_still_exempt(tmp_path: Path) -> None:
    """The direction traded against (Rule 1 / #532 FP-bait): a LIVE
    `dependencies=[requires_authenticated()]` in a multi-line decorator that also carries an
    ordinary comment must STILL be silenced. Pins that comment-blanking does not eat the live auth
    (goes red if `blank_line_comments` ever mangles offsets or clips real code)."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "from .security import requires_authenticated\n"
        "api_router = APIRouter()\n"
        "\n"
        "@api_router.post(\n"
        "    '/admin/delete-user',  # state-changing, admin only\n"
        "    dependencies=[requires_authenticated()],\n"
        ")\n"
        "def delete_user(user_id: int):\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_unterminated_deps_list_does_not_read_the_handler_body(tmp_path: Path) -> None:
    """#872's one behaviour change to this guard (#1041 round-1 review, R1-M2), pinned in its own
    suite. The deps-list bracket scan is not quote-aware, so a `[` inside a string literal leaves the
    list unterminated in VALID Python. Before #872 the scan then ran on into the handler body, where
    a factory merely CALLED (never applied) faked protection; it now stops at the decorator's `)`,
    so this unauthenticated route fires. The live neighbour, the same list with the auth factory
    applied, stays silent (the direction traded against)."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "api_router = APIRouter()\n"
        "\n"
        "@api_router.post('/admin/purge', dependencies=[get_db('[')])\n"
        "def purge(user_id: int):\n"
        "    requires_authenticated()  # called, never applied as a dependency\n"
        "    return {'status': 'purged'}\n"
        "\n"
        "@api_router.post('/admin/wipe', dependencies=[get_db('['), requires_authenticated()])\n"
        "def wipe(user_id: int):\n"
        "    return {'status': 'wiped'}\n",
        encoding="utf-8",
    )
    findings = [
        f for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))
        if f.rule == "auth-dependency-not-applied/no-auth-dependency"
    ]
    assert [f.location for f in findings] == ["app.py:5"], [f.location for f in findings]  # purge's `def`


def test_fp_bait_router_level_dependencies(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter(dependencies=[Depends(get_current_user)])\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(user_id: int):\n"
        "    db.delete(user_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_fp_bait_get_route_not_state_changing(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.get('/status')\n"
        "def get_status():\n"
        "    return {'status': 'ok'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_fp_bait_security_call_recognized(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Security\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(user_id: int, current_user: User = Security(get_current_user, scopes=['admin'])):\n"
        "    db.delete(user_id)\n"
        "    return {'status': 'deleted'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_fp_bait_pragma(tmp_path: Path) -> None:
    # a route-scoped pragma (in the handler body) silences THIS route. Uses a non-auth-flow route so
    # the PRAGMA (not the §A.1 auth-flow exemption) is what silences it.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/create-item')\n"
        "def create_item(name: str, price: int):\n"
        "    # security: allow-unauthenticated-route\n"
        "    save_item(name, price)\n"
        "    return {'status': 'created'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_pragma_is_route_scoped_not_file_wide(tmp_path: Path) -> None:
    # CRITICAL regression: one route's pragma must NOT blind a different unauthed route in the
    # same file (the old file-wide check silenced everything). (PR #268 review, Critical)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/create-item')\n"
        "def create_item(name: str, price: int):\n"
        "    # security: allow-unauthenticated-route\n"
        "    save_item(name, price)\n"
        "\n"
        "@router.delete('/admin/wipe-db')\n"
        "def wipe_db():\n"
        "    db.drop_all()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    locs = [f.location for f in findings if f.rule == "auth-dependency-not-applied/no-auth-dependency"]
    assert len(locs) == 1 and "wipe_db" not in str(locs)  # only the un-pragma'd DELETE fires
    assert any(":9" in loc or ":10" in loc for loc in locs)  # the wipe-db route, not create-item


def test_fires_on_every_unauthed_route_in_file(tmp_path: Path) -> None:
    # MAJOR regression: all unauthed routes in a file are reported, not just the first.
    # (PR #268 review, Major — the guard used to `return` on the first match)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(uid: int):\n"
        "    db.delete(uid)\n"
        "\n"
        "@router.delete('/admin/wipe-db')\n"
        "def wipe_db():\n"
        "    db.drop_all()\n",
        encoding="utf-8",
    )
    findings = [f for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))
                if f.rule == "auth-dependency-not-applied/no-auth-dependency"]
    assert len(findings) == 2


def test_fp_bait_include_router_dependencies(tmp_path: Path) -> None:
    # MAJOR regression: a router included with dependencies=[Depends(...)] authenticates every
    # route on it — no per-route Depends needed. (PR #268 review, Major)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends, FastAPI\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(uid: int):\n"
        "    db.delete(uid)\n"
        "\n"
        "app = FastAPI()\n"
        "app.include_router(router, dependencies=[Depends(get_current_user)])\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_fp_bait_auth_decorator(tmp_path: Path) -> None:
    # MINOR: a well-known auth decorator (@login_required) protects the route — not an FP.
    # (PR #268 review — decorator auth was mislabeled a false negative; it was a false positive)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "from myauth import login_required\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "@login_required\n"
        "def delete_user(uid: int):\n"
        "    db.delete(uid)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_fires_on_route_with_comment_between_decorator_and_def(tmp_path: Path) -> None:
    # CRITICAL regression: a comment/blank between the decorator stack and `def` used to truncate
    # the block walk-up, dropping @router.post entirely -> the route was silently MISSED (false
    # negative), not suppressed. It must fire now. (PR #268 re-review, Critical)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/wipe')\n"
        "# an explanatory comment, not a pragma\n"
        "def wipe():\n"
        "    db.drop_all()\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_pragma_between_decorator_and_def_is_honored(tmp_path: Path) -> None:
    # The pragma sitting in that same between-decorator-and-def position must SUPPRESS (be honored),
    # not merely make the route invisible. (PR #268 re-review, Critical)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/public')\n"
        "# security: allow-unauthenticated-route\n"
        "def public():\n"
        "    return 1\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_include_router_without_deps_still_fires(tmp_path: Path) -> None:
    # `app.include_router(router)` with NO dependencies=[...] must NOT suppress — the router is
    # unauthed. (PR #268 re-review, minor gap: lock the negative direction of the include_router fix)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/delete')\n"
        "def delete(uid: int):\n"
        "    db.delete(uid)\n"
        "\n"
        "app = FastAPI()\n"
        "app.include_router(router)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_near_miss_decorator_does_not_silence(tmp_path: Path) -> None:
    # A security-ish but non-auth decorator (@require_https) is NOT in the auth allowlist and must
    # NOT silence — avoids the false-negative failure mode. (PR #268 re-review, minor gap)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "from utils import require_https\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/delete')\n"
        "@require_https\n"
        "def delete(uid: int):\n"
        "    db.delete(uid)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_fires_on_route_with_multiline_decorator(tmp_path: Path) -> None:
    # CRITICAL regression: a wrapped decorator call (@router.post(\n "/x",\n status_code=201,\n))
    # put a non-`@` `)` line directly above `def`; the old walk-up broke there, dropping the whole
    # decorator so the route was silently INVISIBLE (never fired). It must fire now.
    # (PR #268 agentic re-review, Critical — shared iter_functions() walker.)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post(\n"
        "    '/admin/delete-user',\n"
        "    status_code=201,\n"
        ")\n"
        "def delete_user(user_id: int):\n"
        "    db.delete(user_id)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_pragma_honored_with_multiline_signature(tmp_path: Path) -> None:
    # HIGH regression: with a wrapped signature the closing `) -> dict:` line sits at the def's
    # own indent, so the old body walk-down stopped there and excluded the body — a pragma placed
    # in the body was never seen and the route over-fired. The pragma must suppress now.
    # (PR #268 agentic re-review, High — shared iter_functions() walker.)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/admin/create-item')\n"
        "def create_item(\n"
        "    name: str,\n"
        "    price: int,\n"
        ") -> dict:\n"
        "    # security: allow-unauthenticated-route\n"
        "    save_item(name, price)\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_depends_in_multiline_signature_recognized(tmp_path: Path) -> None:
    # A Depends(...) auth param in a wrapped signature must still be recognized (silent) — the
    # signature is part of the block. (PR #268 agentic re-review, shared walker.)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/x')\n"
        "def f(\n"
        "    uid: int,\n"
        "    current_user = Depends(get_current_user),\n"
        ") -> dict:\n"
        "    return {}\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_unrelated_multiline_expr_above_decorator_not_absorbed(tmp_path: Path) -> None:
    # The bracket-unwind that captures multi-line decorators must NOT absorb an unrelated
    # multi-line expression sitting above the decorator (which could smuggle a stray `Depends(`
    # token into the block and wrongly silence the route). Exactly one finding, on the route.
    # (PR #268 agentic re-review, shared walker correctness.)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "result = some_call(\n"
        "    Depends(x),\n"
        ")\n"
        "@router.post('/wipe')\n"
        "def wipe():\n"
        "    db.drop_all()\n",
        encoding="utf-8",
    )
    findings = [f for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))
                if f.rule == "auth-dependency-not-applied/no-auth-dependency"]
    # exactly one finding (not silenced by the stray Depends above; not double-counted), on the
    # `def wipe` line (line 8), proving the unrelated expression was not folded into the block.
    assert len(findings) == 1 and findings[0].location.endswith(":8")


def test_fires_despite_triple_quoted_description_with_stray_bracket(tmp_path: Path) -> None:
    # CRITICAL regression: a stray bracket inside a triple-quoted OpenAPI `description="""..."""`
    # in the decorator used to skew the bracket-balance count and drop the whole decorator, making
    # an unauthenticated DELETE invisible (silent false negative). strip_python_strings() blanks the
    # string content first, so the route must fire. (PR #268 round-2 review, Critical.)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post(\n"
        "    '/x',\n"
        "    description=\"\"\"\n"
        "    an example: foo(bar\n"
        "    \"\"\",\n"
        ")\n"
        "def delete_user(user_id: int):\n"
        "    db.delete(user_id)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_triple_quoted_default_does_not_merge_adjacent_route(tmp_path: Path) -> None:
    # CRITICAL regression: a stray bracket in a triple-quoted signature default used to stop the
    # walk-down from ending the block at the real end of the signature, merging the NEXT route into
    # this block so its unauthed handler was silenced by this route's pragma. Both routes must be
    # scoped separately -> the un-pragma'd `wipe_db` must fire. (PR #268 round-2 review, Critical.)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/x')\n"
        "def create_item(\n"
        "    name: str,\n"
        "    note: str = \"\"\"\n"
        "    an example: foo(bar\n"
        "    \"\"\",\n"
        "):\n"
        "    # security: allow-unauthenticated-route\n"
        "    save_item(name)\n"
        "\n"
        "@router.post('/next')\n"
        "def wipe_db():\n"
        "    db.drop_all()\n",
        encoding="utf-8",
    )
    findings = [f for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))
                if f.rule == "auth-dependency-not-applied/no-auth-dependency"]
    assert len(findings) == 1 and "wipe_db" in _read_def_line(tmp_path, findings[0])


def test_pragma_honored_despite_triple_quoted_default_with_stray_bracket(tmp_path: Path) -> None:
    # Companion FP direction: a stray `)` in a triple-quoted signature default used to truncate the
    # walk-down early, excluding the body and its pragma so the route over-fired. The pragma must be
    # honored now. (PR #268 round-2 review, Critical.)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/x')\n"
        "def delete_user(\n"
        "    user_id: int,\n"
        "    note: str = \"\"\"\n"
        "    see docs) for details\n"
        "    \"\"\",\n"
        ") -> dict:\n"
        "    # security: allow-unauthenticated-route\n"
        "    db.delete(user_id)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_fires_despite_escaped_quote_and_bracket_in_decorator_string(tmp_path: Path) -> None:
    # CRITICAL regression (round 3): a single-line string with an ESCAPED quote plus an unbalanced
    # bracket (`summary="a \" then ("`) used to mis-split in _SL_STRING and leak the `(` into the
    # bracket count, dropping the whole multi-line decorator -> the unauthed route was invisible.
    # _SL_STRING is now escape-aware, so the route must fire. (PR #268 round-3 review, Critical.)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post(\n"
        "    '/x',\n"
        '    summary="a \\" then (",\n'
        ")\n"
        "def delete_user(user_id: int):\n"
        "    db.delete(user_id)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_fires_despite_bracket_in_comment_inside_multiline_decorator(tmp_path: Path) -> None:
    # CRITICAL regression (round 3): a `#` comment with an unbalanced bracket INSIDE a multi-line
    # decorator's arg list used to rebalance the walk-up unwind at a non-`@` line, so the unwind was
    # rejected and the decorator dropped -> the unauthed route was invisible. _bracket_delta now
    # ignores comment content, so the route must fire. (PR #268 round-3 review, Critical.)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post(\n"
        "    '/x',\n"
        "    # danger ( unbalanced paren in a comment\n"
        ")\n"
        "def delete_user(user_id: int):\n"
        "    db.delete(user_id)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_exempt_auth_flow_routes_by_path(tmp_path: Path) -> None:
    # §A.1 (3 FPs on the flagship): public auth-flow endpoints legitimately have no auth dependency —
    # you cannot require a session to create/establish one. `/signup`, `/login`, `/logout` are exempt.
    (tmp_path / "auth.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/signup')\n"
        "def signup(email: str, password: str):\n"
        "    return create_user(email, password)\n"
        "\n"
        "@router.post('/login')\n"
        "def login(email: str, password: str):\n"
        "    return issue_session(email, password)\n"
        "\n"
        "@router.post('/logout')\n"
        "def logout():\n"
        "    return clear_session()\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_exempt_auth_flow_by_function_name_generic_path(tmp_path: Path) -> None:
    # The path is generic but the handler NAME is an auth-flow verb → exempt (backlog lists funcs too).
    (tmp_path / "auth.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/')\n"
        "def refresh_token(body: dict):\n"
        "    return rotate(body)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_exempt_route_on_auth_prefix_router(tmp_path: Path) -> None:
    # A route on an `APIRouter(prefix="/auth")` whose own last segment is an ambiguous auth VERB
    # (`exchange` — the OAuth code exchange) is exempt: the verb counts because the full path
    # carries an `auth` segment. The prefix alone is not an exemption (#482 review) — see
    # `test_auth_prefix_router_exempts_only_the_auth_flow_route`.
    (tmp_path / "auth.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/auth', tags=['auth'])\n"
        "\n"
        "@router.post('/exchange')\n"
        "def exchange(code: str):\n"
        "    return swap(code)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_webhook_path_without_signature_verification_still_fires(tmp_path: Path) -> None:
    # §E.2 exempts a webhook receiver because a provider SIGNATURE authenticates it. This handler
    # verifies NOTHING, so the path shape alone must not exempt it — an unauthenticated receiver
    # with no signature check is precisely the bug worth reporting (#482 review; this test
    # previously asserted the opposite).
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/api/webhook/stripe')\n"
        "def stripe_webhook(request):\n"
        "    return handle(request)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_exempt_route_that_verifies_signature(tmp_path: Path) -> None:
    # §E.2: even at a non-`/webhook/` path, a handler that verifies a provider signature
    # (`construct_event`) is a signature-authenticated receiver → exempt.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/api/stripe-events')\n"
        "def receive(request, stripe_signature: str):\n"
        "    event = stripe.Webhook.construct_event(request.body, stripe_signature, secret)\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_still_fires_on_non_auth_route_beside_auth_flow_routes(tmp_path: Path) -> None:
    # The exemption is per-route: a protected-worthy admin route in the SAME file as auth-flow routes
    # must STILL fire. Keeps the guard from being blinded by proximity to an auth router.
    (tmp_path / "auth.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/login')\n"
        "def login(email: str, password: str):\n"
        "    return issue_session(email, password)\n"
        "\n"
        "@router.delete('/admin/wipe-db')\n"
        "def wipe_db():\n"
        "    db.drop_all()\n",
        encoding="utf-8",
    )
    findings = [f for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))
                if f.rule == "auth-dependency-not-applied/no-auth-dependency"]
    assert len(findings) == 1 and "wipe_db" in _read_def_line(tmp_path, findings[0])


def test_exemption_does_not_over_match_compound_names(tmp_path: Path) -> None:
    # PR #482 review: a compound handler name that merely CONTAINS an auth verb must still fire —
    # `register_device`, `sso_link_account`, `refresh_dashboard`, `verify_payment` all genuinely need
    # auth. The allowlist is whole-token, so none of these are exempted.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/devices')\n"
        "def register_device(serial: str):\n"
        "    add_device(serial)\n"
        "\n"
        "@router.post('/link')\n"
        "def sso_link_account(uid: int):\n"
        "    link(uid)\n"
        "\n"
        "@router.post('/api/token')\n"
        "def create_token(scope: str):\n"
        "    return mint(scope)\n",
        encoding="utf-8",
    )
    findings = [f for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))
                if f.rule == "auth-dependency-not-applied/no-auth-dependency"]
    assert len(findings) == 3  # all three fire (none wrongly exempted)


def test_auth_prefix_boundary_does_not_match_authors(tmp_path: Path) -> None:
    # PR #482 review: `prefix="/authors"` must NOT be treated as an `/auth` router — the boundary
    # after `/auth` prevents `/authors` / `/authenticate` / `/authz` from exempting an unrelated router.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/authors')\n"
        "\n"
        "@router.post('/')\n"
        "def create_author(name: str):\n"
        "    save(name)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_sig_verify_in_comment_or_unused_header_does_not_exempt(tmp_path: Path) -> None:
    # PR #482 review: a commented-out mention of a verification primitive, or a declared-but-unused
    # `X-*-Signature` header, must NOT exempt a genuinely unauthenticated state-changing route.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Header\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/events')\n"
        "def receive(sig: str = Header(alias='X-Hub-Signature-256')):\n"
        "    # we removed the verify_signature() check last year\n"
        "    log(sig)\n"
        "    return save()\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_webhook_management_collection_still_fires(tmp_path: Path) -> None:
    # PR #482 review: a `POST /api/webhooks` MANAGEMENT endpoint (create a webhook subscription) needs
    # auth — only a receiver path `/webhook(s)/<provider>` or a signature-verifying handler is exempt.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/api/webhooks')\n"
        "def create_webhook(url: str):\n"
        "    subscribe(url)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def _read_def_line(root: Path, finding: object) -> str:
    """The source line the finding points at (for asserting WHICH route fired)."""
    loc = finding.location  # type: ignore[attr-defined]
    path, _, lineno = loc.rpartition(":")
    return (root / path).read_text(encoding="utf-8").splitlines()[int(lineno) - 1]


# --- #482 review: exemptions were per-router and path-only ------------------------------------

_AUTH_ROUTER_MODULE = (
    'from fastapi import APIRouter\n'
    'router = APIRouter(prefix="{prefix}", tags=["auth"])\n'
    '\n'
    '@router.post("/login")\n'
    'def login(body):\n'
    '    return start_session(body)\n'
    '\n'
    '@router.post("/admin/impersonate")\n'
    'def impersonate(user_id: int):\n'
    '    return act_as(user_id)\n'
    '\n'
    '@router.delete("/users/{{user_id}}")\n'
    'def delete_user(user_id: int):\n'
    '    return remove(user_id)\n'
    '\n'
    '@router.put("/users/{{user_id}}/role")\n'
    'def set_role(user_id: int, body):\n'
    '    return assign(user_id, body)\n'
)


@pytest.mark.parametrize("prefix", ["/auth", "/auth/admin", "/v1/auth/internal"])
def test_auth_prefix_router_exempts_only_the_auth_flow_route(tmp_path: Path, prefix: str) -> None:
    # An `/auth` prefix used to exempt EVERY route on the router (20/20 findings down to 8/20 on a
    # 20-route corpus), and the `/auth` match had no positional bound so `/auth/admin` and
    # `/v1/auth/internal` silenced everything under them too (#482 review). The prefix now only
    # contributes path text; only `/login` is an auth-flow route.
    (tmp_path / "api.py").write_text(_AUTH_ROUTER_MODULE.format(prefix=prefix), encoding="utf-8")
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    names = sorted(_read_def_line(tmp_path, f).strip() for f in findings)
    assert len(findings) == 3, f"{prefix}: {names}"
    assert not any("def login" in n for n in names), names


def test_webhook_management_routes_are_not_exempt(tmp_path: Path) -> None:
    # `_WEBHOOK_RECEIVER_PATH` matched any `/webhook(s)/<word>` pair anywhere in the path, and the
    # exemption was `path OR verifies_signature`. So webhook MANAGEMENT routes were exempt — and so
    # was a receiver that verifies nothing, which is exactly the bug worth reporting (#482 review).
    (tmp_path / "api.py").write_text(
        'from fastapi import APIRouter\n'
        'router = APIRouter()\n'
        '\n'
        '@router.post("/webhooks")\n'
        'def create_webhook(body):\n'
        '    return make(body)\n'
        '\n'
        '@router.post("/webhooks/subscribe")\n'
        'def subscribe(body):\n'
        '    return sub(body)\n'
        '\n'
        '@router.delete("/api/v1/webhooks/all")\n'
        'def wipe_webhooks():\n'
        '    return remove_all()\n'
        '\n'
        '@router.put("/webhooks/rotate-secret")\n'
        'def rotate():\n'
        '    return new_secret()\n'
        '\n'
        '@router.post("/webhooks/stripe")\n'
        'def receive(request):\n'
        '    return handle(request)\n',
        encoding="utf-8",
    )
    assert len(_guard().run(tmp_path, _fastapi_prof(tmp_path))) == 5


def test_signature_verified_webhook_receiver_is_still_exempt(tmp_path: Path) -> None:
    # The FP-bait direction: requiring BOTH a receiver path AND a real verification call must not
    # break the exemption this PR exists to add.
    (tmp_path / "api.py").write_text(
        'from fastapi import APIRouter, Request\n'
        'router = APIRouter()\n'
        '\n'
        '@router.post("/webhooks/stripe")\n'
        'async def receive(request: Request):\n'
        '    event = stripe.Webhook.construct_event(await request.body(), sig, secret)\n'
        '    return handle(event)\n',
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_auth_segment_must_be_adjacent_to_the_ambiguous_verb(tmp_path: Path) -> None:
    # #482 second-pass review: the ambiguous-verb exemption accepted an `auth`/`oauth` segment
    # ANYWHERE earlier in the path, so `POST /auth/admin/token` (mints an admin token) and
    # `POST /oauth/users/{id}/verify` (marks an arbitrary user verified) were exempt — the same
    # "blast radius wider than intended" bug this PR fixed for the router prefix, one level down.
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        '@router.post("/auth/admin/token")\n'
        "def mint(uid): return admin_token(uid)\n"
        '@router.post("/oauth/users/{uid}/verify")\n'
        "def verify_user(uid): return mark_verified(uid)\n",
        encoding="utf-8",
    )
    assert len(_guard().run(tmp_path, _fastapi_prof(tmp_path))) == 2


def test_adjacent_auth_segment_still_exempts_the_flow_route(tmp_path: Path) -> None:
    # The other direction: the real auth-flow routes must stay exempt.
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        '@router.post("/auth/exchange")\n'
        "def ex(code): return swap(code)\n"
        '@router.post("/auth/callback")\n'
        "def cb(code): return handle(code)\n",
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_ambiguous_verify_primitive_needs_a_signature_context(tmp_path: Path) -> None:
    # `verify_header` is generic enough to appear in unrelated code — a CSV-import handler calling
    # `csv_reader.verify_header(...)` was silently exempted (#482 second-pass review).
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        '@router.post("/import/csv")\n'
        "def imp(payload):\n"
        '    csv_reader.verify_header(payload["header"])\n'
        "    return load(payload)\n",
        encoding="utf-8",
    )
    assert len(_guard().run(tmp_path, _fastapi_prof(tmp_path))) == 1


def test_hand_rolled_hmac_receiver_is_exempt(tmp_path: Path) -> None:
    # The opposite direction the same review flagged: a GitHub-style receiver using
    # `hmac.compare_digest` is the most common real implementation and was missed entirely,
    # producing an avoidable false positive on correct code.
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter, Header\n"
        "router = APIRouter()\n"
        '@router.post("/webhooks/github")\n'
        "async def gh(request, x_hub_signature_256: str = Header(None)):\n"
        "    if not hmac.compare_digest(expected, x_hub_signature_256):\n"
        "        raise HTTPException(403)\n"
        "    return ok()\n",
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _fastapi_prof(tmp_path)) == []


# --- #482 third-pass review: the auth-flow exemption had no positional bound -------------------
#
# `_AUTH_FLOW_NAMES` matched the LAST path segment or the WHOLE handler name at ANY nesting depth,
# so `/resource/{id}/<auth-verb>` — an ordinary REST shape, not a corner case — was silently
# exempted. An exemption in an auth guard IS a suppression: every shape it covers stops being
# reported, and the failure mode is an unauthenticated privileged route reported as fine.

_RESOURCE_SCOPED_AUTH_VERBS = (
    'from fastapi import APIRouter\n'
    'router = APIRouter()\n'
    '\n'
    '@router.post("/admin/{user_id}/login")\n'
    'def impersonate_user(user_id: int):\n'
    '    return act_as(user_id)\n'
    '\n'
    '@router.post("/users/{user_id}/reset-password")\n'
    'def admin_force_reset_password(user_id: int):\n'
    '    return force_reset(user_id)\n'
    '\n'
    '@router.post("/users/{user_id}/oauth/token")\n'
    'def mint_token_for_user(user_id: int):\n'
    '    return mint(user_id)\n'
    '\n'
    '@router.delete("/items/{item_id}")\n'
    'def delete_item(item_id: int):\n'
    '    return rm(item_id)\n'
)


def test_resource_scoped_auth_verbs_are_not_public_by_design(tmp_path: Path) -> None:
    # The four reproduced wrong exemptions. Impersonation, arbitrary-user password reset and
    # arbitrary-user token minting were all EXEMPT; only `delete_item` fired. A path parameter
    # before the auth verb means the route acts ON a resource — it is an admin action spelled like
    # an auth flow, not a public entry point.
    (tmp_path / "api.py").write_text(_RESOURCE_SCOPED_AUTH_VERBS, encoding="utf-8")
    findings = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    names = sorted(_read_def_line(tmp_path, f).strip() for f in findings)
    assert len(findings) == 4, names


@pytest.mark.parametrize(
    ("path", "handler"),
    [
        # the auth verb is the last SEGMENT, nested under a resource id
        ("/users/{user_id}/logout", "def force_logout(user_id: int): return kill(user_id)"),
        ("/orgs/{org_id}/sso", "def link_sso(org_id: int): return link(org_id)"),
        ("/tenants/{tenant_id}/register", "def register(tenant_id: int): return add(tenant_id)"),
        # the auth verb is the handler NAME, nested under a resource id
        ("/users/{user_id}/sessions", "def login(user_id: int): return act_as(user_id)"),
        ("/projects/{project_id}/members", "def register(project_id: int): return add(project_id)"),
        # an auth NAMESPACE does not license a route nested under a resource inside it
        ("/auth/admin/{user_id}/login", "def login(user_id: int): return act_as(user_id)"),
        ("/auth/users/{user_id}/reset-password", "def rp(user_id: int): return force(user_id)"),
        ("/users/{user_id}/auth/login", "def login(user_id: int): return act_as(user_id)"),
        # the ambiguous-verb branch: the auth namespace must be at the path ROOT, not merely
        # adjacent to the verb (`oauth` preceding `token` under a per-user resource)
        ("/users/{user_id}/oauth/token", "def mint(user_id: int): return t(user_id)"),
        ("/users/oauth/token", "def mint(body): return t(body)"),
        ("/projects/{pid}/sso/verify", "def v(pid): return mark(pid)"),
    ],
)
def test_privileged_route_spelled_like_an_auth_flow_still_fires(
    tmp_path: Path, path: str, handler: str
) -> None:
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        f'@router.post("{path}")\n'
        f"{handler}\n",
        encoding="utf-8",
    )
    assert len(_guard().run(tmp_path, _fastapi_prof(tmp_path))) == 1, path


def test_router_prefix_supplies_the_resource_scope(tmp_path: Path) -> None:
    # The full path is what is anchored, so a resource prefix on the ROUTER scopes the route just as
    # an inline one does: `APIRouter(prefix="/users")` + `POST /{user_id}/login` is impersonation.
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\n"
        'router = APIRouter(prefix="/users")\n'
        '@router.post("/{user_id}/login")\n'
        "def login(user_id: int):\n"
        "    return act_as(user_id)\n",
        encoding="utf-8",
    )
    assert len(_guard().run(tmp_path, _fastapi_prof(tmp_path))) == 1


# --- the FP direction of the same change: genuinely public routes must stay silent -------------
#
# Narrowing a suppression creates false POSITIVES, so every shape below is a real public auth-flow
# route that must not start firing.

@pytest.mark.parametrize(
    ("ctor", "path", "handler"),
    [
        # at or near the path root
        ("APIRouter()", "/login", "def login(body): return start(body)"),
        ("APIRouter()", "/auth/login", "def login(body): return start(body)"),
        ("APIRouter()", "/api/v1/auth/login", "def login(body): return start(body)"),
        ("APIRouter()", "/auth/callback", "def cb(code): return handle(code)"),
        ("APIRouter()", "/auth/exchange", "def ex(code): return swap(code)"),
        ("APIRouter()", "/oauth/token", "def tok(code): return mint(code)"),
        ("APIRouter()", "/v2/auth/token", "def tok(code): return mint(code)"),
        ("APIRouter()", "/rest/auth/callback", "def cb(code): return handle(code)"),
        # a resource-ish first segment with NO path parameter is still an entry point
        ("APIRouter()", "/users/login", "def login(body): return start(body)"),
        ("APIRouter()", "/account/signup", "def signup(body): return create(body)"),
        # a path parameter AFTER the verb — the emailed-link shape
        ("APIRouter()", "/auth/reset-password/{token}", "def rp(token, body): return reset(token)"),
        ("APIRouter()", "/auth/verify/{token}", "def v(token): return confirm(token)"),
        ("APIRouter()", "/signup/{invite_code}", "def signup(invite_code): return create()"),
        # a path parameter inside an auth NAMESPACE — social login / multi-tenant login
        ("APIRouter()", "/auth/{provider}/login", "def login(provider, body): return start(body)"),
        ("APIRouter()", "/auth/{provider}/callback", "def cb(provider, code): return handle(code)"),
        ("APIRouter()", "/oauth/{provider}/token", "def tok(provider, code): return mint(code)"),
        ("APIRouter()", "/{tenant}/auth/login", "def login(tenant, body): return start(body)"),
        ("APIRouter()", "/api/{version}/auth/login", "def login(version, body): return start(body)"),
        # mounted on a router with an /auth (or versioned) prefix
        ('APIRouter(prefix="/auth")', "/login", "def login(body): return start(body)"),
        ('APIRouter(prefix="/auth")', "/token", "def tok(code): return mint(code)"),
        ('APIRouter(prefix="/api/v1/auth")', "/login", "def login(body): return start(body)"),
        ('APIRouter(prefix="/v1")', "/auth/login", "def login(body): return start(body)"),
    ],
)
def test_public_auth_flow_routes_stay_exempt(
    tmp_path: Path, ctor: str, path: str, handler: str
) -> None:
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\n"
        f"router = {ctor}\n"
        f'@router.post("{path}")\n'
        f"{handler}\n",
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _fastapi_prof(tmp_path)) == [], path


def test_signature_verified_webhook_is_unaffected_by_the_path_anchor(tmp_path: Path) -> None:
    # The webhook exemption is decided by the verification CALL, not the path, so anchoring the
    # auth-flow allowlist to path position must not touch it — including on a resource-scoped path.
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter, Request\n"
        "router = APIRouter()\n"
        '@router.post("/tenants/{tenant_id}/webhooks/stripe")\n'
        "async def receive(tenant_id: str, request: Request):\n"
        "    event = stripe.Webhook.construct_event(await request.body(), sig, secret)\n"
        "    return handle(event)\n",
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def _route_findings(tmp_path: Path, path: str, fn: str) -> int:
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
        f'@router.post("{path}")\ndef {fn}():\n    return {{}}\n',
        encoding="utf-8",
    )
    return len(_guard().run(tmp_path, _fastapi_prof(tmp_path)))


@pytest.mark.parametrize(
    ("path", "fn"),
    [
        # The #482 gate's Major, measured 0 -> 1. A path PARAMETER was counted as a prefix segment,
        # and `{version}` never matches the neutral-prefix regex, so it disqualified the exemption
        # unconditionally — contradicting this guard's own worked example, in which
        # `/api/{version}/auth/login` stays exempt.
        ("/api/{version}/auth/token", "get_token"),
        ("/v1/{region}/auth/token", "get_token"),
        ("/api/{version}/auth/login", "login"),
        # An auth segment is scaffolding too: this is social login, not a resource-scoped mint.
        ("/auth/{provider}/oauth/token", "oauth_token"),
        # The parameter allowlist that replaced "parameters do not exist" must keep every one of
        # these public — they name deployment scaffolding, not the subject the route acts on.
        ("/{tenant}/auth/token", "tenant_token"),
        ("/api/{ver}/auth/token", "get_token"),
        ("/api/{api_version}/auth/token", "get_token"),
        ("/v1/{locale}/auth/authorize", "authorize"),
        ("/auth/{idp}/oauth/token", "idp_token"),
        ("/{workspace}/auth/exchange", "ws_exchange"),
        ("/{realm}/auth/callback", "realm_cb"),
    ],
)
def test_auth_dep_versioned_auth_namespace_stays_exempt(tmp_path: Path, path: str, fn: str) -> None:
    assert _route_findings(tmp_path, path, fn) == 0, path


@pytest.mark.parametrize(
    ("path", "fn"),
    [
        # THE TRADED-AGAINST DIRECTION. Treating params as scaffolding WIDENS the exemption, so its
        # risk is re-opening the impersonation class this PR exists to close. A non-auth, non-neutral
        # name before the namespace must still disqualify.
        ("/users/{user_id}/oauth/token", "mint_for_user"),
        ("/orgs/{org_id}/auth/{provider}/login", "org_login"),
        ("/users/{id}/reset-password", "reset_pw"),
        ("/admin/{id}/login", "impersonate"),
        # …and the same class through the PARAMETER slot, which the four cases above never reach
        # (three of them resolve in the `_AUTH_FLOW_NAMES` branch, and the fourth disqualifies on a
        # NAMED segment). Filtering parameters out wholesale rather than asking WHICH parameter took
        # all five from 1 to 0 — an identity in the parameter slot selects the subject exactly as a
        # named segment does, so `{user_id}` must not be forgiven the way `{version}` is
        # (#482 fourth-pass gate). Each of these FAILS against the pre-fix guard.
        ("/api/{user_id}/auth/token", "mint_for_user"),
        ("/api/{user_id:int}/auth/token", "mint_for_user"),
        ("/v1/{account_id}/auth/refresh", "refresh_for_acct"),
        ("/auth/{id}/oauth/token", "mint_for_id"),
        ("/api/{email}/auth/challenge", "challenge_identity"),
        # A parameter BETWEEN the auth namespace and the verb selects the subject just as squarely.
        ("/auth/{user_id}/token", "mint_for_user"),
        # Fail-closed: an unrecognized parameter name is not scaffolding.
        ("/api/{userId}/auth/token", "mint_for_user"),
        ("/rest/{customer_id}/auth/exchange", "exchange_for_customer"),
        ("/{user_id}/auth/token", "mint_for_user"),
    ],
)
def test_auth_dep_resource_scoped_auth_verbs_still_fire(tmp_path: Path, path: str, fn: str) -> None:
    assert _route_findings(tmp_path, path, fn) == 1, path


@pytest.mark.parametrize(
    ("path", "fn"),
    [
        # ATTACKING the scaffolding-parameter allowlist itself. It is the only thing standing
        # between an ambiguous auth verb and a silent suppression, so a route that mixes an
        # allowlisted parameter with a real subject must still fire.
        ("/tenants/{tenant_id}/users/{user_id}/auth/token", "mint"),
        ("/{tenant}/users/{user_id}/auth/token", "mint"),
        ("/{tenant}/{user_id}/auth/token", "mint"),
        ("/api/{version}/{user_id}/auth/token", "mint"),
        ("/{user_id}/{version}/auth/token", "mint"),
        ("/api/{version}/{region}/orgs/{org_id}/auth/token", "mint"),
        ("/api/{version}/auth/{user_id}/token", "mint"),
        # …and the allowlist is ANCHORED, so a name that merely contains a scaffolding word is
        # not scaffolding. `{provider_id}` is caller-supplied and selects a subject.
        ("/auth/{provider_id}/oauth/token", "mint"),
        ("/{tenant_user_id}/auth/token", "mint"),
        ("/api/{my_version}/auth/token", "mint"),
        ("/api/{langlord}/auth/token", "mint"),
        # Degenerate/odd spellings resolve fail-CLOSED rather than exempting.
        ("/api/{}/auth/token", "mint"),
        ("/api/{user-id}/auth/token", "mint"),
        ("/api/{user_id:path}/auth/token", "mint"),
        ("/API/{USER_ID}/AUTH/TOKEN", "mint"),
        ("/api/{user_id}/auth/token/", "mint"),
    ],
)
def test_auth_dep_scaffold_param_allowlist_does_not_swallow_a_subject(
    tmp_path: Path, path: str, fn: str
) -> None:
    assert _route_findings(tmp_path, path, fn) == 1, path


@pytest.mark.parametrize(
    ("prefix", "path", "fn", "expected"),
    [
        # The router `prefix=` contributes path text, so an identity declared there is subject to
        # the same test — it must not slip past because it is spelled on the router.
        ("/users/{user_id}", "/auth/token", "mint", 1),
        ("/api/{version}/{user_id}", "/auth/token", "mint", 1),
        ("/api/{version}", "/auth/token", "mint", 0),
        ("/{tenant}", "/auth/login", "login", 0),
    ],
)
def test_auth_dep_scaffold_param_test_sees_the_router_prefix(
    tmp_path: Path, prefix: str, path: str, fn: str, expected: int
) -> None:
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\n"
        f'router = APIRouter(prefix="{prefix}")\n\n'
        f'@router.post("{path}")\ndef {fn}():\n    return {{}}\n',
        encoding="utf-8",
    )
    assert len(_guard().run(tmp_path, _fastapi_prof(tmp_path))) == expected, prefix + path


def test_fp_bait_cross_file_include_with_variable_dependency(tmp_path: Path) -> None:
    # The RAG-app case: a bare `router = APIRouter()` in routes/admin.py, protected by main.py's
    # `include_router(admin.router, dependencies=_admin_required)` where the deps are a VARIABLE
    # bound to a list. The guard resolves this cross-file (main.py -> routes/admin.py by stem) AND
    # through the variable, so no route in admin.py fires.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/videos')\n"
        "def add_video(url: str):\n"
        "    library.add(url)\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "from auth import get_current_admin\n"
        "app = FastAPI()\n"
        "_admin_required = [Depends(get_current_admin)]\n"
        "app.include_router(admin.router, prefix='/api', dependencies=_admin_required)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules

def test_cross_file_include_without_deps_still_fires(tmp_path: Path) -> None:
    # Negative direction (FN guard): main.py includes routes/library.py with NO dependencies, so the
    # route file's state-changing routes must still surface for review (a genuinely-public route is
    # suppressed per-route via the pragma, never by a plain include).
    #
    # The route is `/videos`, not the `/login` this test used on the #473 branch. #482's
    # public-by-design exemption landed on main while that branch was open and exempts `/login`
    # outright, so the original fixture would now pass for the WRONG reason — the include-without-deps
    # rule this test exists for would no longer be what keeps the finding alive. Any non-auth-flow
    # route measures the intended rule; do not put an auth-flow verb back here.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "library.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/videos')\n"
        "def add_video(url: str):\n"
        "    library.add(url)\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from routes import library\n"
        "app = FastAPI()\n"
        "app.include_router(library.router, prefix='/api')\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules

def test_cross_file_protection_is_stem_specific(tmp_path: Path) -> None:
    # FN guard: protecting admin.router must NOT suppress an unrelated, unprotected public.py
    # router — the cross-file match keys on the specific module stem, not "some router somewhere
    # is authed". Only admin.py is silenced; public.py's unauthed DELETE still fires.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
        "@router.post('/admin/x')\ndef ax(uid: int):\n    db.touch(uid)\n",
        encoding="utf-8",
    )
    (tmp_path / "routes" / "public.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
        "@router.delete('/wipe')\ndef wipe():\n    db.drop_all()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin, public\n"
        "app = FastAPI()\n"
        "app.include_router(admin.router, dependencies=[Depends(get_current_admin)])\n"
        "app.include_router(public.router)\n",
        encoding="utf-8",
    )
    findings = [f for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))
                if f.rule == "auth-dependency-not-applied/no-auth-dependency"]
    assert len(findings) == 1 and "wipe" in _read_def_line(tmp_path, findings[0])

def test_cross_file_multidot_ref_maps_to_correct_module(tmp_path: Path) -> None:
    # CRITICAL regression (PR #464 review): the protected module is the segment BEFORE `.router`,
    # not the leftmost one. A multi-dot ref `app.routes.admin.router` must protect routes/admin.py
    # (stem `admin`) — NOT a file named after the leftmost segment. A genuinely-unprotected app.py
    # must still fire; admin.py must be silenced.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
        "@router.post('/admin/x')\ndef ax(uid: int):\n    db.touch(uid)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n\n"
        "@router.delete('/wipe')\ndef wipe():\n    db.drop_all()\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "app = FastAPI()\n"
        "app.include_router(app.routes.admin.router, dependencies=[Depends(get_current_admin)])\n",
        encoding="utf-8",
    )
    findings = [f for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))
                if f.rule == "auth-dependency-not-applied/no-auth-dependency"]
    assert len(findings) == 1 and "wipe" in _read_def_line(tmp_path, findings[0])

def test_fp_bait_nested_bracket_before_depends_in_deps_list(tmp_path: Path) -> None:
    # MAJOR regression (PR #464 review): a dependencies= list whose first element contains a nested
    # `[...]` before the real Depends(...) must NOT truncate at the first `]` and spuriously flag the
    # route. The balance-scan finds the Depends anywhere in the list.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter(dependencies=[limiter(times=[5]), Depends(get_current_user)])\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(uid: int):\n"
        "    db.delete(uid)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules

def test_fp_bait_annotated_auth_dep_variable(tmp_path: Path) -> None:
    # A type-annotated auth-dep list variable (`_admin: list = [Depends(...)]`) is resolved.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "_admin: list = [Depends(get_current_admin)]\n"
        "router = APIRouter(dependencies=_admin)\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(uid: int):\n"
        "    db.delete(uid)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules

def test_fp_bait_router_construct_with_variable_dependency(tmp_path: Path) -> None:
    # Same-file construction with dependencies= passed as a VARIABLE (not an inline list) is
    # resolved back to its list literal and recognized as auth.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "_auth = [Depends(get_current_user)]\n"
        "router = APIRouter(dependencies=_auth)\n"
        "\n"
        "@router.post('/admin/delete-user')\n"
        "def delete_user(uid: int):\n"
        "    db.delete(uid)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules

def test_cross_file_protection_is_per_router_not_whole_file(tmp_path: Path) -> None:
    # #473 HIGH 1: two routers in one module, only `admin_router` mounted with auth. The
    # resolver used to mark the whole `admin` STEM protected, so the authed router silenced
    # every state-changing route on its unauthed sibling. Protection is per-router.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\n"
        "admin_router = APIRouter()\n"
        "public_router = APIRouter()\n"
        "\n"
        "@public_router.post('/videos')\n"
        "def add_video(url: str):\n"
        "    library.add(url)\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "from auth import get_current_admin\n"
        "app = FastAPI()\n"
        "app.include_router(admin.admin_router, dependencies=[Depends(get_current_admin)])\n"
        "app.include_router(admin.public_router)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules

def test_cross_file_protection_applies_to_the_named_router(tmp_path: Path) -> None:
    # Pair to the above: the route sits on the router that IS mounted with auth, so
    # per-router resolution must still suppress.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\n"
        "admin_router = APIRouter()\n"
        "public_router = APIRouter()\n"
        "\n"
        "@admin_router.post('/videos')\n"
        "def add_video(url: str):\n"
        "    library.add(url)\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "from auth import get_current_admin\n"
        "app = FastAPI()\n"
        "app.include_router(admin.admin_router, dependencies=[Depends(get_current_admin)])\n"
        "app.include_router(admin.public_router)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


# --- #473 x #482 composition: the shared resolver meets the public-by-design exemption ----------
# These two features were developed on separate branches against different versions of this guard
# and had never run together. Both directions, per the review doctrine: the exemption must survive
# the resolver swap, and the resolver must not let the exemption reach a route it does not own.


def test_include_router_kwarg_form_does_not_leak_a_prefix_to_a_local_router(tmp_path: Path) -> None:
    # REGRESSION (a suppression that exists on main today). `_INCLUDE_PREFIX` took the first token
    # after the paren as the router variable, so `include_router(router=admin.router, prefix='/auth')`
    # bound '/auth' to the keyword NAME `router`. The local `router = APIRouter()` then inherited it,
    # and `POST /token` read as `/auth/token` — an exempted route under the ambiguous-verb branch.
    # Measured on main: positional spelling 1 finding, `router=` spelling 0.
    (tmp_path / "admin.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n", encoding="utf-8"
    )
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "import admin\n"
        "app = FastAPI()\n"
        "router = APIRouter()\n"
        "app.include_router(router=admin.router, prefix='/auth')\n"
        "\n"
        "@router.post('/token')\n"
        "def mint_token(body: TokenIn):\n"
        "    return issue(body.user_id)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_include_router_prefix_first_kwarg_order_also_fires(tmp_path: Path) -> None:
    # The third spelling, pinned for invariance rather than as a regression test: verified that this
    # one PASSES against the pre-fix regex too, so it would not have caught the bug. `prefix=` first
    # matched the old regex not at all, and an invisible call in the PREFIX map is fail-closed (no
    # prefix, shorter path, fewer exemptions, the route fires) — the opposite of an invisible call in
    # the base.py AUTH map, where it is a suppression (#473 gate, B6). Right answer, wrong reason;
    # kept so all three spellings are held to the same result.
    (tmp_path / "admin.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n", encoding="utf-8"
    )
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "import admin\n"
        "app = FastAPI()\n"
        "router = APIRouter()\n"
        "app.include_router(prefix='/auth', router=admin.router)\n"
        "\n"
        "@router.post('/token')\n"
        "def mint_token(body: TokenIn):\n"
        "    return issue(body.user_id)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_fp_bait_same_file_include_prefix_still_exempts_its_own_auth_route(tmp_path: Path) -> None:
    # The direction traded against: the prefix map still has to WORK. A same-file bare-var mount
    # carries its prefix to the routes declared on that variable, so `/auth` + `/exchange` reads as
    # `/auth/exchange` and stays exempt. Narrowing the map to bare refs must not cost this.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "router = APIRouter()\n"
        "app.include_router(router, prefix='/auth')\n"
        "\n"
        "@router.post('/exchange')\n"
        "def exchange(code: str):\n"
        "    return swap(code)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_cross_file_protected_router_and_exempt_route_compose(tmp_path: Path) -> None:
    # Composition, quiet direction: a module mounted with auth cross-file (#473) whose sibling
    # router carries a genuine auth-flow route (#482). Both mechanisms say "do not report", and
    # neither may error or double-count. Nothing fires.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\n"
        "admin_router = APIRouter()\n"
        "public_router = APIRouter()\n"
        "\n"
        "@admin_router.post('/admin/act')\n"
        "def act(body: X):\n"
        "    return go(body)\n"
        "\n"
        "@public_router.post('/login')\n"
        "def login(email: str, password: str):\n"
        "    return issue_session(email, password)\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "app = FastAPI()\n"
        "app.include_router(admin.admin_router, dependencies=[Depends(get_current_admin)])\n"
        "app.include_router(admin.public_router)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_cross_file_protection_does_not_borrow_the_exemption_for_a_privileged_sibling(
    tmp_path: Path,
) -> None:
    # Composition, loud direction and the one that matters: the SAME layout, but the bare sibling
    # carries a privileged route rather than an auth-flow one. Neither the cross-file mount of the
    # authed router nor the auth-flow name on a different route may silence it.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\n"
        "admin_router = APIRouter()\n"
        "public_router = APIRouter()\n"
        "\n"
        "@admin_router.post('/admin/act')\n"
        "def act(body: X):\n"
        "    return go(body)\n"
        "\n"
        "@public_router.post('/login')\n"
        "def login(email: str, password: str):\n"
        "    return issue_session(email, password)\n"
        "\n"
        "@public_router.post('/users/{user_id}/role')\n"
        "def set_role(user_id: int, role: str):\n"
        "    return promote(user_id, role)\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import admin\n"
        "app = FastAPI()\n"
        "app.include_router(admin.admin_router, dependencies=[Depends(get_current_admin)])\n"
        "app.include_router(admin.public_router)\n",
        encoding="utf-8",
    )
    found = _guard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(found) == 1
    assert found[0].location.endswith(":14")


# --- the prefix map may not be minted from a dead line (#473 re-gate, HIGH 1) --------------------
# The auth resolvers in base.py go through `router_resolver_view` because a commented-out include
# faked protection. The prefix map was left reading raw source and failed the same way one exemption
# further along: a prefix the app never applies makes the path read as something
# `_is_public_by_design` forgives. Both spellings below reported 0 findings before the fix.

# --- the prefix map may not be minted from a dead line (#473 re-gate, HIGH 1) --------------------
# A prefix the app never applies makes the path read as something `_is_public_by_design` forgives, so
# a prefix read off a commented-out or docstring'd line silences a live route. All three spellings
# below reported 0 findings before the fix.
#
# NOTE: this block covers the PREFIX map only. The AUTH map (`authed_routers`) had the identical
# defect for `dependencies=[...]` and is closed by #532, whose block is below; both now read the
# one shared blanked `view`. The per-route `_AUTH_SIGNAL` pass still reads the raw block, so a
# `# Depends(get_current_user)` in a comment inside a route body still exempts THAT route (blast
# radius one route, not a whole router). PR #473's `_router_resolver_view` supersedes both maps.


def test_commented_out_include_prefix_does_not_exempt_a_live_route(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "router = APIRouter()\n"
        "# app.include_router(router, prefix='/auth')\n"
        "\n"
        "@router.post('/token')\n"
        "def mint_token(body: TokenIn):\n"
        "    return issue(body.user_id)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_docstring_include_prefix_does_not_exempt_a_live_route(tmp_path: Path) -> None:
    # Same defect via the other half of the blanked view: an example mount inside a module docstring.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        '"""Usage:\n'
        "app.include_router(router, prefix='/auth')\n"
        '"""\n'
        "app = FastAPI()\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/token')\n"
        "def mint_token(body: TokenIn):\n"
        "    return issue(body.user_id)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_commented_out_constructor_prefix_does_not_exempt_a_live_route(tmp_path: Path) -> None:
    # The constructor half of the same map (`_ROUTER_PREFIX`), which reads the blanked view too.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "# router = APIRouter(prefix='/auth')\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/token')\n"
        "def mint_token(body: TokenIn):\n"
        "    return issue(body.user_id)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_fp_bait_a_live_prefix_still_exempts_after_the_blanking(tmp_path: Path) -> None:
    # The direction traded against, and the one that made the fix look impossible at first: the
    # prefix VALUE is itself a string literal, so blanking strings could have erased it. It does not
    # — `strip_python_strings` blanks triple-quoted strings only — and a real mount must still exempt.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "router = APIRouter()\n"
        "app.include_router(router, prefix='/auth')\n"
        "\n"
        "@router.post('/exchange')\n"
        "def exchange(code: str):\n"
        "    return swap(code)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


def test_fp_bait_a_live_constructor_prefix_still_exempts_after_the_blanking(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/auth')\n"
        "\n"
        "@router.post('/exchange')\n"
        "def exchange(code: str):\n"
        "    return swap(code)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules


# --- the shared resolver view must use the PYTHON comment helper (#473 re-gate) -------------------
# `router_resolver_view` was built with `strip_hash_comments`, the YAML/shell helper: it needs
# whitespace before a `#` and its single-quote masking is not backslash-escape-aware. Both are wrong
# for Python, and both consumers of the view broke from that one root cause, in OPPOSITE directions.
# Pinned here because a green suite said nothing about either.


def test_escaped_apostrophe_does_not_let_a_router_steal_the_next_prefix(tmp_path: Path) -> None:
    """FAIL-OPEN direction. `\\'` closed the masker's idea of the string early, the `#` truncated the
    line through the router's closing `)`, and `_ROUTER_PREFIX`'s DOTALL `[^)]*` bled into the NEXT
    router and stole its prefix — so `admin_router` carried `/auth`, the route read as `/auth/token`,
    and a genuinely unauthenticated `POST /admin/token` was exempted. Returned 0 before the fix."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "admin_router = APIRouter(description='it\\'s legacy # internal', prefix=\"/admin\")\n"
        "auth_router = APIRouter(prefix=\"/auth\")\n"
        "app.include_router(admin_router)\n"
        "app.include_router(auth_router)\n"
        "\n"
        "@admin_router.post('/token')\n"
        "def mint_admin_token(body: TokenIn):\n"
        "    return issue(body.user_id)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules

# --- the blanked view must not be built with the YAML/shell comment helper (#531 review) ---------
# The first version of the fix above used `strip_hash_comments`, which is correct for YAML/shell and
# wrong for Python in two ways. Both were measured fail-OPEN: a real finding that raw text reported
# vanished. They are pinned here because a fully green suite said nothing about either.


def test_escaped_apostrophe_before_a_hash_does_not_steal_the_next_routers_prefix(
    tmp_path: Path,
) -> None:
    """#531 Critical 1. `strip_hash_comments`' single-quote masking is not backslash-escape-aware,
    so `\\'` closed the string early, the `#` truncated the line through the router's closing `)`,
    and the DOTALL `[^)]*` in `_ROUTER_PREFIX` bled into the NEXT router and stole its prefix.
    `admin_router` then carried `/auth`, the route read as `/auth/token`, and a genuinely
    unauthenticated `POST /admin/token` was exempted. Returns 1 on main, returned 0 with the wrong
    helper."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "admin_router = APIRouter(description='it\\'s legacy # internal', prefix=\"/admin\")\n"
        "auth_router = APIRouter(prefix=\"/auth\")\n"
        "app.include_router(admin_router)\n"
        "app.include_router(auth_router)\n"
        "\n"
        "@admin_router.post('/token')\n"
        "def mint_admin_token(body: TokenIn):\n"
        "    return issue(body.user_id)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


def test_escaped_apostrophe_does_not_hide_a_real_router_dependency(tmp_path: Path) -> None:
    """FAIL-CLOSED direction, same root cause: a genuine `dependencies=[Depends(...)]` sitting after
    the escaped-apostrophe kwarg was truncated away, so the router stopped counting as authed and
    every route on it over-fired. Returned 1 before the fix; must be silent."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter(description='it\\'s legacy # internal', "
        "dependencies=[Depends(require_admin)])\n"
        "\n"
        "@router.post('/admin/wipe')\n"
        "def wipe():\n"
        "    db.drop()\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" not in rules

def test_hash_with_no_leading_whitespace_still_kills_the_dead_prefix(tmp_path: Path) -> None:
    """#531 finding 3. `strip_hash_comments` treats `#` as a comment only at line-start or after
    whitespace (the YAML/shell rule); Python has no such rule, so `x = 1#...` kept the commented-out
    include alive and it minted a phantom prefix. One space apart from the case above it."""
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "router = APIRouter()\n"
        "x = 1#app.include_router(router, prefix='/auth')\n"
        "\n"
        "@router.post('/token')\n"
        "def mint_token(body: TokenIn):\n"
        "    return issue(body.user_id)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}
    assert "auth-dependency-not-applied/no-auth-dependency" in rules


# --- #532: a DEAD `dependencies=` may not populate the router-auth map ------------------------------
# The map is keyed by router variable, so one non-executable line silenced EVERY state-changing route
# on that router, with exit 0 and no skip. Five shapes reach the same branch. The five fires-tests
# below are the widening; the four stays-silent tests after them are the direction it trades against
# and are the mandatory half (CLAUDE.md rule 1). Every fires-test here was measured red against the
# unpatched guard before it was kept — a fires-test that is green both before and after proves
# nothing, and the first draft of the trailing-comment case was exactly that.

_DEAD_LINE_ROUTE = (
    "\n"
    "@router.post('/admin/delete-user')\n"
    "def delete_user(uid: int):\n"
    "    db.delete(uid)\n"
)


def _dead_line_rules(tmp_path: Path) -> set[str]:
    return {f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))}


def test_commented_out_include_router_dependencies_does_not_exempt(tmp_path: Path) -> None:
    # Shape A: the mount that carried the auth was commented out during a refactor and the live
    # mount below it is bare. The route is genuinely unauthenticated.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends, FastAPI\n"
        "router = APIRouter()\n"
        + _DEAD_LINE_ROUTE
        + "\n"
        "app = FastAPI()\n"
        "# app.include_router(router, dependencies=[Depends(get_current_user)])\n"
        "app.include_router(router)\n",
        encoding="utf-8",
    )
    assert "auth-dependency-not-applied/no-auth-dependency" in _dead_line_rules(tmp_path)


def test_commented_out_router_constructor_dependencies_does_not_exempt(tmp_path: Path) -> None:
    # Shape B: the constructor spelling of A.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "# router = APIRouter(dependencies=[Depends(get_current_user)])\n"
        "router = APIRouter()\n"
        + _DEAD_LINE_ROUTE,
        encoding="utf-8",
    )
    assert "auth-dependency-not-applied/no-auth-dependency" in _dead_line_rules(tmp_path)


def test_dependencies_inside_a_docstring_does_not_exempt(tmp_path: Path) -> None:
    # Shape C: a module docstring showing how to wire the router. Documentation is not wiring.
    (tmp_path / "app.py").write_text(
        '"""Admin routes.\n'
        "\n"
        "Mount with::\n"
        "\n"
        "    app.include_router(router, dependencies=[Depends(get_current_user)])\n"
        '"""\n'
        "from fastapi import APIRouter, FastAPI\n"
        "router = APIRouter()\n"
        + _DEAD_LINE_ROUTE
        + "\n"
        "app = FastAPI()\n"
        "app.include_router(router)\n",
        encoding="utf-8",
    )
    assert "auth-dependency-not-applied/no-auth-dependency" in _dead_line_rules(tmp_path)


def test_trailing_comment_carrying_dead_dependencies_does_not_exempt(tmp_path: Path) -> None:
    # Shape D: a trailing `#` comment INSIDE an open multi-line mount, naming the auth that was
    # removed. The comment must be inside the parens to reach this branch — the map regexes scan
    # `[^)]*` from `include_router(`, so a comment after the call has already closed cannot be
    # swept in and never could (measured: it fires on the unpatched guard too). Do not "simplify"
    # this fixture to a single-line `include_router(router)  # dependencies=[...]`; that shape is
    # green before the fix and the test stops proving anything.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "router = APIRouter()\n"
        + _DEAD_LINE_ROUTE
        + "\n"
        "app = FastAPI()\n"
        "app.include_router(\n"
        "    router,  # was: dependencies=[Depends(get_current_user)]\n"
        ")\n",
        encoding="utf-8",
    )
    assert "auth-dependency-not-applied/no-auth-dependency" in _dead_line_rules(tmp_path)


def test_live_include_router_dependencies_still_exempts(tmp_path: Path) -> None:
    # FP bait for shape A: real router-level auth must still suppress after the widening.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends, FastAPI\n"
        "router = APIRouter()\n"
        + _DEAD_LINE_ROUTE
        + "\n"
        "app = FastAPI()\n"
        "app.include_router(router, dependencies=[Depends(get_current_user)])\n",
        encoding="utf-8",
    )
    assert "auth-dependency-not-applied/no-auth-dependency" not in _dead_line_rules(tmp_path)


def test_live_router_constructor_dependencies_still_exempts(tmp_path: Path) -> None:
    # FP bait for shape B.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter(dependencies=[Depends(get_current_user)])\n"
        + _DEAD_LINE_ROUTE,
        encoding="utf-8",
    )
    assert "auth-dependency-not-applied/no-auth-dependency" not in _dead_line_rules(tmp_path)


def test_live_multiline_include_with_per_argument_comments_still_exempts(tmp_path: Path) -> None:
    # FP bait: blanking the comments must not break a match that spans the blanked lines — the
    # helper truncates each line at its `#` and keeps the newline, so the kwarg is still there.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends, FastAPI\n"
        "router = APIRouter()\n"
        + _DEAD_LINE_ROUTE
        + "\n"
        "app = FastAPI()\n"
        "app.include_router(\n"
        "    router,  # the admin router\n"
        "    prefix='/admin',  # mounted under /admin\n"
        "    dependencies=[Depends(get_current_user)],  # every route is authed\n"
        ")\n",
        encoding="utf-8",
    )
    assert "auth-dependency-not-applied/no-auth-dependency" not in _dead_line_rules(tmp_path)


def test_dead_dependencies_with_no_space_before_the_hash_does_not_exempt(tmp_path: Path) -> None:
    # The shape that pins the helper choice. `strip_hash_comments` (the YAML/shell helper) treats
    # `#` as a comment only at line-start or after WHITESPACE, so `router,#...` is not a comment to
    # it and the dead kwarg survives into the map — fail-open, the exact regression #531's review
    # measured. Swap `strip_python_line_comment` for it in `_scan` and this test, alone, goes red.
    # (Measured three ways: unpatched 0, patched 1, strip_hash_comments variant 0.)
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends, FastAPI\n"
        "router = APIRouter()\n"
        + _DEAD_LINE_ROUTE
        + "\n"
        "app = FastAPI()\n"
        "app.include_router(\n"
        "    router,#was dependencies=[Depends(get_current_user)]\n"
        ")\n",
        encoding="utf-8",
    )
    assert "auth-dependency-not-applied/no-auth-dependency" in _dead_line_rules(tmp_path)


def test_hash_inside_a_string_literal_does_not_truncate_the_live_deps(tmp_path: Path) -> None:
    # FP bait for the opposite helper mistake: a naive `line.split("#", 1)[0]` clips the line at the
    # `#` inside `tags=["#admin"]`, dropping the live `dependencies=` after it and turning real
    # router-level auth into a false positive. Both real helpers mask string spans and keep it.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends, FastAPI\n"
        "router = APIRouter()\n"
        + _DEAD_LINE_ROUTE
        + "\n"
        "app = FastAPI()\n"
        "app.include_router(router, tags=[\"#admin\"], "
        "dependencies=[Depends(get_current_user)])\n",
        encoding="utf-8",
    )
    assert "auth-dependency-not-applied/no-auth-dependency" not in _dead_line_rules(tmp_path)


# --- #532 also NARROWS, and rule 1 wants that direction pinned too ---------------------------------
# Blanking triple-quoted strings deletes the `(` / `)` inside them, so the DOTALL `[^)]*` in
# `_ROUTER_WITH_DEPENDENCIES` is no longer truncated by a paren that lives in a docstring. A live
# `dependencies=` sitting AFTER a multi-line `description="""..."""` therefore becomes reachable and
# the router is correctly recognized as authed: measured 1 finding on main, 0 after the fix. That is
# a false positive being removed, which is the right outcome, but it is findings DISAPPEARING and the
# four-repo FP evidence does not cover it (the shape did not occur there). So it gets both halves:
# the narrowing locked, and the vulnerable neighbour proven to still fire (#537 review, Medium 2).


def test_live_deps_after_a_multiline_description_is_recognized_as_authed(tmp_path: Path) -> None:
    # The narrowing itself: a paren inside the docstring used to truncate the match, so the live
    # router-level auth went unseen and the route was reported. It must stay silent now.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter(\n"
        '    description="""\n'
        "    Admin routes (privileged surface).\n"
        '    """,\n'
        "    dependencies=[Depends(get_current_user)],\n"
        ")\n"
        + _DEAD_LINE_ROUTE,
        encoding="utf-8",
    )
    assert "auth-dependency-not-applied/no-auth-dependency" not in _dead_line_rules(tmp_path)


def test_a_multiline_description_without_deps_still_fires(tmp_path: Path) -> None:
    # The direction the narrowing trades against, and the mandatory half: the SAME docstring shape
    # with no `dependencies=` anywhere must still report. If blanking ever let a match run past the
    # router's own closing `)` and pick up another router's auth, this is the test that goes red.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter(\n"
        '    description="""\n'
        "    Admin routes (privileged surface).\n"
        '    """,\n'
        '    tags=["admin"],\n'
        ")\n"
        + _DEAD_LINE_ROUTE
        + "\n"
        "other = APIRouter(dependencies=[Depends(get_current_user)])\n",
        encoding="utf-8",
    )
    assert "auth-dependency-not-applied/no-auth-dependency" in _dead_line_rules(tmp_path)


def test_auth_dependency_factory_registered_route_reports_once(tmp_path: Path) -> None:
    # Issue #502: the factory's block contains the nested route's decorator, so
    # `_STATE_CHANGING_ROUTE` matched the factory too and one route was reported twice.
    (tmp_path / "r.py").write_text(
        "def make_router():\n"
        "    router = APIRouter()\n"
        "    @router.post('/admin/delete')\n"
        "    async def delete_user(user_id: str):\n"
        "        return db.delete(user_id)\n"
        "    return router\n",
        encoding="utf-8",
    )
    findings = AuthDependencyNotAppliedGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":4")     # the route, not the factory at :1

def test_auth_dependency_factory_registered_authed_route_silent(tmp_path: Path) -> None:
    # FP-bait: a factory-registered route that DOES carry an auth dependency stays silent.
    (tmp_path / "r.py").write_text(
        "def make_router():\n"
        "    router = APIRouter()\n"
        "    @router.post('/admin/delete')\n"
        "    async def delete_user(user_id: str, user=Depends(get_current_user)):\n"
        "        return db.delete(user_id)\n"
        "    return router\n",
        encoding="utf-8",
    )
    assert AuthDependencyNotAppliedGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_auth_dependency_nested_sibling_route_does_not_cover_the_outer(tmp_path: Path) -> None:
    # Rule 1 lock on the WIDENING #502's fix causes, found by the #605 gate. Two routes that are
    # each registered in their own right, one nested inside the other. The outer has no auth; the
    # inner does. Before the blanking, the inner's `Depends(...)` sat inside the outer's scanned
    # block and was read as the OUTER's auth signal, so an unauthenticated state-changing route
    # reported nothing at all.
    #
    # Measured origin/main -> 0 findings, HEAD -> 1 at the outer. This test therefore
    # discriminates: it fails against the unfixed code.
    (tmp_path / "r.py").write_text(
        "@router.post('/admin/delete')\n"
        "async def delete_outer(user_id: str):\n"
        "    @router.post('/admin/delete2')\n"
        "    async def delete_inner(user_id: str, user=Depends(get_current_user)):\n"
        "        return db.delete(user_id)\n"
        "    return db.delete(user_id)\n",
        encoding="utf-8",
    )
    findings = AuthDependencyNotAppliedGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":2")     # the OUTER route, whose auth is genuinely absent

def test_auth_dependency_outer_route_auth_does_not_cover_a_nested_sibling(tmp_path: Path) -> None:
    # The FP-bait mirror of the above, and the evidence that the widening is a RECOVERY rather than
    # a new false positive: with the auth on the outer instead, exactly one finding still lands, on
    # the inner route that really has none. Unlike its twin this shape reports 1 on both old and new
    # code — it is here to pin that the blanking did not start moving findings around, not to
    # discriminate.
    (tmp_path / "r.py").write_text(
        "@router.post('/admin/delete')\n"
        "async def delete_outer(user_id: str, user=Depends(get_current_user)):\n"
        "    @router.post('/admin/delete2')\n"
        "    async def delete_inner(user_id: str):\n"
        "        return db.delete(user_id)\n"
        "    return db.delete(user_id)\n",
        encoding="utf-8",
    )
    findings = AuthDependencyNotAppliedGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":4")     # the INNER route


# --- #538: dead text that still reached the router views --------------------------------------------
# #532 blanked comments and docstrings out of the router-auth view; two shapes still got through, and
# both silenced EVERY route on the router (0 findings where the control has 2), plus the prefix map.
#   A: a comment on the CLOSING line of a multi-line triple-quoted string. The per-line comment masker
#      paired the leftover delimiter quote with a quote inside the comment and hid the `#`. Comments
#      are now located by the tokenizer.
#   B: an ordinary single-line string. Only triple-quoted strings were blanked. The resolvers now
#      match on `router_code_view` (one-line string CONTENT blanked too); a value such as `prefix=`
#      is read from the offset-aligned `router_resolver_view`.
# Both are WIDENINGS, so every fires-test below has an FP-bait partner (CLAUDE.md rule 1). Each
# fires-test was measured 0 on the unpatched tree (`ca759244`) before it was kept.

_TWO_ROUTES = (
    "\n"
    "@widgets.post('/widgets/bulk-delete')\n"
    "async def wipe_widgets(payload: dict):\n"
    "    return {'ok': True}\n"
    "\n"
    "@widgets.delete('/widgets/{wid}')\n"
    "async def drop_widget(wid: str):\n"
    "    return {'ok': True}\n"
)


def _count(tmp_path: Path) -> int:
    return len(_guard().run(tmp_path, _fastapi_prof(tmp_path)))


@pytest.mark.parametrize("quote", ['"""', "'''"])
@pytest.mark.parametrize(
    "dead",
    [
        "widgets = APIRouter(dependencies=[Depends(admin)])",
        "app.include_router(widgets, dependencies=[Depends(admin)])",
    ],
)
def test_dependencies_in_a_comment_on_a_triple_quote_closing_line_do_not_exempt(
    tmp_path: Path, quote: str, dead: str
) -> None:
    # Shape A. The comment must carry a quote of the SAME character as the delimiter, which is what
    # the masker pairs with; `""" # don't ...` never reproduced, and is how the wiki came to record
    # this as not reproducible.
    q = quote[0]
    (tmp_path / "widgets.py").write_text(
        "from fastapi import APIRouter, Depends, FastAPI\n"
        "app = FastAPI()\n"
        "widgets = APIRouter()\n"
        f"DOC = {quote}\n"
        "Widget routes.\n"
        f"{quote}  # TODO restore the {q}admin{q} gate: {dead}\n"
        + _TWO_ROUTES,
        encoding="utf-8",
    )
    assert _count(tmp_path) == 2


def test_include_prefix_in_a_comment_on_a_triple_quote_closing_line_does_not_exempt(
    tmp_path: Path,
) -> None:
    # Shape A through the PREFIX map: a phantom `/auth` turns a bare `POST /token` into `/auth/token`,
    # which the auth-flow exemption forgives.
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n"
        "router = APIRouter()\n"
        'DOC = """\n'
        "Token routes.\n"
        '"""  # app.include_router(router, prefix="/auth") was the "old" wiring\n'
        "\n"
        "@router.post('/token')\n"
        "async def mint(payload: dict):\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    assert _count(tmp_path) == 1


@pytest.mark.parametrize(
    "dead",
    [
        'HINT = "wire it as widgets = APIRouter(dependencies=[Depends(get_current_user)])"\n',
        "HINT = 'wire it as widgets = APIRouter(dependencies=[Depends(get_current_user)])'\n",
        'HINT = f"wire {1} as widgets = APIRouter(dependencies=[Depends(get_current_user)])"\n',
        'HINT = "app.include_router(widgets, dependencies=[Depends(get_current_user)])"\n',
        # implicit concatenation across rows: neither piece is a call on its own row
        'HINT = ("wire it as widgets = APIRouter("\n'
        '        "dependencies=[Depends(get_current_user)])")\n',
        "def fail():\n"
        '    raise RuntimeError("use widgets = APIRouter(dependencies=[Depends(get_current_user)])")\n',
        # an LLM prompt constant, the likeliest place for this text in an AI app
        'PROMPT = "Answer as an API reviewer. Example: widgets = APIRouter('
        'dependencies=[Depends(get_current_user)])"\n',
        # inside a LIVE construction's own string argument: the router is real, its auth is not.
        # The vulnerable neighbour of the `string-spells-deps` narrowing below.
        'widgets = APIRouter(description="lock it with dependencies=[Depends(get_current_user)]")\n',
        # an f-string whose replacement field spans rows (PEP 701). The literal text around the field
        # is dead; only the field is code (#1017 review, High 1: the whole literal used to be kept).
        'HINT = f"widgets = APIRouter(dependencies=[Depends(get_current_user)]) {\n'
        "    name\n"
        '} tail"\n',
        # a string, and an f-string, inside such a field: still literals, wherever they sit
        'HINT = f"{\n'
        "    'widgets = APIRouter(dependencies=[Depends(get_current_user)])'\n"
        '}"\n',
        'HINT = f"{\n'
        "    f'widgets = APIRouter(dependencies=[Depends(get_current_user)]) {name}'\n"
        '}"\n',
    ],
    ids=["dq", "sq", "fstring", "include", "concat", "raise", "prompt", "inside-live-call",
         "multirow-fstring", "string-in-multirow-field", "fstring-in-multirow-field"],
)
def test_dependencies_inside_a_one_line_string_do_not_exempt(tmp_path: Path, dead: str) -> None:
    # Shape B. The identical text inside a triple-quoted string was always handled.
    (tmp_path / "widgets.py").write_text(
        "from fastapi import APIRouter, Depends, FastAPI\n"
        "app = FastAPI()\n"
        "widgets = APIRouter()\n" + dead + _TWO_ROUTES,
        encoding="utf-8",
    )
    assert _count(tmp_path) == 2


@pytest.mark.parametrize(
    "dead",
    [
        "HINT = \"router = APIRouter(prefix='/auth')\"\n",
        "HINT = \"app.include_router(router, prefix='/auth')\"\n",
        # a `prefix=` spelled inside a LIVE call's string argument is not that router's prefix
        "",
    ],
    ids=["ctor", "include", "inside-live-call"],
)
def test_router_prefix_inside_a_one_line_string_does_not_exempt(tmp_path: Path, dead: str) -> None:
    ctor = (
        "router = APIRouter(description=\"was prefix='/auth'\")\n"
        if not dead else "router = APIRouter()\n"
    )
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n" + ctor + dead
        + "\n"
        "@router.post('/token')\n"
        "async def mint(payload: dict):\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    assert _count(tmp_path) == 1


def test_cross_file_mount_inside_a_one_line_string_does_not_exempt_multi_file(
    tmp_path: Path,
) -> None:
    # Shape B through the CROSS-FILE resolver: `main.py` quotes the mount it does not perform.
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "admin.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n" + _DEAD_LINE_ROUTE,
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from routes import admin\n"
        "app = FastAPI()\n"
        'HINT = "app.include_router(admin.router, dependencies=[Depends(get_current_user)])"\n'
        "app.include_router(admin.router)\n",
        encoding="utf-8",
    )
    assert _count(tmp_path) == 1


# The direction A and B trade against: LIVE router auth and LIVE prefixes that sit beside a comment or
# a string must still be seen. A view that blanked too much (code, quotes, or a whole row) goes red here.


@pytest.mark.parametrize(
    "router",
    [
        # a string that SPELLS a deps list, beside the live one. Also a NARROWING (#538): on the
        # unpatched tree the lazy `dependencies=` scan stopped at the empty list inside the string and
        # the authed router over-fired (2 -> 0). Its vulnerable neighbour, the same string with no
        # live deps, is the `inside-live-call` fires case above.
        'widgets = APIRouter(description="set dependencies=[] to open it",'
        " dependencies=[Depends(get_current_user)])\n",
        # a `#` and quotes inside strings, and a closing-line comment just above
        'DOC = """\nx\n"""  # see the "admin" docs\n'
        'widgets = APIRouter(tags=["#admin", "it\'s"], dependencies=[Depends(get_current_user)])\n',
        # a one-line string continued across rows by a backslash, right before the router
        'NOTE = "first \\\nsecond"\n'
        "widgets = APIRouter(dependencies=[Depends(get_current_user)])\n",
        # an f-string whose replacement field spans rows
        'NOTE = f"{len(\n[1])}"\n'
        "widgets = APIRouter(dependencies=[Depends(get_current_user)])\n",
        # ...with literal text around the field, a nested f-string and `{{` escapes: the field is kept
        # as code and the text is blanked, and the live router after it must still be seen
        'NOTE = f"see {\n    f\'{name!r:>{width}}\'\n} for {{details}}, dependencies=[] (sic)"\n'
        "widgets = APIRouter(dependencies=[Depends(get_current_user)])\n",
        # the deps bound to a variable (the #538 FP item, fixed by #473)
        "ADMIN_DEPS = [Depends(require_admin)]\n"
        'widgets = APIRouter(dependencies=ADMIN_DEPS, description="(deps)")\n',
    ],
    ids=["string-spells-deps", "hash-in-strings", "backslash-continued", "multirow-fstring",
         "multirow-fstring-with-text", "var"],
)
def test_fp_bait_live_router_auth_beside_dead_text_still_exempts(
    tmp_path: Path, router: str
) -> None:
    (tmp_path / "widgets.py").write_text(
        "from fastapi import APIRouter, Depends\n" + router + _TWO_ROUTES,
        encoding="utf-8",
    )
    assert _count(tmp_path) == 0


def test_conditional_mount_still_fires_when_the_file_has_strings(tmp_path: Path) -> None:
    # The code view must still PARSE: `_conditional_lines` reads it with `ast`, and if blanking a
    # string ever left it unparseable, the mount under the `if` would silently count as protection.
    # So the file carries every literal shape the blanker has to keep parseable.
    (tmp_path / "app.py").write_text(
        "from fastapi import APIRouter, Depends, FastAPI\n"
        "router = APIRouter()\n" + _DEAD_LINE_ROUTE
        + "\n"
        'A = "first \\\nsecond"\n'
        'B = f"{len(\n[1])} and {{braces}} and {A!r:>10}"\n'
        "C = rb'\\x00' + u'\\u00e9' + 'it\\'s'\n"
        # a multi-row field with text around it, a comment inside the field, a nested f-string and a
        # continued literal run: the field must survive whole, every row break included
        'D = f"x {\n    f\'{A!r:>{len(B)}}\'  # why\n} y \\\nz"\n'
        "app = FastAPI()\n"
        "if settings.ENABLE_AUTH:\n"
        "    app.include_router(router, dependencies=[Depends(get_current_user)])\n",
        encoding="utf-8",
    )
    assert _count(tmp_path) == 1


@pytest.mark.parametrize(
    "router",
    [
        'router = APIRouter(prefix="/auth")\n',
        "router = APIRouter()\napp.include_router(router, prefix='/auth')\n",
        # NARROWING (#538): a `)` inside a string before `prefix=` used to end the `[^)]*` scan, so the
        # live prefix went unseen and `/auth/token` over-fired as `/token`. Its vulnerable neighbour
        # is pinned below.
        'router = APIRouter(description="Auth routes (v2)", prefix="/auth")\n',
    ],
    ids=["ctor", "include", "paren-in-string"],
)
def test_fp_bait_a_live_prefix_still_exempts_through_the_code_view(
    tmp_path: Path, router: str
) -> None:
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter, FastAPI\n"
        "app = FastAPI()\n" + router
        + "\n"
        "@router.post('/token')\n"
        "async def mint(payload: dict):\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    assert _count(tmp_path) == 0


@pytest.mark.parametrize("ending", ["\n", ""], ids=["final-newline", "no-final-newline"])
def test_dead_string_on_the_last_line_does_not_exempt_with_or_without_a_final_newline(
    tmp_path: Path, ending: str
) -> None:
    # #1017 re-review, Critical 1: a file with no final newline lost its token stream and fell back
    # to the pre-#538 view, so a dead one-line string on any line minted the auth map again (0
    # findings with no final newline, 1 with one). Written as bytes so nothing adds the newline back.
    (tmp_path / "api.py").write_bytes(
        (
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "\n"
            '@router.post("/admin/purge")\n'
            "def purge(body: dict):\n"
            "    return act(body)\n"
            'HINT = "router = APIRouter(dependencies=[Depends(require_admin)])"' + ending
        ).encode("utf-8")
    )
    assert _count(tmp_path) == 1


def test_a_paren_in_a_string_does_not_let_a_prefix_bleed_from_the_next_router(tmp_path: Path) -> None:
    # The direction the paren-in-string narrowing trades against: with no `prefix=` of its own, the
    # router must not pick up the NEXT router's `/auth` now that the string's `)` no longer stops the
    # scan. The real `)` closing the call has to.
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\n"
        'router = APIRouter(description="Admin routes (v2)", tags=["admin"])\n'
        'auth = APIRouter(prefix="/auth")\n'
        "\n"
        "@router.post('/token')\n"
        "async def mint(payload: dict):\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    assert _count(tmp_path) == 1


# --- #538 (carried from #510): a SUBJECT parameter after a subject-acting auth verb ----------------
# Both exemption branches used to inspect only parameters BEFORE the auth verb, so on a verb-first
# route every trailing parameter read as the emailed-link credential. Closed for the verbs that act
# on the subject a trailing parameter names; the session-creating and request verbs stay exempt, a
# disclosed trade (`/login/{username}` and `/login/{sns_type}` are common public logins). The fires
# list is the widening, the silent list the direction it trades against.


@pytest.mark.parametrize(
    ("path", "handler"),
    [
        ("/logout/{user_id}", "end_session"),
        ("/signout/{user_id}", "end_session"),
        ("/auth/logout/{user_id}", "end_session"),
        ("/reset-password/{user_id}", "do_reset"),
        ("/refresh-token/{user_id}", "do_refresh"),
        ("/auth/token/{user_id}", "mint"),
        ("/auth/refresh/{user_id}", "mint"),
        ("/auth/verify/{user_id}", "mark"),
        ("/auth/confirm/{email}", "mark"),
        ("/logout/{session_id}", "end_session"),  # fail-closed: a session id is not on the list
        ("/sessions/{user_id}", "logout"),        # the verb carried by the handler name
        # an IDENTIFIER that merely ends in a credential word is a subject, not a credential: a
        # bare-suffix match used to exempt every one of these (#1017 review, High 2)
        ("/logout/{employee_code}", "end_session"),
        ("/auth/token/{dealer_code}", "mint"),
        ("/logout/{file_hash}", "end_session"),
        ("/reset-password/{country_code}", "do_reset"),
        ("/logout/{invite_id}", "end_session"),
        # a QUALIFIER word is not a credential context on its own: it counts only in front of one
        # (`account_recovery_token`), so the identifiers it also starts still fire (#1017 re-review,
        # the direction the compound-name narrowing trades against)
        ("/logout/{account_code}", "end_session"),
        ("/auth/token/{user_token}", "mint"),
        ("/reset-password/{account_id}", "do_reset"),
    ],
)
def test_subject_acting_auth_verb_with_a_trailing_subject_param_fires(
    tmp_path: Path, path: str, handler: str
) -> None:
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        f'@router.post("{path}")\n'
        f"def {handler}(body: dict): return act(body)\n",
        encoding="utf-8",
    )
    assert _count(tmp_path) == 1, path


@pytest.mark.parametrize(
    ("path", "handler"),
    [
        # session-creating verbs: the trailing parameter names the account the caller claims
        ("/login/{user_id}", "handler"),
        ("/login/{username}", "handler"),
        ("/login/{sns_type}", "handler"),
        ("/register/{role}", "handler"),
        ("/oauth/{user_id}", "handler"),
        ("/users/{uid}", "login"),
        # request verbs: they send to the subject's own mailbox
        ("/forgot-password/{email}", "handler"),
        ("/magic-link/{email}", "handler"),
        # a trailing CREDENTIAL, alone or beside the account it is for
        ("/reset-password/{resetToken}", "handler"),
        ("/password-reset/{uidb64}/{token}", "handler"),
        ("/reset-password/{uid}/{token}", "handler"),
        ("/logout/{token}", "handler"),
        ("/auth/verify/{code}", "handler"),
        ("/auth/exchange/{code}", "handler"),
        # a credential word after a CREDENTIAL context, snake or camel case
        ("/reset-password/{reset_token}", "handler"),
        ("/auth/verify/{verification_code}", "handler"),
        ("/auth/verify/{inviteCode}", "handler"),
        ("/auth/confirm/{key}", "handler"),
        ("/logout/{session_token}", "handler"),
        ("/auth/token/{api_key}", "handler"),
        ("/auth/confirm/{invitation}", "handler"),
        # compound credential names: a qualifier and up to two contexts before the credential word
        # (#1017 re-review, Medium 2: the single-context pattern fired on every one of these)
        ("/reset-password/{password_reset_token}", "handler"),
        ("/auth/verify/{email_verification_code}", "handler"),
        ("/auth/verify/{two_factor_code}", "handler"),
        ("/auth/token/{oauth_access_token}", "handler"),
        ("/reset-password/{account_recovery_token}", "handler"),
        ("/auth/confirm/{signup_confirmation_code}", "handler"),
        ("/auth/verify/{userActivationCode}", "handler"),
        # trailing deployment scaffolding, and protocol steps that are not inspected
        ("/logout/{provider}", "handler"),
        ("/auth/callback/{provider}", "handler"),
        ("/auth/authorize/{client_id}", "handler"),
        # no trailing parameter at all
        ("/logout", "handler"),
        ("/sessions", "logout"),
    ],
)
def test_verb_first_routes_that_stay_public_by_design(
    tmp_path: Path, path: str, handler: str
) -> None:
    (tmp_path / "api.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        f'@router.post("{path}")\n'
        f"def {handler}(body: dict): return act(body)\n",
        encoding="utf-8",
    )
    assert _count(tmp_path) == 0, path


def test_auth_dependency_not_applied_pragma_quoted_in_a_string_in_the_route_still_fires(
    tmp_path: Path,
) -> None:
    # #1040: the pragma quoted in a string in the route body is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-unauthenticated-route"):
        (tmp_path / "app.py").write_text(
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "\n"
            "@router.post('/admin/create-item')\n"
            "def create_item(name: str, price: int):\n"
            f'    _note = "{note}"\n'
            "    save_item(name, price)\n",
            encoding="utf-8",
        )
        rules = [f.rule for f in _guard().run(tmp_path, _fastapi_prof(tmp_path))]
        assert rules.count("auth-dependency-not-applied/no-auth-dependency") == 1, note
