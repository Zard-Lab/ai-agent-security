from __future__ import annotations

from agentsec.guards.bola import BolaGuard
from tests.guards._common import *  # noqa: F401,F403


def test_bola_flags_unscoped_route_fetch(tmp_path: Path) -> None:
    (tmp_path / "r.py").write_text(
        "router = APIRouter()\n\n\n"
        "@router.get('/orders/{order_id}')\n"
        "async def get_order(order_id: str):\n    return Order.query.get(order_id)\n", encoding="utf-8"
    )
    findings = BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bola/unscoped-object-fetch"
    assert findings[0].severity == "medium"

def test_bola_passes_with_ownership_check(tmp_path: Path) -> None:
    (tmp_path / "r.py").write_text(
        "@router.get('/orders/{order_id}')\n"
        "async def get_order(order_id: str, current_user=Depends(get_current_user)):\n"
        "    return Order.query.filter_by(id=order_id, user_id=current_user.id).first()\n", encoding="utf-8"
    )
    assert BolaGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_bola_passes_with_auth_dependency_only(tmp_path: Path) -> None:
    # a Depends(...) auth dependency is enough of a signal to stay silent (surfacing guard)
    (tmp_path / "r.py").write_text(
        "@app.get('/items/{item_id}')\n"
        "def read_item(item_id: int, user=Depends(require_auth)):\n    return db.get(item_id)\n", encoding="utf-8"
    )
    assert BolaGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_bola_fires_with_only_a_db_dependency(tmp_path: Path) -> None:
    # Regression (#307): a bare non-auth `Depends(get_db)` is NOT an auth/ownership signal — an
    # unscoped fetch whose only dependency is a DB session must still fire.
    (tmp_path / "r.py").write_text(
        "@router.get('/orders/{order_id}')\n"
        "def get_order(order_id: str, session=Depends(get_db)):\n"
        "    return Order.query.get(order_id)\n", encoding="utf-8"
    )
    findings = BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1 and findings[0].rule == "bola/unscoped-object-fetch"

def test_bola_passes_with_aliased_auth_dependency(tmp_path: Path) -> None:
    # Regression (#307 flagship): auth wired via a module-level DI alias (`admin = AdminReadDep`,
    # where `AdminReadDep = Depends(verify_admin)` is defined elsewhere) must suppress — the guard
    # can't see the alias's definition, so it recognizes the auth-named `*Dep` identifier.
    (tmp_path / "r.py").write_text(
        "@router.get('/admin/audit-logs/{log_id}')\n"
        "def get_log(log_id: str, admin=AdminReadDep):\n"
        "    return AuditLog.query.get(log_id)\n", encoding="utf-8"
    )
    assert BolaGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_bola_passes_non_route_function(tmp_path: Path) -> None:
    # a plain helper that fetches by id is not a route handler -> not BOLA
    (tmp_path / "r.py").write_text("def load(order_id):\n    return Order.query.get(order_id)\n", encoding="utf-8")
    assert BolaGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_bola_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "r.py").write_text(
        "@router.get('/orders/{order_id}')  # security: allow-unscoped-fetch\n"
        "async def get_order(order_id: str):\n    return Order.query.get(order_id)\n", encoding="utf-8"
    )
    assert BolaGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_bola_flags_route_with_comment_between_decorator_and_def(tmp_path: Path) -> None:
    # Issue #272: a comment/blank between the route decorator and `def` used to truncate the
    # walk-up, dropping @router.get and making the BOLA-shaped route invisible (false negative).
    # The shared iter_functions() buffers such lines, so the route must fire now.
    (tmp_path / "r.py").write_text(
        "router = APIRouter()\n\n"
        "@router.get('/orders/{order_id}')\n"
        "# fetch one order\n"
        "def get_order(order_id: str):\n"
        "    return Order.query.get(order_id)\n",
        encoding="utf-8",
    )
    findings = BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bola/unscoped-object-fetch"


def test_bola_flags_route_with_multiline_decorator(tmp_path: Path) -> None:
    # bola shares iter_functions() with auth-dependency-not-applied. A wrapped decorator call used
    # to break the walk-up and make the route invisible (silent false negative). It must fire now.
    # (PR #268 agentic re-review, Critical — shared walker.)
    (tmp_path / "r.py").write_text(
        "router = APIRouter()\n\n\n"
        "@router.get(\n"
        "    '/orders/{order_id}',\n"
        "    response_model=Order,\n"
        ")\n"
        "async def get_order(order_id: str):\n    return Order.query.get(order_id)\n",
        encoding="utf-8",
    )
    findings = BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bola/unscoped-object-fetch"


def test_bola_flags_route_with_triple_quoted_description(tmp_path: Path) -> None:
    # PR #268 round-2 review (Critical, shared iter_functions): a stray bracket inside a triple-quoted
    # OpenAPI description in the decorator used to skew bracket balance and drop the route. It must
    # still be analyzed (and fire, since the fetch is unscoped).
    (tmp_path / "r.py").write_text(
        "router = APIRouter()\n\n"
        "@router.get(\n"
        "    '/orders/{order_id}',\n"
        "    description=\"\"\"\n"
        "    fetch one order (see foo(bar for the id format)\n"
        "    \"\"\",\n"
        ")\n"
        "async def get_order(order_id: str):\n    return Order.query.get(order_id)\n",
        encoding="utf-8",
    )
    findings = BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bola/unscoped-object-fetch"


def test_bola_na_without_fastapi() -> None:
    assert BolaGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False


def test_bola_fires_on_non_auth_substring_lookalike_dependency(tmp_path: Path) -> None:
    # Regression (#307 High): the auth signal matches auth stems at identifier-segment boundaries,
    # not as raw substrings. `Depends(get_tokenizer)` (token is not the segment `token`) is NOT an
    # auth dependency, so an unscoped fetch alongside it must still fire (was false-suppressed).
    (tmp_path / "r.py").write_text(
        "@router.get('/orders/{order_id}')\n"
        "def get_order(order_id: str, tok=Depends(get_tokenizer)):\n"
        "    return Order.query.get(order_id)\n", encoding="utf-8"
    )
    findings = BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1 and findings[0].rule == "bola/unscoped-object-fetch"


def test_bola_fires_with_only_a_db_alias_dependency(tmp_path: Path) -> None:
    # Regression (#307 Low): the alias fragment's headline guarantee — a bare DB *alias*
    # (`session = DbDep`, not an auth stem) is not an auth signal and must still fire — was only
    # covered for the inline `Depends(get_db)` form, not the alias form.
    (tmp_path / "r.py").write_text(
        "@router.get('/orders/{order_id}')\n"
        "def get_order(order_id: str, session=DbDep):\n"
        "    return Order.query.get(order_id)\n", encoding="utf-8"
    )
    findings = BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1 and findings[0].rule == "bola/unscoped-object-fetch"


def test_bola_fires_on_bare_token_substring_lookalikes(tmp_path: Path) -> None:
    # Regression (#345): bola's own trailing auth tokens (`scope`, `require`, `tenant`, ...) used to
    # match as raw substrings, so an unscoped route whose only non-auth identifier merely CONTAINED
    # one of them was false-suppressed. Routing them through the boundaried matcher fixes it: each of
    # these params carries no real auth/ownership signal, so every route must fire.
    #   telescope -> bare `scope`, required_items -> bare `require`, lieutenant -> bare `tenant`.
    for i, param in enumerate(("telescope", "required_items", "lieutenant")):
        d = tmp_path / str(i)
        d.mkdir()
        (d / "r.py").write_text(
            "@router.get('/items/{item_id}')\n"
            f"def read_item(item_id: int, {param}=None):\n"
            "    return Order.query.get(item_id)\n",
            encoding="utf-8",
        )
        findings = BolaGuard().run(d, _fastapi_prof(d))
        assert len(findings) == 1 and findings[0].rule == "bola/unscoped-object-fetch", param


def test_bola_suppresses_plural_and_ownership_signals(tmp_path: Path) -> None:
    # Regression (#345): the fix must NOT over-correct — legitimate PLURAL auth signals in bola's
    # vocabulary (`scopes`, `permissions`, and the bare plurals `owners`/`tenants`), which suppressed
    # via the old bare substrings, must keep suppressing under the boundaried matcher's `s?` tolerance;
    # bola's ownership terms still suppress on `owner_id`/`tenant_id`. Plus (#364) the recovered
    # `ownership` literal: the `ownership*` family is a genuine ownership signal and must suppress.
    for i, signal in enumerate((
        "if 'read' in scopes: pass",
        "if perm in permissions: pass",
        "q = Order.query.filter_by(owner_id=1)",
        "q = Order.query.filter_by(tenant_id=1)",
        "if user in owners: pass",
        "if org in tenants: pass",
        "if not ownership_check(order_id): raise",
    )):
        d = tmp_path / str(i)
        d.mkdir()
        (d / "r.py").write_text(
            "@router.get('/orders/{order_id}')\n"
            "def get_order(order_id: str):\n"
            f"    {signal}\n"
            "    return Order.query.get(order_id)\n",
            encoding="utf-8",
        )
        assert BolaGuard().run(d, _fastapi_prof(d)) == [], signal


def test_bola_fires_on_incidental_non_auth_stem_mentions(tmp_path: Path) -> None:
    # Regression (#345 review, PR #364): bola's body-text suppressor is NARROW — it must not inherit
    # the shared _AUTH_NAME's full Depends-naming stem list. A genuinely unscoped route that merely
    # mentions `token`/`role`/`user`/`login`/`verify` incidentally (a param never used to scope the
    # query, a comment, an unrelated variable/call) carries NO real ownership signal and must fire.
    incidentals = (
        "def get_order(order_id: str, token: str = None):\n    return Order.query.get(order_id)",
        "def get_order(order_id: str):\n    role = 'viewer'\n    return Order.query.get(order_id)",
        "def get_order(order_id: str):\n    # fetch the user's order by id\n    return Order.query.get(order_id)",
        "def get_order(order_id: str):\n    login_ts = 1\n    return Order.query.get(order_id)",
        "def get_order(order_id: str):\n    verify_checksum(order_id)\n    return Order.query.get(order_id)",
        # (#364) NON-ownership derivations of the anchored stems must still fire — `unscoped`/
        # `requirements` aren't ownership signals, and `scoped_session` is a DB construct, not scoping.
        "def get_order(order_id: str):\n    unscoped = True\n    return Order.query.get(order_id)",
        "def get_order(order_id: str):\n    requirements = load()\n    return Order.query.get(order_id)",
        "def get_order(order_id: str):\n    s = scoped_session()\n    return Order.query.get(order_id)",
    )
    for i, fn in enumerate(incidentals):
        d = tmp_path / str(i)
        d.mkdir()
        (d / "r.py").write_text(f"@router.get('/orders/{{order_id}}')\n{fn}\n", encoding="utf-8")
        findings = BolaGuard().run(d, _fastapi_prof(d))
        assert len(findings) == 1 and findings[0].rule == "bola/unscoped-object-fetch", fn


def test_bola_silent_on_nonproduct_path(tmp_path: Path) -> None:
    # Corpus-scan FP: the exact same unscoped-fetch shape sitting under a test/
    # tutorial-example directory already covered by the shared `is_nonproduct_path` list
    # (`fastapi/fastapi`'s own `docs_src/` tutorials fired this way) must stay silent — the guard
    # never called `is_nonproduct_path` at all before this fix.
    d = tmp_path / "docs_src"
    d.mkdir()
    (d / "r.py").write_text(
        "@router.get('/orders/{order_id}')\n"
        "async def get_order(order_id: str):\n    return Order.query.get(order_id)\n", encoding="utf-8"
    )
    assert BolaGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_bola_still_fires_at_a_normal_path_alongside_a_nonproduct_one(tmp_path: Path) -> None:
    # Direction traded against (CLAUDE.md rule 1): the SAME violation shape at an ordinary path
    # must still fire even when a sibling non-product directory exists in the same scan.
    (tmp_path / "docs_src").mkdir()
    (tmp_path / "docs_src" / "r.py").write_text(
        "@router.get('/orders/{order_id}')\n"
        "async def get_order(order_id: str):\n    return Order.query.get(order_id)\n", encoding="utf-8"
    )
    (tmp_path / "app.py").write_text(
        "@router.get('/orders/{order_id}')\n"
        "async def get_order(order_id: str):\n    return Order.query.get(order_id)\n", encoding="utf-8"
    )
    findings = BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.startswith("app.py")


def test_bola_unaffected_by_closure_exclusion(tmp_path: Path) -> None:
    # Blast-radius lock for `iter_functions(include_closures=...)` (#452 re-review). bola is one
    # of the six DECORATOR-gated consumers: it takes the default (closures INCLUDED) and must be
    # unchanged by the flag existing. The undecorated inner closure IS emitted as its own block,
    # and is inert for bola either way — it never matches `_ROUTE_DECORATOR`, so it can neither
    # fire on its own nor suppress the route. Exactly the route is reported, at the route's line.
    (tmp_path / "r.py").write_text(
        "@router.get('/orders/{order_id}')\n"
        "async def get_order(order_id: str):\n"
        "    def _serialize(order):\n"
        "        return {'id': order.id}\n"
        "    return _serialize(Order.query.get(order_id))\n",
        encoding="utf-8",
    )
    findings = BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "bola/unscoped-object-fetch"
    assert findings[0].location.endswith(":2")     # the route, not its closure


def test_bola_factory_registered_route_reports_once(tmp_path: Path) -> None:
    # Issue #502: `iter_functions` emits the factory's block AND the nested route's, and the
    # factory's block CONTAINS the route's decorator — so the route-decorator gate matched twice
    # and one real route was reported twice, the first copy anchored on `def make_app():`, which
    # carries no decorator at all. Exactly one finding, on the route.
    (tmp_path / "r.py").write_text(
        "def make_app():\n"
        "    router = APIRouter()\n"
        "    @router.get('/orders/{order_id}')\n"
        "    async def get_order(order_id: str):\n"
        "        return Order.query.get(order_id)\n"
        "    return router\n",
        encoding="utf-8",
    )
    findings = BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":4")     # the route, not the factory at :1

def test_bola_factory_registered_route_with_ownership_check_silent(tmp_path: Path) -> None:
    # FP-bait for the above: the narrowing must not turn into a suppression the other way. A
    # factory-registered route that DOES scope by owner stays silent — one finding became zero,
    # not one-plus-a-surviving-duplicate.
    (tmp_path / "r.py").write_text(
        "def make_app():\n"
        "    router = APIRouter()\n"
        "    @router.get('/orders/{order_id}')\n"
        "    async def get_order(order_id: str, current_user=Depends(get_current_user)):\n"
        "        return Order.query.filter_by(id=order_id, user_id=current_user.id).first()\n"
        "    return router\n",
        encoding="utf-8",
    )
    assert BolaGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_bola_route_sink_inside_a_plain_closure_still_fires(tmp_path: Path) -> None:
    # The false negative #502's fix has to avoid. Blanking EVERY nested def out of its parent —
    # the obvious reading of "an enclosing block should not contain its children" — would take
    # this route's only sink with it. A closure is not separately reported, so its parent must
    # keep seeing it; only REGISTRATION-decorated nested defs are removed.
    (tmp_path / "r.py").write_text(
        "@router.get('/orders/{order_id}')\n"
        "def get_order(order_id: str):\n"
        "    def _load():\n"
        "        return Order.query.get(order_id)\n"
        "    return _load()\n",
        encoding="utf-8",
    )
    findings = BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":2")


def test_bola_nested_sibling_route_does_not_cover_the_outer(tmp_path: Path) -> None:
    # Rule 1 lock on the WIDENING #502's fix causes, for the SECOND of the five guards that share
    # the mechanism (#605 gate, Medium-1). Two routes each registered in their own right, one
    # nested inside the other. The outer fetches by id with no auth; the inner has `Depends(...)`.
    # Before the blanking, the inner's auth sat inside the outer's scanned block and read as the
    # OUTER's, so a genuine BOLA reported nothing. Measured origin/main -> 0 findings,
    # HEAD -> 1 at the outer, so this discriminates against the unfixed code.
    (tmp_path / "r.py").write_text(
        "@router.get('/items/{item_id}')\n"
        "async def get_item_outer(item_id: str):\n"
        "    @router.get('/other/{item_id}')\n"
        "    async def get_item_inner(item_id: str, user=Depends(get_current_user)):\n"
        "        return db.query(Item).filter(Item.id == item_id).first()\n"
        "    return db.query(Item).filter(Item.id == item_id).first()\n",
        encoding="utf-8",
    )
    findings = BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":2")     # the OUTER route, whose auth is genuinely absent


def test_bola_outer_route_auth_does_not_cover_a_nested_sibling(tmp_path: Path) -> None:
    # FP-bait mirror: auth on the outer instead, and the one finding lands on the inner that really
    # has none. Reports 1 on both old and new code, so it pins that the blanking did not start
    # moving findings around rather than discriminating.
    (tmp_path / "r.py").write_text(
        "@router.get('/items/{item_id}')\n"
        "async def get_item_outer(item_id: str, user=Depends(get_current_user)):\n"
        "    @router.get('/other/{item_id}')\n"
        "    async def get_item_inner(item_id: str):\n"
        "        return db.query(Item).filter(Item.id == item_id).first()\n"
        "    return db.query(Item).filter(Item.id == item_id).first()\n",
        encoding="utf-8",
    )
    findings = BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":4")     # the INNER route


def test_bola_pragma_quoted_in_a_string_in_the_route_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string in the route body is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-unscoped-fetch"):
        (tmp_path / "r.py").write_text(
            "@router.get('/orders/{order_id}')\n"
            "async def get_order(order_id: str):\n"
            f'    _note = "{note}"\n'
            "    return Order.query.get(order_id)\n", encoding="utf-8"
        )
        assert len(BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))) == 1, note


def test_bola_pragma_comment_in_the_route_body_still_suppresses(tmp_path: Path) -> None:
    # #1040 reach unchanged: a real pragma comment in the handler body (not the decorator) still silences.
    (tmp_path / "r.py").write_text(
        "@router.get('/orders/{order_id}')\n"
        "async def get_order(order_id: str):\n"
        "    # security: allow-unscoped-fetch\n"
        "    return Order.query.get(order_id)\n", encoding="utf-8"
    )
    assert BolaGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []


def test_bola_pragma_comment_in_a_sibling_route_does_not_suppress(tmp_path: Path) -> None:
    # #1040 reach not widened: one route's pragma comment leaves its unscoped sibling route firing.
    (tmp_path / "r.py").write_text(
        "@router.get('/orders/{order_id}')\n"
        "async def get_order(order_id: str):\n"
        "    # security: allow-unscoped-fetch\n"
        "    return Order.query.get(order_id)\n"
        "\n\n"
        "@router.get('/invoices/{invoice_id}')\n"
        "async def get_invoice(invoice_id: str):\n"
        "    return Invoice.query.get(invoice_id)\n", encoding="utf-8"
    )
    findings = BolaGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":8")     # get_invoice, not the pragma'd get_order
