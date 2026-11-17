from __future__ import annotations

import pytest

from agentsec.findings import _is_review_finding
from agentsec.guards.truthy_ownership_check import TruthyOwnershipCheckGuard
from agentsec.prioritize import confidence
from tests.guards._common import *  # noqa: F401,F403


def test_truthy_ownership_check_fires_on_unguarded_truthy_scope(tmp_path: Path) -> None:
    (tmp_path / "flow_lookup.py").write_text(
        "def get_flow_by_id(session, flow_id, user_id=None):\n"
        "    query = session.query(Flow).filter(Flow.id == flow_id)\n"
        "    if user_id:\n"
        "        query = query.filter(Flow.user_id == user_id)\n"
        "    return query.first()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = TruthyOwnershipCheckGuard().run(tmp_path, prof)
    assert len(findings) == 1
    assert findings[0].rule == "truthy-ownership-check/unguarded-truthy-scope"
    assert findings[0].severity == "medium"  # PR #742 review, Major 1: was high, see module docstring
    assert "user_id" in findings[0].message


def test_truthy_ownership_check_finding_is_a_review_signal(tmp_path: Path) -> None:
    # #766: declared `surfacing = True`, like `bola`. The structural shape cannot tell a security
    # boundary from an optional filter, so a human confirms; the report must rank it that way.
    (tmp_path / "flow_lookup.py").write_text(
        "def get_flow_by_id(session, flow_id, user_id=None):\n"
        "    query = session.query(Flow).filter(Flow.id == flow_id)\n"
        "    if user_id:\n"
        "        query = query.filter(Flow.user_id == user_id)\n"
        "    return query.first()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = TruthyOwnershipCheckGuard().run(tmp_path, prof)
    assert len(findings) == 1
    assert _is_review_finding(findings[0]) is True
    assert confidence(findings[0]) == "review"


def test_truthy_ownership_check_rejects_on_falsy_stays_silent(tmp_path: Path) -> None:
    # FP-bait, the fixed version: an else that rejects when the id is falsy.
    (tmp_path / "flow_lookup.py").write_text(
        "def get_flow_by_id(session, flow_id, user_id=None):\n"
        "    query = session.query(Flow).filter(Flow.id == flow_id)\n"
        "    if user_id:\n"
        "        query = query.filter(Flow.user_id == user_id)\n"
        "    else:\n"
        "        raise PermissionError('no caller identity')\n"
        "    return query.first()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert TruthyOwnershipCheckGuard().run(tmp_path, prof) == []


def test_truthy_ownership_check_is_not_none_form_stays_silent(tmp_path: Path) -> None:
    # FP-bait: the SAFE form -- `is not None` is not a bare truthy test, must not fire.
    (tmp_path / "flow_lookup.py").write_text(
        "def get_flow_by_id(session, flow_id, user_id=None):\n"
        "    query = session.query(Flow).filter(Flow.id == flow_id)\n"
        "    if user_id is not None:\n"
        "        query = query.filter(Flow.user_id == user_id)\n"
        "    return query.first()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert TruthyOwnershipCheckGuard().run(tmp_path, prof) == []


def test_truthy_ownership_check_unrelated_truthy_check_stays_silent(tmp_path: Path) -> None:
    # FP-bait: `if verbose:` is a bare truthy check too, but the name isn't ownership-shaped.
    (tmp_path / "helper.py").write_text(
        "def log_flow(session, flow_id, verbose=None):\n"
        "    query = session.query(Flow).filter(Flow.id == flow_id)\n"
        "    if verbose:\n"
        "        query = query.filter(Flow.debug == True)\n"
        "    return query.first()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert TruthyOwnershipCheckGuard().run(tmp_path, prof) == []


def test_truthy_ownership_check_no_scope_call_in_body_stays_silent(tmp_path: Path) -> None:
    # FP-bait: `if user_id:` guards something that ISN'T a query-scoping call at all.
    (tmp_path / "helper.py").write_text(
        "def maybe_log(user_id=None):\n"
        "    if user_id:\n"
        "        print(f'called by {user_id}')\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert TruthyOwnershipCheckGuard().run(tmp_path, prof) == []


def test_truthy_ownership_check_unconditional_filter_stays_silent(tmp_path: Path) -> None:
    # FP-bait: the filter is applied unconditionally -- no falsy path to skip it at all.
    (tmp_path / "flow_lookup.py").write_text(
        "def get_flow_by_id(session, flow_id, user_id):\n"
        "    query = session.query(Flow).filter(Flow.id == flow_id, Flow.user_id == user_id)\n"
        "    return query.first()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert TruthyOwnershipCheckGuard().run(tmp_path, prof) == []


def test_truthy_ownership_check_supabase_eq_form_fires(tmp_path: Path) -> None:
    # Supabase-py's own filter-builder DSL: .eq("user_id", user_id) instead of SQLAlchemy .filter().
    (tmp_path / "flow_lookup.py").write_text(
        "def get_flow(supabase, flow_id, user_id=None):\n"
        "    query = supabase.table('flows').select('*').eq('id', flow_id)\n"
        "    if user_id:\n"
        "        query = query.eq('user_id', user_id)\n"
        "    return query.execute()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = TruthyOwnershipCheckGuard().run(tmp_path, prof)
    assert len(findings) == 1


def test_truthy_ownership_check_owner_id_name_fires(tmp_path: Path) -> None:
    (tmp_path / "orders.py").write_text(
        "def get_order(session, order_id, owner_id=None):\n"
        "    query = session.query(Order).filter(Order.id == order_id)\n"
        "    if owner_id:\n"
        "        query = query.filter(Order.owner_id == owner_id)\n"
        "    return query.first()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = TruthyOwnershipCheckGuard().run(tmp_path, prof)
    assert len(findings) == 1
    assert "owner_id" in findings[0].message


def test_truthy_ownership_check_return_tail_rejects_stays_silent(tmp_path: Path) -> None:
    # FP-bait: rejection by `return`, not `raise` -- pins the `return` half of raise/return.
    (tmp_path / "flow_lookup.py").write_text(
        "def get_flow_by_id(session, flow_id, user_id=None):\n"
        "    query = session.query(Flow).filter(Flow.id == flow_id)\n"
        "    if user_id:\n"
        "        query = query.filter(Flow.user_id == user_id)\n"
        "    else:\n"
        "        return None\n"
        "    return query.first()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert TruthyOwnershipCheckGuard().run(tmp_path, prof) == []


def test_truthy_ownership_check_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "flow_lookup.py").write_text(
        "# security: allow-truthy-ownership-check\n"
        "def get_flow_by_id(session, flow_id, user_id=None):\n"
        "    query = session.query(Flow).filter(Flow.id == flow_id)\n"
        "    if user_id:\n"
        "        query = query.filter(Flow.user_id == user_id)\n"
        "    return query.first()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert TruthyOwnershipCheckGuard().run(tmp_path, prof) == []


def test_truthy_ownership_check_not_applicable_without_python() -> None:
    prof = mkprofile(Path("/tmp"), features={"javascript"})
    assert TruthyOwnershipCheckGuard().applies(prof) is False


def test_truthy_ownership_check_optional_ui_filter_look_alike_still_fires(tmp_path: Path) -> None:
    # PR #742 review, Major 1, DISCLOSED (not fixed): an ordinary optional UI filter is
    # AST-IDENTICAL to the CVE-2026-55255 shape this guard exists to catch -- whether the truthy
    # filter is a security boundary or a convenience narrowing isn't expressible in the AST alone.
    # This is the review's own realistic fixture (an admin search endpoint with two optional,
    # non-security dropdown filters). It DOES still fire, on 2 of 3 lines -- pinned here as a
    # known, accepted false positive (severity dropped to medium for exactly this reason, see the
    # module docstring) rather than left undocumented. A real fix needs a corroborating
    # authz-context signal, unverified design work not attempted here.
    (tmp_path / "search.py").write_text(
        "def list_documents(db, owner_id=None, tenant_id=None):\n"
        "    q = db.query(Document)\n"
        "    if owner_id:\n"
        "        q = q.filter(Document.owner_id == owner_id)\n"
        "    if tenant_id:\n"
        "        q = q.filter(Document.tenant_id == tenant_id)\n"
        "    return q.all()\n"
        "\n"
        "def get_flow_for_caller(db, user_id):\n"
        "    query = db.query(Document)\n"
        "    if user_id:\n"
        "        query = query.filter(Document.user_id == user_id)\n"
        "    return query.first()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = TruthyOwnershipCheckGuard().run(tmp_path, prof)
    assert len(findings) == 3
    assert all(f.severity == "medium" for f in findings)


def test_truthy_ownership_check_admin_route_with_privileged_dep_is_suppressed(tmp_path: Path) -> None:
    # Issue #808: the flagship's admin audit-log/feedback search endpoints. The handler runs behind a
    # recognized PRIVILEGED auth dependency alias (`AdminReadDep`, i.e. `Depends(verify_admin...)`),
    # so its truthy `if user_id:` is an optional search filter refining an already-authorized admin
    # scope, not the access boundary. The block iter_functions hands the guard contains the decorator
    # AND the `= AdminReadDep` parameter, so AUTH_CALL_PRIVILEGED sees it in-block (no cross-file
    # resolution needed). This fixture differs from the no-auth one below ONLY in the `AdminReadDep`
    # dependency (its import line and the `= AdminReadDep` parameter), which is what proves the auth
    # gate (not some fixture quirk) does the suppressing.
    (tmp_path / "audit_log_routes.py").write_text(
        "from auth import AdminReadDep\n"
        "\n"
        '@router.get("/api/admin/audit-logs")\n'
        "async def get_audit_logs(user_id=None, admin: dict = AdminReadDep):\n"
        '    query = supabase.table("audit_logs").select("*")\n'
        "    if user_id:\n"
        '        query = query.eq("user_id", user_id)\n'
        "    return query.execute()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = TruthyOwnershipCheckGuard().run(tmp_path, prof)
    assert findings == []


def test_truthy_ownership_check_route_without_auth_dep_still_fires(tmp_path: Path) -> None:
    # Issue #808 negative control (the direction the fix trades against, CLAUDE.md Rule 1): the SAME
    # route/filter shape as the suppressed case above, minus the privileged auth dependency, MUST
    # still fire — otherwise the suppression would be voiding real coverage, not an FP.
    (tmp_path / "audit_log_routes.py").write_text(
        '@router.get("/api/admin/audit-logs")\n'
        "async def get_audit_logs(user_id=None):\n"
        '    query = supabase.table("audit_logs").select("*")\n'
        "    if user_id:\n"
        '        query = query.eq("user_id", user_id)\n'
        "    return query.execute()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = TruthyOwnershipCheckGuard().run(tmp_path, prof)
    assert len(findings) == 1
    assert findings[0].rule == "truthy-ownership-check/unguarded-truthy-scope"


def test_truthy_ownership_check_plain_authenticated_per_user_route_still_fires(tmp_path: Path) -> None:
    # Issue #808 over-suppression guard: a plain `Depends(get_current_user)` route is authenticated
    # but NOT privileged, and truthy-skipping its per-user scope IS a real cross-user IDOR. The fix
    # suppresses only PRIVILEGED auth (AUTH_CALL_PRIVILEGED), so this must still fire — proving the
    # gate did not degrade to "any auth silences the guard".
    (tmp_path / "record_routes.py").write_text(
        "from fastapi import Depends\n"
        "\n"
        '@router.get("/api/my/records")\n'
        "async def my_records(user_id=None, user: dict = Depends(get_current_user)):\n"
        "    query = db.query(Record)\n"
        "    if user_id:\n"
        "        query = query.filter(Record.user_id == user_id)\n"
        "    return query.all()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = TruthyOwnershipCheckGuard().run(tmp_path, prof)
    assert len(findings) == 1
    assert findings[0].rule == "truthy-ownership-check/unguarded-truthy-scope"


# --- Issue #1065: methods and nested functions -------------------------------------------------
# Every fixture above is a column-0 `def`. The guard used to re-parse each `iter_functions` block on
# its own, and a method's block keeps its indentation, so `ast.parse` raised IndentationError and the
# method was silently skipped. Detection now walks each function's node in the whole-file AST. The
# location asserts use `endswith(":N")` so they hold on Windows, where `rel()` gives backslashes.


def _run(tmp_path: Path, src: str) -> list:
    (tmp_path / "repo.py").write_text(src, encoding="utf-8")
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    return TruthyOwnershipCheckGuard().run(tmp_path, prof)


_METHOD = (
    "class DocRepo:\n"
    "    def get_docs(self, db, user_id):\n"
    "        q = db.query(Doc)\n"
    "        if user_id:\n"
    "            q = q.filter(Doc.user_id == user_id)\n"
    "        return q.all()\n"
)


@pytest.mark.parametrize(
    ("src", "if_line"),
    [
        pytest.param(_METHOD, 4, id="method"),
        pytest.param(_METHOD.replace("    def ", "    async def "), 4, id="async-method"),
        pytest.param(
            "class DocRepo:\n"
            "    @staticmethod\n"
            "    def get_docs(db, user_id):\n"
            "        q = db.query(Doc)\n"
            "        if user_id:\n"
            "            q = q.filter(Doc.user_id == user_id)\n"
            "        return q.all()\n",
            5,
            id="decorated-method",
        ),
    ],
)
def test_truthy_ownership_check_fires_in_a_method(tmp_path: Path, src: str, if_line: int) -> None:
    # Issue #1065, the widening: the CVE shape inside a repository/service class method. The finding
    # points at the `if`, not at the `def` or the decorator.
    findings = _run(tmp_path, src)
    assert len(findings) == 1
    assert findings[0].rule == "truthy-ownership-check/unguarded-truthy-scope"
    assert findings[0].location.endswith(f":{if_line}")


@pytest.mark.parametrize(
    "col0_lines",
    [
        pytest.param('        sql = """\nSELECT * FROM docs\n"""\n', id="sql-string-closing-quotes"),
        pytest.param('        """Fetch docs.\nContinued at column zero.\n"""\n', id="docstring-continuation"),
        pytest.param("        order = Doc.id \\\n.desc()\n", id="backslash-continuation"),
    ],
)
def test_truthy_ownership_check_fires_in_a_method_with_column_0_lines(
    tmp_path: Path, col0_lines: str
) -> None:
    # Issue #1065: `textwrap.dedent` is a no-op when any line of the block sits at column 0, so a
    # dedent-then-reparse fix still misses these methods. Analysing the whole-file AST does not
    # depend on the block's indentation at all.
    src = (
        "class DocRepo:\n"
        "    def get_docs(self, db, user_id):\n"
        + col0_lines
        + "        q = db.query(Doc)\n"
        "        if user_id:\n"
        "            q = q.filter(Doc.user_id == user_id)\n"
        "        return q.all()\n"
    )
    if_line = src.splitlines().index("        if user_id:") + 1
    findings = _run(tmp_path, src)
    assert len(findings) == 1
    assert findings[0].location.endswith(f":{if_line}")


@pytest.mark.parametrize(
    ("src", "if_line"),
    [
        pytest.param(
            "class DocRepo:\n"
            "    def lookup(self, db):\n"
            "        def scoped(user_id):\n"
            "            q = db.query(Doc)\n"
            "            if user_id:\n"
            "                q = q.filter(Doc.user_id == user_id)\n"
            "            return q.all()\n"
            "        return scoped\n",
            5,
            id="nested-in-method",
        ),
        pytest.param(
            "def make_lookup(db):\n"
            "    def scoped(user_id):\n"
            "        q = db.query(Doc)\n"
            "        if user_id:\n"
            "            q = q.filter(Doc.user_id == user_id)\n"
            "        return q.all()\n"
            "    return scoped\n",
            4,
            id="nested-in-function",
        ),
    ],
)
def test_truthy_ownership_check_nested_function_fires_once(tmp_path: Path, src: str, if_line: int) -> None:
    # Issue #1065: `iter_functions` emits the enclosing function AND the nested one, and both
    # contain the same `if`. It is one bug, so it is one finding.
    findings = _run(tmp_path, src)
    assert len(findings) == 1
    assert findings[0].location.endswith(f":{if_line}")


@pytest.mark.parametrize(
    "src",
    [
        pytest.param(
            "class DocRepo:\n"
            "    def get_docs(self, db, user_id):\n"
            "        q = db.query(Doc)\n"
            "        if user_id:\n"
            "            q = q.filter(Doc.user_id == user_id)\n"
            "        else:\n"
            "            raise PermissionError('no caller identity')\n"
            "        return q.all()\n",
            id="else-raise",
        ),
        pytest.param(
            "class DocRepo:\n"
            "    def get_docs(self, db, user_id):\n"
            "        q = db.query(Doc)\n"
            "        if user_id is not None:\n"
            "            q = q.filter(Doc.user_id == user_id)\n"
            "        return q.all()\n",
            id="is-not-none",
        ),
    ],
)
def test_truthy_ownership_check_safe_method_stays_silent(tmp_path: Path, src: str) -> None:
    # FP-bait for the #1065 widening (CLAUDE.md Rule 1): the safe forms stay silent inside a method
    # too, so analysing methods did not loosen the `If` checks themselves.
    assert _run(tmp_path, src) == []


_ADMIN_IMPORT = "from auth import AdminReadDep\n\n"
_METHOD_ROUTE = (
    "class AuditViews:\n"
    '    @router.get("/api/admin/audit-logs")\n'
    "    async def get_audit_logs(self, user_id=None{dep}):\n"
    '        query = supabase.table("audit_logs").select("*")\n'
    "        if user_id:\n"
    '            query = query.eq("user_id", user_id)\n'
    "        return query.execute()\n"
)


def test_truthy_ownership_check_admin_method_route_is_suppressed(tmp_path: Path) -> None:
    # Issue #808's privileged-route suppression must hold for a class-based-view method too. This
    # passed vacuously before #1065, when no method was analysed; the control below fires on the
    # same method minus the admin dependency, which is what makes the silence here meaningful.
    assert _run(tmp_path, _ADMIN_IMPORT + _METHOD_ROUTE.format(dep=", admin: dict = AdminReadDep")) == []


def test_truthy_ownership_check_method_route_without_admin_dep_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, _METHOD_ROUTE.format(dep=""))
    assert len(findings) == 1
    assert findings[0].location.endswith(":5")


_CLOSURE_ROUTE = (
    '@router.get("/api/admin/audit-logs")\n'
    "async def get_audit_logs(user_id=None{dep}):\n"
    "    def build(user_id):\n"
    '        query = supabase.table("audit_logs").select("*")\n'
    "        if user_id:\n"
    '            query = query.eq("user_id", user_id)\n'
    "        return query\n"
    "    return build(user_id).execute()\n"
)


def test_truthy_ownership_check_closure_in_admin_route_is_suppressed(tmp_path: Path) -> None:
    # Issue #1065 x #808: an undecorated helper defined inside an admin-gated route runs under that
    # route's authorization. `iter_functions` hands the closure over as its own block, which carries
    # no route decorator, so a per-block suppression would let it fire. The suppression covers the
    # route's whole span instead.
    assert _run(tmp_path, _ADMIN_IMPORT + _CLOSURE_ROUTE.format(dep=", admin: dict = AdminReadDep")) == []


def test_truthy_ownership_check_closure_in_plain_route_fires_once(tmp_path: Path) -> None:
    findings = _run(tmp_path, _CLOSURE_ROUTE.format(dep=""))
    assert len(findings) == 1
    assert findings[0].location.endswith(":5")


_FACTORY_ROUTE = (
    "def register(router):\n"
    '    @router.get("/api/admin/audit-logs")\n'
    "    async def get_audit_logs(user_id=None{dep}):\n"
    '        query = supabase.table("audit_logs").select("*")\n'
    "        if user_id:\n"
    '            query = query.eq("user_id", user_id)\n'
    "        return query.execute()\n"
)


def test_truthy_ownership_check_factory_registered_admin_route_is_suppressed(tmp_path: Path) -> None:
    # Issue #1065: `iter_functions` blanks a registered nested route out of its factory's BLOCK text
    # (#502), but the factory's AST node still contains it. Walking the factory's node therefore
    # reaches the admin route's `if`, and it has to be suppressed by the route's span, not by
    # skipping the route's own block.
    assert _run(tmp_path, _ADMIN_IMPORT + _FACTORY_ROUTE.format(dep=", admin: dict = AdminReadDep")) == []


def test_truthy_ownership_check_factory_registered_route_without_admin_dep_fires_once(
    tmp_path: Path,
) -> None:
    findings = _run(tmp_path, _FACTORY_ROUTE.format(dep=""))
    assert len(findings) == 1
    assert findings[0].location.endswith(":5")


@pytest.mark.parametrize(
    ("body", "if_line"),
    [
        pytest.param(
            "def get_docs(db, user_id):\n"
            "    q = db.query(Doc)\n"
            "    if user_id:\n"
            "        q = q.filter(Doc.user_id == user_id)\n"
            "    return q.all()\n",
            5,
            id="top-level-function",
        ),
        pytest.param(
            "class DocRepo:\n"
            "    @staticmethod\n"
            "    def get_docs(db, user_id):\n"
            "        q = db.query(Doc)\n"
            "        if user_id:\n"
            "            q = q.filter(Doc.user_id == user_id)\n"
            "        return q.all()\n",
            7,
            id="decorated-method",
        ),
        pytest.param(
            "def make_lookup(db):\n"
            "    def scoped(user_id):\n"
            "        q = db.query(Doc)\n"
            "        if user_id:\n"
            "            q = q.filter(Doc.user_id == user_id)\n"
            "        return q.all()\n"
            "    return scoped\n",
            6,
            id="nested-function-once",
        ),
    ],
)
def test_truthy_ownership_check_file_that_does_not_parse_still_fires(
    tmp_path: Path, body: str, if_line: int
) -> None:
    # Issue #1065, the direction traded against (CLAUDE.md Rule 1): a file with an unrelated syntax
    # error has no whole-file AST, so the guard falls back to parsing each block, dedented. The
    # top-level case fired before #1065 and must keep firing; the method case is the fallback's own
    # share of the widening, and pins that the decorator-start line mapping still holds there. The
    # nested `if` sits in two blocks that both parse once dedented, and is still reported once.
    findings = _run(tmp_path, 'print "py2"\n\n' + body)
    assert len(findings) == 1
    assert findings[0].location.endswith(f":{if_line}")
