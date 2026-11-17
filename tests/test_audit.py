"""Tests for the audit pipeline (`audit.py`) — crash isolation + changed-set scoping.

Relocated from the (now-split) guard-test monolith: these exercise `audit()` behavior
itself, not any single guard, so they live next to `audit.py`'s slice rather than in a
per-guard file (BB1, #186)."""
from __future__ import annotations

from pathlib import Path

import pytest

from agentsec.detect import StackProfile


def test_audit_survives_a_crashing_guard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A guard that raises (e.g. on a malformed/hostile file) must not abort the audit."""
    from agentsec import audit as audit_mod

    class _Boom:
        id = "boom-guard"

        def run(self, root: Path, profile: StackProfile) -> list[object]:
            raise RuntimeError("boom")

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(audit_mod, "select_guards", lambda profile: [_Boom()])
    res = audit_mod.audit(tmp_path, run_scanners=False)
    assert "boom-guard" in res.tools_errored  # crash recorded, audit completed


def test_audit_empty_changed_set_scopes_out_all_findings(tmp_path: Path) -> None:
    """An empty changed-set (git ok, nothing changed) filters every finding out — not a full scan."""
    from agentsec.audit import audit
    (tmp_path / "app.py").write_text("import hashlib\nh = hashlib.md5(b'x')\n", encoding="utf-8")
    assert len(audit(tmp_path, run_scanners=False).findings) >= 1          # fixture produces a finding
    assert audit(tmp_path, run_scanners=False, changed_paths=frozenset()).findings == []


# --- run-scoped derived-state memo, end to end (issue #544) ------------------------------------


def test_audit_findings_are_identical_with_and_without_the_derived_memo(tmp_path: Path) -> None:
    """The memo (#544) must change only speed, never output. Compares a real `audit()` over the
    same tree with the cache enabled and disabled, element-wise rather than by count.

    This is the regression that makes the optimization safe to land: `strip_python_strings` feeds
    a large share of the guard set, so a divergence would silently move findings across it. Counts
    alone would not catch a swap, so the comparison is on (rule, location, severity, message)."""
    import agentsec.guards.base as base
    from agentsec.audit import audit

    (tmp_path / "app.py").write_text(
        'import os\n'
        '"""Docstring showing an anti-pattern: os.system("rm -rf /")"""\n'
        'def handler(cmd):\n'
        '    os.system(cmd)\n'
        "    token = 'sk-live-abcdefghijklmnopqrstuvwxyz'\n"
        '    return token\n',
        encoding="utf-8",
    )
    (tmp_path / "helper.py").write_text(
        "def f(u):\n    '''eval(u) in a docstring, not code'''\n    return eval(u)\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("fastapi==0.100.0\n", encoding="utf-8")

    def signature() -> list[tuple[str, str, str, str]]:
        res = audit(tmp_path, run_scanners=False, exceptions_path=tmp_path / "none.json")
        return sorted((f.rule, f.location, f.severity, f.message) for f in res.findings)

    with_memo = signature()
    original = base._MAX_DERIVED_ENTRIES
    try:
        base._MAX_DERIVED_ENTRIES = 0          # disables the memo; every call recomputes
        without_memo = signature()
    finally:
        base._MAX_DERIVED_ENTRIES = original

    assert with_memo == without_memo, (
        "the derived-state memo changed audit output — it must be a pure speedup.\n"
        f"only with memo: {[f for f in with_memo if f not in without_memo]}\n"
        f"only without:   {[f for f in without_memo if f not in with_memo]}"
    )
    assert with_memo, "fixture produced no findings at all — the comparison would be vacuous"


def test_derived_memo_is_actually_engaged_during_a_real_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The memo must be ON, not merely correct (#544 review).

    `test_audit_findings_are_identical_with_and_without_the_derived_memo` above proves the memo does
    not change output — but it cannot prove the memo is engaged. If `_with_run_caches` ever stopped
    entering `derived_state_run()`, `_derived_depth` would stay 0, which is the SAME code path as the
    `_MAX_DERIVED_ENTRIES = 0` arm that test uses to disable it. Both arms would then compute the
    identical result and that test would keep passing vacuously while the optimization silently did
    nothing — a performance regression no gate would report.

    This counts real derivations through a real `audit()` instead, so dropped wiring fails loudly."""
    import agentsec.guards.base as base
    from agentsec.audit import audit

    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).write_text(
            f'"""doc for {name} with os.system("x") inside"""\nimport os\n\n\ndef f():\n    pass\n',
            encoding="utf-8",
        )

    def count_calls() -> int:
        calls = 0
        original = base._strip_python_strings_uncached

        # Forwards `filename` (#779). A double that drops it does not merely miscount: the
        # TypeError is raised INSIDE a guard, where it is swallowed, so every derivation
        # disappears and the counter reads 0 — a clean-looking "no derivations" rather than an
        # error. Only the `without_memo > 0` anti-vacuity assertion below catches that, which is
        # exactly the shape review-doctrine Rule 3 is about.
        def counting(text: str, *, filename: str | Path = "<unknown>") -> str:
            nonlocal calls
            calls += 1
            return original(text, filename=filename)

        monkeypatch.setattr(base, "_strip_python_strings_uncached", counting)
        audit(tmp_path, run_scanners=False, exceptions_path=tmp_path / "none.json")
        monkeypatch.undo()
        return calls

    with_memo = count_calls()
    monkeypatch.setattr(base, "_MAX_DERIVED_ENTRIES", 0)
    without_memo = count_calls()
    monkeypatch.undo()

    assert without_memo > 0, "the fixture triggered no derivations at all — the check would be vacuous"
    assert with_memo * 3 <= without_memo, (
        f"the derived-state memo does not appear to be engaged during a real audit: "
        f"{with_memo} derivations with it enabled vs {without_memo} with it disabled. "
        "Check that `_with_run_caches` still enters `derived_state_run()` (#544)."
    )


def test_js_audit_findings_are_identical_with_and_without_the_derived_memo(tmp_path: Path) -> None:
    """The JS analog of `test_audit_findings_are_identical_with_and_without_the_derived_memo`.

    That test is the one its own docstring calls "the regression that makes the optimization safe to
    land", but its fixture is all `.py`, so it would pass unchanged even if the JS table were wired
    in wrongly — it never reaches any of the guard modules that consume `strip_js_comments`. This runs
    the same on/off comparison over a multi-file JS/TS tree instead.

    The JS derivation is the more expensive of the two and carries far more edge-case machinery
    (a template-literal frame stack, the regex-vs-division heuristic, the unterminated-comment cap),
    so a divergence between the cached and uncached paths has more places to hide here, not fewer.

    WHAT THIS TEST DOES NOT CATCH, measured rather than assumed: sabotaging the cache key to
    `(text, False)` — the exact bug the key design exists to prevent — leaves this test GREEN. All
    three JS files here are derived at both `strip_strings` settings, so the bug is exercised; it
    just does not change what these particular guards report. That axis is covered by
    `test_js_derived_memo_keys_on_the_strip_strings_flag` and
    `test_js_derived_memo_returns_identical_output_to_the_uncached_path`, both of which DO fail
    against that sabotage (verified). Recorded here so nobody reads this test as the key's guard."""
    import agentsec.guards.base as base
    from agentsec.audit import audit

    (tmp_path / "package.json").write_text(
        '{"name": "app", "dependencies": {"react": "18.2.0", "express": "4.18.2"}}\n',
        encoding="utf-8",
    )
    # Several files, each tripping a DIFFERENT guard, so the comparison spans more than one consumer
    # of strip_js_comments rather than exercising one code path repeatedly.
    (tmp_path / "render.jsx").write_text(
        "// innerHTML mentioned in a comment must stay silenced\n"
        "export function R({ d }) {\n"
        "  const el = document.getElementById('x');\n"
        "  el.innerHTML = d;\n"
        "  return <p>Don't lose this line</p>;\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "auth.js").write_text(
        "const KEY = 'sk-live-abcdefghijklmnopqrstuvwxyz';\n"
        "localStorage.setItem('token', KEY);\n"
        "/* a block comment mentioning localStorage.setItem('token', x) */\n",
        encoding="utf-8",
    )
    (tmp_path / "frame.ts").write_text(
        "window.addEventListener('message', (e) => {\n"
        "  const re = /^\\/api\\//;  // a regex embedding // that must not read as a comment\n"
        "  eval(e.data);\n"
        "});\n",
        encoding="utf-8",
    )

    def signature() -> list[tuple[str, str, str, str]]:
        res = audit(tmp_path, run_scanners=False, exceptions_path=tmp_path / "none.json")
        return sorted((f.rule, f.location, f.severity, f.message) for f in res.findings)

    with_memo = signature()
    original = base._MAX_DERIVED_ENTRIES
    try:
        base._MAX_DERIVED_ENTRIES = 0          # disables the memo; every call recomputes
        without_memo = signature()
    finally:
        base._MAX_DERIVED_ENTRIES = original

    assert with_memo == without_memo, (
        "the JS derived-state memo changed audit output — it must be a pure speedup.\n"
        f"only with memo: {[f for f in with_memo if f not in without_memo]}\n"
        f"only without:   {[f for f in without_memo if f not in with_memo]}"
    )
    assert with_memo, "fixture produced no findings at all — the comparison would be vacuous"
    # Non-vacuity, and the reason it is spelled out: `location` is `path:line`, not a bare path, so
    # an `endswith(".jsx")` check silently matches NOTHING and the test passes while comparing only
    # the package.json findings. It did exactly that when first written.
    js_rules = {rule for rule, loc, _, _ in with_memo
                if loc.split(":")[0].endswith((".jsx", ".js", ".ts", ".tsx"))}
    assert len(js_rules) >= 2, (
        "this did not exercise the JS memo across more than one consumer of strip_js_comments; "
        f"JS/TS-anchored rules seen: {sorted(js_rules)}"
    )


def test_js_derived_memo_is_actually_engaged_during_a_real_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same "is it ON?" check for the JS/TS table, on a JS-shaped target.

    The Python counterpart above cannot cover this: its fixture is all `.py`, so it would pass
    unchanged even if the JS memo were never wired in. `strip_js_comments` is called by most of the
    JS/TS guards, so on a JS/TS target the same once-per-(guard, file) multiplication applies."""
    import agentsec.guards.base as base
    from agentsec.audit import audit

    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18.2.0"}}\n', encoding="utf-8")
    for name in ("a.jsx", "b.jsx", "c.jsx"):
        (tmp_path / name).write_text(
            "// a comment mentioning innerHTML\n"
            "export function C({ d }) {\n"
            "  const el = document.getElementById('x');\n"
            "  el.innerHTML = d;\n"
            "  return <p>Don't forget</p>;\n"
            "}\n",
            encoding="utf-8",
        )

    def count_calls() -> int:
        calls = 0
        original = base._strip_js_comments_uncached

        def counting(
            text: str, *, strip_strings: bool = False, strip_regex: bool = False, keep_substitutions: bool = False
        ) -> str:
            nonlocal calls
            calls += 1
            return original(
                text, strip_strings=strip_strings, strip_regex=strip_regex, keep_substitutions=keep_substitutions
            )

        monkeypatch.setattr(base, "_strip_js_comments_uncached", counting)
        audit(tmp_path, run_scanners=False, exceptions_path=tmp_path / "none.json")
        monkeypatch.undo()
        return calls

    with_memo = count_calls()
    monkeypatch.setattr(base, "_MAX_DERIVED_ENTRIES", 0)
    without_memo = count_calls()
    monkeypatch.undo()

    assert without_memo > 0, "the fixture triggered no JS derivations at all — the check would be vacuous"
    assert with_memo * 3 <= without_memo, (
        f"the JS derived-state memo does not appear to be engaged during a real audit: "
        f"{with_memo} derivations with it enabled vs {without_memo} with it disabled (#544)."
    )


# --- compounding-risk signal is actually wired into the real audit() pipeline -------

def test_compounding_risk_fires_through_a_real_audit(tmp_path: Path) -> None:
    """Plant real bola + sqlalchemy-text-parameterized violations and confirm the compounding-risk
    finding appears in a genuine audit() run, not just in compounding_risk.assess()'s own unit
    tests — proves the pipeline wiring, not just the logic."""
    from agentsec import audit as audit_mod

    (tmp_path / "orders.py").write_text(
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n\n"
        "@router.get(\"/orders/{order_id}\")\n"
        "async def get_order(order_id: str):\n    return Order.query.get(order_id)\n",
        encoding="utf-8",
    )
    (tmp_path / "q.py").write_text(
        'conn.execute("UPDATE t SET x=1 WHERE id = " + uid)\n', encoding="utf-8"
    )
    res = audit_mod.audit(tmp_path, run_scanners=False, exceptions_path=tmp_path / "none.json")
    rules = {f.rule for f in res.findings}
    assert "bola/unscoped-object-fetch" in rules  # the fixture itself is sound
    assert "sqlalchemy-text-parameterized/string-built-sql" in rules
    assert "compounding-risk/sqli-plus-idor-account-takeover" in rules


def test_compounding_risk_finding_is_suppressible_like_any_other(tmp_path: Path) -> None:
    """The synthetic compounding-risk finding flows through the SAME exception/baseline registry
    as any real finding — via its own, second, independent `apply_exceptions` pass (it is computed
    AFTER the first pass, over `outcome.kept`, not before — #683 review, Critical 1) — so a project
    can still waive it the same way as any real finding, via `write_baseline()` + re-audit."""
    from datetime import date

    from agentsec import audit as audit_mod
    from agentsec.exceptions import write_baseline

    (tmp_path / "orders.py").write_text(
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n\n"
        "@router.get(\"/orders/{order_id}\")\n"
        "async def get_order(order_id: str):\n    return Order.query.get(order_id)\n",
        encoding="utf-8",
    )
    (tmp_path / "q.py").write_text(
        'conn.execute("UPDATE t SET x=1 WHERE id = " + uid)\n', encoding="utf-8"
    )
    baseline = tmp_path / "exceptions.json"
    first = audit_mod.audit(tmp_path, run_scanners=False, exceptions_path=tmp_path / "none.json")
    assert "compounding-risk/sqli-plus-idor-account-takeover" in {f.rule for f in first.findings}
    write_baseline(first.findings, baseline, date.today())

    second = audit_mod.audit(tmp_path, run_scanners=False, exceptions_path=baseline)
    assert "compounding-risk/sqli-plus-idor-account-takeover" not in {
        f.rule for f in second.findings
    }


def test_compounding_risk_finding_suppressible_on_its_own_while_legs_still_fire(tmp_path: Path) -> None:
    """The compounding-risk finding's own second apply_exceptions pass is genuinely independent:
    baselining ONLY its own rule (not the legs) still suppresses just the synthetic finding and
    leaves the two contributing findings themselves visible."""
    from datetime import date

    from agentsec import audit as audit_mod
    from agentsec.exceptions import write_baseline

    (tmp_path / "orders.py").write_text(
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n\n"
        "@router.get(\"/orders/{order_id}\")\n"
        "async def get_order(order_id: str):\n    return Order.query.get(order_id)\n",
        encoding="utf-8",
    )
    (tmp_path / "q.py").write_text(
        'conn.execute("UPDATE t SET x=1 WHERE id = " + uid)\n', encoding="utf-8"
    )
    baseline = tmp_path / "exceptions.json"
    first = audit_mod.audit(tmp_path, run_scanners=False, exceptions_path=tmp_path / "none.json")
    compound_only = [f for f in first.findings if f.check_id == "compounding-risk"]
    write_baseline(compound_only, baseline, date.today())

    second = audit_mod.audit(tmp_path, run_scanners=False, exceptions_path=baseline)
    rules = {f.rule for f in second.findings}
    assert "compounding-risk/sqli-plus-idor-account-takeover" not in rules  # suppressed on its own
    assert "bola/unscoped-object-fetch" in rules              # legs are untouched
    assert "sqlalchemy-text-parameterized/string-built-sql" in rules


def test_compounding_risk_does_not_fire_when_legs_are_already_baselined(tmp_path: Path) -> None:
    """#683 review, Critical 1 — the regression this PR's own gate was red on. When BOTH legs are
    already individually baselined, they never reach `outcome.kept`, so `assess()` — which now
    runs over `outcome.kept`, not the pre-suppression list — has nothing to compound. Before this
    fix, an already-fully-baselined repo still manufactured a brand-new, unbaselined critical on
    every subsequent run."""
    from datetime import date

    from agentsec import audit as audit_mod
    from agentsec.exceptions import write_baseline

    (tmp_path / "orders.py").write_text(
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n\n\n"
        "@router.get(\"/orders/{order_id}\")\n"
        "async def get_order(order_id: str):\n    return Order.query.get(order_id)\n",
        encoding="utf-8",
    )
    (tmp_path / "q.py").write_text(
        'conn.execute("UPDATE t SET x=1 WHERE id = " + uid)\n', encoding="utf-8"
    )
    baseline = tmp_path / "exceptions.json"
    first = audit_mod.audit(tmp_path, run_scanners=False, exceptions_path=tmp_path / "none.json")
    legs_only = [f for f in first.findings if f.check_id != "compounding-risk"]
    write_baseline(legs_only, baseline, date.today())

    second = audit_mod.audit(tmp_path, run_scanners=False, exceptions_path=baseline)
    rules = {f.rule for f in second.findings}
    assert "bola/unscoped-object-fetch" not in rules  # both legs correctly suppressed
    assert "sqlalchemy-text-parameterized/string-built-sql" not in rules
    assert "compounding-risk/sqli-plus-idor-account-takeover" not in rules  # never manufactured


# --- #894: audit() resolves the repo root ONCE and hands the ABSOLUTE root to every ------------
# guard and runner. A raw relative root (e.g. `agentsec audit minirepo`) double-joins under
# cwd=root in gitleaks/hadolint/pip-audit/trivy (and bandit's -c config), so the scanner exits
# non-zero and its findings are silently dropped while still reported as run. We assert the
# ARTIFACT — the root each dispatch point receives — never the exit code (review-doctrine Rule 3).


def _dispatch_roots(
    monkeypatch: pytest.MonkeyPatch, chdir_to: Path, path_arg: Path
) -> dict[str, Path]:
    """Run audit() with CWD=`chdir_to` and the repo addressed as `path_arg`, capturing the `root`
    handed to a probe guard and a probe runner. The runner probe subclasses the real Runner and
    overrides run() so it inherits the tier/coverage metadata but skips the binary-availability
    check (no scanner need be installed)."""
    from agentsec import audit as audit_mod
    from agentsec.runners.base import Runner, RunnerResult

    seen: dict[str, Path] = {}

    class _GuardProbe:
        id = "root-probe-guard"

        def run(self, root: Path, profile: StackProfile) -> list[object]:  # noqa: ARG002
            seen["guard"] = root
            return []

    class _RunnerProbe(Runner):
        id = "root-probe-runner"
        area = "Secrets"
        binary = "root-probe"

        def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
            return True

        def run(self, root: Path, profile: StackProfile) -> RunnerResult:  # noqa: ARG002
            seen["runner"] = root  # override: skip which(binary), capture the root we're handed
            return RunnerResult(self.id, available=True)

    monkeypatch.setattr(audit_mod, "select_guards", lambda profile: [_GuardProbe()])
    monkeypatch.setattr(audit_mod, "select_runners", lambda profile: [_RunnerProbe()])
    monkeypatch.chdir(chdir_to)
    audit_mod.audit(path_arg, run_scanners=True)
    return seen


def _assert_no_double_join(root: Path, repo: Path) -> None:
    """The captured root is absolute and equals the resolved repo. The absoluteness check is
    the discriminator for #894: a raw relative root is what double-joins downstream, so a
    relative root fails here first. The join simulation below is a belt-and-suspenders guard
    against a *different* failure mode (an absolute-but-still-doubled root), not today's
    regression — kept deliberately, but is_absolute() is what proves the fix."""
    assert root.is_absolute(), f"root handed downstream is relative: {root!r}"
    assert root == repo.resolve()
    # Mirror what gitleaks/trivy do: target = str(root), cwd = root. An absolute target ignores
    # cwd (a no-op join); a relative one would nest into a missing <root>/<root>.
    joined = root / str(root)  # `Path / absolute_str` == the absolute path (join no-op)
    assert joined.exists() and joined.resolve() == repo.resolve()


def test_audit_hands_an_absolute_root_for_a_relative_repo_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#894 revival: `agentsec audit minirepo` from the parent dir must resolve `minirepo` to an
    absolute root before guards/runners see it — otherwise five scanners double-join and go silent."""
    repo = tmp_path / "minirepo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

    seen = _dispatch_roots(monkeypatch, chdir_to=tmp_path, path_arg=Path("minirepo"))

    assert set(seen) == {"guard", "runner"}  # both dispatch points were actually reached
    _assert_no_double_join(seen["guard"], repo)
    _assert_no_double_join(seen["runner"], repo)


def test_audit_absolute_repo_path_stays_absolute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No-regression (the direction traded against): the absolute-path invocation that already
    worked keeps handing guards/runners the same absolute root."""
    repo = tmp_path / "minirepo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

    seen = _dispatch_roots(monkeypatch, chdir_to=tmp_path, path_arg=repo.resolve())

    _assert_no_double_join(seen["guard"], repo)
    _assert_no_double_join(seen["runner"], repo)


def test_audit_bare_dot_repo_path_resolves_to_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Edge case that MASKED the bug: `agentsec audit .` was never broken (a `.` join is a no-op).
    It must still resolve to an absolute root equal to the CWD repo."""
    repo = tmp_path / "minirepo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")

    seen = _dispatch_roots(monkeypatch, chdir_to=repo, path_arg=Path("."))

    _assert_no_double_join(seen["guard"], repo)
    _assert_no_double_join(seen["runner"], repo)
