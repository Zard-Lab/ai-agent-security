"""The run-scoped parse / read / `_conditional_lines` memos (#597).

A pure-refactor speedup, so the test that matters is equivalence (CLAUDE.md rule 1 for a change with
no intended behaviour change): an audit with the memos on must equal one with them off, field for
field, over the targets that exercise the most guards. The rest pins the two contracts the memos
rest on: parsed trees are SHARED, so no guard may write to one; and the read memo is keyed by PATH,
so it must never be live where files are edited between reads (the pragma-anchoring gate does
exactly that inside `derived_state_run()`)."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

import agentsec.astutil as astutil
import agentsec.guards.base as base
from agentsec.audit import AuditResult, audit
from agentsec.canary import write_canary_repo
from agentsec.clean_canary import write_clean_canary_repo
from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.guards.base import Guard

_FIXTURES = Path(__file__).resolve().parent / "fixtures"


class _NeverStores(dict[str, frozenset[int]]):
    """A `_conditional_lines` table that never holds anything: the memo-off arm."""

    def __setitem__(self, key: str, value: frozenset[int]) -> None:
        return None


def _memos_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(astutil, "_MAX_PARSE_CACHE_NODES", -1)
    monkeypatch.setattr(base, "_MAX_READ_CACHE_CHARS", -1)
    monkeypatch.setattr(base, "_conditional_lines_cache", _NeverStores())


def _shape(result: AuditResult) -> tuple[object, ...]:
    findings = [
        (f.check_id, f.rule, f.severity, f.location, f.message, tuple(f.standards), f.fingerprint())
        for f in result.findings
    ]
    return findings, result.ran, result.skipped, result.tools_errored


@pytest.mark.slow  # two canary-sized audits per target
@pytest.mark.parametrize("target", ["canary", "clean-canary", "fixtures"])
def test_the_memos_change_no_audit_result(
    target: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if target == "canary":
        root = write_canary_repo(tmp_path / "t")
    elif target == "clean-canary":
        root = write_clean_canary_repo(tmp_path / "t")
    else:
        root = _FIXTURES
    on = audit(root, run_scanners=False)
    assert on.findings or target == "clean-canary", "an audit with no findings proves no equivalence"
    with monkeypatch.context() as m:
        _memos_off(m)
        off = audit(root, run_scanners=False)
    assert _shape(on) == _shape(off)


@pytest.mark.slow
def test_no_guard_writes_to_a_shared_parse_tree(tmp_path: Path) -> None:
    """Every guard fires on the canary. Holding the run open around the audit keeps its parse table
    alive afterwards, so each cached tree can be compared with a fresh parse of its text: a guard
    that annotated or rewrote a node (a parent pointer, a shifted position) would leave a tree that
    no longer equals what the next caller would have parsed."""
    root = write_canary_repo(tmp_path / "canary")
    with base.derived_state_run():
        audit(root, run_scanners=False)
        cached = dict(astutil._parse_cache)
    assert len(cached) > 50, "the canary audit cached almost nothing; the check would be vacuous"
    for text, tree in cached.items():
        if tree is None:
            continue
        assert _same_tree(tree, astutil._parse(text, "<fresh>")), (
            f"a guard mutated a shared parse tree (text starts {text[:60]!r})"
        )


def _same_tree(a: ast.AST, b: ast.AST) -> bool:
    """`ast.dump` serialises only `_fields` and `_attributes`, so it catches a rewritten node or a
    shifted position but is blind to an ad-hoc attribute such as `node.parent = ...`, the most
    common way a caller would annotate a shared tree. Comparing each node's instance attribute
    names as well closes that gap."""
    if ast.dump(a, include_attributes=True) != ast.dump(b, include_attributes=True):
        return False
    return all(vars(x).keys() == vars(y).keys() for x, y in zip(ast.walk(a), ast.walk(b), strict=True))


def test_the_shared_tree_check_sees_every_kind_of_write() -> None:
    """Negative control for `test_no_guard_writes_to_a_shared_parse_tree` (#1146 round-1 review,
    R1-M1): the comparison must fail on each kind of write it claims to catch, not only pass on an
    untouched tree."""
    text = "def f(x):\n    return x\n"
    assert _same_tree(ast.parse(text), ast.parse(text))
    annotated = ast.parse(text)
    for node in ast.walk(annotated):
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, ast.expr_context):  # Load/Store are interpreter-wide singletons
                child.parent = node  # type: ignore[attr-defined]
    assert not _same_tree(annotated, ast.parse(text)), "a parent pointer went unseen"
    shifted = ast.parse(text)
    ast.increment_lineno(shifted, 3)
    assert not _same_tree(shifted, ast.parse(text)), "a shifted position went unseen"
    rewritten = ast.parse(text)
    fn = rewritten.body[0]
    assert isinstance(fn, ast.FunctionDef)
    fn.body.append(ast.Pass())
    assert not _same_tree(rewritten, ast.parse(text)), "a rewritten body went unseen"


def test_the_read_memo_is_not_live_inside_derived_state_run_alone(tmp_path: Path) -> None:
    """The pragma-anchoring gate edits canary files between probes inside `derived_state_run()`.
    A path-keyed read served there would hand every probe the unedited file, and the gate would
    pass while testing nothing."""
    f = tmp_path / "a.py"
    f.write_text("one\n", encoding="utf-8")
    with base.derived_state_run():
        assert base.read(f) == "one\n"
        f.write_text("two\n", encoding="utf-8")
        assert base.read(f) == "two\n"


def test_the_read_memo_serves_one_run_and_clears_after_it(tmp_path: Path) -> None:
    f = tmp_path / "a.py"
    f.write_text("one\n", encoding="utf-8")
    with base.read_run():
        assert base.read(f) == "one\n"
        f.write_text("two\n", encoding="utf-8")
        assert base.read(f) == "one\n", "inside one run the target is fixed, so the read is memoised"
        with base.read_run():  # re-entrant: a nested scope shares the table
            assert base.read(f) == "one\n"
    assert base.read(f) == "two\n", "the memo outlived its run"
    with base.read_run():
        assert base.read(f) == "two\n", "a new run was served the previous run's text"


def test_the_read_memo_stops_at_its_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base, "_MAX_READ_CACHE_CHARS", 3)
    f = tmp_path / "a.py"
    f.write_text("four\n", encoding="utf-8")
    with base.read_run():
        base.read(f)
        f.write_text("five\n", encoding="utf-8")
        assert base.read(f) == "five\n", "a text over the cap was cached anyway"


def test_a_cached_parse_failure_still_records_every_file() -> None:
    """#1001's disclosure names each file that failed to parse; the memo must not hide the second."""
    with astutil.parse_failure_run(), astutil.parse_cache_run():
        assert astutil.safe_ast_parse("def (:\n", filename="a.py") is None
        assert astutil.safe_ast_parse("def (:\n", filename="b.py") is None
        assert astutil.parse_failure_candidates().paths == frozenset({"a.py", "b.py"})


def test_the_parse_memo_shares_within_a_run_and_not_across_runs() -> None:
    with astutil.parse_cache_run():
        first = astutil.safe_ast_parse("x = 1\n")
        assert astutil.safe_ast_parse("x = 1\n") is first
        # Keyed by TEXT, not by file: guards pass different filenames for the same text, so a key
        # that carried the filename would defeat the memo with every finding unchanged (R1-M3).
        assert astutil.safe_ast_parse("x = 1\n", filename="a.py") is first
        assert astutil.safe_ast_parse("x = 1\n", filename=Path("b.py")) is first
    with astutil.parse_cache_run():
        assert astutil.safe_ast_parse("x = 1\n") is not first
    assert astutil.safe_ast_parse("x = 1\n") is not astutil.safe_ast_parse("x = 1\n"), (
        "outside a run every call must parse afresh"
    )


def test_conditional_lines_is_memoised_by_text_in_a_run() -> None:
    text = "if x:\n    y = 1\n"
    with base.derived_state_run():
        a = base._conditional_lines(text)
        assert base._conditional_lines_cache[text] == a == frozenset({2})
    assert text not in base._conditional_lines_cache


def test_a_transient_parse_failure_is_not_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    """A RecursionError or MemoryError depends on the interpreter's state at the call (the stack depth
    it was reached from), not only on the text, so it must not be served as a permanent failure to
    every later caller in the run (#1146 round-1 review, R1-L1). A SyntaxError is a property of the
    text and stays cached."""
    real = astutil._parse
    calls: list[str] = []

    def flaky(text: str, filename: object) -> ast.AST:
        calls.append(text)
        if text == "x = 1\n" and calls.count(text) == 1:
            raise RecursionError("deep caller stack")
        return real(text, filename)  # type: ignore[arg-type]

    monkeypatch.setattr(astutil, "_parse", flaky)
    with astutil.parse_failure_run(), astutil.parse_cache_run():
        assert astutil.safe_ast_parse("x = 1\n", filename="a.py") is None
        assert astutil.safe_ast_parse("x = 1\n", filename="b.py") is not None, (
            "a transient failure was cached for the rest of the run"
        )
        assert astutil.safe_ast_parse("def (:\n", filename="c.py") is None
        assert astutil.safe_ast_parse("def (:\n", filename="d.py") is None
        assert calls.count("def (:\n") == 1, "a SyntaxError is a property of the text and stays cached"
        assert astutil.parse_failure_candidates().paths == frozenset({"a.py", "c.py", "d.py"})


@pytest.mark.slow
def test_the_memos_are_engaged_during_a_real_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The equivalence test above passes whether or not a memo is wired in; this one fails if
    `audit()` stops opening the scopes (#1146 review, M2). Every distinct text is parsed once and every
    file `read()` reads is read from disk once, where without the memos both repeat per guard."""
    root = write_canary_repo(tmp_path / "canary")
    parses: list[str] = []
    real_parse = astutil._parse

    def counting_parse(text: str, filename: object) -> ast.AST:
        parses.append(text)
        return real_parse(text, filename)  # type: ignore[arg-type]  # filename passes through as given

    disk_reads: list[Path] = []
    real_read_text = Path.read_text

    def counting_read_text(self: Path, *args: object, **kwargs: object) -> str:
        import sys

        if sys._getframe(1).f_code is base.read.__code__:
            disk_reads.append(self)
        return real_read_text(self, *args, **kwargs)  # type: ignore[arg-type]  # same pass-through

    monkeypatch.setattr(astutil, "_parse", counting_parse)
    monkeypatch.setattr(Path, "read_text", counting_read_text)
    audit(root, run_scanners=False)
    assert parses and disk_reads, "the canary audit parsed or read nothing; the check is vacuous"
    assert len(parses) == len(set(parses)), f"{len(parses) - len(set(parses))} repeated parses: no parse memo"
    assert len(disk_reads) == len(set(disk_reads)), f"{len(disk_reads) - len(set(disk_reads))} repeated reads"


def test_the_guard_worker_child_runs_inside_the_memos(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The budgeted lanes run guards in a child (`guard_worker._child_main`), which opens its own run
    scopes; the in-process equivalence test never reaches it (#1146 review, M2 / L3). Driven here
    in-process over a pipe, with a guard that reports which scopes are open, and the lane's share of
    the per-audit parse-cache cap (an uncut cap would multiply by the lane count)."""
    import multiprocessing

    from agentsec.detect import StackProfile
    from agentsec.findings import Finding
    from agentsec.guard_worker import _child_main
    from agentsec.guards.base import Guard

    class ScopeProbe(Guard):
        id = "test-scope-probe"
        title = "scope probe"

        def applies(self, profile: StackProfile) -> bool:
            return True

        def run(self, root: Path, profile: StackProfile) -> list[Finding]:
            open_ = (f"read={base._read_depth} parse={astutil._parse_depth} derived={base._derived_depth} "
                     f"share={astutil._parse_cache_share}")
            return [Finding(check_id=self.id, severity="info", title=self.title, location="", message=open_)]

    monkeypatch.setattr(astutil, "_parse_cache_share", 1)  # the "child" runs in this process: restore it
    parent, child = multiprocessing.Pipe()
    _child_main(tmp_path, StackProfile(root=tmp_path), [ScopeProbe()], child, 4)
    messages = [parent.recv()]
    while messages[-1][0] != "end":  # the child closes its end after ("end",)
        messages.append(parent.recv())
    done = [m for m in messages if m[0] == "done"]
    assert done and done[0][3] is False, messages
    assert done[0][2][0].message == "read=1 parse=1 derived=1 share=4", done[0][2][0].message


def test_a_conditional_lines_cache_hit_still_records_a_parse_failure() -> None:
    """#1146 review, L1: `_conditional_lines` caches an empty set for broken text, which is also its
    answer for text with no `if`. The second file with the same broken text must still be recorded
    for #1001's disclosure."""
    with astutil.parse_failure_run(), base.derived_state_run():
        assert base._conditional_lines("def (:\n", filename="a.py") == frozenset()
        assert base._conditional_lines("def (:\n", filename="b.py") == frozenset()
        assert astutil.parse_failure_candidates().paths == frozenset({"a.py", "b.py"})


def _nodes(text: str) -> int:
    return sum(1 for _ in ast.walk(ast.parse(text)))


def test_the_parse_memo_cap_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    """#1146 round-3 review, R3-M1: the node cap is what bounds the memo's memory, so its edges are
    pinned directly. Exactly at the cap is stored; past it the text is still parsed and returned,
    nothing is stored, a smaller text still fits, a failure is still recorded (#1001), and the
    counter resets when the run ends."""
    small, big = "x = 1\n", "x = 1\ny = 2\n"
    n = _nodes(small)
    assert _nodes(big) > n
    monkeypatch.setattr(astutil, "_MAX_PARSE_CACHE_NODES", n)
    with astutil.parse_failure_run(), astutil.parse_cache_run():
        tree = astutil.safe_ast_parse(big)
        assert isinstance(tree, ast.Module) and len(tree.body) == 2, "a past-cap text must still parse"
        assert big not in astutil._parse_cache and astutil._parse_cache_nodes == 0
        assert astutil.safe_ast_parse(small) is astutil.safe_ast_parse(small), "exactly at the cap is stored"
        assert astutil._parse_cache_nodes == n
        assert astutil.safe_ast_parse("def (:\n", filename="z.py") is None
        assert "def (:\n" not in astutil._parse_cache, "a full cache stored a failure"
        assert astutil.parse_failure_candidates().paths == frozenset({"z.py"})
    assert astutil._parse_cache_nodes == 0 and not astutil._parse_cache, "the run left its table behind"


def test_the_parse_memo_cap_is_divided_by_the_lane_share(monkeypatch: pytest.MonkeyPatch) -> None:
    """R3-M1: each budgeted lane child holds 1/N of the per-audit cap. A text that fits the whole cap
    but not half of it is cached at share 1 and not at share 2."""
    text = "x = 1\n"
    monkeypatch.setattr(astutil, "_MAX_PARSE_CACHE_NODES", 2 * _nodes(text) - 1)
    for share, stored in ((1, True), (2, False)):
        monkeypatch.setattr(astutil, "_parse_cache_share", share)
        with astutil.parse_cache_run():
            astutil.safe_ast_parse(text)
            assert (text in astutil._parse_cache) is stored, f"share={share}"


def test_the_parse_memo_charges_for_the_text_it_keeps(monkeypatch: pytest.MonkeyPatch) -> None:
    """#1146 round-3 review, R3-M4: the table keeps every source text as a key, so the cap must
    count it. A comment-only module is one node however long it is, and a failed parse has no tree
    at all; both used to be stored for free, so neither the text nor the number of entries was
    bounded."""
    monkeypatch.setattr(astutil, "_MAX_PARSE_CACHE_NODES", 10)
    long_comment = "#" * (astutil._KEY_CHARS_PER_NODE * 20) + "\n"
    assert _nodes(long_comment) == 1
    with astutil.parse_failure_run(), astutil.parse_cache_run():
        assert astutil.safe_ast_parse(long_comment) is not None
        assert long_comment not in astutil._parse_cache, "a long text was stored as if it cost one node"
        broken = [f"def f{i}(:\n" for i in range(15)]
        for i, text in enumerate(broken):
            assert astutil.safe_ast_parse(text, filename=f"b{i}.py") is None
        assert sum(t in astutil._parse_cache for t in broken) <= 10, "failures were stored for free"
        assert len(astutil.parse_failure_candidates().paths) == 15, "every failing file is still recorded"


class _Quiet(Guard):
    """A trivial picklable guard for the lane-plumbing spy below (spawn pickles it by reference)."""

    id = "test-run-memo-quiet"
    title = "quiet"

    def applies(self, profile: StackProfile) -> bool:
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        return []


class _QuietToo(_Quiet):
    id = "test-run-memo-quiet-too"


@pytest.mark.parametrize("workers", [1, 2])
def test_every_lane_child_is_told_how_many_lanes_share_the_cap(
    workers: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1146 round-3 review, R3-M2: the child applies the share it is handed, but nothing pinned that
    the lane driver hands it one. Without it every lane holds the whole cap, the multiplication the
    share exists to prevent, and the run still reports success."""
    from agentsec import guard_worker
    from agentsec.guard_worker import run_guards_budgeted

    real_process = guard_worker._CTX.Process
    handed: list[object] = []

    def spy(*args: object, **kwargs: object) -> object:
        child_args = kwargs.get("args")
        assert isinstance(child_args, tuple)
        handed.append(child_args[-1])
        return real_process(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(guard_worker._CTX, "Process", spy)
    out = run_guards_budgeted(tmp_path, StackProfile(root=tmp_path), [_Quiet(), _QuietToo()],
                              budget=60.0, workers=workers)
    assert set(out.ran) == {"test-run-memo-quiet", "test-run-memo-quiet-too"}
    assert out.fallback_inprocess is False, "the lanes never ran as children"
    assert handed and all(h == workers for h in handed), handed
