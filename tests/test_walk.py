"""Tests for the shared repo-walking layer (`agentsec.walk`).

Covers the gitignore matcher (negation / dir-only / anchoring / globs), nested
gitignores, nested-worktree skipping, the stable-ordering invariant, and the
sandbox-cleanliness of the module itself (it is imported into the guard path).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from agentsec import walk
from agentsec.guard_sandbox import evaluate
from agentsec.walk import (
    DEFAULT_EXCLUDE_DIRS,
    GitignoreMatcher,
    _Meter,
    gitignore_cap_notices,
    is_worktree_link,
    walk_files,
    walk_run,
)


def _names(paths: list[Path], root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in paths}


# --- gitignore matcher unit tests -------------------------------------------


def test_matcher_basic_and_anchoring() -> None:
    m = GitignoreMatcher.from_text("*.log\n/build\nfoo/bar\n")
    assert m.match("app.log", False)              # *.log anywhere
    assert m.match("sub/dir/app.log", False)
    assert m.match("build", True)                 # /build anchored at root
    assert not m.match("sub/build", True)         # not at root
    assert m.match("foo/bar", True)               # internal slash → anchored
    assert not m.match("x/foo/bar", True)


def test_matcher_dir_only_and_star_scope() -> None:
    m = GitignoreMatcher.from_text("cache/\n")
    assert m.match("cache", True)                 # dir-only matches a dir
    assert not m.match("cache", False)            # ...but not a file named cache
    star = GitignoreMatcher.from_text("a*b\n")
    assert star.match("axxb", False)
    assert not star.match("a/b", False)           # `*` does not cross `/`


def test_matcher_doublestar_crosses_slash() -> None:
    m = GitignoreMatcher.from_text("logs/**\n")
    assert m.match("logs/a/b/c.txt", False)


def test_matcher_negation_reincludes() -> None:
    # the flagship pattern: ignore .env.*, but keep .env.example
    m = GitignoreMatcher.from_text(".env.*\n!.env.example\n")
    assert m.match(".env.local", False)
    assert not m.match(".env.example", False)     # re-included by the later !rule


def test_matcher_blanks_and_comments_ignored() -> None:
    m = GitignoreMatcher.from_text("# a comment\n\n   \n*.tmp\n")
    assert m.match("x.tmp", False) and not m.match("x.py", False)


def test_matcher_doublestar_between_segments() -> None:
    m = GitignoreMatcher.from_text("a/**/b\n")
    assert m.match("a/b", False)                  # `**/` matches zero dirs
    assert m.match("a/x/b", False)
    assert m.match("a/x/y/b", False)
    assert not m.match("a/xb", False)


def test_matcher_hostile_pattern_is_linear() -> None:
    # Regression (issue #419, audit-killer #1): a crafted `*a*a*…*b` pattern against a
    # resistant path hung every audit — each `*` became a `[^/]*` regex group and the
    # backtracking engine tried every combination (exponential: ~18× per two added
    # segments, reproduced at 1.763s for just 12 stars). The token matcher is linear;
    # an exponential form would exceed this budget by orders of magnitude.
    import time

    m = GitignoreMatcher.from_text("*a" * 25 + "b\n")
    name = "a" * 300 + "c"
    start = time.monotonic()
    assert m.match(name, False) is False           # resistant: no trailing `b`
    assert m.match("a" * 50 + "b", False) is True  # the pattern still works
    assert time.monotonic() - start < 1.0, "exponential gitignore backtracking reintroduced"


# --- walk_files integration -------------------------------------------------


def _build_repo(root: Path) -> None:
    (root / "src").mkdir()
    (root / "src" / "main.py").write_text("x = 1\n", encoding="utf-8")
    (root / "generated").mkdir()
    (root / "generated" / "huge.py").write_text("# generated\n", encoding="utf-8")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "dep.py").write_text("# vendored\n", encoding="utf-8")
    (root / "app.log").write_text("noise\n", encoding="utf-8")
    (root / ".env.example").write_text("KEY=value\n", encoding="utf-8")
    (root / ".env.local").write_text("SECRET=real\n", encoding="utf-8")
    (root / ".gitignore").write_text("generated/\n*.log\n.env.*\n!.env.example\n", encoding="utf-8")


def test_walk_honors_gitignore_and_default_dirs(tmp_path: Path) -> None:
    _build_repo(tmp_path)
    names = _names(walk_files(tmp_path), tmp_path)
    assert "src/main.py" in names
    assert ".env.example" in names                # negation kept it (payments-detection critical)
    assert "generated/huge.py" not in names       # gitignored dir pruned
    assert "node_modules/dep.py" not in names      # DEFAULT_EXCLUDE_DIRS pruned
    assert "app.log" not in names                  # *.log gitignored
    assert ".env.local" not in names               # .env.* gitignored


def test_walk_suffix_filter(tmp_path: Path) -> None:
    _build_repo(tmp_path)
    py = _names(walk_files(tmp_path, suffixes=(".py",)), tmp_path)
    assert py == {"src/main.py"}                    # only the non-ignored .py file


def test_walk_skips_nested_worktree(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("x = 1\n", encoding="utf-8")
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / ".git").write_text("gitdir: /somewhere/.git/worktrees/wt\n", encoding="utf-8")  # worktree link marker
    (wt / "other.py").write_text("y = 2\n", encoding="utf-8")
    assert is_worktree_link(wt) is True
    names = _names(walk_files(tmp_path), tmp_path)
    assert "keep.py" in names
    assert "wt/other.py" not in names               # the linked worktree is skipped whole


def test_walk_nested_gitignore(tmp_path: Path) -> None:
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "app.tsx").write_text("//\n", encoding="utf-8")
    (tmp_path / "frontend" / "scratch.tsx").write_text("//\n", encoding="utf-8")
    (tmp_path / "frontend" / ".gitignore").write_text("scratch.tsx\n", encoding="utf-8")
    names = _names(walk_files(tmp_path), tmp_path)
    assert "frontend/app.tsx" in names
    assert "frontend/scratch.tsx" not in names      # nested gitignore honored


def test_walk_is_sorted_and_deterministic(tmp_path: Path) -> None:
    for n in ("c.py", "a.py", "b.py"):
        (tmp_path / n).write_text("x\n", encoding="utf-8")
    first = walk_files(tmp_path)
    assert first == sorted(first)                   # stable ordering invariant
    assert walk_files(tmp_path) == first            # two-run byte-identical


def test_walk_missing_dir_is_empty(tmp_path: Path) -> None:
    assert walk_files(tmp_path / "nope") == []


def test_walk_deep_tree_does_not_hit_recursion_limit(tmp_path: Path) -> None:
    # Regression (issue #419, audit-killer #2): _collect recursed one Python stack frame
    # per directory level, so a ~1200-deep tree (well past sys.getrecursionlimit()'s
    # default 1000) aborted the audit with an uncaught RecursionError — walk_files runs
    # in detect(), BEFORE the per-guard crash containment. The walk is now iterative.
    #
    # The tree MUST be torn down here (issue #546). pytest retains tmp dirs
    # (`tmp_path_retention_count` defaults to 3) and garbage-collects the older ones on a
    # LATER session via shutil.rmtree, which on CPython <= 3.12.3 recurses one frame per
    # directory level — the very defect this test proves walk_files does not have. Leaving
    # the tree behind therefore kills an unrelated later run inside pytest_sessionfinish
    # (measured: run 4 onward, permanently, since a failed delete becomes a `garbage-*`
    # dir that is retried every session). Unwinding the recorded chain bottom-up is O(depth),
    # does no traversal of its own, and uses the depth actually ACHIEVED — the loop breaks
    # early on the Windows MAX_PATH ceiling, so the nominal 1500 is not a safe assumption.
    # `shutil.rmtree` cannot be used for the same reason it fails in pytest's GC, and
    # `ignore_errors=True` does not help: RecursionError is not routed through it.
    # Guard the guard: the REQUESTED depth must stay above the interpreter's recursion
    # limit, or this test silently stops exercising #419 at all. Asserted on the requested
    # depth, not the achieved one — a platform that caps path length (Windows MAX_PATH)
    # truncates the tree to ~130 levels, which we cannot control and must not fail on.
    requested_depth = 1500
    assert requested_depth > sys.getrecursionlimit()
    root = tmp_path / "deep"
    root.mkdir()
    chain: list[Path] = []
    d = root
    for _ in range(requested_depth):
        d = d / "d"
        try:
            d.mkdir()
        except OSError:  # platform path-length ceiling (e.g. Windows MAX_PATH)
            d = d.parent
            break
        chain.append(d)
    try:
        (d / "leaf.py").write_text("x = 1\n", encoding="utf-8")
        files = walk_files(root, suffixes=(".py",))
        assert any(p.name == "leaf.py" for p in files)
    finally:
        if d.exists():
            for child in d.iterdir():
                if child.is_file():
                    child.unlink()
        for created in reversed(chain):
            created.rmdir()
        root.rmdir()
    # #546: nothing may be left for pytest's GC to trip over on a later run. Runs only when
    # the body passed — a real #419 regression keeps its own traceback, but is still cleaned up.
    assert not root.exists()


# --- doctrine: the shared helper is sandbox-clean ---------------------------


def test_walk_module_is_sandbox_clean() -> None:
    # walk.py is imported into the guard path (iter_files), so it must satisfy the
    # Guard Sandbox Contract: no os/subprocess/network/dynamic-import/file-write.
    source = (Path(__file__).resolve().parents[1] / "agentsec" / "walk.py").read_text(encoding="utf-8")
    assert evaluate("walk.py", source) == []


def test_default_exclude_dirs_shared() -> None:
    # the single source of truth still carries the vendored-dir names guards rely on
    assert {"node_modules", "__pycache__", ".venv", "dist"} <= DEFAULT_EXCLUDE_DIRS


def test_walk_does_not_follow_inner_symlinks_but_follows_root(tmp_path: Path) -> None:
    """A symlink found mid-walk is not followed — a hostile target repo can't escape the
    tree via `evil -> /` or self-cycle via `loop -> .` — but a top-level symlink target IS
    scanned (the supported Test-FE / corpus 'scan a private repo via a generic symlink' pattern)."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "real.py").write_text("x = 1\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("SECRET = 1\n", encoding="utf-8")
    (repo / "evil").symlink_to(outside, target_is_directory=True)   # escape attempt
    (repo / "loop").symlink_to(repo, target_is_directory=True)      # cycle (must not RecursionError)

    names = {p.name for p in walk_files(repo, suffixes=(".py",))}
    assert "real.py" in names
    assert "secret.py" not in names  # inner symlink not followed → no escape

    # the root target itself is followed even when it is a symlink
    link = tmp_path / "link"
    link.symlink_to(repo, target_is_directory=True)
    via_link = {p.name for p in walk_files(link, suffixes=(".py",))}
    assert "real.py" in via_link
    assert "secret.py" not in via_link


# --- .gitignore resource caps + the walk memo (issue #419 / PR #430) ----------
#
# The pre-existing `test_matcher_hostile_pattern_is_linear` above cannot catch this
# class: one rule, 25 stars, a 300-char name — ~2 ms against a 1 s budget, four orders
# of magnitude of headroom. It proves the matcher is not EXPONENTIAL. It says nothing
# about the cost that actually bit, which is the (rule x entry) PRODUCT: the matcher is
# run for every rule against every walked path, and nothing bounded either factor.
#
# The tests below are sized so they FAIL if a cap is taken away — verified by actually
# removing them (see `test_..._collapses_without_the_cap`, which does the removal
# in-process and asserts the blow-up, so the teeth are checked by CI, not by hand).

_STEPS_BUDGET = 10**15  # a meter big enough to COUNT steps rather than cap them


def _resistant_gitignore(n_rules: int) -> str:
    """`*a*ab` x n. Five characters per rule, but against an `aaaa…` path every `*`
    keeps the whole position set alive — the shape that costs the most per byte.
    NOT matched by the trailing `b`, so nothing is pruned and every entry stays."""
    return "\n".join("*a*ab" for _ in range(n_rules)) + "\n"


def _steps_for(text: str, path: str) -> int:
    """Deterministic work (position-set steps) one `.gitignore` spends on one path."""
    meter = _Meter(_STEPS_BUDGET)
    GitignoreMatcher.from_text(text).status(path, False, meter)
    return _STEPS_BUDGET - meter.left


def _hostile_repo(root: Path, n_files: int, gitignore: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for i in range(n_files):
        (root / (("a" * 30) + f"{i:06d}.py")).write_text("x = 1\n", encoding="utf-8")
    (root / ".gitignore").write_text(gitignore, encoding="utf-8")


def test_hostile_gitignore_work_per_path_is_capped() -> None:
    """The deterministic half of the regression — no wall clock, so it cannot flake.

    A 5,000-rule hostile `.gitignore` must cost no more per path than the per-entry
    budget, however many rules it declares."""
    hostile = _resistant_gitignore(5000)
    spent = _steps_for(hostile, "a" * 40)
    assert spent <= walk._MAX_MATCH_STEPS, f"per-path work escaped the budget: {spent:,} steps"
    # and the input caps must have thrown most of those rules away, loudly
    m = GitignoreMatcher.from_text(hostile)
    assert len(m._rules) < 200, f"{len(m._rules)} rules survived the whole-file wildcard budget"
    assert m.dropped, "rules were dropped SILENTLY — a capped scan must disclose"


def test_hostile_gitignore_work_collapses_without_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Proves the cap is load-bearing: remove it and the SAME input costs orders of
    magnitude more. If someone deletes the caps, this test fails."""
    hostile = _resistant_gitignore(5000)
    path = "a" * 40
    capped = _steps_for(hostile, path)
    for name in ("_MAX_GITIGNORE_BYTES", "_MAX_GITIGNORE_RULES", "_MAX_PATTERN_CHARS",
                 "_MAX_PATTERN_WILDCARDS", "_MAX_TOTAL_WILDCARDS", "_MAX_MATCH_STEPS"):
        monkeypatch.setattr(walk, name, 10**15)
    uncapped = _steps_for(hostile, path)
    # measured: ~27k steps capped vs ~1.6M uncapped on this input (~60x)
    assert uncapped > 20 * capped, (
        f"removing the caps changed nothing ({capped:,} -> {uncapped:,} steps) — "
        "the caps are no longer load-bearing"
    )


@pytest.mark.slow
def test_hostile_gitignore_walk_stays_within_budget(tmp_path: Path) -> None:
    """The wall-clock half: a 30 KB / 5,000-rule hostile `.gitignore` over a 100-file
    repo. Measured ~0.7 s with the caps and ~41 s with them removed (the step counts in
    the two tests above are the flake-free proof of that ratio). The 8 s ceiling leaves
    ~11x headroom for `-n auto`/CI contention while staying ~5x under the
    uncapped cost."""
    _hostile_repo(tmp_path, 100, _resistant_gitignore(5000))
    start = time.monotonic()
    files = walk_files(tmp_path)
    elapsed = time.monotonic() - start
    assert len(files) == 101  # nothing was hidden — the caps fail OPEN
    assert elapsed < 8.0, f"hostile .gitignore walk took {elapsed:.1f}s — a cap regressed"


def test_oversize_gitignore_is_skipped_and_disclosed(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "ignored.log").write_text("x\n", encoding="utf-8")
    padding = "\n".join("# " + "p" * 100 for _ in range(1000))  # >64 KiB of comments
    (tmp_path / ".gitignore").write_text(f"*.log\n{padding}\n", encoding="utf-8")
    with walk_run():
        names = {p.name for p in walk_files(tmp_path)}
        notices = gitignore_cap_notices()
    assert "ignored.log" in names, "oversize .gitignore must fail OPEN (scan more, not less)"
    assert [n.path for n in notices] == [".gitignore"]
    assert "read cap" in notices[0].detail and "NONE of its rules" in notices[0].detail


def test_real_world_gitignore_trips_no_cap() -> None:
    """Headroom check against reality: the widest `.gitignore` shape surveyed on this
    machine (141 rules / 121 wildcards / 54-char patterns) must pass untouched, so the
    caps never fire on a legitimate repo. If a cap is tightened past real-world usage,
    this fails."""
    real = "\n".join(
        ["# comment", "node_modules/", "*.log", ".env.*", "!.env.example", "/dist", "build/"]
        + [f"*.tmp{i}" for i in range(134)]
    )
    m = GitignoreMatcher.from_text(real)
    assert not m.dropped, f"a real-world .gitignore tripped a cap: {m.dropped}"
    assert _steps_for(real, "src/app/components/widget.tsx") < walk._MAX_MATCH_STEPS


def test_walk_is_memoised_within_a_run(tmp_path: Path) -> None:
    """The other half of the fix: the registered guards must not each re-walk the tree."""
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.ts").write_text("x\n", encoding="utf-8")
    calls: list[Path] = []
    real_collect = walk._collect

    def counting(directory: Path, rel: str, matchers: object, out: list[Path], rg: bool) -> None:
        calls.append(directory)
        real_collect(directory, rel, matchers, out, rg)  # type: ignore[arg-type]

    with walk_run():
        walk._collect = counting  # type: ignore[assignment]
        try:
            first = walk_files(tmp_path)
            for _ in range(20):  # what many guards asking for different suffixes looks like
                walk_files(tmp_path, suffixes=(".py",))
                walk_files(tmp_path, suffixes=(".ts",))
        finally:
            walk._collect = real_collect  # type: ignore[assignment]
    assert len(calls) == 1, f"tree was walked {len(calls)}x inside one run — memo not applied"
    assert {p.name for p in first} == {"a.py", "b.ts"}


def test_walk_memo_does_not_leak_across_roots_or_options(tmp_path: Path) -> None:
    """The cache must key on the start path AND the option set — a hit from the wrong
    root would return files that are not under the requested tree."""
    one, two = tmp_path / "one", tmp_path / "two"
    for d, name in ((one, "only_one.py"), (two, "only_two.py")):
        d.mkdir()
        (d / name).write_text("x = 1\n", encoding="utf-8")
        (d / "hidden.py").write_text("x = 1\n", encoding="utf-8")
        (d / ".gitignore").write_text("hidden.py\n", encoding="utf-8")
    with walk_run():
        assert {p.name for p in walk_files(one)} == {"only_one.py", ".gitignore"}
        assert {p.name for p in walk_files(two)} == {"only_two.py", ".gitignore"}
        # same root, different option set — must not serve the gitignore-respecting entry
        assert "hidden.py" in {p.name for p in walk_files(one, respect_gitignore=False)}
        assert "hidden.py" not in {p.name for p in walk_files(one)}


def test_walk_memo_returns_a_fresh_list_each_call(tmp_path: Path) -> None:
    """A caller that sorts/clears the list it got must not corrupt the cache."""
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("x = 1\n", encoding="utf-8")
    with walk_run():
        first = walk_files(tmp_path)
        assert len(first) == 2
        first.clear()
        first.append(tmp_path / "bogus.py")
        second = walk_files(tmp_path)
    assert len(second) == 2 and second is not first


def test_walk_memo_is_inactive_outside_a_run(tmp_path: Path) -> None:
    """No global cache between audits: a file added after the first walk must show up."""
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert len(walk_files(tmp_path)) == 1
    (tmp_path / "b.py").write_text("x = 1\n", encoding="utf-8")
    assert len(walk_files(tmp_path)) == 2


def test_budget_trip_never_leaves_an_entry_ignored(tmp_path: Path) -> None:
    """A spent per-entry budget must force NOT-ignored, never a partial "ignored" verdict.

    `status()` used to `break` and return whatever the rules evaluated so far had decided. That is
    safe only while no earlier rule has already set `result = True`. The counter-case is the textbook
    ignore-everything-then-allow-list idiom, and it is not exotic:

        *                    <- blanket ignore, sets result = True
        <170 resistant rules><- spends the per-entry budget
        !<target>            <- the re-include is NEVER REACHED

    so the entry stayed IGNORED and the file was silently skipped (#494 agentic gate). Silent coverage
    loss is worse than the DoS the budget exists to stop: a slow audit is visible, a missing file is not.

    The existing hostile-gitignore tests cannot catch this — their filler rules are engineered never to
    MATCH, so no rule ever sets `ignored=True` and trip-handling is never composed with an already-true
    verdict. This test is that composition, and it fails red against the pre-fix code.
    """
    target = "target_" + "x" * 200 + "_secret.py"
    (tmp_path / ".gitignore").write_text(
        "\n".join(["*"] + ["*a*a*ab"] * 170 + ["!" + target]) + "\n", encoding="utf-8"
    )
    (tmp_path / target).write_text("SECRET = 'aws_key'\n", encoding="utf-8")

    names = {p.name for p in walk_files(tmp_path, suffixes=(".py",))}
    assert target in names, "a re-included file was starved by the budget and silently skipped"


def test_budget_trip_does_not_disturb_ordinary_negation(tmp_path: Path) -> None:
    """The other direction: forcing not-ignored on a trip must not weaken normal gitignore semantics
    when there is no budget pressure at all."""
    (tmp_path / ".gitignore").write_text(".env.*\n!.env.example\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text("A=1\n", encoding="utf-8")
    (tmp_path / ".env.local").write_text("B=2\n", encoding="utf-8")

    names = {p.name for p in walk_files(tmp_path)}
    assert ".env.example" in names   # re-included
    assert ".env.local" not in names  # still ignored
