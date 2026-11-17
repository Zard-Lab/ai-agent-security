"""Shared repo-walking layer — the single source of truth for *which files agentsec
looks at*.

Both the detection walk (`detect._walk`) and the guard scan helper
(`guards.base.iter_files`) route through `walk_files()`, so the exclude policy lives
in exactly one place instead of two drifting hardcoded sets. On top of the static
vendored/build dir list it:

- **honors `.gitignore`** (a small, dependency-free matcher: negation, dir-only,
  anchoring, `*`/`?`/`**`) — the repo's own ignores, evaluated relative to the walk's
  start dir and any nested `.gitignore` below it; and
- **skips nested git worktrees** — a subdir whose `.git` is a *file* (the worktree
  link marker) is a checkout of another branch, not part of this tree.

⚖ This module is imported into the **guard path** (`iter_files`), so it honors the
Guard Sandbox Contract: **`pathlib` only** — no `os`, `subprocess`, `socket`, or file
writes, and worktree detection inspects the filesystem directly rather than shelling
out to `git`. `walk_files` returns a **sorted** list so two runs over the same tree
are byte-identical (the determinism invariant the guards rely on).

⚠ Everything here runs on **attacker-controlled input** (the target repo's tree and
its `.gitignore` files) *before* the per-guard crash containment in `audit.py`, so a
hang or abort here kills the whole audit. Hence four hard rules (issues #419, #430):

1. glob patterns are matched with the linear token matcher below — NEVER compiled
   into a backtracking regex;
2. the tree walk is iterative — NEVER one stack frame per directory level;
3. `.gitignore` input is **capped and metered** — being linear per query was not
   enough, because the audit pays that cost per (rule × entry) and nothing bounded
   the product. See the cap block below for the measurements; the disclosure
   (`gitignore_cap_notices`) is part of the contract, never a silent truncation; and
4. the walk is **memoised per `walk_run()` scope** — otherwise every registered guard
   re-walks the whole tree and multiplies any per-entry cost by the guard count.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

# Vendored / generated / cache dirs that are never worth scanning, independent of
# any `.gitignore`. The single source of truth (was duplicated in detect.py and
# guards/base.py). Project-agnostic — no target-specific names.
DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset({
    ".git", ".venv", "venv", "venv_linux", "node_modules", "__pycache__",
    ".mypy_cache", ".ruff_cache", ".pytest_cache", "dist", "build", ".vite",
    "coverage", "playwright-report", ".egg-info", "site-packages",
})


# --- .gitignore resource caps (issue #419 / PR #430) -------------------------
#
# `.gitignore` content is fully attacker-controlled and `status()` runs EVERY rule
# against EVERY walked entry, so the file is a work multiplier over the whole tree.
# The token matcher below is linear *per query*, but "linear" here means
# O(tokens × len(path)) per (rule, entry) — and the (rule, entry) product is the
# part nothing bounded.
#
# **Measured, and it disproves the obvious fix.** Input-size caps alone do NOT
# work. On a 500-file repo with 40-char names (walk floor 0.274 s) a `.gitignore`
# of just **96 bytes / 16 rules / 5-char patterns** (`*a*ab` ×16) takes the walk to
# **2.495 s**, and 128 such rules — fewer than the 141 a real `.gitignore` on this
# machine carries — to **13.784 s**. Conversely a 5 KB / 2,505-wildcard file costs
# only 3.720 s, because a long pattern's position set drains once the path runs out.
# So the multiplier is the RULE COUNT × path length, not bytes, not pattern length,
# and not wildcard count — and no byte/length cap set above real-world usage can
# bound it. The caps below therefore come in two kinds:
#
#   1. **Input caps** (bytes / rules / pattern chars / wildcards) — cheap structural
#      bounds on parse time and memory, and they kill the absurd shapes outright.
#      Sized with >=4x headroom over a survey of 31 real `.gitignore` files on this
#      machine (observed maxima: 5,803 bytes | 141 rules | 54-char pattern |
#      3 wildcards/rule | 121 wildcards/file).
#   2. **`_MAX_MATCH_STEPS`, a deterministic per-entry work budget** — the cap that
#      actually bounds the cost, because it bounds the (rule × path) product that
#      the input caps cannot reach. See its comment for the measured worst case.
#
# Every cap is DISCLOSED when it trips (`gitignore_cap_notices()` -> an info finding
# in `audit.py`, mirroring the oversize-PDF read cap). A scan that quietly stops
# honoring rules is worse than a slow one: silent truncation is not acceptable.

# Each line: value (headroom over the real-world max) — worst case AT that cap.
# "worst case" = the most expensive input the cap still admits, in per-entry match
# work, at 252 ns/step. Every one of them is then ALSO subject to `_MAX_MATCH_STEPS`,
# which is what makes the aggregate bounded; on their own these four are not enough.
_MAX_GITIGNORE_BYTES = 64 * 1024   # (11x 5,803) worst: the read + splitlines only,
                                   #   ~1 ms; the rule/wildcard caps below bound the
                                   #   matching, so bytes only bound parse + memory.
_MAX_GITIGNORE_RULES = 1024        # (7.3x 141)  worst: 1,024 literal-only rules ~=
                                   #   1,024 steps/entry ~= 0.26 ms/entry. Wildcard
                                   #   rules hit the 512 budget below long before this.
_MAX_PATTERN_CHARS = 256           # (4.7x 54)   worst: one pattern of <=128 wildcards
                                   #   (2 chars each) — capped harder at 64 just below.
_MAX_PATTERN_WILDCARDS = 64        # (21x 3)     worst: one rule ~= 64 x len(path)
                                   #   steps; at a 240-char path ~= 3.9 ms/entry.
# 512: the SURVEYED max was 121 wildcards/file, but that sample's widest file spends
# most of its 141 rules on anchored/literal paths. A 141-rule file of plain unanchored
# globs (`*.tmp`, each = a `**/` + a `*`) needs 282, so a cap sized on the survey alone
# would fire on a perfectly ordinary repo — caught by
# `test_real_world_gitignore_trips_no_cap`. 512 clears that shape ~1.8x over.
# Worst case at this cap: ~170 maximally-resistant rules (`*a*ab`, 3 wildcards each).
# MEASURED end-to-end on a 500-file / 40-char-name repo: walk 3.120 s = 6.2 ms/entry,
# against 2.634 s = 5.2 ms/entry for a LEGITIMATE 141-rule file on the same repo. So
# the residual amplification a hostile `.gitignore` can still buy at typical path
# lengths is ~1.2x, not the 100x+ it was (30 KB / 5,000 rules: 198.234 s -> 1.952 s).
_MAX_TOTAL_WILDCARDS = 512

# Deterministic per-entry work budget for `.gitignore` matching, in position-set
# steps (one step ~= one candidate path offset examined). It is a pure function of
# the input — no wall clock — so the walk stays byte-identical run to run, which the
# determinism invariant requires. When an entry exhausts its budget the REMAINING
# rules are skipped for that entry and the entry is treated as NOT ignored, i.e. the
# walk fails *open* (scans more, never less) and says so. Hiding a file from a
# security scan on a resource cap would be the dangerous direction.
#
# Measured cost of one step on this machine: **252 ns** (41,344 steps in 10.43 ms).
# Measured need of REAL `.gitignore` files (worst of the 31 surveyed, per path):
#     2,708 steps on `src/app/main.py` | 6,786 on a 40-char name |
#    37,416 on a realistic deep path (8 x 30-char dirs, 247 chars).
# So 100,000 steps is **2.7x the worst real file at a realistic deep path**, and it
# ceilings the attacker at 100,000 x 252 ns = **~25 ms per entry** — from which the
# whole-walk cost is 25 ms x n_entries, i.e. LINEAR in repo size and independent of
# what the `.gitignore` says. (A legitimate file only trips this past ~600-char
# paths, which the disclosure covers. A tripped entry is forced to NOT-ignored, so nothing is
# hidden — see `GitignoreMatcher.status`, which returns False rather than a partial verdict.)
_MAX_MATCH_STEPS = 100_000

_WILDCARD_TOKENS = frozenset({"*", "**", "**/"})


# --- .gitignore matcher (dependency-free) -----------------------------------


@dataclass(frozen=True)
class _Rule:
    tokens: tuple[str, ...]  # from `_tokenize` (plus a leading "**/" when unanchored)
    negated: bool      # a leading `!` re-includes
    dir_only: bool     # a trailing `/` matches directories only


def _tokenize(pat: str) -> tuple[str, ...]:
    """Split a glob pattern into matcher tokens: `"**/"` (zero or more whole leading
    dirs), `"**"` (anything, crossing `/`), `"*"` (within a segment), `"?"` (one
    non-`/` char), or a run of literal characters (never contains `*`/`?`, so the
    token kinds cannot collide)."""
    toks: list[str] = []
    lit: list[str] = []
    i, n = 0, len(pat)
    while i < n:
        c = pat[i]
        if c in "*?":
            if lit:
                toks.append("".join(lit))
                lit = []
            if pat[i:i + 2] == "**":
                i += 2
                if i < n and pat[i] == "/":
                    toks.append("**/")
                    i += 1
                else:
                    toks.append("**")
            else:
                toks.append(c)
                i += 1
        else:
            lit.append(c)
            i += 1
    if lit:
        toks.append("".join(lit))
    return tuple(toks)


class _Meter:
    """Deterministic work meter for one *entry*'s worth of `.gitignore` matching.

    Counts position-set steps (a pure function of the input — never the clock, so the
    walk stays reproducible) and reports when the per-entry budget is spent. One meter
    is shared across every rule of every active matcher for a single walked path, so
    the bound is per ENTRY, which is what makes the total cost linear in repo size."""

    __slots__ = ("left", "tripped")

    def __init__(self, budget: int | None = None) -> None:
        # Read the module global at construction (not as a default argument) so a test
        # can raise/lower the cap and observe the difference — the regression test in
        # tests/test_walk.py relies on being able to take the cap away.
        self.left = _MAX_MATCH_STEPS if budget is None else budget
        self.tripped = False

    def spend(self, steps: int) -> bool:
        """Charge `steps`; False once the budget is gone (the caller must stop)."""
        self.left -= steps
        if self.left <= 0:
            self.tripped = True
            return False
        return True


def _match_tokens(tokens: tuple[str, ...], name: str, meter: _Meter | None = None) -> bool:
    """Whether the whole of `name` matches the token sequence. `*`/`?` do not cross
    `/`; `**` does; `**/` consumes zero or more complete leading directories.

    Linear set-of-positions matcher — O(len(tokens) × len(name)) worst case. The
    pattern comes from an untrusted `.gitignore`, so it must NEVER be compiled into a
    backtracking regex: `*a*a*…*b` as adjacent `[^/]*` regex groups is exponential on
    a resistant path and hangs every audit (issue #419, audit-killer #1).

    `meter` charges each token's work against the caller's per-entry budget. Being
    linear per query was never enough on its own: the audit pays this per (rule,
    entry), and *that* product is what a hostile `.gitignore` inflates (PR #430). A
    match that runs out of budget returns False — fail OPEN, so the entry is scanned
    rather than silently hidden — and the trip is disclosed by the caller."""
    n = len(name)
    cur = {0}  # every prefix length of `name` the tokens so far can have consumed
    next_slash: list[int] | None = None
    for tok in tokens:
        if not cur:
            return False
        if meter is not None and not meter.spend(n + len(cur)):
            return False  # budget exhausted — treat as no-match (fail open), disclosed
        if tok == "**":
            cur = set(range(min(cur), n + 1))
        elif tok == "**/":
            lo = min(cur)
            cur |= {j + 1 for j in range(lo, n) if name[j] == "/"}
        elif tok == "*":
            if next_slash is None:  # next_slash[j] = first "/" at or after j (n if none)
                next_slash = [n] * (n + 1)
                for j in range(n - 1, -1, -1):
                    next_slash[j] = j if name[j] == "/" else next_slash[j + 1]
            grown: set[int] = set()
            covered = -1
            for j in sorted(cur):
                if j <= covered:
                    continue  # inside the previous position's segment range already
                end = next_slash[j] if j < n else n
                grown.update(range(j, end + 1))
                covered = end
            cur = grown
        elif tok == "?":
            cur = {j + 1 for j in cur if j < n and name[j] != "/"}
        else:  # literal run
            L = len(tok)
            cur = {j + L for j in cur if name.startswith(tok, j)}
    return n in cur


def _parse_rule(line: str) -> _Rule | None:
    """Parse one `.gitignore` line into a `_Rule` (or None for blanks/comments).
    A pattern containing a `/` is anchored to the gitignore's directory; an
    unanchored one may match at any depth (hence the prepended `"**/"` token)."""
    s = line.rstrip("\r\n").rstrip()
    if not s or s.startswith("#"):
        return None
    negated = s.startswith("!")
    if negated:
        s = s[1:]
    dir_only = s.endswith("/")
    if dir_only:
        s = s[:-1]
    if not s:
        return None
    anchored = s.startswith("/")
    if anchored:
        s = s[1:]
    if "/" in s:
        anchored = True
    toks = _tokenize(s)
    if not anchored:
        toks = ("**/",) + toks
    return _Rule(toks, negated, dir_only)


class GitignoreMatcher:
    """A compiled set of `.gitignore` rules. Last matching rule wins (so a later
    negation re-includes); `status()` is tri-state so a deeper gitignore can override
    a shallower one without a non-match silently un-ignoring a parent decision."""

    def __init__(self, rules: list[_Rule], dropped: str = "") -> None:
        self._rules = rules
        self.dropped = dropped  # "" or a one-line description of which caps trimmed the file

    def __bool__(self) -> bool:
        return bool(self._rules)

    @classmethod
    def from_text(cls, text: str) -> GitignoreMatcher:
        """Compile `text`, enforcing the input caps. Rules past a cap are DROPPED and
        named in `.dropped` so the caller can disclose them — never silently."""
        rules: list[_Rule] = []
        too_long = too_wild = over_count = over_budget = 0
        spent = 0
        for ln in text.splitlines():
            # Parse FIRST, then measure: a blank or `#` comment line is not a rule, so a
            # long one must not be reported as a dropped rule. Parsing is O(len(line))
            # and the whole file is already under the byte cap, so this is safe to do
            # before the length check.
            rule = _parse_rule(ln)
            if rule is None:
                continue
            wild = sum(1 for t in rule.tokens if t in _WILDCARD_TOKENS)
            if len(ln.rstrip()) > _MAX_PATTERN_CHARS:
                too_long += 1
            elif wild > _MAX_PATTERN_WILDCARDS:
                too_wild += 1
            elif len(rules) >= _MAX_GITIGNORE_RULES:
                over_count += 1
            elif spent + wild > _MAX_TOTAL_WILDCARDS:
                over_budget += 1
            else:
                spent += wild
                rules.append(rule)
        parts = [
            f"{n} {what}" for n, what in (
                (too_long, f"over the {_MAX_PATTERN_CHARS}-char pattern-length cap"),
                (too_wild, f"over the {_MAX_PATTERN_WILDCARDS}-wildcard per-pattern cap"),
                (over_count, f"past the {_MAX_GITIGNORE_RULES}-rule cap"),
                (over_budget, f"past the {_MAX_TOTAL_WILDCARDS}-wildcard whole-file budget"),
            ) if n
        ]
        dropped = f"{sum(int(p.split()[0]) for p in parts)} rule(s) dropped: " + "; ".join(parts) if parts else ""
        return cls(rules, dropped)

    def status(self, relpath: str, is_dir: bool, meter: _Meter | None = None) -> bool | None:
        """True = ignored, False = explicitly re-included, None = no opinion.

        `meter` is the caller's per-entry work budget (see `_Meter`); once it is spent this returns
        **False** — no verdict that would HIDE the entry may survive a trip.

        Returning the partially-accumulated verdict was not safe, and this docstring used to claim it
        was ("never more-ignored than the uncapped answer"). That holds only while no earlier rule has
        already set `result = True`. The counter-case is the textbook ignore-everything-then-allow-list
        idiom: `*` sets ignored, filler rules spend the budget, and the later `!keep-this` re-include is
        never reached — so the entry stayed IGNORED and the file was silently skipped. For a security
        tool that is worse than the DoS the budget exists to stop, because a slow audit is visible and a
        missing file is not (#494 agentic gate)."""
        result: bool | None = None
        for rule in self._rules:
            if meter is not None and meter.tripped:
                return False
            if rule.dir_only and not is_dir:
                continue
            if _match_tokens(rule.tokens, relpath, meter):
                result = not rule.negated
        return result

    def match(self, relpath: str, is_dir: bool) -> bool:
        """Whether `relpath` is ignored (a non-match counts as not-ignored)."""
        return bool(self.status(relpath, is_dir))


def _relativize(relpath: str, base: str) -> str | None:
    """`relpath` expressed relative to gitignore-base `base`, or None if not under it."""
    if not base:
        return relpath
    if relpath == base:
        return ""
    prefix = base + "/"
    return relpath[len(prefix):] if relpath.startswith(prefix) else None


def _ignored(
    relpath: str, is_dir: bool, matchers: list[tuple[str, GitignoreMatcher]]
) -> tuple[bool, bool]:
    """Combine active (base, matcher) pairs outer→inner; deeper/later opinions win.

    Returns `(ignored, budget_tripped)`. ONE `_Meter` covers the whole entry — every
    rule of every active `.gitignore` — so the gitignore work charged to a walk is at
    most `_MAX_MATCH_STEPS × n_entries`: linear in repo size whatever the rules say."""
    if not matchers:
        return False, False  # no `.gitignore` in force — don't even build a meter
    status: bool | None = None
    meter = _Meter()
    for base, matcher in matchers:
        if meter.tripped:
            break
        sub = _relativize(relpath, base)
        if sub is None:
            continue
        s = matcher.status(sub, is_dir, meter)
        if s is not None:
            status = s
    return bool(status), meter.tripped


# --- the walk ---------------------------------------------------------------


def _read_gitignore(path: Path) -> tuple[str, str]:
    """`(text, cap_reason)`. An oversize `.gitignore` is NOT read at all and none of
    its rules apply — mirroring the oversize-PDF read cap, and disclosed the same way
    rather than silently half-parsed."""
    try:
        size = path.stat().st_size
    except OSError:
        return "", ""
    if size > _MAX_GITIGNORE_BYTES:
        return "", (
            f"{size:,} bytes exceeds the {_MAX_GITIGNORE_BYTES:,}-byte .gitignore read cap; "
            "the file was not read and NONE of its rules were applied"
        )
    try:
        return path.read_text(encoding="utf-8", errors="ignore"), ""
    except OSError:
        return "", ""


# --- cap disclosure + per-run memoisation -----------------------------------
#
# `walk.py` sits inside the guard trust boundary (pathlib only — no `os`, no writes,
# no stderr), so it cannot emit a `Finding` itself. It records cap trips here and
# `audit.py` turns them into disclosed `info` findings, the same shape the oversize
# PDF cap uses. Single-threaded by contract: an audit runs guards sequentially.


@dataclass(frozen=True)
class GitignoreCapNotice:
    """One `.gitignore` whose rules were not fully applied, and why."""

    path: str    # repo-relative path of the `.gitignore`
    detail: str  # which cap tripped and what it cost


_MAX_NOTICES = 50  # bound the record itself — a hostile tree can hold thousands of .gitignores
_notices: dict[str, GitignoreCapNotice] = {}

_walk_depth = 0
_walk_cache: dict[tuple[str, bool], list[Path]] = {}


def _record_notice(path: str, detail: str) -> None:
    if detail and path not in _notices and len(_notices) < _MAX_NOTICES:
        _notices[path] = GitignoreCapNotice(path, detail)


def _record_budget_trip(active: list[tuple[str, GitignoreMatcher]]) -> None:
    """A path that exhausted its per-entry match budget. Keyed on the INNERMOST
    `.gitignore` actually in force (which therefore exists on disk), so one hostile
    file is one notice however many paths it blows the budget on."""
    base = active[-1][0] if active else ""
    _record_notice(
        f"{base}/.gitignore" if base else ".gitignore",
        f"exhausted the {_MAX_MATCH_STEPS:,}-step per-path .gitignore match budget "
        "(the rules here are pathologically expensive to evaluate); the remaining rules "
        "were not applied to at least one path, which is therefore scanned rather than ignored",
    )


def gitignore_cap_notices() -> list[GitignoreCapNotice]:
    """Every `.gitignore` cap trip recorded since the current `walk_run()` began."""
    return sorted(_notices.values(), key=lambda n: n.path)


@contextmanager
def walk_run() -> Iterator[None]:
    """Memoise `walk_files` for the duration of one audit, and scope cap disclosures to it.

    Without this, `walk_files` re-walks the whole tree for **every** registered guard
    — so any per-entry cost, hostile `.gitignore` or not, is paid once per registered
    guard (issue #419 / PR #430). The cache is keyed on the start path *as given*
    (never `resolve()`d: two spellings of one directory yield different output paths,
    and sharing a hit between them would return paths under the wrong root) plus
    `respect_gitignore`, so no root or option set can read another's entry. It is
    active ONLY inside this scope, so nothing is served stale between audits, and
    callers always get a fresh list copy — a caller that sorts or filters its result
    in place must not corrupt the cache. Re-entrant: nested scopes share one cache."""
    global _walk_depth
    if _walk_depth == 0:
        _walk_cache.clear()
        _notices.clear()
    _walk_depth += 1
    try:
        yield
    finally:
        _walk_depth -= 1
        if _walk_depth == 0:
            _walk_cache.clear()


def is_worktree_link(directory: Path) -> bool:
    """True if `directory` is a linked git worktree — its `.git` is a *file* (a
    `gitdir:` pointer), not a directory. Such a dir is a checkout of another branch
    and must not be folded into this tree's scan. Pure filesystem inspection (no
    `git` shell-out)."""
    return (directory / ".git").is_file()


_GLOB_TOKENS: dict[str, tuple[str, ...]] = {}  # memo — globs are a small fixed set


def _name_match(name: str, globs: tuple[str, ...]) -> bool:
    """True if `name` matches any filename glob (`*`/`?`, no `/`). Used so guards can
    enumerate by name (`.env*`, `Dockerfile`, `requirements*.txt`) through the walk —
    instead of `root.rglob(...)`, which descends into excluded dirs and worktrees.
    Matched with the same linear token matcher as the gitignore rules (issue #419) —
    never a backtracking regex."""
    for g in globs:
        toks = _GLOB_TOKENS.get(g)
        if toks is None:
            toks = _GLOB_TOKENS[g] = _tokenize(g)
        if _match_tokens(toks, name):
            return True
    return False


def _collect(
    directory: Path,
    rel: str,
    matchers: list[tuple[str, GitignoreMatcher]],
    out: list[Path],
    respect_gitignore: bool,
) -> None:
    # Explicit-stack traversal, NOT recursion: tree depth is attacker-controlled, and one
    # Python stack frame per directory level aborts the whole audit with a RecursionError
    # on a ~1200-deep tree (issue #419, audit-killer #2). Traversal order is free — the
    # caller sorts `out`.
    stack: list[tuple[Path, str, list[tuple[str, GitignoreMatcher]]]] = [
        (directory, rel, matchers)
    ]
    while stack:
        directory, rel, matchers = stack.pop()
        active = matchers
        if respect_gitignore:
            gi = directory / ".gitignore"
            if gi.is_file():
                text, oversize = _read_gitignore(gi)
                m = GitignoreMatcher.from_text(text)
                # Disclose, never truncate silently: a scan that stopped honoring some
                # of the repo's ignore rules has to say so (issue #419 / PR #430).
                _record_notice(f"{rel}/.gitignore" if rel else ".gitignore", oversize or m.dropped)
                if m:
                    active = matchers + [(rel, m)]
        try:
            entries = sorted(directory.iterdir())
        except (OSError, PermissionError):
            continue
        for e in entries:
            child_rel = f"{rel}/{e.name}" if rel else e.name
            # Never follow a symlink discovered mid-walk: an untrusted target repo can ship a
            # directory symlink (e.g. `evil -> /`) to escape the scanned tree and leak host
            # files into findings, or a self/ancestor cycle (`loop -> .`) to walk forever. The
            # root target is still followed normally — it is the initial `directory`, never an
            # `e` child here — so scanning a private repo via a top-level symlink (e.g.
            # `Test-FE -> …`) and the corpus self-scan keep working.
            if e.is_symlink():
                continue
            try:
                is_dir = e.is_dir()
            except OSError:
                continue
            if is_dir:
                if e.name in DEFAULT_EXCLUDE_DIRS:
                    continue
                if is_worktree_link(e):
                    continue
                if respect_gitignore:
                    ignored, tripped = _ignored(child_rel, True, active)
                    if tripped:
                        _record_budget_trip(active)
                    if ignored:
                        continue
                stack.append((e, child_rel, active))
            else:
                if respect_gitignore:
                    ignored, tripped = _ignored(child_rel, False, active)
                    if tripped:
                        _record_budget_trip(active)
                    if ignored:
                        continue
                out.append(e)


def walk_files(
    start: Path,
    *,
    suffixes: tuple[str, ...] | None = None,
    names: tuple[str, ...] | None = None,
    respect_gitignore: bool = True,
) -> list[Path]:
    """All files under `start`, **sorted**, skipping vendored/build dirs and nested git
    worktrees (and, by default, `.gitignore`-matched entries — the start dir's `.gitignore`
    and any nested ones). `suffixes` keeps files by suffix; `names` keeps files whose name
    matches a glob (for suffix-less / name-matched files like `.env*` or `Dockerfile`).

    `respect_gitignore=False` skips the `.gitignore` filtering (vendored-dir + worktree
    skips still apply) — use it for secret/env guards that must still see a real,
    gitignored `.env`. This is the supported way to do that **without** `root.rglob`,
    which descends into worktrees and excluded dirs (the source of duplicate findings).

    Inside a `walk_run()` scope the expensive part (the tree traversal itself) is
    memoised per `(start, respect_gitignore)` and the `suffixes`/`names` filters are
    applied to a fresh copy — so every registered guard asking for a different suffix
    set still walks the tree at most twice. The returned list is always the caller's own."""
    out = _walk_all(start, respect_gitignore)
    if suffixes is not None:
        out = [p for p in out if p.suffix in suffixes]
    if names is not None:
        out = [p for p in out if _name_match(p.name, names)]
    return out


def _walk_all(start: Path, respect_gitignore: bool) -> list[Path]:
    """The sorted, unfiltered walk — memoised while a `walk_run()` scope is active.
    Always returns a fresh list: callers may sort/mutate what they get."""
    key = (str(start), respect_gitignore)
    if _walk_depth > 0:
        cached = _walk_cache.get(key)
        if cached is not None:
            return list(cached)
    if not start.is_dir():
        return []
    out: list[Path] = []
    _collect(start, "", [], out, respect_gitignore)
    out.sort()
    if _walk_depth > 0:
        _walk_cache[key] = out
        return list(out)
    return out
