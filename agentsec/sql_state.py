"""SQL schema-state reconciliation — tell live schema from migration history.

The static SQL guards scan every `*.sql` file independently, so a statement created in an
early migration and later dropped/replaced is still flagged (a per-file false positive).
This module reconciles state so the audit can DEMOTE (never drop) superseded findings.

**Scope: snapshot-preference only.** When a repo ships an authoritative schema dump
(`schema-snapshot.sql`, `supabase db dump`, …), that dump is the source of truth **for the
schema objects it reproduces**: a SCHEMA-STATE finding not in the dump is historical, and
anything still live is also flagged in the dump at full priority. That premise is what bounds
the demotion, so the demotion is bounded by it, on three axes:

- **which file is a dump** — a dump-like NAME and pg_dump's output signature in its head
  (`find_dumps`). A name alone is not evidence: most `schema.sql` files are hand-written;
- **which files it speaks for** — the `.sql` files in the dump's own directory subtree, not
  the whole repo (`governing_dump`), so one app's dump cannot answer for another app's tree.
  Every qualifying dump governs its own subtree; where dumps nest, the nearest one governs;
- **which findings** — a check declares `schema_state` when a dump can speak for it, and a
  finding that merely *sits* in a `.sql` file is untouched.

The stamp is GATE-GRADE since #800 (`findings.is_historical` → `cli._gating`), so every axis
errs toward gating: a real dump that misses the bar costs status quo (its migrations keep
gating), while a false match would void the gate on a live finding (#1037: a hand-written
`db/schema.sql` flipped `--fail-on high` from FAIL to PASS). Full migration-replay
(cross-file DROP/REVOKE reconciliation) is
deliberately out of scope — that reimplements the database's own state resolution at lower
fidelity than the live DB or the dump itself (see
`docs/knowledge/sql-guards-vs-splinter-division.md`); the right tool for resolved live
state is Splinter (`agentsec live`) or the dump (which this module uses).

Stdlib-only; pure functions of the file set. Not a guard, but kept import-clean anyway.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from agentsec.findings import _LOCATION_LINE_SUFFIX

# Authoritative-dump filenames (Supabase `db dump`, a checked-in snapshot, etc.). A name match is
# necessary, not sufficient: the file must also look like pg_dump output (`_looks_like_pg_dump`).
# Several may qualify, and each governs its own subtree (`governing_dump`); the name never ranks.
_SNAPSHOT_EXACT = ("schema-snapshot.sql", "schema.sql", "schema_dump.sql", "dump.sql")
_SNAPSHOT_SUFFIX = ("-snapshot.sql", ".dump.sql", ".snapshot.sql")

# pg_dump's output signature. Every plain-format dump opens with this session preamble, including
# `supabase db dump` (which wraps pg_dump and strips its comment banner — the flagship's dump has
# 10 of these lines and no banner). Line-anchored and case-sensitive, as pg_dump writes them: a
# comment or a string that quotes one mid-line is not a preamble line. Older pg_dump versions lack
# some (`set_config('search_path'…)` arrived in 2018), so `_PREAMBLE_MIN` of them suffice.
_PG_DUMP_PREAMBLE = tuple(re.compile(p, re.MULTILINE) for p in (
    r"^SET statement_timeout = 0;",
    r"^SET lock_timeout = 0;",
    r"^SET idle_in_transaction_session_timeout = 0;",
    r"^SET client_encoding = '[^'\n]+';",
    r"^SET standard_conforming_strings = (?:on|off);",
    r"^SELECT pg_catalog\.set_config\('search_path', '', false\);",
    r"^SET check_function_bodies = false;",
    r"^SET xmloption = content;",
    r"^SET client_min_messages = warning;",
    r"^SET row_security = off;",
))
_PREAMBLE_MIN = 3
# pg_dump's banner: each marker is the whole of its own comment line, so prose that says "this is
# not a PostgreSQL database dump" does not match (the #819 negation lesson).
_PG_DUMP_BANNER = re.compile(
    r"^-- (?:PostgreSQL database dump|Dumped by pg_dump version [^\n]+?)[ \t]*$", re.MULTILINE
)
# How much of a candidate is read. Both signals sit at the top of a dump (the flagship's preamble
# ends at line 18, behind a 4-line custom header); no file is read further.
_HEAD_CHARS = 8192


def _is_snapshot_name(name: str) -> bool:
    n = name.lower()
    return n in _SNAPSHOT_EXACT or any(n.endswith(s) for s in _SNAPSHOT_SUFFIX)


def _looks_like_pg_dump(head: str) -> bool:
    """True when `head` (the start of a file) carries pg_dump's banner or at least `_PREAMBLE_MIN`
    lines of its session preamble."""
    if _PG_DUMP_BANNER.search(head):
        return True
    return sum(1 for p in _PG_DUMP_PREAMBLE if p.search(head)) >= _PREAMBLE_MIN


def _read_head(path: Path) -> str:
    """The first `_HEAD_CHARS` of `path`; "" when unreadable (so it is not a dump). `utf-8-sig`
    drops a BOM that would otherwise hide a preamble line on line 1, and text mode folds `\r\n`."""
    try:
        with open(path, encoding="utf-8-sig", errors="ignore") as fh:
            return fh.read(_HEAD_CHARS)
    except OSError:
        return ""


def find_dumps(sql_files: list[Path]) -> list[Path]:
    """Every authoritative schema dump among `sql_files`: a dump-like name AND pg_dump's output
    signature in the file's head.

    The evidence bar matches the consequence. A dump un-gates other files' findings, so a name
    alone (the rule until #1037) let any hand-written `schema.sql` void the gate on real HIGH
    findings, with a report that called them "superseded by a later migration". Only name-matched
    files are read, and only their head, so the cost stays negligible."""
    return [f for f in sql_files if _is_snapshot_name(f.name) and _looks_like_pg_dump(_read_head(f))]


def _rank(f: Path) -> tuple[int, str]:
    try:
        size = f.stat().st_size
    except OSError:
        size = 0
    return (-size, str(f))  # largest first, then stable path


def find_snapshot(sql_files: list[Path]) -> Path | None:
    """The largest schema dump among `sql_files` (see `find_dumps`) by byte size, with a stable
    path tiebreak, or None. Not the dump that governs a given file: every dump governs its own
    subtree (`governing_dump`), and size only breaks a tie between dumps in one directory."""
    dumps = find_dumps(sql_files)
    return min(dumps, key=_rank) if dumps else None


@dataclass
class SqlState:
    """Reconciled SQL state. `dumps` holds every file that qualified as a dump (repo-relative
    posix paths), largest first: each governs its own directory subtree (`governing_dump`), and
    none is ever stamped superseded. Empty when the repo ships none; then nothing is superseded."""

    dumps: tuple[str, ...] = ()

    @property
    def snapshot(self) -> str | None:
        """The largest dump, or None. It is not necessarily the dump that governs a given file
        (`governing_dump` decides that), only the answer to "does this repo ship a dump"."""
        return self.dumps[0] if self.dumps else None


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def build_sql_state(root: Path, sql_files: list[Path]) -> SqlState:
    return SqlState(dumps=tuple(_relative(root, d) for d in sorted(find_dumps(sql_files), key=_rank)))


def _location_file(location: str) -> str:
    """The path part of a finding `location` (strip a trailing `:line[:col]`), posix-normalized."""
    suffix = _LOCATION_LINE_SUFFIX.search(location)
    path = location[: len(location) - len(suffix.group(0))] if suffix else location
    return path.replace("\\", "/")


def is_schema_state_check(check_id: str) -> bool:
    """True when `check_id` reads `.sql` as SCHEMA STATE, so a dump can supersede its finding.

    The check declares this about itself (`schema_state` on the class, `checkmeta.CheckMeta`).
    An unregistered id — an ingested report, a synthetic finding — resolves to False, which is
    the safe direction: it keeps gating. See `governing_dump` for why the location alone is not
    enough to answer this."""
    from agentsec.registry import check_meta  # lazy: avoids an import cycle

    meta = check_meta(check_id)
    return meta is not None and meta.schema_state


def _dump_governs(dump: str, path: str) -> bool:
    """True when `path` sits in `dump`'s directory subtree (a dump at the repo root: everywhere)."""
    dump_dir = dump.rpartition("/")[0]
    return not dump_dir or path.startswith(dump_dir + "/")


def governing_dump(location: str, state: SqlState, check_id: str) -> str | None:
    """The dump that makes this finding a historical SCHEMA-STATE fact, or None when it stays
    live: the finding sits in a `*.sql` file inside some dump's directory subtree, is not itself
    a dump, and the check that produced it reads SQL as schema state. Non-SQL findings and
    dump-less repos → None. `location` is assumed already repo-relative + posix (post
    `normalize_location`).

    **The subtree bound is load-bearing.** A dump reproduces the database it was taken from, and
    nothing ties that database to `.sql` files elsewhere in the repo. Repo-wide authority let one
    app's `apps/www/schema.sql` un-gate findings in the root `supabase/migrations` and in unrelated
    packages (#1037). A dump at the repo root keeps the whole-repo reach. Every dump governs its
    own subtree, not only the largest: two apps that each ship one are each answered by their own
    (#1073 review M1). Where dumps nest, the nearest (deepest) one governs, and between dumps in
    one directory the largest does, so the report names the dump that speaks for the file.

    **The `check_id` gate is load-bearing, not a refinement.** The location test alone answers
    "is this in an old migration file", which is not the same question as "would the dump
    re-flag this if it were still live". A homoglyph identifier, an invisible-unicode payload
    or a committed secret can all anchor in `sql/003_seed.sql`, and a dump carries none of them
    — so demoting those makes the audit pass on a live finding rather than on an answered one
    (#829 review round 2, reproduced end to end: a HIGH homoglyph in a migration exited 0).
    An empty `check_id` is treated as non-schema-state, keeping the caller's finding gating."""
    if not state.dumps or not location:
        return None
    path = _location_file(location)
    if not path.endswith(".sql") or path in state.dumps:
        return None
    covering = [d for d in state.dumps if _dump_governs(d, path)]
    if not covering or not is_schema_state_check(check_id):
        return None
    # The covering dumps' directories are all ancestors of `path`, so the deepest is the nearest.
    # `max` keeps the first of equals, and `dumps` is largest first: the size tiebreak.
    return max(covering, key=lambda d: d.count("/"))


def is_superseded(location: str, state: SqlState, check_id: str) -> bool:
    """True when some dump governs this finding (`governing_dump`, which documents the rules)."""
    return governing_dump(location, state, check_id) is not None
