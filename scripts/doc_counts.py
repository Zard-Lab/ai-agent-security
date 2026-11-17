#!/usr/bin/env python3
"""Refresh the hard-coded current-state counts across the docs to the live values.

Mirrors ``scripts/cut-release.py::patch_readme``: pure ``str -> str`` patch functions that rewrite
only the count *values* in place, so hand-curated prose / table labels / "(manual by nature)"
annotations are preserved. Ground truth comes from ``agentsec.registry`` (guard + runner counts) and
``checklist.json`` (version, item count, and the stack-agnostic **full-registry** per-section rollup —
every item by its raw ``status``, so ``na`` is 0 by construction).

Covered docs (README is deliberately EXCLUDED — it is owned by ``cut-release.py::patch_readme`` +
``tests/test_readme_facts.py``; do not double-own it here):

- ``docs/knowledge/ROADMAP.md``            — the ``**Baseline:**`` line
- ``docs/user-guide.md``                   — the checklist "(N items, …)" mention
- ``docs/infographic/*.html`` (x2)         — the four guard/item mentions each
- ``wiki/coverage-dashboard.md``           — snapshot line, the per-section table, totals, the named
                                             "strongest areas" percentages, and the history endpoint

This touches only the ``.html``; re-export the rendered ``.png`` companions afterwards with
``docs/infographic/render.py`` (headless Playwright/Chromium — see its docstring for the two
``uv run --with playwright`` commands).

Separately, ``--check-narrative`` enforces the "prose never carries live counts" doctrine (see
``docs/README.md``): it flags a hard ``N guards`` / ``N items`` / ``N runners`` in live prose that
disagrees with the registry. It is DETECT-ONLY (no ``--write``): prose context varies too much to
auto-patch. The blessed count locations above stay ``== live`` (via ``--write`` / ``cut-release``) so
they never trip it; append-only records are excluded, and a one-off historical line can be waived with
a trailing ``<!-- stale-ok -->`` marker.

Usage::

    python scripts/doc_counts.py --check   # report scalar drift, exit 1 if any doc is stale (CI-friendly)
    python scripts/doc_counts.py --check-narrative   # report prose hard-coding a live count (detect-only)
    python scripts/doc_counts.py --write   # rewrite the docs to live counts
    python scripts/doc_counts.py --json     # print the computed live counts
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# --- sys.path FIRST, and prove it took ---------------------------------------------------------
# Resolve `agentsec` from THIS checkout, whatever the cwd (including a git worktree): without it
# the import falls through to an editable install of a different tree and the script silently
# reports that tree's numbers and exits 0 (#453 review).
#
# The insert alone is not enough, and that is the half issue #511 was still open on. sys.path
# governs resolution, never RE-resolution: a caller that already imported `agentsec` in this
# process leaves it cached in sys.modules, and the submodule imports in live_counts() then
# resolve through the CACHED package's __path__ rather than by re-consulting sys.path. That is
# not hypothetical — tests/conftest.py imports agentsec at module scope, and pytest imports
# conftest before tests/test_doc_counts.py execs this file in-process.
#
# So: drop any later duplicate, insert the real root at position 0, and then ASSERT the package we
# actually got is our sibling. Docs come from ROOT but counts come from the import, and a mixed pair
# silently describes the wrong tree. The ASSERTION is the load-bearing part — `insert(0)` wins over a
# later `.pth` entry with or without the dedup pass (measured: removing the loop alone leaves every
# test green), so the loop is list hygiene kept for symmetry with the sibling guard in
# scripts/validate-checklist.py, which carries the same trap note (#524 review).
while str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

import agentsec  # noqa: E402

# stdout/stderr as UTF-8 — these scripts print the same non-ASCII the CLI does, and on
# Windows the default cp1252 cannot encode it. Shared with the CLI (#453 review).
from agentsec.console import force_utf8_stdio  # noqa: E402

force_utf8_stdio()

_EXPECTED_PKG = ROOT / "agentsec"
_ACTUAL_PKG = Path(agentsec.__file__).resolve().parent
if _ACTUAL_PKG != _EXPECTED_PKG:
    sys.stderr.write(
        f"doc_counts: refusing to run - `import agentsec` resolved to {_ACTUAL_PKG}, "
        f"not this checkout's {_EXPECTED_PKG}. An editable install is shadowing the repo; "
        "the counts would describe the wrong tree.\n"
    )
    raise SystemExit(2)


# --------------------------------------------------------------------------- ground truth
@dataclass(frozen=True)
class Counts:
    guards: int
    runners: int
    version: str
    items: int
    covered: int
    partial: int
    manual: int
    pct: int
    # section id -> (auto, rev, man, tot, pct)
    sections: dict[str, tuple[int, int, int, int, int]]


def _pct(cov: int, tot: int) -> int:
    return round(cov / tot * 100) if tot else 0


def live_counts() -> Counts:
    """Compute the authoritative numbers from the registry + checklist.json."""
    from agentsec.checklist import load_checklist
    from agentsec.registry import ALL_GUARDS, ALL_RUNNERS

    checklist = load_checklist()
    # full-registry rollup: raw status, no stack filtering → na == 0
    raw: dict[str, list[int]] = {}
    idx = {"covered": 0, "partial": 1, "manual": 2}
    for it in checklist.items:
        raw.setdefault(it.section, [0, 0, 0])[idx[it.status]] += 1
    sections: dict[str, tuple[int, int, int, int, int]] = {}
    for sec, (a, r, m) in raw.items():
        tot = a + r + m
        sections[sec] = (a, r, m, tot, _pct(a, tot))
    covered = sum(v[0] for v in sections.values())
    partial = sum(v[1] for v in sections.values())
    manual = sum(v[2] for v in sections.values())
    items = len(checklist.items)
    return Counts(
        guards=len(ALL_GUARDS), runners=len(ALL_RUNNERS), version=checklist.version,
        items=items, covered=covered, partial=partial, manual=manual,
        pct=_pct(covered, items), sections=sections,
    )


# --------------------------------------------------------------------------- coverage-dashboard table
# The per-section rows are a fixed-width table whose numeric columns right-align to fixed END columns
# (verified byte-identical against the current hand table — see tests). Labels + trailing annotations
# are preserved verbatim; only the numbers/bar/percent are rebuilt.
_COL_ENDS = (51, 56, 61, 66)  # end columns for auto, rev, man, tot
_ROW = re.compile(
    r"^(?P<label>§(?P<sec>\S+) .+?)\s+\d+\s+\d+\s+\d+\s+\d+\s+\[[#.]{10}\]\s+\d+%(?P<annot>.*)$"
)


def _bar(pct: int) -> str:
    """10-char ``#``/``.`` bar, ``round(pct/10)`` filled — matches the live dashboard renderer's rounding."""
    filled = round(pct / 10)
    return "#" * filled + "." * (10 - filled)


def render_row(label: str, auto: int, rev: int, man: int, tot: int, pct: int, annot: str = "") -> str:
    """Rebuild one table row, right-aligning each number to its fixed end column."""
    s = label
    for val, end in zip((auto, rev, man, tot), _COL_ENDS, strict=True):
        v = str(val)
        pad = end - len(s) - len(v)
        # Fail loudly on overflow (a 3-digit count or an over-long label) rather than silently
        # misaligning the fixed-width table. Current data fits with room to spare.
        if pad < 1:
            raise ValueError(f"coverage-dashboard column overflow rendering row {label!r} (value {v!r})")
        s += " " * pad + v
    s += " " * max(1, 69 - len(s)) + f"[{_bar(pct)}]"
    s += " " + f"{pct:>3}%"
    return s + annot


# --------------------------------------------------------------------------- patch functions (pure str->str)
def patch_roadmap(text: str, c: Counts) -> str:
    return re.sub(
        r"(is \*\*v)[\d.]+, \d+ checklist items, \d+ guards, \d+ runners(\*\*)",
        rf"\g<1>{c.version}, {c.items} checklist items, {c.guards} guards, {c.runners} runners\g<2>",
        text,
    )


def patch_user_guide(text: str, c: Counts) -> str:
    return re.sub(r"(checklist \()\d+( items,)", rf"\g<1>{c.items}\g<2>", text)


def patch_infographic(text: str, c: Counts) -> str:
    text = re.sub(r"running \d+ static guards", f"running {c.guards} static guards", text)
    text = re.sub(r"each of the \d+ guards", f"each of the {c.guards} guards", text)
    text = re.sub(r"\d+ Dependency-Free Static Guards", f"{c.guards} Dependency-Free Static Guards", text)
    text = re.sub(r"\d+ Guards &amp; \d+-Item Checklist", f"{c.guards} Guards &amp; {c.items}-Item Checklist", text)
    text = re.sub(r"supplemented by \d+ optional integrations", f"supplemented by {c.runners} optional integrations", text)
    return text


def patch_dashboard_scalars(text: str, c: Counts) -> str:
    """The dashboard's scalar count lines (snapshot / totals / named %s / history) — NOT the table rows.
    Split out so the drift test can gate these cheaply without pinning every per-section cell."""
    text = re.sub(
        r"(registry v)[\d.]+, \d+ items, \d+ guards",
        rf"\g<1>{c.version}, {c.items} items, {c.guards} guards", text,
    )
    text = re.sub(
        r"\*\*Total automatic coverage: \d+ of \d+ checks \(\d+%\)\*\* — plus \d+ partial \(review-assist\) and \d+ manual\.",
        f"**Total automatic coverage: {c.covered} of {c.items} checks ({c.pct}%)** — "
        f"plus {c.partial} partial (review-assist) and {c.manual} manual.",
        text,
    )
    # named "strongest areas" percentages: keep the numbers honest for whatever sections the prose names
    # (the *choice* of which to name stays editorial — the skill flags that for human eyes).
    for label_re, sec in ((r"CI/CD", "1"), (r"general input safety", "3a"), (r"application code", "8")):
        if sec in c.sections:
            text = re.sub(rf"({label_re} \()\d+(%\))", rf"\g<1>{c.sections[sec][4]}\g<2>", text)
    text = re.sub(
        r"this snapshot \(\d+ guards: \d+/\d+/\d+ of \d+ items, \d+%\)",
        f"this snapshot ({c.guards} guards: {c.covered}/{c.partial}/{c.manual} of {c.items} items, {c.pct}%)",
        text,
    )
    return text


def patch_dashboard_table(text: str, c: Counts) -> str:
    """Rebuild the per-section table rows in place (labels + annotations preserved)."""
    out: list[str] = []
    for line in text.split("\n"):
        m = _ROW.match(line)
        if m and m.group("sec") in c.sections:
            a, r, mn, tot, pct = c.sections[m.group("sec")]
            out.append(render_row(m.group("label"), a, r, mn, tot, pct, m.group("annot")))
        else:
            out.append(line)
    return "\n".join(out)


def patch_dashboard(text: str, c: Counts) -> str:
    return patch_dashboard_table(patch_dashboard_scalars(text, c), c)


# --------------------------------------------------------------------------- doc manifest + drivers
# (relative path, full patch fn, scalar-only patch fn for the cheap drift gate)
_DOCS: list[tuple[str, Callable[[str, Counts], str], Callable[[str, Counts], str]]] = [
    ("docs/knowledge/ROADMAP.md", patch_roadmap, patch_roadmap),
    ("docs/user-guide.md", patch_user_guide, patch_user_guide),
    ("docs/infographic/agentsec_infographic.html", patch_infographic, patch_infographic),
    ("docs/infographic/agentsec_infographic_landscape.html", patch_infographic, patch_infographic),
    ("wiki/coverage-dashboard.md", patch_dashboard, patch_dashboard_scalars),
]


def _iter_docs() -> Iterator[tuple[Path, Callable[[str, Counts], str], Callable[[str, Counts], str]]]:
    for rel, full, scalar in _DOCS:
        yield ROOT / rel, full, scalar


def drift(c: Counts, *, scalar_only: bool = False) -> list[Path]:
    """Docs whose live-patched text differs from disk. `scalar_only` skips the per-section table."""
    stale: list[Path] = []
    for path, full, scalar in _iter_docs():
        fn = scalar if scalar_only else full
        text = path.read_text(encoding="utf-8")
        if fn(text, c) != text:
            stale.append(path)
    return stale


def write(c: Counts) -> list[Path]:
    changed: list[Path] = []
    for path, full, _ in _iter_docs():
        text = path.read_text(encoding="utf-8")
        new = full(text, c)
        if new != text:
            # newline="" so an existing \n is written verbatim (no CRLF re-translation on Windows)
            path.write_text(new, encoding="utf-8", newline="")
            changed.append(path)
    return changed


# --------------------------------------------------------------------------- narrative count drift net
# Live counts must not be hard-coded in prose (they drift silently). The blessed doc_counts/README
# locations DO carry live counts, but they are kept ``== live`` by ``--write`` / ``cut-release`` so they
# never trip this check. Everywhere else, a hard "N guards / N items / N runners" that disagrees with
# the registry is drift. Append-only records (issues, validation runs, ledgers, changelogs, research)
# legitimately carry historical numbers and are excluded; a one-off historical line elsewhere can be
# waived with a trailing ``<!-- stale-ok -->`` marker.
_NARRATIVE_WAIVER = "<!-- stale-ok -->"

# Path prefixes / exact names (relative to ROOT, POSIX-style) excluded from the narrative scan.
_NARRATIVE_EXCLUDE: tuple[str, ...] = (
    "docs/archive/",                                   # frozen, tombstoned
    "docs/validation/",                                # point-in-time validation records
    "docs/ledger/marconi-merge-ledger.md",             # append-only merge ledger
    "docs/ledger/checklist-proposed-additions.md",     # live /threat-intake staging record
    "wiki/guards/",                                    # per-guard design docs: fixed-window "N guards" prose abounds
    "docs/knowledge/improvement-backlog-",             # point-in-time self-improvement records: "retires 9 items" etc. are backlog counts, not the registry
    "wiki/threat-coverage-changelog.md",               # append-only changelog
    "wiki/research/",                                   # dated threat research
    # Belt-and-suspenders: these are NOT reachable by the current scan surface (_narrative_files
    # yields only README/CONTRIBUTING/docs/**/wiki/**), so they are inert today. They are kept so
    # the exclusion stays correct if that surface is ever widened to the repo root / tests.
    "CHANGELOG.md",                                    # append-only release notes (top-level, unscanned today)
    "tests/fixtures/",                                 # intentionally-vulnerable samples (linter-excluded, unscanned today)
)

# (compiled pattern capturing the count, the Counts attribute it must equal, the human noun)
_NARRATIVE_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"(\d+)\s+guards\b"), "guards", "guards"),
    (re.compile(r"(\d+)\s+(?:checklist\s+)?items\b"), "items", "items"),
    (re.compile(r"(\d+)\s+runners\b"), "runners", "runners"),
)


def _narrative_files() -> Iterator[Path]:
    """The docs whose prose is subject to the no-live-counts rule (excludes append-only records)."""
    candidates: list[Path] = [ROOT / "README.md", *sorted(ROOT.glob("CONTRIBUTING*.md"))]
    candidates += sorted((ROOT / "docs").rglob("*.md"))
    candidates += sorted((ROOT / "wiki").rglob("*.md"))
    for p in candidates:
        if not p.is_file():
            continue
        rel = p.relative_to(ROOT).as_posix()
        if any(rel == e or rel.startswith(e) for e in _NARRATIVE_EXCLUDE):
            continue
        yield p


def narrative_drift(c: Counts) -> list[str]:
    """Lines of live prose that hard-code a guard/item/runner count disagreeing with the registry.

    Returns ``"relpath:line: found 'N guards', live is M"``-style strings (empty list == clean).
    Detect-only — there is no ``--write`` path (prose context varies too much to auto-patch safely).
    Fix a hit by removing the count from the prose, or waive a genuinely historical line with a
    trailing ``<!-- stale-ok -->`` marker.
    """
    live = {"guards": c.guards, "items": c.items, "runners": c.runners}
    findings: list[str] = []
    for path in _narrative_files():
        rel = path.relative_to(ROOT).as_posix()
        # errors="ignore" (matches guards/base.py::read): the scan surface is wide (all of docs/ +
        # wiki/), so a stray non-UTF-8 byte in a future doc must not crash the check with a traceback.
        text = path.read_text(encoding="utf-8", errors="ignore")
        for lineno, line in enumerate(text.split("\n"), start=1):
            if _NARRATIVE_WAIVER in line:
                continue
            for pat, attr, noun in _NARRATIVE_PATTERNS:
                for m in pat.finditer(line):
                    found = int(m.group(1))
                    if found != live[attr]:
                        findings.append(f"{rel}:{lineno}: found '{found} {noun}', live is {live[attr]}")
    return findings


def _summary(c: Counts) -> str:
    return f"{c.guards} guards / {c.runners} runners / {c.items} items / v{c.version}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Refresh doc counts to live ground truth.")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="report scalar drift, exit 1 if any doc is stale")
    g.add_argument(
        "--check-narrative", action="store_true",
        help="report prose that hard-codes a live count (detect-only), exit 1 if any",
    )
    g.add_argument("--write", action="store_true", help="rewrite the docs to live counts")
    g.add_argument("--json", action="store_true", help="print the computed live counts and exit")
    args = ap.parse_args(argv)

    c = live_counts()

    if args.check_narrative:
        hits = narrative_drift(c)
        if hits:
            print(f"NARRATIVE DRIFT: prose disagrees with live counts ({_summary(c)}):")
            for h in hits:
                print(f"  {h}")
            print(
                "Fix: remove the count from the prose (link to the baseline line / README instead), "
                "or append `<!-- stale-ok -->` to a genuinely historical line."
            )
            return 1
        print(f"OK — no narrative count drift ({_summary(c)})")
        return 0

    if args.json:
        print(json.dumps({
            "guards": c.guards, "runners": c.runners, "version": c.version, "items": c.items,
            "covered": c.covered, "partial": c.partial, "manual": c.manual, "pct": c.pct,
            "sections": {k: list(v) for k, v in c.sections.items()},
        }, indent=2))
        return 0

    if args.write:
        changed = write(c)
        for p in changed:
            print(f"updated {p.relative_to(ROOT)}")
        print(f"{len(changed)} file(s) updated -> {_summary(c)}")
        print(
            "NOTE: infographic .png files are NOT auto-regenerated -> re-export with "
            "docs/infographic/render.py (headless Playwright/Chromium).",
            file=sys.stderr,
        )
        return 0

    # default: --check
    stale = drift(c)
    if stale:
        print(f"STALE: docs should read {_summary(c)}")
        for p in stale:
            print(f"  {p.relative_to(ROOT)}")
        print("Run `python scripts/doc_counts.py --write` (or the /refresh-doc-counts skill).")
        return 1
    print(f"OK — all docs current ({_summary(c)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
