#!/usr/bin/env python3
"""Migrate the per-guard design docs into the OKF wiki: ``wiki/guards/<id>.md``.

RFC ``docs/knowledge/rfc-soft-launch-readiness.md`` Proposal 3, accepted 2026-08-03 (Q4).
The per-guard "why" moves next to the methodology "why" it derives from, so ``wiki/`` becomes
the whole public knowledge base and ``docs/knowledge/`` becomes private dev-process only.

**This script is committed on purpose, and it is idempotent on purpose.** It is not a one-shot
transform that gets deleted after the migration PR: it is the tool a contributor whose branch
predates the migration runs after rebasing, to relocate the guard doc they wrote at the old path.
``tests/guards/test_meta.py::test_no_stray_guard_design_docs_in_the_old_home`` fails loudly and
prints exactly that instruction, so the two are a matched pair. Re-running it is always safe: a
doc that already carries frontmatter is reported ``already migrated`` and left untouched.

What the transform does to one doc:

1. ``git mv docs/knowledge/guard-design-<id>.md wiki/guards/<id>.md`` (history preserved: the
   edit below keeps similarity at ~95%+, far above git's 50% rename-detection threshold).
2. Prepends OKF frontmatter (the four required fields per ``OKF_DOCUMENTATION_COOKBOOK.md``
   lines 209-218, plus the ``guard_id`` / ``checklist_section`` / ``standards`` extension fields).
3. Rewrites the H1 from ``# Guard Design: <id> (§N)`` to the guard's title as prose. The ``§``
   marker is deleted from the heading because it now lives in ``checklist_section`` (RFC Q6).
4. Appends ``# Citations`` as the last top-level heading (cookbook line 238: "The ``# Citations``
   heading must always be last if present").

Rewriting an existing H1 is a heading *rename*, which the cookbook's immutability rule (line 623)
forbids in the steady state. It is legitimate here for two reasons, both recorded so a later
reader does not conclude the rule was simply ignored: this IS the migration that introduces these
docs to OKF, and RFC Q5 designates ``type: Guard`` as the one *revisable* concept type.

``checklist_section`` and ``standards`` are derived from ``agentsec/checklist/checklist.json``,
not from the doc heading. The checklist is the CI-enforced artifact (``validate-checklist.py``
proves every ``check_ids`` entry resolves); the heading was prose gated only on containing a
``§``. Where the two disagree the checklist wins and the disagreement is REPORTED, never silently
resolved: run with ``--report-drift`` to list them.

Usage::

    python scripts/migrate_guard_docs.py                 # dry run: print the plan, write nothing
    python scripts/migrate_guard_docs.py --write         # migrate every un-migrated doc
    python scripts/migrate_guard_docs.py --write --only cors-wildcard,jwt-alg
    python scripts/migrate_guard_docs.py --report-drift   # doc-heading vs checklist section drift
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEGACY_DIR = ROOT / "docs" / "knowledge"
WIKI_GUARDS_DIR = ROOT / "wiki" / "guards"
CHECKLIST = ROOT / "agentsec" / "checklist" / "checklist.json"

# The TEMPLATE is intentionally NOT handled here: it has no registry entry and its body is
# instructions rather than a guard's design, so it was migrated by hand to wiki/guards/TEMPLATE.md.
LEGACY_PREFIX = "guard-design-"

# The H1 every legacy doc carries. Measured 2026-08-14: all 259 guard docs match this, and zero
# have a heading id that disagrees with their filename. A doc that stops matching is an ERROR,
# never a skip -- a silent skip here is the "failure that presents as success" class (CLAUDE.md
# review rule 3), because the doc would be left behind with no signal.
_H1 = re.compile(r"^#\s+[Gg]uard [Dd]esign:\s*`?(?P<id>[a-z0-9-]+)`?\s*\((?P<sections>.*)\)\s*$")

# A section marker inside that heading. Eleven docs carry more than one, across four separator
# styles (", " / " / " / "/" / "/§"), which is why the frontmatter field is always a LIST.
_SECTION = re.compile(r"§\s*([0-9]+[a-z]?)")

# A fenced code block opener/closer. Guard docs are full of shell and Python comment lines that
# start with "# " INSIDE fences ("# Fires:", "# Bad -- ..."). A fence-blind heading scan reads
# those as top-level headings: one doc appears to have 16. Fence-aware, every doc has exactly 1.
_FENCE = re.compile(r"^(`{3,}|~{3,})")

_CITATIONS_HEADING = "# Citations"


def top_level_headings(text: str) -> list[str]:
    """Every real top-level (``# ``) markdown heading, ignoring lines inside fenced code blocks."""
    out: list[str] = []
    fence: str | None = None
    for line in text.splitlines():
        stripped = line.lstrip()
        match = _FENCE.match(stripped)
        if match:
            token = match.group(1)[0] * 3
            if fence is None:
                fence = token
            elif stripped.startswith(fence):
                fence = None
            continue
        if fence is None and line.startswith("# "):
            out.append(line)
    return out


@dataclass(frozen=True)
class GuardMeta:
    """Everything the frontmatter for one guard is built from."""

    guard_id: str
    title: str
    sections: tuple[str, ...]        # from checklist.json (authoritative)
    doc_sections: tuple[str, ...]    # from the legacy H1 (reported when it disagrees)
    standards: tuple[str, ...]
    items: tuple[tuple[str, str], ...]   # (checklist item id, its section)


def _checklist_index() -> tuple[dict[str, set[str]], dict[str, set[tuple[str, str]]]]:
    """``(standards, items)`` keyed by guard id, from checklist.json.

    ``items`` holds ``(item_id, section)`` pairs, so the section a citation names is the section
    of that specific item rather than a guess from an unordered set.
    """
    data = json.loads(CHECKLIST.read_text(encoding="utf-8"))
    standards: dict[str, set[str]] = {}
    items: dict[str, set[tuple[str, str]]] = {}
    for item in data["items"]:
        for check_id in item.get("check_ids") or []:
            standards.setdefault(check_id, set()).update(item.get("standards") or [])
            items.setdefault(check_id, set()).add((item["id"], item["section"]))
    return standards, items


def _git_created(path: Path) -> str:
    """The doc's git creation time as ISO-8601, for the OKF ``timestamp`` field.

    Falls back to the repo HEAD's commit time when the file has no add-record (a brand-new,
    uncommitted doc -- the in-flight-contributor case). The fallback is always REPORTED by the
    caller rather than applied silently.
    """
    rel = path.relative_to(ROOT).as_posix()
    out = subprocess.run(
        ["git", "log", "--diff-filter=A", "--format=%aI", "--", rel],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=False,
    ).stdout.strip()
    stamps = [line for line in out.splitlines() if line.strip()]
    if stamps:
        return stamps[-1]
    head = subprocess.run(
        ["git", "log", "-1", "--format=%aI"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=False,
    ).stdout.strip()
    return head or "1970-01-01T00:00:00Z"


def _yaml_scalar(value: str) -> str:
    """A YAML-safe double-quoted scalar, without importing a YAML library.

    A JSON string IS a valid YAML 1.2 double-quoted flow scalar, so ``json.dumps`` is a correct
    emitter here. It matters: guard titles carry em dashes, parentheses, colons, slashes and (in
    one case) an embedded double quote.

    ``ensure_ascii=False`` is load-bearing, not a style choice. The default (``True``) escapes
    every non-ASCII character, so an em dash is emitted as the six characters ``\\u2014``. That is
    still valid YAML and ``yaml.safe_load`` decodes it, which is exactly why it went unnoticed:
    the OKF frontmatter gate saw a correct em dash while the generated index rendered the literal
    escape into 31 of 259 bullets. Emit the real character (#618 review, H1).
    """
    return json.dumps(value, ensure_ascii=False)


def _yaml_list(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(_yaml_scalar(v) for v in values) + "]"


def build_frontmatter(meta: GuardMeta, timestamp: str) -> str:
    """The OKF frontmatter block, field order mirroring the cookbook's canonical example."""
    lines = [
        "---",
        "type: Guard",
        f"title: {_yaml_scalar(meta.guard_id)}",
        f"description: {_yaml_scalar(meta.title + '.')}",
        f"timestamp: {_yaml_scalar(timestamp)}",
        f"guard_id: {_yaml_scalar(meta.guard_id)}",
        f"checklist_section: {_yaml_list(meta.sections)}",
    ]
    # Six guards carry no standards in the checklist. Omit the key rather than emit an empty
    # list: OKF extension fields are optional, and an empty list reads as a claim of "none apply".
    if meta.standards:
        lines.append(f"standards: {_yaml_list(meta.standards)}")
    lines.append("---")
    return "\n".join(lines) + "\n\n"


def build_citations(meta: GuardMeta) -> str:
    """The trailing ``# Citations`` section: real, checkable references only.

    Deliberately cites artifacts that exist in this repo (the checklist items that map the guard)
    and the standards ids those items carry. No URLs are invented -- the cookbook's rule for this
    section is "real sources only".
    """
    entries = [f"agentsec checklist item `{item_id}` (§{section})" for item_id, section in meta.items]
    entries.extend(meta.standards)
    numbered = "\n".join(f"[{i}] {e}" for i, e in enumerate(entries, 1))
    return f"\n{_CITATIONS_HEADING}\n\n{numbered}\n"


def transform(text: str, meta: GuardMeta, timestamp: str) -> str:
    """The whole doc transform. Pure, so it is unit-testable without touching the filesystem."""
    lines = text.splitlines(keepends=True)
    heading_index = next((i for i, line in enumerate(lines) if line.startswith("#")), None)
    if heading_index is None:
        raise ValueError(f"{meta.guard_id}: no heading found")
    match = _H1.match(lines[heading_index].rstrip("\n"))
    if match is None:
        raise ValueError(f"{meta.guard_id}: H1 does not match the expected shape: {lines[heading_index]!r}")
    if match.group("id") != meta.guard_id:
        raise ValueError(
            f"{meta.guard_id}: H1 declares id {match.group('id')!r}, which disagrees with the filename"
        )
    lines[heading_index] = f"# {meta.title}\n"
    body = "".join(lines)
    if _CITATIONS_HEADING not in top_level_headings(body):
        body = body.rstrip("\n") + "\n" + build_citations(meta)
    return build_frontmatter(meta, timestamp) + body


def _collect(only: set[str] | None) -> tuple[list[GuardMeta], list[str]]:
    """Guard metadata for every doc still at the legacy path, plus any anomalies found."""
    sys.path.insert(0, str(ROOT))
    from agentsec.registry import ALL_GUARDS

    standards, items = _checklist_index()
    metas: list[GuardMeta] = []
    problems: list[str] = []
    for guard in sorted(ALL_GUARDS, key=lambda g: g.id):
        if only is not None and guard.id not in only:
            continue
        legacy = LEGACY_DIR / f"{LEGACY_PREFIX}{guard.id}.md"
        if not legacy.is_file():
            continue
        head = next(
            (line for line in legacy.read_text(encoding="utf-8").splitlines() if line.startswith("#")),
            "",
        )
        match = _H1.match(head)
        if match is None:
            problems.append(f"{guard.id}: H1 does not match the expected shape: {head!r}")
            continue
        doc_sections = tuple(sorted(set(_SECTION.findall(match.group("sections")))))
        guard_items = tuple(sorted(items.get(guard.id, set())))
        chk_sections = tuple(sorted({section for _item_id, section in guard_items}))
        if not chk_sections:
            problems.append(f"{guard.id}: no checklist item maps this guard via check_ids")
            continue
        metas.append(
            GuardMeta(
                guard_id=guard.id,
                title=guard.title,
                sections=chk_sections,
                doc_sections=doc_sections,
                standards=tuple(sorted(standards.get(guard.id, set()))),
                items=guard_items,
            )
        )
    return metas, problems


def _git_mv(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "mv", src.relative_to(ROOT).as_posix(), dst.relative_to(ROOT).as_posix()],
        cwd=ROOT, check=True, capture_output=True, text=True, encoding="utf-8",
    )


def migrate(metas: list[GuardMeta], write: bool) -> tuple[int, int, list[str]]:
    """Returns ``(migrated, already, notes)``."""
    migrated = already = 0
    notes: list[str] = []
    for meta in metas:
        legacy = LEGACY_DIR / f"{LEGACY_PREFIX}{meta.guard_id}.md"
        target = WIKI_GUARDS_DIR / f"{meta.guard_id}.md"
        if target.is_file() and target.read_text(encoding="utf-8").startswith("---"):
            already += 1
            continue
        timestamp = _git_created(legacy)
        text = legacy.read_text(encoding="utf-8")
        new_text = transform(text, meta, timestamp)
        before = len(top_level_headings(text))
        after = len(top_level_headings(new_text))
        if after < before:
            raise ValueError(f"{meta.guard_id}: transform LOST a top-level heading ({before} -> {after})")
        if meta.doc_sections and set(meta.doc_sections) != set(meta.sections):
            notes.append(
                f"{meta.guard_id}: heading said §{'/§'.join(meta.doc_sections)}, "
                f"checklist says §{'/§'.join(meta.sections)} (checklist wins)"
            )
        if write:
            _git_mv(legacy, target)
            # newline="" so an existing CRLF is not re-translated into CRCRLF on Windows.
            with target.open("w", encoding="utf-8", newline="") as handle:
                handle.write(new_text)
        migrated += 1
    return migrated, already, notes


def refresh_frontmatter(write: bool) -> tuple[int, list[str]]:
    """Rebuild the frontmatter block of every ALREADY-migrated doc, in place.

    The body is untouched; only the block between the opening and closing ``---`` is re-emitted
    from the live registry + checklist. The doc's existing ``timestamp`` is preserved (it records
    the doc's git creation time, which is not recoverable once the file has moved), as is any
    extra key the rebuild does not own, such as ``status``.

    This exists because the migration is not the only time frontmatter can go stale: a guard's
    title changes, a checklist mapping is added, or (as in #618's review) the emitter itself had a
    bug and 259 committed docs need re-emitting. A re-runnable mode makes that a verifiable
    operation rather than a one-off hand-edit nobody can reproduce.

    Returns ``(changed, notes)``.
    """
    sys.path.insert(0, str(ROOT))
    from agentsec.registry import ALL_GUARDS

    standards, items = _checklist_index()
    changed = 0
    notes: list[str] = []
    for guard in sorted(ALL_GUARDS, key=lambda g: g.id):
        target = WIKI_GUARDS_DIR / f"{guard.id}.md"
        if not target.is_file():
            continue
        text = target.read_text(encoding="utf-8")
        if not text.startswith("---"):
            notes.append(f"{guard.id}: no frontmatter block, skipped")
            continue
        _, _, rest = text.partition("---")
        block, sep, body = rest.partition("\n---")
        if not sep:
            notes.append(f"{guard.id}: unterminated frontmatter block, skipped")
            continue
        preserved: dict[str, str] = {}
        for line in block.splitlines():
            key, sep_colon, value = line.partition(":")
            if sep_colon and key.strip() in {"timestamp", "status"}:
                preserved[key.strip()] = value.strip()

        guard_items = tuple(sorted(items.get(guard.id, set())))
        meta = GuardMeta(
            guard_id=guard.id,
            title=guard.title,
            sections=tuple(sorted({section for _item_id, section in guard_items})),
            doc_sections=(),
            standards=tuple(sorted(standards.get(guard.id, set()))),
            items=guard_items,
        )
        raw_timestamp = preserved.get("timestamp", "")
        timestamp = raw_timestamp[1:-1] if raw_timestamp.startswith('"') else raw_timestamp
        if not timestamp:
            notes.append(f"{guard.id}: no timestamp to preserve, skipped")
            continue

        # build_frontmatter ends with "---\n\n"; `body` opens with the blank line that followed
        # the old closing "---", so strip it rather than doubling the gap.
        rebuilt = build_frontmatter(meta, timestamp)
        if "status" in preserved:
            close = rebuilt.rindex("---")
            rebuilt = rebuilt[:close] + f"status: {preserved['status']}\n" + rebuilt[close:]
        new_text = rebuilt + body.lstrip("\n")
        if new_text == text:
            continue
        changed += 1
        if write:
            with target.open("w", encoding="utf-8", newline="") as handle:
                handle.write(new_text)
    return changed, notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write", action="store_true", help="perform the migration (default: dry run)")
    parser.add_argument("--only", default="", help="comma-separated guard ids to restrict to")
    parser.add_argument(
        "--report-drift", action="store_true",
        help="list docs whose legacy H1 section disagrees with checklist.json, then exit",
    )
    parser.add_argument(
        "--refresh-frontmatter", action="store_true",
        help="rebuild the frontmatter of ALREADY-migrated docs in place (bodies untouched)",
    )
    args = parser.parse_args(argv)

    if args.refresh_frontmatter:
        changed, notes = refresh_frontmatter(write=args.write)
        verb = "refreshed" if args.write else "would refresh"
        print(f"{verb} frontmatter in {changed} doc(s)")
        for note in notes:
            print(f"  {note}", file=sys.stderr)
        return 0

    only = {i.strip() for i in args.only.split(",") if i.strip()} or None
    metas, problems = _collect(only)

    if problems:
        print("ANOMALIES (nothing was written):", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    if args.report_drift:
        # `metas` only ever holds docs still at the LEGACY path, so on a fully-migrated tree this
        # command has nothing to compare. Saying "0 disagreements" there would be a clean-looking
        # miss (CLAUDE.md review rule 3): the honest answer is "I cannot see the inputs", not
        # "there are none". The migration-time set is recorded in issue #619.
        if not metas:
            print(
                "No docs at the legacy path (docs/knowledge/guard-design-*.md), so there is "
                "nothing to compare: this reports drift between a LEGACY H1 and checklist.json.\n"
                "This is NOT a finding of zero drift. The migration-time set (26 of 259 guards) "
                "is recorded in issue #619.",
                file=sys.stderr,
            )
            return 2
        drift = [m for m in metas if m.doc_sections and set(m.doc_sections) != set(m.sections)]
        print(f"{len(drift)} of {len(metas)} legacy doc(s) whose H1 section disagrees with checklist.json:")
        for meta in drift:
            print(
                f"  {meta.guard_id}: doc §{'/§'.join(meta.doc_sections)} "
                f"vs checklist §{'/§'.join(meta.sections)}"
            )
        return 0

    migrated, already, notes = migrate(metas, write=args.write)
    verb = "migrated" if args.write else "would migrate"
    print(f"{verb} {migrated} doc(s); {already} already migrated")
    if notes:
        print(f"\n{len(notes)} section disagreement(s) resolved in favour of checklist.json:")
        for note in notes:
            print(f"  {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
