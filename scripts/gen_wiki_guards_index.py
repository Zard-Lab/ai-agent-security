#!/usr/bin/env python3
"""Generate ``wiki/guards/index.md`` from the frontmatter of every ``wiki/guards/<id>.md``.

OKF requires an index per directory (``docs/knowledge/OKF_DOCUMENTATION_COOKBOOK.md`` lines
288-317). Two rules from that section drive the whole shape of this file, and both are easy to
get backwards:

1. **A non-root index carries NO frontmatter at all**, not even ``okf_version``. The root
   ``wiki/index.md`` is the only place in the bundle where an ``index.md`` may have frontmatter.
2. **An index lists only its own directory**, never cross-references a sibling.

Bullets are ``* [title](relative-path.md) - Description sentence.``, with the description copied
VERBATIM from the doc's ``description`` frontmatter field, and grouped under a ``# {TypeValue}``
heading (cookbook line 141) -- for guard docs that is ``# Guard``.

The wiki's other two indexes (``wiki/research/index.md``, ``wiki/methodology/index.md``) are
hand-maintained. This one is generated because it has 259 entries and grows with every guard PR,
so hand-maintenance would rot within a week. ``--check`` is the CI gate that keeps it in sync.

Usage::

    python scripts/gen_wiki_guards_index.py --write     # regenerate the index
    python scripts/gen_wiki_guards_index.py --check     # exit 1 if it is out of sync
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WIKI_GUARDS_DIR = ROOT / "wiki" / "guards"
INDEX = WIKI_GUARDS_DIR / "index.md"

# Docs that are not guard concept docs and so never appear as index bullets.
_NON_CONCEPT = {"index.md", "TEMPLATE.md"}

_HEADING = "# Guard"


def read_frontmatter(path: Path) -> dict[str, str]:
    """The doc's frontmatter as flat ``key -> raw value`` strings (no YAML dependency).

    Only the scalar string fields this generator needs (``title``, ``description``) are unquoted;
    list values are returned raw. Deliberately minimal: ``scripts/`` is stdlib-only, since it must
    run wherever the CLI runs, not only inside the dev extra.
    """
    out: dict[str, str] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        return out
    for line in lines[1:]:
        if line.strip() == "---":
            break
        key, sep, value = line.partition(":")
        if not sep:
            continue
        raw = value.strip()
        if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
            # `json.loads` is the exact inverse of the `json.dumps` emitter in
            # migrate_guard_docs.py, so it handles EVERY escape that emitter can produce.
            # The previous hand-rolled unescape covered only \" and \\, so a `—` em dash
            # (which json.dumps emits by default) was rendered literally into the index for
            # 31 of 259 bullets (#618 review, H1). Never re-narrow this to a hand-rolled pass:
            # the emitter's escape set is json's, so the decoder's must be too.
            try:
                decoded = json.loads(raw)
                raw = decoded if isinstance(decoded, str) else raw
            except json.JSONDecodeError:
                # A hand-edited value that is quoted but not valid JSON: fall back to the raw
                # inner text rather than dropping the field, and let the OKF gate flag it.
                raw = raw[1:-1]
        out[key.strip()] = raw
    return out


def concept_docs() -> list[Path]:
    return sorted(p for p in WIKI_GUARDS_DIR.glob("*.md") if p.name not in _NON_CONCEPT)


def render() -> str:
    """The full index text."""
    lines = [_HEADING]
    for path in concept_docs():
        front = read_frontmatter(path)
        title = front.get("title") or path.stem
        description = front.get("description") or ""
        lines.append(f"* [{title}]({path.name}) - {description}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", action="store_true", help="regenerate the index (default)")
    group.add_argument("--check", action="store_true", help="exit 1 if the committed index is stale")
    args = parser.parse_args(argv)

    expected = render()
    if args.check:
        actual = INDEX.read_text(encoding="utf-8") if INDEX.is_file() else ""
        if actual != expected:
            print(
                "wiki/guards/index.md is out of sync with the guard docs. "
                "Run: python scripts/gen_wiki_guards_index.py --write",
                file=sys.stderr,
            )
            return 1
        print(f"wiki/guards/index.md is in sync ({len(concept_docs())} guard docs)")
        return 0

    INDEX.parent.mkdir(parents=True, exist_ok=True)
    # newline="" so the emitted "\n" endings are not re-translated to CRLF on Windows.
    with INDEX.open("w", encoding="utf-8", newline="") as handle:
        handle.write(expected)
    print(f"wrote {INDEX.relative_to(ROOT).as_posix()} ({len(concept_docs())} guard docs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
