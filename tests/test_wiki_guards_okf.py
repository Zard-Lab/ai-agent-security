"""OKF conformance gate for `wiki/guards/` (the per-guard design docs).

RFC `docs/knowledge/rfc-soft-launch-readiness.md` Proposal 3 moved the guard-design docs into the
OKF knowledge base. Before this file there was ZERO automated OKF enforcement anywhere in the repo
(no linter, no frontmatter check, nothing) -- the wiki was conformant by discipline only. That was
tolerable for ~35 hand-curated docs; it is not tolerable for 259 that every contributor adds to.

Scope is deliberately `wiki/guards/` ONLY. The rest of the wiki has never been gated, and widening
the net here would mix a migration with a compliance sweep over docs this PR does not touch.

The rules enforced are the cookbook's own, cited per-test:
`docs/knowledge/OKF_DOCUMENTATION_COOKBOOK.md` lines 209-218 (required fields), 216 (one-sentence
description), 862 (the ISO-8601 regex), 237-238 (`# Citations` last), 288-317 (index frontmatter).
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[1]
_GUARDS_DIR = _REPO / "wiki" / "guards"
_INDEX = _GUARDS_DIR / "index.md"
_TEMPLATE = _GUARDS_DIR / "TEMPLATE.md"

# Loaded the same way tests/test_doc_counts.py loads scripts/doc_counts.py.
_spec = importlib.util.spec_from_file_location("gen_wiki_guards_index", _REPO / "scripts" / "gen_wiki_guards_index.py")
assert _spec is not None and _spec.loader is not None
gen = importlib.util.module_from_spec(_spec)
sys.modules["gen_wiki_guards_index"] = gen
_spec.loader.exec_module(gen)

_migrate_spec = importlib.util.spec_from_file_location("migrate_guard_docs", _REPO / "scripts" / "migrate_guard_docs.py")
assert _migrate_spec is not None and _migrate_spec.loader is not None
migrate = importlib.util.module_from_spec(_migrate_spec)
sys.modules["migrate_guard_docs"] = migrate
_migrate_spec.loader.exec_module(migrate)

# OKF_DOCUMENTATION_COOKBOOK.md:862 -- the cookbook's own timestamp validator, verbatim.
_ISO_8601 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})$")

# A description carrying a second sentence (cookbook Level 3, line 840).
_MULTI_SENTENCE = re.compile(r"[.!?]\s+\S")

_REQUIRED_FIELDS = ("type", "title", "description", "timestamp")


def _concept_docs() -> list[Path]:
    """Every per-guard concept doc (excludes the reserved index and the TEMPLATE)."""
    return sorted(p for p in _GUARDS_DIR.glob("*.md") if p.name not in {"index.md", "TEMPLATE.md"})


def _frontmatter(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}
    _, _, rest = text.partition("---")
    block, sep, _ = rest.partition("\n---")
    if not sep:
        return {}
    loaded = yaml.safe_load(block)
    return loaded if isinstance(loaded, dict) else {}


def test_there_are_guard_docs_to_check() -> None:
    # Every other test in this file iterates _concept_docs(). If that ever returns [] -- a moved
    # directory, a renamed glob -- all of them would pass while checking nothing. Assert the
    # corpus is non-empty first, so a green file cannot mean "found nothing to look at"
    # (CLAUDE.md review rule 3: a failure that presents as success).
    assert len(_concept_docs()) > 200


@pytest.mark.slow
def test_every_guard_doc_has_the_required_okf_frontmatter() -> None:
    # Cookbook lines 209-218: "All four fields are required." A field present but empty counts as
    # missing (line 464, min_length=1).
    bad: list[str] = []
    for path in _concept_docs():
        front = _frontmatter(path)
        if not front:
            bad.append(f"{path.name}: no parseable frontmatter block")
            continue
        for field in _REQUIRED_FIELDS:
            value = front.get(field)
            if not isinstance(value, str) or not value.strip():
                bad.append(f"{path.name}: required field {field!r} missing or empty")
        if front.get("type") != "Guard":
            bad.append(f"{path.name}: type is {front.get('type')!r}, expected 'Guard'")
        if front.get("guard_id") != path.stem:
            bad.append(f"{path.name}: guard_id {front.get('guard_id')!r} does not match the filename")
    assert not bad, "OKF frontmatter violations:\n  " + "\n  ".join(bad)


@pytest.mark.slow
def test_every_description_is_exactly_one_sentence() -> None:
    # Cookbook line 216: "Exactly one sentence; used verbatim in index bullets; ends with period."
    # It really is used verbatim -- gen_wiki_guards_index.py copies it into the bullet -- so a
    # two-sentence description corrupts the index, not just the frontmatter.
    bad: list[str] = []
    for path in _concept_docs():
        description = str(_frontmatter(path).get("description", ""))
        if not description.endswith("."):
            bad.append(f"{path.name}: description does not end with a period: {description!r}")
        if _MULTI_SENTENCE.search(description):
            bad.append(f"{path.name}: description is more than one sentence: {description!r}")
    assert not bad, "description-quality violations:\n  " + "\n  ".join(bad)


@pytest.mark.slow
def test_every_timestamp_is_iso_8601() -> None:
    # Cookbook line 862, the cookbook's own regex.
    bad = [
        f"{p.name}: {_frontmatter(p).get('timestamp')!r}"
        for p in _concept_docs()
        if not _ISO_8601.match(str(_frontmatter(p).get("timestamp", "")))
    ]
    assert not bad, "timestamps not matching the OKF ISO-8601 form:\n  " + "\n  ".join(bad)


@pytest.mark.slow
def test_citations_is_the_last_top_level_heading() -> None:
    # Cookbook line 238: "The `# Citations` heading must always be last if present."
    #
    # The scan MUST be fence-aware. Guard docs are full of shell/Python comment lines beginning
    # "# " inside fenced blocks ("# Fires:", "# Silent (safe defaults):"). A fence-blind scan reads
    # those as headings -- measured: one doc appears to have 16 top-level headings and every doc
    # appears to have several. Fence-aware, each has exactly one plus the appended Citations.
    bad: list[str] = []
    for path in _concept_docs():
        headings = migrate.top_level_headings(path.read_text(encoding="utf-8"))
        if "# Citations" not in headings:
            bad.append(f"{path.name}: no '# Citations' section")
        elif headings[-1] != "# Citations":
            bad.append(f"{path.name}: '# Citations' is not last (last is {headings[-1]!r})")
    assert not bad, "Citations-ordering violations:\n  " + "\n  ".join(bad)


def test_fence_aware_heading_scan_ignores_code_comments() -> None:
    # Direct unit test of the helper the gate above leans on. Without this, the Citations check is
    # only ever exercised against real docs, so a fence-handling regression would silently widen
    # or narrow it. (Same reasoning as test_meta.py's normalizer unit test.)
    text = (
        "# Real heading\n"
        "```bash\n"
        "# not a heading, a shell comment\n"
        "```\n"
        "~~~python\n"
        "# also not a heading\n"
        "~~~\n"
        "## not top level\n"
        "# Citations\n"
    )
    assert migrate.top_level_headings(text) == ["# Real heading", "# Citations"]


def test_guards_index_has_no_frontmatter_and_is_in_sync() -> None:
    # Cookbook lines 315-317: a NON-ROOT index has "no frontmatter at all -- not even
    # `okf_version`". Only the root wiki/index.md may carry frontmatter. Getting this backwards is
    # the single easiest OKF mistake to make here, so it is asserted rather than assumed.
    assert _INDEX.is_file(), "wiki/guards/index.md is missing"
    assert not _INDEX.read_text(encoding="utf-8").startswith("---"), (
        "wiki/guards/index.md must have NO frontmatter (it is a non-root index)"
    )
    assert gen.render() == _INDEX.read_text(encoding="utf-8"), (
        "wiki/guards/index.md is stale. Run: python scripts/gen_wiki_guards_index.py --write"
    )


@pytest.mark.slow
def test_index_bullets_match_an_INDEPENDENT_parse_of_each_doc() -> None:
    # The sync test above compares the generator's output to the generator's own committed
    # output. That cannot catch a bug in the generator: both sides are wrong together. It did not
    # catch exactly that (#618 review, H1) -- `json.dumps` defaults to `ensure_ascii=True`, so em
    # dashes reached the frontmatter as `—`, the generator's hand-rolled unescape did not
    # decode them, and 31 of 259 bullets shipped the literal escape text.
    #
    # So this test parses each doc with `yaml.safe_load` -- a DIFFERENT parser from the one the
    # generator uses -- and asserts the bullet says what the doc says. Any future divergence
    # between the two parsers surfaces here instead of in the rendered wiki.
    index = _INDEX.read_text(encoding="utf-8")
    bullets = {
        line.split("](", 1)[0].removeprefix("* ["): line.split(") - ", 1)[1]
        for line in index.splitlines()
        if line.startswith("* [")
    }
    bad: list[str] = []
    for path in _concept_docs():
        front = _frontmatter(path)
        title, description = str(front.get("title", "")), str(front.get("description", ""))
        if title not in bullets:
            bad.append(f"{path.name}: no index bullet for title {title!r}")
        elif bullets[title] != description:
            bad.append(f"{path.name}: bullet says {bullets[title]!r}, doc says {description!r}")
    assert not bad, "index bullets disagree with an independent parse of the docs:\n  " + "\n  ".join(bad)


def test_no_index_bullet_carries_an_undecoded_escape() -> None:
    # The narrow, fast form of the same guarantee: a literal `\uXXXX` (or `\"`, `\\`) surviving
    # into rendered wiki text is always a decoder bug, never intended content. Cheap enough to run
    # outside the slow set, because this is the symptom a reader actually sees.
    index = _INDEX.read_text(encoding="utf-8")
    offenders = [ln for ln in index.splitlines() if re.search(r"\\u[0-9a-fA-F]{4}|\\\"|\\\\", ln)]
    assert not offenders, (
        "undecoded escape sequences rendered into wiki/guards/index.md:\n  " + "\n  ".join(offenders)
    )


def test_frontmatter_emitter_and_index_parser_round_trip(tmp_path: Path) -> None:
    # Pin the emitter/decoder contract directly, so neither side can be narrowed back into
    # disagreement. The emitter is json.dumps(ensure_ascii=False); the decoder must handle that
    # AND the escaped form that a pre-fix doc or a hand-edit may still carry.
    import json

    values = (
        "@agent.tool function has no logging — silent tool invocation.",   # em dash
        'Use rel="noopener" on target="_blank" — reverse tabnabbing.',      # embedded quotes
        "Arrow → and section § and emoji 🔴.",                              # the repo's other non-ASCII
        "A plain ASCII description.",                                       # the boring case still works
    )
    for i, value in enumerate(values):
        assert migrate._yaml_scalar(value) == json.dumps(value, ensure_ascii=False)
        for j, emitted in enumerate((json.dumps(value), json.dumps(value, ensure_ascii=False))):
            doc = tmp_path / f"doc-{i}-{j}.md"
            doc.write_text(f"---\ndescription: {emitted}\n---\n\n# x\n", encoding="utf-8")
            assert gen.read_frontmatter(doc)["description"] == value, emitted


def test_root_wiki_index_carries_only_okf_version_and_lists_guards() -> None:
    # Cookbook lines 288-290: the root index's frontmatter must contain exactly `okf_version` and
    # nothing else. Also assert the new subdirectory bullet exists, since an index that does not
    # list guards/ makes 259 docs unreachable by navigation.
    text = (_REPO / "wiki" / "index.md").read_text(encoding="utf-8")
    _, _, rest = text.partition("---")
    block, _, body = rest.partition("\n---")
    assert yaml.safe_load(block) == {"okf_version": "0.1"}
    assert "* [guards/](guards/index.md)" in body


def test_template_is_not_indexed_but_is_okf_shaped() -> None:
    # The TEMPLATE is scaffolding, not a concept doc: it must stay out of the index (it would
    # appear as a guard named "<id>") while still modelling the frontmatter a contributor copies.
    assert _TEMPLATE.is_file()
    assert "TEMPLATE.md" not in _INDEX.read_text(encoding="utf-8")
    front = _frontmatter(_TEMPLATE)
    assert front.get("type") == "Guard"
    assert front.get("status") == "draft"
    for field in _REQUIRED_FIELDS:
        assert field in front, field


@pytest.mark.slow
def test_no_guard_doc_references_the_pre_migration_filename() -> None:
    # The migration renamed every file, which silently broke the cross-references BETWEEN guard
    # docs: 11 of them cited `guard-design-<id>.md`, and two used the OKF `[[guard-design-<id>]]`
    # wiki-link form, so those links pointed at nothing. A diff-based review does not surface this
    # (the lines are inside the 259 otherwise-unchanged renamed files), and the cookbook's own
    # cross-link check (audit step 8) is not automated here. Hence a gate.
    #
    # Guard docs reference siblings by bare filename (`<id>.md`) or wiki-link (`[[<id>]]`).
    stale: list[str] = []
    for path in [*_concept_docs(), _TEMPLATE]:
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "guard-design-" in line:
                stale.append(f"{path.name}:{i}: {line.strip()[:100]}")
    assert not stale, (
        "guard docs citing pre-migration filenames (use `<id>.md` or `[[<id>]]` for a sibling):\n  "
        + "\n  ".join(stale)
    )


def _strip_code(text: str) -> str:
    """Blank out fenced blocks and inline code spans, keeping line count stable.

    Needed because `[[...]]` is also TOML array-of-table syntax: `dependency-version-floor.md`
    documents reading `poetry.lock` and writes `` `[[package]]` `` in backticks. A link checker
    that does not strip code reports that as a broken wiki-link.
    """
    out, fence = [], False
    for line in text.splitlines():
        if re.match(r"^\s*(`{3,}|~{3,})", line):
            fence = not fence
            out.append("")
            continue
        out.append("" if fence else re.sub(r"`[^`]*`", "", line))
    return "\n".join(out)


@pytest.mark.slow
def test_guard_doc_cross_links_resolve() -> None:
    # A cross-link naming a file that does not exist is the same defect one rename later, and the
    # migration created 13 of them at once. Resolve against the whole wiki, not just siblings, and
    # against the wiki ONLY: `docs/knowledge/` is private, so a [[link]] into it is dead in the
    # public repo (six such links shipped until the public export was first tested).
    stems = _wiki_stems()
    sibling_files = {p.name for p in _GUARDS_DIR.glob("*.md")}
    broken: list[str] = []
    for path in _concept_docs():
        text = _strip_code(path.read_text(encoding="utf-8"))
        for target in re.findall(r"\[\[([a-z0-9][a-z0-9-]*)\]\]", text):
            if target not in stems:
                broken.append(f"{path.name}: [[{target}]] resolves to no known doc")
        for target in re.findall(r"\]\((?!https?:|/|#)([a-z0-9-]+\.md)\)", text):
            if target not in sibling_files:
                broken.append(f"{path.name}: link to {target} resolves to nothing in wiki/guards/")
    assert not broken, "broken cross-links in wiki/guards/:\n  " + "\n  ".join(broken)


def test_cross_link_checker_ignores_code_and_accepts_cross_directory_links() -> None:
    # FP-bait for the widening above (CLAUDE.md review rule 1). The checker must stay silent on
    # the two legitimate shapes that tripped its first draft, and still catch a real dangling link.
    assert "[[package]]" not in _strip_code("- lockfiles: `[[package]]` name/version\n")
    assert "[[package]]" not in _strip_code("```toml\n[[package]]\nname = 'x'\n```\n")
    assert "[[cors-wildcard]]" in _strip_code("see [[cors-wildcard]] for the sibling\n")
    # a cross-directory link to a real wiki page outside wiki/guards/ resolves...
    stems = _wiki_stems()
    assert "operating-doctrine" in stems and (_REPO / "wiki" / "methodology" / "operating-doctrine.md").is_file()
    # ...and one into the private docs/knowledge/ does not, whether or not this tree holds the note
    # (the private repo does; the public export does not, and the answer must be the same in both)
    assert "severity-axes-doctrine" not in stems


def _wiki_stems() -> set[str]:
    return {p.stem for p in _REPO.joinpath("wiki").rglob("*.md")}


def test_no_guard_doc_still_carries_a_section_marker_in_its_heading() -> None:
    # RFC Q6: the checklist section moved OUT of the H1 and into `checklist_section` frontmatter.
    # A doc whose heading still carries "§" is one a contributor hand-wrote to the old convention;
    # the frontmatter gate would not catch it, because the frontmatter can be correct while the
    # heading duplicates (and then drifts from) the same fact.
    bad = [
        p.name
        for p in _concept_docs()
        if any("§" in h for h in migrate.top_level_headings(p.read_text(encoding="utf-8")))
    ]
    assert not bad, "guard docs whose H1 still carries a § marker (it belongs in frontmatter):\n  " + "\n  ".join(bad)
