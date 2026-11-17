"""The gate on the generated helper index in `agentsec/guards/base.py`'s module docstring.

`base.py` is the shared toolbox, and it is far too long to browse: three documents told a guard
author "reuse the shared helpers" and then named five of them, leaving the comment strippers, the
path classifiers and the cross-file router-auth resolvers undiscoverable (codebase-as-prompt audit
2026-08-27, QW3). The index closes that, and this file is what stops it rotting.

Two gates, and the pairing is the whole design:

1. `test_index_in_base_docstring_is_in_sync` compares the generator's render to the committed file.
   That catches a stale index, and NOTHING else: it compares the generator's output to the
   generator's own committed output, so a bug in the generator makes both sides wrong together.
2. `test_index_matches_an_INDEPENDENT_parse_of_the_live_module` reaches the same facts by a
   different route (import the module, `inspect.getdoc` on live function objects, a separately
   written paragraph extractor) and asserts the committed index agrees. The duplicated summary rule
   is deliberate, not an oversight: it is what catches a generator that renders confidently wrong
   text and then writes it to disk. This is the #618 lesson, in which `wiki/guards/index.md` shipped
   31 wrong bullets under a green sync test.

The independence is in the code path AND in the constants, and the second half was learned the hard
way here: this file first imported `gen.MAX_SUMMARY`, and a review found that mutating the
generator's cap and re-running `--write` kept every test green. Anything the rendered text depends
on has to be restated on this side, or "independent" is only true of the parts nobody parameterized.
The sentinels are the one deliberate exception: they LOCATE the region rather than describe its
contents, and a renamed sentinel is caught by the sync gate.
"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import re
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_BASE = _REPO / "agentsec" / "guards" / "base.py"

# Loaded the same way tests/test_wiki_guards_okf.py loads scripts/gen_wiki_guards_index.py.
_spec = importlib.util.spec_from_file_location(
    "gen_guard_helpers_index", _REPO / "scripts" / "gen_guard_helpers_index.py"
)
assert _spec is not None and _spec.loader is not None
gen = importlib.util.module_from_spec(_spec)
sys.modules["gen_guard_helpers_index"] = gen
_spec.loader.exec_module(gen)

_ROW = re.compile(r"^  (?P<name>\w+) +(?P<summary>\S.*)$")

# The independent gate's own copy of the truncation cap, as a LITERAL. It must not be
# `gen.MAX_SUMMARY`: importing it made the "independent" side move with the generator, so changing
# the generator's cap and re-running `--write` left all of these tests green while every rendered
# summary silently changed width. That is the same both-sides-wrong-together failure this file
# exists to prevent, reached through a shared constant instead of shared code. Pinned rather than
# derived, and `test_the_two_caps_are_pinned_together` makes moving it a deliberate two-file edit.
_INDEPENDENT_MAX_SUMMARY = 75


def _committed_index() -> dict[str, str]:
    """`{helper name -> rendered summary}` parsed out of the committed base.py docstring.

    Reads the FILE, not the generator, so the second gate never consults the thing it is checking.
    """
    source = _BASE.read_text(encoding="utf-8")
    body = source.split("\n")
    begin, end = body.index(gen.BEGIN), body.index(gen.END)
    rows: dict[str, str] = {}
    for line in body[begin + 1 : end]:
        match = _ROW.match(line)
        if match:
            rows[match.group("name")] = match.group("summary")
    return rows


def _independent_summary(docstring: str) -> str:
    """The leading-paragraph rule, written a second time and on purpose.

    Deliberately NOT `gen.summary`: a shared implementation would make the gate below agree with the
    generator by construction, which is exactly the failure mode this file exists to avoid. The
    paragraph split is a regex here and a line loop there.
    """
    paragraph = re.split(r"\n[ \t]*\n", docstring.strip(), maxsplit=1)[0]
    text = " ".join(paragraph.split())
    if len(text) <= _INDEPENDENT_MAX_SUMMARY:
        return text
    words = text[: _INDEPENDENT_MAX_SUMMARY - 3].split(" ")
    kept = " ".join(words[:-1]) if len(words) > 1 else words[0]
    return kept.rstrip(" ,;:-.") + "..."


def _live_helpers() -> dict[str, str]:
    """`{name -> docstring}` for every public helper, from the IMPORTED module."""
    from agentsec.guards import base

    return {
        name: inspect.getdoc(fn) or ""
        for name, fn in inspect.getmembers(base, inspect.isfunction)
        if not name.startswith("_") and fn.__module__ == "agentsec.guards.base"
    }


def test_index_in_base_docstring_is_in_sync() -> None:
    source = _BASE.read_text(encoding="utf-8")
    assert gen.render(source) == source, (
        "agentsec/guards/base.py's helper index is stale. "
        "Run: python scripts/gen_guard_helpers_index.py --write"
    )


def test_index_matches_an_INDEPENDENT_parse_of_the_live_module() -> None:
    live = _live_helpers()
    # Not a formality: a sweep that silently collected nothing would satisfy every assertion below
    # while checking zero helpers (CLAUDE.md review rule 3, a failure that presents as success).
    assert len(live) > 30, "the independent sweep collected no helpers"

    committed = _committed_index()
    assert set(committed) == set(live), (
        "the committed index and the live module disagree about which helpers exist: "
        f"only in the index {sorted(set(committed) - set(live))}, "
        f"only in the module {sorted(set(live) - set(committed))}"
    )

    wrong = {
        name: (committed[name], _independent_summary(doc))
        for name, doc in live.items()
        if committed[name] != _independent_summary(doc)
    }
    assert not wrong, "index rows disagree with an independent read of the live docstrings:\n  " + "\n  ".join(
        f"{name}: index says {got!r}, the docstring says {want!r}" for name, (got, want) in sorted(wrong.items())
    )


def test_every_public_helper_has_a_docstring_and_a_group() -> None:
    # The two invariants that make a docstring-derived index possible at all. Asserted against the
    # live source so a helper added without either fails BY NAME, with the fix in the message.
    source = _BASE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    public = [
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and not n.name.startswith("_")
    ]
    assert len(public) > 30, "the sweep collected no helpers"

    undocumented = [n.name for n in public if not (ast.get_docstring(n) or "").strip()]
    assert not undocumented, (
        f"public helpers in base.py with no docstring: {undocumented} - the index is generated from "
        "the docstring, so an undocumented helper cannot be described. Add a one-line summary."
    )

    grouped = {h.name for h in gen.helpers(source)}
    ungrouped = [n.name for n in public if n.name not in grouped]
    assert not ungrouped, (
        f"public helpers in base.py with no `# === helpers: <Group> ===` banner above them: "
        f"{ungrouped} - add a banner (repeated titles merge, so re-opening a group is fine and no "
        "helper ever needs to move)."
    )


def test_summary_rule_handles_the_shapes_that_broke_naive_extraction() -> None:
    # The live corpus passes by construction, so it proves nothing about the rule itself. These are
    # the four real shapes in base.py that defeated the two obvious implementations, planted
    # directly. Same reason, same shape, as test_meta.py's planted-divergence test.
    #
    # 1. a one-line docstring passes through verbatim
    assert gen.summary("Blank Go `//` comments.") == "Blank Go `//` comments."
    # 2. a first sentence wrapped across physical lines is JOINED, not truncated at the wrap
    assert gen.summary("Resolve the detected python\ndirs to absolute paths.") == (
        "Resolve the detected python dirs to absolute paths."
    )
    # 3. `{ ... }` inside the summary must not be read as a sentence end (iter_terraform_locals_blocks)
    assert gen.summary("Yield spans for each `locals { ... }` block.") == (
        "Yield spans for each `locals { ... }` block."
    )
    # 4. a literal backslash survives (join_dockerfile_continuations); the raw docstring carries it
    assert "\\" in gen.summary("Join a ``\\`` continuation.")
    # 5. only the LEADING paragraph is taken
    assert gen.summary("First para.\n\nSecond para.") == "First para."
    # 6. over-long text truncates at a word boundary, inside the cap, with no doubled period
    long = gen.summary("Blank Go comments, preserving layout. " + "word " * 40)
    assert len(long) <= gen.MAX_SUMMARY
    assert long.endswith("...") and not long.endswith("....")
    assert not long.rstrip(".").endswith(" "), "truncation must not leave a dangling space"


def test_the_generator_rejects_a_helper_above_the_first_banner() -> None:
    # There is deliberately no catch-all group. A default bucket is how findings.py::_AREA degraded
    # silently for 256 check ids until BB4 drained it: the report still rendered, still passed CI,
    # still looked correct.
    orphan = 'def stray_helper() -> None:\n    """Does a thing."""\n'
    with pytest.raises(gen.GeneratorError, match="stray_helper"):
        gen.helpers(orphan)

    banner = "# === helpers: Something ===\n"
    with pytest.raises(gen.GeneratorError, match="no docstring"):
        gen.helpers(banner + "def undocumented() -> None:\n    return None\n")

    # ...and the same source WITH a banner and a docstring is accepted, so the two assertions above
    # are rejecting the planted defect rather than everything.
    assert gen.helpers(banner + orphan) == [gen.Helper("Something", "stray_helper", "Does a thing.")]

    # `async def` is a DIFFERENT ast node, and filtering on `ast.FunctionDef` alone dropped one
    # silently: no index row, no error, in a design whose whole promise is "there is deliberately no
    # catch-all bucket". Dormant today (base.py has no async helper) and therefore exactly the kind
    # of gap that ships. Both rejections are asserted for async too, plus the accept case.
    async_orphan = 'async def stray_async() -> None:\n    """Does an async thing."""\n'
    with pytest.raises(gen.GeneratorError, match="stray_async"):
        gen.helpers(async_orphan)
    with pytest.raises(gen.GeneratorError, match="no docstring"):
        gen.helpers(banner + "async def undocumented_async() -> None:\n    return None\n")
    assert gen.helpers(banner + async_orphan) == [
        gen.Helper("Something", "stray_async", "Does an async thing.")
    ]


def test_the_two_caps_are_pinned_together() -> None:
    # The independent gate restates the cap as a literal rather than importing it (see
    # _INDEPENDENT_MAX_SUMMARY). That closes the shared-constant hole but opens a smaller one: the
    # two could drift apart and nothing would say so. Pinning them here means changing the width is
    # a deliberate two-file edit, and it is what turns a generator-side cap mutation red.
    assert _INDEPENDENT_MAX_SUMMARY == gen.MAX_SUMMARY, (
        "the generator's MAX_SUMMARY moved. Re-read the rendered index, confirm the new width is "
        "what you want, then update _INDEPENDENT_MAX_SUMMARY to match - deliberately, not reflexively"
    )


def test_index_rows_cannot_be_mistaken_for_call_sites() -> None:
    # The index lives INSIDE a file under `agentsec/guards/`, and
    # `tests/test_guard_sandbox.py::test_is_nonproduct_path_callers_thread_archive_segments`
    # text-scans every line of every guard module for `is_nonproduct_path(` to prove each call site
    # threads `archive_segments`. Rows first rendered as `name()`, which is indistinguishable from a
    # call site to that scan, and it turned the gate red. Rows carry bare names now. This pins it,
    # because "put the parens back" is a one-character cosmetic edit whose consequence is two files
    # away and reads as an unrelated failure.
    source = _BASE.read_text(encoding="utf-8")
    body = source.split("\n")
    region = body[body.index(gen.BEGIN) + 1 : body.index(gen.END)]
    assert region, "the index region is empty"

    call_shaped = [line for line in region if "is_nonproduct_path(" in line]
    assert not call_shaped, (
        "the generated index contains text the guard-sandbox scan reads as an `is_nonproduct_path` "
        f"call site: {call_shaped}"
    )
    parenthesised = [line for line in region if (m := _ROW.match(line)) and "(" in m.group("name")]
    assert not parenthesised, f"index rows must name helpers bare, without `()`: {parenthesised}"


def test_line_splitting_follows_ast_not_str_splitlines() -> None:
    # base.py carries literal U+2028/U+2029 inside its JS line-terminator constants, and
    # `str.splitlines()` splits on those while the tokenizer does not. Measured on the real file:
    # splitlines() reports six more lines than `ast` counts, so a splitlines()-based splice writes
    # the docstring six lines from where it belongs. Nothing else in the suite would notice, because
    # the corrupted file still parses.
    source = _BASE.read_text(encoding="utf-8")
    extra = sum(source.count(ch) for ch in "\u2028\u2029\x0b\x0c\x1c\x1d\x1e\x85")
    assert extra, "base.py no longer carries the separators that make this gate meaningful"
    assert len(source.splitlines()) == source.count("\n") + extra, "the two line notions still differ"
    assert len(gen.split_lines(source)) == source.count("\n") + 1, "split_lines must count ast's lines"
