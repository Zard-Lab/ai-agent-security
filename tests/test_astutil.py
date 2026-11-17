"""Tests for `agentsec.astutil` — the shared total-parse helper (issue #370)."""
from __future__ import annotations

import ast
import re
import warnings
from pathlib import Path

import pytest

from agentsec import astutil
from agentsec.astutil import (
    PARSE_FAILURE_EXCEPTIONS,
    ParseCandidates,
    parse_failure_candidates,
    parse_failure_reason,
    parse_failure_run,
    safe_ast_parse,
)
from agentsec.audit import audit
from agentsec.guards.base import (
    derived_state_run,
    enclosing_function,
    iter_functions,
    strip_python_strings,
)

# `ast.parse` may be called directly ONLY in these files: astutil.py owns the helper; guard_sandbox
# catches the shared PARSE_FAILURE_EXCEPTIONS tuple in place because it needs the exception object to
# report the failing line. Every other site must route through `safe_ast_parse`.
_AST_PARSE_ALLOWLIST = {"astutil.py", "guard_sandbox.py"}
_AST_PARSE_CALL = re.compile(r"\bast\.parse\s*\(")


def test_safe_ast_parse_returns_module_on_valid_source() -> None:
    tree = safe_ast_parse("x = 1\ndef f():\n    return x\n")
    assert isinstance(tree, ast.Module)


def test_safe_ast_parse_returns_none_on_syntax_error() -> None:
    assert safe_ast_parse("def broken(:\n    pass\n") is None


def test_safe_ast_parse_returns_none_on_nul_byte() -> None:
    # NUL bytes raise ValueError, not SyntaxError.
    assert safe_ast_parse("x = 1\x00\n") is None


@pytest.mark.parametrize("exc", PARSE_FAILURE_EXCEPTIONS)
def test_safe_ast_parse_catches_every_failure_exception(
    exc: type[Exception], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Deterministic (version-independent, cf. #320): force ast.parse to raise each member of the
    # set and confirm safe_ast_parse swallows it and returns None rather than propagating.
    # `**_kw` so the double matches the real call shape: `safe_ast_parse` passes `filename=`
    # through to `ast.parse`, and a stub that rejects it raises TypeError — which is NOT in
    # PARSE_FAILURE_EXCEPTIONS, so it would propagate and this test would assert the wrong thing.
    def boom(_text: object, **_kw: object) -> object:
        raise exc("forced")
    monkeypatch.setattr("agentsec.astutil.ast.parse", boom)
    assert safe_ast_parse("x = 1\n") is None


def test_safe_ast_parse_is_total_on_a_really_deeply_nested_expression() -> None:
    # Real-behavior anchor: a deeply nested unary makes CPython's parser raise MemoryError
    # ("Parser stack overflowed"). Whether a given depth overflows is version-specific, so assert
    # the contract that holds regardless — it never raises (returns None if it overflowed, else an AST).
    result = safe_ast_parse("x = " + "-" * 7000 + "1\n")
    assert result is None or isinstance(result, ast.AST)


def test_parse_failure_exceptions_are_the_expected_set() -> None:
    assert set(PARSE_FAILURE_EXCEPTIONS) == {SyntaxError, ValueError, RecursionError, MemoryError}


# --- a leading byte-order mark (#1064) ----------------------------------------------------------
# `read()` decodes "utf-8", so a BOM survives into the text, and `ast.parse` rejects a str that
# starts with U+FEFF. Built with chr(): agentsec's own invisible-unicode guard reads this tree.
_BOM = chr(0xFEFF)


def test_safe_ast_parse_accepts_a_leading_bom_with_the_tree_cpython_compiles() -> None:
    # The structure and the line numbers are CPython's: it strips the BOM when it reads the file,
    # and a BOM is not a line break. Columns are pinned by the next test.
    src = "import os\nfoo(1)\n"
    tree = safe_ast_parse(_BOM + src, filename="bom.py")
    assert isinstance(tree, ast.Module)
    assert ast.dump(tree) == ast.dump(ast.parse(src))
    assert [getattr(n, "lineno", None) for n in ast.walk(tree)] == [
        getattr(n, "lineno", None) for n in ast.walk(ast.parse(src))
    ]


def test_a_bom_trees_positions_index_the_text_passed_in() -> None:
    """#1069 round 1, M1: every caller slices its OWN text, which still starts with the BOM, by the
    tree's positions (`ast.get_source_segment`, `strip_python_strings`, `tool_chaining_exfil`). A
    tree with CPython's BOM-free line-1 columns sliced that text 3 bytes early and cut segments
    short. Every node's segment must read the same as in the BOM-free file: single-line and
    multi-line nodes, starting on line 1 and below it."""
    src = 'x = foo(1, """a\nb""")\nimport os\ndef f(): return eval(y)\n'
    plain = ast.parse(src)
    tree = safe_ast_parse(_BOM + src, filename="bom.py")
    assert tree is not None
    pairs = list(zip(ast.walk(tree), ast.walk(plain), strict=True))
    segments = [(ast.get_source_segment(_BOM + src, a), ast.get_source_segment(src, b)) for a, b in pairs]
    assert any(want and want.startswith("x = foo(1") for _, want in segments)  # line 1 is covered
    assert [got for got, _ in segments] == [want for _, want in segments]


def test_strip_python_strings_blanks_a_line_one_string_in_a_bom_file() -> None:
    # #1069 round 1, H1: `_is_triple_quoted` read the BOM-bearing line at the BOM-free column, so a
    # line-1 docstring was never blanked and every text guard then read its prose as code. The
    # result must be the BOM-free one with the BOM kept in front: strings blanked, code kept.
    doc = '"""Docs: os.system(cmd) and eval(user).\n"""\nimport os\nos.getcwd()  # "a"\n'
    plain = strip_python_strings(doc, filename="a.py")
    assert "os.system" not in plain and "os.getcwd()" in plain  # anti-vacuity: it blanks, keeps code
    assert strip_python_strings(_BOM + doc, filename="a.py") == _BOM + plain


def test_a_bom_file_whose_line_one_docstring_names_a_sink_stays_silent(tmp_path: Path) -> None:
    """#1069 round 1, H1 end to end, the FP bait for #1064's widening. Measured on the round-1
    tip: this file raised command-injection and code-injection-eval-exec at a.py:1 with a BOM and
    nothing without one."""
    doc = '"""Docs: run subprocess.run(cmd, shell=True), os.system(cmd), eval(user).\n"""\nimport os\n'
    # The traded direction (rule 1): real code on line 1 of a BOM file must still be read as code.
    code = 'eval(user)  # "x"\nimport os\n'
    (tmp_path / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    rules = {}
    for label, text in (("doc", doc), ("bom-doc", _BOM + doc), ("code", code), ("bom-code", _BOM + code)):
        (tmp_path / "a.py").write_text(text, encoding="utf-8")
        result = audit(tmp_path, run_scanners=False)
        rules[label] = sorted(f.rule for f in result.findings if f.location.startswith("a.py"))
    assert rules["bom-doc"] == rules["doc"] == []
    assert rules["bom-code"] == rules["code"] == ["code-injection-eval-exec/dynamic-content"]


def test_safe_ast_parse_still_rejects_a_bom_anywhere_but_the_start() -> None:
    # The direction the strip traded against: only ONE leading BOM is a file-encoding artifact. A
    # second one, or one mid-file, is an invalid character to CPython too, so it stays a failure.
    assert safe_ast_parse("x = 1\n" + _BOM + "y = 2\n") is None
    assert safe_ast_parse(_BOM + _BOM + "x = 1\n") is None


def test_a_real_audit_analyses_a_bom_prefixed_file(tmp_path: Path) -> None:
    """#1064 end to end: an AST-only guard fires on a BOM-prefixed file through the real pipeline.

    Before the fix the parse failed, the guard skipped the file and the audit reported nothing.
    `ssrf-redirect-bypass` is used because it has no text fallback (`_walk_python` returns [] on a
    failed parse), so the finding can only come from the AST."""
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "fetcher.py").write_text(
        _BOM + "import requests\n\n"
        "def fetch_document(url):\n"
        "    if not validate_safe_url(url):\n"
        "        raise ValueError('unsafe url')\n"
        "    response = requests.get(url)\n"
        "    return response.text\n",
        encoding="utf-8",
    )
    result = audit(tmp_path, run_scanners=False)
    hits = [f for f in result.findings if f.rule == "ssrf-redirect-bypass/redirect-not-disabled"]
    assert [f.location for f in hits] == ["fetcher.py:6"]


# --- the parse-failure record (#1001) -----------------------------------------------------------
# The pipeline half (confirm, scope, render, the worker transport) is in
# tests/test_parse_failure_disclosure.py. These pin the record itself.
_PY2 = 'print "loaded"\n'


def test_a_failed_parse_is_recorded_inside_a_run() -> None:
    with parse_failure_run():
        assert safe_ast_parse(_PY2, filename="a.py") is None
        assert safe_ast_parse("x = 1\n", filename="b.py") is not None
        assert parse_failure_candidates() == ParseCandidates(frozenset({"a.py"}), truncated=False)


def test_nothing_is_recorded_outside_a_run() -> None:
    # A library caller outside an audit (the advisor's reachability pass) must leave no state behind.
    assert safe_ast_parse(_PY2, filename="a.py") is None
    with parse_failure_run():
        assert parse_failure_candidates().paths == frozenset()


def test_the_run_is_reentrant_and_cleared_on_exit() -> None:
    with parse_failure_run():
        safe_ast_parse(_PY2, filename="outer.py")
        with parse_failure_run():  # nested scopes share one record...
            safe_ast_parse(_PY2, filename="inner.py")
        # ...so leaving the inner scope keeps both
        assert parse_failure_candidates().paths == {"outer.py", "inner.py"}
    with parse_failure_run():  # and a new outermost scope starts empty
        assert parse_failure_candidates().paths == frozenset()


def test_an_unnamed_parse_is_never_recorded() -> None:
    with parse_failure_run():
        safe_ast_parse(_PY2)
        assert parse_failure_candidates().paths == frozenset()


def test_the_record_is_capped_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    # A hostile tree can hold any number of files; the cap must be disclosed, never silent.
    monkeypatch.setattr(astutil, "_MAX_CANDIDATES", 2)
    with parse_failure_run():
        for name in ("a.py", "b.py"):
            safe_ast_parse(_PY2, filename=name)
        assert parse_failure_candidates() == ParseCandidates(frozenset({"a.py", "b.py"}), truncated=False)
        safe_ast_parse(_PY2, filename="a.py")  # a repeat is not an overflow
        assert parse_failure_candidates().truncated is False
        safe_ast_parse(_PY2, filename="c.py")
        assert parse_failure_candidates() == ParseCandidates(frozenset({"a.py", "b.py"}), truncated=True)


def test_parse_candidates_union() -> None:
    a = ParseCandidates(frozenset({"a.py"}), truncated=False)
    b = ParseCandidates(frozenset({"b.py"}), truncated=True)
    assert a | b == ParseCandidates(frozenset({"a.py", "b.py"}), truncated=True)
    assert a | ParseCandidates() == a


def test_parse_failure_reason_names_the_line_and_the_parser_message() -> None:
    reason = parse_failure_reason("x = 1\n" + _PY2, filename="a.py")
    assert reason is not None
    assert reason.startswith("line 2: Missing parentheses in call to 'print'")


def test_parse_failure_reason_is_none_when_the_text_parses() -> None:
    assert parse_failure_reason("x = 1\n") is None
    assert parse_failure_reason(_BOM + "x = 1\n") is None  # the BOM strip applies here too (#1064)


def test_parse_failure_reason_covers_the_non_syntax_error_members() -> None:
    reason = parse_failure_reason("x = 1\x00\n")  # ValueError on some CPython versions
    assert reason is not None and reason


def test_parse_failure_reason_records_nothing() -> None:
    with parse_failure_run():
        assert parse_failure_reason(_PY2, filename="a.py") is not None
        assert parse_failure_candidates().paths == frozenset()


def test_no_direct_ast_parse_outside_the_helper() -> None:
    # Drift gate (#370): every ast.parse on target source must go through safe_ast_parse (which owns
    # the total-parse exception set), so a new call site can't silently reintroduce the crash class
    # that produced #367/#368/#369. Only the allow-listed files may call ast.parse directly.
    agentsec_dir = Path(__file__).resolve().parent.parent / "agentsec"
    offenders = []
    for py in agentsec_dir.rglob("*.py"):
        if py.name in _AST_PARSE_ALLOWLIST:
            continue
        # Grep the RAW source — deliberately no docstring-stripping. A docstring mention of
        # `ast.parse(` would be a harmless false POSITIVE (someone looks, adds an allow-list entry);
        # stripping via a regex (the #366 bug) could instead mis-pair a comment `"""` and blank a
        # REAL call, a false NEGATIVE — the dangerous failure mode for a safety gate.
        if _AST_PARSE_CALL.search(py.read_text(encoding="utf-8")):
            offenders.append(str(py.relative_to(agentsec_dir.parent)))
    assert not offenders, (
        "direct ast.parse() outside the safe_ast_parse helper (route through it or add to "
        "_AST_PARSE_ALLOWLIST with a reason):\n  " + "\n  ".join(offenders)
    )


# The three tests below trigger a compile-time warning with an invalid escape sequence, which
# CPython reports as a `SyntaxWarning` from 3.12 onward — this project's floor (`requires-python
# >=3.12`; CI pins 3.12 on every leg). Unlike the `PARSE_FAILURE_EXCEPTIONS` test above (which is
# version-independent by construction, cf. #320) these are version-DEPENDENT by necessity: only
# CPython can raise a compiler warning, so the trigger has to be real source. The escape-sequence
# warning is on CPython's path to becoming a hard `SyntaxError`; when that lands, these tests need
# a different trigger, not a different assertion.
def test_safe_ast_parse_stamps_filename_onto_syntax_warnings() -> None:
    """The point of the `filename` parameter: a compile-time `SyntaxWarning` names the file the
    source came from. Without it every such warning in an audit renders as `<unknown>:<line>`,
    which is unattributable across a whole scanned tree."""
    src = 'p = "\\w"\n'  # invalid escape in a non-raw string -> SyntaxWarning at compile time
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert safe_ast_parse(src, filename="pkg/target.py") is not None
    syntax = [w for w in caught if issubclass(w.category, SyntaxWarning)]
    assert syntax, "expected a SyntaxWarning for the invalid escape sequence"
    assert syntax[0].filename == "pkg/target.py"


def test_safe_ast_parse_accepts_a_path_for_filename() -> None:
    """Callers hold a `Path`, not a `str` — it must not need stringifying at every call site."""
    src = 'p = "\\w"\n'
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert safe_ast_parse(src, filename=Path("pkg") / "target.py") is not None
    syntax = [w for w in caught if issubclass(w.category, SyntaxWarning)]
    assert syntax and syntax[0].filename == str(Path("pkg") / "target.py")


def test_safe_ast_parse_filename_defaults_to_unknown() -> None:
    """The default is unchanged, so every existing call site keeps its current behaviour.

    Intentionally does NOT discriminate pre-/post-`filename`: `ast.parse` already defaulted to
    `<unknown>`, so this passes either way. It pins the DEFAULT, not the threading — the two tests
    above carry the proof that the parameter landed (they fail with `TypeError` against the old
    signature).

    No call site in `agentsec/` relies on this default any more (#779 threaded the last of them,
    and `test_every_safe_ast_parse_call_site_names_its_file` keeps it that way). The default stays
    because `safe_ast_parse` is a public helper with callers outside that gate — tests, and any
    future one — and silently changing what an omitted argument means is worse than keeping it.
    """
    src = 'p = "\\w"\n'
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        safe_ast_parse(src)
    syntax = [w for w in caught if issubclass(w.category, SyntaxWarning)]
    assert syntax and syntax[0].filename == "<unknown>"


def test_safe_ast_parse_filename_does_not_change_the_parse_result() -> None:
    """`filename` is diagnostic only: it must not affect what is returned, on either path."""
    good, bad = "x = 1\n", "def broken(:\n    pass\n"
    assert ast.dump(safe_ast_parse(good)) == ast.dump(  # type: ignore[arg-type]
        safe_ast_parse(good, filename="anything.py")     # type: ignore[arg-type]
    )
    assert safe_ast_parse(bad) is None
    assert safe_ast_parse(bad, filename="anything.py") is None


# --- end-to-end: does `filename` actually attribute a REAL audit's warnings? ---------------------
#
# Everything above pins `safe_ast_parse`'s contract in isolation. These two pin the thing the
# parameter EXISTS for, over the real `audit()` pipeline, and they point in opposite directions on
# purpose (CLAUDE.md "Changing a check", rule 1): one asserts the threaded call site really does
# name the file, the other asserts nothing is left unattributed. Isolated-helper tests cannot see
# the gap between those two, which is exactly the gap #775 shipped with.
#
# The fixture is one ordinary module carrying an invalid escape in a non-raw string, which CPython
# reports on every parse of that text. Self-contained on purpose: it does NOT rely on issue #776
# (`strip_python_strings` mis-lexing one real guard module), so fixing #776 cannot silently rot it.
# Cost is ~0.02s — a one-module repo, not a package-wide scan, so this needs no `slow` marker.
_WARNING_FIXTURE = '''import re
from fastapi import APIRouter

router = APIRouter()
TOKEN_RE = re.compile("\\w+")          # invalid escape in a NON-raw string

@router.get("/items")
def list_items(q: str) -> list[str]:
    return TOKEN_RE.findall(q)
'''


def _audit_fixture_syntax_warnings(tmp_path: Path) -> list[warnings.WarningMessage]:
    """Every `SyntaxWarning` raised while the real pipeline audits a one-module repo."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "api.py").write_text(_WARNING_FIXTURE, encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("fastapi\nopenai\n", encoding="utf-8")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        audit(tmp_path, run_scanners=False)
    return [w for w in caught if issubclass(w.category, SyntaxWarning)]


def test_a_real_audit_attributes_warnings_from_the_threaded_call_site(tmp_path: Path) -> None:
    """The direction #775 DID deliver: a threaded call site names the file the source came from.

    Doubles as the anti-vacuity guard for the xfail below. If this fixture ever stops emitting a
    compile warning at all, the xfail would start passing for the wrong reason and read as a fixed
    bug; this test fails loudly first.
    """
    caught = _audit_fixture_syntax_warnings(tmp_path)
    assert caught, "fixture no longer triggers a compile-time SyntaxWarning — it has rotted"
    assert [w for w in caught if w.filename.endswith("api.py")], (
        "no warning names the fixture file: the threaded call site (reachability.py::_imports) "
        "stopped passing `filename=`"
    )


def test_a_real_audit_emits_no_unattributed_syntax_warnings(tmp_path: Path) -> None:
    """The claim `filename` exists to make true: no warning from an audit is unattributable.

    `<unknown>:<line>` names no file across the whole scanned tree, and its line number indexes
    whatever derived text was handed to the parser rather than the file on disk — so it is not
    merely terse, it points somewhere that does not exist.
    """
    stray = [w for w in _audit_fixture_syntax_warnings(tmp_path) if w.filename == "<unknown>"]
    assert not stray, (
        f"{len(stray)} unattributed SyntaxWarning(s) at derived-text lines "
        f"{sorted({w.lineno for w in stray})} — see #779"
    )


# --- the ratchet that replaces the #779 xfail ---------------------------------------------------
#
# The test above is an END-TO-END claim over ONE fixture, so it only sees the call sites that
# fixture happens to reach. That is exactly how #779 was scoped short in the first place: the
# original measurement ran over a self-audit, saw four derived-text call sites, and missed the
# raw-text ones because agentsec's own source did not trigger them. A new guard added tomorrow with
# a bare `safe_ast_parse(text)` reopens the gap one call site at a time, and the fixture above would
# very likely keep passing. This gate is structural instead of behavioral, so it cannot be dodged by
# a fixture that does not happen to reach the new site.


def _safe_ast_parse_names(tree: ast.AST) -> set[str]:
    """Every name bound to `safe_ast_parse` in one module, following aliases.

    Matching the literal spelling `safe_ast_parse(` is NOT enough, and the difference is not
    theoretical: `from agentsec.astutil import safe_ast_parse as sap` then `sap(text)` reads as a
    call to `sap`, so a name-only gate walks straight past it. Verified by planting exactly that
    module during the #851 review — the gate passed. A gate whose own bypass is one `as` clause
    away is worth 10 lines more than it is worth the footnote explaining the hole.

    Resolution is per-module and binding-directed, so it cannot over-fire: a module with its own
    unrelated `sap` never enters this set, because nothing bound that name FROM `safe_ast_parse`.
    """
    names = {"safe_ast_parse"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(a.asname or a.name for a in node.names if a.name == "safe_ast_parse")
        # A local rebinding: `sap = safe_ast_parse` (no call — that is an alias, not a result).
        elif (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Name)
            and node.value.id in names
        ):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


def test_every_safe_ast_parse_call_site_names_its_file() -> None:
    """Every `safe_ast_parse` call in `agentsec/` passes a `filename` (keyword, or positionally).

    AST-based, not a regex: the question "does this CALL pass filename?" is structural, and a
    `filename=` mentioned in a neighbouring docstring or comment must not count as passing it.
    Alias-aware via `_safe_ast_parse_names` — see it for why the literal spelling is not enough.
    """
    agentsec_dir = Path(__file__).resolve().parent.parent / "agentsec"
    offenders: list[str] = []
    for py in sorted(agentsec_dir.rglob("*.py")):
        if py.name == "astutil.py":  # the definition itself, plus its own default
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"))
        bound = _safe_ast_parse_names(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            # A bound local name (`sap(...)`) or an attribute call (`astutil.safe_ast_parse(...)`).
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
            if name not in bound:
                continue
            # `filename` is the 2nd positional parameter, so either spelling attributes the parse.
            if any(k.arg == "filename" for k in node.keywords) or len(node.args) >= 2:
                continue
            offenders.append(f"{py.relative_to(agentsec_dir.parent)}:{node.lineno}")
    assert not offenders, (
        "safe_ast_parse call site(s) with no filename — every warning they emit renders as "
        "`<unknown>:<line>`, which names no file in the scanned tree (#779). Pass the path the "
        "text came from, threading it through the enclosing helper if needed:\n  "
        + "\n  ".join(offenders)
    )


def test_the_call_site_gate_resolves_aliases_and_does_not_over_fire() -> None:
    """Both directions on `_safe_ast_parse_names`, the widening the gate above just took.

    Widening direction: an aliased import must be resolved, or the gate is one `as` clause from
    being bypassed. FP-bait direction: an unrelated name that merely LOOKS like an alias must not
    be picked up, or the gate starts failing on ordinary modules that never touch the helper.
    """
    aliased = ast.parse(
        "from agentsec.astutil import safe_ast_parse as sap\n"
        "second = sap\n"
    )
    assert _safe_ast_parse_names(aliased) == {"safe_ast_parse", "sap", "second"}

    unrelated = ast.parse(
        "from somewhere.else_ import parse_tree as sap\n"   # same alias, different function
        "from agentsec.astutil import PARSE_FAILURE_EXCEPTIONS\n"
        "def sap2(text): return None\n"
    )
    assert _safe_ast_parse_names(unrelated) == {"safe_ast_parse"}


# --- the direction the sweep traded against (CLAUDE.md "Changing a check", rule 1) ---------------
#
# Threading `filename` grew the signature of helpers that are called tens of thousands of times per
# audit and are memoised on `text`. The risk is not that attribution stops working; it is that the
# parameter silently changes a RESULT or collapses the cache. Both are asserted here, because
# neither would show up as a failing attribution test.


def test_attribution_names_the_file_the_source_actually_came_from(tmp_path: Path) -> None:
    """The FP-bait direction: a warning must never name a file that did not produce it.

    "No warning says `<unknown>`" is satisfiable by naming the wrong path — and a wrong path is
    worse than `<unknown>`, because it reads as a real answer and sends the reader to a file with
    nothing wrong in it. The sweep threads `filename` through helpers whose caller holds several
    paths at once (`for f, text in files`, the cross-file router resolvers), which is exactly where
    a mixed-up pairing would land. Two sibling modules, only one of which can warn.
    """
    (tmp_path / "app").mkdir()
    # NAMES ARE LOAD-BEARING: the warning-producing file must sort LAST. Several call sites hold a
    # whole `list[tuple[Path, str]]` and pick one path out of it, so a mis-pairing that always
    # reaches for `files[0]` lands on the FIRST file. With the noisy file first, that bug names the
    # right path by accident and this test passes while broken — verified by mutation, which is the
    # only reason the ordering is spelled out rather than left to chance.
    (tmp_path / "app" / "zz_noisy.py").write_text(_WARNING_FIXTURE, encoding="utf-8")
    # Same shape, same imports, same router wiring — but a RAW string, so it cannot warn.
    (tmp_path / "app" / "aa_quiet.py").write_text(
        _WARNING_FIXTURE.replace('re.compile("\\w+")', 're.compile(r"\\w+")'), encoding="utf-8"
    )
    (tmp_path / "requirements.txt").write_text("fastapi\nopenai\n", encoding="utf-8")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        audit(tmp_path, run_scanners=False)
    syntax = [w for w in caught if issubclass(w.category, SyntaxWarning)]
    assert syntax, "fixture no longer warns — the assertion below would hold vacuously"
    misattributed = [w for w in syntax if Path(w.filename).name != "zz_noisy.py"]
    assert not misattributed, (
        "warning(s) attributed to a file that cannot produce one: "
        f"{sorted({w.filename for w in misattributed})} — only app/zz_noisy.py has an invalid escape"
    )


def test_filename_does_not_change_what_the_derived_text_helpers_return() -> None:
    """`filename` is diagnostic: same text in, same value out, whatever path is named."""
    src = (
        'import re\n'
        'TOKEN = re.compile("\\w+")\n'
        'def handler(q: str) -> list[str]:\n'
        '    """A docstring with a `def fake():` inside it."""\n'
        '    return TOKEN.findall(q)\n'
    )
    with warnings.catch_warnings():  # the invalid escape is the point elsewhere, not here
        warnings.simplefilter("ignore", SyntaxWarning)
        assert strip_python_strings(src) == strip_python_strings(src, filename="a/b.py")
        assert iter_functions(src) == iter_functions(src, filename="a/b.py")
        assert enclosing_function(src, 5) == enclosing_function(src, 5, filename="a/b.py")


def test_filename_is_not_part_of_the_derived_state_cache_key() -> None:
    """The memo stays keyed on `text` alone (#544's 2.21x), so `filename` cannot halve the hit rate.

    Asserted through observable behaviour rather than by reaching into the cache dict: inside a
    `derived_state_run()` scope, a second call with the SAME text but a different path must be
    served from the cache, which is visible as the parser never running again — no second warning.
    """
    src = 'PATTERN = "\\w+"\n'  # invalid escape: every real parse of this text warns
    with derived_state_run():
        with warnings.catch_warnings(record=True) as first:
            warnings.simplefilter("always")
            strip_python_strings(src, filename="one.py")
        with warnings.catch_warnings(record=True) as second:
            warnings.simplefilter("always")
            strip_python_strings(src, filename="two.py")
    assert [w for w in first if issubclass(w.category, SyntaxWarning)], (
        "the fixture no longer warns on first parse — this test can no longer tell a cache hit "
        "from a miss, so it would pass vacuously"
    )
    assert not [w for w in second if issubclass(w.category, SyntaxWarning)], (
        "a second call with the same text but a different filename re-parsed: `filename` has "
        "entered the cache key and the #544 memo is now a per-path cache"
    )
