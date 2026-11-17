"""Drift gate: every text read/write in ``agentsec/``, ``scripts/`` and ``tests/`` passes an encoding (#518).

CLAUDE.md requires an explicit ``encoding=`` on every text read and write, because Windows defaults
to cp1252. Nothing enforced that sentence, and review did not hold it: by 2026-10 the tests carried
854 bare ``read_text()``/``write_text()`` calls, 739 of them added after the rule was written down.

A bare read fails on Windows in one of two ways. A byte cp1252 does not map (0x81, 0x8D, 0x8F, 0x90,
0x9D) raises ``UnicodeDecodeError``, and the Windows CI leg catches that (#478). But every byte of an
em dash, arrow or ellipsis IS mapped, so the read succeeds and returns mojibake, and the test then
asserts against corrupted text while staying green. Three tests did exactly that, two of them
security checks (the Guard Sandbox Contract over ``agentsec/walk.py``, and the sanitization denylist
over the CI component library). A green Windows leg is not evidence a file was read correctly; this
gate is, because it fails on BOTH legs before the call is ever executed.

WHAT IT FLAGS. A call with no ``encoding`` keyword, no positional reaching the encoding slot, and no
``*``/``**`` splat, when it is one of:

  * ``<x>.read_text()`` -- its first positional IS ``encoding``;
  * ``<x>.write_text(data)`` -- its second positional is;
  * builtin ``open(...)`` or ``io.open(...)`` in text mode (encoding is the 4th positional);
  * ``<x>.open(...)`` (``Path.open``) in text mode (encoding is the 3rd positional), unless the
    receiver is a module whose ``open`` is not a text file (``_NON_FILE_OPEN_RECEIVERS``);
  * ``tempfile.NamedTemporaryFile``/``TemporaryFile``/``SpooledTemporaryFile`` in text mode. Their
    default mode is binary, so only an explicit text mode is flagged.

"Text mode" is a missing mode argument (except for ``tempfile``) or a string literal of only
``rwxat+``. A mode holding ``b``, or one that is not a literal (``zf.open(name)``), is skipped.

WHY AN AST GATE, NOT RUFF. Ruff's ``PLW1514`` is preview-only and resolves the receiver's type, so it
saw 9 of the 855 sites: it misses ``tmp_path / "x"``, unannotated parameters and ``io.open``. Telling
a repo-file read from a ``tmp_path`` read needs dataflow the AST does not carry, so the gate covers
every call, as the rule is written.

KNOWN FALSE NEGATIVES, accepted: ``gzip``/``bz2``/``lzma.open(p, "rt")``, ``os.fdopen``,
``io.TextIOWrapper``, ``codecs.open``, aliased imports (``from tempfile import NamedTemporaryFile``),
and ``subprocess(..., text=True)``, which decodes child output and needs per-site judgement. None has
a bare text-mode use in the scanned population except the subprocess calls, which are out of scope.

``tests/fixtures/`` is not scanned: it holds intentionally vulnerable sample code (see CLAUDE.md).

WHY ASSERT THE ARTIFACT. The gate asserts the offender LIST is empty (Rule 3), and a floor proves the
walk still sees the population it claims to, as ``test_no_vacuous_tests.py`` does for its own gate.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from agentsec.astutil import safe_ast_parse

_REPO = Path(__file__).resolve().parents[1]
_SCANNED_ROOTS = ("agentsec", "scripts", "tests")
_FIXTURES = _REPO / "tests" / "fixtures"

# A mode string that opens a text stream: no `b`, and nothing that is not a mode letter (tarfile's
# "r:gz", or the member name in `zf.open("n")`, fails this and is skipped).
_TEXT_MODE = re.compile(r"[rwxat+]*")
# Modules whose `.open(...)` is not a text file the encoding rule governs, or (for `io`) is matched by
# its own branch with builtin `open`'s signature.
_NON_FILE_OPEN_RECEIVERS = frozenset(
    {"webbrowser", "tarfile", "zipfile", "os", "io", "gzip", "bz2", "lzma", "shelve", "dbm"}
)
# constructor -> (positional index of `mode`, positional index of `encoding`)
_TEMPFILE_CTORS = {
    "NamedTemporaryFile": (0, 2),
    "TemporaryFile": (0, 2),
    "SpooledTemporaryFile": (1, 3),
}


def _scanned_files() -> list[Path]:
    """Every ``*.py`` under the scanned roots, minus ``tests/fixtures/`` -- the single population BOTH
    the gate and the floor below draw from, so a regression in discovery trips the floor too."""
    out: list[Path] = []
    for root in _SCANNED_ROOTS:
        out.extend(p for p in (_REPO / root).rglob("*.py") if _FIXTURES not in p.parents)
    return sorted(out)


def _mode_arg(call: ast.Call, index: int) -> ast.expr | None:
    """The call's ``mode`` argument, positional at ``index`` or by keyword; ``None`` when absent."""
    if len(call.args) > index:
        return call.args[index]
    return next((kw.value for kw in call.keywords if kw.arg == "mode"), None)


def _is_text_mode(mode: ast.expr | None, *, default_text: bool) -> bool:
    if mode is None:
        return default_text
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return _TEXT_MODE.fullmatch(mode.value) is not None
    return False  # a non-literal mode cannot be judged; skip rather than guess


def _text_io_form(call: ast.Call) -> tuple[str, int] | None:
    """``(label, positional index of encoding)`` when ``call`` is a text-mode file call, else ``None``.

    This classifies the call's SHAPE only; whether it passes an encoding is ``_passes_encoding``'s job.
    """
    func = call.func
    if isinstance(func, ast.Name):
        if func.id == "open" and _is_text_mode(_mode_arg(call, 1), default_text=True):
            return "open()", 3
        return None
    if not isinstance(func, ast.Attribute):
        return None
    receiver = func.value.id if isinstance(func.value, ast.Name) else None
    if func.attr == "read_text":
        return ".read_text()", 0
    if func.attr == "write_text":
        return ".write_text()", 1
    if func.attr == "open":
        if receiver == "io":
            return ("io.open()", 3) if _is_text_mode(_mode_arg(call, 1), default_text=True) else None
        if receiver in _NON_FILE_OPEN_RECEIVERS:
            return None
        return (".open()", 2) if _is_text_mode(_mode_arg(call, 0), default_text=True) else None
    if receiver == "tempfile" and func.attr in _TEMPFILE_CTORS:
        mode_index, encoding_index = _TEMPFILE_CTORS[func.attr]
        if _is_text_mode(_mode_arg(call, mode_index), default_text=False):
            return f"tempfile.{func.attr}()", encoding_index
    return None


def _passes_encoding(call: ast.Call, encoding_index: int) -> bool:
    """True when the call names an encoding, or splats arguments the AST cannot see into."""
    if len(call.args) > encoding_index or any(isinstance(a, ast.Starred) for a in call.args):
        return True
    return any(kw.arg in (None, "encoding") for kw in call.keywords)  # `arg is None` is a `**` splat


def _bare_text_io_in_source(src: str, filename: str) -> list[tuple[int, str]]:
    """Every bare text I/O call in one source string, as ``(lineno, label)``."""
    tree = safe_ast_parse(src, filename)
    if tree is None:  # a file that will not parse is its own loud failure, never a silent skip
        return [(0, f"<unparseable: {filename}>")]
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        form = _text_io_form(node)
        if form is not None and not _passes_encoding(node, form[1]):
            out.append((node.lineno, form[0]))
    return sorted(out)


def _bare_text_io_calls() -> list[tuple[str, int, str]]:
    """Every bare text I/O call across the population, as ``(relpath, lineno, label)``."""
    out: list[tuple[str, int, str]] = []
    for path in _scanned_files():
        rel = path.relative_to(_REPO).as_posix()
        for lineno, label in _bare_text_io_in_source(path.read_text(encoding="utf-8"), rel):
            out.append((rel, lineno, label))
    return out


def test_no_bare_text_io() -> None:
    """The gate. A text read or write with no encoding fails here on both CI legs, before review."""
    offenders = _bare_text_io_calls()
    assert not offenders, (
        "text I/O with no explicit encoding -- Windows decodes it as cp1252 and can return mojibake "
        "while the test stays green (#518). Pass encoding='utf-8':\n"
        + "\n".join(f"  {rel}:{lineno} {label}" for rel, lineno, label in offenders)
    )


def test_the_gate_sees_the_population_it_claims_to() -> None:
    """A walk that silently stopped finding files or calls would pass the gate above forever.

    Counts over the SAME ``_scanned_files()`` and ``_text_io_form`` the gate uses. The floors sit well
    below the live counts, so ordinary growth or pruning never trips them, but a discovery or detector
    that has gone blind fails loudly instead of reporting clean.
    """
    files = _scanned_files()
    rels = {p.relative_to(_REPO).as_posix() for p in files}
    calls = 0
    for path in files:
        tree = safe_ast_parse(path.read_text(encoding="utf-8"), path.name)
        if tree is None:  # unparseable: the gate lists it as an offender; it adds 0 calls here
            continue
        calls += sum(isinstance(n, ast.Call) and _text_io_form(n) is not None for n in ast.walk(tree))
    assert len(files) >= 900, f"only {len(files)} files walked -- has the gate gone blind?"
    assert calls >= 5000, f"only {calls} text I/O calls seen -- has the detector gone blind?"
    # One known file per scanned root, the nested one proving the walk recurses.
    assert {"agentsec/walk.py", "scripts/validate-checklist.py", "tests/guards/test_cors_wildcard.py"} <= rels
    # The exclusion is real: fixtures hold .py files, and none of them is scanned.
    assert any(_FIXTURES.rglob("*.py")), "tests/fixtures/ holds no .py files -- the exclusion is untested"
    assert not any(r.startswith("tests/fixtures/") for r in rels)


# The detector's own behaviour, exercised through the SAME `_bare_text_io_in_source` the gate uses, so
# a detector that stopped working cannot pass here while the gate above reports clean.
@pytest.mark.parametrize(
    "src",
    [
        "p.read_text()",
        "p.read_text(errors='ignore')",  # an error handler is not an encoding
        "(tmp_path / 'x').write_text('data')",
        "p.write_text(data, newline='')",
        "open(p)",
        "open(p, 'w')",
        "open(p, mode='a+')",
        "open(p, 'r', -1)",  # three positionals stop short of the encoding slot
        "io.open(p)",
        "p.open()",
        "p.open('w')",
        "p.open(mode='rt')",
        "tempfile.NamedTemporaryFile('w', suffix='.json')",
        "tempfile.TemporaryFile(mode='w+')",
        "tempfile.SpooledTemporaryFile(10, 'w+')",
        "with open(p) as fh:\n    pass",
    ],
)
def test_detector_flags_a_bare_text_call(src: str) -> None:
    assert _bare_text_io_in_source(src, "<inline>")


@pytest.mark.parametrize(
    "src",
    [
        "p.read_text('utf-8')",  # the first positional IS encoding
        "p.read_text(encoding='utf-8', errors='ignore')",
        "p.write_text(s, 'utf-8')",
        "p.write_text(s, encoding='utf-8', newline='')",
        "open(p, 'w', -1, 'utf-8')",
        "open(p, encoding='utf-8')",
        "open(p, 'rb')",
        "open(p, mode='wb')",
        "io.open(p, 'rb')",
        "p.open('rb')",
        "p.open('r', -1, 'utf-8')",
        "webbrowser.open(url)",
        "tarfile.open(p, mode='r:gz')",
        "zipfile.ZipFile(p).open('n')",  # a member name, not a mode letter run
        "zf.open(name)",  # a non-literal mode cannot be judged
        "os.open(p, os.O_RDONLY)",
        "gzip.open(p)",
        "tempfile.NamedTemporaryFile()",  # binary by default
        "tempfile.NamedTemporaryFile(suffix='.json', delete=False)",
        "tempfile.TemporaryFile('w+', encoding='utf-8')",
        "p.read_text(**kw)",
        "p.write_text(*args)",
        "open(p, mode)",
    ],
)
def test_detector_stays_silent_on_a_benign_neighbour(src: str) -> None:
    assert _bare_text_io_in_source(src, "<inline>") == []


def test_unparseable_file_is_surfaced_not_skipped() -> None:
    """A file that will not parse must fail loudly, never be silently dropped (Rule 3)."""
    found = _bare_text_io_in_source("p.read_text(\n", "broken.py")
    assert found and "unparseable" in found[0][1]
