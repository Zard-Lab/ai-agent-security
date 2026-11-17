"""A Python file the checks could not parse is disclosed, never silent (#1001).

`safe_ast_parse` returns None on a file that does not parse (Python 2, syntax newer than this
interpreter, a template, a truncated file), and the AST-based checks skip it or fall back to a
text scan. Before #1001 nothing reported that, so a skipped file read exactly like a clean one: a
planted HIGH ssrf-redirect-bypass in a file with one Python 2 line vanished, exit 0, no trace.

These tests pin the whole channel: the record in astutil, the guard worker's pipe, the whole-file
confirm, the user's scope, and the renderers (`coverage_notices()` for SARIF, the markdown footer,
the triage header). The record itself is pinned in tests/test_astutil.py.
"""
from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest

# `agentsec.cli` is imported at module level on purpose: it binds `audit` once, at import.
# Imported lazily, it can be first loaded while another test (triage's) has
# `agentsec.audit.audit` monkeypatched, and keep that fake for the rest of the worker's session.
import agentsec.audit as audit_mod
from agentsec.astutil import ParseCandidates, safe_ast_parse
from agentsec.audit import AuditResult, audit
from agentsec.cli import _meta_lines, main
from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.guards.base import Guard, iter_files, read
from agentsec.guards.ssrf_redirect_bypass import SsrfRedirectBypassGuard
from agentsec.triage_cli import source_lines

_PY2 = 'print "loaded"\n'
# An AST-only planted violation: ssrf-redirect-bypass has no text fallback, so a file that does
# not parse loses the finding entirely. That is the shape #1001 reproduced.
_FIRING = (
    "import requests\n\n"
    "def fetch_document(url):\n"
    "    if not validate_safe_url(url):\n"
    "        raise ValueError('unsafe url')\n"
    "    response = requests.get(url)\n"
    "    return response.text\n"
)
_RULE = "ssrf-redirect-bypass/redirect-not-disabled"


class FragmentParsingGuard(Guard):
    """Parses an indented FRAGMENT of every file, the way truthy-ownership-check parses a method's
    block on its own (#1065). The fragment fails while the file parses, so this records a
    candidate for every file. Module-level so a spawned worker child could import it."""

    id = "test-fragment-parser"
    title = "test: parses an indented fragment of each file"

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        for f in iter_files(root, (".py",)):
            safe_ast_parse("    " + read(f), filename=f)
        return []


def _repo(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _only(monkeypatch: pytest.MonkeyPatch, *guards: Guard) -> None:
    # Selection happens in this process; a budgeted run pickles these instances to the child.
    monkeypatch.setattr("agentsec.audit.select_guards", lambda profile: list(guards))


def _result(**kw: object) -> AuditResult:
    return AuditResult(profile=StackProfile(root=Path(".")), findings=[], ran=[], skipped=[], **kw)


# --- the pipeline -------------------------------------------------------------------------------

@pytest.mark.parametrize("budget", [None, 60.0], ids=["in-process", "budgeted-worker"])
def test_an_unparseable_file_is_disclosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, budget: float | None
) -> None:
    """Both guard paths. The budgeted one is the CLI default and runs the guards in a spawned
    child, so a record kept only in this process passes the in-process case and discloses
    nothing on the CLI."""
    _repo(tmp_path, {"legacy.py": _FIRING + _PY2, "app.py": _FIRING})
    _only(monkeypatch, SsrfRedirectBypassGuard())
    r = audit(tmp_path, run_scanners=False, guard_budget=budget)
    # The disclosure only adds a notice: the parseable sibling still fires.
    assert [f.location for f in r.findings if f.rule == _RULE] == ["app.py:6"]
    assert [path for path, _ in r.unparsed_python] == ["legacy.py"]
    assert r.unparsed_python[0][1].startswith("line 8: Missing parentheses in call to 'print'")
    assert r.unparsed_python_truncated is False
    assert any("could not be parsed" in n and "legacy.py" in n for n in r.coverage_notices())


def test_a_fragment_that_fails_on_its_own_is_not_disclosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FP bait for the widening. Measured on agentsec's own tree: 500 candidate files, every one
    a fragment failure, none a file that does not parse. The whole-file confirm must drop them."""
    _repo(tmp_path, {"repo.py": "class DocRepo:\n    def get(self, user_id):\n        return user_id\n"})
    _only(monkeypatch, FragmentParsingGuard())
    seen: list[ParseCandidates] = []
    real = audit_mod._confirm_unparsed

    def spy(root: Path, candidates: ParseCandidates) -> list[tuple[str, str]]:
        seen.append(candidates)
        return real(root, candidates)

    monkeypatch.setattr("agentsec.audit._confirm_unparsed", spy)
    r = audit(tmp_path, run_scanners=False)
    # Anti-vacuity: the fragment failure really was recorded, and then dropped.
    assert [Path(p).name for p in seen[0].paths] == ["repo.py"]
    assert r.unparsed_python == []
    assert r.coverage_notices() == []


def test_one_file_named_two_ways_is_disclosed_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Guards name a file by its absolute path or by `rel()`'s repo-relative one. Both spellings
    # reach the record; the notice must still list the file once (seen on the #1001 repro).
    _repo(tmp_path, {"legacy.py": _FIRING + _PY2})
    _only(monkeypatch, SsrfRedirectBypassGuard())
    monkeypatch.setattr(
        "agentsec.audit.parse_failure_candidates",
        lambda: ParseCandidates(frozenset({"legacy.py", str(tmp_path / "legacy.py")})),
    )
    r = audit(tmp_path, run_scanners=False)
    assert [path for path, _ in r.unparsed_python] == ["legacy.py"]


def test_a_path_the_user_excluded_is_left_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Decided on #1001: an excluded path is out of the report, so it is out of the notice. The
    # traded direction is in the same run: a file that is NOT excluded is still disclosed.
    _repo(tmp_path, {"vendor/old.py": _FIRING + _PY2, "legacy.py": _FIRING + _PY2})
    _only(monkeypatch, SsrfRedirectBypassGuard())
    r = audit(tmp_path, run_scanners=False, excludes=["vendor"])
    assert [path for path, _ in r.unparsed_python] == ["legacy.py"]


def test_a_syntax_warning_promoted_to_an_error_is_disclosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#781: `-W error::SyntaxWarning` turns an ordinary invalid escape into a parse failure. The
    notice names the promoted warning, so a reader can tell that apart from a broken file."""
    # The escape is built with chr(): no backslash passes through the editing tools.
    _repo(tmp_path, {"api.py": _FIRING + 'TOKEN = "' + chr(92) + 'd+"\n'})
    _only(monkeypatch, SsrfRedirectBypassGuard())
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        assert audit(tmp_path, run_scanners=False).unparsed_python == []  # parses, with a warning
    with warnings.catch_warnings():
        warnings.simplefilter("error", SyntaxWarning)
        r = audit(tmp_path, run_scanners=False)
    assert [path for path, _ in r.unparsed_python] == ["api.py"]
    assert "invalid escape sequence" in r.unparsed_python[0][1]


def test_a_parseable_repo_carries_no_notice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _repo(tmp_path, {"app.py": _FIRING})
    _only(monkeypatch, SsrfRedirectBypassGuard())
    r = audit(tmp_path, run_scanners=False)
    assert r.unparsed_python == [] and r.unparsed_python_truncated is False
    assert r.unparsed_python_notice() is None
    assert r.coverage_notices() == []


# --- the renderers ------------------------------------------------------------------------------

def test_the_notice_names_five_files_and_counts_the_rest() -> None:
    r = _result(unparsed_python=[(f"m{i}.py", "line 1: invalid syntax") for i in range(7)])
    notice = r.unparsed_python_notice()
    assert notice is not None
    label, detail = notice
    assert "could not be parsed by Python 3." in label
    assert detail.startswith("7 file(s): m0.py (line 1: invalid syntax), m1.py")
    assert "m4.py" in detail and "m5.py" not in detail
    assert detail.endswith("; +2 more")


def test_a_capped_record_is_disclosed_even_with_nothing_confirmed() -> None:
    # The cap is a Rule-3 trap of its own: a capped record must say so, not read as complete.
    notice = _result(unparsed_python_truncated=True).unparsed_python_notice()
    assert notice is not None and "hit its cap" in notice[1]


def test_the_markdown_footer_carries_the_notice() -> None:
    r = _result(unparsed_python=[("legacy.py", "line 8: invalid syntax")])
    footer = "\n".join(_meta_lines(r, []))
    assert "_⚠ Python files that could not be parsed by Python 3." in footer
    assert "legacy.py (line 8: invalid syntax)" in footer


def test_the_triage_header_carries_the_notice() -> None:
    r = _result(unparsed_python=[("legacy.py", "line 8: invalid syntax")])
    lines = source_lines(r, scanners_ran=False)
    assert any(
        ln.startswith("  python files that could not be parsed") and "legacy.py" in ln for ln in lines
    )


def test_audit_cli_sarif_carries_the_notice_and_the_gate_stays_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The documented CI path, end to end through the CLI (budgeted worker by default). Decided
    on #1001: a notice, not a gate failure, so a lone unparseable file exits 0 without --no-fail."""
    _repo(tmp_path, {"legacy.py": _FIRING + _PY2})
    _only(monkeypatch, SsrfRedirectBypassGuard())
    monkeypatch.setattr("agentsec.audit.select_runners", lambda profile: [])
    out = tmp_path / "report.sarif"
    assert main(["audit", str(tmp_path), "--format", "sarif", "--out", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    texts = [n["message"]["text"] for n in data["runs"][0]["invocations"][0]["toolExecutionNotifications"]]
    assert any("could not be parsed" in t and "legacy.py" in t for t in texts)
