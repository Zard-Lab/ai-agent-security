"""Tests for `agentsec fix` — the deterministic, diff-first auto-fixer.

Each fixer applies the safe transformation, is idempotent, and only touches
drop-in-safe forms; dry-run writes nothing; non-allowlisted findings are
report-only and their files are left untouched.
"""
from __future__ import annotations

from pathlib import Path

from agentsec.fix import FIXERS, fix


def _write(root: Path, name: str, text: str) -> Path:
    p = root / name
    p.write_text(text, encoding="utf-8")
    return p


def test_fix_xxe_import_aliased(tmp_path: Path) -> None:
    f = _write(tmp_path, "x.py", "import xml.etree.ElementTree as ET\nET.fromstring('<a/>')\n")
    result = fix(tmp_path, write=True)
    assert "import defusedxml.ElementTree as ET" in f.read_text(encoding="utf-8")
    assert any(a.status == "fixed" and a.rule == "xxe-safe/unsafe-xml-import" for a in result.actions)
    # re-audit confirms the rule cleared
    assert "xxe-safe/unsafe-xml-import" not in {x.rule for x in result.remaining}


def test_fix_xxe_from_import(tmp_path: Path) -> None:
    f = _write(tmp_path, "x.py", "from xml.etree.ElementTree import fromstring\nfromstring('<a/>')\n")
    fix(tmp_path, write=True)
    assert "from defusedxml.ElementTree import fromstring" in f.read_text(encoding="utf-8")


def test_fix_xxe_bare_import_is_report_only(tmp_path: Path) -> None:
    # bare `import xml.etree.ElementTree` (no alias) is NOT drop-in → must not be rewritten
    src = "import xml.etree.ElementTree\nxml.etree.ElementTree.fromstring('<a/>')\n"
    f = _write(tmp_path, "x.py", src)
    result = fix(tmp_path, write=True)
    assert f.read_text(encoding="utf-8") == src  # untouched
    assert any(a.status == "skipped" and a.rule == "xxe-safe/unsafe-xml-import" for a in result.actions)


def test_fix_api_docs_empty_ctor(tmp_path: Path) -> None:
    f = _write(tmp_path, "app.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    fix(tmp_path, write=True)
    assert "FastAPI(docs_url=None, redoc_url=None)" in f.read_text(encoding="utf-8")


def test_fix_api_docs_with_existing_args(tmp_path: Path) -> None:
    f = _write(tmp_path, "app.py", "from fastapi import FastAPI\napp = FastAPI(title='x')\n")
    fix(tmp_path, write=True)
    assert "FastAPI(docs_url=None, redoc_url=None, title='x')" in f.read_text(encoding="utf-8")


def test_fix_debug_default_off_simple(tmp_path: Path) -> None:
    f = _write(tmp_path, "config.py", "DEBUG = True\n")
    result = fix(tmp_path, write=True)
    assert f.read_text(encoding="utf-8") == "DEBUG = False\n"
    assert any(a.status == "fixed" and a.rule == "debug-default-off/debug-enabled" for a in result.actions)
    assert "debug-default-off/debug-enabled" not in {x.rule for x in result.remaining}


def test_fix_debug_default_off_preserves_annotation_and_trailing_content(tmp_path: Path) -> None:
    f = _write(tmp_path, "settings.py", "class Settings:\n    DEBUG: bool = True  # dev only\n")
    fix(tmp_path, write=True)
    assert "DEBUG: bool = False  # dev only" in f.read_text(encoding="utf-8")


def test_fix_debug_default_off_kwarg_form(tmp_path: Path) -> None:
    # Both fixers legitimately apply to this line (no docs_url either) — assert the debug
    # flip specifically, not the whole line, since api-docs-exposed's own insertion also fires.
    f = _write(
        tmp_path, "app.py",
        "from fastapi import FastAPI\napp = FastAPI(debug=True, title='x')\n",
    )
    fix(tmp_path, write=True)
    assert "debug=False, title='x'" in f.read_text(encoding="utf-8")


def test_fix_debug_default_off_pragma_is_report_only(tmp_path: Path) -> None:
    # Direction traded against (CLAUDE.md rule 1): the guard's own suppress pragma must still
    # be honored — a pragma'd line never reaches the fixer as a finding at all.
    src = "DEBUG = True  # security: allow-debug-true\n"
    f = _write(tmp_path, "config.py", src)
    fix(tmp_path, write=True)
    assert f.read_text(encoding="utf-8") == src  # untouched


def test_fix_idempotent(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _write(tmp_path, "x.py", "import xml.etree.ElementTree as ET\nET.fromstring('<a/>')\n")
    _write(tmp_path, "config.py", "DEBUG = True\n")
    fix(tmp_path, write=True)
    again = fix(tmp_path, write=True)
    assert not [a for a in again.actions if a.status == "fixed"], "second run should fix nothing"


def test_fix_dry_run_writes_nothing(tmp_path: Path) -> None:
    src = "import xml.etree.ElementTree as ET\nET.fromstring('<a/>')\n"
    f = _write(tmp_path, "x.py", src)
    result = fix(tmp_path, write=False)
    assert f.read_text(encoding="utf-8") == src  # unchanged
    assert result.diffs  # but a diff is shown
    assert any(a.status == "would-fix" for a in result.actions)


def test_fix_reports_non_allowlisted(tmp_path: Path) -> None:
    # cors-wildcard is report-only — file must be untouched
    src = (
        "from fastapi import FastAPI\n"
        "from fastapi.middleware.cors import CORSMiddleware\n"
        "app = FastAPI(docs_url=None, redoc_url=None)\n"
        'app.add_middleware(CORSMiddleware, allow_origins=["*"])\n'
    )
    f = _write(tmp_path, "app.py", src)
    result = fix(tmp_path, write=True)
    assert 'allow_origins=["*"]' in f.read_text(encoding="utf-8")  # untouched
    assert any(a.status == "reported" and a.rule == "cors-wildcard/allow-origins-star" for a in result.actions)


def test_fix_restrict_with_rules(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    f = _write(tmp_path, "x.py", "import xml.etree.ElementTree as ET\nET.fromstring('<a/>')\n")
    # restrict to xxe only → FastAPI() untouched
    fix(tmp_path, write=True, rules=["xxe-safe/unsafe-xml-import"])
    assert "import defusedxml" in f.read_text(encoding="utf-8")
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == "from fastapi import FastAPI\napp = FastAPI()\n"


def test_fix_preserves_crlf_line_endings(tmp_path: Path) -> None:
    # H6: applying a fix must NOT flatten the file's CRLF terminators to LF while
    # showing a one-line diff — "diff shown = diff applied" must hold byte-for-byte.
    f = tmp_path / "x.py"
    f.write_bytes(b"import xml.etree.ElementTree as ET\r\nET.fromstring('<a/>')\r\n")
    fix(tmp_path, write=True)
    raw = f.read_bytes()
    assert b"defusedxml.ElementTree" in raw   # the fix was applied
    assert b"\r\n" in raw and b"\n" not in raw.replace(b"\r\n", b"")  # CRLF preserved, no lone LF


def test_fix_missing_line_does_not_raise(tmp_path: Path) -> None:
    # a fixer must be total even if the finding line is out of range
    from agentsec.findings import Finding
    out, changed = FIXERS["xxe-safe/unsafe-xml-import"]("short\n", Finding(
        check_id="xxe-safe", severity="medium", title="t", location="x.py:999",
        rule="xxe-safe/unsafe-xml-import",
    ))
    assert (out, changed) == ("short\n", False)


# --- G3 write-safety: path guard, diff cap, printed undo ---------------------


def test_is_safe_target_refuses_unsafe_paths(tmp_path: Path) -> None:
    from agentsec.fix import _is_safe_target

    root = tmp_path / "repo"
    (root / ".github").mkdir(parents=True)
    (root / "node_modules").mkdir()
    assert _is_safe_target(root, root / "a.py")                 # in-repo .py → ok
    assert _is_safe_target(root, root / "pkg" / "b.py")
    assert not _is_safe_target(root, root / ".github" / "x.py")  # CI dir → refused
    assert not _is_safe_target(root, root / "node_modules" / "p" / "x.py")
    assert not _is_safe_target(root, root / "uv.lock")           # not .py → refused
    assert not _is_safe_target(root, tmp_path / "outside.py")    # outside root → refused
    assert not _is_safe_target(root, root / ".." / "esc.py")     # .. escape → refused


def test_fix_diff_cap_refuses_large_change(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # a runaway fixer (huge diff) must be refused, not written — the blast-radius cap.
    from agentsec import fix as fixmod

    big = "".join(f"x{i} = {i}\n" for i in range(200))

    def fat_fixer(text: str, finding: object) -> tuple[str, bool]:
        return text + "\n" + big, True

    monkeypatch.setitem(fixmod.FIXERS, "xxe-safe/unsafe-xml-import", fat_fixer)
    f = _write(tmp_path, "x.py", "import xml.etree.ElementTree as ET\nET.fromstring('<a/>')\n")
    before = f.read_text(encoding="utf-8")
    result = fixmod.fix(tmp_path, write=True)
    assert f.read_text(encoding="utf-8") == before  # refused — file untouched
    assert any(a.status == "skipped" and "cap" in a.detail for a in result.actions)
    assert result.written == []


def test_fix_prints_undo_after_write(tmp_path: Path) -> None:
    from agentsec.fix import render_summary

    _write(tmp_path, "x.py", "import xml.etree.ElementTree as ET\nET.fromstring('<a/>')\n")
    result = fix(tmp_path, write=True)
    assert result.written == ["x.py"]
    out = render_summary(result, write=True)
    assert "Undo: git restore -- x.py" in out
