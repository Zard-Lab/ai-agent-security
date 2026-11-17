from __future__ import annotations

from agentsec.guards.staticfiles_broad_mount import StaticfilesBroadMountGuard
from tests.guards._common import *  # noqa: F401,F403


def test_staticfiles_fires_on_dot_directory(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        'app.mount("/", StaticFiles(directory="."))\n', encoding="utf-8"
    )
    findings = StaticfilesBroadMountGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "staticfiles-broad-mount/root-or-parent-dir-mounted"
    assert findings[0].severity == "high"
    assert findings[0].check_id == "staticfiles-broad-mount"

def test_staticfiles_fires_on_slash_directory(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        'app.mount("/static", StaticFiles(directory="/"))\n', encoding="utf-8"
    )
    findings = StaticfilesBroadMountGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "staticfiles-broad-mount/root-or-parent-dir-mounted"

def test_staticfiles_fires_on_dotdot_directory(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        'StaticFiles(directory="..")\n', encoding="utf-8"
    )
    findings = StaticfilesBroadMountGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "staticfiles-broad-mount/root-or-parent-dir-mounted"

def test_staticfiles_silent_on_safe_paths(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        'app.mount("/static", StaticFiles(directory="static"))\n'
        'app.mount("/assets", StaticFiles(directory="frontend/build"))\n',
        encoding="utf-8",
    )
    findings = StaticfilesBroadMountGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert findings == []

def test_staticfiles_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "# security: allow-staticfiles-mount\n"
        'app.mount("/", StaticFiles(directory="."))\n',
        encoding="utf-8",
    )
    findings = StaticfilesBroadMountGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert findings == []

def test_staticfiles_applies_gate() -> None:
    guard = StaticfilesBroadMountGuard()
    assert guard.applies(mkprofile(Path("/tmp"), features=set())) is False
    assert guard.applies(mkprofile(Path("/tmp"), features={"fastapi"})) is True
    assert guard.applies(mkprofile(Path("/tmp"), features={"python"})) is True


def test_staticfiles_broad_mount_silent_on_docstring_example(tmp_path: Path) -> None:
    # FP-bait (#424): the StaticFiles(directory=".") example lives only in a docstring
    # (this guard's own module docstring self-matches). strip_python_strings blanks it.
    (tmp_path / "app.py").write_text(
        '"""Do not do this:\n'
        "\n"
        '    app.mount("/", StaticFiles(directory="."))\n'
        '"""\n'
        "from fastapi import FastAPI\n",
        encoding="utf-8",
    )
    assert StaticfilesBroadMountGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

