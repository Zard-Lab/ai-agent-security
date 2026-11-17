from __future__ import annotations

from agentsec.guards.mass_assignment import MassAssignmentGuard
from tests.guards._common import *  # noqa: F401,F403


def test_mass_assignment_fires_on_setattr_loop(tmp_path: Path) -> None:
    (tmp_path / "crud.py").write_text(
        "def update_user(db, update_data):\n"
        "    for field, value in update_data.dict().items():\n"
        "        setattr(db_user, field, value)\n",
        encoding="utf-8",
    )
    findings = MassAssignmentGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mass-assignment/orm-update-from-request"
    assert findings[0].severity == "high"
    assert findings[0].check_id == "mass-assignment"

def test_mass_assignment_fires_on_values_splat(tmp_path: Path) -> None:
    (tmp_path / "crud.py").write_text(
        "stmt = update(User).values(**body.dict())\n",
        encoding="utf-8",
    )
    findings = MassAssignmentGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mass-assignment/orm-update-from-request"
    assert findings[0].severity == "high"

def test_mass_assignment_fires_on_model_dump_splat(tmp_path: Path) -> None:
    (tmp_path / "crud.py").write_text(
        "stmt = update(User).values(**body.model_dump())\n",
        encoding="utf-8",
    )
    findings = MassAssignmentGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mass-assignment/orm-update-from-request"

def test_mass_assignment_silent_on_explicit_fields(tmp_path: Path) -> None:
    (tmp_path / "crud.py").write_text(
        "user.name = body.name\n"
        "user.email = body.email\n",
        encoding="utf-8",
    )
    assert MassAssignmentGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_mass_assignment_silent_on_named_values(tmp_path: Path) -> None:
    (tmp_path / "crud.py").write_text(
        "stmt = update(User).values(name=body.name, email=body.email)\n",
        encoding="utf-8",
    )
    assert MassAssignmentGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_mass_assignment_silent_on_pragma(tmp_path: Path) -> None:
    (tmp_path / "crud.py").write_text(
        "# security: allow-mass-assignment\n"
        "def update_user(db, update_data):\n"
        "    for field, value in update_data.dict().items():\n"
        "        setattr(db_user, field, value)\n",
        encoding="utf-8",
    )
    assert MassAssignmentGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_mass_assignment_fires_on_setattr_later_in_module_level_loop(tmp_path: Path) -> None:
    # Module-level loop header: the setattr on a later body line must still be found
    # (the old dedent check broke at the first body line for indent-0 headers).
    (tmp_path / "crud.py").write_text(
        "for field, value in payload.dict().items():\n"
        "    if field == 'id':\n"
        "        continue\n"
        "    setattr(obj, field, value)\n",
        encoding="utf-8",
    )
    findings = MassAssignmentGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "mass-assignment/orm-update-from-request"
    assert findings[0].location.endswith("crud.py:1")

def test_mass_assignment_silent_on_setattr_after_loop_body_ends(tmp_path: Path) -> None:
    # FP bait: the scan must stop at the dedent that ends the loop body, not run on
    # into unrelated code that happens to call setattr within the 5-line window.
    (tmp_path / "crud.py").write_text(
        "def update_user(db_user, update_data):\n"
        "    for field, value in update_data.dict().items():\n"
        "        allowed[field] = value\n"
        "    return db_user\n"
        "\n"
        "def audit(obj):\n"
        "    setattr(obj, 'seen', True)\n",
        encoding="utf-8",
    )
    assert MassAssignmentGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_mass_assignment_not_applies_without_python(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"fastapi", "supabase"}, python_dirs=["."])
    assert not MassAssignmentGuard().applies(prof)

