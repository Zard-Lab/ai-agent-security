"""Tests for the sql-race-check-then-insert guard.

Covers:
  - sql-race-check-then-insert/check-then-insert (MEDIUM)
"""
from __future__ import annotations

from agentsec.guards.sql_race_check_then_insert import SqlRaceCheckThenInsertGuard
from tests.guards._common import *  # noqa: F401,F403


def _guard() -> SqlRaceCheckThenInsertGuard:
    return SqlRaceCheckThenInsertGuard()


# ---------------------------------------------------------------------------
# applies() gate
# ---------------------------------------------------------------------------

def test_applies_when_python_feature_present() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert _guard().applies(prof) is True


def test_not_applies_without_python_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"frontend"})
    assert _guard().applies(prof) is False


# ---------------------------------------------------------------------------
# sql-race-check-then-insert/check-then-insert (MEDIUM)
# ---------------------------------------------------------------------------

def test_fires_on_orm_query_check_then_add_commit(tmp_path: Path) -> None:
    (tmp_path / "signup.py").write_text(
        "def signup(db, email):\n"
        "    existing = db.query(User).filter(User.email == email).first()\n"
        "    if existing is not None:\n"
        "        raise ValueError('already registered')\n"
        "    db.add(User(email=email))\n"
        "    db.commit()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["sql-race-check-then-insert/check-then-insert"]
    assert findings[0].severity == "medium"


def test_fires_on_raw_sql_check_then_insert(tmp_path: Path) -> None:
    (tmp_path / "signup.py").write_text(
        "def signup(db, email):\n"
        "    row = db.execute(\"SELECT * FROM users WHERE email = %s\", (email,)).fetchone()\n"
        "    if row is None:\n"
        "        db.execute(\"INSERT INTO users (email) VALUES (%s)\", (email,))\n"
        "        db.commit()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert "sql-race-check-then-insert/check-then-insert" in {f.rule for f in findings}


def test_fires_on_flask_sqlalchemy_model_query(tmp_path: Path) -> None:
    (tmp_path / "signup.py").write_text(
        "def signup(email):\n"
        "    existing = User.query.filter_by(email=email).first()\n"
        "    if existing is not None:\n"
        "        raise ValueError('dup')\n"
        "    db.session.add(User(email=email))\n"
        "    db.session.commit()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert "sql-race-check-then-insert/check-then-insert" in {f.rule for f in findings}


def test_fires_on_django_style_create(tmp_path: Path) -> None:
    (tmp_path / "signup.py").write_text(
        "def signup(email):\n"
        "    existing = User.objects.filter(email=email).first()\n"
        "    if existing:\n"
        "        raise ValueError('dup')\n"
        "    User.objects.create(email=email)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert "sql-race-check-then-insert/check-then-insert" in {f.rule for f in findings}


def test_fires_on_pluralized_table_vs_model_name(tmp_path: Path) -> None:
    # `users` (raw table) vs `User` (ORM model) — naive singular/plural normalization
    # recognizes these as the same target.
    (tmp_path / "signup.py").write_text(
        "def signup(db, email):\n"
        "    existing = db.query(User).filter(User.email == email).first()\n"
        "    if existing is not None:\n"
        "        raise ValueError('dup')\n"
        "    db.execute(\"INSERT INTO users (email) VALUES (%s)\", (email,))\n"
        "    db.commit()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert "sql-race-check-then-insert/check-then-insert" in {f.rule for f in findings}


# ---------------------------------------------------------------------------
# FP-bait
# ---------------------------------------------------------------------------

def test_fp_bait_on_conflict_guard_present(tmp_path: Path) -> None:
    (tmp_path / "signup.py").write_text(
        "def signup(db, email):\n"
        "    row = db.execute(\"SELECT * FROM users WHERE email = %s\", (email,)).fetchone()\n"
        "    if row is None:\n"
        "        db.execute(\n"
        "            \"INSERT INTO users (email) VALUES (%s) ON CONFLICT (email) DO NOTHING\",\n"
        "            (email,),\n"
        "        )\n"
        "        db.commit()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert "sql-race-check-then-insert/check-then-insert" not in {f.rule for f in findings}


def test_fp_bait_unique_constraint_try_except(tmp_path: Path) -> None:
    (tmp_path / "signup.py").write_text(
        "def signup(db, email):\n"
        "    try:\n"
        "        existing = db.query(User).filter(User.email == email).first()\n"
        "        if existing is not None:\n"
        "            raise ValueError('dup')\n"
        "        db.add(User(email=email))\n"
        "        db.commit()\n"
        "    except IntegrityError:\n"
        "        db.rollback()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert "sql-race-check-then-insert/check-then-insert" not in {f.rule for f in findings}


def test_fp_bait_select_for_update(tmp_path: Path) -> None:
    (tmp_path / "signup.py").write_text(
        "def signup(db, email):\n"
        "    existing = db.execute(\n"
        "        \"SELECT * FROM users WHERE email = %s FOR UPDATE\", (email,)\n"
        "    ).fetchone()\n"
        "    if existing is None:\n"
        "        db.execute(\"INSERT INTO users (email) VALUES (%s)\", (email,))\n"
        "        db.commit()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert "sql-race-check-then-insert/check-then-insert" not in {f.rule for f in findings}


def test_fp_bait_with_for_update_orm(tmp_path: Path) -> None:
    (tmp_path / "signup.py").write_text(
        "def signup(db, email):\n"
        "    existing = db.query(User).filter(User.email == email).with_for_update().first()\n"
        "    if existing is not None:\n"
        "        raise ValueError('dup')\n"
        "    db.add(User(email=email))\n"
        "    db.commit()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert "sql-race-check-then-insert/check-then-insert" not in {f.rule for f in findings}


def test_fp_bait_lone_select_no_insert(tmp_path: Path) -> None:
    (tmp_path / "lookup.py").write_text(
        "def get_user(db, email):\n"
        "    return db.query(User).filter(User.email == email).first()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert findings == []


def test_fp_bait_insert_on_different_table(tmp_path: Path) -> None:
    (tmp_path / "signup.py").write_text(
        "def signup(db, email):\n"
        "    existing = db.query(User).filter(User.email == email).first()\n"
        "    if existing is not None:\n"
        "        raise ValueError('dup')\n"
        "    db.add(AuditLog(action='signup'))\n"
        "    db.commit()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert "sql-race-check-then-insert/check-then-insert" not in {f.rule for f in findings}


def test_fp_bait_add_without_commit(tmp_path: Path) -> None:
    # `.add()` alone never reaches the database — no `.commit()` anywhere in the function
    # means this isn't a completed write, so it must not fire.
    (tmp_path / "stage.py").write_text(
        "def stage(db, email):\n"
        "    existing = db.query(User).filter(User.email == email).first()\n"
        "    if existing is not None:\n"
        "        raise ValueError('dup')\n"
        "    db.add(User(email=email))\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert findings == []


def test_fp_bait_when_pragma_present(tmp_path: Path) -> None:
    (tmp_path / "signup.py").write_text(
        "# security: allow-sql-race-check-then-insert\n"
        "def signup(db, email):\n"
        "    existing = db.query(User).filter(User.email == email).first()\n"
        "    if existing is not None:\n"
        "        raise ValueError('dup')\n"
        "    db.add(User(email=email))\n"
        "    db.commit()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert "sql-race-check-then-insert/check-then-insert" not in {f.rule for f in findings}


def test_fp_bait_test_file_silent(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_signup.py").write_text(
        "def signup(db, email):\n"
        "    existing = db.query(User).filter(User.email == email).first()\n"
        "    if existing is not None:\n"
        "        raise ValueError('dup')\n"
        "    db.add(User(email=email))\n"
        "    db.commit()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["tests"])
    assert _guard().run(tmp_path, profile) == []


def test_fp_bait_isolation_level_signal(tmp_path: Path) -> None:
    (tmp_path / "signup.py").write_text(
        "def signup(db, email):\n"
        "    db.execute('SET TRANSACTION ISOLATION LEVEL SERIALIZABLE')\n"
        "    existing = db.query(User).filter(User.email == email).first()\n"
        "    if existing is not None:\n"
        "        raise ValueError('dup')\n"
        "    db.add(User(email=email))\n"
        "    db.commit()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert "sql-race-check-then-insert/check-then-insert" not in {f.rule for f in findings}


def test_reports_every_violation_across_files(tmp_path: Path) -> None:
    violation = (
        "def signup(db, email):\n"
        "    existing = db.query(User).filter(User.email == email).first()\n"
        "    if existing is not None:\n"
        "        raise ValueError('dup')\n"
        "    db.add(User(email=email))\n"
        "    db.commit()\n"
    )
    (tmp_path / "service_a.py").write_text(violation, encoding="utf-8")
    (tmp_path / "service_b.py").write_text(violation, encoding="utf-8")
    findings = _guard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["sql-race-check-then-insert/check-then-insert"] * 2
    assert {f.location.split(":")[0] for f in findings} == {"service_a.py", "service_b.py"}
