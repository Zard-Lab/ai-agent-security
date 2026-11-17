from __future__ import annotations

from agentsec.guards.nosql_metadata_injection import NoSqlMetadataInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_nosql_flags_where_operator(tmp_path: Path) -> None:
    (tmp_path / "q.py").write_text(
        "from pymongo import MongoClient\ndef f(db, user):\n    return db.c.find({\"$where\": user})\n", encoding="utf-8"
    )
    findings = NoSqlMetadataInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "nosql-metadata-injection/dynamic-operator"
    assert findings[0].severity == "high"

def test_nosql_flags_dynamic_regex(tmp_path: Path) -> None:
    (tmp_path / "q.py").write_text(
        "import pymongo\ndef f(c, term):\n    return c.find({\"$regex\": f\".*{term}.*\"})\n", encoding="utf-8"
    )
    assert len(NoSqlMetadataInjectionGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_nosql_passes_without_mongo(tmp_path: Path) -> None:
    # no pymongo/motor and no $-operator in the file -> not scanned (Postgres app)
    (tmp_path / "q.py").write_text("def f(db, user):\n    return db.execute('select 1')\n", encoding="utf-8")
    assert NoSqlMetadataInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_nosql_passes_static_query(tmp_path: Path) -> None:
    (tmp_path / "q.py").write_text(
        "from pymongo import MongoClient\ndef f(c):\n    return c.find({\"name\": \"alice\"})\n", encoding="utf-8"
    )
    assert NoSqlMetadataInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_nosql_pragma(tmp_path: Path) -> None:
    (tmp_path / "q.py").write_text(
        "from pymongo import MongoClient\ndef f(c, u):\n"
        "    return c.find({\"$where\": u})  # security: allow-nosql-operator\n", encoding="utf-8"
    )
    assert NoSqlMetadataInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_nosql_passes_ne_none(tmp_path: Path) -> None:
    # #423 FP-bait: {"$ne": None} is the ubiquitous pymongo soft-delete idiom — None is a
    # literal, not a user-controlled variable.
    (tmp_path / "q.py").write_text(
        "import pymongo\ndef f(c):\n    return c.find({\"deleted_at\": {\"$ne\": None}})\n", encoding="utf-8"
    )
    assert NoSqlMetadataInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_nosql_passes_static_raw_regex(tmp_path: Path) -> None:
    # #423 FP-bait: a raw string is a STATIC regex, not an f-string.
    (tmp_path / "q.py").write_text(
        "import pymongo\ndef f(c):\n    return c.find({\"name\": {\"$regex\": r\"^admin$\"}})\n", encoding="utf-8"
    )
    assert NoSqlMetadataInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_nosql_passes_literal_containing_plus(tmp_path: Path) -> None:
    # #423 FP-bait: a `+` INSIDE a string literal is not a concatenation.
    (tmp_path / "q.py").write_text(
        "import pymongo\ndef f(c):\n    return c.find({\"code\": {\"$regex\": \"C++\"}})\n", encoding="utf-8"
    )
    assert NoSqlMetadataInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_nosql_passes_static_value_with_inner_comma(tmp_path: Path) -> None:
    # PR #444 review: a comma INSIDE a static string value must not truncate the value
    # (quote-aware _op_value). {"$regex": "foo,bar"} is a static literal — no finding.
    (tmp_path / "q.py").write_text(
        "import pymongo\ndef f(c):\n    return c.find({\"$regex\": \"foo,bar\"})\n", encoding="utf-8"
    )
    assert NoSqlMetadataInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_nosql_flags_concat_with_inner_comma(tmp_path: Path) -> None:
    # PR #444 review: a real concat whose literal contains a comma must STILL fire — the
    # quote-aware scan keeps the value whole so the `+ user` survives.
    (tmp_path / "q.py").write_text(
        "import pymongo\ndef f(c, user):\n    return c.find({\"$ne\": \"1,2\" + user})\n", encoding="utf-8"
    )
    assert len(NoSqlMetadataInjectionGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_nosql_flags_string_prefixed_concat(tmp_path: Path) -> None:
    # regression: a real concat whose left side is a string literal must still fire.
    (tmp_path / "q.py").write_text(
        "import pymongo\ndef f(c, user):\n    return c.find({\"name\": {\"$regex\": \"^\" + user}})\n", encoding="utf-8"
    )
    assert len(NoSqlMetadataInjectionGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_nosql_na_without_python() -> None:
    assert NoSqlMetadataInjectionGuard().applies(mkprofile(Path("/tmp"), features={"frontend"})) is False



def test_nosql_static_string_ending_in_f_is_not_an_fstring(tmp_path: Path) -> None:
    # Regression (#444 review): `_FSTR` was searched anywhere in the value, so it matched the
    # `f"` sequence formed by the LAST character of a static string and its closing quote.
    # Every one of these drew a HIGH on a completely static query.
    (tmp_path / "q.py").write_text(
        "def f(db):\n"
        "    db.users.find({'path': {'$regex': '\\\\.pdf'}})\n"
        "    db.users.find({'role': {'$ne': 'staff'}})\n"
        "    db.users.find({'name': {'$regex': '^conf'}})\n"
        "    db.users.find({'kind': {'$in': ['pdf','doc']}})\n",
        encoding="utf-8",
    )
    assert NoSqlMetadataInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_nosql_real_dynamic_values_still_fire(tmp_path: Path) -> None:
    # The anchoring must not cost the real signal: a genuine f-string and a bare variable.
    (tmp_path / "q.py").write_text(
        "def f(db, uname):\n"
        "    db.users.find({'name': {'$regex': f'^{uname}'}})\n"
        "    db.users.find({'role': {'$ne': uname}})\n",
        encoding="utf-8",
    )
    assert len(NoSqlMetadataInjectionGuard().run(tmp_path, _pyprof(tmp_path))) == 2


def test_nosql_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the flagged line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-nosql-operator"):
        (tmp_path / "q.py").write_text(
            "from pymongo import MongoClient\ndef f(c, u):\n"
            f'    return c.find({{"$where": u, "note": "{note}"}})\n', encoding="utf-8"
        )
        assert len(NoSqlMetadataInjectionGuard().run(tmp_path, _pyprof(tmp_path))) == 1, note
