from __future__ import annotations

import pytest

from agentsec.guards.node_db_driver_hardcoded_password import NodeDbDriverHardcodedPasswordGuard
from tests.guards._common import *  # noqa: F401,F403

_PG = "const { Pool, Client } = require('pg');\n"
_CFG = "node-db-driver-hardcoded-password/driver-config-literal-password"
_URL = "node-db-driver-hardcoded-password/connection-url-embedded-password"


def _run(tmp_path: Path, body: str, name: str = "db.js") -> list[tuple[str, int]]:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    findings = NodeDbDriverHardcodedPasswordGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    return [(f.rule, int(f.location.rsplit(":", 1)[1])) for f in findings]


@pytest.mark.parametrize(
    "body",
    [
        _PG + "const pool = new Pool({ user: 'app', password: 'Sup3rS3cretPw!' });\n",
        _PG + "const c = new Client({\n  host: 'db',\n  password: \"Sup3rS3cretPw!\",\n});\n",
        "const mysql = require('mysql');\nmysql.createConnection({ host: 'h', password: 'Hunt3rTwo22' });\n",
        "import mysql from 'mysql2/promise';\nconst p = mysql.createPool({ 'password': 'Hunt3rTwo22' });\n",
        "const sql = require('mssql');\nconst p = new sql.ConnectionPool({ password: `Hunt3rTwo22` });\n",
        _PG + "const pool = new Pool({ ssl: { rejectUnauthorized: false }, password: 'Sup3rS3cretPw!' });\n",
    ],
)
def test_literal_password_in_driver_config_fires(tmp_path: Path, body: str) -> None:
    assert [r for r, _ in _run(tmp_path, body)] == [_CFG]


def test_config_finding_reports_the_password_line(tmp_path: Path) -> None:
    body = _PG + "const c = new Client({\n  host: 'db',\n  password: 'Sup3rS3cretPw!',\n});\n"
    assert _run(tmp_path, body) == [(_CFG, 4)]


@pytest.mark.parametrize(
    "body",
    [
        _PG + "new Pool({ connectionString: 'postgres://app:Sup3rS3cretPw@db:5432/app' });\n",
        _PG + "const u = `mysql://root:Hunt3rTwo22@127.0.0.1/db`;\n",
    ],
)
def test_connection_url_with_password_fires(tmp_path: Path, body: str) -> None:
    assert [r for r, _ in _run(tmp_path, body)] == [_URL]


@pytest.mark.parametrize(
    "body",
    [
        _PG + "new Pool({ user: 'app', password: process.env.DB_PASSWORD });\n",
        _PG + "new Pool({ password: config.db.password });\n",
        _PG + "new Pool({ password: '' });\n",
        _PG + "new Pool({ password: 'pw' });\n",
        _PG + "new Pool({ password: 'test' });\n",
        _PG + "new Pool({ password: 'changeme' });\n",
        _PG + "new Pool({ password: 'your-password-here' });\n",
        _PG + "new Pool({ password: '<password>' });\n",
        _PG + "new Pool({ password: 'postgres' });\n",
        _PG + "new Pool({ password: `${secret}` });\n",
        _PG + "new Pool({ host: 'db' }); // password: 'Sup3rS3cretPw!'\n",
        _PG + "log(\"new Pool({ password: 'Sup3rS3cretPw!' })\");\n",
        _PG + "const u = `postgres://${user}:${pw}@db/app`;\n",
        _PG + "const u = 'postgres://app@db/app';\n",
        _PG + "const u = 'postgres://app:changeme@db/app';\n",
        _PG + "const form = { password: 'Sup3rS3cretPw!' };\n",
    ],
)
def test_safe_or_placeholder_values_silent(tmp_path: Path, body: str) -> None:
    assert _run(tmp_path, body) == []


def test_needs_a_driver_import(tmp_path: Path) -> None:
    body = "const { Client } = require('some-sdk');\nnew Client({ password: 'Sup3rS3cretPw!' });\n"
    assert _run(tmp_path, body) == []


@pytest.mark.parametrize("path", ["__tests__/db.js", "tests/db.test.js", "fixtures/db.js", "examples/db.js", "__mocks__/pg.js"])
def test_test_and_fixture_paths_silent(tmp_path: Path, path: str) -> None:
    body = _PG + "new Pool({ password: 'Sup3rS3cretPw!' });\n"
    assert _run(tmp_path, body, path) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    body = "// security: allow-node-db-driver-hardcoded-password\n" + _PG + "new Pool({ password: 'Sup3rS3cretPw!' });\n"
    assert _run(tmp_path, body) == []


def test_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    body = _PG + "const note = 'security: allow-node-db-driver-hardcoded-password';\nnew Pool({ password: 'Sup3rS3cretPw!' });\n"
    assert [r for r, _ in _run(tmp_path, body)] == [_CFG]


def test_typescript_file_and_aliased_constructor_fires(tmp_path: Path) -> None:
    body = "import { Pool as PgPool } from 'pg';\nconst p = new pg.Pool({ password: 'Sup3rS3cretPw!' });\n"
    assert [r for r, _ in _run(tmp_path, body, "src/db.ts")] == [_CFG]


def test_migrations_tree_is_still_scanned(tmp_path: Path) -> None:
    body = _PG + "new Client({ password: 'Sup3rS3cretPw!' });\n"
    assert [r for r, _ in _run(tmp_path, body, "migrations/run.js")] == [_CFG]


def test_not_applies_without_js_or_ts(tmp_path: Path) -> None:
    assert not NodeDbDriverHardcodedPasswordGuard().applies(mkprofile(tmp_path, features={"python"}))
