"""Tests for the target-locality classifier (`agentsec.targets`).

Pure string parsing — no sockets are opened. Covers the local/remote decision,
the secret-free `describe`, and the env-file DB-URL surfacing.
"""
from __future__ import annotations

import pytest

from agentsec.targets import classify_host, db_urls_in_env, describe, extract_host


@pytest.mark.parametrize("url", [
    "http://localhost:8001",
    "http://127.0.0.1:54322",
    "https://127.0.0.1/health",
    "postgresql://postgres:postgres@localhost:54322/postgres",
    "http://host.docker.internal:8000",
    "http://[::1]:8000",
    "http://192.168.1.10:3000",
    "http://10.0.0.5",
    "http://172.16.4.4:5432",
    "http://my-box.local",
    "localhost:8001",  # bare host:port, no scheme
])
def test_classify_local(url: str) -> None:
    assert classify_host(url) == "local"


@pytest.mark.parametrize("url", [
    "https://api.example.com",
    "https://abcd.supabase.co",
    "postgresql://postgres:secret@db.abcd.supabase.co:5432/postgres",
    "postgresql://u:p@prod.cluster.rds.amazonaws.com:5432/app",
    "http://8.8.8.8",
    "http://1.1.1.1:8001",
    "",            # empty → safe default
    "not a url",   # unparseable → safe default
])
def test_classify_remote(url: str) -> None:
    assert classify_host(url) == "remote"


def test_extract_host_strips_credentials() -> None:
    host = extract_host("postgresql://postgres:sup3rsecret@db.abcd.supabase.co:5432/postgres")
    assert host == "db.abcd.supabase.co"
    assert "sup3rsecret" not in host


def test_describe_is_secret_free_with_callouts() -> None:
    dsn = "postgresql://postgres:sup3rsecret@db.abcd.supabase.co:5432/postgres"
    out = describe(dsn)
    assert "sup3rsecret" not in out          # never leak the password
    assert "remote" in out and "db.abcd.supabase.co" in out
    assert "hosted Supabase project" in out


def test_describe_local_and_public_ip() -> None:
    assert describe("http://localhost:8001").startswith("local (")
    assert "public IP" in describe("http://8.8.8.8")
    assert "rds" in describe("postgresql://u:p@x.cluster.rds.amazonaws.com/db").lower() \
        or "RDS" in describe("postgresql://u:p@x.cluster.rds.amazonaws.com/db")


def test_db_urls_in_env_parses_and_dedupes() -> None:
    env = (
        "# comment line\n"
        "DATABASE_URL=postgresql://postgres:pw@db.xyz.supabase.co:5432/postgres\n"
        'SUPABASE_URL="https://xyz.supabase.co"\n'
        "export DIRECT_URL=postgresql://localhost:5432/app\n"
        "DATABASE_URL=postgresql://second/ignored\n"  # first occurrence wins
        "UNRELATED=value\n"
        "EMPTY=\n"
    )
    found = dict(db_urls_in_env(env))
    assert found["DATABASE_URL"] == "postgresql://postgres:pw@db.xyz.supabase.co:5432/postgres"
    assert found["SUPABASE_URL"] == "https://xyz.supabase.co"   # quotes stripped
    assert found["DIRECT_URL"] == "postgresql://localhost:5432/app"  # `export ` prefix handled
    assert "UNRELATED" not in found and "EMPTY" not in found


def test_db_urls_in_env_empty() -> None:
    assert db_urls_in_env("") == []
    assert db_urls_in_env("FOO=bar\n# DATABASE_URL=commented\n") == []
