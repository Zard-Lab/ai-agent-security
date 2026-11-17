"""Tests for `agentsec scan-live-url`'s probe layer (BL-*).

Network + subprocess (dig/nslookup) are mocked — we exercise the ownership gate,
discovery, and probe→Finding wiring, never a real HTTP call.
"""
from __future__ import annotations

import io
import json
import subprocess
from typing import Any

import pytest

from agentsec import livescan


class _FakeResp(io.BytesIO):
    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


def _fake_urlopen(body: bytes) -> Any:
    def _open(*_a: object, **_kw: object) -> _FakeResp:
        return _FakeResp(body)
    return _open


# --- ownership: file-based ---------------------------------------------------


def test_verify_ownership_file_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(livescan.net, "urlopen", _fake_urlopen(b"abc123token"))
    r = livescan.verify_ownership_file("https://x.example/", "abc123token")
    assert r.verified is True
    assert r.method == "file"


def test_verify_ownership_file_wrong_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(livescan.net, "urlopen", _fake_urlopen(b"some other content"))
    r = livescan.verify_ownership_file("https://x.example/", "abc123token")
    assert r.verified is False
    assert "not found" in r.reason


def test_verify_ownership_file_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_kw: object) -> None:
        raise OSError("connection refused")
    monkeypatch.setattr(livescan.net, "urlopen", boom)
    r = livescan.verify_ownership_file("https://x.example/", "tok")
    assert r.verified is False
    assert "could not fetch" in r.reason


def test_verify_ownership_file_checks_the_well_known_path(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake(url: str, timeout: int = 10) -> _FakeResp:
        captured["url"] = url
        return _FakeResp(b"tok")
    monkeypatch.setattr(livescan.net, "urlopen", fake)
    livescan.verify_ownership_file("https://app.example/some/path", "tok")
    assert captured["url"] == "https://app.example" + livescan.WELL_KNOWN_PATH


# --- ownership: DNS-based -----------------------------------------------------


def test_verify_ownership_dns_no_tool_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(livescan, "which", lambda _name: None)
    r = livescan.verify_ownership_dns("https://x.example/", "tok")
    assert r.verified is False
    assert "dig/nslookup" in r.reason


def test_verify_ownership_dns_succeeds_via_dig(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(livescan, "which", lambda name: "/usr/bin/dig" if name == "dig" else None)

    def fake_run(cmd: list[str], **_kw: object) -> subprocess.CompletedProcess[str]:
        assert cmd[0] == "dig"
        assert "_agentsec-verify.x.example" in cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="tok123\n", stderr="")
    monkeypatch.setattr(livescan.subprocess, "run", fake_run)
    r = livescan.verify_ownership_dns("https://x.example/", "tok123")
    assert r.verified is True
    assert r.method == "dns"


def test_verify_ownership_dns_wrong_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(livescan, "which", lambda name: "/usr/bin/dig" if name == "dig" else None)
    monkeypatch.setattr(
        livescan.subprocess, "run",
        lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout="somethingelse\n", stderr=""),
    )
    r = livescan.verify_ownership_dns("https://x.example/", "tok123")
    assert r.verified is False


def test_verify_ownership_dns_unparseable_url() -> None:
    r = livescan.verify_ownership_dns("not-a-url", "tok")
    assert r.verified is False
    assert "host" in r.reason


# --- discovery -----------------------------------------------------------------


def test_discover_supabase_config_from_html(monkeypatch: pytest.MonkeyPatch) -> None:
    anon_key = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    html = f'<html><body>url=https://myproj.supabase.co key={anon_key}</body></html>'.encode()
    monkeypatch.setattr(livescan.net, "urlopen", _fake_urlopen(html))
    url, key = livescan.discover_supabase_config("https://app.example/")
    assert url == "https://myproj.supabase.co"
    assert key == anon_key


def test_discover_supabase_config_fetches_bounded_scripts(monkeypatch: pytest.MonkeyPatch) -> None:
    anon_key = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    html = b'<html><script src="/static/bundle.js"></script></html>'
    calls: list[str] = []

    def fake(url: str, timeout: int = 15) -> _FakeResp:
        calls.append(url)
        if url.endswith("bundle.js"):
            return _FakeResp(f"https://otherproj.supabase.co {anon_key}".encode())
        return _FakeResp(html)
    monkeypatch.setattr(livescan.net, "urlopen", fake)
    url, key = livescan.discover_supabase_config("https://app.example/")
    assert url == "https://otherproj.supabase.co"
    assert key == anon_key
    assert any(c.endswith("/static/bundle.js") for c in calls)


def test_discover_supabase_config_no_match_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(livescan.net, "urlopen", _fake_urlopen(b"<html>nothing here</html>"))
    url, key = livescan.discover_supabase_config("https://app.example/")
    assert (url, key) == ("", "")


def test_discover_supabase_config_unreachable_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_kw: object) -> None:
        raise OSError("refused")
    monkeypatch.setattr(livescan.net, "urlopen", boom)
    assert livescan.discover_supabase_config("https://app.example/") == ("", "")


# --- probe: exposed tables -------------------------------------------------------


def test_probe_exposed_tables_fires_on_sensitive_name(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps({"paths": {"/users": {}, "/todos": {}}}).encode()
    monkeypatch.setattr(livescan.net, "urlopen", _fake_urlopen(body))
    r = livescan.probe_exposed_tables("https://x.supabase.co", "anon")
    assert r.ran is True
    assert len(r.findings) == 1
    assert r.findings[0].severity == "high"
    assert "users" in r.findings[0].message


def test_probe_exposed_tables_medium_when_no_sensitive_name(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps({"paths": {"/blog_posts": {}, "/categories": {}}}).encode()
    monkeypatch.setattr(livescan.net, "urlopen", _fake_urlopen(body))
    r = livescan.probe_exposed_tables("https://x.supabase.co", "anon")
    assert r.findings[0].severity == "medium"


def test_probe_exposed_tables_silent_on_empty_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps({"paths": {}}).encode()
    monkeypatch.setattr(livescan.net, "urlopen", _fake_urlopen(body))
    r = livescan.probe_exposed_tables("https://x.supabase.co", "anon")
    assert r.ran is True
    assert r.findings == []


def test_probe_exposed_tables_unreachable_is_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_kw: object) -> None:
        raise OSError("refused")
    monkeypatch.setattr(livescan.net, "urlopen", boom)
    r = livescan.probe_exposed_tables("https://x.supabase.co", "anon")
    assert r.ran is False
    assert "unreachable" in r.skip_reason


# --- probe: public storage -------------------------------------------------------


def test_probe_public_storage_fires_on_public_bucket(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps([{"name": "avatars", "public": True}, {"name": "private", "public": False}]).encode()
    monkeypatch.setattr(livescan.net, "urlopen", _fake_urlopen(body))
    r = livescan.probe_public_storage("https://x.supabase.co", "anon")
    assert len(r.findings) == 1
    assert "avatars" in r.findings[0].message
    assert "private" not in r.findings[0].message


def test_probe_public_storage_silent_when_all_private(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps([{"name": "private", "public": False}]).encode()
    monkeypatch.setattr(livescan.net, "urlopen", _fake_urlopen(body))
    r = livescan.probe_public_storage("https://x.supabase.co", "anon")
    assert r.findings == []


# --- probe: pg_graphql -------------------------------------------------------


def test_probe_pg_graphql_fires_when_schema_exposed(monkeypatch: pytest.MonkeyPatch) -> None:
    types = [{"name": n} for n in ("__Schema", "String", "Int", "Boolean", "ID", "Float", "users", "posts")]
    body = json.dumps({"data": {"__schema": {"types": types}}}).encode()
    monkeypatch.setattr(livescan.net, "urlopen", _fake_urlopen(body))
    r = livescan.probe_pg_graphql("https://x.supabase.co", "anon")
    assert len(r.findings) == 1
    assert r.findings[0].severity == "high"


def test_probe_pg_graphql_silent_on_baseline_schema_only(monkeypatch: pytest.MonkeyPatch) -> None:
    types = [{"name": n} for n in ("__Schema", "String", "Int", "Boolean")]
    body = json.dumps({"data": {"__schema": {"types": types}}}).encode()
    monkeypatch.setattr(livescan.net, "urlopen", _fake_urlopen(body))
    r = livescan.probe_pg_graphql("https://x.supabase.co", "anon")
    assert r.findings == []


def test_probe_pg_graphql_posts_introspection_query(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake(req: Any, timeout: int = 15) -> _FakeResp:
        captured["method"] = req.get_method()
        captured["body"] = req.data
        return _FakeResp(json.dumps({"data": {"__schema": {"types": []}}}).encode())
    monkeypatch.setattr(livescan.net, "urlopen", fake)
    livescan.probe_pg_graphql("https://x.supabase.co", "anon")
    assert captured["method"] == "POST"
    assert b"__schema" in captured["body"]


# --- edge functions disclosure -------------------------------------------------------


def test_edge_functions_not_probed_discloses_honestly() -> None:
    r = livescan.edge_functions_not_probed()
    assert r.ran is False
    assert "enumeration" in r.skip_reason
