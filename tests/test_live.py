"""Tests for the live scanners (`agentsec live` plumbing).

Subprocess + Docker + psql are mocked: we exercise the graceful-skip paths and the
output→Finding wiring, not real ZAP/Postgres.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from agentsec import live


def test_zap_skips_without_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "which", lambda _name: None)
    r = live.run_zap("http://localhost:8082")
    assert r.ran is False and "docker not installed" in r.skip_reason and r.findings == []


def test_zap_parses_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/docker")
    zap_json = (
        '{"site":[{"alerts":[{"name":"CSP Header Not Set","riskdesc":"Medium (High)",'
        '"desc":"<p>x</p>","instances":[{"uri":"http://h/"}],"pluginid":"10038"}]}]}'
    )

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        # the `-v <dir>:/zap/wrk:rw` mount dir is the 2nd value after -v; write the
        # report there. rsplit off the container suffix (a naive split(":") would eat
        # a Windows drive letter, e.g. "C:\\...").
        wrk = Path(cmd[cmd.index("-v") + 1].rsplit(":/zap/wrk:", 1)[0])
        (wrk / "zap.json").write_text(zap_json, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 2)

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    r = live.run_zap("http://localhost:8082")
    assert r.ran is True
    assert any(f.check_id == "zap" and f.severity == "medium" for f in r.findings)


def test_zap_tempdir_ignores_cleanup_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    # #420: the ZAP container writes into the bind mount as uid 1000, so tempdir
    # cleanup can raise PermissionError — and the success return sits outside the
    # `with`, so a scan that succeeded died during cleanup. Pin the fix flag.
    import tempfile as tempfile_mod

    captured: dict[str, Any] = {}
    real_td = tempfile_mod.TemporaryDirectory

    def spy_td(*args: Any, **kwargs: Any) -> Any:
        captured.update(kwargs)
        return real_td(*args, **kwargs)

    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(live.tempfile, "TemporaryDirectory", spy_td)
    monkeypatch.setattr(
        live.subprocess, "run",
        lambda cmd, **_: subprocess.CompletedProcess(cmd, 2),  # no report written → skip
    )
    live.run_zap("http://localhost:8082")
    assert captured.get("ignore_cleanup_errors") is True


def test_zap_network_mode_toggles_docker_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/docker")
    seen: list[list[str]] = []

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        seen.append(cmd)
        # no report written → run_zap returns a skip; we only care about the cmd shape
        return subprocess.CompletedProcess(cmd, 2)

    monkeypatch.setattr(live.subprocess, "run", fake_run)

    live.run_zap("http://localhost:8082")  # default: bridge net + host.docker.internal
    assert "--add-host=host.docker.internal:host-gateway" in seen[-1]
    assert "--network=host" not in seen[-1]

    live.run_zap("http://127.0.0.1:8082", network_host=True)  # Linux host-net mode
    assert "--network=host" in seen[-1]
    assert "--add-host=host.docker.internal:host-gateway" not in seen[-1]


# A local DSN so these exercise the psql/sql/parse flow, not the remote gate
# (covered separately below). The `-f` arg distinguishes the main lint query from
# the `SELECT 1` pre-flight in the mocks.
_LOCAL_DSN = "postgresql://localhost/x"


def test_splinter_skips_without_psql(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "which", lambda _name: None)
    r = live.run_splinter(_LOCAL_DSN, splinter_sql="/whatever.sql")
    assert r.ran is False and "psql not installed" in r.skip_reason


def test_splinter_missing_sql_no_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/psql")
    r = live.run_splinter(_LOCAL_DSN, splinter_sql=None, allow_fetch=False)
    assert r.ran is False and "fetch disabled" in r.skip_reason


def test_splinter_refuses_remote_without_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    # a remote DSN is refused before psql/sql are even consulted (read-only, but
    # don't lint production by accident); the flag opts in.
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/psql")
    r = live.run_splinter("postgresql://db.abcd.supabase.co:5432/postgres", splinter_sql="/x.sql")
    assert r.ran is False and "remote database" in r.skip_reason


def test_splinter_parses_psql_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/psql")
    src = tmp_path / "splinter.sql"
    src.write_text("set local search_path = '';\nselect 1;\n", encoding="utf-8")  # body is irrelevant (psql mocked)
    lints = (
        '[{"name":"rls_disabled_in_public","level":"error","title":"RLS Disabled in Public",'
        '"detail":"public.docs has RLS off","metadata":{"name":"docs"},"remediation":"enable rls"}]'
    )

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        if "-f" not in cmd:  # the SELECT 1 pre-flight
            return subprocess.CompletedProcess(cmd, 0, stdout="1\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="SET\n" + lints + "\n", stderr="")

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    r = live.run_splinter(_LOCAL_DSN, splinter_sql=str(src))
    assert r.ran is True
    assert any(f.check_id == "splinter" and f.severity == "high" for f in r.findings)


def test_splinter_preflight_failure_is_clean_skip(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/psql")
    src = tmp_path / "splinter.sql"
    src.write_text("set local search_path = '';\nselect 1;\n", encoding="utf-8")

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        # the pre-flight itself fails (bad/unreachable DSN) → a clean skip, not a crash
        return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="could not connect to server")

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    r = live.run_splinter(_LOCAL_DSN, splinter_sql=str(src))
    assert r.ran is False and "database unreachable" in r.skip_reason


def test_splinter_no_json_line_is_skip(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/psql")
    src = tmp_path / "splinter.sql"
    src.write_text("set local search_path = '';\nselect 1;\n", encoding="utf-8")

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        if "-f" not in cmd:  # pre-flight passes
            return subprocess.CompletedProcess(cmd, 0, stdout="1\n", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr='ERROR: relation "x" does not exist')

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    r = live.run_splinter(_LOCAL_DSN, splinter_sql=str(src))
    assert r.ran is False and "splinter produced no findings" in r.skip_reason


def test_wrap_splinter_drops_first_line_and_sets_schema() -> None:
    wrapped = live._wrap_splinter("set local search_path = '';\n(select 1 as name)\n")
    assert wrapped.startswith("set pgrst.db_schemas = 'public';")
    assert "json_agg(row_to_json(t))" in wrapped
    assert "set local search_path" not in wrapped  # splinter's own line dropped


def test_wrap_splinter_custom_exposed_schemas() -> None:
    wrapped = live._wrap_splinter("set local search_path = '';\n(select 1 as name)\n",
                                  "public, workbook , graphql_public")
    # spaces stripped, list preserved → exposed-schema lints now cover workbook
    assert wrapped.startswith("set pgrst.db_schemas = 'public,workbook,graphql_public';")


def test_wrap_splinter_rejects_injection() -> None:
    # an out-of-charset value (would be a SQL-injection vector) falls back to public
    wrapped = live._wrap_splinter("set local search_path = '';\n(select 1)\n",
                                  "public'; DROP TABLE x; --")
    assert wrapped.startswith("set pgrst.db_schemas = 'public';")


# --- auth bootstrap + reachability (Theme 4) --------------------------------


def test_mint_token_cmd_returns_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: object, **_: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 0, stdout="  tok-123\n", stderr="")

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    assert live.mint_token_cmd("echo tok-123") == "tok-123"  # trimmed


def test_mint_token_cmd_failure_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(cmd: object, **_: Any) -> subprocess.CompletedProcess[str]:
        raise OSError("no shell")

    monkeypatch.setattr(live.subprocess, "run", boom)
    assert live.mint_token_cmd("whatever") == ""  # never raises


def test_mint_supabase_token_parses_access_token(monkeypatch: pytest.MonkeyPatch) -> None:
    import io

    captured: dict[str, Any] = {}

    def fake_urlopen(req: Any, timeout: int = 30) -> Any:
        captured["url"] = req.full_url
        captured["body"] = req.data
        return io.BytesIO(b'{"access_token": "jwt-abc", "token_type": "bearer"}')

    monkeypatch.setattr(live.urllib.request, "urlopen", fake_urlopen)
    tok = live.mint_supabase_token("https://x.supabase.co", "anon", "u@e.com", "pw")
    assert tok == "jwt-abc"
    assert "grant_type=password" in captured["url"]
    assert b"pw" in captured["body"]


def test_mint_supabase_token_missing_params_is_empty() -> None:
    assert live.mint_supabase_token("", "anon", "u", "p") == ""   # no url → no call
    assert live.mint_supabase_token("https://x", "", "u", "p") == ""


def test_mint_supabase_token_http_error_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(req: Any, timeout: int = 30) -> Any:
        raise OSError("connection refused")

    monkeypatch.setattr(live.urllib.request, "urlopen", boom)
    assert live.mint_supabase_token("https://x.supabase.co", "anon", "u", "p") == ""


def test_mint_supabase_token_refuses_non_https(monkeypatch: pytest.MonkeyPatch) -> None:
    # A password must never be POSTed over cleartext: a non-https URL returns ""
    # WITHOUT ever opening a connection.
    def boom(req: Any, timeout: int = 30) -> Any:
        raise AssertionError("urlopen must not be called for a non-https Supabase URL")

    monkeypatch.setattr(live.urllib.request, "urlopen", boom)
    assert live.mint_supabase_token("http://x.supabase.co", "anon", "u@e.com", "pw") == ""


def test_reachable_rejects_non_http_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    # A user-supplied probe URL with a file:// / custom scheme is rejected before
    # urlopen (B310's real concern) — never opens a local file.
    def boom(url: Any, timeout: int = 10) -> Any:
        raise AssertionError("urlopen must not be called for a non-http(s) scheme")

    monkeypatch.setattr(live.urllib.request, "urlopen", boom)
    assert live._reachable("file:///etc/passwd") is False
    assert live._reachable("ftp://example.com/x") is False


# --- schemathesis ------------------------------------------------------------


def test_schemathesis_skips_without_st(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "which", lambda _name: None)
    r = live.run_schemathesis("http://localhost:8001")
    assert r.ran is False and "not installed" in r.skip_reason and r.findings == []


def test_schemathesis_parses_junit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/st")
    monkeypatch.setattr(live, "_reachable", lambda *a, **k: True)
    junit = ('<testsuite><testcase name="GET /x"><failure message="Server error (500)"/>'
             '</testcase></testsuite>')

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        report = Path(cmd[cmd.index("--report-junit-path") + 1])
        report.write_text(junit, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 1)

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    r = live.run_schemathesis("http://localhost:8001")
    assert r.ran is True
    assert any(f.check_id == "schemathesis" and f.severity == "high" for f in r.findings)


def test_schemathesis_skip_list_adds_exclude_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/st")
    monkeypatch.setattr(live, "_reachable", lambda *a, **k: True)
    captured: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        Path(cmd[cmd.index("--report-junit-path") + 1]).write_text("<testsuite></testsuite>", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    live.run_schemathesis("http://localhost:8001", skip_paths=["/api/chat", "/api/rag"])
    cmd = captured["cmd"]
    assert cmd.count("--exclude-path") == 2 and "/api/chat" in cmd


def test_schemathesis_unreachable_openapi_is_clean_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    # health-check: a down target skips with a clear reason, no st run
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/st")
    monkeypatch.setattr(live, "_reachable", lambda *a, **k: False)
    monkeypatch.setattr(live.subprocess, "run",
                        lambda *a, **k: pytest.fail("st must not run when the spec is unreachable"))
    r = live.run_schemathesis("http://localhost:8001")
    assert r.ran is False and "OpenAPI spec unreachable" in r.skip_reason


def test_schemathesis_refuses_remote_without_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    # fuzzing sends mutating traffic → hard-refused on a remote host before any st run
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/st")
    monkeypatch.setattr(live.subprocess, "run",
                        lambda cmd, **_: pytest.fail("st must not run on a refused remote target"))
    r = live.run_schemathesis("https://api.example.com")
    assert r.ran is False and "fuzzing refused" in r.skip_reason and r.findings == []


def test_schemathesis_allow_remote_bypasses_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/st")
    monkeypatch.setattr(live, "_reachable", lambda *a, **k: True)
    junit = '<testsuite><testcase name="GET /x"><failure message="Server error (500)"/></testcase></testsuite>'

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        Path(cmd[cmd.index("--report-junit-path") + 1]).write_text(junit, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 1)

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    r = live.run_schemathesis("https://api.example.com", allow_remote=True)
    assert r.ran is True and any(f.check_id == "schemathesis" for f in r.findings)


def test_load_schemathesis_skips_toml(tmp_path: Path) -> None:
    p = tmp_path / "skip.toml"
    p.write_text('[skip]\nllm = ["/api/chat"]\n', encoding="utf-8")
    assert live._load_schemathesis_skips(str(p)) == ["/api/chat"]
    assert live._load_schemathesis_skips(None) == []
    assert live._load_schemathesis_skips(str(tmp_path / "missing.toml")) == []


# --- jwt_tool ----------------------------------------------------------------


def test_jwt_tool_skips_without_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "which", lambda _name: None)
    r = live.run_jwt_tool("http://localhost:8001/api/auth")
    assert r.ran is False and "jwt_tool not installed" in r.skip_reason


def test_jwt_tool_classifies_killer_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/jwt_tool")

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            cmd, 0, stdout='jwttool_abc Response Code: 200 "alg":"none" tampering OK', stderr="")

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    r = live.run_jwt_tool("http://localhost:8001/api/auth")
    assert r.ran is True
    assert any(f.check_id == "jwt-tool" and "alg:none" in f.title for f in r.findings)


# --- zap active --------------------------------------------------------------


def test_zap_active_uses_api_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/docker")
    captured: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        wrk = Path(cmd[cmd.index("-v") + 1].rsplit(":/zap/wrk:", 1)[0])
        (wrk / "zap.json").write_text('{"site":[]}', encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    r = live.run_zap("http://localhost:8001/openapi.json", active=True, auth_header="tok")
    assert r.ran is True
    assert "zap-api-scan.py" in captured["cmd"] and "zap-baseline.py" not in captured["cmd"]
    assert any("Bearer tok" in a for a in captured["cmd"])  # replacer injected the token


def test_zap_rules_tsv_passthrough(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # --zap-rules copies the TSV into /zap/wrk and passes `-c rules.tsv`
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/docker")
    rules = tmp_path / "zap-rules.tsv"
    # a non-ASCII comment (em dash) exercises the UTF-8 read/write — would corrupt or
    # raise under a cp1252 default (Windows) if the encoding weren't pinned.
    rules.write_text("10038\tIGNORE\t(CSP — handled at the edge)\n", encoding="utf-8")
    captured: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        wrk = Path(cmd[cmd.index("-v") + 1].rsplit(":/zap/wrk:", 1)[0])
        (wrk / "zap.json").write_text('{"site":[]}', encoding="utf-8")
        copied = wrk / "rules.tsv"
        assert copied.is_file()  # copied into the mounted work dir
        assert "—" in copied.read_text(encoding="utf-8")  # UTF-8 round-trips intact
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    r = live.run_zap("http://localhost:8082", rules_tsv=str(rules))
    assert r.ran is True
    cmd = captured["cmd"]
    assert cmd[cmd.index("-c") + 1] == "rules.tsv"


def test_zap_active_refuses_remote_without_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    # the active scan (real attack payloads) is hard-refused on a remote host before docker
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(live.subprocess, "run",
                        lambda cmd, **_: pytest.fail("docker must not run on a refused remote target"))
    r = live.run_zap("https://staging.example.com", active=True)
    assert r.ran is False and "active scan refused" in r.skip_reason


def test_zap_passive_allowed_on_remote(monkeypatch: pytest.MonkeyPatch) -> None:
    # passive baseline (spider + observe only) is NOT gated — only the active scan is
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/docker")

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        wrk = Path(cmd[cmd.index("-v") + 1].rsplit(":/zap/wrk:", 1)[0])
        (wrk / "zap.json").write_text('{"site":[]}', encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    r = live.run_zap("https://staging.example.com", active=False)
    assert r.ran is True  # passive baseline runs anywhere


# --- garak / promptfoo (dynamic LLM red-team) --------------------------------


def test_garak_skips_without_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "which", lambda _name: None)
    r = live.run_garak("http://localhost:9000/generate")
    assert r.ran is False and "garak not installed" in r.skip_reason and r.findings == []


def test_garak_parses_report(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/garak")
    line = ('{"entry_type":"eval","probe":"promptinject.Hijack",'
            '"detector":"mitigation.MitigationBypass","passed":3,"total":10}')

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        prefix = cmd[cmd.index("--report_prefix") + 1]
        Path(f"{prefix}.report.jsonl").write_text(line + "\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    r = live.run_garak("http://localhost:9000/generate")
    assert r.ran is True
    assert any(f.check_id == "garak" and f.severity == "high" for f in r.findings)


def test_garak_no_report_is_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/garak")
    monkeypatch.setattr(live.subprocess, "run",
                        lambda cmd, **_: subprocess.CompletedProcess(cmd, 1))
    r = live.run_garak("http://localhost:9000/generate")
    assert r.ran is False and "no report" in r.skip_reason


def test_garak_targets_uri_via_rest_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: garak must get the endpoint URI via a -G REST config, not the
    deprecated --model_name (which since garak 0.13.1 no longer sets the URI)."""
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/garak")
    captured: dict[str, Any] = {}

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        captured["config"] = json.loads(Path(cmd[cmd.index("-G") + 1]).read_text(encoding="utf-8"))
        prefix = cmd[cmd.index("--report_prefix") + 1]
        Path(f"{prefix}.report.jsonl").write_text("", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    r = live.run_garak("http://localhost:9000/redteam")
    assert r.ran is True
    cmd = captured["cmd"]
    assert "--model_name" not in cmd  # the deprecated flag that broke targeting
    assert cmd[cmd.index("--target_type") + 1] == "rest"
    gen = captured["config"]["rest"]["RestGenerator"]
    assert gen["uri"] == "http://localhost:9000/redteam"
    assert gen["method"] == "post"
    assert gen["response_json"] is False
    # A generous read timeout so one slow target response doesn't abort the run.
    assert gen["request_timeout"] >= 60


def _capture_garak_cmd(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/garak")
    captured: dict[str, Any] = {}

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        prefix = cmd[cmd.index("--report_prefix") + 1]
        Path(f"{prefix}.report.jsonl").write_text("", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    return captured


def test_garak_defaults_are_cost_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Defaults must be cheap: generations=1 (not garak's 5) and no invalid `xss`
    probe (removed in garak 0.15.x — it aborts the whole run)."""
    captured = _capture_garak_cmd(monkeypatch)
    live.run_garak("http://localhost:9000/redteam")
    cmd = captured["cmd"]
    assert cmd[cmd.index("--generations") + 1] == "1"
    probes = cmd[cmd.index("--probes") + 1]
    assert "xss" not in probes and "promptinject" in probes


def test_garak_probes_and_generations_override(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _capture_garak_cmd(monkeypatch)
    live.run_garak("http://localhost:9000/redteam", probes="dan", generations=3)
    cmd = captured["cmd"]
    assert cmd[cmd.index("--probes") + 1] == "dan"
    assert cmd[cmd.index("--generations") + 1] == "3"


def test_promptfoo_skips_without_binary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(live, "which", lambda _name: None)
    cfg = tmp_path / "promptfooconfig.yaml"
    cfg.write_text("prompts: []\n", encoding="utf-8")
    r = live.run_promptfoo(str(cfg))
    assert r.ran is False and "promptfoo not installed" in r.skip_reason


def test_promptfoo_skips_without_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/promptfoo")
    r = live.run_promptfoo(str(tmp_path / "absent.yaml"))
    assert r.ran is False and "config not found" in r.skip_reason


def test_promptfoo_parses_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(live, "which", lambda _name: "/usr/bin/promptfoo")
    cfg = tmp_path / "promptfooconfig.yaml"
    cfg.write_text("prompts: []\n", encoding="utf-8")

    def fake_run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        out_json = Path(cmd[cmd.index("-o") + 1])
        out_json.write_text('{"results":[{"success":false,"description":"jailbreak"}]}', encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 100)

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    r = live.run_promptfoo(str(cfg))
    assert r.ran is True
    assert any(f.check_id == "promptfoo" and "jailbreak" in f.message for f in r.findings)
