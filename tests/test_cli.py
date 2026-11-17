"""Smoke tests for the CLI surface (argument wiring, not scanner behavior)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.cli import main


def _vuln_repo(root: Path) -> None:
    """A tiny repo that trips a high+ guard (command injection from request input)."""
    (root / "app.py").write_text(
        "import os\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/x')\n"
        "def h(cmd: str):\n"
        "    os.system(cmd)\n", encoding="utf-8"
    )


def test_doctor_runs_and_reports(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["doctor"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Deterministic scanners" in out
    assert "Live scanners" in out
    # every deterministic runner id is listed
    for rid in ("bandit", "semgrep", "pip-audit", "gitleaks", "trivy", "hadolint", "node-audit"):
        assert rid in out
    # live prerequisites listed
    assert "docker" in out and "psql" in out


def test_doctor_shows_registry_staleness_stamp(capsys: pytest.CaptureFixture[str]) -> None:
    # RFC #253 Phase 1 — plain doctor states registry age, no markdown emphasis markers
    # (doctor's other lines are plain text; the audit/coverage meta line uses `_..._`).
    main(["doctor"])
    out = capsys.readouterr().out
    assert "Checklist registry:" in out and "released" in out
    assert "days old" in out or "day old" in out
    assert "_Checklist registry:_" not in out


def test_registry_stamp_reports_age_from_released_date() -> None:
    from agentsec.cli import _registry_stamp

    stamp = _registry_stamp()
    assert "_Checklist registry:_ v" in stamp
    assert "sha256" in stamp
    assert "released" in stamp
    assert "days old" in stamp or "day old" in stamp


def test_registry_stamp_plain_has_no_markdown_emphasis() -> None:
    # doctor's plain-text caller uses markdown=False — the label must lose its `_..._` emphasis
    # without stripping every underscore (the old .replace("_","") was a landmine). (PR #265 review)
    from agentsec.cli import _registry_stamp

    plain = _registry_stamp(markdown=False)
    assert plain.startswith("Checklist registry: v")
    assert "_" not in plain.split(" old")[0]  # no stray emphasis markers in the stamp body


def test_registry_stamp_matches_coverage_stamp_line() -> None:
    # cli._registry_stamp and coverage._stamp_line are duplicated copies (a cli->coverage import
    # cycle blocks sharing) — nothing but this parity test stops them drifting in wording/spacing/
    # sha-slice/plural. They must render byte-identical for the same registry. (PR #265 review, Medium)
    from pathlib import Path

    from agentsec.cli import _registry_stamp
    from agentsec.coverage import _stamp_line, coverage

    result = coverage(Path(__file__).resolve().parents[1])  # real checklist version/sha/released/age
    assert _stamp_line(result) == _registry_stamp()


def test_help_lists_all_commands(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    for cmd in ("detect", "audit", "scan", "trifecta", "live", "doctor", "setup"):
        assert cmd in out


def test_audit_help_discloses_semgrep_degradation_under_deterministic(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """#863: --deterministic's --help must disclose EVERY coverage consequence a CI author
    weighs before a run — including that the tier-0 cap drops semgrep to its local pack (the
    OSS registry packs, hundreds of rules, are a network fetch). The help enumerated only the
    four *excluded* live-advisory scanners, hiding this fifth *degradation*. semgrep still runs,
    so it must NOT be listed among the excluded scanners — assert the separate degradation
    clause, not a longer exclusion list."""
    with pytest.raises(SystemExit):
        main(["audit", "--help"])
    out = capsys.readouterr().out
    assert "semgrep" in out
    assert "local LLM/agent pack only" in out
    # the OSS registry packs are named so the reader can look up what coverage they lose
    for pack in ("p/python", "p/owasp-top-ten", "p/secrets"):
        assert pack in out


def test_doctor_help_does_not_call_check_updates_fetch_public(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """#645: versions.json sits in a private repo until the public launch, so `--help` calling
    the --check-updates fetch "public" was false. This is the third copy of the runtime/preview
    disclosure (bound in test_update_check), so it gets its own pin. Whitespace is normalized
    because argparse rewraps help to the terminal width."""
    with pytest.raises(SystemExit):
        main(["doctor", "--help"])
    out = " ".join(capsys.readouterr().out.split())
    assert "Tier-1 unauthenticated fetch" in out  # anchor: we are reading the right help text
    assert "public fetch" not in out


def test_doctor_lists_llm_redteam_live_tools(capsys: pytest.CaptureFixture[str]) -> None:
    main(["doctor"])
    out = capsys.readouterr().out
    assert "garak" in out and "promptfoo" in out


def test_live_garak_promptfoo_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from agentsec import live
    from agentsec.findings import Finding

    monkeypatch.setattr(
        live, "run_garak",
        lambda url, **_: live.LiveResult(
            "garak", True, findings=[Finding(check_id="garak", severity="high", title="probe failed")]
        ),
    )
    monkeypatch.setattr(
        live, "run_promptfoo",
        lambda cfg, **_: live.LiveResult("promptfoo", False, skip_reason="promptfoo not installed"),
    )
    rc = main([
        "live", str(tmp_path), "--guards-only", "--no-fail",
        "--garak-target", "http://localhost:9000/generate",
        "--promptfoo-config", "promptfooconfig.yaml",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "garak (http://localhost:9000/generate)" in out and "ran" in out
    assert "promptfoo (promptfooconfig.yaml)" in out and "skipped" in out


def test_live_garak_cost_flags_passthrough(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--garak-probes / --garak-generations must reach run_garak so CI can bound cost."""
    from agentsec import live

    captured: dict[str, object] = {}

    def fake_garak(url: str, **kwargs: object) -> live.LiveResult:
        captured["url"] = url
        captured["kwargs"] = kwargs
        return live.LiveResult("garak", True, findings=[])

    monkeypatch.setattr(live, "run_garak", fake_garak)
    main([
        "live", str(tmp_path), "--live-only", "--no-fail",
        "--garak-target", "http://localhost:9000/x",
        "--garak-probes", "promptinject",
        "--garak-generations", "1",
    ])
    assert captured["url"] == "http://localhost:9000/x"
    assert captured["kwargs"] == {"probes": "promptinject", "generations": 1}


def test_live_no_flags_prints_notice(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["live", str(tmp_path), "--guards-only", "--no-fail"])
    err = capsys.readouterr().err
    assert "nothing live to run" in err


def test_audit_prints_ci_one_liner(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "app.py").write_text("import os\ndef h(c):\n    os.system(c)\n", encoding="utf-8")  # critical
    rc = main(["audit", str(tmp_path), "--guards-only"])  # default fail-on high
    err = capsys.readouterr().err
    assert rc == 1
    assert "agentsec:" in err and "FAIL" in err and "gate ≥high" in err


def test_audit_top_n_caps_detail_list(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # FastAPI + os.system trips several guards (command-injection + api-docs + headers)
    (tmp_path / "app.py").write_text(
        "import os\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/x')\n"
        "def h(cmd: str):\n"
        "    os.system(cmd)\n", encoding="utf-8"
    )
    main(["audit", str(tmp_path), "--guards-only", "--no-fail", "--top", "1"])
    out = capsys.readouterr().out
    assert "### Summary by check" in out  # full tally retained
    assert "showing 1 of" in out          # honest truncation marker


# --- Theme 5: one run → all artifacts -------------------------------------


def test_sarif_out_emits_both_from_one_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--sarif-out writes a SARIF artifact alongside the human --out report (one run)."""
    _vuln_repo(tmp_path)
    md = tmp_path / "report.md"
    sarif = tmp_path / "report.sarif"
    rc = main([
        "audit", str(tmp_path), "--guards-only", "--no-fail",
        "--out", str(md), "--sarif-out", str(sarif),
    ])
    assert rc == 0
    assert md.is_file() and sarif.is_file()
    assert "## Security findings" in md.read_text(encoding="utf-8")
    data = json.loads(sarif.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0" and data["runs"][0]["results"]  # real SARIF with results


# --- repo-relative SARIF + GitHub annotations (the composite action's inputs) ---------------

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _sarif_uris(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in data["runs"][0]["results"] if "locations" in r
    ]


def test_subdirectory_scan_from_the_repo_root_writes_repo_relative_sarif_uris(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`agentsec audit tests/fixtures/saas_sample` run from the checkout root: every uri must
    resolve against the checkout (where code scanning and annotations look), not the scan root."""
    monkeypatch.chdir(_REPO_ROOT)
    sarif = tmp_path / "a.sarif"
    main(["audit", "tests/fixtures/saas_sample", "--guards-only", "--no-fail",
          "--out", str(tmp_path / "r.md"), "--sarif-out", str(sarif)])
    uris = _sarif_uris(sarif)
    assert uris, "the saas_sample fixture must produce located findings"
    assert all(u.startswith("tests/fixtures/saas_sample") for u in uris), uris
    assert all((_REPO_ROOT / u).exists() for u in uris), "a prefixed uri must name a real path"


def test_scan_root_outside_the_cwd_keeps_scan_root_relative_uris(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The direction traded against: a root that is the cwd, or lies outside it, has no
    repo-relative spelling to add, so its uris stay exactly as before (no prefix)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _vuln_repo(repo)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    for cwd, target in ((elsewhere, str(repo)), (repo, ".")):
        monkeypatch.chdir(cwd)
        sarif = tmp_path / "out.sarif"
        main(["audit", target, "--guards-only", "--no-fail", "--format", "sarif", "--out", str(sarif)])
        uris = _sarif_uris(sarif)
        assert "app.py" in uris, (cwd, uris)
        assert not any(u.startswith(("repo/", "elsewhere/", "..")) for u in uris), (cwd, uris)


def test_annotations_print_workflow_commands_after_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sub = tmp_path / "svc"
    sub.mkdir()
    _vuln_repo(sub)
    monkeypatch.chdir(tmp_path)
    main(["audit", "svc", "--guards-only", "--no-fail", "--annotations", "2"])
    out = capsys.readouterr().out
    commands = [ln for ln in out.splitlines() if ln.startswith("::")]
    assert len(commands) == 2
    assert commands[0].startswith("::error file=svc/app.py,line=")
    assert out.index("## Security findings") < out.index(commands[0])  # after the report


def test_annotations_zero_and_unset_print_no_workflow_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _vuln_repo(tmp_path)
    for extra in (["--annotations", "0"], []):
        main(["audit", str(tmp_path), "--guards-only", "--no-fail", *extra])
        captured = capsys.readouterr()
        assert not any(ln.startswith("::") for ln in (captured.out + captured.err).splitlines()), extra


def test_annotations_rejects_a_negative_count(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["audit", ".", "--annotations", "-1"])
    assert "must be 0 or more" in capsys.readouterr().err


def test_annotations_skip_baselined_findings_and_keep_new_ones(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Both directions: a finding a --baseline-snapshot accepted is still in the report but is
    NOT annotated onto the PR; a finding new since the snapshot is."""
    _vuln_repo(tmp_path)
    snap = tmp_path / "snap.json"
    main(["audit", str(tmp_path), "--guards-only", "--save-snapshot", str(snap), "--no-fail"])
    capsys.readouterr()

    main(["audit", str(tmp_path), "--guards-only", "--baseline-snapshot", str(snap),
          "--no-fail", "--annotations", "50"])
    out = capsys.readouterr().out
    assert "app.py" in out, "the baselined finding stays visible in the report"
    assert not [ln for ln in out.splitlines() if ln.startswith("::")], "nothing new to annotate"

    (tmp_path / "more.py").write_text("import os\ndef g(c: str):\n    os.system(c)\n", encoding="utf-8")
    main(["audit", str(tmp_path), "--guards-only", "--baseline-snapshot", str(snap),
          "--no-fail", "--annotations", "50"])
    commands = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("::")]
    assert commands and all("more.py" in ln for ln in commands), commands


def test_annotations_stay_off_stdout_when_stdout_is_the_sarif_document(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--format sarif` with no `--out` prints the SARIF document itself; annotations then go to
    stderr so a consumer piping stdout still receives valid JSON."""
    _vuln_repo(tmp_path)
    main(["audit", str(tmp_path), "--guards-only", "--no-fail", "--format", "sarif", "--annotations", "3"])
    captured = capsys.readouterr()
    assert json.loads(captured.out)["version"] == "2.1.0"
    assert any(ln.startswith("::error ") for ln in captured.err.splitlines())


def test_scan_writes_all_artifacts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _vuln_repo(tmp_path)
    out_dir = tmp_path / "out"
    rc = main(["scan", str(tmp_path), "--guards-only", "--out-dir", str(out_dir), "--no-fail"])
    assert rc == 0
    for name in ("detect.txt", "audit.md", "audit.sarif", "agentsec-exceptions.json"):
        assert (out_dir / name).is_file(), f"missing {name}"
    # the scaffolded registry is a valid, empty exceptions file
    assert json.loads((out_dir / "agentsec-exceptions.json").read_text(encoding="utf-8")) == {"exceptions": []}
    # honest-coverage footer travels into the written report
    assert "_Skipped (N/A for this stack):_" in (out_dir / "audit.md").read_text(encoding="utf-8")
    # SARIF is real
    assert json.loads((out_dir / "audit.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_scan_does_not_clobber_existing_exceptions(tmp_path: Path) -> None:
    """If the repo already has agentsec-exceptions.json, scan must not scaffold over it."""
    _vuln_repo(tmp_path)
    existing = {"exceptions": [{"rule": "command-injection", "reason": "mine", "review_by": "2099-01-01"}]}
    (tmp_path / "agentsec-exceptions.json").write_text(json.dumps(existing), encoding="utf-8")
    out_dir = tmp_path / "out"
    main(["scan", str(tmp_path), "--guards-only", "--out-dir", str(out_dir), "--no-fail"])
    # no starter scaffold written into the out-dir (the repo already manages exceptions)
    assert not (out_dir / "agentsec-exceptions.json").exists()
    # and the user's file is untouched
    assert json.loads((tmp_path / "agentsec-exceptions.json").read_text(encoding="utf-8")) == existing


def test_scan_honors_fail_gate(tmp_path: Path) -> None:
    """scan is CI-usable: a high+ finding fails the run unless --no-fail."""
    _vuln_repo(tmp_path)  # eval → command-injection (high/critical)
    out_dir = tmp_path / "out"
    rc = main(["scan", str(tmp_path), "--guards-only", "--out-dir", str(out_dir)])
    assert rc == 1
    rc_nofail = main(["scan", str(tmp_path), "--guards-only", "--out-dir", str(out_dir), "--no-fail"])
    assert rc_nofail == 0


def test_auth_token_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    """_resolve_api_token: --api-token > --auth-cmd > --supabase-login (env fallback)."""
    import argparse

    from agentsec import live
    from agentsec.cli import _resolve_api_token

    monkeypatch.setattr(live, "mint_token_cmd", lambda cmd, **_: "cmd-tok")
    monkeypatch.setattr(live, "mint_supabase_token", lambda *a, **k: "sb-tok")

    base = {"api_token": None, "auth_cmd": None, "supabase_login": False,
            "supabase_url": None, "supabase_anon_key": None,
            "supabase_email": None, "supabase_password": None}
    assert _resolve_api_token(argparse.Namespace(**{**base, "api_token": "pre"})) == "pre"
    assert _resolve_api_token(argparse.Namespace(**{**base, "auth_cmd": "echo x"})) == "cmd-tok"
    assert _resolve_api_token(argparse.Namespace(**{**base, "supabase_login": True})) == "sb-tok"
    assert _resolve_api_token(argparse.Namespace(**base)) == ""   # unauthenticated default


def test_live_auth_cmd_token_reaches_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A token minted by --auth-cmd is injected into the live scanner call."""
    from agentsec import live

    monkeypatch.setattr(live, "mint_token_cmd", lambda cmd, **_: "minted-jwt")
    captured: dict[str, object] = {}

    def fake_jwt(url: str, **kwargs: object) -> live.LiveResult:
        captured.update(kwargs)
        return live.LiveResult("jwt-tool", True, findings=[])

    monkeypatch.setattr(live, "run_jwt_tool", fake_jwt)
    main([
        "live", str(tmp_path), "--live-only", "--no-fail",
        "--jwt-url", "http://localhost:8001/api/me", "--auth-cmd", "mint.sh",
    ])
    assert captured["token"] == "minted-jwt"


def test_live_remote_db_refused_without_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A remote --db-url is refused non-interactively; run_splinter receives
    allow_remote=False and the warning names the host (not the secret)."""
    from agentsec import live

    captured: dict[str, object] = {}

    def fake_splinter(db_url: str, **kwargs: object) -> live.LiveResult:
        captured.update(kwargs)
        return live.LiveResult("splinter", False, skip_reason="remote database — refused")

    monkeypatch.setattr(live, "run_splinter", fake_splinter)
    rc = main([
        "live", str(tmp_path), "--guards-only", "--no-fail",
        "--db-url", "postgresql://postgres:sup3rsecret@db.abcd.supabase.co:5432/postgres",
    ])
    err = capsys.readouterr().err
    assert rc == 0
    assert captured["allow_remote"] is False
    assert "refused" in err and "db.abcd.supabase.co" in err
    assert "sup3rsecret" not in err  # never leak the DSN password


def test_live_remote_db_allowed_with_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from agentsec import live

    captured: dict[str, object] = {}

    def fake_splinter(db_url: str, **kwargs: object) -> live.LiveResult:
        captured.update(kwargs)
        return live.LiveResult("splinter", True, findings=[])

    monkeypatch.setattr(live, "run_splinter", fake_splinter)
    main([
        "live", str(tmp_path), "--guards-only", "--no-fail", "--allow-remote-db",
        "--db-url", "postgresql://postgres:pw@db.abcd.supabase.co:5432/postgres",
    ])
    assert captured["allow_remote"] is True
    assert "proceeding" in capsys.readouterr().err


def test_live_remote_intrusive_refused_without_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Schemathesis fuzzing against a remote target is hard-refused (no prompt)."""
    from agentsec import live

    captured: dict[str, object] = {}

    def fake_st(base_url: str, **kwargs: object) -> live.LiveResult:
        captured.update(kwargs)
        return live.LiveResult("schemathesis", False, skip_reason="refused")

    monkeypatch.setattr(live, "run_schemathesis", fake_st)
    main([
        "live", str(tmp_path), "--live-only", "--no-fail",
        "--schemathesis-url", "https://api.example.com",
    ])
    err = capsys.readouterr().err
    assert captured["allow_remote"] is False
    assert "Refusing intrusive scan" in err and "--allow-remote-target" in err


def test_live_local_target_no_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A local target proceeds silently — no remote warning, allow_remote irrelevant."""
    from agentsec import live

    captured: dict[str, object] = {}

    def fake_splinter(db_url: str, **kwargs: object) -> live.LiveResult:
        captured.update(kwargs)
        return live.LiveResult("splinter", True, findings=[])

    monkeypatch.setattr(live, "run_splinter", fake_splinter)
    main([
        "live", str(tmp_path), "--guards-only", "--no-fail",
        "--db-url", "postgresql://postgres:postgres@localhost:54322/postgres",
    ])
    err = capsys.readouterr().err
    assert captured["allow_remote"] is True   # local → consent granted automatically
    assert "REMOTE" not in err


def test_live_remote_db_interactive_confirm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a TTY, a read-only remote DB lint may be confirmed interactively."""
    from agentsec import live

    captured: dict[str, object] = {}
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")

    def fake_splinter(db_url: str, **kwargs: object) -> live.LiveResult:
        captured.update(kwargs)
        return live.LiveResult("splinter", True, findings=[])

    monkeypatch.setattr(live, "run_splinter", fake_splinter)
    main([
        "live", str(tmp_path), "--guards-only", "--no-fail",
        "--db-url", "postgresql://postgres:pw@db.abcd.supabase.co:5432/postgres",
    ])
    assert captured["allow_remote"] is True   # interactive "y" granted consent


def test_ai_bom_command_json_and_out(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`ai-bom` prints a JSON inventory (rc 0) and `--out` writes a round-trippable file."""
    (tmp_path / "agent.py").write_text("from openai import OpenAI\nMODEL='gpt-4o'\n", encoding="utf-8")
    rc = main(["ai-bom", str(tmp_path)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert "OpenAI" in {p["name"] for p in payload["providers"]}
    assert "gpt-4o" in {m["name"] for m in payload["models"]}

    out_file = tmp_path / "bom.json"
    rc2 = main(["ai-bom", str(tmp_path), "--out", str(out_file)])
    assert rc2 == 0
    assert json.loads(out_file.read_text(encoding="utf-8"))["component_count"] >= 2


def test_detect_surfaces_db_locality(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`detect` reads env files and prints the DB target's locality (host only)."""
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text(
        "DATABASE_URL=postgresql://postgres:sup3rsecret@db.abcd.supabase.co:5432/postgres\n"
        "SUPABASE_URL=https://abcd.supabase.co\n", encoding="utf-8"
    )
    rc = main(["detect", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "db target [DATABASE_URL]: remote (db.abcd.supabase.co" in out
    assert "hosted Supabase project" in out
    assert "sup3rsecret" not in out   # never print the DSN password


def test_exclude_drops_matching_findings() -> None:
    """audit(excludes=...) drops findings whose path matches a dir / prefix / glob /
    bare-segment pattern, recording them in `.excluded` (no silent truncation)."""
    from agentsec.audit import _matches_excludes, audit
    from agentsec.findings import Finding

    fs = [
        Finding(check_id="g", severity="high", title="a", location="src/app.py:10"),
        Finding(check_id="g", severity="high", title="b", location="tests/test_x.py:3"),
        Finding(check_id="g", severity="high", title="c", location="frontend/dist/bundle.js:1"),
        Finding(check_id="g", severity="high", title="d", location="src/util.py"),
    ]
    # unit-level pattern semantics
    assert _matches_excludes("tests/test_x.py:3", ["tests"])           # bare segment
    assert _matches_excludes("frontend/dist/bundle.js:1", ["frontend/dist"])  # prefix dir
    assert _matches_excludes("src/app.py:10", ["*.py"])                 # glob
    assert not _matches_excludes("src/app.py:10", ["docs"])
    assert not _matches_excludes("", ["tests"])

    # end-to-end through audit() — empty repo, so only the injected findings exist
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        r = audit(Path(d), run_scanners=False, skip_static=True,
                  extra_findings=fs, excludes=["tests", "frontend/dist"])
    kept = {f.title for f in r.findings}
    assert kept == {"a", "d"}                          # tests/ and dist/ dropped
    assert {f.title for f in r.excluded} == {"b", "c"}


def test_exclude_cli_reports_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--exclude` on the live CLI drops the matching live finding and notes the count."""
    from agentsec import live
    from agentsec.findings import Finding

    monkeypatch.setattr(
        live, "run_garak",
        lambda url, **_: live.LiveResult(
            "garak", True,
            findings=[Finding(check_id="garak", severity="high", title="p",
                              location="vendor/thirdparty/x.py:1")],
        ),
    )
    rc = main([
        "live", str(tmp_path), "--live-only", "--no-fail", "--exclude", "vendor",
        "--garak-target", "http://localhost:9000/generate",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Excluded by --exclude" in out and "1 finding" in out


def test_audit_skip_static_reports_only_live_findings(tmp_path: Path) -> None:
    """--live-only (skip_static) bypasses every static guard/scanner and reports
    only the merged live findings, still applying the exception registry."""
    from agentsec.audit import audit
    from agentsec.findings import Finding

    (tmp_path / "app.py").write_text("import os\nx = os.system('echo hi')\n", encoding="utf-8")  # would trip guards
    live_finding = Finding(check_id="garak", severity="high", title="probe failed")
    r = audit(tmp_path, extra_findings=[live_finding], skip_static=True)
    assert r.ran == [] and r.skipped == []           # no static guards/scanners ran
    assert [f.check_id for f in r.findings] == ["garak"]   # only the live finding survives


def test_live_only_skips_static_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from agentsec import live
    from agentsec.findings import Finding

    monkeypatch.setattr(
        live, "run_garak",
        lambda url, **_: live.LiveResult(
            "garak", True, findings=[Finding(check_id="garak", severity="high", title="probe failed")]
        ),
    )
    rc = main([
        "live", str(tmp_path), "--live-only", "--no-fail",
        "--garak-target", "http://localhost:9000/generate",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "garak (http://localhost:9000/generate)" in out and "ran" in out
    assert "_Checks run:_ none" in out   # static audit was skipped


# --- suggest-excludes (exclude advisor) ---

def _advisor_repo(root: Path) -> None:
    (root / "app").mkdir()
    (root / "app" / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    (root / "evals").mkdir()
    (root / "evals" / "test_judge.py").write_text("def test_x(): ...\n", encoding="utf-8")
    (root / "evals" / "conftest.py").write_text("import pytest\n", encoding="utf-8")


def test_suggest_excludes_dry_run_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _advisor_repo(tmp_path)
    rc = main(["suggest-excludes", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Suggested non-product directories" in out
    assert "evals" in out and "nonproduct_paths" in out
    assert not (tmp_path / ".agentsec").exists()  # advisory: nothing written


def test_suggest_excludes_write_yes_persists(tmp_path: Path) -> None:
    from agentsec.config import load_repo_config
    _advisor_repo(tmp_path)
    rc = main(["suggest-excludes", str(tmp_path), "--write", "--yes"])
    assert rc == 0
    assert "evals" in load_repo_config(tmp_path).nonproduct_segments


def test_suggest_excludes_write_refuses_without_yes_noninteractive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _advisor_repo(tmp_path)
    rc = main(["suggest-excludes", str(tmp_path), "--write"])  # pytest stdin is not a TTY
    err = capsys.readouterr().err
    assert rc == 1
    assert "Refusing to write" in err
    assert not (tmp_path / ".agentsec").exists()


def test_suggest_excludes_json_format(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _advisor_repo(tmp_path)
    rc = main(["suggest-excludes", str(tmp_path), "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert any(c["directory"] == "evals" and c["kind"] == "demote" for c in data)


def test_suggest_excludes_accept_subset_persists(tmp_path: Path) -> None:
    from agentsec.config import load_repo_config
    _advisor_repo(tmp_path)
    rc = main(["suggest-excludes", str(tmp_path), "--write", "--accept", "evals"])
    assert rc == 0
    assert "evals" in load_repo_config(tmp_path).nonproduct_segments


def test_suggest_excludes_accept_implies_write(tmp_path: Path) -> None:
    from agentsec.config import load_repo_config
    _advisor_repo(tmp_path)
    rc = main(["suggest-excludes", str(tmp_path), "--accept", "evals"])  # no explicit --write
    assert rc == 0
    assert "evals" in load_repo_config(tmp_path).nonproduct_segments


def test_suggest_excludes_accept_noninteractive_no_tty_ok(tmp_path: Path) -> None:
    # --accept (explicit named subset) must NOT hit the TTY refusal that bare --write does
    # (pytest stdin is not a TTY).
    from agentsec.config import load_repo_config
    _advisor_repo(tmp_path)
    rc = main(["suggest-excludes", str(tmp_path), "--accept", "evals"])
    assert rc == 0
    assert "evals" in load_repo_config(tmp_path).nonproduct_segments


def test_suggest_excludes_accept_unknown_name_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _advisor_repo(tmp_path)
    rc = main(["suggest-excludes", str(tmp_path), "--accept", "does-not-exist"])
    err = capsys.readouterr().err
    # NON-ZERO: a --accept that matched nothing is a failed request, not a silent no-op. Exiting 0
    # let a typo read as "the repo is primed" to the caller (#478 review — this test previously
    # enshrined that fail-open).
    assert rc == 1
    assert "skipped: does-not-exist" in err
    assert not (tmp_path / ".agentsec").exists()  # nothing accepted -> no write


def test_suggest_excludes_accept_blank_writes_nothing(tmp_path: Path) -> None:
    # A whitespace/comma-only --accept normalizes to an empty set and must write NOTHING
    # (never fall back to accept-all) — the core "typo'd/empty set is safe" guarantee. It also
    # exits non-zero: an unset shell variable expanding to `--accept ""` is a caller mistake.
    _advisor_repo(tmp_path)
    for blank in (" , ", ""):
        rc = main(["suggest-excludes", str(tmp_path), "--accept", blank])
        assert rc == 1, blank
        assert not (tmp_path / ".agentsec").exists()


def test_suggest_excludes_accept_precedence_over_yes(tmp_path: Path) -> None:
    # A named subset wins over --yes: only the named dir is written, not accept-all.
    from agentsec.config import load_repo_config
    _advisor_repo(tmp_path)
    # Second qualifying candidate (structural .ipynb shape + name hint) that must be EXCLUDED.
    (tmp_path / "notebooks").mkdir()
    (tmp_path / "notebooks" / "a.ipynb").write_text("{}\n", encoding="utf-8")
    (tmp_path / "notebooks" / "b.ipynb").write_text("{}\n", encoding="utf-8")
    rc = main(["suggest-excludes", str(tmp_path), "--yes", "--accept", "evals"])
    assert rc == 0
    cfg = load_repo_config(tmp_path)
    assert "evals" in cfg.nonproduct_segments
    assert "notebooks" not in cfg.nonproduct_segments  # --accept subset, NOT accept-all


def test_suggest_excludes_discloses_builtin_demoted_trees(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """#716: the proactive listing must not silently omit the hardwired Layer-1 trees. Layer 1 only
    rank-demotes external-scanner findings (never drops), so on a real repo the tests/ tree can be
    the report's dominant noise source while the advisor reads as "nothing left to reduce"."""
    _advisor_repo(tmp_path)
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("def test_a(): ...\n", encoding="utf-8")
    rc = main(["suggest-excludes", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Built-in demoted trees" in out and "tests" in out
    assert "still count" in out


def test_suggest_excludes_no_disclosure_without_builtin_trees(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # FP-bait for the disclosure: a repo with no Layer-1 tree gets no extra line.
    _advisor_repo(tmp_path)
    rc = main(["suggest-excludes", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Built-in demoted trees" not in out


def test_accept_builtin_name_in_nonproduct_config_still_gets_honest_wording(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """#724 review (Critical): `built-in+nonproduct_paths` is still demote-only (that config entry
    is a no-op for a Layer-1 tree), so the pre-fix "nothing to do" must not resurface for the
    combined tier: that is the #716 reporter's exact config state."""
    _two_candidate_repo(tmp_path)
    (tmp_path / "migrations").mkdir()
    (tmp_path / "migrations" / "0001_init.sql").write_text("select 1;\n", encoding="utf-8")
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir(exist_ok=True)
    cfg.write_text(json.dumps({"nonproduct_paths": ["migrations"]}) + "\n", encoding="utf-8")
    assert main(["suggest-excludes", str(tmp_path), "--accept", "migrations"]) == 0
    out = capsys.readouterr().out
    assert "Already rank-demoted by the built-in conventions: migrations" in out
    assert "nothing to do" not in out


def test_accept_builtin_name_in_archive_config_is_genuinely_nothing_to_do(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # FP-bait for the honest-wording split: with the ARCHIVE tier in effect the drop is real, so
    # "nothing to do" is a true statement and must stay.
    _two_candidate_repo(tmp_path)
    (tmp_path / "migrations").mkdir()
    (tmp_path / "migrations" / "0001_init.sql").write_text("select 1;\n", encoding="utf-8")
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir(exist_ok=True)
    cfg.write_text(json.dumps({"archive_paths": ["migrations"]}) + "\n", encoding="utf-8")
    assert main(["suggest-excludes", str(tmp_path), "--accept", "migrations"]) == 0
    assert "Already non-product, nothing to do: migrations" in capsys.readouterr().out


def test_audit_suggest_excludes_reactive(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _advisor_repo(tmp_path)
    rc = main(["audit", str(tmp_path), "--guards-only", "--no-fail", "--suggest-excludes"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Suggested non-product directories" in out and "evals" in out


def test_network_subcommand_default_tier0(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["network", "."])
    out = capsys.readouterr().out
    assert rc == 0
    assert "TIER 0" in out and "Nothing leaves your machine" in out
    assert "--kev" in out and "needs tier 1" in out          # blocked at tier 0


def test_network_do_not_track_forces_tier0(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setenv("DO_NOT_TRACK", "1")
    main(["network", ".", "--network", "tier2"])             # explicit tier2 …
    assert "TIER 0" in capsys.readouterr().out               # … overridden by DO_NOT_TRACK


def test_audit_kev_offline_notes_skip(tmp_path: Path, monkeypatch, capsys) -> None:
    """--kev with DO_NOT_TRACK → tier 0 → KEV skipped with a clear note (audit still runs)."""
    monkeypatch.setenv("DO_NOT_TRACK", "1")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    rc = main(["audit", str(tmp_path), "--guards-only", "--no-fail", "--kev"])
    assert rc == 0
    assert "KEV enrichment skipped" in capsys.readouterr().err


def test_audit_epss_offline_notes_skip(tmp_path: Path, monkeypatch, capsys) -> None:
    """--epss with DO_NOT_TRACK → tier 0 → EPSS skipped with a clear note (audit still runs)."""
    monkeypatch.setenv("DO_NOT_TRACK", "1")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    rc = main(["audit", str(tmp_path), "--guards-only", "--no-fail", "--epss"])
    assert rc == 0
    assert "EPSS enrichment skipped" in capsys.readouterr().err


def test_audit_kev_and_epss_offline_notes_skip_both(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("DO_NOT_TRACK", "1")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    rc = main(["audit", str(tmp_path), "--guards-only", "--no-fail", "--kev", "--epss"])
    assert rc == 0
    assert "KEV + EPSS enrichment skipped" in capsys.readouterr().err


def test_deterministic_discloses_the_effective_tier_not_the_resolved_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """Review #609 M1 (a regression from the H4 fix): H4 moved the KEV/EPSS *gate* onto the
    deterministic-capped `profile.network_tier` but left the *disclosure* on the raw resolved
    tier. So `--deterministic --network tier1 --epss` printed a TIER 1 manifest claiming the
    user's CVE profile had been sent to api.first.org, while the fetch never happened and nothing
    said the enrichment was skipped — the manifest is the privacy contract, and it was wrong in
    the direction of over-claiming egress while under-reporting a silent no-op."""
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    rc = main(["audit", str(tmp_path), "--guards-only", "--no-fail",
               "--deterministic", "--network", "tier1", "--kev", "--epss"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "KEV + EPSS enrichment skipped" in err        # the truth: nothing was fetched
    assert "api.first.org" not in err                    # no egress was claimed...
    assert "www.cisa.gov" not in err
    assert "TIER 1" not in err                           # ...and no tier-1 manifest was printed


def test_non_deterministic_tier1_still_discloses_the_manifest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """The direction traded against: suppressing the disclosure under `--deterministic` must not
    also suppress it on the ordinary `--network tier1` path, where the egress really does happen
    and the manifest is the only thing that tells the user what leaves."""
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    rc = main(["audit", str(tmp_path), "--guards-only", "--no-fail",
               "--network", "tier1", "--kev", "--epss"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "TIER 1" in err
    assert "api.first.org" in err and "www.cisa.gov" in err
    assert "enrichment skipped" not in err


def test_deterministic_runtime_note_discloses_semgrep_degradation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """#863 (class-consistency): the runtime `deterministic mode:` note enumerated only the four
    excluded live-advisory scanners, matching the stale --help. It must also state that semgrep
    is degraded to its local pack — same misleading enumeration, same fix."""
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    rc = main(["audit", str(tmp_path), "--guards-only", "--no-fail", "--deterministic"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "deterministic mode:" in err
    assert "semgrep runs its local LLM/agent pack only" in err


def test_live_rejects_kev_flag(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Review #609 M1: `live` used to silently accept --kev/--epss and do nothing with them (a
    # "failure that presents as success" — the user asked for enrichment, got a clean report with
    # none, and nothing told them). Rejecting the flag outright is the safer failure mode.
    with pytest.raises(SystemExit):
        main(["live", str(tmp_path), "--kev"])
    assert "unrecognized argument" in capsys.readouterr().err.lower()


def test_live_rejects_epss_flag(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["live", str(tmp_path), "--epss"])
    assert "unrecognized argument" in capsys.readouterr().err.lower()


def test_network_subcommand_lists_epss_blocked_at_tier0(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["network", "."])
    out = capsys.readouterr().out
    assert rc == 0
    assert "--epss" in out and "needs tier 1" in out          # blocked at tier 0


def test_python_dash_m_agentsec_runs() -> None:
    """`python -m agentsec` works (F6: agentsec/__main__.py delegates to cli.main)."""
    import subprocess
    import sys
    r = subprocess.run([sys.executable, "-m", "agentsec", "--help"],
                       capture_output=True, text=True)
    assert r.returncode == 0
    assert "agentsec" in (r.stdout + r.stderr)


# --------------------------------------------------------------------------- #
# `ci add --with-baseline` confirmation (Marconi #176): a baseline must not
# silently accept existing HIGH/CRITICAL findings on first install.
# --------------------------------------------------------------------------- #

class _FakeStdin:
    def __init__(self, tty: bool) -> None:
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _bf(severity: str, loc: str = "src/app.py:1"):
    from agentsec.findings import Finding
    return Finding(check_id="g", severity=severity, title=f"{severity} thing", location=loc,
                   rule=f"g/{severity}")


def test_confirm_baseline_no_high_proceeds(capsys: pytest.CaptureFixture[str]) -> None:
    from agentsec.cli import _confirm_baseline
    assert _confirm_baseline([_bf("low"), _bf("medium")], accept_all=False) is True
    out = capsys.readouterr().out
    assert "2 finding(s)" in out and "1 MEDIUM" in out and "1 LOW" in out


def test_confirm_baseline_high_refused_non_interactively(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentsec.cli import _confirm_baseline
    monkeypatch.setattr("sys.stdin", _FakeStdin(False))
    assert _confirm_baseline([_bf("high"), _bf("critical"), _bf("low")], accept_all=False) is False
    err = capsys.readouterr().err
    assert "HIGH/CRITICAL" in err and "Refusing" in err


def test_confirm_baseline_high_accepted_with_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentsec.cli import _confirm_baseline
    monkeypatch.setattr("sys.stdin", _FakeStdin(False))  # CI: no tty
    assert _confirm_baseline([_bf("high")], accept_all=True) is True


def test_confirm_baseline_high_accepted_interactively(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentsec.cli import _confirm_baseline
    monkeypatch.setattr("sys.stdin", _FakeStdin(True))
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    assert _confirm_baseline([_bf("high")], accept_all=False) is True


def test_audit_baseline_snapshot_ratchets_on_new_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--baseline-snapshot keeps existing findings VISIBLE in the report but excludes them
    from the --fail-on gate; a NEW finding (not in the snapshot) still fails CI. This is the
    ratchet model that replaced the suppress-existing baseline (Marconi #176)."""
    (tmp_path / "app.py").write_text(
        "import os\n"
        "def h(cmd: str):\n"
        "    os.system(cmd)\n",            # command-injection — the existing finding
        encoding="utf-8",
    )
    snap = tmp_path / "agentsec-baseline.json"
    # 1) record the current posture
    rc = main(["audit", str(tmp_path), "--guards-only", "--save-snapshot", str(snap), "--no-fail"])
    assert rc == 0 and snap.is_file()
    capsys.readouterr()

    # 2) gate against the snapshot → the existing finding is non-gating → PASS,
    #    but it is STILL rendered in the report (visible, not suppressed).
    rc2 = main(["audit", str(tmp_path), "--guards-only",
                "--baseline-snapshot", str(snap), "--fail-on", "high"])
    out2 = capsys.readouterr().out
    assert rc2 == 0, "existing finding should be excluded from the gate"
    assert "app.py" in out2, "existing finding must remain visible in the report"

    # 3) introduce a NEW finding not in the snapshot → the gate fails on it.
    (tmp_path / "more.py").write_text(
        "import os\n"
        "def g(c: str):\n"
        "    os.system(c)\n",
        encoding="utf-8",
    )
    rc3 = main(["audit", str(tmp_path), "--guards-only",
                "--baseline-snapshot", str(snap), "--fail-on", "high"])
    assert rc3 == 1, "a finding new since the snapshot must trip the gate"


# --- #478 review: --accept path matching, config preservation, exit codes -----------------------

def _nested_advisor_repo(root: Path) -> None:
    """An `evals/` tree one level down, so the tool prints `backend/evals`, not `evals`."""
    (root / "app").mkdir()
    (root / "app" / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    (root / "backend" / "evals").mkdir(parents=True)
    (root / "backend" / "evals" / "test_judge.py").write_text("def test_x(): ...\n", encoding="utf-8")
    (root / "backend" / "evals" / "conftest.py").write_text("import pytest\n", encoding="utf-8")


def test_suggest_excludes_accept_matches_the_full_printed_path(tmp_path: Path) -> None:
    # The listing and the skill both show the repo-relative path; matching was segment-only, so
    # `--accept backend/evals` printed "skipped", wrote nothing, and exited 0 (#478 review).
    from agentsec.config import load_repo_config
    _nested_advisor_repo(tmp_path)
    rc = main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals"])
    assert rc == 0
    assert "evals" in load_repo_config(tmp_path).nonproduct_segments


def test_suggest_excludes_accept_still_matches_the_bare_segment(tmp_path: Path) -> None:
    # The pre-existing spelling keeps working — this widening must not break the segment form.
    from agentsec.config import load_repo_config
    _nested_advisor_repo(tmp_path)
    rc = main(["suggest-excludes", str(tmp_path), "--accept", "evals"])
    assert rc == 0
    assert "evals" in load_repo_config(tmp_path).nonproduct_segments


@pytest.mark.parametrize(
    "spelling",
    [
        "backend/evals",      # what the tool PRINTS and the skill says to pass
        "backend\\evals",     # the same path as a Windows user types it
        "backend\\evals\\",   # ...with a trailing separator
        "backend/evals/",
        "evals",              # the bare segment
        "Backend/Evals",      # case-insensitive
    ],
)
def test_suggest_excludes_accept_normalizes_separators_and_case(tmp_path: Path, spelling: str) -> None:
    # #478 second-pass review (B19): `_accept_keys` normalized backslashes on the CANDIDATE side and
    # the `--accept` parse did not, so a hand-typed `backend\evals` matched nothing on Windows.
    #
    # This is the "failure that presents as success" shape — "skipped", no config written, exit 0 —
    # so the assertions have to be that the file was WRITTEN and carries the entry, never merely that
    # the command exited 0. Both sides now go through `_norm_accept_name`, so they cannot drift again.
    from agentsec.config import load_repo_config

    _nested_advisor_repo(tmp_path)
    rc = main(["suggest-excludes", str(tmp_path), "--accept", spelling])
    assert rc == 0, spelling
    assert (tmp_path / ".agentsec" / "config.json").is_file(), spelling
    assert "evals" in load_repo_config(tmp_path).nonproduct_segments, spelling


def test_suggest_excludes_refuses_to_clobber_a_malformed_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A present-but-unparseable config was read as empty and then written over unconditionally, so
    # a hand-written `network.tier` vanished with exit 0 — while the skill promised the writer
    # "never clobbers" (#478 review).
    _advisor_repo(tmp_path)
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    original = '{"network": {"tier": 1}, oops\n'
    cfg.write_text(original, encoding="utf-8")
    rc = main(["suggest-excludes", str(tmp_path), "--accept", "evals"])
    assert rc == 1
    assert cfg.read_text(encoding="utf-8") == original  # untouched, not silently destroyed
    assert "Could not write" in capsys.readouterr().err


def test_write_repo_config_raises_on_malformed_existing_config(tmp_path: Path) -> None:
    from agentsec.config import write_repo_config
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    cfg.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_repo_config(tmp_path, nonproduct_add=("evals",))
    # ...and a JSON scalar/array is refused the same way (it would lose the file's content too).
    cfg.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_repo_config(tmp_path, nonproduct_add=("evals",))


def test_write_repo_config_still_merges_into_a_valid_config(tmp_path: Path) -> None:
    # Control for the two above: a VALID existing config is still merged, unknown keys preserved.
    import json as _json

    from agentsec.config import write_repo_config
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    cfg.write_text('{"network": {"tier": 1}, "nonproduct_paths": ["seed"]}', encoding="utf-8")
    write_repo_config(tmp_path, nonproduct_add=("evals",))
    data = _json.loads(cfg.read_text(encoding="utf-8"))
    assert data["network"] == {"tier": 1}
    assert sorted(data["nonproduct_paths"]) == ["evals", "seed"]


def test_write_repo_config_refuses_non_utf8_existing_config(tmp_path: Path) -> None:
    # The traded-against direction of #513: the LOADER falls back to empty on an un-decodable file,
    # but the WRITER must refuse it. Treating it as empty (widening its `except OSError: raw = ""`)
    # would overwrite the user's file — the exact clobber the #478 review closed.
    from agentsec.config import write_repo_config
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    original = '{"network": {"tier": 1}}'.encode("utf-16")
    cfg.write_bytes(original)
    with pytest.raises(ValueError, match="not UTF-8"):
        write_repo_config(tmp_path, nonproduct_add=("evals",))
    assert cfg.read_bytes() == original


def test_write_repo_config_merges_into_a_utf8_bom_config(tmp_path: Path) -> None:
    # The reader honours a BOM'd config (#513), so the writer must merge it too, not refuse it as
    # "not valid JSON" — the two used to disagree about the same file.
    import json as _json

    from agentsec.config import write_repo_config
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    cfg.write_bytes(b'\xef\xbb\xbf{"network": {"tier": 1}, "nonproduct_paths": ["seed"]}')
    write_repo_config(tmp_path, nonproduct_add=("evals",))
    data = _json.loads(cfg.read_text(encoding="utf-8"))
    assert data["network"] == {"tier": 1}
    assert sorted(data["nonproduct_paths"]) == ["evals", "seed"]


def test_suggest_excludes_refuses_to_clobber_a_non_utf8_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # #513: this crashed with a traceback in the advisor's config load, before the write was reached.
    _advisor_repo(tmp_path)
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    original = '{"network": {"tier": 1}}'.encode("utf-16")
    cfg.write_bytes(original)
    rc = main(["suggest-excludes", str(tmp_path), "--accept", "evals"])
    assert rc == 1
    assert cfg.read_bytes() == original
    err = capsys.readouterr().err
    # The WRITER's refusal, not the loader's "warning: ignoring ... (not UTF-8 text)", which the
    # advisor's config read prints first and which alone would satisfy a bare "not UTF-8" check.
    assert "Could not write" in err
    assert "refusing to overwrite" in err
    assert "Traceback" not in err


def test_audit_with_non_utf8_config_runs_with_defaults(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # #513: the first config read (network-tier resolution) ran before `audit()` and tracebacked,
    # rc=1 — indistinguishable in CI from "HIGH+ findings".
    _advisor_repo(tmp_path)
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    cfg.write_bytes('{"archive_paths": true}'.encode("utf-16"))
    assert main(["audit", str(tmp_path), "--guards-only", "--no-fail"]) == 0
    # ...and says so exactly once, although the run loads the config more than once (#961 M1).
    assert capsys.readouterr().err.count("warning: ignoring") == 1


def test_suggest_excludes_accept_warns_that_the_match_is_by_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Selection is per-path, but the config matches per-SEGMENT, so accepting one `evals/` also
    # covers the other. Name the directories that inherit it rather than demote product code
    # invisibly (#478 review).
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    for side in ("backend", "frontend"):
        (tmp_path / side / "evals").mkdir(parents=True)
        (tmp_path / side / "evals" / "test_judge.py").write_text("def test_x(): ...\n", encoding="utf-8")
        (tmp_path / side / "evals" / "conftest.py").write_text("import pytest\n", encoding="utf-8")
    rc = main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "matches by directory NAME" in err and "frontend/evals" in err


# --- #478 agentic gate (B33): an already-satisfied --accept is success, not failure -------------

def test_repeat_accept_of_an_already_configured_name_succeeds(tmp_path: Path) -> None:
    # THE MIRROR of the bug this PR fixed. `suggest_proactive` drops any already-configured directory
    # from the candidate list, so an already-accepted name can never appear in `typed`, and
    # `_persist_excludes` could not tell "already true" from "never valid" — reporting BOTH as rc=1.
    #
    # `security-prime/SKILL.md` tells the driving agent that a non-zero exit means a failed priming
    # run, and re-priming a repo is this workflow's own repeat-usage shape, so a correct no-op was
    # being reported as an actionable failure.
    from agentsec.config import load_repo_config

    _nested_advisor_repo(tmp_path)
    assert main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals"]) == 0
    assert "evals" in load_repo_config(tmp_path).nonproduct_segments
    before = (tmp_path / ".agentsec" / "config.json").read_text(encoding="utf-8")

    # The identical request again: the desired state already holds.
    assert main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals"]) == 0
    assert (tmp_path / ".agentsec" / "config.json").read_text(encoding="utf-8") == before


def test_unknown_accept_name_still_fails_even_when_another_is_satisfied(tmp_path: Path) -> None:
    # The other direction: "already configured" must not become a blanket excuse. A genuine typo
    # alongside an already-satisfied name is still a failed request.
    #
    # And it asserts the ARTIFACT, not just the exit code (#478 agentic gate, F5): a mutant that
    # deleted `.agentsec/config.json` on the "Nothing accepted" return — a failed accept destroying a
    # correct config while printing "unchanged" — passed the whole file when this read rc only. That
    # exit-code-only asymmetry is precisely what let the original defect through; the standing rule
    # here is assert the artifact, never the exit code.
    _nested_advisor_repo(tmp_path)
    assert main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals"]) == 0
    before = (tmp_path / ".agentsec" / "config.json").read_text(encoding="utf-8")
    assert main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals,bogus"]) == 1
    assert (tmp_path / ".agentsec" / "config.json").read_text(encoding="utf-8") == before


def test_accept_mixed_known_and_unknown_persists_the_known_subset(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The third code path (`unknown` non-empty AND `accepted` non-empty), which neither the
    # pure-unknown nor the pure-known test covered, and which this PR's fixes are specifically about.
    from agentsec.config import load_repo_config

    _nested_advisor_repo(tmp_path)
    rc = main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals,bogus"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "bogus" in err
    assert "evals" in load_repo_config(tmp_path).nonproduct_segments


# --- #478 independent adversarial gate: F1-F5, F7 -----------------------------------------------
#
# THE INVARIANT for `suggest-excludes --accept`:
#   exit 0 iff the state each named directory requests is IN EFFECT afterwards, and every directory
#   in the repo that the resulting config affects is named on stderr.
# Both halves had holes, in both directions, and the tests pinned neither direction.

def _two_candidate_repo(root: Path) -> None:
    """Two independent candidates, so accepting one leaves the OTHER live — which keeps a repeat run
    inside `_persist_excludes` instead of the no-candidates early return in `_cmd_suggest_excludes`.
    `_nested_advisor_repo` has exactly one, so every repeat run there takes the early return and the
    `_persist_excludes` half of the fix was never executed by a test (#478 agentic gate, F4)."""
    (root / "app").mkdir()
    (root / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    (root / "backend" / "evals").mkdir(parents=True)
    (root / "backend" / "evals" / "test_judge.py").write_text("def test_x(): ...\n", encoding="utf-8")
    (root / "backend" / "evals" / "conftest.py").write_text("import pytest\n", encoding="utf-8")
    (root / "backend" / "notebooks").mkdir(parents=True)
    (root / "backend" / "notebooks" / "a.ipynb").write_text("{}\n", encoding="utf-8")
    (root / "backend" / "notebooks" / "b.ipynb").write_text("{}\n", encoding="utf-8")


def _shared_segment_repo(root: Path) -> None:
    """A gitignored, generated `libs/vendor/` (a genuine `kind: exclude` candidate) beside
    `app/vendor/` — LIVE product code with real findings, imported by the served entrypoint, that
    merely shares the segment name.

    The product tree is import-reachable and not test/notebook-shaped, so `advisor._score_dir` gives
    it zero robust axes: it can never be a `Candidate`. That is why a warning computed from this
    run's candidates could not see it, by construction (#478 agentic gate, F1)."""
    (root / "app").mkdir()
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    (root / "app" / "main.py").write_text(
        "from fastapi import FastAPI\nfrom app.vendor import pay\napp = FastAPI()\n", encoding="utf-8")
    (root / "app" / "vendor").mkdir()
    (root / "app" / "vendor" / "__init__.py").write_text("", encoding="utf-8")
    (root / "app" / "vendor" / "pay.py").write_text(
        "import os\n"
        "from fastapi import FastAPI\n"
        "from fastapi.middleware.cors import CORSMiddleware\n"
        "\n"
        "app = FastAPI()\n"
        "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n"
        "\n"
        "def run(cmd: str):\n"
        "    os.system('echo ' + cmd)\n",
        encoding="utf-8")
    (root / "libs" / "vendor").mkdir(parents=True)
    (root / "libs" / "vendor" / "lib.py").write_text(
        "# DO NOT EDIT - generated\nX = 1\n", encoding="utf-8")
    (root / ".gitignore").write_text("libs/vendor/\n", encoding="utf-8")


# --- F1: the "also covers" warning must scan the REPO TREE, not this run's candidates ------------

def test_accept_names_the_product_tree_an_archive_segment_silently_drops(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """F1. Accepting the vendored `libs/vendor` writes `archive_paths: ["vendor"]`, which matches by
    NAME and therefore DROPS every finding in the live `app/vendor/` package. The command must say so.

    Measured at the tip: rc=0, stderr EMPTY, product findings gone — a security tool disabling its
    own coverage through its consent flow, while `security-prime/SKILL.md` tells the driving agent
    that stderr would have named the extra directories."""
    from agentsec.audit import audit

    _shared_segment_repo(tmp_path)
    before = [f for f in audit(tmp_path, run_scanners=False).findings
              if f.location.startswith("app/vendor/")]
    assert before, "fixture must plant real findings in the product tree"

    assert main(["suggest-excludes", str(tmp_path), "--accept", "libs/vendor"]) == 0
    err = capsys.readouterr().err
    # The artifact: the lossy tier really was written, so the warning is about a real loss.
    assert json.loads((tmp_path / ".agentsec" / "config.json").read_text(encoding="utf-8")) == {
        "archive_paths": ["vendor"]
    }
    assert "DROPPED" in err and "app/vendor" in err and "LOSSY" in err
    # ...and the loss is real: without the warning this is a silent suppression.
    after = [f for f in audit(tmp_path, run_scanners=False).findings
             if f.location.startswith("app/vendor/")]
    assert after == []


def test_accept_warns_about_a_demoted_product_tree_the_advisor_never_suggested(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """F1, demote half. The bounded version of the same shape: a product `frontend/evals` that the
    advisor cannot suggest still inherits the accepted `evals` segment and gets re-ranked."""
    from agentsec.config import load_repo_config

    _two_candidate_repo(tmp_path)
    (tmp_path / "frontend" / "evals").mkdir(parents=True)
    (tmp_path / "frontend" / "evals" / "runner.py").write_text(
        "from app.main import app\n\ndef go(): return app\n", encoding="utf-8")

    assert main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals"]) == 0
    err = capsys.readouterr().err
    assert load_repo_config(tmp_path).nonproduct_segments == frozenset({"evals"})
    assert "matches by directory NAME" in err and "frontend/evals" in err
    assert "DROPPED" not in err          # demote is not lossy — reserve the shout for archive_paths


# --- F2: "already satisfied" must mirror `suggest_proactive`'s ANY-segment rule ------------------

def test_accept_is_satisfied_by_a_configured_parent_segment(tmp_path: Path) -> None:
    """F2. `{"nonproduct_paths": ["backend"]}` already demotes everything under `backend/`, and
    `advisor.suggest_proactive` drops the `backend/evals` candidate for exactly that reason — so the
    desired state HOLDS and no write could ever make it hold "more". Testing only the LEAF segment
    made it read as "never valid": rc=1 at both parent and tip, the same bug class the tip was
    written to eliminate, surviving the fix."""
    from agentsec.advisor import suggest_proactive
    from agentsec.detect import detect

    _two_candidate_repo(tmp_path)
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    original = json.dumps({"nonproduct_paths": ["backend"]}) + "\n"
    cfg.write_text(original, encoding="utf-8")

    assert suggest_proactive(tmp_path, detect(tmp_path)) == [], "premise: the advisor sees it covered"
    assert main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals"]) == 0
    assert cfg.read_text(encoding="utf-8") == original     # satisfied means nothing to write


# --- F3: satisfaction is about the REPO, and it names the tier ----------------------------------

@pytest.mark.parametrize(
    ("key", "name"),
    [
        ("nonproduct_paths", "docs"),   # one of the 9 default segments behind the `true` shorthand
        ("archive_paths", "archive"),   # ...and one of the 7 archive defaults
    ],
)
def test_accept_of_a_name_that_matches_no_directory_is_never_already_configured(
    tmp_path: Path, key: str, name: str
) -> None:
    """F3, the mirror this gate exists to hunt: a request that is NOT satisfied reporting success.

    `already` was a bare name set with no relation to the repo, so the documented `true` shorthand
    (16 segment names across the two tiers — `docs`, `scripts`, `tools`, `evals`, `archive`, `legacy`
    …) turned exactly the names an agent is most likely to guess wrong into free passes at rc=0.
    Measured parent rc=1 -> tip rc=0. A name that names no directory cannot have its state in
    effect."""
    _two_candidate_repo(tmp_path)
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    original = json.dumps({key: True}) + "\n"
    cfg.write_text(original, encoding="utf-8")

    assert not (tmp_path / name).exists()
    assert main(["suggest-excludes", str(tmp_path), "--accept", name]) == 1
    assert cfg.read_text(encoding="utf-8") == original


def test_the_shorthand_still_satisfies_a_name_whose_directory_does_exist(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CONTROL for the test above, so the existence requirement cannot be "fixed" by simply
    refusing every `true`-shorthand name: with a real `docs/` in the tree, `{"nonproduct_paths":
    true}` genuinely covers it and `--accept docs` is a true no-op at rc=0."""
    _two_candidate_repo(tmp_path)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("hi\n", encoding="utf-8")
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    original = json.dumps({"nonproduct_paths": True}) + "\n"
    cfg.write_text(original, encoding="utf-8")

    assert main(["suggest-excludes", str(tmp_path), "--accept", "docs"]) == 0
    assert "Already non-product, nothing to do: docs (nonproduct_paths)" in capsys.readouterr().out
    assert cfg.read_text(encoding="utf-8") == original


def test_a_bare_segment_is_not_satisfied_while_a_second_tree_of_that_name_is_uncovered(
    tmp_path: Path,
) -> None:
    """Satisfaction is per-DIRECTORY, not per-name: `--accept evals` under
    `{"nonproduct_paths": ["backend"]}` covers `backend/evals` but not `frontend/evals`, so the
    request is NOT in effect and must fall through to the write path that covers the second tree
    too. Declaring it satisfied would be F3's false-success reintroduced by the F2 fix."""
    from agentsec.config import load_repo_config

    _two_candidate_repo(tmp_path)
    (tmp_path / "frontend" / "evals").mkdir(parents=True)
    (tmp_path / "frontend" / "evals" / "test_k.py").write_text("def test_y(): ...\n", encoding="utf-8")
    (tmp_path / "frontend" / "evals" / "conftest.py").write_text("import pytest\n", encoding="utf-8")
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    cfg.write_text(json.dumps({"nonproduct_paths": ["backend"]}) + "\n", encoding="utf-8")

    assert main(["suggest-excludes", str(tmp_path), "--accept", "evals"]) == 0
    assert load_repo_config(tmp_path).nonproduct_segments == frozenset({"backend", "evals"})


def test_already_configured_names_the_tier_that_actually_holds_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """F3, S3/S9. `--accept` cannot express a kind and `suggest_proactive` unions the two tiers, so a
    name carried by the OTHER tier is genuinely nothing-to-do (no write path can ever reach it — the
    advisor will not re-suggest it, so rc=1 would be a permanent, unfixable failure). But the
    unqualified "Already configured — nothing to do" was a false statement about the config: here the
    advisor classifies `vendor` as `kind: exclude` (a DROP) while only `nonproduct_paths` (a demote)
    is in effect. Say which tier."""
    _shared_segment_repo(tmp_path)
    cfg = tmp_path / ".agentsec" / "config.json"
    cfg.parent.mkdir()
    original = json.dumps({"nonproduct_paths": ["vendor"]}) + "\n"
    cfg.write_text(original, encoding="utf-8")

    assert main(["suggest-excludes", str(tmp_path), "--accept", "vendor"]) == 0
    assert "Already non-product, nothing to do: vendor (nonproduct_paths)" in capsys.readouterr().out
    assert cfg.read_text(encoding="utf-8") == original


def test_accept_of_a_layer_1_convention_directory_is_satisfied_not_unknown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Found by attacking the F2 fix, and the same bug from the OTHER disjunct of the advisor's skip
    rule: `suggest_proactive` refuses to suggest a directory when a config segment covers it **or**
    when `guards.base.is_nonproduct_path` already does (the hardwired `tests/` / `fixtures/` /
    `migrations/` conventions). Mirroring only the config half left `--accept migrations` — with no
    config at all, on a repo that has a `migrations/` tree that IS already non-product — reporting a
    failed priming run, which `security-prime/SKILL.md` tells the agent to act on. Measured rc=1 at
    parent, at tip, and after the F2 fix alone."""
    _two_candidate_repo(tmp_path)
    (tmp_path / "migrations").mkdir()
    (tmp_path / "migrations" / "0001_init.sql").write_text("select 1;\n", encoding="utf-8")

    assert not (tmp_path / ".agentsec").exists()
    assert main(["suggest-excludes", str(tmp_path), "--accept", "migrations"]) == 0
    out = capsys.readouterr().out
    # #716: the wording is honest about what "built-in" covers (rank-demote only, findings still
    # count) because "nothing to do" sent users away from the one action (archive) that changes
    # the totals. rc stays 0: the demote state genuinely holds, and rc=1 would be a permanent,
    # unfixable failure for scripted `--accept migrations` (see the docstring above).
    assert "Already rank-demoted by the built-in conventions: migrations" in out
    assert "still count" in out
    assert not (tmp_path / ".agentsec").exists()      # satisfied by a built-in rule: nothing to write


# --- F4/F5: the `_persist_excludes` half of the B33 fix, and the failure direction --------------

def test_persist_excludes_reports_an_already_satisfied_name_as_success(tmp_path: Path) -> None:
    """F4, THE DISCRIMINATING ONE: with `backend/notebooks` still live, the repeat run stays inside
    `_persist_excludes` instead of taking `_cmd_suggest_excludes`'s no-candidates early return.
    Deleting the entire `_persist_excludes` satisfied hunk left all three of the tip's new tests
    green; this one goes red."""
    from agentsec.config import load_repo_config

    _two_candidate_repo(tmp_path)
    assert main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals"]) == 0
    cfg = tmp_path / ".agentsec" / "config.json"
    before = cfg.read_text(encoding="utf-8")
    assert main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals"]) == 0
    assert cfg.read_text(encoding="utf-8") == before
    assert load_repo_config(tmp_path).nonproduct_segments == frozenset({"evals"})


def test_persist_excludes_satisfied_plus_new_writes_the_new_one_and_succeeds(tmp_path: Path) -> None:
    from agentsec.config import load_repo_config

    _two_candidate_repo(tmp_path)
    assert main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals"]) == 0
    assert main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals,backend/notebooks"]) == 0
    assert load_repo_config(tmp_path).nonproduct_segments == frozenset({"evals", "notebooks"})


def test_persist_excludes_satisfied_plus_typo_still_fails_and_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """F5 for the `_persist_excludes` return: a failed request must leave a correct config exactly as
    it found it. A mutant that unlinked the config on this path passed the whole file."""
    _two_candidate_repo(tmp_path)
    assert main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals"]) == 0
    cfg = tmp_path / ".agentsec" / "config.json"
    before = cfg.read_text(encoding="utf-8")
    assert main(["suggest-excludes", str(tmp_path), "--accept", "backend/evals,bogus"]) == 1
    assert "bogus" in capsys.readouterr().err
    assert cfg.read_text(encoding="utf-8") == before


# --- F7: `--format json` is a read-only listing -------------------------------------------------

@pytest.mark.parametrize("flags", [["--accept", "backend/evals"], ["--write", "--yes"]])
def test_format_json_refuses_a_write_request_instead_of_silently_dropping_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], flags: list[str]
) -> None:
    """F7. The JSON branch returns before every write path, so `--format json --accept X` exited 0
    having written nothing — the shape this command's whole rc contract exists to prevent, reachable
    by combining `security-prime` step 2 (`--format json`) with step 5 (`--accept`)."""
    _two_candidate_repo(tmp_path)
    assert main(["suggest-excludes", str(tmp_path), "--format", "json", *flags]) == 2
    assert "read-only" in capsys.readouterr().err
    assert not (tmp_path / ".agentsec").exists()


# --- scan-live-url: no repo, no DB DSN, ownership-gated ---------------------------

def test_scan_live_url_refuses_non_https(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan-live-url", "http://insecure.example"]) == 2
    assert "https://" in capsys.readouterr().err


def test_scan_live_url_no_token_prints_instructions(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["scan-live-url", "https://app.example"])
    out = capsys.readouterr().out
    assert rc == 2
    assert ".well-known/agentsec-verify.txt" in out
    assert "--verify-token" in out


def test_scan_live_url_ownership_not_verified(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from agentsec import livescan

    monkeypatch.setattr(
        livescan, "verify_ownership_file",
        lambda url, token, **_: livescan.OwnershipResult(False, "file", "token not found"),
    )
    rc = main(["scan-live-url", "https://app.example", "--verify-token", "tok"])
    assert rc == 2
    assert "ownership not verified" in capsys.readouterr().err


def test_scan_live_url_no_supabase_config_found(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from agentsec import livescan

    monkeypatch.setattr(
        livescan, "verify_ownership_file",
        lambda url, token, **_: livescan.OwnershipResult(True, "file"),
    )
    monkeypatch.setattr(livescan, "discover_supabase_config", lambda url, **_: ("", ""))
    rc = main(["scan-live-url", "https://app.example", "--verify-token", "tok"])
    assert rc == 2
    assert "no Supabase URL" in capsys.readouterr().err


def test_scan_live_url_full_run_gates_on_finding(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from agentsec import livescan
    from agentsec.findings import Finding
    from agentsec.live import LiveResult

    monkeypatch.setattr(
        livescan, "verify_ownership_file",
        lambda url, token, **_: livescan.OwnershipResult(True, "file"),
    )
    monkeypatch.setattr(
        livescan, "discover_supabase_config",
        lambda url, **_: ("https://proj.supabase.co", "anon-key"),
    )
    hit = Finding(check_id="scan-live-url", severity="high", title="exposed table",
                  rule="scan-live-url/exposed-tables")
    monkeypatch.setattr(
        livescan, "probe_exposed_tables",
        lambda *_a, **_k: LiveResult("scan-live-url/exposed-tables", True, findings=[hit]),
    )
    monkeypatch.setattr(
        livescan, "probe_public_storage",
        lambda *_a, **_k: LiveResult("scan-live-url/public-storage", True, findings=[]),
    )
    monkeypatch.setattr(
        livescan, "probe_pg_graphql",
        lambda *_a, **_k: LiveResult("scan-live-url/pg-graphql-exposed", True, findings=[]),
    )
    rc = main(["scan-live-url", "https://app.example", "--verify-token", "tok"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "exposed table" in out


def test_scan_live_url_no_fail_overrides_gate(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from agentsec import livescan
    from agentsec.findings import Finding
    from agentsec.live import LiveResult

    monkeypatch.setattr(
        livescan, "verify_ownership_file",
        lambda url, token, **_: livescan.OwnershipResult(True, "file"),
    )
    monkeypatch.setattr(
        livescan, "discover_supabase_config",
        lambda url, **_: ("https://proj.supabase.co", "anon-key"),
    )
    hit = Finding(check_id="scan-live-url", severity="high", title="exposed table",
                  rule="scan-live-url/exposed-tables")
    monkeypatch.setattr(
        livescan, "probe_exposed_tables",
        lambda *_a, **_k: LiveResult("scan-live-url/exposed-tables", True, findings=[hit]),
    )
    monkeypatch.setattr(
        livescan, "probe_public_storage",
        lambda *_a, **_k: LiveResult("scan-live-url/public-storage", True, findings=[]),
    )
    monkeypatch.setattr(
        livescan, "probe_pg_graphql",
        lambda *_a, **_k: LiveResult("scan-live-url/pg-graphql-exposed", True, findings=[]),
    )
    rc = main(["scan-live-url", "https://app.example", "--verify-token", "tok", "--no-fail"])
    capsys.readouterr()
    assert rc == 0


def test_scan_live_url_explicit_supabase_flags_skip_discovery(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from agentsec import livescan
    from agentsec.live import LiveResult

    monkeypatch.setattr(
        livescan, "verify_ownership_file",
        lambda url, token, **_: livescan.OwnershipResult(True, "file"),
    )

    def boom(*_a: object, **_k: object) -> tuple[str, str]:
        raise AssertionError("discover_supabase_config must not be called when both flags are given")
    monkeypatch.setattr(livescan, "discover_supabase_config", boom)
    monkeypatch.setattr(
        livescan, "probe_exposed_tables",
        lambda *_a, **_k: LiveResult("scan-live-url/exposed-tables", True, findings=[]),
    )
    monkeypatch.setattr(
        livescan, "probe_public_storage",
        lambda *_a, **_k: LiveResult("scan-live-url/public-storage", True, findings=[]),
    )
    monkeypatch.setattr(
        livescan, "probe_pg_graphql",
        lambda *_a, **_k: LiveResult("scan-live-url/pg-graphql-exposed", True, findings=[]),
    )
    rc = main([
        "scan-live-url", "https://app.example", "--verify-token", "tok", "--no-fail",
        "--supabase-url", "https://proj.supabase.co", "--supabase-anon-key", "anon-key",
    ])
    capsys.readouterr()
    assert rc == 0


def _patch_scan_live_url_ownership(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentsec import livescan
    monkeypatch.setattr(
        livescan, "verify_ownership_file",
        lambda url, token, **_: livescan.OwnershipResult(True, "file"),
    )
    monkeypatch.setattr(
        livescan, "discover_supabase_config",
        lambda url, **_: ("https://proj.supabase.co", "anon-key"),
    )


def test_scan_live_url_all_probes_skipped_is_incomplete_not_pass(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # #904 L1 ("a failure that presents as success"): every probe skipped => findings=[] not
    # because the target is clean but because nothing ran. Must NOT read as PASS/exit 0, and
    # --no-fail (which governs findings-based gating only) must not suppress it. Assert the
    # ARTIFACT (verdict text + exit code), never just the exit code.
    from agentsec import livescan
    from agentsec.live import LiveResult

    _patch_scan_live_url_ownership(monkeypatch)
    for name, attr in (
        ("scan-live-url/exposed-tables", "probe_exposed_tables"),
        ("scan-live-url/public-storage", "probe_public_storage"),
        ("scan-live-url/pg-graphql-exposed", "probe_pg_graphql"),
    ):
        monkeypatch.setattr(
            livescan, attr,
            lambda *_a, _n=name, **_k: LiveResult(_n, False, skip_reason="unreachable"),
        )
    rc = main(["scan-live-url", "https://app.example", "--verify-token", "tok", "--no-fail"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "INCOMPLETE" in err
    assert "0 of 3 probes ran" in err
    assert "PASS" not in err


def test_scan_live_url_ran_but_clean_still_passes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Boundary control for the L1 fix: when probes DID run and found nothing, the verdict is a
    # genuine PASS/exit 0 — the INCOMPLETE branch must fire only on the all-skipped case.
    from agentsec import livescan
    from agentsec.live import LiveResult

    _patch_scan_live_url_ownership(monkeypatch)
    for name, attr in (
        ("scan-live-url/exposed-tables", "probe_exposed_tables"),
        ("scan-live-url/public-storage", "probe_public_storage"),
        ("scan-live-url/pg-graphql-exposed", "probe_pg_graphql"),
    ):
        monkeypatch.setattr(
            livescan, attr,
            lambda *_a, _n=name, **_k: LiveResult(_n, True, findings=[]),
        )
    rc = main(["scan-live-url", "https://app.example", "--verify-token", "tok"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "PASS" in err
    assert "INCOMPLETE" not in err
