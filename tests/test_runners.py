"""Runner tests: parsers against fixture JSON + availability/error handling.

The subprocess `invoke()` only runs when the binary is installed; the parsers
are pure and fully covered here without the binaries present.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.runners.bandit import BanditRunner
from agentsec.runners.base import Runner
from agentsec.runners.gitleaks import GitleaksRunner
from agentsec.runners.hadolint import HadolintRunner
from agentsec.runners.node_audit import NodeAuditRunner
from agentsec.runners.pip_audit import PipAuditRunner
from agentsec.runners.scorecard import ScorecardRunner, _github_slug
from agentsec.runners.semgrep import SemgrepRunner
from agentsec.runners.trivy import TrivyRunner


def test_bandit_parse() -> None:
    raw = json.dumps({"results": [
        {"filename": "a.py", "line_number": 5, "issue_severity": "HIGH",
         "test_id": "B602", "test_name": "subprocess_shell", "issue_text": "shell=True", "more_info": "http://x"}
    ]})
    f = BanditRunner().parse(raw)
    assert len(f) == 1 and f[0].severity == "high" and f[0].location == "a.py:5" and f[0].rule == "B602"


def test_bandit_config_detection(tmp_path: Path) -> None:
    from agentsec.runners.bandit import _bandit_config

    assert _bandit_config(tmp_path) is None                      # nothing → defaults
    (tmp_path / "pyproject.toml").write_text("[tool.bandit]\nskips = ['B101']\n", encoding="utf-8")
    assert _bandit_config(tmp_path) == str(tmp_path / "pyproject.toml")
    (tmp_path / ".bandit").write_text("[bandit]\n", encoding="utf-8")
    assert _bandit_config(tmp_path) == str(tmp_path / ".bandit")  # dedicated config wins


def test_bandit_invoke_passes_config(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import agentsec.runners.bandit as bandit_mod

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".bandit").write_text("[bandit]\n", encoding="utf-8")
    captured: dict[str, list[str]] = {}

    def fake_exec(args: list[str], cwd: Path, timeout: int = 300) -> tuple[int, str, str]:
        captured["args"] = args
        return 0, '{"results": []}', ""

    monkeypatch.setattr(bandit_mod, "exec_capture_or_raise", fake_exec)
    BanditRunner().invoke(tmp_path, StackProfile(root=tmp_path, python_dirs=["."]))
    assert "-c" in captured["args"]
    assert str(tmp_path / ".bandit") in captured["args"]


def test_pip_audit_parse_prefers_cve() -> None:
    raw = json.dumps({"dependencies": [
        {"name": "aiohttp", "version": "3.13.4",
         "vulns": [{"id": "GHSA-x", "aliases": ["CVE-2026-1"], "fix_versions": ["3.14.0"], "description": "bad"}]}
    ]})
    f = PipAuditRunner().parse(raw)
    assert len(f) == 1 and f[0].severity == "high" and f[0].rule == "CVE-2026-1"
    assert "nvd.nist.gov" in f[0].url and "3.14.0" in f[0].remediation


def test_gitleaks_parse_excludes_pii() -> None:
    raw = json.dumps([
        {"RuleID": "aws-key", "File": "x.py", "StartLine": 3, "Commit": "abcdef1234567",
         "Description": "AWS key", "Author": "Jane Dev", "Email": "jane@x.com", "Link": "http://l"}
    ])
    f = GitleaksRunner().parse(raw)
    assert len(f) == 1 and f[0].severity == "high"
    assert f[0].location == "x.py:3 @ abcdef12"
    blob = " ".join([f[0].title, f[0].location, f[0].message, f[0].url])
    assert "Jane Dev" not in blob and "jane@x.com" not in blob  # PII excluded


def test_semgrep_parse_severity_map() -> None:
    raw = json.dumps({"results": [
        {"check_id": "python.lang.security.foo", "path": "a.py", "start": {"line": 7},
         "extra": {"severity": "ERROR", "message": "bad"}}
    ]})
    f = SemgrepRunner().parse(raw)
    assert f[0].severity == "high" and f[0].title == "foo" and f[0].location == "a.py:7"
    assert f[0].rule == "python.lang.security.foo"   # OSS registry id stays full (portable)


def test_semgrep_custom_pack_rule_id_is_portable() -> None:
    # the custom pack is loaded by absolute path, so semgrep prefixes the check_id
    # with the on-disk rules-dir; the bare `agentsec-*` id must survive as `rule`.
    machine_id = "home.user.checkout.agentsec.ai.semgrep-rules.python-llm.agentsec-jwt-unverified-decode"
    raw = json.dumps({"results": [
        {"check_id": machine_id, "path": "a.py", "start": {"line": 3},
         "extra": {"severity": "ERROR", "message": "unverified jwt"}}
    ]})
    f = SemgrepRunner().parse(raw)
    assert f[0].rule == "agentsec-jwt-unverified-decode"   # portable, no machine path
    assert f[0].title == "agentsec-jwt-unverified-decode"


def test_trivy_parse_vuln_secret_misconfig() -> None:
    raw = json.dumps({"Results": [
        {"Target": "requirements.txt",
         "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1.0",
                              "Severity": "CRITICAL", "Title": "t", "FixedVersion": "2.0", "PrimaryURL": "u"}],
         "Secrets": [{"RuleID": "aws", "StartLine": 2, "Severity": "HIGH", "Title": "secret"}],
         "Misconfigurations": [{"ID": "DS002", "Title": "root", "Severity": "MEDIUM",
                                "Status": "FAIL", "Message": "runs as root"}]}
    ]})
    f = TrivyRunner().parse(raw)
    sevs = sorted(x.severity for x in f)
    assert sevs == ["critical", "high", "medium"] and len(f) == 3


def test_hadolint_parse() -> None:
    raw = json.dumps([{"file": "Dockerfile", "line": 3, "level": "warning", "code": "DL3008", "message": "pin"}])
    f = HadolintRunner().parse(raw)
    assert f[0].severity == "medium" and f[0].rule == "DL3008" and f[0].location == "Dockerfile:3"


def test_node_audit_pnpm_advisories() -> None:
    raw = json.dumps({"advisories": {"1": {
        "module_name": "react-router", "severity": "moderate", "title": "DoS",
        "url": "u", "github_advisory_id": "GHSA-y", "patched_versions": ">=7.5"}}})
    f = NodeAuditRunner().parse(raw)
    assert f[0].severity == "medium" and f[0].location == "react-router" and f[0].rule == "GHSA-y"


def test_node_audit_npm_vulnerabilities() -> None:
    raw = json.dumps({"vulnerabilities": {"lodash": {
        "severity": "high", "via": [{"title": "proto", "url": "u"}], "fixAvailable": {"version": "4.17.21"}}}})
    f = NodeAuditRunner().parse(raw)
    assert f[0].severity == "high" and "4.17.21" in f[0].remediation


def test_node_audit_handles_empty() -> None:
    assert NodeAuditRunner().parse("{}") == []
    assert BanditRunner().parse('{"results": []}') == []


def test_react_doctor_parse_is_total_on_non_json() -> None:
    # react-doctor can write a non-JSON but truthy string to stdout on a crash; parse() must not
    # raise (runner parse() is total) — treat unparseable output as "nothing" (#255).
    from agentsec.runners.react_doctor import ReactDoctorRunner
    r = ReactDoctorRunner()
    assert r.parse("Fatal error: unexpected token") == []
    assert r.parse("") == []
    assert r.parse("[]") == []          # valid JSON, not a dict -> nothing
    assert r.parse('{"diagnostics": []}') == []


def test_node_audit_signatures_failure() -> None:
    raw = json.dumps({"invalid": [{"name": "evil", "version": "1.2.3"}],
                      "missing": [{"name": "unsigned", "version": "0.1.0"}]})
    f = NodeAuditRunner().parse(raw)
    invalid = next(x for x in f if x.rule == "node-audit/signature")
    missing = next(x for x in f if x.rule == "node-audit/signature-missing")
    assert invalid.severity == "high" and invalid.location == "evil@1.2.3"
    assert missing.severity == "medium" and "OWASP:A08" in invalid.standards


def test_node_audit_signatures_clean() -> None:
    assert NodeAuditRunner().parse('{"invalid": [], "missing": []}') == []


def test_node_audit_combined_cve_and_signatures() -> None:
    cve = '{"advisories":{"1":{"module_name":"x","severity":"high","title":"t","github_advisory_id":"GHSA-z"}}}'
    sig = '{"invalid":[{"name":"evil","version":"1.0"}],"missing":[]}'
    f = NodeAuditRunner().parse(cve + "\n\x1e\n" + sig)
    assert {x.check_id for x in f} == {"node-audit"} and len(f) == 2


# --- availability + error handling -------------------------------------------

class _Bogus(Runner):
    id = "bogus"
    binary = "definitely-not-a-real-binary-xyz"

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True


def test_missing_binary_is_not_fatal(tmp_path: Path) -> None:
    res = _Bogus().run(tmp_path, StackProfile(root=tmp_path))
    assert res.available is False and res.findings == [] and res.error is None


class _Boom(Runner):
    id = "boom"
    binary = "sh"  # present on POSIX

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def invoke(self, root: Path, profile: StackProfile) -> str:  # noqa: ARG002
        raise RuntimeError("scanner crashed")

    def parse(self, raw: str) -> list[Finding]:
        return []


def test_invoke_crash_captured(tmp_path: Path) -> None:
    res = _Boom().run(tmp_path, StackProfile(root=tmp_path))
    assert res.available is True and res.error is not None and "scanner crashed" in res.error


class _BadJson(Runner):
    id = "badjson"
    binary = "sh"

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def invoke(self, root: Path, profile: StackProfile) -> str:  # noqa: ARG002
        return "not json{"

    def parse(self, raw: str) -> list[Finding]:
        return BanditRunner().parse(raw)  # raises JSONDecodeError


def test_parse_error_becomes_info_finding(tmp_path: Path) -> None:
    res = _BadJson().run(tmp_path, StackProfile(root=tmp_path))
    assert res.available is True and len(res.findings) == 1 and res.findings[0].severity == "info"


def test_parse_tolerates_explicit_top_level_null() -> None:
    # #420: `.get(key, [])` defaults only when the key is *absent* — Go scanners
    # marshal empty slices as an explicit null, which iterated as None and dropped
    # the scanner's entire finding set behind a generic parse-error info finding.
    assert BanditRunner().parse('{"results": null}') == []
    assert SemgrepRunner().parse('{"results": null}') == []
    assert TrivyRunner().parse('{"Results": null}') == []
    assert TrivyRunner().parse('{"Results": [{"Vulnerabilities": 5, "Secrets": null}]}') == []
    assert PipAuditRunner().parse('{"dependencies": null}') == []
    assert PipAuditRunner().parse('{"dependencies": [{"name": "x", "vulns": null}]}') == []


def test_pip_audit_invoke_tolerates_null_dependencies(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # #420: `deps.extend(None)` killed the whole scanner's results for one odd output.
    import agentsec.runners.pip_audit as pa_mod

    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")

    def fake_exec(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        return 0, '{"dependencies": null}', ""

    monkeypatch.setattr(pa_mod, "exec_capture_or_raise", fake_exec)
    raw = PipAuditRunner().invoke(tmp_path, StackProfile(root=tmp_path))
    assert PipAuditRunner().parse(raw) == []


def test_node_audit_via_advisory_without_title() -> None:
    # #420: an npm-v7 via-advisory dict lacking "title" rendered "lodash: None".
    raw = json.dumps({"vulnerabilities": {"lodash": {
        "severity": "high", "via": [{"url": "u"}], "fixAvailable": True}}})
    f = NodeAuditRunner().parse(raw)
    assert len(f) == 1 and f[0].message == "lodash: Vulnerable dependency"


def test_scanner_launch_failure_is_recorded_not_clean(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # #420: exec_capture maps a timeout/launch failure to rc=-1, which no invoke()
    # inspected — a timed-out trivy became RunnerResult(available=True, findings=[],
    # error=None) and the CI gate saw "ran, clean". It must record an error now.
    import subprocess

    import agentsec.runners.base as base_mod

    monkeypatch.setattr(base_mod, "which", lambda b: "/usr/bin/fake-scanner")

    def raise_timeout(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise subprocess.TimeoutExpired(cmd="fake-scanner", timeout=600)

    monkeypatch.setattr(base_mod.subprocess, "run", raise_timeout)
    res = TrivyRunner().run(tmp_path, StackProfile(root=tmp_path))
    assert res.available is True and res.findings == []
    assert res.error is not None and "timed out" in res.error


def test_exec_capture_decodes_non_utf8_without_raising() -> None:
    # #420: text=True with the platform default (cp1252 on Windows) raised
    # UnicodeDecodeError through the except tuple; utf-8 + errors="replace" must
    # turn undecodable bytes into U+FFFD instead.
    import sys

    from agentsec.runners.base import exec_capture

    rc, out, _ = exec_capture(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\xff\\xfeok')"],
        cwd=Path.cwd(),
    )
    assert rc == 0 and out.endswith("ok") and "�" in out


def test_sibling_parsers_tolerate_truthy_non_list() -> None:
    # #432 review: eslint/react-doctor/scorecard still used `x.get(k) or []`, which
    # guards an explicit null but not a truthy non-list — the exact #420 bug class.
    from agentsec.runners.eslint import EslintRunner
    from agentsec.runners.react_doctor import ReactDoctorRunner
    from agentsec.runners.scorecard import ScorecardRunner as _SC

    assert EslintRunner().parse('[{"filePath": "x", "messages": 5}]') == []
    assert ReactDoctorRunner().parse('{"diagnostics": 5}') == []
    assert _SC().parse('{"checks": 5}') == []


def test_no_falsy_only_collection_guards_in_runners_or_ingest() -> None:
    # Drift gate (#432 review): `x.get(k) or []` only guards *falsy* bad values — a
    # truthy non-list crashes parse()/invoke(). This idiom has regressed twice
    # (#255, #432); use base.as_list / ingest._as_list instead.
    import re

    pat = re.compile(r"\.get\([^)]*\)\s+or\s+\[\]")
    pkg = Path(__file__).resolve().parents[1] / "agentsec"
    offenders: list[str] = []
    for py in [*sorted((pkg / "runners").glob("*.py")), pkg / "ingest.py"]:
        for i, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
            if pat.search(line.split("#", 1)[0]):
                offenders.append(f"{py.name}:{i}")
    assert offenders == [], f"use as_list()/_as_list() instead of `.get(...) or []`: {offenders}"


def test_gitleaks_invoke_unlinks_report_on_launch_failure(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    # #432 review: exec_capture_or_raise ran before the try/finally that unlinks the
    # report tempfile, so a launch failure/timeout leaked one tmp*.json per run.
    import tempfile

    import agentsec.runners.gitleaks as gl_mod
    from agentsec.runners.base import ScannerExecError

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    def boom(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        raise ScannerExecError("timed out")

    monkeypatch.setattr(gl_mod, "exec_capture_or_raise", boom)
    with pytest.raises(ScannerExecError):
        GitleaksRunner().invoke(tmp_path, StackProfile(root=tmp_path))
    assert list(tmp_path.glob("tmp*")) == []


def test_pip_audit_invoke_keeps_partial_results_when_one_file_fails(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    # #432 review: one requirements file timing out must not erase the findings
    # already gathered from the others.
    import agentsec.runners.pip_audit as pa_mod
    from agentsec.runners.base import ScannerExecError

    (tmp_path / "requirements.txt").write_text("a\n", encoding="utf-8")
    (tmp_path / "requirements-dev.txt").write_text("b\n", encoding="utf-8")

    def fake_exec(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        if "dev" in args[2]:
            raise ScannerExecError("timed out")
        return 0, '{"dependencies": [{"name": "a", "version": "1", "vulns": []}]}', ""

    monkeypatch.setattr(pa_mod, "exec_capture_or_raise", fake_exec)
    raw = PipAuditRunner().invoke(tmp_path, StackProfile(root=tmp_path))
    assert json.loads(raw)["dependencies"], "partial results must survive one file's failure"


def test_pip_audit_invoke_raises_when_all_files_fail(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    # ... but a TOTAL failure still raises, so run() records an error, not "clean".
    import agentsec.runners.pip_audit as pa_mod
    from agentsec.runners.base import ScannerExecError

    (tmp_path / "requirements.txt").write_text("a\n", encoding="utf-8")

    def boom(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        raise ScannerExecError("timed out")

    monkeypatch.setattr(pa_mod, "exec_capture_or_raise", boom)
    with pytest.raises(ScannerExecError):
        PipAuditRunner().invoke(tmp_path, StackProfile(root=tmp_path))


def test_hadolint_invoke_keeps_partial_results_when_one_dockerfile_fails(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    import agentsec.runners.hadolint as hl_mod
    from agentsec.runners.base import ScannerExecError

    (tmp_path / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    (tmp_path / "Dockerfile.dev").write_text("FROM y\n", encoding="utf-8")

    def fake_exec(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        if args[-1].endswith(".dev"):
            raise ScannerExecError("timed out")
        return 0, '[{"code": "DL3006", "level": "warning", "file": "Dockerfile", "line": 1, "message": "m"}]', ""

    monkeypatch.setattr(hl_mod, "exec_capture_or_raise", fake_exec)
    raw = HadolintRunner().invoke(tmp_path, StackProfile(root=tmp_path))
    assert HadolintRunner().parse(raw), "partial results must survive one Dockerfile's failure"


def test_node_audit_invoke_keeps_cve_results_when_signatures_fails(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    # #432 review: the secondary `npm audit signatures` call failing must not erase
    # the CVE results from the primary audit call.
    import agentsec.runners.node_audit as na_mod
    from agentsec.runners.base import ScannerExecError

    cve_json = '{"vulnerabilities": {"lodash": {"severity": "high", "via": [{"title": "t"}]}}}'

    def fake_exec(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        if "signatures" in args:
            raise ScannerExecError("timed out")
        return 0, cve_json, ""

    monkeypatch.setattr(na_mod, "exec_capture_or_raise", fake_exec)
    raw = NodeAuditRunner().invoke(tmp_path, StackProfile(root=tmp_path))
    assert len(NodeAuditRunner().parse(raw)) == 1, "CVE results must survive a signatures failure"


def test_exec_capture_caps_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # #420: no cap on captured output — a hostile repo can make a scanner emit
    # effectively unbounded stdout (memory DoS).
    import sys

    import agentsec.runners.base as base_mod

    monkeypatch.setattr(base_mod, "CAPTURE_CAP", 16)
    rc, out, _ = base_mod.exec_capture(
        [sys.executable, "-c", "print('x' * 1000)"], cwd=Path.cwd(),
    )
    assert rc == 0 and len(out) == 16


def test_trivy_invoke_disables_egress(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Trivy's own version-check + telemetry are suppressed via env vars (version-safe:
    # an older Trivy ignores an unknown TRIVY_* var). The tool-adoption "no egress" rule.
    import agentsec.runners.trivy as trivy_mod

    captured: dict[str, object] = {}

    def fake_exec(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        captured["env_extra"] = env_extra
        return 0, '{"Results": []}', ""

    monkeypatch.setattr(trivy_mod, "exec_capture_or_raise", fake_exec)
    TrivyRunner().invoke(tmp_path, StackProfile(root=tmp_path))
    env_extra = captured["env_extra"]
    assert isinstance(env_extra, dict)
    assert env_extra.get("TRIVY_SKIP_VERSION_CHECK") == "true"
    assert env_extra.get("TRIVY_DISABLE_TELEMETRY") == "true"


# --- the mechanism A: trivy image scan of foreign_artifacts Go base images ---------------

def test_image_refs_extracts_the_backtick_quoted_ref() -> None:
    from agentsec.runners.trivy import _image_refs

    prof = StackProfile(root=Path("."))
    prof.foreign_artifacts = {
        "Go (Docker base image `caddy:2.7`)",
        "HashiCorp Vault (Docker base image `hashicorp/vault:1.15`)",
    }
    assert _image_refs(prof) == ["caddy:2.7", "hashicorp/vault:1.15"]


def test_image_refs_empty_when_no_foreign_artifacts() -> None:
    from agentsec.runners.trivy import _image_refs

    assert _image_refs(StackProfile(root=Path("."))) == []


def test_image_refs_ignores_a_malformed_entry_without_backticks() -> None:
    # Total by contract: a hand-constructed profile (e.g. in another test) with a malformed
    # foreign_artifacts entry must not crash the extractor, just skip that entry.
    from agentsec.runners.trivy import _image_refs

    prof = StackProfile(root=Path("."))
    prof.foreign_artifacts = {"no backticks here"}
    assert _image_refs(prof) == []


def test_trivy_invoke_scans_each_foreign_artifacts_image(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import agentsec.runners.trivy as trivy_mod

    calls: list[list[str]] = []

    def fake_exec(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        calls.append(args)
        if "image" in args:
            ref = args[-1]
            return 0, json.dumps({"Results": [{"Target": ref, "Vulnerabilities": [
                {"VulnerabilityID": "CVE-IMG", "PkgName": "stdlib", "InstalledVersion": "1.26.3",
                 "Severity": "HIGH", "Title": "t"}
            ]}]}), ""
        return 0, json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": []}]}), ""

    monkeypatch.setattr(trivy_mod, "exec_capture_or_raise", fake_exec)
    prof = StackProfile(root=tmp_path)
    prof.foreign_artifacts = {"Go (Docker base image `caddy:2.7`)"}
    raw = TrivyRunner().invoke(tmp_path, prof)

    image_calls = [c for c in calls if "image" in c]
    assert len(image_calls) == 1
    assert image_calls[0][:5] == ["trivy", "image", "--image-src", "remote", "--quiet"]
    assert "--" in image_calls[0]  # end-of-options marker precedes the ref (#684 review, Medium 3)
    assert image_calls[0][-1] == "caddy:2.7"

    findings = TrivyRunner().parse(raw)
    rules = {f.rule for f in findings}
    assert "trivy-image/CVE-IMG" in rules  # the image scan's own finding survived the merge with fs's


def test_trivy_invoke_rejects_flag_injection_via_crafted_from_line(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # #684 review, Medium 3: a crafted `FROM -x/caddy:latest` (or `FROM --cache-dir=/tmp/x/caddy`)
    # passes the curated base-image name filter on its last path segment alone, with no format
    # validation on the ref string itself. A ref starting with `-` must never reach argv — a repo
    # under audit must not be able to steer the auditor's own tool invocation.
    import agentsec.runners.trivy as trivy_mod

    calls: list[list[str]] = []

    def fake_exec(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        calls.append(args)
        return 0, json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": []}]}), ""

    monkeypatch.setattr(trivy_mod, "exec_capture_or_raise", fake_exec)
    prof = StackProfile(root=tmp_path)
    prof.foreign_artifacts = {"Go (Docker base image `--cache-dir=/tmp/x/caddy`)"}
    TrivyRunner().invoke(tmp_path, prof)

    image_calls = [c for c in calls if "image" in c]
    assert image_calls == []  # the malicious ref never reached an image-scan invocation


def test_trivy_invoke_no_image_scan_without_foreign_artifacts(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import agentsec.runners.trivy as trivy_mod

    calls: list[list[str]] = []

    def fake_exec(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        calls.append(args)
        return 0, '{"Results": []}', ""

    monkeypatch.setattr(trivy_mod, "exec_capture_or_raise", fake_exec)
    TrivyRunner().invoke(tmp_path, StackProfile(root=tmp_path))
    assert not any("image" in c for c in calls)  # no foreign_artifacts -> fs scan only


def test_trivy_image_scan_failure_is_a_partial_failure_not_fatal(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Mirrors hadolint.py's per-target pattern: one unreachable/renamed image must not erase the
    # filesystem scan's own results, and must not raise out of invoke() (#432-class regression).
    import agentsec.runners.trivy as trivy_mod
    from agentsec.runners.base import ScannerExecError

    def fake_exec(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        if "image" in args:
            raise ScannerExecError("manifest unknown: image not found")
        return 0, json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-FS", "PkgName": "x", "InstalledVersion": "1.0", "Severity": "LOW"}
        ]}]}), ""

    monkeypatch.setattr(trivy_mod, "exec_capture_or_raise", fake_exec)
    prof = StackProfile(root=tmp_path)
    prof.foreign_artifacts = {"Go (Docker base image `ghost:no-such-tag`)"}
    r = TrivyRunner()
    r._partial_failures = []  # class-level mutable default; direct .invoke() must reset it (#684 review)
    raw = r.invoke(tmp_path, prof)  # must not raise

    findings = r.parse(raw)
    assert {f.rule for f in findings} == {"CVE-FS"}  # fs result survived the image-scan failure
    assert any("ghost:no-such-tag" in pf for pf in r._partial_failures)


def test_trivy_image_scan_finding_has_a_third_party_remediation(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # The RFC's own "still genuinely open" question: a CVE inside a THIRD-PARTY base image can't
    # be fixed with "Upgrade to X" the way a CVE in the user's own declared dependency can — no
    # `pip install` into someone else's prebuilt image. Resolved by tagging image-scan Results and
    # giving them a distinct remediation + a `trivy-image/` rule prefix (review-tier signal).
    import agentsec.runners.trivy as trivy_mod

    def fake_exec(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        if "image" in args:
            return 0, json.dumps({"Results": [{"Target": "caddy:2.7", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-IMG", "PkgName": "stdlib", "InstalledVersion": "1.26.3",
                 "Severity": "HIGH", "Title": "t", "FixedVersion": "1.26.5"}
            ]}]}), ""
        return 0, json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-FS", "PkgName": "x", "InstalledVersion": "1.0",
             "Severity": "HIGH", "Title": "t", "FixedVersion": "2.0"}
        ]}]}), ""

    monkeypatch.setattr(trivy_mod, "exec_capture_or_raise", fake_exec)
    prof = StackProfile(root=tmp_path)
    prof.foreign_artifacts = {"Go (Docker base image `caddy:2.7`)"}
    raw = TrivyRunner().invoke(tmp_path, prof)
    findings = {f.rule: f for f in TrivyRunner().parse(raw)}

    image_finding = findings["trivy-image/CVE-IMG"]
    assert "third-party base image" in image_finding.remediation
    assert not image_finding.remediation.startswith("Upgrade to")  # the misleading fs-scan phrasing
    assert image_finding.severity == "high"  # severity itself is unchanged — trivy's own call

    fs_finding = findings["CVE-FS"]  # unprefixed, unchanged — the existing fs-scan behavior
    assert fs_finding.remediation == "Upgrade to 2.0"


def test_trivy_image_scan_rule_prefix_is_a_review_signal() -> None:
    from agentsec.findings import _is_review_finding

    f = Finding(check_id="trivy", severity="high", title="t", rule="trivy-image/CVE-IMG")
    assert _is_review_finding(f)
    fs = Finding(check_id="trivy", severity="high", title="t", rule="CVE-FS")
    assert not _is_review_finding(fs)


def test_trivy_egress_disclosure_mentions_the_registry() -> None:
    # Sanity check on the widened disclosure (the own finding: the pre-mechanism-A
    # disclosure was accurate for fs-only mode but became false once image mode could also fetch
    # from a registry).
    assert "registry" in TrivyRunner.egress_dest.lower()
    assert "registry" in TrivyRunner.egress_sends.lower()


def _fake_semgrep_exec(captured: dict, rc: int = 0, out: str = '{"results": []}', err: str = ""):  # type: ignore[no-untyped-def]
    def fake_exec(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        captured["args"] = args
        return rc, out, err
    return fake_exec


def test_semgrep_invoke_disables_egress(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import agentsec.runners.semgrep as semgrep_mod

    captured: dict[str, list[str]] = {}
    monkeypatch.setattr(semgrep_mod, "exec_capture_or_raise", _fake_semgrep_exec(captured))
    SemgrepRunner().invoke(tmp_path, StackProfile(root=tmp_path, features={"python"}, python_dirs=["."]))
    assert "--disable-version-check" in captured["args"]
    assert "--metrics=off" in captured["args"]


def test_semgrep_invoke_tier0_runs_local_pack_only(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # #421: at the offline default (network_tier=0) semgrep passes ONLY the pinned on-disk
    # pack — none of the p/... registry shorthands that would fetch from semgrep.dev.
    import agentsec.runners.semgrep as semgrep_mod

    captured: dict[str, list[str]] = {}
    monkeypatch.setattr(semgrep_mod, "exec_capture_or_raise", _fake_semgrep_exec(captured))
    SemgrepRunner().invoke(tmp_path, StackProfile(root=tmp_path, features={"python"}, python_dirs=["."]))
    args = captured["args"]
    assert str(semgrep_mod.SEMGREP_RULES_DIR) in args           # local pack present
    assert not any(a.startswith("p/") for a in args)            # no registry fetch


def test_semgrep_invoke_tier1_adds_registry_packs(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # #421: at tier >= 1 the OSS registry packs join the local pack (disclosed advisory fetch).
    import agentsec.runners.semgrep as semgrep_mod

    captured: dict[str, list[str]] = {}
    monkeypatch.setattr(semgrep_mod, "exec_capture_or_raise", _fake_semgrep_exec(captured))
    profile = StackProfile(root=tmp_path, features={"python"}, python_dirs=["."], network_tier=1)
    SemgrepRunner().invoke(tmp_path, profile)
    args = captured["args"]
    assert str(semgrep_mod.SEMGREP_RULES_DIR) in args
    for pack in ("p/python", "p/owasp-top-ten", "p/secrets"):
        assert pack in args


def test_semgrep_invoke_raises_on_fatal_exit(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # #421: an unreachable/invalid --config makes semgrep exit rc>=2 with empty stdout.
    # That must surface as a runner error (ScannerExecError), NOT be masked as "ran, clean".
    import agentsec.runners.semgrep as semgrep_mod
    from agentsec.runners.base import ScannerExecError

    captured: dict[str, list[str]] = {}
    monkeypatch.setattr(
        semgrep_mod, "exec_capture_or_raise",
        _fake_semgrep_exec(captured, rc=2, out="", err="could not reach semgrep.dev"),
    )
    with pytest.raises(ScannerExecError):
        SemgrepRunner().invoke(tmp_path, StackProfile(root=tmp_path, features={"python"}, python_dirs=["."]))


def test_semgrep_invoke_findings_exit_is_not_an_error(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # rc==1 is semgrep's "findings found" exit (via --error), not a failure — must not raise,
    # and rc==0/1 with empty stdout still falls back to clean-empty JSON.
    import agentsec.runners.semgrep as semgrep_mod

    captured: dict[str, list[str]] = {}
    monkeypatch.setattr(semgrep_mod, "exec_capture_or_raise", _fake_semgrep_exec(captured, rc=1, out=""))
    raw = SemgrepRunner().invoke(tmp_path, StackProfile(root=tmp_path, features={"python"}, python_dirs=["."]))
    assert raw == '{"results": []}'


# --- OpenSSF Scorecard runner ----------------------------------------------

_SCORECARD_RAW = json.dumps({
    "repo": {"name": "github.com/acme/widget"},
    "score": 4.2,
    "checks": [
        {"name": "Dangerous-Workflow", "score": 0, "reason": "dangerous workflow patterns detected",
         "documentation": {"url": "https://x/dw"}},
        {"name": "Branch-Protection", "score": 3, "reason": "branch protection not enabled",
         "documentation": {"url": "https://x/bp"}},
        {"name": "Fuzzing", "score": -1, "reason": "not run"},          # not run → skipped
        {"name": "Token-Permissions", "score": 10, "reason": "all good"},  # perfect → skipped
        {"name": "License", "score": 6, "reason": "no license file"},    # <7, unlisted risk → medium
        {"name": "Webhooks", "score": 2, "reason": "no webhook auth"},   # docs: Critical
        {"name": "Binary-Artifacts", "score": 4, "reason": "binary in repo"},  # docs: High
    ],
})


def test_scorecard_parse() -> None:
    findings = ScorecardRunner().parse(_SCORECARD_RAW)
    by_rule = {f.rule: f for f in findings}
    # -1 (not run) and 10 (pass) are skipped; the three deficient checks surface.
    assert set(by_rule) == {
        "scorecard/Dangerous-Workflow", "scorecard/Branch-Protection", "scorecard/License",
        "scorecard/Webhooks", "scorecard/Binary-Artifacts",
    }
    dw = by_rule["scorecard/Dangerous-Workflow"]
    assert dw.severity == "critical"                    # from the risk map
    assert dw.check_id == "scorecard"
    assert dw.location == "github.com/acme/widget"
    assert dw.title == "OpenSSF Scorecard: Dangerous-Workflow scored 0/10"
    assert dw.url == "https://x/dw"
    assert dw.standards == ["OWASP:A06", "OWASP-LLM:LLM03"]
    assert by_rule["scorecard/Branch-Protection"].severity == "high"
    assert by_rule["scorecard/License"].severity == "medium"  # unlisted → conservative default
    # Severities match Scorecard's published docs/checks.md (regression guard against re-inversion).
    assert by_rule["scorecard/Webhooks"].severity == "critical"
    assert by_rule["scorecard/Binary-Artifacts"].severity == "high"


def test_scorecard_parse_total_on_junk() -> None:
    r = ScorecardRunner()
    for raw in ("", "   ", "not json", "[1,2,3]", '{"checks": [1, 2, "x"]}',
                '{"checks": [{"name": "X"}]}', '{"checks": [{"name": "X", "score": true}]}'):
        assert r.parse(raw) == [], f"parse({raw!r}) should be empty, never raise"


def _write_git_remote(root: Path, url: str) -> None:
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text(
        f'[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = {url}\n', encoding="utf-8"
    )


def test_scorecard_github_slug_parses_https_and_ssh(tmp_path: Path) -> None:
    for url, want in (
        ("https://github.com/acme/widget.git", "acme/widget"),
        ("https://github.com/acme/widget", "acme/widget"),
        ("https://github.com/acme/widget/", "acme/widget"),          # trailing slash
        ("git@github.com:acme/widget.git", "acme/widget"),
        ("ssh://git@ssh.github.com:443/acme/widget.git", "acme/widget"),  # ssh over https port
        ("https://github.com/acme/my.repo.git", "acme/my.repo"),     # dot in repo name
        ("https://gitlab.com/acme/widget.git", None),   # non-GitHub → None
        ("https://github.company.com/acme/widget.git", None),  # lookalike host → None
    ):
        d = tmp_path / url.replace("/", "_").replace(":", "_")
        d.mkdir()
        _write_git_remote(d, url)
        assert _github_slug(d) == want, url
    assert _github_slug(tmp_path / "no-git-here") is None  # missing .git → None


def test_scorecard_invoke_skips_without_token(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A GitHub remote but no token → invoke returns '' and never shells out."""
    import agentsec.runners.scorecard as sc_mod

    _write_git_remote(tmp_path, "https://github.com/acme/widget.git")
    monkeypatch.delenv("GITHUB_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    called = {"n": 0}

    def fake_exec(*a, **k):  # type: ignore[no-untyped-def]
        called["n"] += 1
        return 0, "{}", ""

    monkeypatch.setattr(sc_mod, "exec_capture_or_raise", fake_exec)
    assert ScorecardRunner().invoke(tmp_path, StackProfile(root=tmp_path)) == ""
    assert called["n"] == 0


def test_scorecard_invoke_skips_non_github(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """No GitHub remote → invoke returns '' even with a token present."""
    import agentsec.runners.scorecard as sc_mod

    _write_git_remote(tmp_path, "https://gitlab.com/acme/widget.git")
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "x")
    called = {"n": 0}
    monkeypatch.setattr(sc_mod, "exec_capture_or_raise",
                        lambda *a, **k: (called.__setitem__("n", called["n"] + 1), (0, "{}", ""))[1])
    assert ScorecardRunner().invoke(tmp_path, StackProfile(root=tmp_path)) == ""
    assert called["n"] == 0


def test_scorecard_invoke_passes_repo_flag(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """GitHub remote + token → invoke shells `scorecard --repo=github.com/owner/repo`."""
    import agentsec.runners.scorecard as sc_mod

    _write_git_remote(tmp_path, "git@github.com:acme/widget.git")
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "x")
    captured: dict[str, object] = {}

    def fake_exec(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        captured["args"] = args
        return 0, _SCORECARD_RAW, ""

    monkeypatch.setattr(sc_mod, "exec_capture_or_raise", fake_exec)
    ScorecardRunner().invoke(tmp_path, StackProfile(root=tmp_path))
    args = captured["args"]
    assert isinstance(args, list)
    assert args[0] == "scorecard"
    assert "--repo=github.com/acme/widget" in args
    assert "--format=json" in args


# --- deterministic vs live-advisory classification (F1) --------------------

def test_advisory_runners_are_nondeterministic() -> None:
    from agentsec.runners.node_audit import NodeAuditRunner
    from agentsec.runners.pip_audit import PipAuditRunner
    from agentsec.runners.react_doctor import ReactDoctorRunner
    from agentsec.runners.trivy import TrivyRunner
    for r in (NodeAuditRunner(), PipAuditRunner(), TrivyRunner(), ReactDoctorRunner(), ScorecardRunner()):
        assert r.deterministic is False, f"{r.id} should be live-advisory"
    # static, pinned-rule scanners stay deterministic (baseline-able)
    assert BanditRunner().deterministic is True
    assert GitleaksRunner().deterministic is True


def test_audit_deterministic_excludes_advisory_runners(tmp_path, monkeypatch) -> None:
    """audit(deterministic=True) skips runners whose `deterministic` is False."""
    import os

    from agentsec import audit as audit_mod
    from agentsec.runners.base import RunnerResult

    class _Advisory(Runner):
        id = "fake-advisory"
        binary = "true"
        deterministic = False

        def applies(self, profile: StackProfile) -> bool:
            return True

        def run(self, root: Path, profile: StackProfile) -> RunnerResult:
            return RunnerResult(self.id, available=True,
                                findings=[Finding(check_id=self.id, severity="high", title="x")])

    monkeypatch.setattr(audit_mod, "select_runners", lambda p: [_Advisory()])
    monkeypatch.setattr(audit_mod, "select_guards", lambda p: [])
    (tmp_path / "requirements.txt").write_text("fastapi\n", encoding="utf-8")

    det = audit_mod.audit(tmp_path, deterministic=True, exceptions_path=Path(os.devnull))
    assert "fake-advisory" not in det.ran
    nondet = audit_mod.audit(tmp_path, deterministic=False, exceptions_path=Path(os.devnull))
    assert "fake-advisory" in nondet.ran


# --- silent-success failures (#432 review) ----------------------------------
#
# Three shapes of "a failure that presents as success". The pre-existing partial-results
# tests asserted only that surviving findings survive; NONE asserted that the gap was
# disclosed, so a scan covering half the dependency surface stayed indistinguishable from
# a full one. These assert the disclosure itself.


def test_partial_scan_is_disclosed_in_both_channels() -> None:
    # One target fails while another returns a real CVE. Previously: available=True,
    # findings=1, error=None, no footer, no disclosure — half the surface unscanned and
    # reported as a normal run.
    class _Partial(Runner):
        id = "fake-dep-audit"
        binary = "python3"

        def applies(self, profile: StackProfile) -> bool:
            return True

        def invoke(self, root: Path, profile: StackProfile) -> str:
            self.note_partial_failure("requirements-dev.txt: timed out")
            return '{"vulns": ["CVE-2026-0001"]}'

        def parse(self, raw: str) -> list[Finding]:
            return [Finding(check_id=self.id, severity="high", title=v)
                    for v in json.loads(raw)["vulns"]]

    result = _Partial().run(Path("."), StackProfile(root=Path(".")))
    assert result.available and len(result.findings) == 2
    # channel 1: `error` set, so the runner lands in the report's tools_errored list
    assert result.error and "partial scan" in result.error
    # channel 2: an in-band finding, so the gap survives into EVERY format including SARIF
    disclosure = [f for f in result.findings if f.rule == "fake-dep-audit/partial-scan"]
    assert len(disclosure) == 1 and disclosure[0].severity == "info"
    # the real finding is untouched
    assert any(f.severity == "high" and f.title == "CVE-2026-0001" for f in result.findings)


def test_clean_scan_emits_no_partial_disclosure() -> None:
    # FP-bait for the above: a fully successful scan must stay silent, and `error` unset.
    class _Clean(Runner):
        id = "fake-clean"
        binary = "python3"

        def applies(self, profile: StackProfile) -> bool:
            return True

        def invoke(self, root: Path, profile: StackProfile) -> str:
            return "{}"

        def parse(self, raw: str) -> list[Finding]:
            return []

    result = _Clean().run(Path("."), StackProfile(root=Path(".")))
    assert result.available and result.findings == [] and not result.error


def test_launched_and_failed_scanner_is_not_reported_clean(tmp_path: Path) -> None:
    # "Surface launch failures" covered only rc == -1 (never launched). A scanner that
    # LAUNCHED and failed — bad config, OOM kill, permission error, the commoner case —
    # exits non-zero with no report and still read as clean for 9 of 10 runners.
    from agentsec.runners.base import ScannerExecError, exec_capture_or_raise

    with pytest.raises(ScannerExecError):
        exec_capture_or_raise(
            ["python3", "-c", "import sys; sys.stderr.write('bad config\\n'); sys.exit(2)"],
            cwd=tmp_path,
        )


def test_nonzero_exit_with_a_report_still_returns(tmp_path: Path) -> None:
    # The other side of that rule, and why it is keyed on empty output rather than on an
    # exit code: several scanners exit non-zero to mean "I found something", and that is a
    # successful run which must NOT raise.
    from agentsec.runners.base import exec_capture_or_raise

    rc, out, _ = exec_capture_or_raise(
        ["python3", "-c", "import sys; print('{\"results\": []}'); sys.exit(1)"], cwd=tmp_path
    )
    assert rc == 1 and out.strip() == '{"results": []}'


def test_scanner_reported_errors_become_a_finding() -> None:
    # bandit/semgrep report per-file failures in their own `errors[]` array. Dropping it
    # made a scan that skipped part of the tree read as a full one.
    from agentsec.runners.base import scanner_reported_errors

    out = scanner_reported_errors("semgrep", {"results": [], "errors": [{"message": "cannot parse a.py"}]})
    assert len(out) == 1 and out[0].severity == "info"
    assert out[0].rule == "semgrep/scanner-errors"
    # total on shape: never raises, whatever the scanner emits
    assert scanner_reported_errors("semgrep", {"errors": None}) == []
    assert scanner_reported_errors("semgrep", {}) == []
    assert scanner_reported_errors("semgrep", []) == []
    assert scanner_reported_errors("semgrep", None) == []


def test_semgrep_parse_surfaces_its_own_errors_array() -> None:
    raw = json.dumps({"results": [], "errors": [{"message": "rule pack failed to load"}]})
    out = SemgrepRunner().parse(raw)
    assert any(f.rule == "semgrep/scanner-errors" for f in out)


def test_bandit_parse_surfaces_its_own_errors_array() -> None:
    raw = json.dumps({"results": [], "errors": [{"filename": "a.py", "reason": "syntax error"}]})
    out = BanditRunner().parse(raw)
    assert any(f.rule == "bandit/scanner-errors" for f in out)


# --- #860: delegated scanners must inherit the DEFAULT_EXCLUDE_DIRS path policy -------------
#
# bandit/semgrep hand a DIRECTORY to the binary with `-r` and let it recurse, so — unlike the
# file-enumerating runners (hadolint/pip_audit) — they walked straight into a gitignored
# `.venv/site-packages` and reported third-party code under the user's repo path (664 spurious
# findings, 3 spurious HIGHs, in the field report). The two runners now pass a scanner-level
# exclude built from the SAME policy. Both directions are exercised (CLAUDE.md Rule 1): the
# vendored tree is dropped AND the user's own target is still scanned. The exact glob form was
# proven against the real binaries (bandit 1.9.x / semgrep 1.177) — the assertions below encode
# that proof, since the binaries are absent in CI.


def test_bandit_invoke_excludes_vendored_trees(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import agentsec.runners.bandit as bandit_mod

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    captured: dict[str, list[str]] = {}

    def fake_exec(args: list[str], cwd: Path, timeout: int = 300) -> tuple[int, str, str]:
        captured["args"] = args
        return 0, '{"results": []}', ""

    monkeypatch.setattr(bandit_mod, "exec_capture_or_raise", fake_exec)
    BanditRunner().invoke(tmp_path, StackProfile(root=tmp_path, python_dirs=["."]))
    args = captured["args"]
    assert "-x" in args
    xval = args[args.index("-x") + 1]
    # the policy dirs are excluded, in bandit's VERIFIED `*/name/*` form (a bare name does not match)
    for seg in ("*/.venv/*", "*/site-packages/*", "*/node_modules/*", "*/build/*"):
        assert seg in xval
    # still-fires direction: the user's own target dir is still handed to bandit
    assert str(tmp_path) in args


def test_bandit_exclude_glob_drops_vendored_keeps_user_code() -> None:
    # Hermetic both-directions proof: replicate bandit's own fnmatch(full_path, glob) matching so
    # the exclude semantics are tested without the binary. The FP-bait paths (a dir that merely
    # SUBSTRING-contains an excluded name) must stay in scope — over-exclusion would silence real
    # findings in the user's `mybuild/`, `venv_helper.py`, etc.
    import fnmatch

    from agentsec.runners.base import bandit_exclude_arg

    globs = bandit_exclude_arg().split(",")

    def excluded(p: str) -> bool:
        return any(fnmatch.fnmatch(p, g) for g in globs)

    # dropped — vendored/generated trees at any depth, under an absolute target path
    assert excluded("/repo/.venv/lib/python3.12/site-packages/pkg/mod.py")
    assert excluded("/repo/editor/.venv/lib/site-packages/dep/mod.py")
    assert excluded("/repo/node_modules/lib/mod.py")
    assert excluded("/repo/build/generated.py")
    # still fires — the user's own code, incl. FP-bait that only substring-matches a policy name
    assert not excluded("/repo/src/main.py")
    assert not excluded("/repo/mybuild/app.py")            # not a `build` segment
    assert not excluded("/repo/app/services/venv_helper.py")  # not a `venv` segment


def test_semgrep_invoke_excludes_vendored_trees(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import agentsec.runners.semgrep as semgrep_mod

    captured: dict[str, list[str]] = {}
    monkeypatch.setattr(semgrep_mod, "exec_capture_or_raise", _fake_semgrep_exec(captured))
    SemgrepRunner().invoke(tmp_path, StackProfile(root=tmp_path, features={"python"}, python_dirs=["."]))
    args = captured["args"]
    # semgrep's VERIFIED form is the bare segment name, one per `--exclude` (NOT bandit's glob)
    for seg in (".venv", "site-packages", "node_modules", "build"):
        assert seg in args
        assert args[args.index(seg) - 1] == "--exclude"
    # still-fires direction: the user's own target dir is still scanned
    assert str(tmp_path) in args


def test_scanner_exclude_helpers_use_their_own_verified_forms() -> None:
    # Locks in the review-doctrine Rule 2 lesson: the THREE scanners DISAGREE on the glob form,
    # each proven against the real binary (bandit 1.9 / semgrep 1.177 / trivy 0.73). A future
    # "unification" that gave them the same form would silently stop excluding a (top-level or
    # nested) vendored dir for at least one — a failure that presents as success. Fail loudly here.
    from agentsec.runners.base import bandit_exclude_arg, semgrep_exclude_args, trivy_skip_dirs_args

    # bandit: every pattern is the segment-anchored `*/name/*` glob
    assert all(p.startswith("*/") and p.endswith("/*") for p in bandit_exclude_arg().split(","))
    # semgrep: every excluded value is a BARE dir name (no slash, no glob metachar)
    semgrep_args = semgrep_exclude_args()
    semgrep_vals = [semgrep_args[i + 1] for i, a in enumerate(semgrep_args) if a == "--exclude"]
    assert semgrep_vals, "semgrep must pass at least one --exclude"
    assert all("/" not in v and "*" not in v for v in semgrep_vals)
    # trivy: every skipped value is the doublestar `**/name/**` glob (bare/`*/name/*` miss a nested dir)
    trivy_args = trivy_skip_dirs_args()
    trivy_vals = [trivy_args[i + 1] for i, a in enumerate(trivy_args) if a == "--skip-dirs"]
    assert trivy_vals, "trivy must pass at least one --skip-dirs"
    assert all(v.startswith("**/") and v.endswith("/**") for v in trivy_vals)
    # all three derive from the same policy — same set of directory names
    bandit_names = {p[2:-2] for p in bandit_exclude_arg().split(",")}
    assert bandit_names == set(semgrep_vals) == {v[3:-3] for v in trivy_vals}


def test_trivy_invoke_skips_vendored_trees(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # #860 (PR #870 review, Low): trivy's `fs` scan runs secret+misconfig over the whole walk, so
    # it anchored findings inside a gitignored `.venv` exactly like bandit. Assert the `--skip-dirs`
    # is present in the doublestar form AND the user's own root is still scanned.
    import agentsec.runners.trivy as trivy_mod

    captured: dict[str, list[str]] = {}

    def fake_exec(args, cwd, timeout=300, env_extra=None):  # type: ignore[no-untyped-def]
        captured["args"] = args
        return 0, '{"Results": []}', ""

    monkeypatch.setattr(trivy_mod, "exec_capture_or_raise", fake_exec)
    TrivyRunner().invoke(tmp_path, StackProfile(root=tmp_path))
    args = captured["args"]
    # the policy dirs are skipped in trivy's VERIFIED `**/name/**` doublestar form
    for seg in ("**/.venv/**", "**/site-packages/**", "**/node_modules/**"):
        assert seg in args
        assert args[args.index(seg) - 1] == "--skip-dirs"
    # still-fires direction: the user's own root is still handed to `trivy fs`
    assert str(tmp_path) in args
