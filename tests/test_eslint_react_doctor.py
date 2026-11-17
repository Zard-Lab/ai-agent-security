"""Parser tests for the ESLint and react-doctor runners (pure, no binaries)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import agentsec.runners.react_doctor as rd
from agentsec.runners.eslint import EslintRunner
from agentsec.runners.react_doctor import ReactDoctorRunner

from .conftest import mkprofile

# --- eslint ------------------------------------------------------------------


def test_eslint_security_rule_is_high() -> None:
    raw = json.dumps([
        {"filePath": "src/a.tsx", "messages": [
            {"ruleId": "security/detect-object-injection", "severity": 2, "line": 3, "message": "x"}
        ]}
    ])
    f = EslintRunner().parse(raw)
    assert len(f) == 1
    assert f[0].severity == "high" and f[0].location == "src/a.tsx:3"
    assert f[0].rule == "security/detect-object-injection" and f[0].standards == ["OWASP:A03"]


def test_eslint_security_warning_is_medium() -> None:
    raw = json.dumps([{"filePath": "a.ts", "messages": [
        {"ruleId": "security/detect-non-literal-fs-filename", "severity": 1, "line": 9, "message": "y"}
    ]}])
    assert EslintRunner().parse(raw)[0].severity == "medium"


def test_eslint_style_rule_is_info() -> None:
    raw = json.dumps([{"filePath": "a.ts", "messages": [
        {"ruleId": "no-unused-vars", "severity": 2, "line": 1, "message": "y"}
    ]}])
    f = EslintRunner().parse(raw)
    assert f[0].severity == "info" and f[0].standards == []


def test_eslint_handles_empty_and_null_rule() -> None:
    assert EslintRunner().parse("[]") == []
    # a parser-error message has ruleId null → must not crash; title falls back
    raw = json.dumps([{"filePath": "a.ts", "messages": [
        {"ruleId": None, "severity": 2, "line": 0, "message": "Parsing error"}
    ]}])
    f = EslintRunner().parse(raw)
    assert f[0].title == "eslint" and f[0].severity == "info"


# --- eslint: the runnable-project gate (#714) --------------------------------
#
# A repo that does not use ESLint must be a DISCLOSED SKIP, never a scanner error, and must
# not execute anything (`npx --no-install` still resolves the package against the npm
# registry before declining, which egressed at Tier 0). Both directions are tested: the
# skip, and — the direction traded against — that a real eslint project is STILL scanned.


def _eslint_project(root: Path, *, binary: bool = True, config: bool = True) -> None:
    """Plant a project where the project's own eslint is (or is not) runnable."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text('{"name": "t"}', encoding="utf-8")
    if binary:
        binp = root / "node_modules" / ".bin" / "eslint"
        binp.parent.mkdir(parents=True, exist_ok=True)
        binp.write_text("#!/bin/sh\n", encoding="utf-8")
    if config:
        (root / "eslint.config.js").write_text("export default [];\n", encoding="utf-8")


def _record_subprocesses(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Record every attempt to launch a scanner, and return the (initially empty) log.

    Recording rather than raising is load-bearing: `Runner.run()` swallows EVERY exception
    (base.py), so a stub that raised would be silently converted into an `error` string and
    the assertion would never reach the test. Assert the artifact, not the exception."""
    calls: list[object] = []

    def _record(*args: object, **kwargs: object) -> tuple[int, str, str]:
        calls.append(args)
        return (0, "[]", "")

    monkeypatch.setattr("agentsec.runners.eslint.exec_capture_or_raise", _record)
    monkeypatch.setattr("agentsec.runners.base.exec_capture", _record)
    return calls


def _stub_eslint_run(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    """Make the base class's binary probe + the scanner call deterministic."""
    monkeypatch.setattr("agentsec.runners.base.which", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr(
        "agentsec.runners.eslint.exec_capture_or_raise", lambda *a, **k: (0, raw, "")
    )


def test_eslint_runs_when_the_project_really_has_eslint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The direction traded against: a genuine eslint project must STILL be scanned."""
    _eslint_project(tmp_path)
    raw = json.dumps([{"filePath": "src/a.tsx", "messages": [
        {"ruleId": "security/detect-object-injection", "severity": 2, "line": 3, "message": "x"}
    ]}])
    _stub_eslint_run(monkeypatch, raw)
    res = EslintRunner().run(tmp_path, mkprofile(tmp_path, features={"frontend"}, frontend_dir="."))
    assert res.available is True and res.error is None
    assert [f.severity for f in res.findings] == ["high"]


def test_eslint_biome_bun_repo_is_a_disclosed_skip_not_an_error(tmp_path: Path) -> None:
    """The reported #714 shape: a RAG app's frontend is Biome + Bun with no eslint at all."""
    (tmp_path / "package.json").write_text(
        '{"name":"t","devDependencies":{"@biomejs/biome":"^1.9.0"}}', encoding="utf-8"
    )
    (tmp_path / "biome.json").write_text("{}", encoding="utf-8")
    (tmp_path / "bun.lock").write_text("", encoding="utf-8")
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".", package_managers={"bun"})
    res = EslintRunner().run(tmp_path, prof)
    assert res.available is False   # → "Scanners not installed (skipped)"
    assert res.error is None        # → NOT "Scanners that errored"
    assert res.findings == []


def test_eslint_pnpm_repo_without_eslint_emits_no_parse_error_finding(tmp_path: Path) -> None:
    """The pnpm shape of the same bug: `pnpm exec eslint` exits 1 with a progress banner on
    STDOUT, so exec_capture_or_raise did not raise and parse() turned the banner into a
    spurious `eslint: could not parse scanner output` info finding."""
    (tmp_path / "package.json").write_text('{"name":"t"}', encoding="utf-8")
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".", package_managers={"pnpm"})
    res = EslintRunner().run(tmp_path, prof)
    assert res.available is False and res.error is None
    assert not any("could not parse" in f.title for f in res.findings)


def test_eslint_skip_never_executes_a_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The egress lock. Assert the artifact (no subprocess), not the label: a future npx
    fallback must not be able to silently restore the Tier-0 registry fetch."""
    calls = _record_subprocesses(monkeypatch)
    res = EslintRunner().run(tmp_path, mkprofile(tmp_path, features={"frontend"}, frontend_dir="."))
    assert res.available is False and res.error is None
    assert calls == []  # nothing was launched, so nothing could reach registry.npmjs.org


@pytest.mark.parametrize(("binary", "config"), [(True, False), (False, True), (False, False)])
def test_eslint_needs_both_a_binary_and_a_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, binary: bool, config: bool,
) -> None:
    """Half a toolchain is not a scan: eslint exits non-zero with an empty report when it
    cannot find a config, which is the same `errored` trap as a missing binary."""
    _eslint_project(tmp_path, binary=binary, config=config)
    calls = _record_subprocesses(monkeypatch)
    res = EslintRunner().run(tmp_path, mkprofile(tmp_path, features={"frontend"}, frontend_dir="."))
    assert res.available is False and res.error is None and calls == []


def test_eslint_finds_a_hoisted_workspace_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """node_modules + the shared config at the repo ROOT with the app in a subdir is the
    normal monorepo shape — checking only frontend_dir would invent a new false skip."""
    _eslint_project(tmp_path)
    fe = tmp_path / "app" / "frontend"
    fe.mkdir(parents=True)
    (fe / "package.json").write_text('{"name": "fe"}', encoding="utf-8")
    _stub_eslint_run(monkeypatch, "[]")
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir="app/frontend")
    assert EslintRunner().run(tmp_path, prof).available is True


def test_eslint_config_in_package_json_counts_as_a_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ESLint 8 projects carry the config as a package.json key rather than a file."""
    _eslint_project(tmp_path, config=False)
    (tmp_path / "package.json").write_text(
        '{"name":"t","eslintConfig":{"root":true}}', encoding="utf-8"
    )
    _stub_eslint_run(monkeypatch, "[]")
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".")
    assert EslintRunner().run(tmp_path, prof).available is True


def test_eslint_tolerates_unreadable_or_malformed_package_json(tmp_path: Path) -> None:
    """The config probe must never raise on shape — a broken manifest is a skip, not a crash."""
    (tmp_path / "package.json").write_text("{not json", encoding="utf-8")
    res = EslintRunner().run(tmp_path, mkprofile(tmp_path, features={"frontend"}, frontend_dir="."))
    assert res.available is False and res.error is None


def test_eslint_skip_honours_frontend_dir_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`frontend_dir` is `str | None`; None must behave like "." and not crash _search_dirs."""
    calls = _record_subprocesses(monkeypatch)
    res = EslintRunner().run(tmp_path, mkprofile(tmp_path, features={"frontend"}, frontend_dir=None))
    assert res.available is False and res.error is None and calls == []


# --- eslint: config vocabulary vs installed major version (#720 review) ------
#
# A config file existing is not a config eslint will ACCEPT. From v9 the flat config is the
# default and eslint refuses a legacy-only project, exiting non-zero with an empty report --
# the same `errored` trap as a missing binary, through a different door. Verified against a
# real eslint 9.39.5: "ESLint couldn't find an eslint.config.(js|mjs|cjs) file."


def _plant_version(root: Path, version: str) -> None:
    p = root / "node_modules" / "eslint" / "package.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"name": "eslint", "version": version}), encoding="utf-8")


def _plant_legacy_config(root: Path) -> None:
    (root / "eslint.config.js").unlink(missing_ok=True)
    (root / ".eslintrc.json").write_text('{"root": true}', encoding="utf-8")


def test_eslint9_with_legacy_config_only_is_a_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The #720 review finding: eslint 9 cannot run here, so do not pretend it errored."""
    _eslint_project(tmp_path)
    _plant_legacy_config(tmp_path)
    _plant_version(tmp_path, "9.39.5")
    monkeypatch.delenv("ESLINT_USE_FLAT_CONFIG", raising=False)
    calls = _record_subprocesses(monkeypatch)
    res = EslintRunner().run(tmp_path, mkprofile(tmp_path, features={"frontend"}, frontend_dir="."))
    assert res.available is False and res.error is None and calls == []


def test_eslint9_with_flat_config_still_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Traded-against direction: the normal, correctly-migrated v9 project must still scan."""
    _eslint_project(tmp_path)  # writes eslint.config.js
    _plant_version(tmp_path, "9.39.5")
    monkeypatch.delenv("ESLINT_USE_FLAT_CONFIG", raising=False)
    _stub_eslint_run(monkeypatch, "[]")
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".")
    assert EslintRunner().run(tmp_path, prof).available is True


def test_eslint8_with_legacy_config_still_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Traded-against direction: v8 accepts eslintrc, so the version gate must not skip it."""
    _eslint_project(tmp_path)
    _plant_legacy_config(tmp_path)
    _plant_version(tmp_path, "8.57.0")
    monkeypatch.delenv("ESLINT_USE_FLAT_CONFIG", raising=False)
    _stub_eslint_run(monkeypatch, "[]")
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".")
    assert EslintRunner().run(tmp_path, prof).available is True


def test_eslint9_legacy_config_runs_when_the_opt_out_is_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The user deliberately opted legacy back in; honor it rather than inventing a skip.

    `exec_capture` builds the child env from `child_env()` == dict(os.environ) + PATH, so
    what we read here is exactly what the scanner subprocess will see."""
    _eslint_project(tmp_path)
    _plant_legacy_config(tmp_path)
    _plant_version(tmp_path, "9.39.5")
    monkeypatch.setenv("ESLINT_USE_FLAT_CONFIG", "false")
    _stub_eslint_run(monkeypatch, "[]")
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".")
    assert EslintRunner().run(tmp_path, prof).available is True


@pytest.mark.parametrize("version_json", ['{"version": "not-a-version"}', "{not json", '{"a": 1}'])
def test_eslint_unreadable_version_stays_permissive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version_json: str,
) -> None:
    """A false SKIP is a silent coverage loss, so an undeterminable version accepts both
    vocabularies rather than guessing."""
    _eslint_project(tmp_path)
    _plant_legacy_config(tmp_path)
    p = tmp_path / "node_modules" / "eslint" / "package.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(version_json, encoding="utf-8")
    monkeypatch.delenv("ESLINT_USE_FLAT_CONFIG", raising=False)
    _stub_eslint_run(monkeypatch, "[]")
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".")
    assert EslintRunner().run(tmp_path, prof).available is True


def test_eslint9_flat_config_at_workspace_root_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The version gate must search the same dirs as the rest of the precondition."""
    _eslint_project(tmp_path)  # root: .bin/eslint + eslint.config.js
    _plant_version(tmp_path, "9.39.5")
    fe = tmp_path / "app" / "frontend"
    fe.mkdir(parents=True)
    (fe / "package.json").write_text('{"name": "fe"}', encoding="utf-8")
    monkeypatch.delenv("ESLINT_USE_FLAT_CONFIG", raising=False)
    _stub_eslint_run(monkeypatch, "[]")
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir="app/frontend")
    assert EslintRunner().run(tmp_path, prof).available is True


def test_eslint_skip_is_disclosed_in_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end: the skip reaches the user as a disclosure, and never as an error."""
    from agentsec.audit import audit

    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".")
    monkeypatch.setattr("agentsec.audit.select_runners", lambda profile: [EslintRunner()])
    monkeypatch.setattr("agentsec.audit.select_guards", lambda profile: [])
    monkeypatch.setattr("agentsec.audit.detect", lambda root: prof)
    res = audit(tmp_path, exceptions_path=Path("/dev/null"))
    assert "eslint" in res.tools_unavailable
    assert "eslint" not in res.tools_errored and "eslint" not in res.ran
    notices = res.coverage_notices()
    assert any("not installed (skipped)" in n and "eslint" in n for n in notices)
    assert not any("errored" in n for n in notices)


# --- react-doctor ------------------------------------------------------------


def _rd(diagnostics: list[dict]) -> str:
    # 0.5.x schemaVersion-1 report: flat top-level diagnostics[] + summary + projects[].
    return json.dumps({
        "schemaVersion": 1,
        "summary": {"errorCount": 0, "warningCount": 0},
        "projects": [{"project": {"projectName": "app"}, "score": {"score": 90}}],
        "diagnostics": diagnostics,
    })


def test_react_doctor_security_error_is_high_xss() -> None:
    raw = _rd([{"filePath": "src/A.jsx", "rule": "no-dangerous-html", "severity": "error",
                "message": "dangerouslySetInnerHTML without sanitization", "line": 5, "category": "Security"}])
    f = ReactDoctorRunner().parse(raw)
    assert len(f) == 1
    assert f[0].severity == "high" and f[0].standards == ["OWASP:A03"]
    assert f[0].location == "src/A.jsx:5" and f[0].rule == "react-doctor/no-dangerous-html"


def test_react_doctor_secret_maps_to_a07() -> None:
    raw = _rd([{"filePath": "src/A.jsx", "rule": "hardcoded-secret", "severity": "error",
                "message": "API key found", "line": 3, "category": "Security"}])
    assert ReactDoctorRunner().parse(raw)[0].standards == ["OWASP:A07"]


def test_react_doctor_non_security_is_info() -> None:
    raw = _rd([{"filePath": "package.json", "rule": "unused-dependency", "severity": "warning",
                "message": "x", "line": 0, "category": "Dead Code"}])
    f = ReactDoctorRunner().parse(raw)
    assert f[0].severity == "info" and f[0].standards == [] and f[0].location == "package.json"


def test_react_doctor_empty_and_no_diagnostics() -> None:
    # An empty object, or a report with no diagnostics, yields no findings (a clean repo
    # — react-doctor reports score: null with zero diagnostics).
    assert ReactDoctorRunner().parse("{}") == []
    assert ReactDoctorRunner().parse(_rd([])) == []
    assert ReactDoctorRunner().parse(json.dumps({"schemaVersion": 1})) == []
    assert ReactDoctorRunner().parse(json.dumps({"ok": True, "diagnostics": []})) == []


def test_react_doctor_scan_error_is_info() -> None:
    # A tool-reported scan error (ok: false) surfaces as one info finding, not a silent skip.
    f = ReactDoctorRunner().parse(json.dumps({"ok": False, "error": "boom", "diagnostics": []}))
    assert len(f) == 1 and f[0].severity == "info" and f[0].rule == "react-doctor/scan-error"


def _captured_argv(monkeypatch: pytest.MonkeyPatch) -> dict:
    calls: dict = {}

    def fake_exec(args: list[str], cwd: Path, timeout: int) -> tuple[int, str, str]:
        calls["args"] = args
        calls["cwd"] = cwd
        return (0, '{"diagnostics": []}', "")

    monkeypatch.setattr(rd, "exec_capture_or_raise", fake_exec)
    return calls


def test_react_doctor_invoke_uses_npx_when_not_installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _captured_argv(monkeypatch)
    out = ReactDoctorRunner().invoke(tmp_path, mkprofile(tmp_path, features={"frontend"}, frontend_dir="."))
    assert out == '{"diagnostics": []}'
    assert calls["args"][:3] == ["npx", "-y", f"react-doctor@{rd.REACT_DOCTOR_VERSION}"]
    assert "--no-telemetry" in calls["args"] and "--json" in calls["args"]


def test_react_doctor_invoke_prefers_installed_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binp = tmp_path / "node_modules" / ".bin" / "react-doctor"
    binp.parent.mkdir(parents=True)
    binp.write_text("#!/bin/sh\n", encoding="utf-8")
    calls = _captured_argv(monkeypatch)
    ReactDoctorRunner().invoke(tmp_path, mkprofile(tmp_path, features={"frontend"}, frontend_dir="."))
    assert calls["args"][0] == str(binp)  # the installed binary, not npx
    assert "npx" not in calls["args"]
    assert "--no-telemetry" in calls["args"]
