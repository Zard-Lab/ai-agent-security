"""Tests for the go-osv-hygiene runner (mechanism C)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsec.runners.go_osv_hygiene import (
    GoOsvHygieneRunner,
    _escape_module_path,
    parse_go_mod,
    parse_go_mod_replace,
)
from tests.conftest import mkprofile


def _runner() -> GoOsvHygieneRunner:
    return GoOsvHygieneRunner()


# -- go.mod parsing ----------------------------------------------------------------------

def test_parse_go_mod_single_line_require() -> None:
    text = "module example.com/app\n\ngo 1.22\n\nrequire golang.org/x/crypto v0.31.0\n"
    assert parse_go_mod(text) == [("golang.org/x/crypto", "v0.31.0")]


def test_parse_go_mod_block_require() -> None:
    text = (
        "module example.com/app\n\ngo 1.22\n\n"
        "require (\n"
        "\tgolang.org/x/crypto v0.31.0\n"
        "\tgolang.org/x/net v0.28.0 // indirect\n"
        ")\n"
    )
    assert parse_go_mod(text) == [
        ("golang.org/x/crypto", "v0.31.0"),
        ("golang.org/x/net", "v0.28.0"),
    ]


def test_parse_go_mod_mixed_single_and_block() -> None:
    text = (
        "module example.com/app\n\ngo 1.22\n\n"
        "require github.com/pkg/errors v0.9.1\n\n"
        "require (\n"
        "\tgolang.org/x/crypto v0.31.0\n"
        ")\n"
    )
    assert parse_go_mod(text) == [
        ("github.com/pkg/errors", "v0.9.1"),
        ("golang.org/x/crypto", "v0.31.0"),
    ]


def test_parse_go_mod_no_require_block() -> None:
    assert parse_go_mod("module example.com/app\n\ngo 1.22\n") == []


def test_parse_go_mod_ignores_module_and_go_directives() -> None:
    # "module"/"go" lines must not be misread as a require entry.
    text = "module example.com/app\ngo 1.22\n"
    assert parse_go_mod(text) == []


# -- go.mod replace-directive parsing -----------------------------------------------------

def test_parse_go_mod_replace_single_line() -> None:
    text = "replace golang.org/x/crypto => golang.org/x/crypto v0.17.0\n"
    assert parse_go_mod_replace(text) == [("golang.org/x/crypto", "v0.17.0")]


def test_parse_go_mod_replace_with_old_version_constraint() -> None:
    # OLDVERSION is optional on the left of `=>` -- must not be confused with NEWVERSION.
    text = "replace golang.org/x/net v0.20.0 => golang.org/x/net v0.17.0\n"
    assert parse_go_mod_replace(text) == [("golang.org/x/net", "v0.17.0")]


def test_parse_go_mod_replace_to_different_module() -> None:
    text = "replace github.com/old/fork => github.com/new/fork v2.0.0\n"
    assert parse_go_mod_replace(text) == [("github.com/new/fork", "v2.0.0")]


def test_parse_go_mod_replace_block_form() -> None:
    text = (
        "replace (\n"
        "\tgithub.com/old/fork => github.com/new/fork v2.0.0\n"
        "\tgolang.org/x/net v0.20.0 => golang.org/x/net v0.17.0\n"
        ")\n"
    )
    assert parse_go_mod_replace(text) == [
        ("github.com/new/fork", "v2.0.0"),
        ("golang.org/x/net", "v0.17.0"),
    ]


def test_parse_go_mod_replace_local_path_excluded() -> None:
    # A local filesystem path has no version to check -- Go itself REQUIRES no NEWVERSION
    # in this case, so the version group simply never matches.
    text = "replace example.com/local-thing => ../local-thing\n"
    assert parse_go_mod_replace(text) == []


def test_parse_go_mod_replace_no_replace_block() -> None:
    assert parse_go_mod_replace("module example.com/app\n\ngo 1.22\n") == []


def test_parse_go_mod_replace_mixed_with_require() -> None:
    # A real go.mod with both require and replace blocks -- confirms the two parsers don't
    # interfere with each other on the same text (verified live against this exact shape).
    text = (
        "module example.com/app\n\ngo 1.22\n\n"
        "require (\n"
        "\tgolang.org/x/crypto v0.31.0\n"
        "\tgolang.org/x/net v0.28.0 // indirect\n"
        ")\n\n"
        "require github.com/pkg/errors v0.9.1\n\n"
        "replace golang.org/x/crypto => golang.org/x/crypto v0.17.0\n\n"
        "replace (\n"
        "\tgithub.com/old/fork => github.com/new/fork v2.0.0\n"
        "\texample.com/local-thing => ../local-thing\n"
        ")\n"
    )
    assert parse_go_mod(text) == [
        ("golang.org/x/crypto", "v0.31.0"),
        ("golang.org/x/net", "v0.28.0"),
        ("github.com/pkg/errors", "v0.9.1"),
    ]
    assert parse_go_mod_replace(text) == [
        ("golang.org/x/crypto", "v0.17.0"),
        ("github.com/new/fork", "v2.0.0"),
    ]


# -- parse() — confirmed (SEMVER-range) vulnerability -------------------------------------

def test_parse_confirmed_vuln_fires_high() -> None:
    raw = json.dumps({"modules": [{
        "module": "golang.org/x/crypto", "version": "v0.17.0", "resolves": True,
        "vulns": [{"id": "GO-2024-1234", "aliases": ["CVE-2024-9999", "GHSA-aaaa-bbbb-cccc"],
                   "summary": "some real vuln", "confirmed": True}],
    }]})
    findings = _runner().parse(raw)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].rule == "GO-2024-1234"
    assert "golang.org/x/crypto" in findings[0].title


# -- parse() — replace-directive source labeling ------------------------------------------

def test_parse_replace_source_vuln_is_labeled() -> None:
    raw = json.dumps({"modules": [{
        "module": "golang.org/x/crypto", "version": "v0.17.0", "resolves": True, "source": "replace",
        "vulns": [{"id": "GO-2024-1234", "aliases": [], "summary": "some real vuln", "confirmed": True}],
    }]})
    findings = _runner().parse(raw)
    assert len(findings) == 1
    assert "replace" in findings[0].title.lower()
    assert "replace" in findings[0].remediation.lower()


def test_parse_require_source_default_not_labeled_as_replace() -> None:
    # No "source" key at all (the shape older callers/tests already use) must default to
    # "require" framing, not silently misreport as a replace-directive finding.
    raw = json.dumps({"modules": [{
        "module": "golang.org/x/crypto", "version": "v0.17.0", "resolves": True,
        "vulns": [{"id": "GO-2024-1234", "aliases": [], "summary": "x", "confirmed": True}],
    }]})
    findings = _runner().parse(raw)
    assert "replace" not in findings[0].title.lower()


# -- parse() — needs-review (non-SEMVER-range) vulnerability ------------------------------

def test_parse_unconfirmed_vuln_fires_medium_needs_review() -> None:
    raw = json.dumps({"modules": [{
        "module": "example.com/tool", "version": "v1.0.0", "resolves": True,
        "vulns": [{"id": "GO-2025-5678", "aliases": [], "summary": "commit-boundary vuln",
                   "confirmed": False}],
    }]})
    findings = _runner().parse(raw)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "needs manual review" in findings[0].message.lower() or "review" in findings[0].message.lower()


# -- parse() — alias deduplication ---------------------------------------------------------

def test_parse_alias_dedup_reports_once() -> None:
    # Same underlying vuln reported under 3 different IDs (GHSA, a GO id, and one that
    # cross-references the GO id via aliases) -- must collapse to ONE finding.
    raw = json.dumps({"modules": [{
        "module": "golang.org/x/crypto", "version": "v0.17.0", "resolves": True,
        "vulns": [
            {"id": "GHSA-45gg-vh54-h5m9", "aliases": ["CVE-2026-39828", "GO-2026-5014"],
             "summary": "cert bypass", "confirmed": True},
            {"id": "GO-2026-5014", "aliases": ["CVE-2026-39828", "GHSA-45gg-vh54-h5m9"],
             "summary": "cert bypass", "confirmed": True},
        ],
    }]})
    findings = _runner().parse(raw)
    assert len(findings) == 1
    # The canonical GO- id is preferred as the reported rule when present in the group.
    assert findings[0].rule == "GO-2026-5014"


def test_parse_distinct_vulns_not_merged() -> None:
    # Two genuinely unrelated vulns (no shared aliases) for the same module must stay separate.
    raw = json.dumps({"modules": [{
        "module": "golang.org/x/crypto", "version": "v0.17.0", "resolves": True,
        "vulns": [
            {"id": "GO-2024-1111", "aliases": ["CVE-2024-1111"], "summary": "vuln A", "confirmed": True},
            {"id": "GO-2024-2222", "aliases": ["CVE-2024-2222"], "summary": "vuln B", "confirmed": True},
        ],
    }]})
    findings = _runner().parse(raw)
    assert len(findings) == 2
    assert {f.rule for f in findings} == {"GO-2024-1111", "GO-2024-2222"}


# -- parse() — module-path resolution ------------------------------------------------------

def test_parse_unresolvable_module_fires() -> None:
    raw = json.dumps({"modules": [{
        "module": "example.com/typo-module", "version": "v1.0.0", "resolves": False, "vulns": [],
    }]})
    findings = _runner().parse(raw)
    assert len(findings) == 1
    assert findings[0].rule == "go-osv-hygiene/unresolvable-module-path"
    assert findings[0].severity == "medium"


def test_parse_resolvable_clean_module_silent() -> None:
    raw = json.dumps({"modules": [{
        "module": "golang.org/x/crypto", "version": "v0.31.0", "resolves": True, "vulns": [],
    }]})
    assert _runner().parse(raw) == []


def test_parse_unresolvable_module_with_vulns_only_reports_vulns() -> None:
    # If OSV somehow returned vulns for a module that ALSO failed to resolve (shouldn't
    # normally happen given invoke()'s own logic, but parse() must not double-report), only
    # the vuln finding(s) fire -- the unresolvable-path finding is specifically for the
    # zero-vulns case, where "clean" would otherwise be misleading.
    raw = json.dumps({"modules": [{
        "module": "example.com/weird", "version": "v1.0.0", "resolves": False,
        "vulns": [{"id": "GO-2024-9999", "aliases": [], "summary": "x", "confirmed": True}],
    }]})
    findings = _runner().parse(raw)
    assert len(findings) == 1
    assert findings[0].rule == "GO-2024-9999"


def test_parse_empty_modules_silent() -> None:
    assert _runner().parse(json.dumps({"modules": []})) == []


def test_parse_total_on_malformed_input() -> None:
    assert _runner().parse(json.dumps({})) == []


# -- applies() ------------------------------------------------------------------------------

def test_applies_unconditionally() -> None:
    assert GoOsvHygieneRunner().applies(mkprofile(Path("/tmp"), features=set())) is True


# -- invoke() orchestration (monkeypatched network calls) -----------------------------------

def test_invoke_no_go_mod_returns_empty(tmp_path: Path) -> None:
    raw = GoOsvHygieneRunner().invoke(tmp_path, mkprofile(tmp_path, features=set()))
    assert json.loads(raw) == {"modules": []}


def test_invoke_queries_replace_target_independently_of_require(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A `replace` pinning the SAME module to an OLDER, vulnerable version than what `require`
    # declares -- the exact real-world shape this extension exists to catch. Both the
    # require-side (clean) and replace-side (vulnerable) versions must be queried and
    # labeled independently, since the replace is what actually gets compiled in.
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\ngo 1.22\n\n"
        "require golang.org/x/crypto v0.31.0\n\n"
        "replace golang.org/x/crypto => golang.org/x/crypto v0.17.0\n",
        encoding="utf-8",
    )

    queried_versions: list[str] = []

    def fake_http_json(url: str, *, tier: int = 1, body: dict[str, object] | None = None) -> object:
        assert body is not None
        queries = body["queries"]
        assert isinstance(queries, list)
        results = []
        for q in queries:
            assert isinstance(q, dict)
            version = q["version"]
            assert isinstance(version, str)
            queried_versions.append(version)
            if version == "v0.17.0":
                results.append({"vulns": [{"id": "GO-2024-1234"}]})
            else:
                results.append({})
        return {"results": results}

    def fake_detail(url: str, *, tier: int = 1, body: dict[str, object] | None = None) -> object:
        return {"id": "GO-2024-1234", "aliases": [], "summary": "vulnerable old pin",
                "affected": [{"package": {"name": "golang.org/x/crypto"},
                              "ranges": [{"type": "SEMVER"}]}]}

    def dispatch(url: str, *, tier: int = 1, body: dict[str, object] | None = None) -> object:
        return fake_detail(url, tier=tier, body=body) if "vulns/" in url else fake_http_json(url, tier=tier, body=body)

    monkeypatch.setattr("agentsec.runners.go_osv_hygiene._http_json", dispatch)
    # The require-side entry (v0.31.0) has zero vulns, so invoke() falls back to a module-
    # resolution check for it -- not what this test is about; keep it out of the way rather
    # than let it depend on the ambient network_tier (mirrors the isolation used above for
    # test_invoke_network_failure_notes_partial_not_total).
    monkeypatch.setattr("agentsec.runners.go_osv_hygiene._module_resolves", lambda *a, **k: True)

    raw = GoOsvHygieneRunner().invoke(tmp_path, mkprofile(tmp_path, features=set()))
    data = json.loads(raw)
    assert sorted(queried_versions) == ["v0.17.0", "v0.31.0"]

    by_source = {m["source"]: m for m in data["modules"]}
    assert by_source["require"]["version"] == "v0.31.0"
    assert by_source["require"]["vulns"] == []
    assert by_source["replace"]["version"] == "v0.17.0"
    assert by_source["replace"]["vulns"][0]["id"] == "GO-2024-1234"

    findings = GoOsvHygieneRunner().parse(raw)
    assert len(findings) == 1
    assert "replace" in findings[0].title.lower()


def test_invoke_orchestrates_batch_detail_and_resolution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\ngo 1.22\n\n"
        "require (\n"
        "\tgolang.org/x/crypto v0.17.0\n"
        "\texample.com/typo-module v1.0.0\n"
        ")\n",
        encoding="utf-8",
    )

    def fake_http_json(url: str, *, tier: int = 1, body: dict[str, object] | None = None) -> object:
        if "querybatch" in url:
            assert body is not None
            assert body["queries"] == [
                {"package": {"name": "golang.org/x/crypto", "ecosystem": "Go"}, "version": "v0.17.0"},
                {"package": {"name": "example.com/typo-module", "ecosystem": "Go"}, "version": "v1.0.0"},
            ]
            return {"results": [{"vulns": [{"id": "GO-2024-1234"}]}, {}]}
        if "vulns/GO-2024-1234" in url:
            return {
                "id": "GO-2024-1234", "aliases": [], "summary": "a real vuln",
                "affected": [{"package": {"name": "golang.org/x/crypto"},
                              "ranges": [{"type": "SEMVER"}]}],
            }
        raise AssertionError(f"unexpected URL: {url}")

    def fake_resolves(module: str, version: str, *, tier: int = 1) -> bool:
        assert module == "example.com/typo-module"
        assert version == "v1.0.0"
        return False

    monkeypatch.setattr("agentsec.runners.go_osv_hygiene._http_json", fake_http_json)
    monkeypatch.setattr("agentsec.runners.go_osv_hygiene._module_resolves", fake_resolves)

    raw = GoOsvHygieneRunner().invoke(tmp_path, mkprofile(tmp_path, features=set()))
    data = json.loads(raw)
    modules = {m["module"]: m for m in data["modules"]}

    assert modules["golang.org/x/crypto"]["vulns"][0]["id"] == "GO-2024-1234"
    assert modules["golang.org/x/crypto"]["vulns"][0]["confirmed"] is True
    assert modules["golang.org/x/crypto"]["resolves"] is True  # never checked -- a hit already proves it

    assert modules["example.com/typo-module"]["vulns"] == []
    assert modules["example.com/typo-module"]["resolves"] is False


def test_invoke_network_failure_notes_partial_not_total(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "go.mod").write_text(
        "require golang.org/x/crypto v0.17.0\n", encoding="utf-8",
    )

    def fake_http_json(url: str, *, tier: int = 1, body: dict[str, object] | None = None) -> object:
        if "querybatch" in url:
            return {"results": [{"vulns": [{"id": "GO-2024-1234"}]}]}
        raise TimeoutError("simulated network failure")

    runner = GoOsvHygieneRunner()
    # _partial_failures is a class-level mutable default, only reset by run() -- direct
    # .invoke() calls (as this test does) must reset it themselves to stay order-independent.
    runner._partial_failures = []
    monkeypatch.setattr("agentsec.runners.go_osv_hygiene._http_json", fake_http_json)
    # Isolate what this test actually checks (a detail-fetch failure) from the module-
    # resolution fallback call this runner also makes when a module ends up with zero
    # vulns (real behavior, covered by its own dedicated tests above).
    monkeypatch.setattr("agentsec.runners.go_osv_hygiene._module_resolves", lambda *a, **k: True)

    raw = runner.invoke(tmp_path, mkprofile(tmp_path, features=set()))
    data = json.loads(raw)
    assert data["modules"][0]["vulns"] == []  # the detail fetch failed, so no vuln recorded
    assert len(runner._partial_failures) == 1


def test_escape_module_path_encodes_uppercase() -> None:
    # Review H1 (verified live against the real proxy before this fix): an un-escaped uppercase
    # module path 404s even for a real, well-known module.
    assert _escape_module_path("github.com/Masterminds/semver/v3") == "github.com/!masterminds/semver/v3"
    assert _escape_module_path("github.com/Azure/azure-sdk-for-go") == "github.com/!azure/azure-sdk-for-go"


def test_escape_module_path_multi_uppercase() -> None:
    assert _escape_module_path("github.com/BurntSushi/toml") == "github.com/!burnt!sushi/toml"


def test_escape_module_path_lowercase_unchanged() -> None:
    assert _escape_module_path("golang.org/x/crypto") == "golang.org/x/crypto"


def test_module_resolves_escapes_the_url(monkeypatch: pytest.MonkeyPatch) -> None:
    # Confirms the fix is actually wired in, not just present as a standalone helper.
    from agentsec.runners import go_osv_hygiene as mod

    seen: dict[str, str] = {}

    def fake_get(url: str, **kwargs: object) -> bytes:
        seen["url"] = url
        return b"{}"

    monkeypatch.setattr(mod.net, "get", fake_get)
    mod._module_resolves("github.com/Masterminds/semver/v3", "v3.2.1", tier=1)
    assert "!masterminds" in seen["url"] and "Masterminds" not in seen["url"]


def test_invoke_short_batch_notes_partial_failure_not_silent_drop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Review H2: OSV returning fewer results than queries must not silently evaluate only the
    # first N modules and read as a completed clean scan of everything.
    (tmp_path / "go.mod").write_text(
        "require (\n\tgolang.org/x/crypto v0.17.0\n\tgolang.org/x/text v0.14.0\n)\n",
        encoding="utf-8",
    )

    def fake_http_json(url: str, *, tier: int = 1, body: dict[str, object] | None = None) -> object:
        assert "querybatch" in url
        return {"results": [{"vulns": []}]}  # 1 result for 2 queried modules

    runner = GoOsvHygieneRunner()
    # _partial_failures is a class-level mutable default, only reset by run() -- direct
    # .invoke() calls (as this test does) must reset it themselves to stay order-independent.
    runner._partial_failures = []
    monkeypatch.setattr("agentsec.runners.go_osv_hygiene._http_json", fake_http_json)
    monkeypatch.setattr("agentsec.runners.go_osv_hygiene._module_resolves", lambda *a, **k: True)

    raw = runner.invoke(tmp_path, mkprofile(tmp_path, features=set()))
    data = json.loads(raw)
    assert len(data["modules"]) == 1  # only the module OSV actually returned a result for
    assert len(runner._partial_failures) == 1
    assert "golang.org/x/text" in runner._partial_failures[0]  # names the dropped module


def test_invoke_null_batch_entry_does_not_crash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Review M1: a null entry in the OSV batch response must not raise AttributeError and
    # discard every already-fetched finding in the run.
    (tmp_path / "go.mod").write_text(
        "require (\n\tgolang.org/x/crypto v0.17.0\n\tgolang.org/x/text v0.14.0\n)\n",
        encoding="utf-8",
    )

    def fake_http_json(url: str, *, tier: int = 1, body: dict[str, object] | None = None) -> object:
        if "querybatch" in url:
            return {"results": [{"vulns": [{"id": "GO-2024-1234"}]}, None]}
        return {"id": "GO-2024-1234", "aliases": [], "summary": "x",
                "affected": [{"package": {"name": "golang.org/x/crypto"}, "ranges": [{"type": "SEMVER"}]}]}

    runner = GoOsvHygieneRunner()
    # _partial_failures is a class-level mutable default, only reset by run() -- direct
    # .invoke() calls (as this test does) must reset it themselves to stay order-independent.
    runner._partial_failures = []
    monkeypatch.setattr("agentsec.runners.go_osv_hygiene._http_json", fake_http_json)
    monkeypatch.setattr("agentsec.runners.go_osv_hygiene._module_resolves", lambda *a, **k: True)

    raw = runner.invoke(tmp_path, mkprofile(tmp_path, features=set()))  # must not raise
    data = json.loads(raw)
    modules = {m["module"]: m for m in data["modules"]}
    assert modules["golang.org/x/crypto"]["vulns"][0]["id"] == "GO-2024-1234"  # not discarded
    assert modules["golang.org/x/text"]["vulns"] == []  # the null entry, handled gracefully


def test_invoke_refuses_below_tier_1(tmp_path: Path) -> None:
    # Real behavior, not mocked: network_tier defaults to 0 (offline) on a profile built
    # without audit()'s tier stamping, and net.get() must refuse rather than silently call
    # out. Caught live while fixing a different test in this file (the fallback
    # module-resolution call legitimately refused at Tier 0) -- worth a dedicated test.
    (tmp_path / "go.mod").write_text("require golang.org/x/crypto v0.17.0\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features=set())
    assert profile.network_tier == 0
    with pytest.raises(RuntimeError, match="tier"):
        GoOsvHygieneRunner().invoke(tmp_path, profile)
