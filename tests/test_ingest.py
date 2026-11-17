"""Tests for ingesting external ZAP / Splinter / SARIF reports."""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from agentsec.audit import audit
from agentsec.ingest import (
    ingest_file,
    parse_garak,
    parse_promptfoo,
    parse_sarif,
    parse_splinter,
    parse_zap,
)


def test_parse_zap() -> None:
    data = {"site": [{"alerts": [{
        "name": "SQL Injection", "riskdesc": "High (Medium)",
        "desc": "<p>bad</p>", "reference": "<p>https://owasp.org/x</p>",
        "alertRef": "40018", "instances": [{"uri": "https://app.example/api/login"}],
    }]}]}
    f = parse_zap(data)
    assert len(f) == 1 and f[0].severity == "high"
    assert f[0].location == "/api/login" and f[0].url == "https://owasp.org/x"
    assert "<p>" not in f[0].message


def test_parse_zap_and_sarif_tolerate_explicit_null() -> None:
    # H3: a hand-edited/attacker report with an explicit JSON null where a list is
    # expected must return [], not crash the whole audit with a TypeError.
    assert parse_zap({"site": None}) == []
    assert parse_zap({"site": [{"alerts": None}]}) == []
    assert parse_sarif({"runs": None}) == []
    assert parse_sarif({"runs": [{"results": None}]}) == []


def test_parse_zap_splinter_sarif_tolerate_truthy_non_collections() -> None:
    # #420: `x.get(k) or []` only guards *falsy* bad values — a truthy non-list/non-dict
    # (e.g. "alerts": 5) previously crashed the parser and aborted the whole audit.
    assert parse_zap({"site": [{"alerts": 5}]}) == []
    assert parse_zap({"site": [{"alerts": [{"name": "x", "instances": {"a": "b"}}]}]})[0].location == ""
    assert parse_zap({"site": [{"alerts": [{"name": "x", "instances": [{"uri": 7}]}]}]})[0].location == "7"
    assert parse_splinter({"lints": 5}) == []
    assert parse_sarif({"runs": [{"results": 5}]}) == []
    assert parse_sarif({"runs": [{"tool": "oops", "results": [{"ruleId": "r"}]}]})[0].check_id == "sarif:sarif"
    assert parse_sarif({"runs": [{"results": [{"ruleId": "r", "message": "m"}]}]})[0].message == ""
    assert parse_sarif({"runs": [{"results": [{"ruleId": "r", "locations": {"a": 1}}]}]})[0].location == ""


def test_parse_splinter() -> None:
    data = [{
        "name": "rls_disabled_in_public", "title": "RLS Disabled", "level": "ERROR",
        "detail": "Table public.x has RLS disabled", "remediation": "https://supabase.com/lint/0013",
        "metadata": {"name": "x", "type": "table"},
    }]
    f = parse_splinter(data)
    assert f[0].severity == "high" and f[0].location == "x"
    assert f[0].url == "https://supabase.com/lint/0013"


def test_parse_sarif() -> None:
    data = {"runs": [{"tool": {"driver": {"name": "bandit"}}, "results": [
        {"ruleId": "B602", "level": "error", "message": {"text": "shell=True"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 9}}}]}
    ]}]}
    f = parse_sarif(data)
    assert f[0].severity == "high" and f[0].location == "a.py:9" and f[0].check_id == "sarif:bandit"


def test_ingest_file_unknown_kind(tmp_path: Path) -> None:
    p = tmp_path / "x.json"
    p.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown ingest kind"):
        ingest_file("nope", p)


def test_ingest_file_missing_is_info_finding(tmp_path: Path) -> None:
    f = ingest_file("zap", tmp_path / "absent.json")
    assert len(f) == 1 and f[0].severity == "info" and "could not read" in f[0].title


def test_ingest_schemathesis_xml(tmp_path: Path) -> None:
    p = tmp_path / "schemathesis-junit.xml"
    p.write_text('<testsuite><testcase name="POST /login">'
                 '<failure message="Undocumented HTTP status code (500)"/></testcase></testsuite>', encoding="utf-8")
    f = ingest_file("schemathesis", p)
    assert len(f) == 1 and f[0].check_id == "schemathesis"
    assert f[0].location == "POST /login" and f[0].severity == "high"


def test_ingest_jwt_text(tmp_path: Path) -> None:
    p = tmp_path / "jwt.txt"
    p.write_text('jwttool_x Response Code: 200 - "alg":"none" accepted\n', encoding="utf-8")
    f = ingest_file("jwt", p)
    assert len(f) == 1 and f[0].check_id == "jwt-tool" and "alg:none" in f[0].title


def test_ingest_schemathesis_missing_is_info_finding(tmp_path: Path) -> None:
    f = ingest_file("schemathesis", tmp_path / "absent.xml")
    assert len(f) == 1 and f[0].severity == "info" and "could not read" in f[0].title


def test_ingest_schemathesis_whitespace_only_message(tmp_path: Path) -> None:
    # #420: message=" " is truthy but strips to "" — splitlines()[0] used to IndexError.
    p = tmp_path / "schemathesis-junit.xml"
    p.write_text('<testsuite><testcase name="GET /x"><failure message=" "> </failure></testcase></testsuite>', encoding="utf-8")
    f = ingest_file("schemathesis", p)
    assert len(f) == 1 and f[0].rule == "schemathesis/contract_violation"


def test_ingest_file_parser_crash_becomes_info_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #420 belt-and-braces: a future parser bug must degrade to one info finding,
    # never abort the whole `agentsec audit --ingest` run.
    import agentsec.ingest as ingest_mod

    def boom(_data: object) -> list:
        raise RuntimeError("kaboom")

    monkeypatch.setitem(ingest_mod.INGESTERS, "zap", boom)
    monkeypatch.setitem(ingest_mod._TEXT_INGESTERS, "jwt", boom)
    p = tmp_path / "report.json"
    p.write_text("{}", encoding="utf-8")
    for kind in ("zap", "jwt"):
        f = ingest_file(kind, p)
        assert len(f) == 1 and f[0].severity == "info", kind
        assert "could not parse" in f[0].title and "RuntimeError" in f[0].message, kind


# --- dynamic LLM red-team parsers (garak JSONL / promptfoo JSON) -------------

def test_parse_garak_failed_probe() -> None:
    raw = "\n".join([
        json.dumps({"entry_type": "start_run"}),
        json.dumps({"entry_type": "eval", "probe": "promptinject.Hijack",
                    "detector": "mitigation.MitigationBypass", "passed": 7, "total": 10}),
        json.dumps({"entry_type": "eval", "probe": "leakreplay.Clean",
                    "detector": "base.TriggerListDetector", "passed": 10, "total": 10}),
    ])
    f = parse_garak(raw)
    assert len(f) == 1
    assert f[0].rule == "garak/promptinject.Hijack" and f[0].severity == "high"
    assert f[0].check_id == "garak" and f[0].standards == ["OWASP-LLM:LLM01"]


def test_parse_garak_empty_and_malformed() -> None:
    assert parse_garak("") == []
    assert parse_garak("not json\n{bad") == []


def test_parse_promptfoo_nested_failure() -> None:
    data = {"results": {"results": [
        {"success": True, "description": "benign"},
        {"success": False, "description": "xss-injection",
         "gradingResult": {"reason": "output contained <script>"}},
    ]}}
    f = parse_promptfoo(data)
    assert len(f) == 1
    assert f[0].rule == "promptfoo/assertion-failed" and "xss-injection" in f[0].message


def test_parse_promptfoo_flat_all_pass_and_empty() -> None:
    assert parse_promptfoo({"results": [{"success": True}]}) == []
    assert parse_promptfoo({}) == []
    assert parse_promptfoo("not a dict") == []


def test_parse_promptfoo_severity_from_metadata() -> None:
    # A per-test `metadata.severity` maps onto the scale, so a benign vector isn't gated as HIGH (#365).
    data = {"results": [
        {"success": False, "description": "benign string op", "metadata": {"severity": "low"}},
        {"success": False, "description": "system-prompt exfil", "metadata": {"severity": "critical"}},
    ]}
    f = parse_promptfoo(data)
    sev = {x.message.split(":")[0]: x.severity for x in f}
    assert sev["benign string op"] == "low"
    assert sev["system-prompt exfil"] == "critical"


def test_parse_promptfoo_metadata_under_testcase() -> None:
    # promptfoo may nest metadata under `testCase` (version-dependent) — read either place (#365).
    data = {"results": [{"success": False, "description": "x",
                         "testCase": {"metadata": {"severity": "medium"}}}]}
    assert parse_promptfoo(data)[0].severity == "medium"


def test_parse_promptfoo_defaults_high_when_metadata_absent_or_unrecognized() -> None:
    # No metadata OR an unrecognized value -> HIGH, so the gate fails safe (#365).
    absent = parse_promptfoo({"results": [{"success": False, "description": "a"}]})
    bogus = parse_promptfoo({"results": [{"success": False, "description": "b",
                                          "metadata": {"severity": "totally-bogus"}}]})
    assert absent[0].severity == "high" and bogus[0].severity == "high"


def test_parse_promptfoo_stable_per_test_location() -> None:
    # Each probe gets a stable, non-empty, colon-free per-test location so ONE probe can be waived
    # without blinding the rest; distinct tests get distinct locations AND fingerprints (#365).
    data = {"results": [
        {"success": False, "description": "xss injection"},
        {"success": False, "description": "sql injection"},
    ]}
    f = parse_promptfoo(data)
    locs = [x.location for x in f]
    assert all(loc and ":" not in loc for loc in locs)   # non-empty + colon-free (SARIF-safe)
    assert locs[0] != locs[1]                             # per-test, not shared
    assert f[0].fingerprint() != f[1].fingerprint()       # so a waiver targets one probe
    assert locs[0] == "promptfoo/xss_injection"           # stable slug of the description


def test_parse_promptfoo_location_falls_back_to_index_without_description() -> None:
    # A description-less, vars-less failed row still gets a distinct location (the test index) (#365).
    data = {"results": [{"success": False}, {"success": False}]}
    f = parse_promptfoo(data)
    assert f[0].location != f[1].location
    assert all(":" not in x.location for x in f)


def test_parse_promptfoo_same_description_gets_distinct_locations() -> None:
    # #365 review (High): two distinct probes sharing a description must NOT collapse to one
    # location, or a rule+location waiver for one silently suppresses the other.
    data = {"results": [
        {"success": False, "description": "Prompt Injection", "vars": {"v": "payload-1"}},
        {"success": False, "description": "Prompt Injection", "vars": {"v": "payload-2"}},
        {"success": False, "description": "Prompt Injection", "vars": {"v": "payload-3"}},
    ]}
    f = parse_promptfoo(data)
    locs = [x.location for x in f]
    assert len(set(locs)) == 3                       # all distinct — no over-waiver collision
    assert all(":" not in loc for loc in locs)       # still SARIF-safe (colon-free)
    assert locs[0] == "promptfoo/prompt_injection"   # first keeps the clean, reorder-stable form
    # The behavioral guarantee (distinctness alone is not enough — the disambiguator must not be a
    # path/line boundary or the base still prefix-matches its siblings): a waiver on ONE probe's
    # location must NOT match the others.
    from agentsec.exceptions import Exception_
    waiver = Exception_(rule="promptfoo/assertion-failed", location=locs[0])
    assert waiver.matches(f[0])
    assert not waiver.matches(f[1]) and not waiver.matches(f[2])


def test_parse_promptfoo_symbol_only_descriptions_dont_collide() -> None:
    # A symbol-only description slugs to the "finding" fallback; two of them must still be distinct.
    data = {"results": [
        {"success": False, "description": "!!!"},
        {"success": False, "description": "@@@"},
    ]}
    locs = [x.location for x in parse_promptfoo(data)]
    assert len(set(locs)) == 2


def test_parse_promptfoo_descriptor_length_capped() -> None:
    # #365 review (Low): a very long description must not produce an unbounded location/SARIF URI.
    data = {"results": [{"success": False, "description": "x" * 500}]}
    loc = parse_promptfoo(data)[0].location
    assert len(loc) <= len("promptfoo/") + 60


def test_ingest_garak_jsonl(tmp_path: Path) -> None:
    report = tmp_path / "run.report.jsonl"
    report.write_text(json.dumps(
        {"entry_type": "eval", "probe": "xss.MdExfil", "detector": "x", "passed": 0, "total": 5}
    ) + "\n", encoding="utf-8")
    f = ingest_file("garak", report)
    assert len(f) == 1 and f[0].check_id == "garak"


def test_ingest_promptfoo_json(tmp_path: Path) -> None:
    report = tmp_path / "results.json"
    report.write_text(json.dumps({"results": [{"success": False, "description": "leak"}]}), encoding="utf-8")
    f = ingest_file("promptfoo", report)
    assert len(f) == 1 and f[0].check_id == "promptfoo"


def test_audit_merges_ingested_findings(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\n", encoding="utf-8")
    zap = tmp_path / "zap.json"
    zap.write_text(json.dumps({"site": [{"alerts": [{
        "name": "XSS", "riskdesc": "High (Medium)", "instances": [{"uri": "https://a/x"}],
    }]}]}), encoding="utf-8")
    extra = ingest_file("zap", zap)
    r = audit(tmp_path, run_scanners=False, extra_findings=extra, today=date(2026, 6, 5))
    assert any(f.check_id == "zap" and f.title == "XSS" for f in r.findings)


def test_parse_zap_tolerates_non_string_riskdesc() -> None:
    """A crafted/malformed zap.json with a non-string riskdesc must not raise (totality)."""
    data = {"site": [{"alerts": [{"name": "X", "riskdesc": 5, "instances": []}]}]}
    out = parse_zap(data)
    assert len(out) == 1 and out[0].severity == "info"


def test_parse_splinter_tolerates_non_string_level() -> None:
    """A crafted/malformed splinter.json with a non-string level must not raise (totality)."""
    out = parse_splinter([{"level": 5, "metadata": {}}])
    assert len(out) == 1 and out[0].severity == "info"


def test_ingest_json_report_with_non_utf8_bytes_does_not_abort(tmp_path: Path) -> None:
    # Regression (#432 review): the #420 audit-abort repro was still open. The JSON branch
    # caught `(OSError, json.JSONDecodeError)`, but `UnicodeDecodeError` is a subclass of
    # `ValueError` and of neither, so it escaped and killed the whole audit with an uncaught
    # traceback. ZAP embeds target response text verbatim, so one latin-1 byte in a scanned
    # page is enough — ordinary, not crafted.
    report = tmp_path / "zap.json"
    report.write_bytes(b'{"site":[{"alerts":[{"name":"caf\xe9 leak","riskcode":"3"}]}]}')
    out = ingest_file("zap", report)          # must not raise
    assert len(out) == 1 and out[0].severity == "info"
    assert "could not read" in out[0].title
    assert "UnicodeDecodeError" in out[0].message
