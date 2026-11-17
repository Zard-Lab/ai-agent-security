"""Ingest externally-produced reports into the unified findings model.

Some scanners need a running service, not a static repo: **OWASP ZAP** (DAST
against the live app) and **Supabase Splinter** (linting the live DB). Rather
than have agentsec stand those up, it ingests the JSON they produce in CI — plus
generic **SARIF** from any other tool — so everything lands in one report.

    agentsec audit . --ingest zap=zap.json --ingest splinter=splinter.json --ingest sarif=other.sarif
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET  # noqa: S405  # security: xml-trusted-junit (first-party CI output only; see parse_schemathesis)  # nosec B405
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agentsec.findings import Finding, Severity, normalize_severity

_URL = re.compile(r"https?://[^\s<>\"']+")
_TAG = re.compile(r"<[^>]+>")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _slug(text: str) -> str:
    return _NON_ALNUM.sub("_", text.strip().lower()).strip("_") or "finding"


def _first_url(text: Any) -> str:
    if not isinstance(text, str):
        return ""
    m = _URL.search(text)
    return m.group(0) if m else ""


def _strip(text: Any) -> str:
    return _TAG.sub(" ", str(text or "")).strip()


def _path_of(uri: str) -> str:
    # Keep the URL path (drop scheme/host) so locations are compact.
    m = re.match(r"https?://[^/]+(/\S*)?", uri)
    return (m.group(1) or "/") if m else uri


# Totality guards for untrusted report JSON: `x.get(k) or []` only replaces *falsy*
# bad values — a truthy non-list/non-dict (e.g. `"alerts": 5`) sails through into
# iteration/indexing and crashes the parser (#420). These coerce by type instead.
def _as_list(x: Any) -> list[Any]:
    return x if isinstance(x, list) else []


def _as_dict(x: Any) -> dict[str, Any]:
    return x if isinstance(x, dict) else {}


def parse_zap(data: Any) -> list[Finding]:
    risk = {"high": "high", "medium": "medium", "low": "low", "informational": "info"}
    out: list[Finding] = []
    for site in _as_list(data.get("site")) if isinstance(data, dict) else []:
        if not isinstance(site, dict):
            continue
        for a in _as_list(site.get("alerts")):
            if not isinstance(a, dict):
                continue
            rd = a.get("riskdesc")
            sev = risk.get(rd.split(" ")[0].lower() if isinstance(rd, str) else "", "info")
            insts = _as_list(a.get("instances"))
            uri = str(insts[0].get("uri") or "") if insts and isinstance(insts[0], dict) else ""
            out.append(Finding(
                check_id="zap",
                severity=normalize_severity(sev),
                title=str(a.get("name") or a.get("alert") or "ZAP alert"),
                location=_path_of(uri),
                message=_strip(a.get("desc"))[:200],
                url=_first_url(a.get("reference")),
                rule=f"zap-{a.get('alertRef') or a.get('pluginid') or 'alert'}",
                standards=["OWASP"],
            ))
    return out


def parse_splinter(data: Any) -> list[Finding]:
    lvl = {"error": "high", "warn": "medium", "warning": "medium", "info": "low"}
    items = data if isinstance(data, list) else _as_list(data.get("lints")) if isinstance(data, dict) else []
    out: list[Finding] = []
    for r in items:
        if not isinstance(r, dict):
            continue
        lv = r.get("level")
        sev = lvl.get(lv.lower() if isinstance(lv, str) else "", "info")
        meta = r.get("metadata")
        if not isinstance(meta, dict):
            meta = {}
        loc = str(meta.get("name") or meta.get("entity") or r.get("categories") or "")
        remediation = str(r.get("remediation") or "")
        out.append(Finding(
            check_id="splinter",
            severity=normalize_severity(sev),
            title=str(r.get("title") or r.get("name") or "Splinter lint"),
            location=loc,
            message=str(r.get("detail") or r.get("description") or "")[:200],
            remediation=remediation if not remediation.startswith("http") else "",
            url=remediation if remediation.startswith("http") else "",
            rule=f"splinter-{r.get('name') or 'lint'}",
            standards=["OWASP:A01", "OWASP-LLM:LLM08"],
        ))
    return out


def parse_sarif(data: Any) -> list[Finding]:
    lvl = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
    out: list[Finding] = []
    for run in _as_list(data.get("runs")) if isinstance(data, dict) else []:
        if not isinstance(run, dict):
            continue
        tool = str(_as_dict(_as_dict(run.get("tool")).get("driver")).get("name") or "sarif")
        for res in _as_list(run.get("results")):
            if not isinstance(res, dict):
                continue
            sev = lvl.get(str(res.get("level") or "warning").lower(), "medium")
            rid = str(res.get("ruleId") or "")
            loc = ""
            locs = _as_list(res.get("locations"))
            if locs and isinstance(locs[0], dict):
                pl = _as_dict(locs[0].get("physicalLocation"))
                uri = str(_as_dict(pl.get("artifactLocation")).get("uri") or "")
                line = _as_dict(pl.get("region")).get("startLine")
                loc = f"{uri}:{line}" if line else uri
            out.append(Finding(
                check_id=f"sarif:{tool}",
                severity=normalize_severity(sev),
                title=rid or "SARIF result",
                location=loc,
                message=str(_as_dict(res.get("message")).get("text") or "")[:200],
                rule=rid or "sarif",
            ))
    return out


def parse_schemathesis(raw: str) -> list[Finding]:
    """Parse a Schemathesis JUnit XML report. Each `<testcase>` with a `<failure>`
    is a contract violation; `name` is `"METHOD /path"`, the failure heading is the check.

    The XML is **first-party CI output** (produced by `st --report junit`), and
    `xml.etree.ElementTree` does not resolve external entities by default — so this
    does not contradict agentsec's own `xxe-safe` guard, which targets parsing of
    *untrusted* XML in scanned apps. Never raises (returns [] on malformed input).
    """
    try:
        root = ET.fromstring(raw)  # noqa: S314  # nosec B314
    except ET.ParseError:
        return []
    out: list[Finding] = []
    for tc in root.iter("testcase"):
        failure = tc.find("failure")
        if failure is None:
            continue  # a pass
        endpoint = tc.get("name") or "?"
        # A whitespace-only message is truthy but strips to "" — splitlines() is then
        # empty, so index defensively rather than gating on truthiness (#420).
        msg_lines = (failure.get("message") or "").strip().splitlines()
        heading = msg_lines[0] if msg_lines else ""
        check = _slug(heading) if heading else "contract_violation"
        out.append(Finding(
            check_id="schemathesis",
            severity="high",
            title=f"{check} @ {endpoint}",
            location=endpoint,
            message=(failure.get("message") or failure.text or "")[:200],
            rule=f"schemathesis/{check}",
            standards=["OWASP:A04"],
        ))
    return out


# jwt_tool "killer finding" classifiers — ported from the donor's
# parse-jwt-tool-output.sh: a regex over a (200-OK) jwt_tool line → a human label.
_JWT_CLASSIFIERS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'alg.*none|none algorithm|"alg":"none"', re.I), "alg:none accepted (auth bypass)"),
    (re.compile(r"key confusion|rsa key confusion|hs256 secret=rs256", re.I),
     "RSA/HMAC algorithm confusion accepted (auth bypass)"),
    (re.compile(r"injected kid|kid.*sql|kid.*traversal", re.I),
     "kid injection succeeded (SQLi/path-traversal/cmd-injection)"),
    (re.compile(r"expired|exp.*claim", re.I), "expired token accepted (replay window)"),
    (re.compile(r"jku|x5u", re.I), "jku/x5u spoofing accepted (key-sourcing bypass)"),
    (re.compile(r"secret (cracked|found)|found secret|cracked hmac secret", re.I),
     "weak HMAC secret cracked"),
]


def parse_jwt_tool(raw: str) -> list[Finding]:
    """Classify jwt_tool text output into killer findings (deduped by label).

    jwt_tool emits ANSI-colored text, not structured output; this scans each line
    against the donor's classifier table. Never raises.
    """
    out: list[Finding] = []
    seen: set[str] = set()
    for line in _ANSI.sub("", raw).splitlines():
        for pattern, label in _JWT_CLASSIFIERS:
            if label in seen:
                continue
            if pattern.search(line):
                seen.add(label)
                out.append(Finding(
                    check_id="jwt-tool",
                    severity="high",
                    title=label,
                    message=line.strip()[:200],
                    rule=f"jwt-tool/{_slug(label)}",
                    standards=["OWASP:A07", "OWASP-LLM:LLM03"],
                ))
    return out


def parse_garak(raw: str) -> list[Finding]:
    """Parse GARAK's `*.report.jsonl` (the dynamic LLM red-team layer; the guards
    read code, GARAK attacks the running model). Each `entry_type == "eval"` line
    carries a probe + detector + passed/total; a probe with `passed < total` is a
    failed attack surface and becomes a finding.

    JSONL, not a single JSON doc — hence a text ingester. Never raises; a malformed
    line is skipped. (Verify the schema against your installed GARAK version.)
    """
    out: list[Finding] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e: Any = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(e, dict) or e.get("entry_type") != "eval":
            continue
        passed = e.get("passed", 0)
        total = e.get("total", e.get("instances", 0))
        if not isinstance(passed, int) or not isinstance(total, int):
            continue
        if total <= 0 or passed >= total:
            continue
        probe = str(e.get("probe") or "?")
        detector = str(e.get("detector") or "?")
        out.append(Finding(
            check_id="garak",
            severity="high",
            title=f"GARAK probe failed: {probe}",
            message=f"{passed}/{total} passed for detector {detector} — the model is "
                    f"vulnerable to this attack class.",
            rule=f"garak/{probe}",
            standards=["OWASP-LLM:LLM01"],
        ))
    return out


def _promptfoo_rows(data: Any) -> list[dict[str, Any]]:
    # tolerate {"results": {"results": [...]}} and {"results": [...]}
    if not isinstance(data, dict):
        return []
    results = data.get("results")
    if isinstance(results, dict):
        results = results.get("results")
    if not isinstance(results, list):
        return []
    return [r for r in results if isinstance(r, dict)]


# A promptfoo test may carry `metadata: {severity: low|medium|high|critical|info}` (promptfoo's
# free-form per-test metadata, surfaced on each result row) so a benign vector isn't gated the same
# as a data-exfil one. Absent OR unrecognized -> HIGH, so the gate fails safe and a config that does
# not opt in keeps today's behavior (#365).
_PROMPTFOO_SEV: dict[str, Severity] = {
    "critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info",
}


def _promptfoo_meta(r: dict[str, Any]) -> dict[str, Any]:
    """The per-test metadata, whether promptfoo puts it at the result top level or under
    `testCase` (version-dependent). Always a dict — never raises."""
    tc = r.get("testCase")
    for src in (r.get("metadata"), tc.get("metadata") if isinstance(tc, dict) else None):
        if isinstance(src, dict):
            return src
    return {}


def parse_promptfoo(data: Any) -> list[Finding]:
    """Parse `promptfoo eval -o <json>` (the dynamic LLM red-team layer): each result
    carries a `success` flag; a failed assertion (the prompt firewall / sanitizer
    regressed) becomes a finding. Tolerant of nested/flat shapes; never raises.

    Severity is per-test: a test's `metadata.severity` maps onto the scale, defaulting to
    HIGH when absent/unrecognized so the gate fails safe (#365). Each finding also gets a
    STABLE, UNIQUE, per-test `location` (`promptfoo/<slug-of-description>`, falling back to the
    vars or the test index; disambiguated by a `.`-joined row index on a slug collision) so a
    single flaky probe can be waived — via the (rule, location) exception key AND the SARIF
    locations[]/fingerprint — without blinding the whole suite (#365). The location is
    colon-free by design: `to_sarif` splits a location on the first `:` to peel off
    `path:line`, so a `:` before the descriptor would truncate the SARIF uri and re-collapse
    per-test identity."""
    out: list[Finding] = []
    seen: set[str] = set()
    for idx, r in enumerate(_promptfoo_rows(data)):
        if r.get("success") is not False:  # only failed assertions are findings
            continue
        grading = r.get("gradingResult")
        reason_src = grading.get("reason") if isinstance(grading, dict) else None
        reason = str(reason_src or r.get("error") or "assertion failed")
        tc_raw = r.get("testCase")
        tc = tc_raw if isinstance(tc_raw, dict) else {}
        raw_desc = r.get("description") or tc.get("description")
        if raw_desc:
            desc = str(raw_desc)
            descriptor = _slug(desc)[:60]  # cap so a long description can't make an unbounded location/URI
        else:
            vars_src = r.get("vars") or tc.get("vars") or {}
            desc = str(vars_src) if vars_src else "prompt"
            descriptor = _slug(desc)[:60] if vars_src else f"test_{idx}"
        # Guarantee a UNIQUE per-test location within the run: two probes that share a description (or
        # both slug to the same string) would otherwise collide, and a rule+location waiver for one
        # would silently suppress the other (#365 review). On collision append the globally-unique row
        # index with a `.` — NOT `/` or `:`: `Exception_.matches` treats those as path/line boundaries
        # (a `promptfoo/x` waiver would then still prefix-match a `promptfoo/x/1` sibling), and `_slug`
        # never emits `.`, so it can neither trip the boundary nor collide with a real slug.
        location = f"promptfoo/{descriptor}"
        if location in seen:
            location = f"promptfoo/{descriptor}.{idx}"
        seen.add(location)
        severity = _PROMPTFOO_SEV.get(str(_promptfoo_meta(r).get("severity") or "").strip().lower(), "high")
        out.append(Finding(
            check_id="promptfoo",
            severity=severity,
            title="Promptfoo assertion failed",
            location=location,
            message=f"{desc}: {reason}"[:200],
            rule="promptfoo/assertion-failed",
            standards=["OWASP-LLM:LLM01"],
        ))
    return out


INGESTERS: dict[str, Callable[[Any], list[Finding]]] = {
    "zap": parse_zap,
    "splinter": parse_splinter,
    "sarif": parse_sarif,
    "promptfoo": parse_promptfoo,
}

# Ingesters that consume raw text (not JSON): Schemathesis JUnit XML, jwt_tool text,
# GARAK report JSONL (newline-delimited JSON, parsed line-by-line).
_TEXT_INGESTERS: dict[str, Callable[[str], list[Finding]]] = {
    "schemathesis": parse_schemathesis,
    "jwt": parse_jwt_tool,
    "garak": parse_garak,
}


def ingest_file(kind: str, path: Path) -> list[Finding]:
    """Parse one external report. Raises ValueError on an unknown kind; returns
    a single info finding if the file is missing/unparseable (never silent)."""
    text_parser = _TEXT_INGESTERS.get(kind)
    if text_parser is not None:
        try:
            return text_parser(path.read_text(encoding="utf-8"))
        except OSError as e:
            return [Finding(check_id=f"ingest:{kind}", severity="info",
                            title=f"could not read {kind} report {path}", message=str(e))]
        except Exception as e:  # noqa: BLE001 - a malformed report must not abort the audit (#420)
            return [Finding(check_id=f"ingest:{kind}", severity="info",
                            title=f"could not parse {kind} report {path}",
                            message=f"{type(e).__name__}: {e}")]
    parser = INGESTERS.get(kind)
    if parser is None:
        known = sorted([*INGESTERS, *_TEXT_INGESTERS])
        raise ValueError(f"unknown ingest kind '{kind}' (expected one of {known})")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        # Deliberately broad, matching the text-kind branch above. The narrow
        # `(OSError, json.JSONDecodeError)` tuple missed `UnicodeDecodeError` — a subclass of
        # `ValueError`, not of either — so a single latin-1 byte in a ZAP report (ZAP embeds
        # target response text verbatim, so this is ordinary, not crafted) escaped and aborted
        # the whole audit with an uncaught traceback. That is the #420 repro, still open
        # after the fix that was meant to close it (#432 review).
        return [Finding(check_id=f"ingest:{kind}", severity="info",
                        title=f"could not read {kind} report {path}",
                        message=f"{type(e).__name__}: {e}")]
    try:
        return parser(data)
    except Exception as e:  # noqa: BLE001 - a malformed report must not abort the audit (#420)
        return [Finding(check_id=f"ingest:{kind}", severity="info",
                        title=f"could not parse {kind} report {path}",
                        message=f"{type(e).__name__}: {e}")]
