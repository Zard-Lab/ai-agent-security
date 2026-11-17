from __future__ import annotations

import pytest

from agentsec.findings import Finding
from agentsec.guards.js_cors_wildcard import JsCorsWildcardGuard
from tests.guards._common import *  # noqa: F401,F403


def test_js_cors_wildcard_flags_options_cors(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const cors = require('cors');\n"
        "const app = require('express')();\n"
        "app.options('*', cors());\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsCorsWildcardGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-cors-wildcard/explicit-options-wildcard"
    assert findings[0].severity == "high"


def test_js_cors_wildcard_flags_res_set_header(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/data', (req, res) => {\n"
        "  res.set('Access-Control-Allow-Origin', '*');\n"
        "  res.json({ok: true});\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsCorsWildcardGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-cors-wildcard/response-header-wildcard"


def test_js_cors_wildcard_flags_writehead_object_literal(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/data', (req, res) => {\n"
        "  res.writeHead(200, { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' });\n"
        "  res.end(JSON.stringify({ok: true}));\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsCorsWildcardGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-cors-wildcard/response-header-wildcard"


def test_js_cors_wildcard_silent_with_explicit_origin_allowlist(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const cors = require('cors');\n"
        "app.use(cors({ origin: ['https://app.example.com'] }));\n"
        "app.get('/data', (req, res) => {\n"
        "  res.set('Access-Control-Allow-Origin', 'https://app.example.com');\n"
        "  res.json({ok: true});\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsCorsWildcardGuard().run(tmp_path, profile) == []


def test_js_cors_wildcard_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.options('*', cors());  // security: allow-cors-wildcard\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsCorsWildcardGuard().run(tmp_path, profile) == []


def test_js_cors_wildcard_not_applies_without_feature(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text("app.options('*', cors());\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features=set())
    assert not JsCorsWildcardGuard().applies(profile)


def test_js_cors_wildcard_flags_multiline_writehead_object(tmp_path: Path) -> None:
    # Regression (PR #407 review #4): a Prettier-formatted multi-line writeHead object literal
    # (the object form spanning lines) must fire — the per-line pass previously missed it.
    (tmp_path / "app.js").write_text(
        "res.writeHead(200, {\n"
        "  'Access-Control-Allow-Origin': '*',\n"
        "});\n",
        encoding="utf-8",
    )
    findings = JsCorsWildcardGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "js-cors-wildcard/response-header-wildcard"


def test_js_cors_wildcard_silent_on_commented_wildcard(tmp_path: Path) -> None:
    # A commented-out wildcard header must not fire.
    (tmp_path / "app.js").write_text(
        "// res.set('Access-Control-Allow-Origin', '*');\n",
        encoding="utf-8",
    )
    assert JsCorsWildcardGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_cors_wildcard_flags_origin_true(tmp_path: Path) -> None:
    # CodeQL CWE-942: `origin: true` reflects the request's Origin header — effectively any origin.
    (tmp_path / "app.js").write_text(
        "const cors = require('cors');\n"
        "app.use(cors({\n"
        "  origin: true,\n"
        "}));\n",
        encoding="utf-8",
    )
    findings = JsCorsWildcardGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "js-cors-wildcard/permissive-origin-config"
    assert findings[0].severity == "high"


def test_js_cors_wildcard_flags_origin_null(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const cors = require('cors');\n"
        "app.use(cors({\n"
        "  origin: null,\n"
        "}));\n",
        encoding="utf-8",
    )
    findings = JsCorsWildcardGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "js-cors-wildcard/permissive-origin-config"


def test_js_cors_wildcard_silent_origin_true_credentials_false(tmp_path: Path) -> None:
    # CodeQL's sanitizing pair: origin:true + credentials:false can't carry cookies/auth cross-origin.
    (tmp_path / "app.js").write_text(
        "const cors = require('cors');\n"
        "app.use(cors({\n"
        "  origin: true,\n"
        "  credentials: false,\n"
        "}));\n",
        encoding="utf-8",
    )
    assert JsCorsWildcardGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_cors_wildcard_silent_specific_origin_string(tmp_path: Path) -> None:
    # Existing behavior unchanged: a specific origin string is safe, not origin:true/null.
    (tmp_path / "app.js").write_text(
        "const cors = require('cors');\n"
        "app.use(cors({\n"
        "  origin: 'https://trusted.example.com',\n"
        "}));\n",
        encoding="utf-8",
    )
    assert JsCorsWildcardGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


# --- Reflected-origin + credentials (codeql js/cors-misconfiguration-for-credentials) ---

def test_js_cors_wildcard_flags_reflected_origin_with_credentials(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/data', (req, res) => {\n"
        "  res.set('Access-Control-Allow-Origin', req.headers.origin);\n"
        "  res.set('Access-Control-Allow-Credentials', 'true');\n"
        "  res.json({ok: true});\n"
        "});\n",
        encoding="utf-8",
    )
    findings = JsCorsWildcardGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "js-cors-wildcard/reflected-origin-with-credentials"
    assert findings[0].severity == "high"


def test_js_cors_wildcard_silent_reflected_origin_without_credentials(tmp_path: Path) -> None:
    # FP-bait: reflecting Origin without ever enabling credentials can't carry cookies/auth
    # cross-origin — CodeQL's own scoping for this exact query.
    (tmp_path / "app.js").write_text(
        "app.get('/data', (req, res) => {\n"
        "  res.set('Access-Control-Allow-Origin', req.headers.origin);\n"
        "  res.json({ok: true});\n"
        "});\n",
        encoding="utf-8",
    )
    assert JsCorsWildcardGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_cors_wildcard_silent_literal_origin_with_credentials(tmp_path: Path) -> None:
    # FP-bait: a literal allowlisted origin with credentials:true is the correct, safe pattern.
    (tmp_path / "app.js").write_text(
        "app.get('/data', (req, res) => {\n"
        "  res.set('Access-Control-Allow-Origin', 'https://app.example.com');\n"
        "  res.set('Access-Control-Allow-Credentials', 'true');\n"
        "  res.json({ok: true});\n"
        "});\n",
        encoding="utf-8",
    )
    assert JsCorsWildcardGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_cors_wildcard_pragma_silences_reflected_origin_with_credentials(tmp_path: Path) -> None:
    # L5 (the PR #905 review): the reflected-origin-with-credentials sub-rule
    # implements the pragma correctly but had no test proving it — every other rule in this
    # guard does.
    (tmp_path / "app.js").write_text(
        "app.get('/data', (req, res) => {\n"
        "  res.set('Access-Control-Allow-Origin', req.headers.origin);\n"
        "  res.set('Access-Control-Allow-Credentials', 'true');  // security: allow-cors-wildcard\n"
        "  res.json({ok: true});\n"
        "});\n",
        encoding="utf-8",
    )
    assert JsCorsWildcardGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_cors_wildcard_flags_reflected_req_get_origin_with_credentials(tmp_path: Path) -> None:
    # M-1 (PR #905 review): `req.get('origin')` is the most idiomatic Express header read and
    # the docstring claims it, but the value-capture regex used to truncate at the inner `)` of
    # `req.get('origin'` — so this shape was SILENT. Widened to tolerate one nested-paren level.
    (tmp_path / "app.js").write_text(
        "app.get('/data', (req, res) => {\n"
        "  res.set('Access-Control-Allow-Origin', req.get('origin'));\n"
        "  res.set('Access-Control-Allow-Credentials', 'true');\n"
        "  res.json({ok: true});\n"
        "});\n",
        encoding="utf-8",
    )
    findings = JsCorsWildcardGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "js-cors-wildcard/reflected-origin-with-credentials"
    assert findings[0].severity == "high"


def test_js_cors_wildcard_flags_reflected_req_header_origin_with_credentials(tmp_path: Path) -> None:
    # M-1 (PR #905 review): the other nested-paren header-read form the docstring claims,
    # `req.header('origin')`, which the pre-fix regex also truncated and left silent.
    (tmp_path / "app.js").write_text(
        "app.get('/data', (req, res) => {\n"
        "  res.header('Access-Control-Allow-Origin', req.header('origin'));\n"
        "  res.header('Access-Control-Allow-Credentials', 'true');\n"
        "  res.json({ok: true});\n"
        "});\n",
        encoding="utf-8",
    )
    findings = JsCorsWildcardGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "js-cors-wildcard/reflected-origin-with-credentials"


def test_js_cors_wildcard_silent_reflected_req_get_origin_without_credentials(tmp_path: Path) -> None:
    # M-1 both-directions FP-bait: now that the nested-paren value IS captured, the credentials
    # gate must still hold — reflecting Origin via `req.get('origin')` without ever enabling
    # credentials can't carry cookies/auth cross-origin, so it stays silent.
    (tmp_path / "app.js").write_text(
        "app.get('/data', (req, res) => {\n"
        "  res.set('Access-Control-Allow-Origin', req.get('origin'));\n"
        "  res.json({ok: true});\n"
        "});\n",
        encoding="utf-8",
    )
    assert JsCorsWildcardGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_cors_wildcard_skips_non_product_paths(tmp_path: Path) -> None:
    # L-2 (PR #905 review): parity with the sibling JS guards fixed by M2/M3 in this same batch —
    # the same wildcard fires in a product path but is skipped under a target's tests/ tree.
    (tmp_path / "app.js").write_text(
        "app.options('*', cors());\n", encoding="utf-8",
    )
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "app.spec.js").write_text(
        "app.options('*', cors());\n", encoding="utf-8",
    )
    findings = JsCorsWildcardGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1  # only the product-path app.js fires
    assert findings[0].location == "app.js:1"


# --- #1055: a CORS call, config key or credentials credit counts only when it is live code --------

_CRED_TRUE = "res.set('Access-Control-Allow-Credentials', 'true');\n"


def _run_cors(tmp_path: Path, src: str) -> list[Finding]:
    (tmp_path / "app.js").write_text(src, encoding="utf-8")
    prof = mkprofile(tmp_path, features={"javascript", "node", "express"})
    guard = JsCorsWildcardGuard()
    assert guard.applies(prof)
    return guard.run(tmp_path, prof)


def _rules_at(findings: list[Finding]) -> list[str]:
    return sorted(f"{f.rule.split('/')[1]}@{f.location.rsplit(':', 1)[1]}" for f in findings)


@pytest.mark.parametrize(
    "src",
    [
        "app.use(cors({ origin: true, note: 'credentials: false is the safe pairing' }));\n",
        "app.use(cors({ origin: true, note: `credentials: false for ${env}` }));\n",
    ],
)
def test_js_cors_wildcard_quoted_credentials_false_no_longer_clears(tmp_path: Path, src: str) -> None:
    # The FN direction (#1055): `credentials: false` spelled out in a note string used to clear it.
    findings = _run_cors(tmp_path, src)
    assert _rules_at(findings) == ["permissive-origin-config@1"]
    assert findings[0].location.replace("\\", "/").endswith("app.js:1")


@pytest.mark.parametrize(
    "src",
    [
        "app.use(cors({\n  origin: true,\n  credentials: false,\n}));\n",
        # A real key nested in a `${...}` substitution is code: the shortcut-separating case, which
        # plain `strip_strings=True` would have blanked.
        "app.use(cors({ origin: true, tag: `${{ credentials: false }.credentials}` }));\n",
        # A quoted copy earlier in the object must not decide for the real key after it.
        "app.use(cors({ origin: true, note: 'credentials: false', credentials: false }));\n",
    ],
)
def test_js_cors_wildcard_real_credentials_false_still_clears(tmp_path: Path, src: str) -> None:
    assert _run_cors(tmp_path, src) == []


@pytest.mark.parametrize(
    "src",
    [
        "const HELP = \"app.options('*', cors()) opens preflight to every origin\";\n",
        "const HELP = \"res.set('Access-Control-Allow-Origin', '*') is the bad shape\";\n",
        "const HELP = `res.writeHead(200, { 'Access-Control-Allow-Origin': '*' }) in ${doc}`;\n",
        "const HELP = \"cors({ origin: true })\";\n",
        "app.use(cors({ note: 'never origin: true', origin: ['https://app.example.com'] }));\n",
        # The reflected-origin rule: the credentials call, or the Origin read, spelled out in a string.
        "res.set('Access-Control-Allow-Origin', req.headers.origin);\n"
        "const H = \"res.set('Access-Control-Allow-Credentials', 'true')\";\n",
        "res.set('Access-Control-Allow-Origin', 'req.headers.origin');\n" + _CRED_TRUE,
        # A log line quoting the header call around a live Origin read is not a header call.
        "log(\"res.set('Access-Control-Allow-Origin', \" + req.headers.origin + \")\");\n" + _CRED_TRUE,
    ],
)
def test_js_cors_wildcard_quoted_shape_stays_silent(tmp_path: Path, src: str) -> None:
    # The FP direction (#1055): every rule fired on a CORS shape spelled out in a string.
    assert _run_cors(tmp_path, src) == []


@pytest.mark.parametrize(
    ("src", "expected"),
    [
        ("log(`${app.options('*', cors())}`);\n", ["explicit-options-wildcard@1"]),
        ("log(`${res.set('Access-Control-Allow-Origin', '*')}`);\n", ["response-header-wildcard@1"]),
        ("log(`${cors({ origin: true })}`);\n", ["permissive-origin-config@1"]),
        (
            "log(`${res.set('Access-Control-Allow-Origin', req.headers.origin)}`);\n" + _CRED_TRUE,
            ["reflected-origin-with-credentials@1"],
        ),
        # A quoted copy earlier on the line must not hide the real call after it.
        (
            "log(\"res.set('Access-Control-Allow-Origin', '*')\"); res.header('Access-Control-Allow-Origin', '*');\n",
            ["response-header-wildcard@1"],
        ),
        ("app.use(cors({ note: 'origin: true', origin: true }));\n", ["permissive-origin-config@1"]),
        # The object-literal header scan spans lines: a dropped quoted `.set(` above must not swallow
        # the real `writeHead` below it.
        (
            "log('calling res.set(');\nres.writeHead(200, { 'Access-Control-Allow-Origin': '*' });\n",
            ["response-header-wildcard@2"],
        ),
    ],
)
def test_js_cors_wildcard_real_shape_still_fires(tmp_path: Path, src: str, expected: list[str]) -> None:
    assert _rules_at(_run_cors(tmp_path, src)) == expected


@pytest.mark.parametrize(
    "src",
    [
        "log(`${res.set('Access-Control-Allow-Origin', '*')}`); // security: allow-cors-wildcard\n",
        "// security: allow-cors-wildcard\nlog(`${cors({ origin: true })}`);\n",
    ],
)
def test_js_cors_wildcard_pragma_still_suppresses_a_code_anchored_shape(tmp_path: Path, src: str) -> None:
    assert _run_cors(tmp_path, src) == []
