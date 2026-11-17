from __future__ import annotations

from agentsec.guards.js_ssrf import JsSsrfGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_fetch_template_literal_query_param(tmp_path: Path) -> None:
    (tmp_path / "route.js").write_text(
        "app.get('/proxy', (req, res) => {\n"
        "  fetch(`https://api.example.com/${req.query.target}`);\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsSsrfGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-ssrf/request-derived-url"
    assert findings[0].severity == "high"
    # OWASP:A10 (Server-Side Request Forgery) is SSRF's real Top-10 category — aligned during the
    # PR #395 merge (test_guard_standards_reflected_on_checklist caught the drift against the
    # checklist item's own OWASP:A10, which was already correct).
    assert findings[0].standards == ["OWASP:A10", "CWE-918"]


def test_flags_axios_get_concatenated_host(tmp_path: Path) -> None:
    (tmp_path / "route.ts").write_text(
        "app.post('/proxy', (req, res) => {\n"
        "  axios.get(\"http://\" + req.body.host);\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    findings = JsSsrfGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-ssrf/request-derived-url"


def test_flags_axios_post_params_derived(tmp_path: Path) -> None:
    (tmp_path / "route.js").write_text(
        "axios.post(`https://internal.example.com/${params.id}/sync`, payload);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert len(JsSsrfGuard().run(tmp_path, profile)) == 1


def test_flags_http_request_body_derived(tmp_path: Path) -> None:
    (tmp_path / "route.js").write_text(
        "http.request(`http://${body.upstreamHost}/health`, cb);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert len(JsSsrfGuard().run(tmp_path, profile)) == 1


def test_silent_on_template_literal_config_constant(tmp_path: Path) -> None:
    # FP-bait: interpolated but from a config constant, not request-derived — must stay silent.
    (tmp_path / "route.js").write_text(
        "fetch(`https://api.example.com/${API_VERSION}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSsrfGuard().run(tmp_path, profile) == []


def test_silent_on_fully_static_url(tmp_path: Path) -> None:
    (tmp_path / "route.js").write_text(
        'fetch("https://api.example.com/static");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSsrfGuard().run(tmp_path, profile) == []


def test_silent_on_bare_variable_no_signal(tmp_path: Path) -> None:
    # conservative by design: a bare variable with no template/concat signal does NOT fire
    (tmp_path / "route.js").write_text(
        "const url = getUpstreamUrl();\nfetch(url);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSsrfGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "route.js").write_text(
        "// Never do: fetch(`https://api.example.com/${req.query.target}`)\n"
        'fetch("https://api.example.com/static");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSsrfGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "route.js").write_text(
        "// security: allow-js-ssrf\n"
        "fetch(`https://api.example.com/${req.query.target}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSsrfGuard().run(tmp_path, profile) == []


def test_not_applies_without_js_or_ts(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features=set())
    assert not JsSsrfGuard().applies(profile)


def test_applies_with_typescript_only(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"typescript"})
    assert JsSsrfGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.js").write_text(
        "fetch(`https://api.example.com/${req.query.target}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSsrfGuard().run(tmp_path, profile) == []


def test_js_ssrf_trailing_comment_sink_silent(tmp_path: Path) -> None:
    # #395 H1: a sink pattern in a TRAILING same-line comment (not a whole-line comment) must
    # not fire — the old `^\s*//` whole-line check missed it.
    (tmp_path / "route.js").write_text(
        "const timeout = 5000;  // fetch(`https://api/${req.query.u}`) is the old proxy call\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsSsrfGuard().run(tmp_path, profile) == []
