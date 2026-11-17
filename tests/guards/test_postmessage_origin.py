from __future__ import annotations

import pytest

from agentsec.guards.postmessage_origin import PostmessageOriginGuard
from tests.guards._common import *  # noqa: F401,F403


def test_postmessage_origin_flags_missing_check(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        'window.addEventListener("message", (event) => { doAction(event.data); });',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = PostmessageOriginGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "postmessage-origin/no-origin-check"
    assert findings[0].severity == "high"

def test_postmessage_origin_silent_with_event_origin(tmp_path: Path) -> None:
    (tmp_path / "app.tsx").write_text(
        'window.addEventListener("message", (event) => {\n'
        '  if (event.origin !== "https://trusted.com") return;\n'
        "  doAction(event.data);\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = PostmessageOriginGuard().run(tmp_path, profile)
    assert findings == []

def test_postmessage_origin_silent_named_handler_then_register(tmp_path: Path) -> None:
    # T4 precision: handler defined first with the origin check in its body, registered later
    # (the check is far from / before the addEventListener — was a false positive).
    (tmp_path / "widgetAuth.ts").write_text(
        "function handleMessage(event: MessageEvent) {\n"
        '  if (event.origin !== window.location.origin) return;\n'
        "  process(event.data);\n"
        "}\n"
        "// ... 30 other lines ...\n"
        'window.addEventListener("message", handleMessage);\n',
        encoding="utf-8",
    )
    assert PostmessageOriginGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []

def test_postmessage_origin_silent_named_validator_helper(tmp_path: Path) -> None:
    (tmp_path / "embed.ts").write_text(
        'window.addEventListener("message", (e) => {\n'
        "  if (!isParentOriginAllowed(e.origin)) return;\n"
        "  handle(e.data);\n"
        "});\n",
        encoding="utf-8",
    )
    assert PostmessageOriginGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []

def test_postmessage_origin_still_flags_no_origin_anywhere(tmp_path: Path) -> None:
    # ...but a file with a listener and NO origin evidence at all MUST still fire (no FN).
    (tmp_path / "bad.ts").write_text(
        'window.addEventListener("message", (event) => {\n'
        "  doThing(event.data);\n"
        "});\n",
        encoding="utf-8",
    )
    findings = PostmessageOriginGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1 and findings[0].rule == "postmessage-origin/no-origin-check"

def test_postmessage_origin_silent_with_e_origin(tmp_path: Path) -> None:
    (tmp_path / "handler.ts").write_text(
        "window.addEventListener('message', (e) => {\n"
        "  if (e.origin !== 'https://app.example.com') return;\n"
        "  handleMessage(e.data);\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = PostmessageOriginGuard().run(tmp_path, profile)
    assert findings == []

def test_postmessage_origin_pragma_silences(tmp_path: Path) -> None:
    content = (
        "// security: allow-postmessage-no-origin\n"
        'window.addEventListener("message", (event) => { doAction(event.data); });\n'
    )
    (tmp_path / "widget.js").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = PostmessageOriginGuard().run(tmp_path, profile)
    assert findings == []

def test_postmessage_star_target_flags_sensitive_token(tmp_path: Path) -> None:
    (tmp_path / "send.js").write_text(
        'win.postMessage(userToken, "*");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = PostmessageOriginGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "postmessage-origin/sensitive-data-star-target"
    assert findings[0].severity == "high"

def test_postmessage_star_target_flags_sensitive_property_access(tmp_path: Path) -> None:
    (tmp_path / "send.js").write_text(
        "win.postMessage(user.password, '*');\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = PostmessageOriginGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "postmessage-origin/sensitive-data-star-target"

def test_postmessage_star_target_silent_non_sensitive_name(tmp_path: Path) -> None:
    (tmp_path / "send.js").write_text(
        'win.postMessage(publicData, "*");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert PostmessageOriginGuard().run(tmp_path, profile) == []

def test_postmessage_star_target_silent_specific_origin(tmp_path: Path) -> None:
    (tmp_path / "send.js").write_text(
        'win.postMessage(token, "https://trusted.example.com");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert PostmessageOriginGuard().run(tmp_path, profile) == []

def test_postmessage_star_target_silent_authorname_substring(tmp_path: Path) -> None:
    # #395 H5: `auth` is a substring of `authorName` but not a sensitive stem there — must not fire.
    (tmp_path / "send.js").write_text(
        'win.postMessage(article.authorName, "*");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert PostmessageOriginGuard().run(tmp_path, profile) == []

def test_postmessage_star_target_pragma_silences(tmp_path: Path) -> None:
    content = (
        "// security: allow-postmessage-no-origin\n"
        'win.postMessage(userToken, "*");\n'
    )
    (tmp_path / "send.js").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    assert PostmessageOriginGuard().run(tmp_path, profile) == []

def test_postmessage_star_target_not_applies_without_feature(tmp_path: Path) -> None:
    (tmp_path / "send.js").write_text(
        'win.postMessage(userToken, "*");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    guard = PostmessageOriginGuard()
    assert guard.applies(profile) is False
    assert guard.run(tmp_path, profile) == []

def test_postmessage_origin_receive_and_send_both_fire_independently(tmp_path: Path) -> None:
    # A file with a SAFE receiving-side handler (origin check present) must still fire the
    # sending-side check if it also has an unsafe wildcard-target send — the two rules are
    # independent, not gated by the same file-level `_ORIGIN_CHECK` skip.
    (tmp_path / "both.ts").write_text(
        'window.addEventListener("message", (event) => {\n'
        '  if (event.origin !== "https://trusted.com") return;\n'
        "  doAction(event.data);\n"
        "});\n"
        'win.postMessage(userToken, "*");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = PostmessageOriginGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "postmessage-origin/sensitive-data-star-target"

def test_postmessage_origin_not_applies_without_feature(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        'window.addEventListener("message", (event) => { doAction(event.data); });',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    guard = PostmessageOriginGuard()
    assert guard.applies(profile) is False
    findings = guard.run(tmp_path, profile)
    assert findings == []


def test_postmessage_origin_silent_on_commented_example(tmp_path: Path) -> None:
    # FP-bait (#424): a commented-out listener example must not fire, and a commented `.origin`
    # must not count as real origin evidence either way.
    (tmp_path / "app.js").write_text(
        '// window.addEventListener("message", (event) => { doAction(event.data); });\n'
        "const x = 1;\n",
        encoding="utf-8",
    )
    assert PostmessageOriginGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_postmessage_origin_still_fires_when_origin_check_is_commented_out(tmp_path: Path) -> None:
    # #424 / #440 review (Medium): a real listener whose ONLY origin check is commented out must
    # STILL fire — the commented `// event.origin` is not real validation evidence. This is the
    # exact FN the comment-strip could have caused if it blanked incorrectly.
    (tmp_path / "app.js").write_text(
        'window.addEventListener("message", (event) => {\n'
        '  // if (event.origin !== "https://trusted.com") return;  // TODO re-enable\n'
        "  doAction(event.data);\n"
        "});\n",
        encoding="utf-8",
    )
    findings = PostmessageOriginGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].rule == "postmessage-origin/no-origin-check"


def test_postmessage_origin_mentioned_only_in_a_string_is_not_evidence(tmp_path: Path) -> None:
    # Regression (#440 review): the whole-file origin-evidence check ran on a comment-stripped
    # but NOT string-stripped copy, so merely MENTIONING `event.origin` inside a string — a log
    # line, a TODO message — counted as validation and suppressed a genuine HIGH.
    (tmp_path / "a.js").write_text(
        "console.log('remember to check event.origin here');\n"
        "window.addEventListener('message', (e) => {\n"
        "  document.body.innerHTML = e.data;\n"
        "});\n",
        encoding="utf-8",
    )
    findings = PostmessageOriginGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert any(f.rule == "postmessage-origin/no-origin-check" for f in findings)


def test_postmessage_real_origin_check_still_suppresses(tmp_path: Path) -> None:
    # FP-bait: a real origin comparison must still count. The string-blanked copy is used ONLY
    # for the evidence test — the listener pattern matches `addEventListener('message', …)`,
    # whose selector is itself a string literal, so it keeps the comment-only copy.
    (tmp_path / "a.js").write_text(
        "window.addEventListener('message', (e) => {\n"
        "  if (e.origin !== 'https://trusted.example.com') return;\n"
        "  document.body.innerHTML = e.data;\n"
        "});\n",
        encoding="utf-8",
    )
    findings = PostmessageOriginGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert [f for f in findings if f.rule == "postmessage-origin/no-origin-check"] == []


def test_postmessage_origin_in_keyword_abutting_string_is_not_evidence(tmp_path: Path) -> None:
    # Regression: `strip_js_comments(strip_strings=True)` missed a string opener that ABUTS a
    # keyword (`return'…'`), so the string body was never blanked and the `event.origin` inside
    # it counted as origin evidence again — re-opening the very hole the test above closes.
    (tmp_path / "a.js").write_text(
        "window.addEventListener('message', (e) => {\n"
        "  document.body.innerHTML = e.data;\n"
        "});\n"
        "function note(){ return'remember to check event.origin here'; }\n",
        encoding="utf-8",
    )
    findings = PostmessageOriginGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert any(f.rule == "postmessage-origin/no-origin-check" for f in findings)


# --- #1055: a listener, a send and origin evidence count only when they are live code -------------

_NO_ORIGIN = "postmessage-origin/no-origin-check"
_STAR = "postmessage-origin/sensitive-data-star-target"


def _rules(tmp_path: Path, src: str) -> list[str]:
    (tmp_path / "app.js").write_text(src, encoding="utf-8")
    return [f.rule for f in PostmessageOriginGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))]


_LISTENER = 'window.addEventListener("message", (event) => { doAction(event.data); });\n'


def test_postmessage_origin_check_nested_in_a_substitution_is_evidence(tmp_path: Path) -> None:
    # The shortcut-separating case: plain `strip_strings=True` blanked the `${...}` and fired HIGH on
    # a handler that does read `event.origin` (#1055).
    src = _LISTENER + "const verdict = `${event.origin === TRUSTED ? 'ok' : 'drop'}`;\n"
    assert _rules(tmp_path, src) == []


@pytest.mark.parametrize(
    "extra",
    [
        "log(`TODO: check event.origin before trusting this`);\n",
        "log(`isOriginAllowed is not wired yet ${n}`);\n",
    ],
)
def test_postmessage_origin_named_in_template_text_is_not_evidence(tmp_path: Path, extra: str) -> None:
    # Still-fires for the narrowing above: template TEXT is string, only substitution code counts.
    assert _rules(tmp_path, _LISTENER + extra) == [_NO_ORIGIN]


@pytest.mark.parametrize(
    "src",
    [
        "const DOC = 'window.addEventListener(\"message\", handler)';\n",
        'const DOC = `call addEventListener("message", h) only after the origin check`;\n',
        "const DOC = \"win.postMessage(userToken, '*') leaks the token\";\n",
        "log(`never .postMessage(session.token, '*')`);\n",
    ],
)
def test_postmessage_origin_call_spelled_in_a_string_stays_silent(tmp_path: Path, src: str) -> None:
    assert _rules(tmp_path, src) == []


@pytest.mark.parametrize(
    ("src", "rules"),
    [
        (_LISTENER, [_NO_ORIGIN]),
        ("log('addEventListener(\"message\"'); " + _LISTENER, [_NO_ORIGIN]),
        ("const r = `${window.addEventListener('message', handler)}`;\n", [_NO_ORIGIN]),
        ("win.postMessage(userToken, '*');\n", [_STAR]),
        ("log(\".postMessage(token, '*')\"); win.postMessage(userToken, '*');\n", [_STAR]),
        ("const r = `${win.postMessage(userToken, '*')}`;\n", [_STAR]),
    ],
)
def test_postmessage_origin_real_call_still_fires(tmp_path: Path, src: str, rules: list[str]) -> None:
    # The real call, the real call after a quoted copy on the same line, and the real call nested in
    # a `${...}` substitution.
    assert _rules(tmp_path, src) == rules


def test_postmessage_origin_pragma_still_suppresses_code_anchored_findings(tmp_path: Path) -> None:
    src = _LISTENER + "win.postMessage(userToken, '*');\n"
    assert _rules(tmp_path, src) == [_NO_ORIGIN, _STAR]
    assert _rules(tmp_path, src + "// security: allow-postmessage-no-origin\n") == []


@pytest.mark.parametrize(
    "src",
    [
        "res.send(`<html><script>\n window.addEventListener('message', (e) => { run(e.data); });\n</script></html>`);\n",
        "res.send('<script>window.opener.postMessage(accessToken, \"*\")</script>');\n",
    ],
)
def test_postmessage_origin_inline_script_in_a_js_string_is_an_accepted_trade(tmp_path: Path, src: str) -> None:
    # ACCEPTED TRADE, not a goal (#1133 round 1, M1): a `<script>` served from a JS string or template
    # is string content to the anchor mask, so neither rule fires on it. The base fired only by
    # accident, the same accident that fired on a validated inline listener whose own origin check
    # was blanked. Pinned so a change here is a decision, not a drift; see the wiki's Known bypasses.
    assert _rules(tmp_path, src) == []
