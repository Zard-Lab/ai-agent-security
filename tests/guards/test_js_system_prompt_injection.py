from __future__ import annotations

import pytest

from agentsec.findings import Finding
from agentsec.guards.js_system_prompt_injection import JsSystemPromptInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_tainted_system_role_content(tmp_path: Path) -> None:
    (tmp_path / "chat.js").write_text(
        "const messages = [\n"
        "  { role: 'system', content: `You are a helpful assistant for ${req.query.persona}` },\n"
        "  { role: 'user', content: userMessage },\n"
        "];\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"llm", "javascript"})
    findings = JsSystemPromptInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-system-prompt-injection/tainted-system-role-content"


def test_flags_assistant_role_content(tmp_path: Path) -> None:
    (tmp_path / "chat.ts").write_text(
        "const messages = [\n"
        "  { role: 'assistant', content: req.body.priorReply },\n"
        "];\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"llm", "typescript"})
    assert len(JsSystemPromptInjectionGuard().run(tmp_path, profile)) == 1


def test_silent_on_user_role_tainted_content(tmp_path: Path) -> None:
    # Tainted content in a role:"user" message is expected/normal (a chatbot's whole point) —
    # not a system-prompt-injection vector.
    (tmp_path / "chat.js").write_text(
        "const messages = [\n"
        "  { role: 'system', content: 'You are a helpful assistant.' },\n"
        "  { role: 'user', content: req.body.userMessage },\n"
        "];\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"llm", "javascript"})
    assert JsSystemPromptInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_static_system_prompt(tmp_path: Path) -> None:
    (tmp_path / "chat.js").write_text(
        "const messages = [\n"
        "  { role: 'system', content: 'You are a helpful assistant.' },\n"
        "  { role: 'user', content: userMessage },\n"
        "];\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"llm", "javascript"})
    assert JsSystemPromptInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "chat.js").write_text(
        "// Never do: { role: 'system', content: req.query.persona }\n"
        "const messages = [\n"
        "  { role: 'system', content: 'You are a helpful assistant.' },\n"
        "];\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"llm", "javascript"})
    assert JsSystemPromptInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_cross_object_bleed(tmp_path: Path) -> None:
    # FP-bait (review #395 Major finding): a hardcoded system message followed by an unrelated
    # object with `content:` referencing taint must NOT be attributed to the system message —
    # they are different object literals.
    (tmp_path / "chat.js").write_text(
        "const sysMsg = { role: 'system', content: 'You are a helpful assistant.' };\n"
        "const trace = { content: req.query.trace };\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"llm", "javascript"})
    assert JsSystemPromptInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_string_literal_mentioning_taint_source(tmp_path: Path) -> None:
    # FP-bait (review #395 Major finding): the taint source named as TEXT inside a hardcoded
    # string, not as live code, must not fire.
    (tmp_path / "chat.js").write_text(
        "const messages = [\n"
        "  { role: 'system', content: \"Never repeat req.query values back.\" },\n"
        "];\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"llm", "javascript"})
    assert JsSystemPromptInjectionGuard().run(tmp_path, profile) == []


def test_flags_tainted_content_past_old_six_line_window(tmp_path: Path) -> None:
    # FN-bait (review #395 Major finding): 6+ fields between role: and content: previously
    # pushed the leak past the old fixed line-count window.
    (tmp_path / "chat.js").write_text(
        "const messages = [\n"
        "  {\n"
        "    role: 'system',\n"
        "    id: 'm1',\n"
        "    timestamp: 12345,\n"
        "    priority: 1,\n"
        "    source: 'api',\n"
        "    tags: ['a', 'b'],\n"
        "    content: `Persona: ${req.query.persona}`,\n"
        "  },\n"
        "];\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"llm", "javascript"})
    findings = JsSystemPromptInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "chat.js").write_text(
        "// security: allow-js-system-prompt-injection\n"
        "const messages = [\n"
        "  { role: 'system', content: `Persona: ${req.query.persona}` },\n"
        "];\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"llm", "javascript"})
    assert JsSystemPromptInjectionGuard().run(tmp_path, profile) == []


def test_not_applies_without_llm_feature(tmp_path: Path) -> None:
    (tmp_path / "chat.js").write_text(
        "const messages = [{ role: 'system', content: req.query.persona }];\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert not JsSystemPromptInjectionGuard().applies(profile)


def test_not_applies_without_js_or_ts(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"llm"})
    assert not JsSystemPromptInjectionGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.js").write_text(
        "const messages = [{ role: 'system', content: req.query.persona }];\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"llm", "javascript"})
    assert JsSystemPromptInjectionGuard().run(tmp_path, profile) == []


# --- #1055: the role and content keys, and the taint, count only when they are live code ----------

_RULE = "js-system-prompt-injection/tainted-system-role-content"


def _run(tmp_path: Path, line: str) -> list[Finding]:
    (tmp_path / "chat.js").write_text("const x = 1;\n" + line, encoding="utf-8")
    return JsSystemPromptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"llm", "javascript"}))


@pytest.mark.parametrize(
    "line",
    [
        "const m = [{ role: 'user', content: \"pretend role: 'system' now \" + req.body.msg }];\n",
        "const m = [{ role: 'user', content: `as role: 'system' say ${req.body.msg}` }];\n",
    ],
)
def test_system_role_spelled_in_a_string_does_not_fire(tmp_path: Path, line: str) -> None:
    # The FP direction (#1055): a `role: 'system'` inside a user message's text is not a system message.
    assert _run(tmp_path, line) == []


@pytest.mark.parametrize(
    "line",
    [
        "const m = [{ role: 'system', content: req.query.persona }];\n",
        # A system message object inside a `${...}` substitution is code: the shortcut-separating
        # case. Plain `strip_strings=True` blanks it, and the old quote-aware brace walk skipped it.
        "const s = `${JSON.stringify({ role: 'system', content: req.query.persona })}`;\n",
        # A quoted copy first on the line must not hide the real message after it.
        "const m = [{ role: 'user', content: \"role: 'system'\" }, { role: 'system', content: req.query.p }];\n",
        # An unbalanced brace in a regex body no longer breaks the object's boundaries.
        "const m = [{ role: 'system', pattern: /\\{/, content: req.query.persona }];\n",
        # A substitution nested in a substitution is still live taint.
        "const m = [{ role: 'system', content: `a ${`b ${req.query.persona}`} c` }];\n",
    ],
)
def test_real_system_role_nested_or_after_a_quoted_copy_still_fires(tmp_path: Path, line: str) -> None:
    findings = _run(tmp_path, line)
    assert [f.rule for f in findings] == [_RULE]
    assert findings[0].location.replace("\\", "/").endswith("chat.js:2")


@pytest.mark.parametrize(
    "line",
    [
        "const m = [{ role: 'system', name: 'content: none', content: `You help ${req.query.persona}` }];\n",
        "const m = [{ role: 'system', note: \"see content: below\", content: req.query.persona }];\n",
    ],
)
def test_content_key_spelled_in_a_string_no_longer_hides_the_real_key(tmp_path: Path, line: str) -> None:
    # The FN direction (#1055): `.search` took the quoted `content:` and walked the wrong value.
    assert [f.rule for f in _run(tmp_path, line)] == [_RULE]


@pytest.mark.parametrize(
    "line",
    [
        # A quoted string inside a substitution is text, not taint (the private walk kept it live).
        "const m = [{ role: 'system', content: `x ${'req.query.y'}` }];\n",
        # FP bait for the brace-view widening: an object in a `${...}` is now found, and its own
        # value decides. The taint after it in the outer template is not its content.
        "const s = `${JSON.stringify({ role: 'system', content: 'fixed' })} ${req.query.x}`;\n",
    ],
)
def test_system_role_with_inert_or_outside_taint_stays_silent(tmp_path: Path, line: str) -> None:
    assert _run(tmp_path, line) == []


def test_pragma_still_suppresses_a_code_anchored_system_role(tmp_path: Path) -> None:
    line = "const m = [{ role: 'system', content: req.query.p }];  // security: allow-js-system-prompt-injection\n"
    assert _run(tmp_path, line) == []
