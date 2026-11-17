from __future__ import annotations

from agentsec.guards.js_prototype_pollution import JsPrototypePollutionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_tainted_key_assignment(tmp_path: Path) -> None:
    (tmp_path / "handler.js").write_text(
        "function assignFromBody(req, obj) {\n"
        "  obj[req.body.key] = req.body.value;\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = JsPrototypePollutionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-prototype-pollution/tainted-key-assign"
    assert findings[0].severity == "high"

def test_flags_tainted_merge_call(tmp_path: Path) -> None:
    (tmp_path / "handler.js").write_text(
        "function mergeFromBody(req, target) {\n"
        "  _.merge(target, JSON.parse(req.body.data));\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = JsPrototypePollutionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-prototype-pollution/tainted-merge"

def test_silent_when_denylist_check_nearby(tmp_path: Path) -> None:
    (tmp_path / "handler.js").write_text(
        "function safeAssign(req, obj) {\n"
        "  const key = req.body.key;\n"
        "  if (['__proto__', 'constructor', 'prototype'].includes(key)) return;\n"
        "  obj[key] = req.body.value;\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert JsPrototypePollutionGuard().run(tmp_path, profile) == []


def test_not_suppressed_by_incidental_constructor_word(tmp_path: Path) -> None:
    # #395 review Critical: a real tainted-key assignment must NOT be treated as sanitized just
    # because the bare word `constructor` (an ES6 method) or a comment mentioning `prototype`
    # appears within the window. Only a quoted-key denylist / hasOwnProperty call is a sanitizer.
    (tmp_path / "handler.js").write_text(
        "class Store {\n"
        "  constructor(name) { this.name = name; }\n"
        "  // guard against prototype pollution here (comment only)\n"
        "  assign(req, obj) { obj[req.body.key] = req.body.value; }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = JsPrototypePollutionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-prototype-pollution/tainted-key-assign"


def test_silent_when_denylist_check_uses_template_literal(tmp_path: Path) -> None:
    # Low finding (review #395): a denylist check written as a backtick template literal is
    # equally a real sanitizer.
    (tmp_path / "handler.js").write_text(
        "function safeAssign(req, obj) {\n"
        "  const key = req.body.key;\n"
        "  if ([`__proto__`, `constructor`, `prototype`].includes(key)) return;\n"
        "  obj[key] = req.body.value;\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert JsPrototypePollutionGuard().run(tmp_path, profile) == []


def test_silent_when_hasownproperty_call_nearby(tmp_path: Path) -> None:
    # a genuine hasOwnProperty guard (a CALL) still suppresses
    (tmp_path / "handler.js").write_text(
        "function safeAssign(req, obj) {\n"
        "  const key = req.body.key;\n"
        "  if (Object.prototype.hasOwnProperty.call(obj, key)) obj[key] = req.body.value;\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert JsPrototypePollutionGuard().run(tmp_path, profile) == []


def test_silent_on_static_key_assignment(tmp_path: Path) -> None:
    (tmp_path / "handler.js").write_text(
        "function staticAssign(obj) {\n"
        "  obj['fixedKey'] = 'value';\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert JsPrototypePollutionGuard().run(tmp_path, profile) == []

def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "handler.js").write_text(
        "// security: allow-proto-pollution\n"
        "function assignFromBody(req, obj) {\n"
        "  obj[req.body.key] = req.body.value;\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert JsPrototypePollutionGuard().run(tmp_path, profile) == []

def test_not_applicable_without_frontend() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert JsPrototypePollutionGuard().applies(prof) is False

def test_applies_on_backend_only_js_or_ts() -> None:
    # #395 C1: the sinks are server-side, so the guard must apply on a backend-only Node/TS repo
    # (the `javascript`/`typescript` signal), not only when a React/Vite `frontend` is detected.
    assert JsPrototypePollutionGuard().applies(mkprofile(Path("/tmp"), features={"javascript"})) is True
    assert JsPrototypePollutionGuard().applies(mkprofile(Path("/tmp"), features={"typescript"})) is True
