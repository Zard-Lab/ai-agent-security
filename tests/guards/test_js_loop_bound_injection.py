from __future__ import annotations

from agentsec.guards.js_loop_bound_injection import JsLoopBoundInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_js_loop_bound_injection_flags_for_loop(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text(
        "app.post('/bulk', (req, res) => {\n"
        "  for (let i = 0; i < req.body.items.length; i++) {\n"
        "    processItem(req.body.items[i]);\n"
        "  }\n"
        "});\n",
        encoding="utf-8",
    )
    findings = JsLoopBoundInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "js-loop-bound-injection/tainted-length-bound"
    assert findings[0].severity == "high"


def test_js_loop_bound_injection_flags_while_loop(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text(
        "let i = 0;\nwhile (i < req.query.items.length) {\n  i++;\n}\n",
        encoding="utf-8",
    )
    findings = JsLoopBoundInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1


def test_js_loop_bound_injection_silent_local_array(tmp_path: Path) -> None:
    # FP-bait: a local, non-request-derived array bound is fine.
    (tmp_path / "routes.js").write_text(
        "const items = [1, 2, 3];\n"
        "for (let i = 0; i < items.length; i++) {\n"
        "  console.log(items[i]);\n"
        "}\n",
        encoding="utf-8",
    )
    assert JsLoopBoundInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_loop_bound_injection_silent_capped_with_math_min(tmp_path: Path) -> None:
    # FP-bait: the properly-capped idiom — Math.min(...) sits right after the comparison
    # operator, not req. directly, so this stays silent.
    (tmp_path / "routes.js").write_text(
        "for (let i = 0; i < Math.min(req.body.items.length, MAX_ITEMS); i++) {\n"
        "  processItem(i);\n"
        "}\n",
        encoding="utf-8",
    )
    assert JsLoopBoundInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_loop_bound_injection_pragma(tmp_path: Path) -> None:
    (tmp_path / "routes.js").write_text(
        "for (let i = 0; i < req.body.items.length; i++) {}  "
        "// security: allow-js-loop-bound-injection\n",
        encoding="utf-8",
    )
    assert JsLoopBoundInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_loop_bound_injection_not_applies_without_express() -> None:
    assert JsLoopBoundInjectionGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False
