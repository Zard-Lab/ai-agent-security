from __future__ import annotations

import pytest

from agentsec.guards.js_security_headers_absent import JsSecurityHeadersAbsentGuard
from tests.guards._common import *  # noqa: F401,F403


def _express_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"express"})


def test_js_security_headers_absent_flags_missing_evidence(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/', (req, res) => res.send('hi'));\n",
        encoding="utf-8",
    )
    findings = JsSecurityHeadersAbsentGuard().run(tmp_path, _express_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "js-security-headers-absent/no-security-headers-middleware"
    assert findings[0].severity == "low"
    assert findings[0].location.endswith(":2")  # anchored at the express() call


def test_js_security_headers_absent_silent_with_inline_require_helmet(tmp_path: Path) -> None:
    # #548 review Medium 7: `app.use(require('helmet')())` is ordinary, idiomatic
    # helmet usage (the inline require-then-invoke idiom), but the old `_HELMET_CALL` regex
    # (`\bhelmet\s*\(`) required "helmet" to be immediately followed by "(" — here it's a string
    # literal argument to `require(...)`, followed by `)(`, not `(`, so it was silently missed.
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use(require('helmet')());\n",
        encoding="utf-8",
    )
    assert JsSecurityHeadersAbsentGuard().run(tmp_path, _express_prof(tmp_path)) == []


def test_js_security_headers_absent_silent_with_helmet(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const helmet = require('helmet');\n"
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use(helmet());\n",
        encoding="utf-8",
    )
    assert JsSecurityHeadersAbsentGuard().run(tmp_path, _express_prof(tmp_path)) == []


def test_js_security_headers_absent_silent_with_manual_header(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use((req, res, next) => {\n"
        "  res.setHeader('X-Frame-Options', 'DENY');\n"
        "  next();\n"
        "});\n",
        encoding="utf-8",
    )
    assert JsSecurityHeadersAbsentGuard().run(tmp_path, _express_prof(tmp_path)) == []


def test_js_security_headers_absent_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();  // security: allow-missing-security-headers\n",
        encoding="utf-8",
    )
    assert JsSecurityHeadersAbsentGuard().run(tmp_path, _express_prof(tmp_path)) == []


def test_js_security_headers_absent_not_applicable_without_express() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert JsSecurityHeadersAbsentGuard().applies(prof) is False


def test_js_security_headers_absent_anchors_on_import_when_no_instantiation(tmp_path: Path) -> None:
    # No visible express() call in the scanned source — fall back to the require/import line.
    (tmp_path / "server.js").write_text(
        "const express = require('express');\n"
        "module.exports = buildApp(express);\n",
        encoding="utf-8",
    )
    findings = JsSecurityHeadersAbsentGuard().run(tmp_path, _express_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith(":1")


def test_js_security_headers_absent_silent_when_express_only_in_tests(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "app.test.js").write_text(
        "const express = require('express');\nconst app = express();\n", encoding="utf-8"
    )
    assert JsSecurityHeadersAbsentGuard().run(tmp_path, _express_prof(tmp_path)) == []


def test_js_security_headers_absent_not_silenced_by_comment_mentioning_helmet(tmp_path: Path) -> None:
    # A comment mentioning "helmet" with no real helmet() call must not silence the guard —
    # confirms evidence matching is comment-stripped, not a raw substring search.
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "// TODO: consider adding helmet() at some point\n",
        encoding="utf-8",
    )
    findings = JsSecurityHeadersAbsentGuard().run(tmp_path, _express_prof(tmp_path))
    assert len(findings) == 1


def test_js_security_headers_absent_known_bypass_indirect_header_name(tmp_path: Path) -> None:
    # Documented known bypass (see design doc "Known bypasses"): a header name held in a
    # variable and passed indirectly is NOT recognized as evidence, so the guard still fires
    # even though the header IS actually being set. This test pins the current (missed)
    # behavior rather than silently shipping an undocumented gap.
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "const headerName = 'X-Frame-Options';\n"
        "app.use((req, res, next) => {\n"
        "  res.set(headerName, 'DENY');\n"
        "  next();\n"
        "});\n",
        encoding="utf-8",
    )
    findings = JsSecurityHeadersAbsentGuard().run(tmp_path, _express_prof(tmp_path))
    assert len(findings) == 1  # known miss — the indirect assignment is not recognized


def test_js_security_headers_absent_examples_dir_helmet_does_not_silence(tmp_path: Path) -> None:
    # #548 round-3 review, High 2: the evidence pass used to scan ALL files, so a real helmet()
    # call in a non-product examples/ dir silenced the whole repo's finding even though the
    # actual product app has no header protection at all.
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.js").write_text(
        "const express = require('express');\nconst app = express();\n", encoding="utf-8"
    )
    examples_dir = tmp_path / "examples"
    examples_dir.mkdir()
    (examples_dir / "helmet-demo.js").write_text(
        "app.use(require('helmet')());\n", encoding="utf-8"
    )
    findings = JsSecurityHeadersAbsentGuard().run(tmp_path, _express_prof(tmp_path))
    assert len(findings) == 1


def test_js_security_headers_absent_string_literal_prose_does_not_silence(tmp_path: Path) -> None:
    # #548 round-3 review, High 2 (second half): the widened inline-require-helmet pattern isn't
    # string-literal-aware, so a bare string CONTAINING the matching text (documentation prose,
    # a log message) used to silence the guard as if it were a real helmet() invocation.
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "const tip = \"install require('helmet')() for headers\";\n",
        encoding="utf-8",
    )
    findings = JsSecurityHeadersAbsentGuard().run(tmp_path, _express_prof(tmp_path))
    assert len(findings) == 1


def test_js_security_headers_absent_pragma_honored_outside_product_files(tmp_path: Path) -> None:
    # CLAUDE.md rule 4: a suppression change (scoping evidence to product_files) must not be
    # able to void the user's OWN opt-out pragma — the pragma pass stays unscoped on purpose,
    # unlike the evidence pass right above it in the source.
    #
    # The pragma MUST live under a directory `is_nonproduct_path` actually excludes, or this test
    # cannot see the boundary it exists to pin (#548 round-4 gate). It was written with `docs/`,
    # which is NOT in `NONPRODUCT_DIR_ALT` — so the fixture sat on the product side, and scoping
    # the pragma pass to `product_files` (exactly the rule-4 violation named above) left this test
    # green. Measured, pragma in `docs/`: shipped 0 findings, regressed 0. Pragma in `examples/`:
    # shipped 0, regressed 1. A regression pin that is green for the wrong reason is worse than no
    # pin, because the next reader trusts the name.
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.js").write_text(
        "const express = require('express');\nconst app = express();\n", encoding="utf-8"
    )
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "notes.js").write_text(
        "// security: allow-missing-security-headers\n", encoding="utf-8"
    )
    assert JsSecurityHeadersAbsentGuard().run(tmp_path, _express_prof(tmp_path)) == []


def test_js_security_headers_absent_pragma_quoted_in_a_string_does_not_opt_out(tmp_path: Path) -> None:
    # #424 E4: the repo-level opt-out reads the JS comment-only view of each file, so a string
    # literal quoting the pragma is content - only a real `//` comment opts out.
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        'const help = "opt out with // security: allow-missing-security-headers";\n',
        encoding="utf-8",
    )
    findings = JsSecurityHeadersAbsentGuard().run(tmp_path, _express_prof(tmp_path))
    assert [f.rule for f in findings] == ["js-security-headers-absent/no-security-headers-middleware"]


# --- #1055: header evidence counts only when it is live code --------------------------------------

_HDR_RULE = "js-security-headers-absent/no-security-headers-middleware"
_APP = "const express = require('express');\nconst app = express();\n"


def _hdr_rules(tmp_path: Path, extra: str) -> list[str]:
    (tmp_path / "app.js").write_text(_APP + extra, encoding="utf-8")
    return [f.rule for f in JsSecurityHeadersAbsentGuard().run(tmp_path, _express_prof(tmp_path))]


@pytest.mark.parametrize(
    "extra",
    [
        # Both shapes the module docstring used to list as a measured Known bypass, now closed.
        "console.log(`remember to require('helmet')() before prod`);\n",
        "const NOTES = `\n  TODO before launch:\n  app.use(helmet());\n`;\n",
        "const t = `res.setHeader('X-Frame-Options', 'DENY') is missing`;\n",
        "log('call helmet() here');\n",
    ],
)
def test_js_security_headers_absent_quoted_evidence_does_not_silence(tmp_path: Path, extra: str) -> None:
    assert _hdr_rules(tmp_path, extra) == [_HDR_RULE]


@pytest.mark.parametrize(
    "extra",
    [
        "app.use(helmet());\n",
        "app.use(require('helmet')());\n",
        "app.use((req, res, next) => { res.setHeader('X-Frame-Options', 'DENY'); next(); });\n",
        # A quote inside a regex literal threw the private quote-parity test off: it read the real
        # call after `/'/` as inside a string and fired.
        "const apos = /'/; app.use(helmet());\n",
        # A quoted copy earlier on the line must not hide the real call after it.
        "log('helmet( later'); app.use(helmet());\n",
        # The real call nested in a `${...}` substitution is code (the shortcut-separating case).
        "const s = `${app.use(helmet())}`;\n",
    ],
)
def test_js_security_headers_absent_real_evidence_still_silences(tmp_path: Path, extra: str) -> None:
    assert _hdr_rules(tmp_path, extra) == []
