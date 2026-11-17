from __future__ import annotations

import pytest

from agentsec.findings import Finding
from agentsec.guards.js_path_traversal import JsPathTraversalGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_template_literal_interpolation(tmp_path: Path) -> None:
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  fs.readFile(`./uploads/${req.params.filename}`, cb);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsPathTraversalGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-path-traversal/tainted-fs-path"
    assert findings[0].severity == "high"


def test_flags_concatenation(tmp_path: Path) -> None:
    (tmp_path / "download.ts").write_text(
        "function handler(req, res) {\n"
        '  fs.createReadStream("/data/" + req.query.path);\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    findings = JsPathTraversalGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-path-traversal/tainted-fs-path"


def test_flags_write_sink(tmp_path: Path) -> None:
    (tmp_path / "upload.js").write_text(
        "function handler(req, res) {\n"
        "  fs.writeFileSync(`./data/${req.body.name}`, contents);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert len(JsPathTraversalGuard().run(tmp_path, profile)) == 1


def test_silent_with_nearby_path_resolve_check(tmp_path: Path) -> None:
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  const target = path.resolve(baseDir, req.params.filename);\n"
        "  if (!target.startsWith(baseDir)) throw new Error('bad path');\n"
        "  fs.readFile(`./uploads/${req.params.filename}`, cb);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


def test_silent_with_nearby_normalize_check(tmp_path: Path) -> None:
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  fs.createReadStream(\"/data/\" + req.query.path);\n"
        "  const safe = path.normalize(req.query.path);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


def test_silent_on_fully_static_path(tmp_path: Path) -> None:
    (tmp_path / "config.js").write_text(
        'fs.readFile("./config/app.json", cb);\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


def test_silent_on_bare_tainted_reference(tmp_path: Path) -> None:
    # A bare reference (no concat/interpolation) is not flagged — too common/imprecise a
    # signal on its own, mirrors the Python path-traversal guard's bare-`open(var)` carve-out.
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  fs.readFile(req.query.path, cb);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "download.js").write_text(
        "// Never do: fs.readFile(`./uploads/${req.params.filename}`, cb)\n"
        'fs.readFile("./config/app.json", cb);\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "download.js").write_text(
        "// security: allow-js-path-traversal\n"
        "function handler(req, res) {\n"
        "  fs.readFile(`./uploads/${req.params.filename}`, cb);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


def test_not_applies_without_js_or_ts(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features=set())
    assert not JsPathTraversalGuard().applies(profile)


def test_applies_with_typescript_only(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"typescript"})
    assert JsPathTraversalGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.js").write_text(
        "fs.readFile(`./uploads/${req.params.filename}`, cb);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


def test_js_path_traversal_trailing_comment_sink_silent(tmp_path: Path) -> None:
    # #395 H1: an `fs` sink in a TRAILING same-line comment must not fire.
    (tmp_path / "handler.js").write_text(
        "const base = safeDir();  // fs.readFile(`./uploads/${req.params.filename}`, cb) legacy\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


# --- the fix: a bare .startsWith(base) no longer silences the guard -------------------


def test_naive_startswith_with_no_separator_now_still_fires(tmp_path: Path) -> None:
    # Test the direction traded against (CLAUDE.md rule 1): a bare `.startsWith(base)` with
    # NO trailing separator is exactly CVE-2025-53109/53110's own "EscapeRoute" bypass
    # ("/private/tmp/allowed_dir_evil".startsWith("/private/tmp/allowed_dir") is true) --
    # before the fix this silenced the guard just like a real containment check.
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  const target = req.params.filename;\n"
        "  if (!target.startsWith(baseDir)) throw new Error('bad path');\n"
        "  fs.readFile(`./uploads/${req.params.filename}`, cb);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsPathTraversalGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-path-traversal/tainted-fs-path"


def test_startswith_with_path_sep_separator_stays_silent(tmp_path: Path) -> None:
    # FP bait: a genuinely separator-boundary-aware startsWith check (`path.sep`) must still
    # silence the finding. 2026-09-24 fix (Dean's review, round 2): the base used to be
    # `path.resolve(baseDir, ...)` on the line above, which independently matches `_SAFE_JS`
    # regardless of what the `.startsWith(` argument says -- the test passed even with the
    # separator-boundary check forced off, so it never actually discriminated on `path.sep`
    # evidence. A bare identifier base (no `path.resolve`/`.normalize`/`.isAbsolute` anywhere
    # in the window) isolates the `path.sep` evidence this test claims to cover; the nested-
    # helper-call shape (`getBaseDir() + path.sep`) is covered separately below.
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  const target = req.params.filename;\n"
        "  if (!target.startsWith(baseDir + path.sep)) throw new Error('bad path');\n"
        "  fs.readFile(`./uploads/${req.params.filename}`, cb);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


def test_startswith_with_literal_slash_separator_stays_silent(tmp_path: Path) -> None:
    # FP bait: a literal '/' separator concatenated onto the base is also boundary-aware.
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  const target = req.params.filename;\n"
        "  if (!target.startsWith(baseDir + '/')) throw new Error('bad path');\n"
        "  fs.readFile(`./uploads/${req.params.filename}`, cb);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


def test_startswith_with_template_literal_trailing_slash_stays_silent(tmp_path: Path) -> None:
    # FP bait: `` `${baseDir}/` `` -- a template literal with a trailing separator.
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  const target = req.params.filename;\n"
        "  if (!target.startsWith(`${baseDir}/`)) throw new Error('bad path');\n"
        "  fs.readFile(`./uploads/${req.params.filename}`, cb);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


def test_path_relative_check_stays_silent(tmp_path: Path) -> None:
    # path.relative(base, target).startsWith('..') is unconditionally safe -- no separator-
    # boundary bypass possible, unlike a raw .startsWith(base) prefix check.
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  const rel = path.relative(baseDir, req.params.filename);\n"
        "  if (rel.startsWith('..')) throw new Error('bad path');\n"
        "  fs.readFile(`./uploads/${req.params.filename}`, cb);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


def test_path_relative_merely_logged_still_fires(tmp_path: Path) -> None:
    # (Dean's review): path.relative( used to be an unconditionally-safe marker --
    # its mere PRESENCE nearby silenced the finding, even when its result is never checked
    # against anything. A console.log of it (or any other non-gating use) must NOT silence a
    # real finding; only a genuine `.startsWith('..')`/`.includes('..')` check on its result does.
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  console.log(path.relative(baseDir, req.params.filename));\n"
        "  fs.readFile(`./uploads/${req.params.filename}`, cb);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsPathTraversalGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-path-traversal/tainted-fs-path"


def test_path_relative_includes_check_stays_silent(tmp_path: Path) -> None:
    # FP bait: `.includes('..')` is an equally valid way to test path.relative()'s result --
    # must still silence, mirroring the .startsWith('..') shape.
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  const rel = path.relative(baseDir, req.params.filename);\n"
        "  if (rel.includes('..')) throw new Error('bad path');\n"
        "  fs.readFile(`./uploads/${req.params.filename}`, cb);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


def test_path_relative_split_sep_check_stays_silent(tmp_path: Path) -> None:
    # FP bait: `.split(path.sep)[0] === '..'` (Dean's review, round 2) is a common, correct
    # containment check on path.relative()'s result -- was flagged (a false positive) before
    # this fix, since the escape-check regex only recognized `.startsWith`/`.includes` on the
    # result.
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  const rel = path.relative(baseDir, req.params.filename);\n"
        "  if (rel.split(path.sep)[0] === '..') throw new Error('bad path');\n"
        "  fs.readFile(`./uploads/${req.params.filename}`, cb);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


def test_path_relative_split_sep_inverse_check_stays_silent(tmp_path: Path) -> None:
    # FP bait: the `!== '..'` inverse (guard the happy path instead of throwing on the bad one)
    # is an equally valid containment check on the same split-and-compare idiom.
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  const rel = path.relative(baseDir, req.params.filename);\n"
        "  if (rel.split(path.sep)[0] !== '..') {\n"
        "    fs.readFile(`./uploads/${req.params.filename}`, cb);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


def test_path_relative_split_wrong_index_still_fires(tmp_path: Path) -> None:
    # Narrowing safety check (the direction traded against): a split-and-compare on the WRONG
    # index (or against a different string) is not a real escape check on the first path
    # segment -- must still fire, proving the new pattern requires index 0 and '..' specifically.
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  const rel = path.relative(baseDir, req.params.filename);\n"
        "  if (rel.split(path.sep)[1] === '..') throw new Error('bad path');\n"
        "  fs.readFile(`./uploads/${req.params.filename}`, cb);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsPathTraversalGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-path-traversal/tainted-fs-path"


def test_startswith_nested_call_argument_evidence_still_recognized(tmp_path: Path) -> None:
    # (Dean's review): the evidence regex used to stop at the FIRST nested `)`, so
    # a `.startsWith(...)` argument containing its own function call (e.g. a custom
    # getBaseDir() helper, not path.resolve/normalize/isAbsolute -- which would otherwise
    # independently silence via _SAFE_JS) truncated away the actual separator-boundary
    # evidence that came after it. This is exactly the guard's own documented remediation
    # shape (`path.resolve(baseDir) + path.sep`) with the well-known helper swapped for a
    # generic one, so no other marker masks the bug.
    (tmp_path / "download.js").write_text(
        "function handler(req, res) {\n"
        "  const target = req.params.filename;\n"
        "  if (!target.startsWith(getBaseDir() + path.sep)) throw new Error('bad path');\n"
        "  fs.readFile(`./uploads/${req.params.filename}`, cb);\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsPathTraversalGuard().run(tmp_path, profile) == []


# --- #1055: the fs sink and every containment marker count only when they are live code ----------

_SINK = "  fs.readFile(`./uploads/${req.params.filename}`, cb);\n"


def _run_handler(tmp_path: Path, body: str) -> list[Finding]:
    (tmp_path / "download.js").write_text(
        "const fs = require('fs');\napp.get('/d', (req, res) => {\n" + body + "});\n", encoding="utf-8"
    )
    return JsPathTraversalGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))


@pytest.mark.parametrize(
    "extra",
    [
        "  log.warn('TODO: path.resolve( the target');\n",
        "  log.warn(`TODO: path.normalize( the target first`);\n",
        "  log.warn(\"use p.startsWith(base + '/') here\");\n",
        "  log('path.relative(a, b) then rel.startsWith(\"..\")');\n",
        # A real `path.relative(` whose escape check exists only in a string is not checked.
        "  const r = path.relative(base, t);\n  log(\"then r.split(path.sep)[0] === '..'\");\n",
    ],
)
def test_quoted_containment_marker_no_longer_clears_the_finding(tmp_path: Path, extra: str) -> None:
    # The FN direction (#1055): a marker spelled out in a log string silenced a real sink.
    findings = _run_handler(tmp_path, extra + _SINK)
    assert [f.rule for f in findings] == ["js-path-traversal/tainted-fs-path"]


@pytest.mark.parametrize(
    "extra",
    [
        "  const p = path.resolve(base, name);\n",
        "  if (!p.startsWith(base + path.sep)) throw e;\n",
        "  const r = path.relative(base, t);\n  if (r.startsWith('..')) throw e;\n",
        # The real marker nested in a `${...}` substitution is code: the shortcut-separating case,
        # which plain `strip_strings=True` would have blanked.
        "  log(`resolved ${path.resolve(base, name)}`);\n",
        # A quoted copy earlier on the line must not hide the real call after it (shadowing).
        "  log('path.resolve( todo'); const p = path.resolve(base, name);\n",
    ],
)
def test_real_containment_marker_still_clears_the_finding(tmp_path: Path, extra: str) -> None:
    assert _run_handler(tmp_path, extra + _SINK) == []


@pytest.mark.parametrize(
    "body",
    [
        "  log('fs.readFile(`./u/${req.params.f}`) is unsafe');\n",
        "  log(`never fs.readFile(\"./u/\" + req.params.f)`);\n",
    ],
)
def test_fs_sink_spelled_in_a_string_does_not_fire(tmp_path: Path, body: str) -> None:
    # The FP direction (#1055): a docs or log string is not an fs call.
    assert _run_handler(tmp_path, body) == []


@pytest.mark.parametrize(
    "body",
    [
        _SINK,
        # A sink in a `${...}` substitution is code: the shortcut-separating case.
        "  const s = `${fs.readFileSync('./u/' + req.params.f)}`;\n",
        # A quoted copy, or a static real call, first on the line used to hide the tainted call
        # after it (`.search` took the first hit): a first-match shadowing FN on main.
        "  log('fs.readFile( x'); fs.readFile(`./u/${req.params.f}`, cb);\n",
        "  fs.readFile('./a.json', cb); fs.readFile(`./u/${req.params.f}`, cb);\n",
    ],
)
def test_real_fs_sink_nested_or_after_another_call_still_fires(tmp_path: Path, body: str) -> None:
    findings = _run_handler(tmp_path, body)
    assert [f.rule for f in findings] == ["js-path-traversal/tainted-fs-path"]
    assert findings[0].location.replace("\\", "/").endswith("download.js:3")


def test_pragma_still_suppresses_a_code_anchored_sink(tmp_path: Path) -> None:
    sink = "  fs.readFile(`./u/${req.params.f}`, cb);"
    # Both directions (PR #1131 round-1 L1): the shape fires without the pragma.
    assert len(_run_handler(tmp_path, sink + "\n")) == 1
    assert _run_handler(tmp_path, sink + "  // security: allow-js-path-traversal\n") == []
