from __future__ import annotations

from agentsec.guards.vite_sourcemap_prod import ViteSourcemapProdGuard
from tests.guards._common import *  # noqa: F401,F403


def test_vite_sourcemap_prod_flags_build_sourcemap_true(tmp_path: Path) -> None:
    (tmp_path / "vite.config.ts").write_text(
        "export default {\n  build: {\n    sourcemap: true\n  }\n}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteSourcemapProdGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "vite-sourcemap-prod/build-sourcemap-true"
    assert findings[0].severity == "medium"

def test_vite_sourcemap_prod_flags_inline(tmp_path: Path) -> None:
    (tmp_path / "vite.config.js").write_text(
        'export default {\n  build: {\n    sourcemap: "inline"\n  }\n}\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteSourcemapProdGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "vite-sourcemap-prod/build-sourcemap-true"

def test_vite_sourcemap_prod_flags_top_level(tmp_path: Path) -> None:
    (tmp_path / "vite.config.ts").write_text(
        "export default {\n  sourcemap: true\n}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteSourcemapProdGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "vite-sourcemap-prod/build-sourcemap-true"

def test_vite_sourcemap_prod_silent_server_block(tmp_path: Path) -> None:
    (tmp_path / "vite.config.ts").write_text(
        "export default {\n  server: {\n    sourcemap: true\n  }\n}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteSourcemapProdGuard().run(tmp_path, profile)
    assert findings == []

def test_vite_sourcemap_prod_flags_build_when_server_block_present(tmp_path: Path) -> None:
    # H10 (FN): a `server: {}` block earlier in the file must not silence a real
    # `build: { sourcemap: true }` — the old "server word in lookback" heuristic did.
    (tmp_path / "vite.config.ts").write_text(
        "export default {\n"
        "  server: {\n    port: 3000\n  },\n"
        "  build: {\n    sourcemap: true\n  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend", "react"})
    findings = ViteSourcemapProdGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "vite-sourcemap-prod/build-sourcemap-true"

def test_vite_sourcemap_prod_silent_commented_out(tmp_path: Path) -> None:
    (tmp_path / "vite.config.ts").write_text(
        "export default {\n  build: {\n    // sourcemap: true\n  }\n}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteSourcemapProdGuard().run(tmp_path, profile)
    assert findings == []

def test_vite_sourcemap_prod_silent_false(tmp_path: Path) -> None:
    (tmp_path / "vite.config.ts").write_text(
        "export default { build: { sourcemap: false } }\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteSourcemapProdGuard().run(tmp_path, profile)
    assert findings == []

def test_vite_sourcemap_prod_pragma_silences(tmp_path: Path) -> None:
    content = "// security: allow-vite-sourcemap\nexport default { build: { sourcemap: true } }\n"
    (tmp_path / "vite.config.ts").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = ViteSourcemapProdGuard().run(tmp_path, profile)
    assert findings == []

def test_vite_sourcemap_prod_not_applies_no_frontend(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    assert not ViteSourcemapProdGuard().applies(profile)

def test_vite_sourcemap_prod_silent_quoted_server_block(tmp_path: Path) -> None:
    # #293 FP direction: a quoted "server" block name must still be recognized as
    # the dev-only server block, not treated as an anonymous/unknown block.
    (tmp_path / "vite.config.ts").write_text(
        'export default {\n  "server": {\n    sourcemap: true\n  }\n}\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend", "react"})
    findings = ViteSourcemapProdGuard().run(tmp_path, profile)
    assert findings == []

def test_vite_sourcemap_prod_flags_quoted_build_and_key(tmp_path: Path) -> None:
    # #293 FN direction (the more security-relevant one): a quoted "build" block AND
    # a quoted "sourcemap" key together must still fire — this used to be silently missed.
    (tmp_path / "vite.config.ts").write_text(
        'export default {\n  "build": {\n    "sourcemap": true\n  }\n}\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend", "react"})
    findings = ViteSourcemapProdGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "vite-sourcemap-prod/build-sourcemap-true"

def test_vite_sourcemap_prod_flags_single_quoted_build_and_key(tmp_path: Path) -> None:
    # #293: single-quoted keys ('build' / 'sourcemap') are a legitimate JS/TS config
    # style and must fire the same as double-quoted — the widened regex uses a ["'] class,
    # so this closes the loop on the single-quote path alongside the double-quote test above.
    (tmp_path / "vite.config.ts").write_text(
        "export default {\n  'build': {\n    'sourcemap': true\n  }\n}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend", "react"})
    findings = ViteSourcemapProdGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "vite-sourcemap-prod/build-sourcemap-true"


def test_vite_sourcemap_hostile_brace_file_is_linear(tmp_path: Path) -> None:
    # Regression (issue #419): the block tracker searched the whole `text[:i]` prefix per `{`
    # (slice copy + `$`-anchored scan) — O(n²) on a brace-heavy hostile config. The name search
    # is now a bounded 200-char window. Actual ~0.05s; quadratic at this size takes minutes.
    import time

    (tmp_path / "vite.config.ts").write_text("x:{" * 60_000, encoding="utf-8")
    start = time.monotonic()
    findings = ViteSourcemapProdGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert time.monotonic() - start < 5.0, "quadratic prefix scan reintroduced"
    assert findings == []


def test_vite_sourcemap_name_found_within_window(tmp_path: Path) -> None:
    # The bounded window still resolves the naming identifier across realistic whitespace.
    (tmp_path / "vite.config.ts").write_text(
        "export default {\n  build:\n  {\n    sourcemap: true\n  }\n}\n",
        encoding="utf-8",
    )
    findings = ViteSourcemapProdGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
