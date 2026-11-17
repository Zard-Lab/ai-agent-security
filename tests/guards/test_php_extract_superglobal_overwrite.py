from __future__ import annotations

from agentsec.guards.php_extract_superglobal_overwrite import PhpExtractSuperglobalOverwriteGuard
from tests.guards._common import *  # noqa: F401,F403


def test_php_extract_superglobal_overwrite_flags_extract_get(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { extract($_GET); }\n", encoding="utf-8"
    )
    findings = PhpExtractSuperglobalOverwriteGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-extract-superglobal-overwrite/direct-superglobal-extract"
    assert findings[0].severity == "high"


def test_php_extract_superglobal_overwrite_flags_extract_post(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { extract($_POST); }\n", encoding="utf-8"
    )
    findings = PhpExtractSuperglobalOverwriteGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_extract_superglobal_overwrite_flags_extract_request(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { extract($_REQUEST); }\n", encoding="utf-8"
    )
    findings = PhpExtractSuperglobalOverwriteGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_extract_superglobal_overwrite_flags_extract_cookie(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { extract($_COOKIE); }\n", encoding="utf-8"
    )
    findings = PhpExtractSuperglobalOverwriteGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_extract_superglobal_overwrite_silent_on_local_array(tmp_path: Path) -> None:
    # FP-bait: a non-superglobal array name must not fire — the guard can't tell trusted from
    # untrusted data beyond the direct-superglobal-argument shape (documented scope limit).
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { $safe = ['a' => 1]; extract($safe); }\n", encoding="utf-8"
    )
    assert PhpExtractSuperglobalOverwriteGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_extract_superglobal_overwrite_silent_on_env(tmp_path: Path) -> None:
    # FP-bait: $_ENV is deliberately scoped out (not attacker-controlled in the same direct way).
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { extract($_ENV); }\n", encoding="utf-8"
    )
    assert PhpExtractSuperglobalOverwriteGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_extract_superglobal_overwrite_silent_on_server(tmp_path: Path) -> None:
    # FP-bait: $_SERVER is deliberately scoped out (same reasoning as $_ENV).
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { extract($_SERVER); }\n", encoding="utf-8"
    )
    assert PhpExtractSuperglobalOverwriteGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_extract_superglobal_overwrite_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { extract($_GET); "
        "// security: allow-extract-superglobal-overwrite\n}\n",
        encoding="utf-8",
    )
    assert PhpExtractSuperglobalOverwriteGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_extract_superglobal_overwrite_silent_in_slash_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\n// extract($_GET); example only\nreal();\n", encoding="utf-8"
    )
    assert PhpExtractSuperglobalOverwriteGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_extract_superglobal_overwrite_silent_in_hash_comment(tmp_path: Path) -> None:
    # FP-bait for the # line-comment handling in strip_php_comments: an example inside a real
    # # comment must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\n# extract($_GET); is an example, do not use\nreal();\n", encoding="utf-8"
    )
    assert PhpExtractSuperglobalOverwriteGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_extract_superglobal_overwrite_not_applicable_without_php() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert PhpExtractSuperglobalOverwriteGuard().applies(prof) is False
