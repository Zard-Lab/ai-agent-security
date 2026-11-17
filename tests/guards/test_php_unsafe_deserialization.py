from __future__ import annotations

from agentsec.guards.php_unsafe_deserialization import PhpUnsafeDeserializationGuard
from tests.guards._common import *  # noqa: F401,F403


def test_php_unsafe_deserialization_flags_get_superglobal(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { return unserialize($_GET['data']); }\n", encoding="utf-8"
    )
    findings = PhpUnsafeDeserializationGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-unsafe-deserialization/tainted-unserialize"
    assert findings[0].severity == "critical"


def test_php_unsafe_deserialization_flags_cookie_superglobal(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { return unserialize($_COOKIE['session']); }\n", encoding="utf-8"
    )
    findings = PhpUnsafeDeserializationGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_unsafe_deserialization_flags_bare_variable(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($payload) { return unserialize($payload); }\n", encoding="utf-8"
    )
    findings = PhpUnsafeDeserializationGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_unsafe_deserialization_flags_concatenation(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($x) { return unserialize('prefix' . $x); }\n", encoding="utf-8"
    )
    findings = PhpUnsafeDeserializationGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_unsafe_deserialization_flags_function_call_result(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($p) { return unserialize(file_get_contents($p)); }\n", encoding="utf-8"
    )
    findings = PhpUnsafeDeserializationGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_unsafe_deserialization_flags_post_and_request(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\n"
        "function f() { return unserialize($_POST['data']); }\n"
        "function g() { return unserialize($_REQUEST['data']); }\n",
        encoding="utf-8",
    )
    findings = PhpUnsafeDeserializationGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 2


def test_php_unsafe_deserialization_silent_on_all_literal_single_quoted(tmp_path: Path) -> None:
    # FP-bait: a hardcoded string literal argument must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { return unserialize('a:1:{i:0;s:3:\"foo\";}'); }\n",
        encoding="utf-8",
    )
    assert PhpUnsafeDeserializationGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_unsafe_deserialization_silent_on_all_literal_double_quoted(tmp_path: Path) -> None:
    # FP-bait: a hardcoded double-quoted literal argument must not fire.
    (tmp_path / "T.php").write_text(
        '<?php\nfunction f() { return unserialize("a:0:{}"); }\n',
        encoding="utf-8",
    )
    assert PhpUnsafeDeserializationGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_unsafe_deserialization_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($payload) { return unserialize($payload); "
        "// security: allow-php-unsafe-deserialization\n}\n",
        encoding="utf-8",
    )
    assert PhpUnsafeDeserializationGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_unsafe_deserialization_silent_in_slash_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\n// unserialize($_GET['data']); example only\nreal();\n", encoding="utf-8"
    )
    assert PhpUnsafeDeserializationGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_unsafe_deserialization_silent_in_hash_comment(tmp_path: Path) -> None:
    # FP-bait for the # line-comment handling in strip_php_comments: an example inside a real
    # # comment must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\n# unserialize($_GET['data']); is an example, do not use\nreal();\n",
        encoding="utf-8",
    )
    assert PhpUnsafeDeserializationGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_unsafe_deserialization_not_applicable_without_php() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert PhpUnsafeDeserializationGuard().applies(prof) is False
