from __future__ import annotations

from agentsec.guards.php_reflected_xss import PhpReflectedXssGuard
from tests.guards._common import *  # noqa: F401,F403


def test_php_reflected_xss_flags_unescaped_echo(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { echo $_GET['name']; }\n", encoding="utf-8"
    )
    findings = PhpReflectedXssGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-reflected-xss/unescaped-superglobal-echo"
    assert findings[0].severity == "high"


def test_php_reflected_xss_flags_unescaped_print(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { print $_POST['x']; }\n", encoding="utf-8"
    )
    findings = PhpReflectedXssGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-reflected-xss/unescaped-superglobal-echo"


def test_php_reflected_xss_flags_short_echo_tag(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\n?>\n<?= $_REQUEST['y'] ?>\n", encoding="utf-8"
    )
    findings = PhpReflectedXssGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-reflected-xss/unescaped-superglobal-echo"


def test_php_reflected_xss_silent_on_htmlspecialchars(tmp_path: Path) -> None:
    # FP-bait: the canonical correct-escaping idiom must not fire — this is the single
    # highest-risk case for this guard (graudit's own doc flags escaping-context FP risk).
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { echo htmlspecialchars($_GET['name']); }\n", encoding="utf-8"
    )
    assert PhpReflectedXssGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_reflected_xss_silent_on_htmlentities(tmp_path: Path) -> None:
    # FP-bait.
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { echo htmlentities($_POST['x']); }\n", encoding="utf-8"
    )
    assert PhpReflectedXssGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_reflected_xss_silent_on_strip_tags(tmp_path: Path) -> None:
    # FP-bait.
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { echo strip_tags($_REQUEST['y']); }\n", encoding="utf-8"
    )
    assert PhpReflectedXssGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_reflected_xss_silent_on_filter_var(tmp_path: Path) -> None:
    # FP-bait.
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { echo filter_var($_COOKIE['x'], FILTER_SANITIZE_STRING); }\n",
        encoding="utf-8",
    )
    assert PhpReflectedXssGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_reflected_xss_silent_on_literal_output(tmp_path: Path) -> None:
    # FP-bait: no superglobal at all must not fire.
    (tmp_path / "T.php").write_text(
        '<?php\nfunction f() { echo "Hello, world!"; }\n', encoding="utf-8"
    )
    assert PhpReflectedXssGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_reflected_xss_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { echo $_GET['name']; "
        "// security: allow-php-reflected-xss\n}\n",
        encoding="utf-8",
    )
    assert PhpReflectedXssGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_reflected_xss_silent_in_slash_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\n// echo $_GET['name']; example only\nreal();\n", encoding="utf-8"
    )
    assert PhpReflectedXssGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_reflected_xss_silent_in_hash_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `#` comment must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\n# echo $_GET['name']; is an example, do not use\nreal();\n", encoding="utf-8"
    )
    assert PhpReflectedXssGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_reflected_xss_not_applicable_without_php() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert PhpReflectedXssGuard().applies(prof) is False
