from __future__ import annotations

from agentsec.guards.php_file_inclusion import PhpFileInclusionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_php_file_inclusion_flags_tainted_include(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction loadPage() { include($_GET['page']); }\n", encoding="utf-8"
    )
    findings = PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-file-inclusion/tainted-include"
    assert findings[0].severity == "critical"


def test_php_file_inclusion_flags_tainted_require_variable(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($p) { require($p); }\n", encoding="utf-8"
    )
    findings = PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-file-inclusion/tainted-include"


def test_php_file_inclusion_flags_tainted_require_once_concat(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($p) { require_once($p . '.php'); }\n", encoding="utf-8"
    )
    findings = PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-file-inclusion/tainted-include"


def test_php_file_inclusion_flags_tainted_include_once_superglobal(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { include_once($_REQUEST['x']); }\n", encoding="utf-8"
    )
    findings = PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-file-inclusion/tainted-include"


def test_php_file_inclusion_flags_php_filter_wrapper(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\n$x = file_get_contents("
        "'php://filter/read=convert.base64-encode/resource=index.php');\n",
        encoding="utf-8",
    )
    findings = PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-file-inclusion/dangerous-stream-wrapper"
    assert findings[0].severity == "critical"


def test_php_file_inclusion_flags_php_input_as_include_target(tmp_path: Path) -> None:
    """`include('php://input')` executes the raw POST body as PHP — the real RFI shape."""
    (tmp_path / "T.php").write_text("<?php\ninclude('php://input');\n", encoding="utf-8")
    findings = PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path))
    assert any(f.rule == "php-file-inclusion/dangerous-stream-wrapper" for f in findings)


def test_php_file_inclusion_flags_php_input_built_from_user_input(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\n$x = file_get_contents('php://input' . $_GET['f']);\n", encoding="utf-8"
    )
    findings = PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-file-inclusion/dangerous-stream-wrapper"


def test_php_file_inclusion_silent_on_bare_php_input_body_read(tmp_path: Path) -> None:
    """FP-bait: the canonical benign request-body read, in every PHP JSON API. Firing here at
    `critical` red-gates ordinary code, so the bare literal must stay silent."""
    (tmp_path / "T.php").write_text(
        "<?php\n$body = json_decode(file_get_contents('php://input'), true);\n", encoding="utf-8"
    )
    assert PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_file_inclusion_silent_on_psr7_php_input_stream(tmp_path: Path) -> None:
    """FP-bait: the PSR-7 stream idiom, same reasoning as the body read above."""
    (tmp_path / "T.php").write_text(
        "<?php\nreturn fopen('php://input', 'rb');\n", encoding="utf-8"
    )
    assert PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_file_inclusion_flags_phar_wrapper(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\n$x = new DirectoryIterator('phar://x.phar');\n", encoding="utf-8"
    )
    findings = PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-file-inclusion/dangerous-stream-wrapper"


def test_php_file_inclusion_flags_expect_wrapper(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\n$x = fopen('expect://ls', 'r');\n", encoding="utf-8"
    )
    findings = PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-file-inclusion/dangerous-stream-wrapper"


def test_php_file_inclusion_flags_both_rules_independently_on_one_line(tmp_path: Path) -> None:
    # Tainted include AND a dangerous wrapper string on the same line fire both rules.
    (tmp_path / "T.php").write_text(
        "<?php\ninclude($_GET['p'] . 'php://filter/resource=x');\n", encoding="utf-8"
    )
    findings = PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path))
    rules = sorted(f.rule for f in findings)
    assert rules == [
        "php-file-inclusion/dangerous-stream-wrapper",
        "php-file-inclusion/tainted-include",
    ]


def test_php_file_inclusion_silent_on_all_literal_include(tmp_path: Path) -> None:
    # FP-bait: a fixed string literal path, no variable/superglobal involved.
    (tmp_path / "T.php").write_text("<?php\ninclude('config.php');\n", encoding="utf-8")
    assert PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_file_inclusion_silent_on_all_literal_require_once(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nrequire_once('vendor/autoload.php');\n", encoding="utf-8"
    )
    assert PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_file_inclusion_pragma_silences_tainted_include(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { include($_GET['page']); "
        "// security: allow-php-file-inclusion\n}\n",
        encoding="utf-8",
    )
    assert PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_file_inclusion_pragma_silences_stream_wrapper(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\n$x = file_get_contents('php://filter/resource=x'); "
        "// security: allow-php-file-inclusion\n",
        encoding="utf-8",
    )
    assert PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_file_inclusion_silent_in_slash_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire, for either sub-pattern.
    (tmp_path / "T.php").write_text(
        "<?php\n// include($_GET['page']); example only, and php://filter too\nreal();\n",
        encoding="utf-8",
    )
    assert PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_file_inclusion_silent_in_hash_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `#` comment must not fire, for either sub-pattern.
    (tmp_path / "T.php").write_text(
        "<?php\n# include($_GET['page']); and php://input are both examples here\nreal();\n",
        encoding="utf-8",
    )
    assert PhpFileInclusionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_file_inclusion_not_applicable_without_php() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert PhpFileInclusionGuard().applies(prof) is False
