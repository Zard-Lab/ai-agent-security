from __future__ import annotations

from agentsec.guards.php_tls_verify_disabled import PhpTlsVerifyDisabledGuard
from tests.guards._common import *  # noqa: F401,F403


def test_php_tls_verify_disabled_flags_verifyhost_false(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($ch) { curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); }\n",
        encoding="utf-8",
    )
    findings = PhpTlsVerifyDisabledGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-tls-verify-disabled/curl-ssl-verify-disabled"
    assert findings[0].severity == "high"


def test_php_tls_verify_disabled_flags_verifypeer_zero(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($ch) { curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0); }\n",
        encoding="utf-8",
    )
    findings = PhpTlsVerifyDisabledGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-tls-verify-disabled/curl-ssl-verify-disabled"


def test_php_tls_verify_disabled_flags_null(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($ch) { curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, null); }\n",
        encoding="utf-8",
    )
    findings = PhpTlsVerifyDisabledGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_tls_verify_disabled_flags_array_form(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($ch) { curl_setopt_array($ch, ["
        "CURLOPT_SSL_VERIFYPEER => false,\n"
        "CURLOPT_SSL_VERIFYHOST => 0,\n"
        "]); }\n",
        encoding="utf-8",
    )
    findings = PhpTlsVerifyDisabledGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 2


def test_php_tls_verify_disabled_silent_on_verifyhost_strict_value(tmp_path: Path) -> None:
    # FP-bait: CURLOPT_SSL_VERIFYHOST => 2 is the correct/strict value, must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($ch) { curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2); }\n",
        encoding="utf-8",
    )
    assert PhpTlsVerifyDisabledGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_tls_verify_disabled_silent_on_verifypeer_true(tmp_path: Path) -> None:
    # FP-bait: CURLOPT_SSL_VERIFYPEER => true is the secure default, must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($ch) { curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true); }\n",
        encoding="utf-8",
    )
    assert PhpTlsVerifyDisabledGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_tls_verify_disabled_silent_on_unrelated_zero_option(tmp_path: Path) -> None:
    # FP-bait: an unrelated curl option set to 0 must not fire on the digit alone.
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($ch) { curl_setopt($ch, CURLOPT_TIMEOUT, 0); }\n",
        encoding="utf-8",
    )
    assert PhpTlsVerifyDisabledGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_tls_verify_disabled_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($ch) { curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); "
        "// security: allow-php-tls-verify-disabled\n}\n",
        encoding="utf-8",
    )
    assert PhpTlsVerifyDisabledGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_tls_verify_disabled_silent_in_double_slash_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\n// curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); example only\nreal();\n",
        encoding="utf-8",
    )
    assert PhpTlsVerifyDisabledGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_tls_verify_disabled_silent_in_hash_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a real `#` line comment must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\n# curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0); is an example, do not use\nreal();\n",
        encoding="utf-8",
    )
    assert PhpTlsVerifyDisabledGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_tls_verify_disabled_not_applicable_without_php() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert PhpTlsVerifyDisabledGuard().applies(prof) is False
