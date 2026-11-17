from __future__ import annotations

from agentsec.guards.php_preg_replace_eval_modifier import PhpPregReplaceEvalModifierGuard
from tests.guards._common import *  # noqa: F401,F403


def test_php_preg_replace_eval_modifier_flags_e_modifier(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($r, $s) { preg_replace('/(.*)/e', $r, $s); }\n", encoding="utf-8"
    )
    findings = PhpPregReplaceEvalModifierGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-preg-replace-eval-modifier/e-modifier-set"
    assert findings[0].severity == "critical"


def test_php_preg_replace_eval_modifier_flags_combined_modifiers(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($r, $s) { preg_replace('/(.*)/ie', $r, $s); }\n", encoding="utf-8"
    )
    findings = PhpPregReplaceEvalModifierGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_preg_replace_eval_modifier_flags_alternate_delimiters(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        '<?php\nfunction f($r, $s) { preg_replace("#(.*)#e", $r, $s); }\n', encoding="utf-8"
    )
    findings = PhpPregReplaceEvalModifierGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_preg_replace_eval_modifier_silent_without_e_modifier(tmp_path: Path) -> None:
    # FP-bait: no /e flag must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($r, $s) { preg_replace('/(.*)/i', $r, $s); }\n", encoding="utf-8"
    )
    assert PhpPregReplaceEvalModifierGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_preg_replace_eval_modifier_silent_on_preg_replace_callback(tmp_path: Path) -> None:
    # FP-bait: preg_replace_callback (the safe alternative) must not fire even with an 'e' in its
    # own arguments — the function-name boundary must not blur into a substring match.
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($cb, $s) { preg_replace_callback('/(.*)/e', $cb, $s); }\n",
        encoding="utf-8",
    )
    assert PhpPregReplaceEvalModifierGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_preg_replace_eval_modifier_silent_in_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\n// preg_replace('/(.*)/e', $r, $s); example only\nreal();\n", encoding="utf-8"
    )
    assert PhpPregReplaceEvalModifierGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_preg_replace_eval_modifier_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($r, $s) { preg_replace('/(.*)/e', $r, $s); "
        "// security: allow-preg-replace-e-modifier\n}\n",
        encoding="utf-8",
    )
    assert PhpPregReplaceEvalModifierGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_preg_replace_eval_modifier_not_applicable_without_php() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert PhpPregReplaceEvalModifierGuard().applies(prof) is False


def test_php_preg_replace_eval_modifier_ignores_hash_block_comment(tmp_path: Path) -> None:
    # FP-bait for the # line-comment handling in strip_php_comments: an example inside a real
    # # comment must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\n# preg_replace('/(.*)/e', $r, $s); is an example, do not use\nreal();\n",
        encoding="utf-8",
    )
    assert PhpPregReplaceEvalModifierGuard().run(tmp_path, _phpprof(tmp_path)) == []
