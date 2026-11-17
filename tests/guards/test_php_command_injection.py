from __future__ import annotations

from agentsec.guards.php_command_injection import PhpCommandInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_php_command_injection_flags_system_with_superglobal(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { system($_GET['host']); }\n", encoding="utf-8"
    )
    findings = PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-command-injection/tainted-shell-sink"
    assert findings[0].severity == "critical"


def test_php_command_injection_flags_exec_with_variable(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($cmd) { exec($cmd); }\n", encoding="utf-8"
    )
    findings = PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_command_injection_flags_shell_exec_with_post_superglobal(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { shell_exec($_POST['cmd']); }\n", encoding="utf-8"
    )
    findings = PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_command_injection_flags_proc_open_with_variable(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($cmd) { proc_open($cmd, $desc, $pipes); }\n", encoding="utf-8"
    )
    findings = PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_command_injection_flags_passthru_with_concatenation(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($host) { passthru('ping ' . $host); }\n", encoding="utf-8"
    )
    findings = PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_command_injection_flags_popen_with_function_call_result(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { popen(getUserCmd(), 'r'); }\n", encoding="utf-8"
    )
    findings = PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_command_injection_flags_interpolated_double_quoted_string(tmp_path: Path) -> None:
    # A double-quoted PHP string interpolates variables ("ping $host" != a fixed literal) —
    # exactly as tainted as passing $host directly.
    (tmp_path / "T.php").write_text(
        '<?php\nfunction f($host) { system("ping $host"); }\n', encoding="utf-8"
    )
    findings = PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1


def test_php_command_injection_silent_on_sink_name_inside_message_string(tmp_path: Path) -> None:
    # FP-bait (#848 corpus scan, matomo-org/matomo core/CliMulti/Process.php:240): a diagnostic
    # message DESCRIBING a shell_exec call, built by concatenating the literal text 'shell_exec('
    # into a string, is not an actual call site -- the sink name here is quoted string data.
    (tmp_path / "T.php").write_text(
        "<?php\n"
        "class P {\n"
        "    const PS_COMMAND = 'ps aux';\n"
        "    public static function reason() {\n"
        "        $reasons = [];\n"
        "        $reasons[] = 'shell_exec(' . self::PS_COMMAND . '\" 2> /dev/null\") did not return"
        " a success code';\n"
        "        return $reasons;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    assert PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_command_injection_flags_real_call_alongside_message_string(tmp_path: Path) -> None:
    # The direction traded against (CLAUDE.md Rule 1): a REAL shell_exec() call with a dynamic
    # argument, on its own line, must still fire -- confirms the string-literal check above
    # doesn't blind the guard to a genuine call.
    (tmp_path / "T.php").write_text(
        "<?php\n"
        "class P {\n"
        "    const AWK_COMMAND = \"awk '{print $1}'\";\n"
        "    public static function run() {\n"
        "        return @shell_exec('echo \" 537 \" | ' . self::AWK_COMMAND . ' 2>/dev/null');\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-command-injection/tainted-shell-sink"


def test_php_command_injection_still_fires_after_heredoc_with_odd_quote_count(tmp_path: Path) -> None:
    # PR #884 review regression (Dean's exact repro, same class as php_code_injection's sibling
    # test): a heredoc body containing an odd number of quote characters used to desync the
    # cross-line open_quote tracker and silently swallow every later real sink in the file.
    # strip_php_heredocs blanks the body before quote tracking ever sees it.
    (tmp_path / "T.php").write_text(
        "<?php\n"
        "function run($target) {\n"
        "    $msg = <<<EOT\n"
        "This isn't escaped, it is heredoc content.\n"
        "EOT;\n"
        "    shell_exec($target);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-command-injection/tainted-shell-sink"


def test_php_command_injection_still_fires_after_heredoc_with_control_char_body(
    tmp_path: Path,
) -> None:
    # PR #884 review (reproduced): a heredoc BODY containing a str.splitlines() boundary char that is
    # not \n/\r (here a form-feed) used to desync raw_lines vs code_lines, so zip(strict=True) raised
    # ValueError and the guard's run() aborted -- disabling the WHOLE guard on the repo and silently
    # losing the real system() sink after the heredoc. The base helper now preserves the boundary
    # char, so the sink must still fire (the direction traded against, CLAUDE.md Rule 1).
    (tmp_path / "T.php").write_text(
        "<?php\n"
        "function run() {\n"
        "    $doc = <<<EOT\n"
        "page one\x0cpage two\n"
        "EOT;\n"
        "    system($_GET['host']);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "php-command-injection/tainted-shell-sink"


def test_php_command_injection_silent_on_all_literal_single_quoted(tmp_path: Path) -> None:
    # FP-bait: a fixed single-quoted command string must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f() { system('ls -la'); }\n", encoding="utf-8"
    )
    assert PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_command_injection_silent_on_all_literal_double_quoted(tmp_path: Path) -> None:
    # FP-bait: a fixed double-quoted command string with no interpolation must not fire.
    (tmp_path / "T.php").write_text(
        '<?php\nfunction f() { system("ls -la"); }\n', encoding="utf-8"
    )
    assert PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_command_injection_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.php").write_text(
        "<?php\nfunction f($cmd) { exec($cmd); // security: allow-php-shell-exec\n}\n",
        encoding="utf-8",
    )
    assert PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_command_injection_silent_in_slash_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\n// exec($cmd); example only\nreal();\n", encoding="utf-8"
    )
    assert PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_command_injection_silent_in_hash_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `#` comment must not fire.
    (tmp_path / "T.php").write_text(
        "<?php\n# system($_GET['host']); is an example, do not use\nreal();\n", encoding="utf-8"
    )
    assert PhpCommandInjectionGuard().run(tmp_path, _phpprof(tmp_path)) == []


def test_php_command_injection_not_applicable_without_php() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert PhpCommandInjectionGuard().applies(prof) is False
