from __future__ import annotations

import pytest

from agentsec.guards.command_injection import CommandInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_command_injection_flags_os_system_fstring(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import os\n"
        "def ping(host):\n"
        '    os.system(f"ping {host}")\n', encoding="utf-8"
    )
    findings = CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "command-injection/shell-exec-untrusted"
    assert findings[0].severity == "critical"

def test_command_injection_flags_concat_and_subprocess_shell(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("import os\ndef r(p):\n    os.popen('cat ' + p)\n", encoding="utf-8")
    (tmp_path / "b.py").write_text(
        "import subprocess\ndef r(cmd):\n    subprocess.run(cmd, shell=True)\n", encoding="utf-8"
    )
    assert len(CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path))) == 2

def test_command_injection_passes_static_literal(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text('import os\nos.system("ls -la /tmp")\n', encoding="utf-8")
    assert CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_command_injection_passes_array_form_subprocess(tmp_path: Path) -> None:
    # array form, no shell -> safe even with a variable
    (tmp_path / "t.py").write_text(
        "import subprocess\ndef ping(host):\n    subprocess.run(['ping', host])\n", encoding="utf-8"
    )
    assert CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_command_injection_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import os\ndef ping(host):\n"
        '    os.system(f"ping {host}")  # security: allow-shell-exec\n', encoding="utf-8"
    )
    assert CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_command_injection_silent_on_docstring_example(tmp_path: Path) -> None:
    # FP-bait (#424): an `os.system(f"ping {host}")` EXAMPLE inside a docstring must not fire
    # (this guard's own module docstring self-matched on it).
    (tmp_path / "t.py").write_text(
        '"""Dangerous shell sink:\n'
        "\n"
        '    os.system(f"ping {host}")\n'
        '"""\n'
        "import os\n",
        encoding="utf-8",
    )
    assert CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_command_injection_skips_nonproduct_path(tmp_path: Path) -> None:
    # #424: a shell-injection sink under a tests/ tree is a fixture, not a product finding
    # (mirrors sibling code_injection_eval_exec's is_nonproduct_path skip).
    d = tmp_path / "tests"
    d.mkdir()
    (d / "t.py").write_text(
        "import os\ndef ping(host):\n"
        '    os.system(f"ping {host}")\n',
        encoding="utf-8",
    )
    assert CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_command_injection_not_applicable_without_python() -> None:
    prof = mkprofile(Path("/tmp"), features={"frontend"})
    assert CommandInjectionGuard().applies(prof) is False



def test_command_injection_flags_triple_quoted_fstring(tmp_path: Path) -> None:
    # Regression (#439 review, release-blocking): `strip_python_strings` blanked a
    # triple-quoted node INCLUDING its delimiters and its `{…}` interpolations, so the
    # argument reaching `_is_dynamic` was empty whitespace and the CRITICAL rule never
    # fired. The single-line f-string form still fired, so the loss was specific to
    # triple quotes — invisible unless you tested that shape.
    (tmp_path / "t.py").write_text(
        "import os\n"
        "def backup(d):\n"
        '    os.system(f"""tar -czf b.tgz {d}""")\n',
        encoding="utf-8",
    )
    findings = CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "command-injection/shell-exec-untrusted"


def test_command_injection_silent_on_constant_triple_quoted_command(tmp_path: Path) -> None:
    # FP-bait for the above: keeping the delimiters must not make a CONSTANT command look
    # dynamic. No interpolation, so nothing untrusted reaches the shell.
    (tmp_path / "t.py").write_text(
        'import os\nos.system("""tar -czf b.tgz /srv/data""")\n', encoding="utf-8"
    )
    assert CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_command_injection_docstring_example_stays_silent_after_delimiter_fix(tmp_path: Path) -> None:
    # FP-bait: triple-quoted docstring CONTENT is still blanked, so an anti-pattern shown
    # in prose does not fire. This is the property the delimiter-blanking was protecting;
    # it must survive the fix.
    (tmp_path / "t.py").write_text(
        'def f(x):\n    """Never write os.system(f"rm {x}") in real code."""\n    return x\n',
        encoding="utf-8",
    )
    assert CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_command_injection_flags_shell_named_variable(tmp_path: Path) -> None:
    # Regression (#422): a command variable named *shell* must still register as dynamic. The
    # bare `split("shell")` cut at the variable's own name and tested an empty command portion.
    (tmp_path / "t.py").write_text(
        "import subprocess\n"
        "def r(user):\n"
        "    shell_cmd = 'ping ' + user\n"
        "    subprocess.run(shell_cmd, shell=True)\n", encoding="utf-8"
    )
    findings = CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "command-injection/shell-exec-untrusted"

def test_command_injection_literal_with_shell_in_name_silent(tmp_path: Path) -> None:
    # FP-bait for the widened split: a static literal containing "shell" stays silent.
    (tmp_path / "t.py").write_text(
        'import subprocess\nsubprocess.run("nushell --version", shell=True)\n', encoding="utf-8"
    )
    assert CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []


@pytest.mark.parametrize(
    "call",
    [
        'subprocess.run("shell=" + t, shell=True)',
        "subprocess.run('shell=' + t, shell=True)",
        'subprocess.run("shell=%s" % t, shell=True)',
        'subprocess.run("shell= {}".format(t), shell=True)',
        r'subprocess.run("a\" shell=" + t, shell=True)',
        'subprocess.run("usermod --shell=/bin/zsh " + t, shell=True)',
        'subprocess.check_output("docker exec --env shell=bash " + t, shell=True)',
    ],
)
def test_command_injection_flags_shell_kw_inside_command_literal(tmp_path: Path, call: str) -> None:
    # Regression (#589): a `shell=` INSIDE the command literal must not win the split ahead of the
    # real keyword argument. The textual split cut the command to `"usermod --`, dropping the
    # `+ t` tail, so a dynamic shell command read as a static literal and the CRITICAL went unreported.
    (tmp_path / "t.py").write_text(f"import subprocess\ndef r(t):\n    {call}\n", encoding="utf-8")
    findings = CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["command-injection/shell-exec-untrusted"]


@pytest.mark.parametrize(
    "call",
    [
        'subprocess.run("env shell=bash ls", shell=True)',
        'subprocess.run("echo shell=True", shell=True)',
    ],
)
def test_command_injection_static_literal_containing_shell_kw_silent(tmp_path: Path, call: str) -> None:
    # FP-bait for #589's widening: once the split lands on the real kwarg, the whole literal reaches
    # `_is_dynamic`. A fully static literal that happens to contain `shell=` must stay silent.
    (tmp_path / "t.py").write_text(f"import subprocess\n{call}\n", encoding="utf-8")
    assert CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []


@pytest.mark.parametrize(
    "call",
    [
        'subprocess.run(cmd, shell=True, env={"X": "shell=1"})',
        'subprocess.run(cmd, shell=True, input="shell=True")',
    ],
)
def test_command_injection_shell_kw_in_later_literal_still_fires(tmp_path: Path, call: str) -> None:
    # Pin against the "split at the LAST shell=" alternative (#589): a `shell=` inside a literal
    # AFTER the real kwarg would win that split, drag `shell=True, ...="` into the command portion,
    # and silence a bare-variable command. Both fire today and must keep firing.
    (tmp_path / "t.py").write_text(f"import subprocess\ndef r(cmd):\n    {call}\n", encoding="utf-8")
    findings = CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["command-injection/shell-exec-untrusted"]


@pytest.mark.parametrize(
    "call",
    [
        'subprocess.run(cmd + " --flag shell=True")',
        'subprocess.run("x shell=True" + t, shell=False)',
    ],
)
def test_command_injection_shell_true_only_inside_literal_silent(tmp_path: Path, call: str) -> None:
    # Narrowing (#589): the `shell=True` gate counts only a real keyword argument. Text inside a
    # string literal does not enable the check; with no `shell=True` kwarg, subprocess runs no shell.
    (tmp_path / "t.py").write_text(f"import subprocess\ndef r(cmd, t):\n    {call}\n", encoding="utf-8")
    assert CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_command_injection_concat_with_real_shell_kwarg_still_fires(tmp_path: Path) -> None:
    # Still-fires pair for the narrowing above (CLAUDE.md Rule 1): the same concatenated command
    # with a REAL `shell=True` kwarg is the vulnerable case and must still fire.
    (tmp_path / "t.py").write_text(
        'import subprocess\ndef r(cmd):\n    subprocess.run(cmd + " --flag", shell=True)\n',
        encoding="utf-8",
    )
    findings = CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["command-injection/shell-exec-untrusted"]


def _shell_call_rules(tmp_path: Path, call: str) -> list[str]:
    (tmp_path / "t.py").write_text(
        f"import os, subprocess\ndef r(self, cmd, t):\n    {call}\n", encoding="utf-8"
    )
    return [f.rule for f in CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path))]


@pytest.mark.parametrize(
    "call",
    [
        # #971: a string-literal kwarg ahead of `shell=` made a bare-variable command read static.
        'subprocess.run(cmd, cwd="/tmp", shell=True)',
        'subprocess.check_output(cmd, stderr=subprocess.STDOUT, encoding="utf-8", shell=True)',
        'subprocess.run(cmd, executable="/bin/bash", shell=True)',
        'subprocess.Popen(cmd, env={"A": "1"}, shell=True)',
        'subprocess.run(self.cmd, cwd="/srv", shell=True)',
        'subprocess.run(build(cmd), cwd="/srv", shell=True)',
        'out = subprocess.run(cmd, cwd="/x", shell=True).stdout',
        'subprocess.run(cmd, cwd="/tmp", shell=True,\n        check=True)',
        # #972: `shell=True` passed first, or the command passed as `args=`.
        'subprocess.run(shell=True, args="echo " + t)',
        "subprocess.Popen(shell=True, args=cmd)",
        'subprocess.run(args=cmd, cwd="/tmp", shell=True)',
        # `{}` depth: a paren-only splitter reads the dict's inner comma as a boundary and judges
        # the fake positional `"B": t}`, which carries a literal, so the call stays silent.
        'subprocess.run(shell=True, env={"A": "1", "B": t}, args=cmd)',
        # Always-shell sinks: a later literal argument, or literal code after the call on the line.
        'p = os.popen(cmd, "r")',
        'p = os.popen(cmd, mode="r")',
        'out = subprocess.getoutput(cmd, encoding="utf-8")',
        'if os.system(cmd) != 0: raise RuntimeError("failed")',
        'os.system(cmd) or log("failed")',
        'rc = os.system(cmd); print("done")',
    ],
)
def test_command_injection_judges_command_arg_despite_neighbouring_literal(
    tmp_path: Path, call: str
) -> None:
    # Widening (#971, #972): only the command argument is judged (the first positional, else
    # `args=`). The whole span before `shell=`, or the whole line tail on an always-shell sink, let
    # an unrelated literal hide a bare-variable command. Each of these was silent on main.
    assert _shell_call_rules(tmp_path, call) == ["command-injection/shell-exec-untrusted"]


@pytest.mark.parametrize(
    "call",
    [
        'subprocess.run("ls -la", cwd=workdir, shell=True)',
        'subprocess.run("ls -la", cwd="/tmp", shell=True)',
        'subprocess.run(shell=True, args="ls -la")',
        'if os.system("ls -la") != 0: raise err',
    ],
)
def test_command_injection_static_command_beside_other_args_silent(tmp_path: Path, call: str) -> None:
    # FP-bait for the widening above: a static literal command stays silent whatever its neighbours
    # are. The first case pins the positional-vs-keyword split: judging `cwd=workdir` instead of the
    # command would fire on the bare `workdir`.
    assert _shell_call_rules(tmp_path, call) == []


@pytest.mark.parametrize(
    "call",
    [
        'os.system("make build"); msg = prefix + "done"',
        'os.system("make build") or log(f"failed {rc}")',
        'subprocess.run("make", cwd=base + "/x", shell=True)',
        'subprocess.run("make", cwd=f"{base}/x", shell=True)',
        'subprocess.run("make", env={"P": "%s" % p}, shell=True)',
    ],
)
def test_command_injection_dynamic_neighbour_of_static_command_silent(tmp_path: Path, call: str) -> None:
    # Narrowing (#971): dynamic text in ANOTHER argument, or in code after the call, no longer makes
    # a static command read as dynamic. Each of these was a false CRITICAL on main.
    assert _shell_call_rules(tmp_path, call) == []


@pytest.mark.parametrize(
    "call",
    [
        'subprocess.run("make " + t, cwd=base + "/x", shell=True)',
        'os.system("make " + t); msg = prefix + "done"',
        # The command reachable only through a `**mapping` unpack is judged as that variable.
        "subprocess.run(**opts, shell=True)",
    ],
)
def test_command_injection_dynamic_command_beside_dynamic_neighbour_still_fires(
    tmp_path: Path, call: str
) -> None:
    # Still-fires pair for the narrowing above (CLAUDE.md Rule 1): the same calls with a dynamic
    # COMMAND keep firing.
    assert _shell_call_rules(tmp_path, call) == ["command-injection/shell-exec-untrusted"]


@pytest.mark.parametrize(
    "call",
    [
        'subprocess.run("%s %s" % (cmd, t), cwd="/x", shell=True)',
        'subprocess.run("a, b" + t, cwd="/x", shell=True)',
    ],
)
def test_command_injection_comma_inside_command_is_not_an_argument_boundary(
    tmp_path: Path, call: str
) -> None:
    # A comma inside the command's own literal or nested tuple is content, not a separator. A
    # literal-unaware or depth-unaware split would cut these to a static fragment and go silent.
    assert _shell_call_rules(tmp_path, call) == ["command-injection/shell-exec-untrusted"]


def test_command_injection_flags_argv_interpreter_with_dynamic_code(tmp_path: Path) -> None:
    # (llm-seclint's LlmShellInjectionRule): no shell=True and not an always-shell sink,
    # but the argv list's own first element re-invokes an interpreter with a dynamic argument.
    (tmp_path / "t.py").write_text(
        "import subprocess\n"
        "def run_snippet(code):\n"
        '    subprocess.run(["python3", "-c", code])\n', encoding="utf-8"
    )
    findings = CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "command-injection/argv-interpreter-untrusted"
    assert findings[0].severity == "critical"


def test_command_injection_argv_interpreter_bash_dash_c_variable(tmp_path: Path) -> None:
    # Same shape, a different interpreter/flag pairing, to confirm the check isn't overfit to
    # python3/-c specifically.
    (tmp_path / "t.py").write_text(
        "import subprocess\n"
        "def run(user_cmd):\n"
        '    subprocess.Popen(["bash", "-c", user_cmd])\n', encoding="utf-8"
    )
    findings = CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "command-injection/argv-interpreter-untrusted"


def test_command_injection_argv_interpreter_static_code_silent(tmp_path: Path) -> None:
    # FP-bait: the interpreter's own argument is a plain string literal, not attacker-controlled
    # — the array form recommended elsewhere in this guard's docstring must not itself fire.
    (tmp_path / "t.py").write_text(
        "import subprocess\n"
        "def run():\n"
        '    subprocess.run(["python3", "-c", "print(\'static\')"])\n', encoding="utf-8"
    )
    assert CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_command_injection_argv_form_without_code_flag_silent(tmp_path: Path) -> None:
    # FP-bait: an interpreter named in the array without a -c/-e/--eval flag is an ordinary
    # script invocation (`python3 script.py`), not a code-injection sink.
    (tmp_path / "t.py").write_text(
        "import subprocess\n"
        "def run(path):\n"
        '    subprocess.run(["python3", path])\n', encoding="utf-8"
    )
    assert CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_command_injection_argv_static_code_with_comma_silent(tmp_path: Path) -> None:
    # FP-bait (Dean's review repro): the interpreter's own static payload contains a
    # comma of its own (`print(1, 2)`). A quote-unaware split(",") used to fracture this literal
    # into two pieces, so the fractured last fragment no longer matched as a whole string and the
    # guard read a fully static call as dynamic -> a CRITICAL false positive on code with no
    # attacker-reachable input at all.
    (tmp_path / "t.py").write_text(
        "import subprocess\n"
        "def run():\n"
        '    subprocess.run(["python3", "-c", "print(1, 2)"])\n', encoding="utf-8"
    )
    assert CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_command_injection_argv_dynamic_code_with_comma_in_earlier_literal_still_fires(
    tmp_path: Path,
) -> None:
    # Still-fires (CLAUDE.md Rule 1 — the narrowing must not blind the guard to a comma-bearing
    # literal EARLIER in the list): a static literal ahead of the trailing argument carries its
    # own comma, and the trailing argument is still a bare variable, so this must still fire.
    (tmp_path / "t.py").write_text(
        "import subprocess\n"
        "def run(code):\n"
        '    subprocess.run(["python3", "-c", "note, with comma", code])\n', encoding="utf-8"
    )
    findings = CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "command-injection/argv-interpreter-untrusted"


def test_command_injection_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the flagged line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-shell-exec"):
        (tmp_path / "t.py").write_text(
            "import os\ndef ping(host):\n"
            f'    os.system(f"ping {{host}}"); _note = "{note}"\n', encoding="utf-8"
        )
        findings = CommandInjectionGuard().run(tmp_path, _pyprof(tmp_path))
        assert [f.rule for f in findings] == ["command-injection/shell-exec-untrusted"], note
