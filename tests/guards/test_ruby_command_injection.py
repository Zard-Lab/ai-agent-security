from __future__ import annotations

from agentsec.guards.ruby_command_injection import RubyCommandInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_ruby_command_injection_flags_interpolated_system(tmp_path: Path) -> None:
    # The canary-plant shape.
    (tmp_path / "deploy.rb").write_text(
        'def restart(service)\n  system("systemctl restart #{service}")\nend\n',
        encoding="utf-8",
    )
    findings = RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ruby-command-injection/shell-exec-untrusted"
    assert findings[0].severity == "critical"


def test_ruby_command_injection_flags_parenless_system(tmp_path: Path) -> None:
    # Idiomatic Ruby: `system "..."` without parentheses.
    (tmp_path / "t.rb").write_text('system "rake db:migrate RAILS_ENV=#{env}"\n', encoding="utf-8")
    assert len(RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_command_injection_flags_concatenated_exec(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text('exec("git clone " + repo_url)\n', encoding="utf-8")
    assert len(RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_command_injection_flags_concat_with_literal_on_the_right(tmp_path: Path) -> None:
    # `cmd + " --depth 1"` — the literal is not the FIRST token of the argument. An earlier
    # draft required a leading quote and missed this entirely (caught by the self-test).
    (tmp_path / "t.rb").write_text('system(clone_cmd + " --depth 1")\n', encoding="utf-8")
    assert len(RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_command_injection_flags_backtick_interpolation(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("head = `git rev-parse #{ref}`\n", encoding="utf-8")
    assert len(RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_command_injection_flags_percent_x_interpolation(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text("listing = %x{ls -la #{dir}}\n", encoding="utf-8")
    assert len(RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_command_injection_flags_io_popen_shell_string(tmp_path: Path) -> None:
    # IO.popen's second argument is a MODE, not an argv element — a dynamic first argument is
    # still a shell string here.
    (tmp_path / "t.rb").write_text(
        'IO.popen("ls #{dir}", "r") { |io| io.read }\n', encoding="utf-8"
    )
    assert len(RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_command_injection_flags_open3_shell_string(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        'stdout, _, _ = Open3.capture3("convert #{src} out.png")\n', encoding="utf-8"
    )
    assert len(RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path))) == 1


def test_ruby_command_injection_silent_on_argv_array_form(tmp_path: Path) -> None:
    # FP-bait / the fix: the argv ARRAY form bypasses the shell entirely (Ruby execs the
    # program directly), exactly like `subprocess.run([...])` without `shell=True`.
    (tmp_path / "t.rb").write_text("system([\"ping\", \"-c\", \"1\", host])\n", encoding="utf-8")
    assert RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_command_injection_silent_on_argv_multi_arg_form(tmp_path: Path) -> None:
    # FP-bait / the fix: multiple arguments is the other no-shell form.
    (tmp_path / "t.rb").write_text('Open3.capture3("git", "clone", url)\n', encoding="utf-8")
    assert RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_command_injection_silent_on_static_literal(tmp_path: Path) -> None:
    # FP-bait: a fully static command is not attacker-steerable.
    (tmp_path / "t.rb").write_text(
        'system("bundle install")\nrev = `git rev-parse HEAD`\n', encoding="utf-8"
    )
    assert RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_command_injection_silent_on_single_quoted_string(tmp_path: Path) -> None:
    # FP-bait: Ruby single quotes do not interpolate — `'#{x}'` is three literal characters.
    (tmp_path / "t.rb").write_text("system('echo #{literal}')\n", encoding="utf-8")
    assert RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_command_injection_silent_on_pg_connection_exec(tmp_path: Path) -> None:
    # FP-bait, the realistic collision: `PG::Connection#exec` is a database call, not
    # `Kernel#exec`. The receiver dot is what tells them apart.
    (tmp_path / "t.rb").write_text(
        'conn.exec("SELECT * FROM users WHERE id = #{id}")\n', encoding="utf-8"
    )
    assert RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_command_injection_silent_on_own_exec_definition(tmp_path: Path) -> None:
    # FP-bait: an application defining its own `exec(cmd)` method is not calling Kernel's.
    (tmp_path / "t.rb").write_text('def exec(cmd)\n  @runner.call(cmd)\nend\n', encoding="utf-8")
    assert RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_command_injection_silent_in_comment(tmp_path: Path) -> None:
    # FP-bait: a documented counter-example in a `#` comment must not fire — including the
    # backtick form, whose interpolation is matched on the RAW line.
    (tmp_path / "t.rb").write_text(
        '# never write system("rm -rf #{path}") here\n'
        "# nor `rm -rf #{path}` in a script\n"
        "real = 1\n",
        encoding="utf-8",
    )
    assert RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_command_injection_silent_in_begin_end_block_comment(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        '=begin\nsystem("rm -rf #{path}") is an example, do not use\n=end\nreal = 1\n',
        encoding="utf-8",
    )
    assert RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_command_injection_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "t.rb").write_text(
        'system("rake #{task}")  # security: allow-shell-exec\n', encoding="utf-8"
    )
    assert RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_command_injection_skips_spec_tree(tmp_path: Path) -> None:
    # A planted example under spec/ is not a product finding (same rule the Python sibling
    # applies to tests/fixtures, #424).
    (tmp_path / "spec").mkdir()
    (tmp_path / "spec" / "deploy_spec.rb").write_text(
        'system("rm -rf #{path}")\n', encoding="utf-8"
    )
    assert RubyCommandInjectionGuard().run(tmp_path, _rbprof(tmp_path)) == []


def test_ruby_command_injection_not_applicable_without_ruby() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert RubyCommandInjectionGuard().applies(prof) is False
