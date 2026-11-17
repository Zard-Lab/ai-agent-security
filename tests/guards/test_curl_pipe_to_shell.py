"""Tests for the curl-pipe-to-shell guard.

Covers:
  - curl-pipe-to-shell/unverified-pipe (MEDIUM)
  - curl-pipe-to-shell/python-subprocess-literal (MEDIUM)
"""
from __future__ import annotations

from agentsec.guards.curl_pipe_to_shell import CurlPipeToShellGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_curl_piped_to_bash_in_dockerfile(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "RUN curl https://get.example.com/install.sh | bash\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = CurlPipeToShellGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "curl-pipe-to-shell/unverified-pipe"
    assert findings[0].severity == "medium"


def test_fires_on_wget_piped_to_sh_in_shell_script(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text(
        "#!/bin/bash\n"
        "wget -qO- https://example.com/install.sh | sh\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    findings = CurlPipeToShellGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "curl-pipe-to-shell/unverified-pipe"


def test_fires_on_dockerfile_line_continuation(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "RUN curl -fsSL https://x.io/install.sh \\\n"
        "    | bash\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"})
    findings = CurlPipeToShellGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_silent_on_download_only_no_pipe(tmp_path: Path) -> None:
    (tmp_path / "download.sh").write_text(
        "curl -o /tmp/install.sh https://example.com/install.sh\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert CurlPipeToShellGuard().run(tmp_path, profile) == []


def test_silent_on_commented_out_example(tmp_path: Path) -> None:
    (tmp_path / "note.sh").write_text(
        "# curl ... | bash  (do not do this)\n"
        "echo hello\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert CurlPipeToShellGuard().run(tmp_path, profile) == []


def test_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text(
        "curl -fsSL https://get.example.com/install.sh | bash  # security: allow-curl-pipe-shell\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert CurlPipeToShellGuard().run(tmp_path, profile) == []


def test_dockerfile_not_scanned_without_docker_feature(tmp_path: Path) -> None:
    # A Dockerfile physically present but "docker" not in profile.features (an edge case
    # that shouldn't occur via real detection, since has_docker always sets the feature)
    # stays unscanned for the Dockerfile scope — only the unconditional .sh scope runs.
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "RUN curl -fsSL https://get.example.com/install.sh | bash\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert CurlPipeToShellGuard().run(tmp_path, profile) == []


def test_silent_on_or_fallback_idiom(tmp_path: Path) -> None:
    # Regression (H1): `curl -f url || bash restart.sh` is an OR-fallback (run bash only if
    # curl FAILS), not a pipe-to-shell. A single-pipe match `(?<!\|)\|(?!\|)` must not fire on `||`.
    (tmp_path / "healthcheck.sh").write_text(
        "curl -f http://localhost/health || bash restart.sh\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert CurlPipeToShellGuard().run(tmp_path, profile) == []


def test_silent_on_curl_as_argument_not_command(tmp_path: Path) -> None:
    # Regression (M1): `curl` appearing as an ARGUMENT to another command (not in command
    # position) must not fire — the pipe-to-sh here belongs to grep/cat, not curl.
    (tmp_path / "search.sh").write_text(
        "grep curl file.txt | sh\n"
        "cat curl-notes.txt | sh\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert CurlPipeToShellGuard().run(tmp_path, profile) == []


def test_fires_on_curl_after_shell_separator(tmp_path: Path) -> None:
    # curl in command position after `&&` is still a real pipe-to-shell.
    (tmp_path / "setup.sh").write_text(
        "set -e && curl -fsSL https://get.example.com/i.sh | bash\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert len(CurlPipeToShellGuard().run(tmp_path, profile)) == 1


def test_fires_on_multi_stage_download_filter_execute(tmp_path: Path) -> None:
    # A multi-stage pipe (download, filter, execute) is a real curl-pipe-to-shell and must
    # still fire — the single-pipe fix must not regress the intermediate-pipe true positive.
    (tmp_path / "install.sh").write_text(
        "curl -fsSL https://get.example.com/i.sh | grep -v '#' | bash\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert len(CurlPipeToShellGuard().run(tmp_path, profile)) == 1


def test_fires_on_bash_extension_shell_script(tmp_path: Path) -> None:
    # Regression (M2): a `.bash` script is scanned too (matches the sibling
    # untrusted_package_install_source guard's `.sh`/`.bash` scope and this guard's docstring).
    (tmp_path / "setup.bash").write_text(
        "curl -fsSL https://get.example.com/install.sh | bash\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert len(CurlPipeToShellGuard().run(tmp_path, profile)) == 1


def test_applies_gate_is_universal() -> None:
    # applies() is always True: the .sh scope is unconditional, so the guard is always
    # relevant regardless of detected stack (see the module docstring for why the
    # docker-vs-.sh gating split can't live in applies() itself).
    assert CurlPipeToShellGuard().applies(mkprofile(Path("/tmp"), features=set())) is True
    assert CurlPipeToShellGuard().applies(mkprofile(Path("/tmp"), features={"docker"})) is True


# A line past 1 KB used to keep its `#` comment (the quote mask stopped there, #508), so a pipe
# that appears only in that comment fired.
_LONG_NOTE = "see the runbook for the manual install " * 28  # ~1.1 KB, no `#`, no quotes


def test_silent_on_pipe_only_in_long_line_comment(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text(
        f"echo done  # {_LONG_NOTE}; curl https://get.example.com/install.sh | bash\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert CurlPipeToShellGuard().run(tmp_path, profile) == []


def test_fires_on_long_line_real_pipe_with_comment_and_quoted_hash(tmp_path: Path) -> None:
    # The direction that narrowing traded against: a real pipe still fires with a long comment
    # after it, and a `#` inside a quoted header is value, so it does not clip the pipe.
    (tmp_path / "install.sh").write_text(
        'curl -H "X-Build: nightly #42" https://get.example.com/install.sh | bash'
        f"  # {_LONG_NOTE}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert len(CurlPipeToShellGuard().run(tmp_path, profile)) == 1


# --- python-subprocess-literal -----------------------------------------------------


def test_fires_on_subprocess_run_with_curl_pipe_shell_string(tmp_path: Path) -> None:
    (tmp_path / "bootstrap.py").write_text(
        'subprocess.run("curl https://get.example.com/install.sh | bash", shell=True)\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = CurlPipeToShellGuard().run(tmp_path, profile)
    assert [(f.rule, f.severity) for f in findings] == [
        ("curl-pipe-to-shell/python-subprocess-literal", "medium")
    ]


def test_fires_on_os_system_with_wget_pipe_sh_string(tmp_path: Path) -> None:
    (tmp_path / "bootstrap.py").write_text(
        "os.system('wget -qO- https://example.com/i.sh | sh')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    findings = CurlPipeToShellGuard().run(tmp_path, profile)
    assert [f.rule for f in findings] == ["curl-pipe-to-shell/python-subprocess-literal"]


def test_python_scan_not_run_without_python_feature(tmp_path: Path) -> None:
    (tmp_path / "bootstrap.py").write_text(
        'subprocess.run("curl https://get.example.com/install.sh | bash", shell=True)\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features=set())
    assert CurlPipeToShellGuard().run(tmp_path, profile) == []


def test_silent_on_argv_list_form_no_literal_pipe(tmp_path: Path) -> None:
    # FP bait: the array/argv form never builds a shell string at all -- no pipe literal exists
    # to match, regardless of shell=True/False.
    (tmp_path / "bootstrap.py").write_text(
        'subprocess.run(["curl", "-fsSL", "https://example.com/i.sh"])\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert CurlPipeToShellGuard().run(tmp_path, profile) == []


def test_silent_on_curl_as_argument_not_command_inside_sink_string(tmp_path: Path) -> None:
    # FP bait, the exact class the guard's own H1 fix removed for the .sh scope: `curl` as an
    # ARGUMENT to grep, not in command position, must not fire even inside a sink call's string.
    (tmp_path / "search.py").write_text(
        'subprocess.run("grep curl file.txt | bash", shell=True)\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert CurlPipeToShellGuard().run(tmp_path, profile) == []


def test_silent_on_commented_out_sink_call_example(tmp_path: Path) -> None:
    (tmp_path / "notes.py").write_text(
        '# subprocess.run("curl https://x/y | bash", shell=True)  # never do this\n'
        "pass\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert CurlPipeToShellGuard().run(tmp_path, profile) == []


def test_pragma_silences_python_scope(tmp_path: Path) -> None:
    (tmp_path / "bootstrap.py").write_text(
        'subprocess.run("curl https://get.example.com/install.sh | bash", shell=True)'
        "  # security: allow-curl-pipe-shell\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"})
    assert CurlPipeToShellGuard().run(tmp_path, profile) == []
