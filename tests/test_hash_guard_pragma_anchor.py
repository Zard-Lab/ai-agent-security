"""Cross-guard pins for #1040 T4: the shell, Dockerfile, workflow and host-config guards' suppress
pragma counts only as a real `#` comment, read from the comment view at the guard's own slice.

Both directions, per CLAUDE.md rule 1, against each guard's own violation line:

- widening (must FIRE): the pragma phrase inside a quoted string on the violation's own line, which
  the raw match read as an opt-out;
- must stay SILENT: a real comment on that line (rule 4: the converted check keeps every opt-out the
  raw one had);
- reach: a real comment on the line ABOVE does not reach a per-line guard (the conversion did not
  widen a line to the file), and still reaches a whole-file guard (it did not narrow the file to a line).

Then the slices the RCA flagged: a comment on a CONTINUATION line belongs to its logical line
(`curl-pipe-to-shell`, `docker-apt-update-not-alone` read the joined text), and a shell comment inside a
workflow `run: |` script is an opt-out (the `hash` view, where the `yaml` view would read the script
as scalar content and void it). `env-file-not-gitignored` reads its pragma from `.gitignore`, a file
the finding does not sit in, which the anchoring gate cannot place a string in.

Each case is measured against the same guard's plain violation (the control), so a violation that
stopped firing on its own fails as a broken control, not as a passing case.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from agentsec.guards.actions_script_injection import ActionsScriptInjectionGuard
from agentsec.guards.actions_sha_pin import ActionsShaPinGuard
from agentsec.guards.base import Guard
from agentsec.guards.curl_pipe_to_shell import CurlPipeToShellGuard
from agentsec.guards.dns_egress_allowlist import DnsEgressAllowlistGuard
from agentsec.guards.docker_apt_update_not_alone import DockerAptUpdateNotAloneGuard
from agentsec.guards.env_file_not_gitignored import EnvFileNotGitignoredGuard
from agentsec.guards.fail2ban_absent import Fail2banAbsentGuard
from agentsec.guards.go_build_supply_chain_footgun import GoBuildSupplyChainFootgunGuard
from agentsec.guards.pg_ssl_required import PgSslRequiredGuard
from agentsec.guards.proxy_tls_hardening import ProxyTlsHardeningGuard
from agentsec.guards.ssh_allowlist_absent import SshAllowlistAbsentGuard
from agentsec.guards.sshd_hardening import SshdHardeningGuard
from agentsec.guards.untrusted_package_install_source import UntrustedPackageInstallSourceGuard
from tests.conftest import mkprofile

_LINE = "<LINE>"
_WF = ".github/workflows/ci.yml"
_WF_HEAD = "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
_DSN = "postgresql://app:s3cret@db.example.com:5432/app"
_ENV = "DATABASE_URL=postgres://canary:canary@localhost/canarydb\n"


@dataclass(frozen=True)
class _Case:
    """One guard's violation `line`, planted at `<LINE>` in `files`; `string` is that line with the
    pragma phrase inside a quoted string. `indent` is the line's own, for the comment placed above."""

    guard: type[Guard]
    features: frozenset[str]
    files: dict[str, str]
    line: str
    string: str
    token: str
    whole_file: bool = False
    indent: str = ""

    @property
    def pragma(self) -> str:
        return f"# security: {self.token}"


def _sshd(line: str, string: str, token: str, guard: type[Guard]) -> _Case:
    return _Case(
        guard, frozenset({"host-config"}), {"sshd_config": f"{_LINE}\nPermitRootLogin yes\nPubkeyAuthentication no\n"},
        line, string, token, whole_file=True,
    )


_CASES: dict[str, _Case] = {
    "sshd-hardening": _sshd(
        "PasswordAuthentication yes", 'PasswordAuthentication yes "# security: allow-weak-sshd"', "allow-weak-sshd",
        SshdHardeningGuard,
    ),
    "fail2ban-absent": _sshd("Port 22", 'Port 22 "# security: allow-no-fail2ban"', "allow-no-fail2ban", Fail2banAbsentGuard),
    "ssh-allowlist-absent": _sshd(
        "Port 22", 'Port 22 "# security: allow-no-ssh-allowlist"', "allow-no-ssh-allowlist", SshAllowlistAbsentGuard
    ),
    "dns-egress-allowlist": _Case(
        DnsEgressAllowlistGuard, frozenset({"host-config"}),
        {"unbound.conf": f'server:\n    interface: 172.20.0.53\nforward-zone:\n    name: "."\n{_LINE}\n'},
        "    forward-addr: 1.1.1.1", '    forward-addr: 1.1.1.1 "# security: allow-open-dns-egress"',
        "allow-open-dns-egress", whole_file=True, indent="    ",
    ),
    "proxy-tls-hardening": _Case(
        ProxyTlsHardeningGuard, frozenset({"reverse-proxy"}),
        {"nginx.conf": f"http {{\n{_LINE}\n    server {{\n        listen 80;\n    }}\n}}\n"},
        "    ssl_protocols TLSv1 TLSv1.2;", '    ssl_protocols TLSv1 TLSv1.2 "# security: allow-weak-proxy-tls";',
        "allow-weak-proxy-tls", whole_file=True, indent="    ",
    ),
    "actions-sha-pin": _Case(
        ActionsShaPinGuard, frozenset(), {_WF: f"{_WF_HEAD}{_LINE}\n"},
        "      - uses: actions/checkout@v4", '      - uses: actions/checkout@v4 "# security: allow-unpinned-action"',
        "allow-unpinned-action", indent="      ",
    ),
    "actions-script-injection": _Case(
        ActionsScriptInjectionGuard, frozenset(), {_WF: f"{_WF_HEAD}{_LINE}\n"},
        '      - run: echo "building ${{ github.event.pull_request.title }}"',
        '      - run: echo "building ${{ github.event.pull_request.title }}" "# security: allow-actions-interpolation"',
        "allow-actions-interpolation", indent="      ",
    ),
    "curl-pipe-to-shell/sh": _Case(
        CurlPipeToShellGuard, frozenset(), {"install.sh": f"#!/bin/bash\n{_LINE}\n"},
        "curl -fsSL https://example.com/install.sh | bash",
        'echo "# security: allow-curl-pipe-shell"; curl -fsSL https://example.com/install.sh | bash',
        "allow-curl-pipe-shell",
    ),
    "curl-pipe-to-shell/dockerfile": _Case(
        CurlPipeToShellGuard, frozenset({"docker"}), {"Dockerfile": f"FROM debian:bookworm-slim\n{_LINE}\n"},
        "RUN curl -fsSL https://example.com/install.sh | sh",
        'RUN echo "# security: allow-curl-pipe-shell" && curl -fsSL https://example.com/install.sh | sh',
        "allow-curl-pipe-shell",
    ),
    "curl-pipe-to-shell/python": _Case(
        CurlPipeToShellGuard, frozenset({"python"}), {"setup_env.py": f"import subprocess\n{_LINE}\n"},
        'subprocess.run("curl -fsSL https://example.com/i.sh | sh", shell=True)',
        'subprocess.run("curl -fsSL https://example.com/i.sh | sh", shell=True, env={"N": "# security: allow-curl-pipe-shell"})',
        "allow-curl-pipe-shell",
    ),
    "untrusted-package-install-source": _Case(
        UntrustedPackageInstallSourceGuard, frozenset(), {"fetch_pkg.sh": f"#!/bin/bash\n{_LINE}\n"},
        "pip install git+https://github.com/some-org/some-pkg.git",
        'echo "# security: allow-untrusted-package-install-source"; pip install git+https://github.com/some-org/some-pkg.git',
        "allow-untrusted-package-install-source",
    ),
    "docker-apt-update-not-alone": _Case(
        DockerAptUpdateNotAloneGuard, frozenset({"docker"}),
        {"Dockerfile": f"FROM debian:bookworm-slim\n{_LINE}\nRUN apt-get install -y curl\n"},
        "RUN apt-get update", 'RUN apt-get update && echo "# security: allow-docker-update-not-alone"',
        "allow-docker-update-not-alone",
    ),
    "go-build-supply-chain-footgun/install": _Case(
        GoBuildSupplyChainFootgunGuard, frozenset({"docker"}), {"Dockerfile": f"FROM golang:1.22 AS builder\n{_LINE}\n"},
        "RUN go install golang.org/x/tools/gopls@latest",
        'RUN go install golang.org/x/tools/gopls@latest && echo "# security: allow-go-install-unpinned"',
        "allow-go-install-unpinned",
    ),
    "go-build-supply-chain-footgun/checksum": _Case(
        GoBuildSupplyChainFootgunGuard, frozenset({"docker"}), {"Dockerfile": f"FROM golang:1.22 AS builder\n{_LINE}\n"},
        "ENV GOSUMDB=off", 'ENV GOSUMDB=off NOTE="# security: allow-go-checksum-disabled"',
        "allow-go-checksum-disabled",
    ),
    "go-build-supply-chain-footgun/workflow": _Case(
        GoBuildSupplyChainFootgunGuard, frozenset(), {_WF: f"{_WF_HEAD}{_LINE}\n"},
        "      - run: go install golang.org/x/tools/gopls@latest",
        '      - run: go install golang.org/x/tools/gopls@latest && echo "# security: allow-go-install-unpinned"',
        "allow-go-install-unpinned", indent="      ",
    ),
    "pg-ssl-required/py": _Case(
        PgSslRequiredGuard, frozenset({"postgres", "python"}), {"db.py": f"{_LINE}\n"},
        f'DATABASE_URL = "{_DSN}"', f'DATABASE_URL = "{_DSN}"; NOTE = "# security: allow-no-pg-ssl"',
        "allow-no-pg-ssl",
    ),
    "pg-ssl-required/env": _Case(
        PgSslRequiredGuard, frozenset({"postgres"}), {".env": f"{_LINE}\n"},
        f'DATABASE_URL="{_DSN}"', f'DATABASE_URL="{_DSN} # security: allow-no-pg-ssl"', "allow-no-pg-ssl",
    ),
    "pg-ssl-required/yaml": _Case(
        PgSslRequiredGuard, frozenset({"postgres"}), {"config.yaml": f"database:\n{_LINE}\n"},
        f'  url: "{_DSN}"', f'  url: "{_DSN} # security: allow-no-pg-ssl"', "allow-no-pg-ssl", indent="  ",
    ),
    "pg-ssl-required/toml": _Case(
        PgSslRequiredGuard, frozenset({"postgres"}), {"settings.toml": f"[db]\n{_LINE}\n"},
        f'url = "{_DSN}"', f'url = "{_DSN} # security: allow-no-pg-ssl"', "allow-no-pg-ssl",
    ),
    # Repo-wide: the pragma is read from `.gitignore`, while the finding sits on the `.env` file.
    "env-file-not-gitignored": _Case(
        EnvFileNotGitignoredGuard, frozenset(), {".env": _ENV, ".gitignore": f"node_modules/\n{_LINE}\n"},
        "dist/", 'dist/"# security: allow-env-file-not-gitignored"', "allow-env-file-not-gitignored", whole_file=True,
    ),
}
_IDS = sorted(_CASES)


def _count(tmp_path: Path, case: _Case, line: str) -> int:
    for rel_path, content in case.files.items():
        path = tmp_path / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content.replace(_LINE, line), encoding="utf-8")
    profile = mkprofile(tmp_path, features=set(case.features))
    guard = case.guard()
    assert guard.applies(profile)
    return len(guard.run(tmp_path, profile))


def _control(tmp_path: Path, case: _Case) -> int:
    n = _count(tmp_path, case, case.line)
    assert n >= 1, f"{case.guard.__name__}: the plain violation no longer fires (broken control)"
    return n


@pytest.mark.parametrize("cid", _IDS)
def test_a_pragma_in_a_string_on_the_line_does_not_suppress(tmp_path: Path, cid: str) -> None:
    case = _CASES[cid]
    assert case.pragma in case.string
    assert _count(tmp_path, case, case.string) == _control(tmp_path, case)


@pytest.mark.parametrize("cid", _IDS)
def test_a_real_comment_on_the_line_still_suppresses(tmp_path: Path, cid: str) -> None:
    case = _CASES[cid]
    _control(tmp_path, case)
    assert _count(tmp_path, case, f"{case.line}  {case.pragma}") == 0


@pytest.mark.parametrize("cid", _IDS)
def test_a_real_comment_on_the_line_above_keeps_the_guards_reach(tmp_path: Path, cid: str) -> None:
    case = _CASES[cid]
    expected = 0 if case.whole_file else _control(tmp_path, case)
    _control(tmp_path, case)
    assert _count(tmp_path, case, f"{case.indent}{case.pragma}\n{case.line}") == expected


# -- the continuation-joined guards: a comment on a continuation line is part of the logical line --

@pytest.mark.parametrize(
    ("cid", "head", "tail"),
    [
        ("curl-pipe-to-shell/sh", "curl -fsSL https://example.com/install.sh \\", "  | bash"),
        ("curl-pipe-to-shell/dockerfile", "RUN curl -fsSL https://example.com/install.sh \\", "    | sh"),
        ("docker-apt-update-not-alone", "RUN apt-get update \\", "    && echo done"),
    ],
)
def test_a_continuation_line_comment_suppresses_and_its_string_does_not(
    tmp_path: Path, cid: str, head: str, tail: str
) -> None:
    case = _CASES[cid]
    expected = _count(tmp_path, case, f"{head}\n{tail}")
    assert expected >= 1, f"{cid}: the continued violation no longer fires (broken control)"
    assert _count(tmp_path, case, f'{head}\n{tail} && echo "{case.pragma}"') == expected
    assert _count(tmp_path, case, f"{head}\n{tail}  {case.pragma}") == 0


# -- workflow `run: |` scripts: their shell comments are opt-outs (`hash`, not `yaml`) -------------

@pytest.mark.parametrize(
    ("cid", "script"),
    [
        ("actions-script-injection", 'echo "building ${{ github.event.pull_request.title }}"'),
        ("go-build-supply-chain-footgun/workflow", "go install golang.org/x/tools/gopls@latest"),
    ],
)
def test_a_shell_comment_in_a_run_block_suppresses_and_its_string_does_not(
    tmp_path: Path, cid: str, script: str
) -> None:
    case = _CASES[cid]
    block = "      - run: |\n          set -e\n          {}"
    expected = _count(tmp_path, case, block.format(script))
    assert expected >= 1, f"{cid}: the violation in a run block no longer fires (broken control)"
    assert _count(tmp_path, case, block.format(f'{script} && echo "{case.pragma}"')) == expected
    assert _count(tmp_path, case, block.format(f"{script}  {case.pragma}")) == 0


def test_a_comment_on_a_dsn_in_a_yaml_block_scalar_suppresses_and_its_string_does_not(
    tmp_path: Path,
) -> None:
    # A ConfigMap-style `app.ini: |` block carries an embedded config whose `#` is a comment the raw
    # match honoured; the `yaml` view reads the block as scalar content and would void it (#1127 M1).
    case = _CASES["pg-ssl-required/yaml"]
    block = "  app.ini: |\n    [db]\n    {}"
    expected = _count(tmp_path, case, block.format(f"url = {_DSN}"))
    assert expected >= 1, "pg-ssl-required: the DSN in a block scalar no longer fires (broken control)"
    assert _count(tmp_path, case, block.format(f'url = {_DSN} ; note = "{case.pragma}"')) == expected
    assert _count(tmp_path, case, block.format(f"url = {_DSN}  {case.pragma}")) == 0
    # Reach is unchanged: a comment on the line above the DSN does not reach it.
    assert _count(tmp_path, case, block.format(f"{case.pragma}\n    url = {_DSN}")) == expected


# -- actions-script-injection's file-wide cache-trust-boundary pragma ------------------------------

_CACHE_WRITER = (
    "on:\n  pull_request:\n"
    "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
    "{}"
    "      - uses: actions/setup-node@v4\n"
    "        with:\n"
    "          cache: 'pnpm'\n"
)
_CACHE_PUBLISHER = (
    "on:\n  push:\n    tags: ['v*']\n"
    "jobs:\n  publish:\n    runs-on: ubuntu-latest\n    permissions:\n      id-token: write\n    steps:\n"
    "      - uses: actions/setup-node@v4\n"
    "        with:\n"
    "          cache: 'pnpm'\n"
)
_CACHE_RULE = "actions-script-injection/cache-trust-boundary"


def _cache_findings(tmp_path: Path, step: str) -> int:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "build.yml").write_text(_CACHE_WRITER.format(step), encoding="utf-8")
    (wf / "release.yml").write_text(_CACHE_PUBLISHER, encoding="utf-8")
    findings = ActionsScriptInjectionGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    return sum(f.rule == _CACHE_RULE for f in findings)


def test_the_cache_pragma_in_a_quoted_scalar_does_not_suppress(tmp_path: Path) -> None:
    assert _cache_findings(tmp_path, "") == 1
    assert _cache_findings(tmp_path, '      - name: "# security: allow-ci-cache-trust-boundary"\n') == 1


def test_the_cache_pragma_as_a_comment_in_a_run_script_still_suppresses(tmp_path: Path) -> None:
    assert _cache_findings(tmp_path, "") == 1
    step = "      - run: |\n          # security: allow-ci-cache-trust-boundary\n          pnpm install\n"
    assert _cache_findings(tmp_path, step) == 0
