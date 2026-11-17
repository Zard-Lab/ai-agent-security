from __future__ import annotations

from agentsec.guards.ssrf_ipv6_bypass import SsrfIpv6BypassGuard
from tests.guards._common import *  # noqa: F401,F403


def test_ssrf_ipv6_bypass_flags_is_private_without_mapped(tmp_path: Path) -> None:
    (tmp_path / "validator.py").write_text(
        "import ipaddress\n"
        "\n"
        "def validate_ssrf(host: str) -> None:\n"
        "    ip = ipaddress.ip_address(host)\n"
        "    if ip.is_private or ip.is_loopback:\n"
        "        raise ValueError('SSRF blocked')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = SsrfIpv6BypassGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "ssrf-ipv6-bypass/missing-ipv4-mapped-check"
    assert findings[0].severity == "high"


def test_ssrf_ipv6_bypass_flags_is_link_local_without_mapped(tmp_path: Path) -> None:
    (tmp_path / "ssrf_check.py").write_text(
        "import ipaddress\n"
        "\n"
        "def is_safe_host(host: str) -> bool:\n"
        "    ip = ipaddress.ip_address(host)\n"
        "    return not ip.is_link_local\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SsrfIpv6BypassGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_ssrf_ipv6_bypass_silent_when_ipv4_mapped_present(tmp_path: Path) -> None:
    (tmp_path / "safe_validator.py").write_text(
        "import ipaddress\n"
        "\n"
        "def validate_ssrf(host: str) -> None:\n"
        "    ip = ipaddress.ip_address(host)\n"
        "    effective = ip.ipv4_mapped or ip\n"
        "    if effective.is_private or effective.is_loopback or effective.is_link_local:\n"
        "        raise ValueError('SSRF blocked')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = SsrfIpv6BypassGuard().run(tmp_path, profile)
    assert findings == []


def test_ssrf_ipv6_bypass_silent_when_no_ipaddress_import(tmp_path: Path) -> None:
    (tmp_path / "other.py").write_text(
        "def check_host(host: str) -> bool:\n"
        "    return host.startswith('127.')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SsrfIpv6BypassGuard().run(tmp_path, profile)
    assert findings == []


def test_ssrf_ipv6_bypass_silent_when_no_block_check(tmp_path: Path) -> None:
    (tmp_path / "util.py").write_text(
        "import ipaddress\n"
        "\n"
        "def parse_cidr(network: str) -> str:\n"
        "    return str(ipaddress.ip_network(network, strict=False))\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SsrfIpv6BypassGuard().run(tmp_path, profile)
    assert findings == []


def test_ssrf_ipv6_bypass_pragma_silences_file(tmp_path: Path) -> None:
    (tmp_path / "legacy.py").write_text(
        "# security: allow-ssrf-ipv6-bypass\n"
        "import ipaddress\n"
        "\n"
        "def validate(host: str) -> None:\n"
        "    ip = ipaddress.ip_address(host)\n"
        "    if ip.is_private:\n"
        "        raise ValueError('blocked')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = SsrfIpv6BypassGuard().run(tmp_path, profile)
    assert findings == []


def test_ssrf_ipv6_bypass_does_not_apply_without_python(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"react", "fastapi"}, python_dirs=["."])
    assert SsrfIpv6BypassGuard().applies(profile) is False


def test_ssrf_ipv6_bypass_silent_when_only_is_private(tmp_path: Path) -> None:
    # PR #206 review: is_private DELEGATES to the mapped form on supported CPython
    # (CVE-2024-4032), so it already catches ::ffff:127.0.0.1 — firing on it is a FP.
    (tmp_path / "v.py").write_text(
        "import ipaddress\n"
        "def chk(host):\n"
        "    ip = ipaddress.ip_address(host)\n"
        "    if ip.is_private:\n"
        "        raise ValueError('blocked')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert SsrfIpv6BypassGuard().run(tmp_path, profile) == []


def test_ssrf_ipv6_bypass_silent_when_getattr_ipv4_mapped(tmp_path: Path) -> None:
    # PR #206 review: the correct getattr unwrap (safe on IPv4 inputs) must be recognized.
    (tmp_path / "v.py").write_text(
        "import ipaddress\n"
        "def chk(host):\n"
        "    ip = ipaddress.ip_address(host)\n"
        "    eff = getattr(ip, 'ipv4_mapped', None) or ip\n"
        "    if eff.is_loopback or eff.is_link_local:\n"
        "        raise ValueError('blocked')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert SsrfIpv6BypassGuard().run(tmp_path, profile) == []
