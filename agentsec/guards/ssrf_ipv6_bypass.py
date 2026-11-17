"""Guard: SSRF IPv6-mapped bypass — missing ipv4_mapped check (checklist §3a).

An SSRF blocklist that checks `is_loopback` / `is_link_local` can be bypassed with an
IPv6-mapped address: `::ffff:127.0.0.1`. Python's `ipaddress` reports `is_loopback == False`
and `is_link_local == False` for the mapped form — unless you also unwrap `ip.ipv4_mapped`
and re-apply the guards. CWE-918.

**Note on `is_private`:** it is NOT vulnerable on supported CPython. Since the CVE-2024-4032
fix, `IPv6Address.is_private` delegates to `ipv4_mapped.is_private`, so `::ffff:127.0.0.1`
already reports `is_private == True` — a blocklist using `is_private` catches the mapped form
on its own. This guard therefore keys only on `is_loopback` / `is_link_local`, which do NOT
delegate. (PR #206 review.)

This guard fires when code uses `ipaddress` for SSRF host validation via an `is_loopback` or
`is_link_local` check but does NOT also reference `ipv4_mapped` in the same file.

Suppress a reviewed, intentional case with `# security: allow-ssrf-ipv6-bypass`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, python_scan_dirs, read, rel

_PRAGMA = "security: allow-ssrf-ipv6-bypass"
_STANDARDS = ["OWASP:A10", "CWE-918"]

_IPADDRESS_IMPORT = re.compile(
    r"\b(?:import\s+ipaddress|from\s+ipaddress\s+import)\b"
)
# Only `is_loopback` / `is_link_local` are vulnerable — `is_private` delegates to the mapped
# address on supported CPython (CVE-2024-4032), so firing on it would be a false positive.
_BLOCK_CHECK = re.compile(r"\.(?:is_loopback|is_link_local)\b")
# Match the mapped-unwrap in any form: `ip.ipv4_mapped` AND `getattr(ip, "ipv4_mapped", ...)`.
_MAPPED_CHECK = re.compile(r"\bipv4_mapped\b")


class SsrfIpv6BypassGuard(Guard):
    id = "ssrf-ipv6-bypass"
    title = "SSRF IPv6-mapped bypass — ipv4_mapped not checked alongside is_private/is_loopback"
    area = "Network requests"

    # ssrf_validator.py: ipaddress is_private/is_loopback without ipv4_mapped check ->
    # fires ssrf-ipv6-bypass. Must NOT contain: allow-ssrf-ipv6-bypass, .ipv4_mapped.
    canary_plant = CanaryPlant(
        files={
            "ssrf_validator.py": (
                "import ipaddress\n"
                "\n"
                "\n"
                "def validate_host(host: str) -> None:\n"
                "    ip = ipaddress.ip_address(host)\n"
                "    if ip.is_private or ip.is_loopback or ip.is_link_local:\n"
                "        raise ValueError('SSRF blocked')\n"
            ),
        },
        expects=frozenset({"ssrf-ipv6-bypass/missing-ipv4-mapped-check"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                if not _IPADDRESS_IMPORT.search(text):
                    continue
                block = _BLOCK_CHECK.search(text)
                if not block:
                    continue
                if _MAPPED_CHECK.search(text):
                    continue
                # File blocks on is_loopback/is_link_local but never unwraps ipv4_mapped.
                lineno = text[: block.start()].count("\n") + 1
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="SSRF IP blocklist missing IPv6-mapped check (::ffff:127.0.0.1 bypasses it)",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "This file validates IP addresses for SSRF using `is_loopback` / "
                        "`is_link_local` but never unwraps `ipv4_mapped`. An attacker can send "
                        "`::ffff:127.0.0.1` — `ipaddress` reports it as NOT loopback/link-local "
                        "unless you unwrap the mapped address first. (`is_private` already catches "
                        "the mapped form on supported CPython, but `is_loopback`/`is_link_local` "
                        "do not.)"
                    ),
                    remediation=(
                        "After resolving the IP, unwrap any IPv6-mapped address before applying "
                        "blocklist checks (note: `ipv4_mapped` exists only on IPv6Address, so use "
                        "`getattr` to stay correct on IPv4 inputs):\n"
                        "    ip = ipaddress.ip_address(resolved_host)\n"
                        "    effective = getattr(ip, 'ipv4_mapped', None) or ip\n"
                        "    if effective.is_private or effective.is_loopback or effective.is_link_local:\n"
                        "        raise ValueError('SSRF blocked')\n"
                        "Suppress a reviewed internal fetch with `# security: allow-ssrf-ipv6-bypass`."
                    ),
                    rule="ssrf-ipv6-bypass/missing-ipv4-mapped-check",
                    standards=list(_STANDARDS),
                ))
        return out
