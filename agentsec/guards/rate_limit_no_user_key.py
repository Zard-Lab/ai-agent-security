"""Guard: slowapi / limits rate limiter keyed only on IP address (OWASP:A04 — Insecure Design).

IP-only rate limiting is bypassed by botnet rotation, shared NAT (many legitimate users
share one IP), or any attacker who controls a pool of proxy/VPN exit nodes. For
authenticated endpoints the only reliable rate-limiting key is a stable user identity
(user ID, JWT subject, API key), not the source IP.

This guard performs a cross-file check:

1. If no file in the project imports from ``slowapi`` or ``limits``, the library is not
   in use and there is nothing to flag — return empty.
2. Otherwise, scan for all ``Limiter(...)`` instantiations and capture their ``key_func=``
   values.
3. If ANY ``key_func`` value references a user-identity signal (``user_id``,
   ``current_user``, ``get_current``, ``identity``, ``.sub``, ``authenticated``) — at
   least one user-keyed limiter exists; return empty (benefit of the doubt).
4. If ALL ``key_func`` values are IP-based (``get_remote_address``) with no user-identity
   signal in sight — emit one MEDIUM finding pointing to the first ``Limiter()``
   instantiation found.

**Why MEDIUM?** The bypass requires an attacker with access to IP diversity (botnet,
VPN pool). Behind a corporate NAT, conversely, it also causes false positives for
legitimate users. The risk is real for public, high-value endpoints (login, password
reset, OTP verification) and lower for internal or low-value endpoints.

**Suppress:** add ``# security: allow-ip-rate-limit-only`` anywhere in a file to
silence this check for that file. Use when IP-based limiting is intentional (e.g. a
CDN edge layer provides per-user limiting at a higher level).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_line_comment,
)

_PRAGMA = "security: allow-ip-rate-limit-only"

_STANDARDS = ["OWASP:A04"]

# Detects any import of the slowapi / limits rate-limiting libraries.
_SLOWAPI_IMPORT = re.compile(r"from slowapi|import slowapi|from limits|import limits")

# Detects a Limiter() constructor call.
_LIMITER_INIT = re.compile(r"Limiter\s*\(")

# Extracts the key_func= argument value (non-whitespace token after the '=').
_KEY_FUNC_VAL = re.compile(r"key_func\s*=\s*(\S+)")

# User-identity signals in key_func values.
_USER_KEY = re.compile(r"user_id|current_user|get_current|authenticated|\.sub\b|identity", re.IGNORECASE)

# IP-only key function (the slowapi default).
_IP_KEY = re.compile(r"get_remote_address")

_JOIN_LINES = 10  # max continuation lines to join for a Limiter( call wrapped across lines


def _joined_call(lines: list[str], idx: int) -> str:
    """The call text starting at lines[idx], joined across continuation lines until
    its parens balance (capped at _JOIN_LINES extra lines).

    Lines are comment-stripped before counting AND joining: a stray `)` in a trailing
    `#` comment must not end the join early, and a `key_func=` mentioned only in a
    comment must not count as configured (#437 review High-2)."""
    parts = [strip_python_line_comment(lines[idx])]
    depth = parts[0].count("(") - parts[0].count(")")
    j = idx + 1
    while depth > 0 and j < len(lines) and j <= idx + _JOIN_LINES:
        code = strip_python_line_comment(lines[j])
        parts.append(code)
        depth += code.count("(") - code.count(")")
        j += 1
    return " ".join(p.strip() for p in parts)


class RateLimitNoUserKeyGuard(Guard):
    id = "rate-limit-no-user-key"
    title = "Rate limiter keyed only on IP address — bypassed by botnet/proxy rotation"
    area = "Reliability"

    # ip_limiter.py: slowapi Limiter(key_func=get_remote_address) with no user-identity
    # signal in any scanned file -> fires rate-limit-no-user-key/ip-only-key-func (MEDIUM).
    # Must NOT contain: user_id, current_user, get_current, authenticated, .sub, identity
    # (user-identity signals silence the cross-file check).
    # Must NOT contain: security: allow-ip-rate-limit-only (pragma silences the guard).
    canary_plant = CanaryPlant(
        files={
            "ip_limiter.py": (
                "from slowapi import Limiter\n"
                "from slowapi.util import get_remote_address\n"
                "\n"
                "limiter = Limiter(key_func=get_remote_address)\n"
            ),
        },
        expects=frozenset({"rate-limit-no-user-key/ip-only-key-func"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        if not self.applies(profile):
            return []

        all_files: list[Path] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f not in seen:
                    seen.add(f)
                    all_files.append(f)

        # Pass 1: check whether the library is used at all.
        lib_in_use = False
        for f in all_files:
            text = read(f)
            if _SLOWAPI_IMPORT.search(text):
                lib_in_use = True
                break
        if not lib_in_use:
            return []

        # Pass 2: collect all key_func= values and the first Limiter() location.
        key_funcs: list[str] = []
        first_location: str = ""
        first_file: Path | None = None

        for f in all_files:
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="python"):
                continue
            lines = text.splitlines()
            for i, line in enumerate(lines):
                if not _LIMITER_INIT.search(line):
                    continue
                # Record the location of the first Limiter() init found.
                if first_location == "":
                    first_location = f"{rel(root, f)}:{i + 1}"
                    first_file = f
                call_text = line
                if line.count("(") > line.count(")"):
                    # Multi-line Limiter( call: key_func= may sit on a continuation line.
                    call_text = _joined_call(lines, i)
                kf_match = _KEY_FUNC_VAL.search(call_text)
                if kf_match:
                    key_funcs.append(kf_match.group(1))

        if not key_funcs:
            # No key_func= values found — can't determine the keying strategy.
            return []

        # Pass 3: if any key_func signals user identity, the project is fine.
        for kf in key_funcs:
            if _USER_KEY.search(kf):
                return []

        # All key_func values are IP-based (or unknown) with no user-identity signal.
        ip_only = any(_IP_KEY.search(kf) for kf in key_funcs)
        if not ip_only:
            # No IP key and no user key — ambiguous; skip rather than false-positive.
            return []

        _ = first_file  # referenced above; suppress unused-variable note
        return [
            Finding(
                check_id=self.id,
                severity="medium",
                title="Rate limiter uses IP-only key function — bypassed via botnet or proxy rotation",
                location=first_location,
                message=(
                    "All `Limiter()` instantiations found in this project use "
                    "`get_remote_address` (IP-only) as the `key_func`. IP-based rate "
                    "limiting is trivially bypassed by an attacker who controls a pool "
                    "of IP addresses (botnet, VPN, cloud egress nodes). For authenticated "
                    "endpoints — login, OTP verification, password reset, API operations "
                    "tied to a user — the rate-limit key must be a stable user identity "
                    "(user ID, JWT subject, API key) so limits cannot be evaded by "
                    "switching source IPs."
                ),
                remediation=(
                    "Add a user-identity key function alongside the IP key, e.g.: "
                    "`def user_or_ip(request): return getattr(request.state, 'user_id', None) "
                    "or get_remote_address(request)`. "
                    "Configure the `Limiter` with this composite key so authenticated "
                    "requests are keyed on the user and anonymous requests fall back to IP. "
                    "Suppress with `# security: allow-ip-rate-limit-only` in the file where "
                    "the `Limiter` is defined when IP-only limiting is intentional and a "
                    "higher-layer control (CDN, WAF) provides per-user enforcement."
                ),
                rule="rate-limit-no-user-key/ip-only-key-func",
                standards=list(_STANDARDS),
            )
        ]
