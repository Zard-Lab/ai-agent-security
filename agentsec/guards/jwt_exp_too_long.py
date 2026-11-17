"""Guard: JWT access-token expiry set longer than 24 hours (OWASP:A07, CWE-613).

A long-lived access token widens the window of opportunity for token theft and
replay attacks. If an access token is stolen (e.g. via XSS, log exposure, or a
compromised third-party service), the attacker can impersonate the user for the
full lifetime of the token. The industry standard for access tokens is 15 minutes
to 1 hour; anything beyond 24 hours is considered excessive.

Two statically detectable patterns:

  **`access-token-lifetime-too-long`** (HIGH):

  (1) A constant like ``ACCESS_TOKEN_EXPIRE_MINUTES = 10080`` where the value
  exceeds 1440 (24 hours in minutes).

  (2) A ``timedelta`` assigned to a variable whose name contains *expire*, *exp*,
  or *token_lifetime* (case-insensitive) with ``days >= 1`` or ``hours > 24`` or
  ``minutes > 1440`` — when the variable name also signals it is an *access* token
  context (name does NOT contain *refresh*).

**Why HIGH?** Long-lived access tokens:
  - Remain valid long after a session should have ended (user logs out, account
    revoked, password changed — the token still works)
  - Are routinely captured by XSS, SSRF, log aggregators, and observability tools
  - Are shared across devices and not rotated — a single leak becomes persistent access
  - Violate OWASP:A07 (Identification and Authentication Failures) and CWE-613
    (Insufficient Session Expiration)

**Scope note:** Refresh tokens are deliberately long-lived. Any variable whose name
contains *refresh* (case-insensitive) is skipped.

**Suppress:** ``# security: allow-long-lived-token`` on the flagged line silences
this check for that line. Use only after confirming the token is not an access token
or the lifetime is required by a specific integration (e.g. an API key for a service
that does not support token refresh).

**Checklist item:** ``2a-short-lived-access-tokens``.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_line_set, python_scan_dirs, read, rel

_PRAGMA = "security: allow-long-lived-token"

_STANDARDS = ["OWASP:A07", "CWE-613"]

# Pattern 1: ACCESS_TOKEN_EXPIRE_MINUTES = <N>  (or lowercase variants)
# Matches both ACCESS_TOKEN_EXPIRE_MINUTES and access_token_expire_minutes and TOKEN_EXPIRE_MINUTES
# Left-boundaried so the `TOKEN_EXPIRE_MINUTES` arm does not match inside
# `REFRESH_TOKEN_EXPIRE_MINUTES` (a refresh-token lifetime, allowed to be long) (#423).
_EXPIRE_MINUTES_CONST = re.compile(
    r"(?:ACCESS_TOKEN_EXPIRE_MINUTES|access_token_expire_minutes"
    # Left-boundary ONLY the bare TOKEN_EXPIRE_MINUTES arm, so it doesn't match inside
    # REFRESH_TOKEN_EXPIRE_MINUTES — while a legitimately-prefixed
    # SETTINGS_ACCESS_TOKEN_EXPIRE_MINUTES still matches via the ACCESS arm (PR #447 review).
    r"|(?<![A-Za-z0-9_])TOKEN_EXPIRE_MINUTES)\s*=\s*(\d+)",
)

# Pattern 2a: timedelta with days= in an expiry context
# Variable name must contain (expire|exp|token_lifetime) but NOT refresh.
# Matches: access_token_expires = timedelta(days=30), expires_delta = timedelta(days=7)
_TIMEDELTA_DAYS = re.compile(
    r"timedelta\s*\([^)]*days\s*=\s*(\d+)",
    re.IGNORECASE,
)

# Pattern 2b: timedelta with hours= in an expiry context
_TIMEDELTA_HOURS = re.compile(
    r"timedelta\s*\([^)]*hours\s*=\s*(\d+)",
    re.IGNORECASE,
)

# Pattern 2c: timedelta with minutes= in an expiry context
_TIMEDELTA_MINUTES = re.compile(
    r"timedelta\s*\([^)]*minutes\s*=\s*(\d+)",
    re.IGNORECASE,
)

# Variable name on left-hand side of assignment (anything before the = or :=)
_LHS = re.compile(r"^[\s\w]*?(\w+)\s*(?:=|:=)", re.IGNORECASE)

# Keywords indicating expiry context (case-insensitive, partial match)
_EXPIRY_KEYWORDS = re.compile(r"expire|expir|token_lifetime|\bexp\b", re.IGNORECASE)

# Keyword that marks refresh tokens — these are allowed to be long-lived
_REFRESH_KEYWORD = re.compile(r"refresh", re.IGNORECASE)

# File-level token context: only a file that actually deals with JWTs / auth tokens can have a
# *token* lifetime. Without it, an `expiry`/`expires` variable is some other TTL (a cache entry, a
# memory record, a cooldown) — flagging its `timedelta(days=…)` is a false positive.
_TOKEN_CONTEXT = re.compile(
    r"\b(?:jwt|jose|oauth2?|bearer)\b|access[_.]?token|refresh[_.]?token|id[_.]?token"
    r"|create_access_token|ACCESS_TOKEN_EXPIRE",
    re.IGNORECASE,
)


def _lhs_name(line: str) -> str:
    """Extract the left-hand side variable name from an assignment line."""
    m = _LHS.match(line)
    return m.group(1) if m else ""


def _is_expiry_context(varname: str) -> bool:
    """True if the variable name looks like an access-token expiry, not a refresh token."""
    if not _EXPIRY_KEYWORDS.search(varname):
        return False
    return not _REFRESH_KEYWORD.search(varname)


class JwtExpTooLongGuard(Guard):
    id = "jwt-exp-too-long"
    title = "JWT access-token lifetime exceeds 24 hours"
    area = "Login & access"

    # auth_config.py: ACCESS_TOKEN_EXPIRE_MINUTES = 10080 (7 days, > 1440) ->
    # fires jwt-exp-too-long/access-token-lifetime-too-long.
    # Must NOT contain: security: allow-long-lived-token pragma.
    canary_plant = CanaryPlant(
        files={
            "auth_config.py": (
                "# Application authentication configuration\n"
                "from datetime import timedelta\n"
                "\n"
                "SECRET_KEY = 'change-me-in-production'\n"
                "ALGORITHM = 'HS256'\n"
                "ACCESS_TOKEN_EXPIRE_MINUTES = 10080\n"
                "REFRESH_TOKEN_EXPIRE_DAYS = 30\n"
            ),
        },
        expects=frozenset({"jwt-exp-too-long/access-token-lifetime-too-long"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        if not self.applies(profile):
            return []

        findings: list[Finding] = []
        seen: set[Path] = set()

        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                if not _TOKEN_CONTEXT.search(text):
                    continue  # not a JWT/token file — an `expiry` here is some other TTL
                findings.extend(self._scan_file(root, f, text))

        return findings

    def _scan_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        results: list[Finding] = []
        # The pragma counts only as a real comment on the line, never quoted in a string
        # there (#1040).
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
        for lineno, line in enumerate(text.splitlines(), 1):
            # Skip pragma-annotated lines
            if lineno in pragmas:
                continue

            # Pattern 1: ACCESS_TOKEN_EXPIRE_MINUTES = <N>
            m = _EXPIRE_MINUTES_CONST.search(line)
            if m:
                value = int(m.group(1))
                # Test the matched CONSTANT NAME, not the raw line. `_REFRESH_KEYWORD` was
                # searched against the whole un-comment-stripped line, so a trailing comment
                # mentioning a refresh-token flow silenced a real finding — a month-long ACCESS
                # token went unreported purely because of a TODO note beside it (#447 review).
                # The timedelta arms below already key off the name; this matches them.
                # (The example is described rather than written out: spelling the constant and
                # its value here would make this guard flag its own source.)
                if value > 1440 and not _REFRESH_KEYWORD.search(m.group(0)):
                    results.append(self._finding(
                        root, f, lineno,
                        f"ACCESS_TOKEN_EXPIRE_MINUTES is {value} minutes"
                        f" ({value // 60} hours) — exceeds the 24-hour (1440-minute) limit.",
                    ))
                continue

            # Pattern 2: timedelta in an expiry variable context
            varname = _lhs_name(line)
            if not _is_expiry_context(varname) and not _is_expiry_context(line):
                continue

            # If line contains refresh in the full line context, skip
            if _REFRESH_KEYWORD.search(varname) or (
                _REFRESH_KEYWORD.search(line) and not _EXPIRY_KEYWORDS.search(varname)
            ):
                continue

            # Sum every component of the SAME timedelta call rather than treating
            # days/hours/minutes as mutually exclusive arms. Each arm used to `continue`, so
            # `timedelta(days=1, hours=12)` matched the days arm, failed its `days > 1` test and
            # skipped the rest — a 36-hour access token missed entirely, while the identical
            # `timedelta(hours=36)` fired (#447 review).
            m_days = _TIMEDELTA_DAYS.search(line)
            m_hours = _TIMEDELTA_HOURS.search(line)
            m_mins = _TIMEDELTA_MINUTES.search(line)
            if not (m_days or m_hours or m_mins):
                continue
            days = int(m_days.group(1)) if m_days else 0
            hours = int(m_hours.group(1)) if m_hours else 0
            minutes = int(m_mins.group(1)) if m_mins else 0
            total_hours = days * 24 + hours + minutes / 60
            # Strictly greater than 24h: exactly `timedelta(days=1)` is at the limit, not over it
            # — consistent with the hours>24 / minutes>1440 thresholds this replaces (#423).
            if total_hours > 24 and not _REFRESH_KEYWORD.search(varname):
                parts = []
                if days:
                    parts.append(f"days={days}")
                if hours:
                    parts.append(f"hours={hours}")
                if minutes:
                    parts.append(f"minutes={minutes}")
                results.append(self._finding(
                    root, f, lineno,
                    f"timedelta({', '.join(parts)}) sets an access-token lifetime of"
                    f" {total_hours:g} hours — exceeds the 24-hour limit.",
                ))

        return results

    def _finding(self, root: Path, f: Path, lineno: int, message: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title="JWT access-token lifetime exceeds 24 hours",
            location=f"{rel(root, f)}:{lineno}",
            message=message,
            remediation=(
                "Set access-token lifetimes to 15 minutes to 1 hour (never more than 24 hours). "
                "Use refresh tokens (which may be long-lived) to issue new short-lived access "
                "tokens without requiring re-authentication. For ACCESS_TOKEN_EXPIRE_MINUTES, "
                "set a value <= 1440. For timedelta, use minutes=15 or hours=1. "
                "Suppress with `# security: allow-long-lived-token` only after confirming this "
                "is not a user-facing access token."
            ),
            rule="jwt-exp-too-long/access-token-lifetime-too-long",
            standards=list(_STANDARDS),
        )
