"""Guard: connect to PostgreSQL over SSL (checklist §7).

A Postgres connection string without `sslmode=require` (or stronger) sends the
auth handshake and all query traffic in cleartext — anyone on the network path
(a shared host, a misconfigured VPC, a MITM) reads credentials and data. The fix
is `sslmode=require` at minimum (`verify-full` for real cert checking).

Fires MEDIUM on a `postgres://` / `postgresql://` DSN that has no
`sslmode=require|verify-ca|verify-full` (or `ssl=true`). Localhost/127.0.0.1 DSNs
are not flagged (local dev). Suppress an intentional case with:

    DATABASE_URL = "postgresql://u:p@host/db"  # security: allow-no-pg-ssl
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    iter_files,
    iter_files_named,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
)

_DSN = re.compile(r"postgres(?:ql)?(?:\+\w+)?://[^\s'\"`)]+", re.IGNORECASE)
_SSL_OK = re.compile(r"sslmode=(?:require|verify-ca|verify-full)|ssl=true", re.IGNORECASE)
# Localhost DSNs are exempt (no network SSL needed). Match the host after `@` (with creds)
# OR after `//` (credential-less), and allow it to end at `:`/`/` OR the DSN end — so
# `postgresql://localhost:5432/db` and `u:p@localhost` are both recognized (#423).
#
# This still earns its place beside `_is_internal_host` below: `127.0.0.1` is DOTTED, so the
# bare-single-label rule reads it as an external host and would not exempt it.
_LOCAL = re.compile(r"(?:@|//)(?:localhost|127\.0\.0\.1)(?:[:/]|$)", re.IGNORECASE)
# The DSN authority (`userinfo@host:port`) — everything between `scheme://` and the first `/?#`.
_SCHEME = re.compile(r"[a-zA-Z][\w.+-]*://")
# A hostname / IPv4 / bracketed IPv6, optionally with a `:port`.
_HOST_PORT = re.compile(r"^(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9_.-]+)(?::\d+)?$")


def _host_port(rest: str) -> str | None:
    """The `host[:port]` of a DSN, given everything after `scheme://`.

    Returns None when the authority cannot be identified with confidence. **Every caller must
    treat None as "not an internal host", i.e. FIRE.** This function is the only thing in the
    guard that can SUPPRESS a finding, so every ambiguous parse resolves toward firing.

    Straight RFC 3986: the authority ends at the **first `/`, `?` or `#`**, and userinfo is
    everything up to the **last `@` inside it**. Three earlier attempts hand-rolled a scan
    instead, and each one shipped a defect that its own tests did not catch (#471 review rounds
    1 to 4). The through-line was that each bounded on some delimiters and not others:

    - Round 1 bounded on nothing, so a query-string `@` beat the real separator and a dotted
      external host resolved to a query fragment. Silently exempted, because the fragment had
      no dot.
    - Round 2 bounded on `?`/`#` but then asked "is there an `@` anywhere" to detect userinfo,
      which fired on a credential-less internal host carrying `?application_name=svc@worker` —
      the guard's own canonical exemption case.
    - Round 3 fixed that by testing whether the head parses, but still never bounded on `/`, so
      an `@` in the **path** beat the real separator the same way round 1's query `@` did:
      `prod:pw@db.prod.example.com:5432/tickets@acme` resolved to host `acme` and went silent.
      Measured against main, which fires on it, so it was a real regression.

    (Examples here are written as `rest` — no `scheme://` — which is what this function actually
    receives. It also keeps the guard from matching its own docstring: with the scheme attached,
    the round-3 example above is a literal DSN that this very parse then reports, and the
    self-audit caught exactly that.)

    `/` was the delimiter nobody bounded on, and it is the one the spec puts first.

    The one judgement call left is an `@` in the PATH. It means either a raw delimiter inside
    userinfo pushed the real host past the bound, or the path genuinely contains an `@`; either
    way the authority is not trustworthy, so it returns None and the DSN fires. An `@` in the
    QUERY or FRAGMENT is explicitly NOT suspicious — `?application_name=svc@worker` is an
    ordinary libpq connection label — which is what keeps round 2's regression closed.

    A raw `/`, `?` or `#` inside a password is illegal per RFC 3986 (it must be percent-encoded)
    but does occur in base64 secrets. Those DSNs are unparseable here by construction and so
    they fire. That is a disclosed false-positive class, covered by the pragma; the alternative
    is guessing, and guessing wrong in this function means silence."""
    authority_end = min(
        (i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i != -1),
        default=len(rest),
    )
    path_end = min(
        (i for i in (rest.find("?", authority_end), rest.find("#", authority_end)) if i != -1),
        default=len(rest),
    )
    if "@" in rest[authority_end:path_end]:
        return None
    authority = rest[:authority_end]
    at = authority.rfind("@")
    host = authority[at + 1:] if at != -1 else authority
    return host if _HOST_PORT.match(host) else None


_PRAGMA = re.compile(r"#\s*security:\s*allow-no-pg-ssl")


def _is_internal_host(dsn: str) -> bool:
    """True if the DSN's host is a **bare single-label** name (no dot) — a Docker-compose service
    name (`@postgres:5432`, `@db/app`) reached container-to-container on the internal bridge network,
    where external TLS is not applicable. This generalizes the loopback exemption to "not a real
    external host". Host-anchored (not a loose substring), so a dotted external host
    (`@db.example.com`) still fires, a bracketed IPv6 host (`@[2001:db8::1]`) is treated as external
    and still fires, and neither an unescaped `@` in a password nor one in a query-string parameter
    can fool it (see `_host_port`).

    Note the asymmetry, which is deliberate: True SUPPRESSES a finding, so this returns False —
    fire — for anything it cannot positively identify as a bare service name, including every
    ambiguous parse `_host_port` reports as None."""
    m = _SCHEME.match(dsn)
    if not m:
        return False
    rest = dsn[m.end():]
    host_port = _host_port(rest)
    if host_port is None:
        return False
    if host_port.startswith("["):        # bracketed IPv6 → not a bare service name (external)
        return False
    host = host_port.split(":", 1)[0]    # drop the :port
    return bool(host) and "." not in host

_CONFIG_SUFFIXES = (".py", ".toml", ".yaml", ".yml", ".ini", ".cfg")


class PgSslRequiredGuard(Guard):
    id = "pg-ssl-required"
    title = "PostgreSQL connection requires SSL"
    area = "Database"

    # a remote Postgres DSN with no sslmode (fires pg-ssl-required). db.example.com
    # is non-local, so _LOCAL doesn't exempt it; no sslmode= / ssl=true present.
    canary_plant = CanaryPlant(
        files={
            "db.py": 'DATABASE_URL = "postgresql://app:s3cret@db.example.com:5432/app"\n',
        },
        expects=frozenset({"pg-ssl-required/no-sslmode"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "postgres" in profile.features or "supabase" in profile.features

    def _candidates(self, root: Path, profile: StackProfile) -> list[Path]:
        out: list[Path] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, _CONFIG_SUFFIXES):
                if f not in seen:
                    seen.add(f)
                    out.append(f)
        for f in iter_files(root, _CONFIG_SUFFIXES):
            if f not in seen:
                seen.add(f)
                out.append(f)
        # .env files are matched by name (Path('.env').suffix is empty). A real `.env` is
        # usually gitignored, so scan past .gitignore — but still skip worktrees/vendored dirs.
        for f in iter_files_named(root, ".env*", respect_gitignore=False):
            if f.name != ".env.example" and f not in seen:
                seen.add(f)
                out.append(f)
        return out

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in self._candidates(root, profile):
            text = read(f)
            # YAML takes `hash`, not `yaml`: a DSN in a block scalar (a ConfigMap's `app.ini: |`) is
            # embedded config whose `#` is a real comment, which the yaml view reads as content.
            dialect = "hash" if f.suffix.lower() in (".yaml", ".yml") else comment_dialect_for(f)
            pragma_lines = pragma_line_set(_PRAGMA, text, dialect=dialect)
            for i, line in enumerate(text.splitlines(), start=1):
                for dsn in _DSN.findall(line):
                    if _LOCAL.search(dsn) or _is_internal_host(dsn) or _SSL_OK.search(dsn):
                        continue
                    if i in pragma_lines:
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title="PostgreSQL connection without SSL",
                            location=f"{rel(root, f)}:{i}",
                            message=(
                                "This Postgres DSN has no `sslmode=require` — the auth handshake "
                                "and query traffic travel in cleartext, exposing credentials and "
                                "data to anyone on the network path."
                            ),
                            remediation=(
                                "Append `?sslmode=require` (or `verify-full` for cert checking) to "
                                "the connection string. If this is a local-only DSN, suppress with "
                                "`# security: allow-no-pg-ssl`."
                            ),
                            rule="pg-ssl-required/no-sslmode",
                            standards=["OWASP:A02"],
                        )
                    )
                    break  # one finding per line is enough
        return out
