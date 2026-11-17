"""Target-locality classification for the live-scan layer.

`agentsec live` drives scanners against a **running** target — an HTTP URL (ZAP /
Schemathesis / jwt_tool) or a Postgres DSN (Splinter). Intrusive scans (active
ZAP, Schemathesis fuzzing) and even a read-only DB lint must never be aimed at
production by accident. This module answers one question — *is this target local
or remote?* — by a **pure string parse** of the host.

It opens **no socket and makes no connection** (so it is import-safe even from the
zero-network static path; see the G5 doctrine constraint). The actual probing
(`SELECT 1` pre-flight) and the interactive consent live in `live.py` / `cli.py`.
"""
from __future__ import annotations

import ipaddress
from typing import Literal
from urllib.parse import urlsplit

Locality = Literal["local", "remote"]

# Hostnames that always denote the developer's own machine / the Docker host.
_LOCAL_HOSTNAMES = frozenset({"localhost", "host.docker.internal"})

# Managed-service host suffixes worth calling out by name in a remote warning,
# longest/most-specific first so `.pooler.supabase.com` wins over `.supabase.com`.
_HOSTED_SUFFIXES: tuple[tuple[str, str], ...] = (
    (".pooler.supabase.com", "hosted Supabase pooler"),
    (".supabase.co", "hosted Supabase project"),
    (".supabase.com", "hosted Supabase project"),
    (".rds.amazonaws.com", "AWS RDS instance"),
    (".neon.tech", "Neon database"),
)


def extract_host(url: str) -> str:
    """The lowercased hostname from a URL or DSN (``''`` if unparseable).

    Tolerates a bare ``host[:port]`` (no scheme) by assuming one so ``urlsplit``
    populates ``hostname``. Returns only the host — never the credential portion
    of a DSN."""
    s = (url or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "x://" + s
    try:
        return (urlsplit(s).hostname or "").lower()
    except ValueError:
        return ""


def classify_host(url: str) -> Locality:
    """Classify a target URL/DSN as ``"local"`` or ``"remote"`` by host only.

    Local: ``localhost`` / ``host.docker.internal``, any ``*.local`` mDNS name, and
    loopback / RFC-1918-private / link-local IP literals. Everything else —
    including any DNS hostname and any empty/unparseable host — is ``"remote"``.
    The default is deliberately safe: when in doubt, treat it as production."""
    host = extract_host(url)
    if not host:
        return "remote"
    if host in _LOCAL_HOSTNAMES or host.endswith(".local"):
        return "local"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "remote"  # a real DNS hostname, not an IP literal
    return "local" if (ip.is_loopback or ip.is_private or ip.is_link_local) else "remote"  # security: allow-ssrf-ipv6-bypass


def describe(url: str) -> str:
    """A short, **secret-free** description for warnings / `detect` output — host +
    locality + a managed-service or public-IP callout when recognized. Never
    includes the URL's credentials (only the host is ever rendered)."""
    host = extract_host(url)
    kind = classify_host(url)
    if not host:
        return f"{kind} target (unparseable host)"
    note = ""
    for suffix, label in _HOSTED_SUFFIXES:
        if host.endswith(suffix):
            note = f", {label}"
            break
    if not note and kind == "remote":
        try:
            if ipaddress.ip_address(host).is_global:
                note = ", public IP"
        except ValueError:
            pass
    return f"{kind} ({host}{note})"


# --- env-file DB-target surfacing (for `agentsec detect`) -------------------

# Env vars that carry a DB / Supabase target we can classify for locality.
_DB_ENV_VARS = ("DATABASE_URL", "DIRECT_URL", "SUPABASE_URL", "SUPABASE_DB_URL")


def db_urls_in_env(env_text: str) -> list[tuple[str, str]]:
    """Parse ``VAR=value`` lines for DB/Supabase URLs (pure string scan).

    Returns ``(var, url)`` in a stable order (first occurrence of each var wins).
    Callers must render via :func:`describe` / :func:`classify_host` (host only) —
    **never print the raw value**, which carries the DB password."""
    seen: dict[str, str] = {}
    for raw in env_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        if key in _DB_ENV_VARS and key not in seen:
            v = val.strip().strip('"').strip("'")
            if v:
                seen[key] = v
    return [(k, seen[k]) for k in _DB_ENV_VARS if k in seen]
