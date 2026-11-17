"""Outside-in live scan: probe a deployed app's Supabase backend for anon-key-reachable
exposure, with **no local repo and no database credential required** (
`agentsec scan-live-url`).

Every other live scanner in `live.py` assumes you have the source (`agentsec live` runs the
static audit over `Path(args.path)` first) or a database DSN (Splinter). Neither exists for
someone who built entirely inside a vibe-coding platform's own UI (Lovable/Bolt/Replit) and
never touched a terminal — the exact population RedAccess's May 2026 scan of 380,000 public
vibe-coded apps found ~5,000 with zero authentication. This module is the read-only,
anon-key-only probe that population can actually run: point it at the live URL, nothing else.

**Ownership gate, not a rate limit.** Probing a URL you found, not one you were given, is the
line between a security check and unauthorized scanning. `verify_ownership_file`/`_dns` must
both return `verified=True` before `cli.py` calls any probe — see `docs/knowledge/
design-scan-live-url.md` for the full threat/consent model. This module itself does not
enforce the gate (it has no notion of "the caller already checked") — that is `cli.py`'s job,
the same separation `live.py`'s `_consent_remote` keeps from its own probe functions.

**Discovery, then probing, both read-only GETs (POST only for the GraphQL introspection
query, itself read-only).** `discover_supabase_config` fetches the page's own HTML + a bounded
number of its script bundles — the Supabase URL and anon key are compiled into the client
bundle by construction (the browser must see them to make requests), so they are not a secret
being extracted, only being read from where the app already ships them publicly.
"""
from __future__ import annotations

import json
import re
import secrets
import subprocess  # nosec B404 (dig/nslookup orchestration for DNS TXT lookup; no shell)
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from agentsec import net
from agentsec.findings import Finding, Severity
from agentsec.live import LiveResult
from agentsec.runners.base import child_env, which

WELL_KNOWN_PATH = "/.well-known/agentsec-verify.txt"

_ANON_KEY_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_SUPABASE_URL_RE = re.compile(r"https://[a-z0-9][a-z0-9-]{0,62}\.supabase\.co")
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_MAX_SCRIPTS_FETCHED = 5

# Table/bucket name fragments worth calling out by name — not exhaustive, just enough to
# separate "some tables are reachable" (medium, common and often intentional for public
# reference data) from "a table that is almost never meant to be public is reachable" (high).
_SENSITIVE_NAME_RE = re.compile(
    r"user|profile|account|customer|payment|order|invoice|message|chat|session|token|"
    r"secret|password|admin|credential|api[_-]?key|subscri|billing|medical|patient",
    re.IGNORECASE,
)


@dataclass
class OwnershipResult:
    verified: bool
    method: str
    reason: str = ""


def generate_verify_token() -> str:
    """A random per-run token the user places at the well-known path or a DNS TXT record."""
    return secrets.token_hex(16)


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def verify_ownership_file(url: str, token: str, timeout: int = 10) -> OwnershipResult:
    """Proof-of-ownership via a static file — works on any host, including a drag-and-drop
    platform where the user can add one static asset but has no DNS control at all."""
    check_url = _origin(url) + WELL_KNOWN_PATH
    try:
        with net.urlopen(check_url, timeout=timeout) as r:  # nosec B310 (scheme comes from the caller's own https URL)
            body = r.read(4096).decode("utf-8", errors="replace")
    except (OSError, ValueError) as e:
        return OwnershipResult(False, "file", f"could not fetch {check_url}: {e}")
    if token in body:
        return OwnershipResult(True, "file")
    return OwnershipResult(False, "file", f"token not found at {check_url}")


def verify_ownership_dns(url: str, token: str, timeout: int = 10) -> OwnershipResult:
    """Proof-of-ownership via a `_agentsec-verify.<host>` TXT record.

    Shells out to `dig`/`nslookup` (optional external tools, same posture as `live.py`'s
    `psql`/`docker`) rather than adding a DNS-client runtime dependency — agentsec ships with
    zero runtime dependencies by design, and Python's stdlib has no TXT-record lookup."""
    host = urlsplit(url).hostname or ""
    if not host:
        return OwnershipResult(False, "dns", "could not parse a host from the URL")
    record = f"_agentsec-verify.{host}"
    if which("dig"):
        cmd = ["dig", "+short", "TXT", record]
    elif which("nslookup"):
        cmd = ["nslookup", "-type=TXT", record]
    else:
        return OwnershipResult(
            False, "dns",
            "no DNS lookup tool (dig/nslookup) installed — use the file-based proof instead",
        )
    try:
        proc = subprocess.run(  # nosec B603 (fixed argv, no shell; tool resolved via which())
            cmd, capture_output=True, text=True, timeout=timeout, check=False, env=child_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return OwnershipResult(False, "dns", f"DNS lookup failed: {e}")
    if token in proc.stdout:
        return OwnershipResult(True, "dns")
    return OwnershipResult(False, "dns", f"token not found in a TXT record for {record}")


def discover_supabase_config(url: str, timeout: int = 15) -> tuple[str, str]:
    """Fetch the page and a bounded number of its own script bundles, looking for the
    Supabase URL + anon key every Supabase client ships in plain sight (the browser must be
    able to read them to make requests — this is not extracting a secret, only reading one
    the app already serves to the public). Returns `("", "")` on any failure or non-match;
    never raises."""
    try:
        with net.urlopen(url, timeout=timeout) as r:  # nosec B310 (scheme validated by the caller)
            html = r.read(2_000_000).decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return "", ""
    texts = [html]
    scripts = _SCRIPT_SRC_RE.findall(html)[:_MAX_SCRIPTS_FETCHED]
    for src in scripts:
        script_url = urljoin(url, src)
        if urlsplit(script_url).scheme not in ("http", "https"):
            continue
        try:
            with net.urlopen(script_url, timeout=timeout) as r:  # nosec B310
                texts.append(r.read(3_000_000).decode("utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
    blob = "\n".join(texts)
    url_match = _SUPABASE_URL_RE.search(blob)
    key_match = _ANON_KEY_RE.search(blob)
    return (url_match.group(0) if url_match else "", key_match.group(0) if key_match else "")


def _get_json(url: str, anon_key: str, timeout: int) -> tuple[object | None, str]:
    req = net.Request(url, headers={"apikey": anon_key})
    try:
        with net.urlopen(req, timeout=timeout) as r:  # nosec B310 (scheme validated by callers via supabase_url)
            return json.loads(r.read().decode("utf-8", errors="replace")), ""
    except (OSError, ValueError) as e:
        return None, str(e)


def probe_exposed_tables(supabase_url: str, anon_key: str, timeout: int = 15) -> LiveResult:
    """PostgREST's root document (`GET /rest/v1/`) lists every table/view the anon role can
    reach, by construction — it is the OpenAPI-shaped self-description PostgREST returns to
    ANY caller with a valid API key, no auth token required. A long list, or one containing a
    sensitive-sounding name, means the anon key shipped to every browser can read (at least)
    the schema of that data — RLS may still block rows, but the surface itself is disclosed."""
    url = supabase_url.rstrip("/") + "/rest/v1/"
    data, err = _get_json(url, anon_key, timeout)
    if data is None:
        return LiveResult("scan-live-url/exposed-tables", False, skip_reason=f"PostgREST root unreachable: {err}")
    paths = data.get("paths", {}) if isinstance(data, dict) else {}
    tables = sorted({p.strip("/").split("/")[0] for p in paths if isinstance(p, str) and p.strip("/")})
    if not tables:
        return LiveResult("scan-live-url/exposed-tables", True, findings=[])
    sensitive = [t for t in tables if _SENSITIVE_NAME_RE.search(t)]
    severity: Severity = "high" if sensitive else "medium"
    named = ", ".join(sensitive[:8]) if sensitive else ", ".join(tables[:8])
    finding = Finding(
        check_id="scan-live-url",
        severity=severity,
        title="Database tables reachable via the public anon key",
        location=url,
        message=(
            f"{len(tables)} table(s)/view(s) are listed in the PostgREST schema this app's "
            f"public anon key can query: {named}"
            + (f" (+{len(tables) - 8} more)" if len(tables) > 8 else "")
            + (". At least one name suggests it holds real user data." if sensitive else ".")
        ),
        remediation=(
            "This lists the SCHEMA the anon key can see, not confirmed data access — enable "
            "Row-Level Security on every table above and add explicit policies for the "
            "operations the anon role actually needs (default: none). A table with RLS "
            "enabled and no policy denies all anon rows even though it stays in this list."
        ),
        rule="scan-live-url/exposed-tables",
        standards=["OWASP:A01"],
    )
    return LiveResult("scan-live-url/exposed-tables", True, findings=[finding])


def probe_public_storage(supabase_url: str, anon_key: str, timeout: int = 15) -> LiveResult:
    """`GET /storage/v1/bucket` with the anon key. Supabase Storage only returns the bucket
    list to a caller who can read it; buckets marked `public` there serve their objects to
    anyone with a guessable/leaked object path, no key required at all."""
    url = supabase_url.rstrip("/") + "/storage/v1/bucket"
    data, err = _get_json(url, anon_key, timeout)
    if data is None:
        return LiveResult("scan-live-url/public-storage", False, skip_reason=f"storage bucket list unreachable: {err}")
    if not isinstance(data, list):
        return LiveResult("scan-live-url/public-storage", True, findings=[])
    public_buckets = [
        str(b.get("name", b.get("id", "?"))) for b in data
        if isinstance(b, dict) and b.get("public") is True
    ]
    if not public_buckets:
        return LiveResult("scan-live-url/public-storage", True, findings=[])
    finding = Finding(
        check_id="scan-live-url",
        severity="medium",
        title="Public storage bucket(s) reachable via the anon key",
        location=url,
        message=(
            f"{len(public_buckets)} public storage bucket(s) found: {', '.join(public_buckets[:8])}. "
            "Any object in a public bucket is servable to anyone with (or who can guess/enumerate) "
            "its path — no API key or auth token required."
        ),
        remediation=(
            "Confirm every public bucket is meant to be world-readable (static assets, public "
            "avatars). For anything else, switch the bucket to private and serve objects via "
            "short-lived signed URLs generated server-side after an authorization check."
        ),
        rule="scan-live-url/public-storage",
        standards=["OWASP:A01"],
    )
    return LiveResult("scan-live-url/public-storage", True, findings=[finding])


_GRAPHQL_INTROSPECTION = json.dumps({"query": "{ __schema { types { name } } }"}).encode()


def probe_pg_graphql(supabase_url: str, anon_key: str, timeout: int = 15) -> LiveResult:
    """POST an introspection query to `/graphql/v1` with the anon key. A successful
    introspection response means the anon role can walk the ENTIRE GraphQL schema — every
    table/column pg_graphql exposes — independent of whatever REST-level RLS is configured,
    since pg_graphql is a separate exposure surface with its own reachability."""
    url = supabase_url.rstrip("/") + "/graphql/v1"
    req = net.Request(
        url, data=_GRAPHQL_INTROSPECTION, method="POST",
        headers={"apikey": anon_key, "Content-Type": "application/json"},
    )
    try:
        with net.urlopen(req, timeout=timeout) as r:  # nosec B310 (scheme validated by caller via supabase_url)
            data = json.loads(r.read().decode("utf-8", errors="replace"))
    except (OSError, ValueError) as e:
        return LiveResult("scan-live-url/pg-graphql-exposed", False, skip_reason=f"graphql endpoint unreachable: {e}")
    types = (
        data.get("data", {}).get("__schema", {}).get("types", [])
        if isinstance(data, dict) else []
    )
    # Every GraphQL schema carries the built-in introspection/scalar types (__Schema, __Type,
    # String, Int, ...) even with zero application tables exposed — only a schema with MORE
    # than that baseline actually discloses real domain data.
    app_types = [t for t in types if isinstance(t, dict) and not str(t.get("name", "")).startswith("__")]
    if len(app_types) <= 5:  # a handful of scalars (String/Int/Boolean/ID/Float) is the clean baseline
        return LiveResult("scan-live-url/pg-graphql-exposed", True, findings=[])
    finding = Finding(
        check_id="scan-live-url",
        severity="high",
        title="pg_graphql schema fully introspectable via the public anon key",
        location=url,
        message=(
            f"GraphQL introspection succeeded and returned {len(app_types)} application type(s) "
            "— the anon key can walk the entire pg_graphql schema, a separate exposure surface "
            "from PostgREST with its own reachability regardless of REST-level RLS."
        ),
        remediation=(
            "Disable pg_graphql for the anon role if the app doesn't use it "
            "(`revoke usage on schema graphql from anon;`), or ensure every exposed table has "
            "RLS enabled with explicit anon policies the same as the REST surface."
        ),
        rule="scan-live-url/pg-graphql-exposed",
        standards=["OWASP:A01"],
    )
    return LiveResult("scan-live-url/pg-graphql-exposed", True, findings=[finding])


def edge_functions_not_probed() -> LiveResult:
    """Edge Functions have no enumeration endpoint — unlike tables/buckets/GraphQL types,
    there is no request that lists deployed function names, so this leg cannot be probed
    without a name to guess. Disclosed explicitly (never silently dropped) so a clean report
    doesn't imply this surface was checked when it wasn't (CLAUDE.md's honesty doctrine)."""
    return LiveResult(
        "scan-live-url/edge-functions", False,
        skip_reason="Edge Functions have no enumeration endpoint — cannot be probed by URL alone",
    )
