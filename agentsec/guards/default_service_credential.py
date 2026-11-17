"""Guard: a deployed service left on its well-known factory-default credential.

JadePuffer (Sysdig, securityaffairs.com/194713) — the first documented end-to-end AI-driven
ransomware operation — ran its entire *lateral movement* stage on exactly this: an LLM agent
that had already popped an internet-facing Langflow instance (CVE-2025-3248) walked the compose
stack and logged straight into MinIO with `minioadmin`/`minioadmin`, Nacos with its publicly known
default JWT signing secret (a config axis directly adjacent to CVE-2021-29441, the Nacos
AuthFilter bypass), Postgres with `postgres`/`postgres`, and Grafana with `admin`/`admin`. None of
that required exploiting anything — the credentials were the ones the images ship with.

This is a DIFFERENT axis from `weak-secret-key-literal`. That guard flags an APP's own
`SECRET_KEY`/`JWT_SECRET_KEY` set to a placeholder-shaped value (`"changeme"`, `"secret"`, a
`django-insecure-` prefix) inside Python source — the app's own signing key is weak. This guard
flags a well-known **service** (MinIO / Nacos / Postgres / Grafana) deployed with its **factory
credential pair intact** in compose/env config — nothing about the app's own secret management is
in scope here, and nothing about a service's factory default is in scope there.

    # docker-compose.yml
    services:
      minio:
        image: minio/minio
        environment:
          MINIO_ROOT_USER: minioadmin        # <- the image's own documented default
          MINIO_ROOT_PASSWORD: minioadmin     #    unchanged from day one

Four independently-triggered checks, each a KNOWN-LITERAL match (never an entropy/placeholder
heuristic — a real, changed value never matches):

- **`minio-default-credential`** (HIGH): `MINIO_ROOT_USER`/`MINIO_ACCESS_KEY` = `minioadmin`
  PAIRED with `MINIO_ROOT_PASSWORD`/`MINIO_SECRET_KEY` = `minioadmin` (case-insensitive value
  compare; MinIO's documented factory default). Scanned in compose files AND `.env*` files (MinIO
  creds routinely live in an `.env` consumed via compose's `env_file:`).
- **`nacos-default-jwt-secret`** (HIGH): `NACOS_AUTH_TOKEN` (the compose/env var; before Nacos
  2.1.0 the equivalent property is `nacos.core.auth.default.token.secret.key`, from 2.1.0 on
  `nacos.core.auth.plugin.nacos.token.secret.key`, both matched) equal to the exact literal Nacos's
  own docs used as the shipped example prior to 2.2.0.1:
  `SecretKey012345678901234567890123456789012345678901234567890123456789`. Any Nacos server that
  still signs its admin JWTs with this public value lets anyone forge a valid admin token without
  ever authenticating — the mechanism JadePuffer's lateral movement exploited alongside
  CVE-2021-29441 (a related but distinct Nacos AuthFilter bypass; that CVE is a version-floor
  concern, handled by `dependency-version-floor`, not this guard). Scanned in compose/env files.
- **`postgres-default-credential-exposed`** (CRITICAL): `POSTGRES_USER=postgres` PAIRED with
  `POSTGRES_PASSWORD=postgres` (or the same pair literal in a `postgres://`/`postgresql://` DSN)
  — but ONLY when the SAME compose file also publishes a Postgres container port (5432/5433/6543)
  to a non-loopback host interface. See "Why Postgres is scoped to exposure" below. Compose files
  only — a `.env` carries no port-publish evidence to gate on.
- **`grafana-default-credential`** (HIGH): `GF_SECURITY_ADMIN_USER=admin` PAIRED with
  `GF_SECURITY_ADMIN_PASSWORD=admin`. Scanned in compose/env files.
- **`grafana-implicit-default-credential`** (MEDIUM): a compose service running a
  `grafana/grafana[-oss|-enterprise]` image with **NEITHER** `GF_SECURITY_ADMIN_USER` NOR
  `GF_SECURITY_ADMIN_PASSWORD` set anywhere in the file. This IS Grafana's actual behavior — the
  image logs in as `admin`/`admin` when neither variable is set — so silence here is the same
  vulnerability as the explicit-literal case, just without a literal to point at. See "Why the
  Grafana absent case fires at MEDIUM, not HIGH" below. Compose files only (env-var absence has no
  meaning without knowing a Grafana service exists, which requires an `image:` line).

Why Postgres is scoped to exposure, and the other three are not
-----------------------------------------------------------------
The official Postgres image **refuses to start** without `POSTGRES_PASSWORD` set (or an explicit
trust-auth opt-in), so a `postgres`/`postgres` pair in a *local-only* dev compose (never published
past the compose network) is a far lower-risk case than MinIO/Nacos/Grafana, whose images run
happily exposed with their compiled-in defaults untouched. Narrowing the Postgres rule to the
exposed case only (rather than splitting severity) keeps the CRITICAL tier reserved for the exact
JadePuffer shape — "the datastore is reachable AND takes the default password" — instead of
flagging every internal dev Postgres, which would be the same noise source `compose-db-port-exposed`
already avoids by requiring an actual `ports:` publish. A `postgres`/`postgres` pair with no
exposure evidence in the same file is a documented false negative (see "Known bypasses").

Why the Grafana absent case fires at MEDIUM, not HIGH
-------------------------------------------------------
Detecting "Grafana is present AND neither admin var is set anywhere in this file" is a WEAKER
signal than an explicit literal match: the credential could legitimately be supplied through an
`env_file:` this guard doesn't read, a Kubernetes secret mounted as an env var, or a provisioning
script. An explicit `GF_SECURITY_ADMIN_PASSWORD=admin` is unambiguous; "I found no admin-password
var in this file" is not — the guard cannot distinguish "left on default" from "set elsewhere."
MEDIUM keeps the signal visible (silently dropping it entirely misses Grafana's actual most common
misconfiguration) without asserting the same confidence as a literal-value match.

Detection: file-scoped pairing, not per-service-block
--------------------------------------------------------
Unlike `datastore-auth-absent` (which isolates each compose service into its own block before
checking it), this guard searches the WHOLE file for each variable name and pairs whichever
occurrences it finds first — it does not attribute a `MINIO_ROOT_USER` and a `MINIO_ROOT_PASSWORD`
to the SAME service block. This is a deliberate scope narrowing, not an oversight: the variable
names this guard matches (`MINIO_ROOT_USER`, `NACOS_AUTH_TOKEN`, `POSTGRES_PASSWORD`,
`GF_SECURITY_ADMIN_PASSWORD`, …) are specific enough to one service that two DIFFERENT compose
services coincidentally defining both halves of the same pair is a vanishingly unlikely false
positive, and it keeps one shared implementation working uniformly across compose YAML (map and
list env syntax) and flat `.env` files, which have no "service block" concept at all. The
consequence, made explicit and tested (`test_fires_when_pair_split_across_two_compose_services`):
a `MINIO_ROOT_USER=minioadmin` in one service and an unrelated `MINIO_ROOT_PASSWORD=minioadmin` in
a DIFFERENT service of the SAME file still fires — a known, accepted, narrow false-positive
surface, traded for not needing a second YAML block parser. A pair split across two DIFFERENT
FILES is never paired (no cross-file state) — a known false negative.

Suppress an audited case (e.g. an air-gapped internal demo stack) with the file-level pragma:

    # security: allow-default-service-credential
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_dev_compose_file,
    is_nonproduct_path,
    iter_files_named,
    pragma_present,
    read,
    rel,
    strip_hash_comments,
)

_PRAGMA = "# security: allow-default-service-credential"

# Default-CREDENTIAL findings (MinIO / Postgres / Grafana): a login identity left on its factory
# value. A07:2021 (Identification and Authentication Failures) explicitly calls out default
# credentials; CWE-1392 is "Use of Default Credentials" verbatim.
_STANDARDS_CREDENTIAL = ["OWASP:A07", "CWE-1392"]
# The Nacos finding is a hard-coded CRYPTOGRAPHIC SIGNING KEY, not a login identity — A02:2021
# (Cryptographic Failures) + CWE-321 (Use of Hard-coded Cryptographic Key) fit that axis instead.
_STANDARDS_SIGNING_KEY = ["OWASP:A02", "CWE-321"]

# A `NAME: value` / `NAME=value` / `- NAME=value` assignment, anywhere in the file (compose YAML
# map syntax, compose YAML list syntax, or a flat .env line all shscan the same way). `\b` on both
# sides of NAME means a longer identifier that merely contains NAME as a substring — an env-secret
# Docker-secret convention like `MINIO_ROOT_USER_FILE`, or an unrelated `MY_POSTGRES_USER_HASH` —
# does not match (no word-boundary exists between "R" and "_" in "USER_FILE").
# The left boundary is a normal `\b` OR a literal, case-sensitive `-D` immediately before `name`
# (fix — was a disclosed KNOWN GAP): a JVM system-property form ABUTS the property name
# with no delimiter (`-Dnacos.core.auth.plugin.nacos.token.secret.key=...`, "D" then "n" with no
# ordinary word boundary between them), which a bare `\b` can never match. `(?-i:-D)` is scoped
# case-SENSITIVE despite the surrounding `re.IGNORECASE` so only the real JVM flag spelling
# (capital `-D`, never `-d`) counts — deliberately narrow: it does NOT relax the boundary for any
# other abutting character, so an unrelated identifier that merely ends in "D" right before the
# name (`FIELDnacos.core...`) still does not match. The documented env var (`NACOS_AUTH_TOKEN`)
# and a property spelling with any ordinary delimiter before it (a space, a line start, a quote)
# are both matched via the plain `\b` branch as before.
def _var_pattern(name: str) -> re.Pattern[str]:
    return re.compile(
        r"(?:\b|(?<=(?-i:-D)))" + re.escape(name) + r"\b\s*[:=]\s*"
        r"(?:\"(?P<dq>[^\"\n]*)\"|'(?P<sq>[^'\n]*)'|(?P<bare>[^\s,}\"'#]+))",
        re.IGNORECASE,
    )


def _find(text: str, names: list[str]) -> tuple[str, str, int] | None:
    """First occurrence, anywhere in `text`, of any of `names` — returns
    `(matched_name, value,1_based_line_no)`, or None. `value` has quotes stripped."""
    for name in names:
        m = _var_pattern(name).search(text)
        if m is None:
            continue
        value = m.group("dq") if m.group("dq") is not None else (
            m.group("sq") if m.group("sq") is not None else m.group("bare")
        )
        line_no = text.count("\n", 0, m.start()) + 1
        return name, value or "", line_no
    return None


def _matches(value: str, expected: str) -> bool:
    """Case-insensitive exact match against a known default literal. Deliberately NOT a substring
    or prefix match: `MINIO_ROOT_PASSWORD=my-real-password` must never fire (only the literal
    known-default value does), and an env-var reference (`${MINIO_PASS}`) is captured verbatim as
    the string `${MINIO_PASS}` — it can never equal the default literal, so it silently and
    correctly never fires as a finding (an external secret reference is not itself a finding)."""
    return value.strip().strip("'\"").lower() == expected.lower()


# --- MinIO ----------------------------------------------------------------------------------
_MINIO_USER_VARS = ["MINIO_ROOT_USER", "MINIO_ACCESS_KEY"]
_MINIO_PASS_VARS = ["MINIO_ROOT_PASSWORD", "MINIO_SECRET_KEY"]
_MINIO_DEFAULT = "minioadmin"

# --- Nacos ------------------------------------------------------------------------------------
# The env var (docker/nacos-docker convention) and both historical property-file spellings of the
# JWT signing-key setting (pre-2.1.0 vs. 2.1.0+); all three are matched so either config style fires.
_NACOS_TOKEN_VARS = [
    "NACOS_AUTH_TOKEN",
    "nacos.core.auth.plugin.nacos.token.secret.key",
    "nacos.core.auth.default.token.secret.key",
]
_NACOS_DEFAULT_SECRET = "SecretKey012345678901234567890123456789012345678901234567890123456789"  # nosec B105 (the vendor default this guard detects, not a credential in use)

# --- Postgres --------------------------------------------------------------------------------
_POSTGRES_USER_VARS = ["POSTGRES_USER"]
_POSTGRES_PASS_VARS = ["POSTGRES_PASSWORD"]
_POSTGRES_DEFAULT = "postgres"
_PG_DSN = re.compile(r"postgres(?:ql)?://postgres:postgres@", re.IGNORECASE)
_PG_CONTAINER_PORTS = {"5432", "5433", "6543"}
_LOCALHOST_HOSTS = re.compile(r"^(?:127\.0\.0\.1|::1|localhost)$", re.IGNORECASE)
# Short-syntax `ports:` block only (conservative seed, same documented gap as
# `compose-db-port-exposed`'s own long-syntax miss): the CONTAINER (right-most) port identifies
# the service, so a host remap (`15432:5432`) still counts as exposed.
_PORTS_KEY = re.compile(r"^(\s*)ports\s*:\s*(?:#.*)?$")
_SHORT_ENTRY = re.compile(r"^\s*-\s*['\"]?([0-9a-zA-Z.:_-]+)['\"]?\s*(?:#.*)?$")

# --- Grafana -----------------------------------------------------------------------------------
_GRAFANA_USER_VARS = ["GF_SECURITY_ADMIN_USER"]
_GRAFANA_PASS_VARS = ["GF_SECURITY_ADMIN_PASSWORD"]
# Docker/Kubernetes secrets-FILE convention (`GF_SECURITY_ADMIN_PASSWORD__FILE: /run/secrets/...`)
# — Grafana's own hardened pattern: read the value from a mounted secret file instead of an inline
# literal. `_var_pattern`'s `\b...\b` boundary means this name is invisible to `_GRAFANA_PASS_VARS`
# (a `_` right after `PASSWORD` is a word character, so no boundary), so `_grafana_absent` would
# otherwise read "no admin-password var set" and flag the guard's OWN recommended pattern as if it
# were an absent credential — reproduced live (review M4). Presence of the `__FILE` variant means
# the credential IS externally managed; treat it the same as a real value being set (don't flag).
_GRAFANA_USER_FILE_VARS = ["GF_SECURITY_ADMIN_USER__FILE"]
_GRAFANA_PASS_FILE_VARS = ["GF_SECURITY_ADMIN_PASSWORD__FILE"]
_GRAFANA_DEFAULT = "admin"
_IMAGE_LINE = re.compile(r"^[^\S\n]*image\s*:\s*['\"]?([^'\"\n#]+)", re.MULTILINE)
_GRAFANA_IMAGE = re.compile(r"(?:^|/)grafana/grafana(?:-oss|-enterprise)?(?::|/|@|$)", re.IGNORECASE)


def _has_exposed_postgres_port(text: str) -> bool:
    """True if `text` (a compose file) publishes a Postgres container port (5432/5433/6543) to a
    non-loopback host interface, via the compose short-syntax `ports:` list. Adapted from
    `compose-db-port-exposed`'s own short-syntax branch; the long-syntax mapping
    (`- target:`/`host_ip:` keys) is intentionally out of scope here too — same documented,
    conservative seed that guard itself ships with."""
    in_ports = False
    ports_indent = -1
    for line in text.splitlines():
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        key = _PORTS_KEY.match(line)
        if key:
            in_ports, ports_indent = True, len(key.group(1))
            continue
        if not in_ports:
            continue
        if not line.strip().startswith("-"):
            if indent <= ports_indent:
                in_ports = False
            continue
        m = _SHORT_ENTRY.match(line)
        if m is None:
            continue
        parts = m.group(1).split(":")
        if len(parts) == 3:
            host, container = parts[0], parts[2]
        elif len(parts) in (1, 2):
            host, container = None, parts[-1]
        else:
            continue
        if container not in _PG_CONTAINER_PORTS:
            continue
        if host and _LOCALHOST_HOSTS.match(host):
            continue
        return True
    return False


def _has_grafana_service(text: str) -> int | None:
    """1-based line number of the first `image:` line naming a Grafana image, or None."""
    for m in _IMAGE_LINE.finditer(text):
        if _GRAFANA_IMAGE.search(m.group(1).strip()):
            return text.count("\n", 0, m.start()) + 1
    return None


class DefaultServiceCredentialGuard(Guard):
    id = "default-service-credential"
    title = "Deployed service left on a well-known factory-default credential"
    area = "Secrets"

    canary_plant = CanaryPlant(
        files={
            "docker-compose.minio.yml": (
                "services:\n  minio:\n    image: minio/minio\n    environment:\n"
                "      MINIO_ROOT_USER: minioadmin\n      MINIO_ROOT_PASSWORD: minioadmin\n"
            ),
        },
        expects=frozenset({"default-service-credential/minio-default-credential"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "docker" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml"):
            if is_dev_compose_file(f.name):
                continue
            rel_path = rel(root, f)
            if is_nonproduct_path(rel_path, profile.archive_segments):
                continue
            raw = read(f)
            if pragma_present(_PRAGMA, raw, dialect="yaml"):
                continue
            out.extend(self._scan_compose(strip_hash_comments(raw), rel_path))
        # A real MinIO/Nacos/Grafana .env is usually gitignored, so scan past .gitignore — but
        # the shared walk excludes (vendored dirs, nested worktrees) still apply.
        for f in iter_files_named(root, ".env", ".env.*", respect_gitignore=False):
            rel_path = rel(root, f)
            if is_nonproduct_path(rel_path, profile.archive_segments):
                continue
            raw = read(f)
            if pragma_present(_PRAGMA, raw, dialect=comment_dialect_for(f)):
                continue
            out.extend(self._scan_env(strip_hash_comments(raw), rel_path))
        return out

    def _scan_compose(self, text: str, location: str) -> list[Finding]:
        out: list[Finding] = []
        out.extend(self._minio(text, location))
        out.extend(self._nacos(text, location))
        out.extend(self._grafana_explicit(text, location))
        out.extend(self._grafana_absent(text, location))
        out.extend(self._postgres(text, location))
        return out

    def _scan_env(self, text: str, location: str) -> list[Finding]:
        out: list[Finding] = []
        out.extend(self._minio(text, location))
        out.extend(self._nacos(text, location))
        out.extend(self._grafana_explicit(text, location))
        return out

    # --- per-service checks ------------------------------------------------------------------

    def _minio(self, text: str, location: str) -> list[Finding]:
        u = _find(text, _MINIO_USER_VARS)
        p = _find(text, _MINIO_PASS_VARS)
        if u is None or p is None:
            return []
        if not (_matches(u[1], _MINIO_DEFAULT) and _matches(p[1], _MINIO_DEFAULT)):
            return []
        line = min(u[2], p[2])
        return [Finding(
            check_id=self.id,
            severity="high",
            title="MinIO left on its factory-default credential",
            location=f"{location}:{line}",
            message=(
                f"`{u[0]}`/`{p[0]}` are set to `minioadmin`/`minioadmin` — MinIO's own "
                "documented factory-default credential pair. JadePuffer's lateral-movement stage "
                "(Sysdig) logged into MinIO with exactly this pair and read every bucket it found."
            ),
            remediation=(
                "Set MINIO_ROOT_USER/MINIO_ROOT_PASSWORD to a generated, unique credential (or "
                "load them from a secrets manager) before the service is ever started — MinIO "
                "does not force a change on first login. Suppress an audited air-gapped demo "
                "with `# security: allow-default-service-credential`."
            ),
            rule="default-service-credential/minio-default-credential",
            standards=list(_STANDARDS_CREDENTIAL),
        )]

    def _nacos(self, text: str, location: str) -> list[Finding]:
        hit = _find(text, _NACOS_TOKEN_VARS)
        if hit is None:
            return []
        name, value, line = hit
        if value.strip() != _NACOS_DEFAULT_SECRET:
            return []
        return [Finding(
            check_id=self.id,
            severity="high",
            title="Nacos left on its publicly documented default JWT signing secret",
            location=f"{location}:{line}",
            message=(
                f"`{name}` is set to the exact literal Nacos's own documentation shipped as an "
                "example prior to 2.2.0.1. Anyone who knows this public value can forge a valid "
                "admin JWT for this Nacos server without authenticating — the mechanism "
                "JadePuffer's lateral-movement stage used, alongside the related Nacos AuthFilter "
                "bypass (CVE-2021-29441)."
            ),
            remediation=(
                "Generate a unique Base64-encoded secret at least 32 bytes long "
                '(`openssl rand -base64 32`) and set it as NACOS_AUTH_TOKEN / '
                "nacos.core.auth.plugin.nacos.token.secret.key before exposing the service. "
                "Suppress an audited air-gapped demo with `# security: allow-default-service-credential`."
            ),
            rule="default-service-credential/nacos-default-jwt-secret",
            standards=list(_STANDARDS_SIGNING_KEY),
        )]

    def _grafana_explicit(self, text: str, location: str) -> list[Finding]:
        u = _find(text, _GRAFANA_USER_VARS)
        p = _find(text, _GRAFANA_PASS_VARS)
        if u is None or p is None:
            return []
        if not (_matches(u[1], _GRAFANA_DEFAULT) and _matches(p[1], _GRAFANA_DEFAULT)):
            return []
        line = min(u[2], p[2])
        return [self._grafana_finding(location, line, "high", explicit=True)]

    def _grafana_absent(self, text: str, location: str) -> list[Finding]:
        # Only meaningful when BOTH admin vars are entirely absent from the file — a partial
        # config (one var set, one not) is ambiguous (the other may come from an env_file this
        # guard cannot read) and deliberately left silent rather than guessed at. The `__FILE`
        # secrets-file variant counts as "set" here too — it means the credential is externally
        # managed, not that no credential handling exists.
        if (
            _find(text, _GRAFANA_USER_VARS) is not None
            or _find(text, _GRAFANA_PASS_VARS) is not None
            or _find(text, _GRAFANA_USER_FILE_VARS) is not None
            or _find(text, _GRAFANA_PASS_FILE_VARS) is not None
        ):
            return []
        grafana_line = _has_grafana_service(text)
        if grafana_line is None:
            return []
        return [self._grafana_finding(location, grafana_line, "medium", explicit=False)]

    def _grafana_finding(self, location: str, line: int, severity: Severity, *, explicit: bool) -> Finding:
        if explicit:
            message = (
                "`GF_SECURITY_ADMIN_USER`/`GF_SECURITY_ADMIN_PASSWORD` are both set to `admin` — "
                "Grafana's own factory-default credential pair."
            )
            rule = "default-service-credential/grafana-default-credential"
        else:
            message = (
                "This compose service runs a Grafana image with neither "
                "`GF_SECURITY_ADMIN_USER` nor `GF_SECURITY_ADMIN_PASSWORD` set anywhere in the "
                "file. That is not a missing setting — it IS Grafana's documented default: the "
                "image logs in as `admin`/`admin` when neither variable is configured."
            )
            rule = "default-service-credential/grafana-implicit-default-credential"
        return Finding(
            check_id=self.id,
            severity=severity,
            title="Grafana left on its factory-default admin credential",
            location=f"{location}:{line}",
            message=message,
            remediation=(
                "Set GF_SECURITY_ADMIN_USER/GF_SECURITY_ADMIN_PASSWORD to a generated, unique "
                "credential (or load them from a secrets manager) before the service is ever "
                "started. Suppress an audited air-gapped demo with "
                "`# security: allow-default-service-credential`."
            ),
            rule=rule,
            standards=list(_STANDARDS_CREDENTIAL),
        )

    def _postgres(self, text: str, location: str) -> list[Finding]:
        # Scoped to the exposed case only — see the module docstring's "Why Postgres is scoped
        # to exposure" for why this is a narrowing rather than a severity split.
        if not _has_exposed_postgres_port(text):
            return []
        u = _find(text, _POSTGRES_USER_VARS)
        p = _find(text, _POSTGRES_PASS_VARS)
        pair_hit = u is not None and p is not None and _matches(u[1], _POSTGRES_DEFAULT) and _matches(
            p[1], _POSTGRES_DEFAULT
        )
        dsn_m = _PG_DSN.search(text)
        if not pair_hit and dsn_m is None:
            return []
        line = min(u[2], p[2]) if pair_hit and u is not None and p is not None else (
            text.count("\n", 0, dsn_m.start()) + 1 if dsn_m is not None else 1
        )
        return [Finding(
            check_id=self.id,
            severity="critical",
            title="Internet-reachable Postgres left on its factory-default credential",
            location=f"{location}:{line}",
            message=(
                "This compose file both publishes a Postgres container port "
                "(5432/5433/6543) to a non-loopback host interface AND sets "
                "POSTGRES_USER/POSTGRES_PASSWORD to `postgres`/`postgres` (or the same pair "
                "literal in a connection string) — a database reachable from the whole internet "
                "with the well-known default login. This is the exact JadePuffer shape: Postgres "
                "was the credential-harvesting target AND the datastore later encrypted/dropped."
            ),
            remediation=(
                "Bind the datastore to loopback only (see `compose-db-port-exposed`) AND set a "
                "generated, unique POSTGRES_PASSWORD regardless — defense in depth against any "
                "other exposure path. Suppress an audited case with "
                "`# security: allow-default-service-credential`."
            ),
            rule="default-service-credential/postgres-default-credential-exposed",
            standards=list(_STANDARDS_CREDENTIAL),
        )]
