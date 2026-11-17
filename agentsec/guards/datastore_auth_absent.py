"""Guard: Redis/MongoDB service configured without authentication (docker-compose).

The defense-in-depth partner to `compose-db-port-exposed`. That guard catches a datastore
port PUBLISHED past UFW (the exposure); this one catches a datastore with no password at
all, so a port that leaks by ANY path (docker-compose long-syntax `ports:`, a
`userland-proxy: false` host, a cloud-firewall slip) is not an instant data-loss wipe. The
real incident behind both: an unauthenticated Redis/Mongo reachable from the internet was
found by a bot and wiped in seconds.

Fires HIGH on a docker-compose service whose image (or, when there is no `image:`, its
service name) identifies Redis/Valkey or MongoDB, and whose service block carries NO auth
signal:

- **Redis authed** when the block has `--requirepass` (a `command:` flag), a `requirepass <value>`
  conf line, a `REDIS_ARGS` containing `requirepass`, or an ACL file (`--aclfile`/`REDIS_ACLFILE`).
  A `REDIS_PASSWORD` env counts ONLY on a Bitnami image — the official Docker Hub `redis`/`valkey`
  images never read that variable, so it does not authenticate them (#358 review).
- **Mongo authed** when the block has `MONGO_INITDB_ROOT_USERNAME`/`_PASSWORD` (official), `--auth`,
  `--keyFile`, `security.authorization`, or (Bitnami only) `MONGODB_ROOT_PASSWORD`.
- Env-var signals require a NON-EMPTY value, so an explicitly-empty `MONGO_INITDB_ROOT_PASSWORD:`
  still fires. Comments are stripped before matching, so a commented-out token is not a signal.
- Bitnami's `ALLOW_EMPTY_PASSWORD=yes` is an explicit auth-OFF switch: it always fires.

Postgres/MySQL are out of scope (their official images refuse to start without a password).
Suppress an intentionally-unauthenticated internal cache with the file-level pragma:

    # security: allow-unauthenticated-datastore

Conservative seed (stdlib line parser; PyYAML is dev-only). Known false-negatives, documented
in the design doc: a password supplied via an externally-mounted `redis.conf`/`mongod.conf`
(the guard cannot read the referenced file), injected at runtime by a secrets manager /
entrypoint, or hidden inside a YAML anchor/`extends:` the flat line parser does not resolve.

**Checklist item:** §7 `7-datastore-auth-enabled`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_dev_compose_file,
    iter_files_named,
    pragma_present,
    read,
    rel,
    strip_hash_comments,
)

_PRAGMA = "# security: allow-unauthenticated-datastore"

# Publishing/running a passwordless datastore is a deploy misconfiguration (A05); the
# container-hardening angle is CIS Docker. Mirrors `compose-db-port-exposed`.
_STANDARDS = ["OWASP:A05", "CIS:Docker"]

# Engine identification against an `image:` value (tag/digest included). The `(^|/)name(:|/|@|$)`
# shape matches `redis`, `redis:7`, `redis@sha256:...`, `bitnami/redis`, `valkey/valkey`, `mongo`,
# `bitnami/mongodb` while EXCLUDING the UI sidecars `mongo-express` / `redis-commander` (the char
# after the name is `-`, not `:`/`/`/`@`/end), which have their own auth and are not the datastore.
# For Mongo we match the current official image *name* `mongodb-community-server` (and `mongod`)
# too, not only a `mongo` path segment, so a private re-tag like `someorg/mongodb-community-server`
# is still classified while `mongodb-exporter` / `mongo-express` stay excluded (the `-` terminator
# guards the FP boundary) (#359).
_REDIS_IMAGE = re.compile(r"(?:^|/)(?:redis|valkey)(?::|/|@|$)", re.IGNORECASE)
_MONGO_IMAGE = re.compile(
    r"(?:^|/)(?:mongo(?:db)?|mongodb-community-server|mongod)(?::|/|@|$)", re.IGNORECASE
)

_REDIS_NAMES = {"redis", "valkey"}
_MONGO_NAMES = {"mongo", "mongodb"}

# A Bitnami-flavored image (`bitnami/redis`, `docker.io/bitnami/mongodb`, ...). Bitnami's images read
# `REDIS_PASSWORD` / `MONGODB_ROOT_PASSWORD` env vars; the official Docker Hub images do NOT (they need
# `--requirepass` / `MONGO_INITDB_ROOT_*`), so those env vars only count as auth on a Bitnami image.
_BITNAMI = re.compile(r"(?:^|/)bitnami/", re.IGNORECASE)

# A NON-EMPTY value after `:` or `=`: a quoted string with >=1 inner char, or an unquoted token whose
# first char is neither quote nor space. Rejects an empty value including the quoted-empty `""` / `''`
# form (the opening quote alone must not read as "a value present") (#358 re-review).
_V = r"""\s*[:=]\s*(?:"[^"]+"|'[^']+'|[^\s'"]\S*)"""

# Auth signals that work on ANY image. Env-var tokens require a non-empty value (`_V`) so an
# explicitly-empty `MONGO_INITDB_ROOT_PASSWORD:` (or `: ""`) still fires. Command flags (`--auth`,
# `--requirepass`) imply auth by their presence. Comments are stripped before matching (see `_scan`).
_REDIS_AUTH = re.compile(
    r"--requirepass\b|\brequirepass\s+\S|\bREDIS_ARGS\b[^\n]*requirepass|--aclfile\b"
    r"|\bREDIS_ACLFILE\b" + _V,
    re.IGNORECASE,
)
_MONGO_AUTH = re.compile(
    r"\bMONGO_INITDB_ROOT_USERNAME\b" + _V + r"|\bMONGO_INITDB_ROOT_PASSWORD\b" + _V
    + r"|--auth\b|--keyFile\b|security\.authorization|\bauthorization\s*:\s*enabled\b",
    re.IGNORECASE,
)
# Bitnami-only env-var auth (a non-empty password). Only trusted when the image is Bitnami-flavored.
_REDIS_AUTH_BITNAMI = re.compile(r"\bREDIS_PASSWORD\b" + _V, re.IGNORECASE)
_MONGO_AUTH_BITNAMI = re.compile(r"\bMONGODB_ROOT_PASSWORD\b" + _V, re.IGNORECASE)

# Bitnami's explicit "run without a password" switch — auth is off regardless of anything else.
_ALLOW_EMPTY = re.compile(r"\bALLOW_EMPTY_PASSWORD\b\s*[:=]\s*['\"]?yes", re.IGNORECASE)

_IMAGE_LINE = re.compile(r"^[^\S\n]*image\s*:\s*['\"]?([^'\"\n#]+)", re.MULTILINE)
_SERVICES_KEY = re.compile(r"(\s*)services\s*:\s*(?:#.*)?$")
_SERVICE_HEADER = re.compile(r"\s*([A-Za-z0-9._-]+)\s*:\s*(?:#.*)?$")
# A one-line flow-mapping service: `redis: {image: "redis:7", command: "..."}`. The block-style
# `_SERVICE_HEADER` anchors end-of-line right after the colon, so a flow service needs its own
# branch or it is invisible to the parser. The `{...}` body is normalized (`_normalize_flow`) so
# the same image/auth regexes that scan a block service also scan a flow one (#359).
_FLOW_HEADER = re.compile(r"\s*([A-Za-z0-9._-]+)\s*:\s*(\{.*)$")


def _iter_services(text: str) -> list[tuple[str, int, str]]:
    """Split a compose file into `(service_name, header_line_no, block_text)` tuples.

    Line-based (no PyYAML at runtime). Finds the top-level `services:` key, takes the indent of
    the first service header as the service-indent, and groups each service header with the lines
    beneath it until the next same-indent header or a dedent out of the `services:` block.
    """
    lines = text.splitlines()
    services_indent: int | None = None
    start = 0
    for idx, line in enumerate(lines):
        m = _SERVICES_KEY.match(line)
        if m:
            services_indent = len(m.group(1))
            start = idx + 1
            break
    if services_indent is None:
        return []

    out: list[tuple[str, int, str]] = []
    service_indent: int | None = None
    name: str | None = None
    header_no = 0
    buf: list[str] = []
    for idx in range(start, len(lines)):
        raw = lines[idx]
        if not raw.strip():
            if name is not None:
                buf.append(raw)
            continue
        indent = len(raw) - len(raw.lstrip())
        if indent <= services_indent:
            break  # dedented out of the services: block
        if service_indent is None:
            service_indent = indent
        if indent == service_indent:
            header = _SERVICE_HEADER.match(raw)
            if header:
                if name is not None:
                    out.append((name, header_no, "\n".join(buf)))
                name, header_no, buf = header.group(1), idx + 1, [raw]
                continue
            flow = _FLOW_HEADER.match(raw)
            if flow and _flow_is_closed(flow.group(2)):
                # A one-line flow-mapping service is self-contained: flush any pending block
                # service, emit this one from its normalized body, and reset state so a following
                # line does not attach to it (#359).
                if name is not None:
                    out.append((name, header_no, "\n".join(buf)))
                out.append((flow.group(1), idx + 1, _normalize_flow(flow.group(2))))
                name, header_no, buf = None, 0, []
                continue
            if flow:
                # A MULTI-line flow mapping (`redis: {` with no closing `}` on this line): the flat
                # line parser cannot assemble the body, so we must NOT treat it as a complete
                # service. Doing so would emit an empty body and mis-fire "no auth" on the canonical
                # name while the real `--requirepass`/`MONGO_INITDB_ROOT_PASSWORD` sits on a
                # following line — an active false positive, not the silent miss the earlier note
                # implied (#359 review). Flush any pending block and enter a dead zone (`name=None`)
                # so the following body lines attach to nothing: unscanned (the disclosed miss).
                if name is not None:
                    out.append((name, header_no, "\n".join(buf)))
                name, header_no, buf = None, 0, []
                continue
        if name is not None:
            buf.append(raw)
    if name is not None:
        out.append((name, header_no, "\n".join(buf)))
    return out


def _flow_is_closed(body: str) -> bool:
    """True when a flow-mapping body opened on the header line also CLOSES on it (its braces
    balance), i.e. a self-contained one-line service. `body` always starts with `{`, so an equal
    `{`/`}` count means the `}` is present on this physical line. A `redis: {` whose `}` lands on a
    later line is a multi-line flow mapping the flat parser does not assemble — treating it as
    complete emits an empty body and mis-fires "no auth" (#359 review); the caller falls through to
    unscanned instead. (Braces inside a quoted value are a rare corner the line parser accepts.)"""
    return body.count("{") <= body.count("}")


def _normalize_flow(body: str) -> str:
    """Flatten a one-line flow-mapping service body (`{image: "redis:7", command: "..."}`) into
    newline-separated `key: value` lines so the block-oriented image/auth regexes scan it (#359).
    Braces and commas become newlines; comment stripping still happens later in `_scan`."""
    return re.sub(r"[{},]", "\n", body)


def _engine(name: str, block: str) -> tuple[str | None, str]:
    """Classify a service block as ('redis'|'mongo'|None, image). Prefer the `image:` (lower FP);
    fall back to the service name only when the service declares no image (e.g. a `build:`)."""
    img_m = _IMAGE_LINE.search(block)
    if img_m:
        img = img_m.group(1).strip()
        if _REDIS_IMAGE.search(img):
            return "redis", img
        if _MONGO_IMAGE.search(img):
            return "mongo", img
        return None, img  # has an image, but not a datastore image -> not ours
    low = name.lower()
    if low in _REDIS_NAMES:
        return "redis", ""
    if low in _MONGO_NAMES:
        return "mongo", ""
    return None, ""


class DatastoreAuthAbsentGuard(Guard):
    id = "datastore-auth-absent"
    title = "Datastore (Redis/MongoDB) running without authentication"
    area = "Database"

    # docker-compose.cache.yml: Redis with NO authentication -> fires
    # datastore-auth-absent/no-authentication (HIGH). Must NOT contain: --requirepass, requirepass,
    # REDIS_PASSWORD, # security: allow-unauthenticated-datastore (any silences the guard). No ports:
    # so compose-db-port-exposed stays silent; no volume/MCP so ai-docker stays silent.
    canary_plant = CanaryPlant(
        files={
            "docker-compose.cache.yml": (
                "version: '3'\n"
                "services:\n"
                "  redis:\n"
                "    image: redis:7\n"
            ),
        },
        expects=frozenset({"datastore-auth-absent/no-authentication"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "docker" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml"):
            # A `*.dev.yml` / `*.local.yml` compose is a LOCAL-development environment, where an
            # unauthenticated loopback datastore is conventional and low-risk — keep firing on the
            # prod/base compose (round-2 §H.2). Guard-local, not the shared non-product list. SHARED with
            # `compose-db-port-exposed` so the two mirrors cannot disagree about what a dev compose
            # is: reporting "the port is published" while suppressing "and it has no password" is
            # worse than either answer alone (#484 review).
            if is_dev_compose_file(f.name):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="yaml"):
                continue
            out.extend(self._scan(text, rel(root, f)))
        return out

    def _scan(self, text: str, location: str) -> list[Finding]:
        out: list[Finding] = []
        for name, line_no, block in _iter_services(text):
            block = strip_hash_comments(block)  # a commented-out token is not an auth signal (#358/#362)
            engine, image = _engine(name, block)
            if engine is None:
                continue
            bitnami = bool(_BITNAMI.search(image))
            if engine == "redis":
                authed = bool(_REDIS_AUTH.search(block)) or (bitnami and bool(_REDIS_AUTH_BITNAMI.search(block)))
            else:
                authed = bool(_MONGO_AUTH.search(block)) or (bitnami and bool(_MONGO_AUTH_BITNAMI.search(block)))
            # ALLOW_EMPTY_PASSWORD=yes is an explicit auth-off switch and overrides any password signal.
            if authed and not _ALLOW_EMPTY.search(block):
                continue
            label = "Redis" if engine == "redis" else "MongoDB"
            how = (
                "a `--requirepass` flag (or a REDIS_PASSWORD env on a Bitnami image)"
                if engine == "redis"
                else "MONGO_INITDB_ROOT_USERNAME/PASSWORD env or a `--auth` flag"
            )
            out.append(Finding(
                check_id=self.id,
                severity="high",
                title=f"{label} service has no authentication configured",
                location=f"{location}:{line_no}",
                message=(
                    f"The docker-compose `{name}` service runs {label} with no authentication "
                    f"configured (no {how}). If the port ever becomes reachable — a long-syntax "
                    "publish, a `userland-proxy: false` host where the DNAT rule bypasses UFW, or "
                    "a cloud-firewall mistake — an unauthenticated datastore is a one-request "
                    "data-loss target (a bot can read or wipe it instantly)."
                ),
                remediation=(
                    "Require a password even on an internal network (defense in depth). Redis: "
                    "`command: redis-server --requirepass \"${REDIS_PASSWORD}\"`. MongoDB: set "
                    "`MONGO_INITDB_ROOT_USERNAME` + `MONGO_INITDB_ROOT_PASSWORD` (or run with "
                    "`--auth`). Suppress an audited internal-only cache with "
                    "`# security: allow-unauthenticated-datastore`."
                ),
                rule="datastore-auth-absent/no-authentication",
                standards=list(_STANDARDS),
            ))
        return out
