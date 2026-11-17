"""The single network-egress chokepoint (G5, tiered) — see
`docs/knowledge/rfc-network-egress-policy.md`.

agentsec's egress is **off by default, opt-in per tier, routed through THIS one module,
and disclosed** via a manifest that says exactly what leaves the machine, to where, and
why. This is the **only** module under `agentsec/` permitted to import
`urllib`/`socket`/`http` — `tests/test_net_sandbox.py` enforces that (the inverse of the
guard-sandbox import scan). `--kev`/`deps-monitor` import THIS, never `urllib` directly.

**Tiers** (by what leaves your perimeter):
  - **0 — offline (DEFAULT):** no first-party egress.
  - **1 — advisory fetch:** public vulnerability data; at most your *dependency names* leave.
  - **2 — scan-data egress:** findings / code structure to a third party (consent-gated).

**Resolution precedence:** `DO_NOT_TRACK=1` (force 0) > `--network` (CLI) > `AGENTSEC_NETWORK`
env > `.agentsec/network.json` / `[tool.agentsec.network]` config > default **0**. Tiers are
monotonic (2 ⇒ 1). Runtime is stdlib-only; nothing here performs I/O at import time.

**Error contract:** a transport failure leaves this module as an `OSError`, which is what every
caller's except tuple assumes. `http.client` raises a truncated or malformed response as an
`HTTPException`, which is not an `OSError`, and urllib does not wrap it, so the boundary translates
it into `ProtocolError` (a `urllib.error.URLError`) on the way out (#976).
"""
from __future__ import annotations

import http.client
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

DEFAULT_TIER = 0
_VALID_TIERS = (0, 1, 2)


class EgressRefused(RuntimeError):
    """A network call was requested above the active tier (or without Tier-2 consent)."""


class ProtocolError(urllib.error.URLError):
    """A truncated or malformed HTTP response, or a URL `http.client` cannot use (#976).

    `http.client` raises these as `HTTPException`, which is not an `OSError`, and `urlopen` does
    not wrap them, so they used to escape every caller's `(OSError, ...)` tuple. A `URLError`, and
    so an `OSError`, on purpose: the Go-OSV runner's tuples catch `URLError` with no `OSError` rung,
    and `deps_apply.classify` reads it as a transient network error. The message names the stdlib
    class only, never its text: that is the server-chosen status line or a page-supplied URL, and
    callers interpolate the error into terminal-facing reasons."""


# ---------------------------------------------------------------------------
# Tier resolution
# ---------------------------------------------------------------------------

def _truthy(v: object) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


def parse_tier(value: object) -> int:
    """`'tier1'` / `'1'` / `1` → 1; anything unrecognized → 0 (fail-closed to offline)."""
    s = str(value).strip().lower().removeprefix("tier").strip()
    return int(s) if s in {"0", "1", "2"} else 0


def resolve_tier(
    *, config_tier: int | None = None, cli: object = None, env: dict[str, str] | None = None
) -> int:
    """The active tier, honoring the precedence. `DO_NOT_TRACK=1` always wins → 0."""
    environ = env if env is not None else dict(os.environ)
    if _truthy(environ.get("DO_NOT_TRACK")):
        return 0
    if cli is not None:
        return parse_tier(cli)
    if environ.get("AGENTSEC_NETWORK"):
        return parse_tier(environ["AGENTSEC_NETWORK"])
    if config_tier is not None and config_tier in _VALID_TIERS:
        return config_tier
    return DEFAULT_TIER


# ---------------------------------------------------------------------------
# Disclosure manifest
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EgressOp:
    """One disclosed network operation: what leaves, to where, at which tier."""

    feature: str   # "--kev" | "deps-monitor" | "pip-audit" | …
    dest: str      # "www.cisa.gov"
    sends: str     # human description of what is sent
    tier: int


@dataclass
class Manifest:
    """Collects the egress operations for a run; rendered before any non-Tier-0 call."""

    tier: int = 0
    ops: list[EgressOp] = field(default_factory=list)

    def record(self, op: EgressOp) -> None:
        if not any(o == op for o in self.ops):
            self.ops.append(op)

    def render(self) -> str:
        head = f"agentsec network policy: TIER {self.tier}"
        if not self.ops:
            return f"{head} — offline; nothing leaves your machine."
        w_f = max(len(o.feature) for o in self.ops)
        w_d = max(len(o.dest) for o in self.ops)
        lines = [head]
        for o in sorted(self.ops, key=lambda x: (-x.tier, x.feature)):
            lines.append(f"  {o.feature:<{w_f}}  → {o.dest:<{w_d}}  sends: {o.sends}  [tier {o.tier}]")
        lines.append("Set DO_NOT_TRACK=1 or `--network tier0` to disable all of the above.")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# The boundary (the ONLY urllib in agentsec/)
# ---------------------------------------------------------------------------

def get(
    url: str, *, tier_required: int, sends: str, feature: str, tier: int,
    body: bytes | None = None, manifest: Manifest | None = None, timeout: int = 20,
    headers: dict[str, str] | None = None,
) -> bytes:
    """Perform (or refuse) a network GET/POST, recording it in the manifest first.

    Refuses with `EgressRefused` when the active `tier` is below `tier_required` — so a
    Tier-0 run never egresses. `dest` is derived from `url` for the disclosure. `headers`
    augments the defaults (e.g. an `Authorization` token for an authenticated public API)."""
    dest = urllib.parse.urlsplit(url).hostname or url
    if manifest is not None:
        manifest.record(EgressOp(feature=feature, dest=dest, sends=sends, tier=tier_required))
    if tier < tier_required:
        raise EgressRefused(
            f"{feature} needs network tier {tier_required}, but the active tier is {tier}. "
            f"Enable with `--network tier{tier_required}` (or AGENTSEC_NETWORK=tier{tier_required} / "
            f".agentsec/network.json). DO_NOT_TRACK=1 forces tier 0."
        )
    return _raw_request(url, body=body, timeout=timeout, headers=headers)


def _raw_request(
    url: str, *, body: bytes | None = None, timeout: int = 20,
    headers: dict[str, str] | None = None,
) -> bytes:
    hdrs = {"User-Agent": "agentsec", "Accept": "application/json"}
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, headers=hdrs)  # noqa: S310 (fixed https hosts)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310
            data = resp.read()
    # The OSError rung comes first: `RemoteDisconnected` is both an OSError and an HTTPException,
    # and as an OSError it already meets the contract, so it keeps its type and message.
    except OSError:
        raise
    except http.client.HTTPException as e:
        raise _protocol_error(e) from e
    return data if isinstance(data, bytes) else bytes(data)


def _protocol_error(e: http.client.HTTPException) -> ProtocolError:
    what = "invalid URL" if isinstance(e, http.client.InvalidURL) else "malformed HTTP response"
    return ProtocolError(f"{what} ({type(e).__name__})")


# Low-level primitives for the **explicitly-networked commands** (`setup` downloads pinned
# binaries; `live` probes a running target; `deps-monitor` checks our own pins). Invoking
# those commands IS the opt-in, so they use these directly — but through net.py, so it stays
# the single egress importer. (First-party *advisory* fetches like `--kev` use `get()`, which
# is tier-checked + disclosed.)
Request = urllib.request.Request


class _Response:
    """The response `urlopen` returns, with `read()` held to the error contract.

    The caller reads the body outside this module, so an `IncompleteRead` or an over-long chunk-size
    line raised by that read has to be translated here. Only `read()` is translated. `readline()` and
    `readinto()` forward to the raw response through `__getattr__` untranslated, and iteration is
    not supported at all (`TypeError`: Python looks `__iter__` up on the type, never through
    `__getattr__`). No caller uses any of them today; one that needs one adds a translating method
    here first. Context management delegates, and every other attribute (`status`, `headers`,
    `getcode()`, ...) forwards unchanged."""

    def __init__(self, raw: Any) -> None:
        self._raw = raw

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._raw.__exit__(*exc_info)

    def read(self, amt: int | None = None) -> bytes:
        try:
            data: bytes = self._raw.read() if amt is None else self._raw.read(amt)
        except OSError:
            raise
        except http.client.HTTPException as e:
            raise _protocol_error(e) from e
        return data

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


def urlopen(url_or_req: str | Request, *, timeout: int = 20) -> Any:  # security: allow-ssrf
    """`urllib.request.urlopen`, routed through the chokepoint (net.py is the sole importer).
    Returns the response as a context manager (callers stream/check status): a net-owned wrapper,
    not an `http.client.HTTPResponse`, so an `isinstance` check against that class is False. `Any`
    to avoid re-exporting the http.client type outside the boundary. net.py IS the single audited egress
    boundary — fetching a caller-supplied URL is its whole purpose — so SSRF is allowed here.

    Holds the module's error contract in both phases: a malformed status line or header (or an
    unusable URL) raises `ProtocolError` from this call, and a truncated or malformed body raises
    it from the response's `read()`. An `HTTPError` (a real 4xx/5xx status) passes through as is."""
    try:
        raw = urllib.request.urlopen(url_or_req, timeout=timeout)  # noqa: S310  # security: allow-ssrf  # nosec
    except OSError:
        raise  # HTTPError and RemoteDisconnected included: callers branch on both
    except http.client.HTTPException as e:
        raise _protocol_error(e) from e
    return _Response(raw)
