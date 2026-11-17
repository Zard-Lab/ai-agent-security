"""go-osv-hygiene — Go module CVE + module-path hygiene (mechanism C).

Queries OSV.dev for `go.mod`-declared modules and cross-checks a declared module path
against the Go module proxy (`proxy.golang.org`) — the two checks Dean's own framing named:

  * **CVE lookup**, like `pip-audit`/`node-audit` for their ecosystems, but Go's own
    twist matters: some OSV Go records use a `GIT`-type affected-range (a raw commit
    hash boundary) rather than `SEMVER` — comparable to a pinned `go.mod` version only
    by cloning commit history, which this static scan cannot do. Those are reported as
    `needs-review` (MEDIUM), distinct from a `SEMVER`-range confirmed hit (HIGH) — never
    silently folded into the same confident claim.
  * **Module-path resolution**, the other half: OSV returns an EMPTY result both for "this
    real module genuinely has zero known CVEs" and for "this module path was mistyped and
    doesn't exist" — verified live against the real API (a typo'd module name returns `{}`,
    identical to a clean one). The Go module proxy's `@v/<version>.info` endpoint gives a
    real 200/404 signal the OSV response alone cannot, so a module that resolves to nothing
    reports its OWN finding (the zero-CVE result for it is not trustworthy — there was
    nothing to check against) rather than silently reading as "clean."

Unlike every other Runner in this codebase, this one wraps no external binary — it makes
two direct HTTPS calls (OSV batch query + Go module proxy), routed through
`agentsec/net.py` (the single egress chokepoint every first-party network call goes
through — `tests/test_net_sandbox.py` enforces that `urllib`/`socket`/`http` are never
imported outside it). A different shape from the subprocess-wrapping convention
`pip_audit.py`/`node_audit.py` follow (which don't need `net.py` at all — the network
call happens inside the wrapped BINARY's own process, not agentsec's), chosen
deliberately over shelling out to a Go-toolchain-dependent tool: no Go installation is
required on the machine running agentsec. `Runner.run()`'s binary-presence gate
(`which(self.binary_name(...))`) is overridden for the same reason — there is no binary
to look up.

Parses `go.mod` for BOTH `require` AND `replace` directives (each in both the single-line
and parenthesized block forms) — a `replace` pinning to an old module@version, often added
once to work around a since-fixed issue and never revisited, is checked against OSV just
like a `require` entry, since that's what actually gets compiled in when both exist for
the same module. A `replace` pointing at a local filesystem path has no version to check
and is naturally excluded. What this does NOT do: determine whether a `replace` is still
NEEDED (go.mod itself never records why one was added) — only whether what it currently
pins to is itself vulnerable. See `parse_go_mod_replace`.

Alias-deduplication: OSV commonly publishes the SAME underlying vulnerability under
multiple IDs (a `GHSA-...` from GitHub's advisory database, a `GO-...` from the official Go
vulnerability database, sometimes a `CVE-...` too, cross-referenced via each record's own
`aliases` field). Reported once per underlying vulnerability, grouped by shared aliases —
verified live: a single real dependency version returned OVER A DOZEN distinct OSV IDs for
what was, after grouping, a much smaller set of actual vulnerabilities.

Tier 1 (egresses your declared Go module names+versions to OSV.dev and proxy.golang.org).
"""
from __future__ import annotations

import json
import re
import urllib.error
from pathlib import Path
from typing import Any

from agentsec import net
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import Runner, RunnerResult, as_list

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
_GO_PROXY_INFO_URL = "https://proxy.golang.org/{module}/@v/{version}.info"
_REQUEST_TIMEOUT = 10  # seconds, per HTTP call

_UPPER = re.compile(r"[A-Z]")


def _escape_module_path(module: str) -> str:
    """Go module proxy case-encoding (`golang.org/x/mod/module` `EscapePath`): every
    uppercase letter becomes `!` plus its lowercase form (`Masterminds` -> `!masterminds`),
    so the proxy URL survives case-insensitive filesystems. Required on every proxy call —
    an un-encoded uppercase module path 404s even for a real, well-known module."""
    return _UPPER.sub(lambda m: "!" + m.group(0).lower(), module)

_REQUIRE_SINGLE = re.compile(r"^\s*require\s+(?P<module>[^\s(]+)\s+(?P<version>v[\w.\-+]+)")
_REQUIRE_BLOCK_START = re.compile(r"^\s*require\s*\(\s*$")
_REQUIRE_BLOCK_LINE = re.compile(r"^\s*(?P<module>[^\s()]+)\s+(?P<version>v[\w.\-+]+)")

# `replace OLDPATH [OLDVERSION] => NEWPATH [NEWVERSION]` — only the NEW side matters here:
# that's what actually gets compiled in. NEWVERSION is REQUIRED unless NEWPATH is a local
# filesystem path (Go's own rule), so a `replace` to `./local-fork` or `../vendor/x` has
# nothing to check — the `new` capture stops at the first `v...` token after `=>`, and a
# missing NEWVERSION (the local-path case) simply doesn't match, correctly excluding it.
_REPLACE_SINGLE = re.compile(r"^\s*replace\s+\S+(?:\s+v\S+)?\s*=>\s*(?P<module>\S+)\s+(?P<version>v[\w.\-+]+)")
_REPLACE_BLOCK_START = re.compile(r"^\s*replace\s*\(\s*$")
_REPLACE_BLOCK_LINE = re.compile(r"^\s*\S+(?:\s+v\S+)?\s*=>\s*(?P<module>\S+)\s+(?P<version>v[\w.\-+]+)")


def parse_go_mod(text: str) -> list[tuple[str, str]]:
    """Extract (module, version) pairs from `go.mod`'s `require` directives.

    Handles both the single-line form (`require example.com/mod v1.2.3`) and the
    parenthesized block form. A `// indirect` (or any other trailing comment) is not
    part of the version match, so it's naturally excluded. Does not resolve `replace`
    directives against these — see `parse_go_mod_replace` for those, checked as their own
    thing rather than silently overriding a `require` entry: a repo can legitimately
    intend for OSV to see a `replace`'s target even if it differs from what `require`
    alone would suggest, and reporting both keeps that visible."""
    out: list[tuple[str, str]] = []
    in_block = False
    for line in text.splitlines():
        if in_block:
            if line.strip() == ")":
                in_block = False
                continue
            m = _REQUIRE_BLOCK_LINE.match(line)
            if m:
                out.append((m.group("module"), m.group("version")))
            continue
        if _REQUIRE_BLOCK_START.match(line):
            in_block = True
            continue
        m = _REQUIRE_SINGLE.match(line)
        if m:
            out.append((m.group("module"), m.group("version")))
    return out


def parse_go_mod_replace(text: str) -> list[tuple[str, str]]:
    """Extract (module, version) pairs from `go.mod`'s `replace` directives — the
    REPLACEMENT (right-hand) side only, since that's what actually gets compiled in.

    A `replace` to a local filesystem path (`replace old/mod => ../local-fork`) has no
    version to check and is naturally excluded (the version group won't match). Handles
    both the single-line and parenthesized block forms, mirroring `parse_go_mod`.

    Closes a real, previously-documented gap: a `replace` pinning to an OLD version —
    often added once to work around a since-fixed issue and never revisited — can pin to
    a module@version with its own known OSV vulnerabilities, invisible to a scan that
    only reads `require`. This does not determine WHETHER a replace is still needed
    (that would require knowing why it was added, which go.mod itself never records) —
    only whether what it currently pins to is itself vulnerable."""
    out: list[tuple[str, str]] = []
    in_block = False
    for line in text.splitlines():
        if in_block:
            if line.strip() == ")":
                in_block = False
                continue
            m = _REPLACE_BLOCK_LINE.match(line)
            if m:
                out.append((m.group("module"), m.group("version")))
            continue
        if _REPLACE_BLOCK_START.match(line):
            in_block = True
            continue
        m = _REPLACE_SINGLE.match(line)
        if m:
            out.append((m.group("module"), m.group("version")))
    return out


def _http_json(url: str, *, tier: int, body: dict[str, Any] | None = None) -> Any:
    """One HTTP call, routed through `agentsec.net` (the sole egress chokepoint), JSON in
    (if `body`) and out. Raises on any failure — callers decide how to degrade; this
    function never silently returns a fabricated empty result."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    raw = net.get(
        url, tier_required=1, feature="go-osv-hygiene", tier=tier,
        sends="your go.mod-declared Go module names+versions", body=data, timeout=_REQUEST_TIMEOUT,
    )
    return json.loads(raw.decode("utf-8"))


def _module_resolves(module: str, version: str, *, tier: int) -> bool:
    """True if the Go module proxy confirms this exact module@version exists.

    A 404 means "does not resolve" — distinct from a network/timeout error, which
    propagates (the caller treats an inconclusive check differently from a confirmed
    non-resolution)."""
    url = _GO_PROXY_INFO_URL.format(module=_escape_module_path(module), version=version)
    try:
        net.get(
            url, tier_required=1, feature="go-osv-hygiene", tier=tier,
            sends="your go.mod-declared Go module names+versions", timeout=_REQUEST_TIMEOUT,
        )
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise


def _range_is_semver_confirmed(vuln: dict[str, Any], module: str) -> bool:
    """True only if EVERY range for THIS module's `affected` entry is SEMVER-typed.

    A GIT-type (or any non-SEMVER) range means the fix/introduction boundary is a raw
    commit hash, not comparable to a pinned `go.mod` version without cloning history —
    Dean's own "no-semver-boundary advisories treated as needs-review" instruction."""
    for aff in as_list(vuln.get("affected")):
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        if not isinstance(pkg, dict) or pkg.get("name") != module:
            continue
        ranges = as_list(aff.get("ranges"))
        if not ranges:
            continue
        return all(isinstance(r, dict) and r.get("type") == "SEMVER" for r in ranges)
    return True  # no matching affected entry found — nothing to downgrade on


class GoOsvHygieneRunner(Runner):
    id = "go-osv-hygiene"
    area = "Build pipeline"
    binary = ""  # no external binary — see module docstring
    tier_required = 1
    egress_dest = "OSV.dev / Go module proxy (proxy.golang.org)"
    egress_sends = "your go.mod-declared Go module names+versions"
    deterministic = False

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        # Unconditionally relevant, deliberately NOT gated on "go" in profile.features:
        # that flag requires actual .go SOURCE files (detect.py, by design — see
        # go_build_supply_chain_footgun.py's module docstring for the same reasoning).
        # A go.mod can exist, and be worth checking, in a repo with none.
        return True

    def run(self, root: Path, profile: StackProfile) -> RunnerResult:
        # Overridden (not the base `Runner.run()`): there is no binary to look up via
        # `which()`, so the base class's binary-presence gate does not apply here.
        self._partial_failures = []
        try:
            raw = self.invoke(root, profile)
        except Exception as e:  # noqa: BLE001 - a network failure must not abort the audit
            return RunnerResult(self.id, available=True, error=f"{type(e).__name__}: {e}")
        partial = list(self._partial_failures)
        try:
            findings = self.parse(raw)
        except Exception as e:  # noqa: BLE001 - a parse error becomes one info finding
            return RunnerResult(
                self.id, available=True,
                findings=[Finding(
                    check_id=self.id, severity="info",
                    title=f"{self.id}: could not parse scan output",
                    message=f"{type(e).__name__}: {e}",
                )],
                error=str(e),
            )
        if not partial:
            return RunnerResult(self.id, available=True, findings=findings)
        detail = "; ".join(partial)
        findings.append(Finding(
            check_id=self.id, severity="info",
            title=f"{self.id}: scan was incomplete — some modules could not be checked",
            message=f"{len(partial)} module(s) failed to query while others succeeded: {detail}",
            remediation="Re-run later, or check network access to OSV.dev / proxy.golang.org.",
            rule=f"{self.id}/partial-scan",
        ))
        return RunnerResult(self.id, available=True, findings=findings, error=f"partial scan: {detail}")

    def invoke(self, root: Path, profile: StackProfile) -> str:
        go_mod = root / "go.mod"
        if not go_mod.is_file():
            return json.dumps({"modules": []})
        text = go_mod.read_text(encoding="utf-8", errors="ignore")
        # `replace` targets are what actually gets compiled in when both exist for the same
        # module, so they're checked independently rather than deduplicated against `require`
        # — a require-side "clean" result would otherwise sit next to (and could be read as
        # contradicting) a genuinely vulnerable replace-side finding for the same module name.
        deps: list[tuple[str, str, str]] = [
            (m, v, "require") for m, v in parse_go_mod(text)
        ] + [
            (m, v, "replace") for m, v in parse_go_mod_replace(text)
        ]
        if not deps:
            return json.dumps({"modules": []})

        tier = profile.network_tier
        try:
            batch = _http_json(
                _OSV_BATCH_URL, tier=tier,
                body={"queries": [
                    {"package": {"name": m, "ecosystem": "Go"}, "version": v} for m, v, _src in deps
                ]},
            )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, net.EgressRefused) as e:
            raise RuntimeError(f"OSV batch query failed: {e}") from e

        results = as_list(batch.get("results")) if isinstance(batch, dict) else []
        if len(results) < len(deps):
            # A truncated/partial batch response would otherwise silently evaluate only the
            # first len(results) modules and read as a completed clean scan of every module —
            # the exact failure-that-presents-as-success shape this codebase's own review
            # doctrine names (rule 3). Disclose the shortfall before it can go unnoticed.
            missing = ", ".join(f"{m}@{v}" for m, v, _src in deps[len(results):])
            self.note_partial_failure(f"OSV batch returned {len(results)}/{len(deps)} results — not evaluated: {missing}")
        modules_out: list[dict[str, Any]] = []
        for (module, version, source), result in zip(deps, results, strict=False):
            # `isinstance(result, dict)` must gate the `.get()` call itself, not just filter the
            # comprehension — a null batch entry otherwise raises AttributeError on `result.get(...)`
            # before the isinstance check is ever reached, discarding every already-fetched finding.
            raw_vulns = as_list(result.get("vulns")) if isinstance(result, dict) else []
            hit_ids = [v.get("id") for v in raw_vulns if isinstance(v, dict) and v.get("id")]
            vulns_out: list[dict[str, Any]] = []
            for vid in hit_ids:
                try:
                    detail = _http_json(_OSV_VULN_URL.format(id=vid), tier=tier)
                except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, net.EgressRefused) as e:
                    self.note_partial_failure(f"{module}@{version} ({vid}): {e}")
                    continue
                if not isinstance(detail, dict):
                    continue
                vulns_out.append({
                    "id": vid,
                    "aliases": [a for a in as_list(detail.get("aliases")) if isinstance(a, str)],
                    "summary": str(detail.get("summary") or ""),
                    "confirmed": _range_is_semver_confirmed(detail, module),
                })
            resolves = True
            if not vulns_out:
                # Only worth the extra round-trip when there's nothing else telling us
                # this module is real — a confirmed CVE hit already proves it resolves.
                try:
                    resolves = _module_resolves(module, version, tier=tier)
                except (urllib.error.URLError, TimeoutError, net.EgressRefused) as e:
                    self.note_partial_failure(f"{module}@{version} (proxy check): {e}")
                    resolves = True  # inconclusive — do not claim non-resolution on a network error
            modules_out.append({
                "module": module, "version": version, "vulns": vulns_out, "resolves": resolves,
                "source": source,
            })
        return json.dumps({"modules": modules_out})

    def parse(self, raw: str) -> list[Finding]:
        data: Any = json.loads(raw)
        out: list[Finding] = []
        for mod in as_list(data.get("modules")) if isinstance(data, dict) else []:
            if not isinstance(mod, dict):
                continue
            module = str(mod.get("module") or "?")
            version = str(mod.get("version") or "?")
            source = str(mod.get("source") or "require")
            vulns = [v for v in as_list(mod.get("vulns")) if isinstance(v, dict)]
            out.extend(self._vuln_findings(module, version, vulns, source))
            if not vulns and mod.get("resolves") is False:
                via = " (from a go.mod `replace` directive)" if source == "replace" else ""
                out.append(Finding(
                    check_id=self.id,
                    severity="medium",
                    title=f"Declared module does not resolve: {module}@{version}",
                    location=module,
                    message=(
                        f"go.mod declares {module}@{version}{via}, but the Go module proxy has "
                        "no record of this module/version. OSV reported zero vulnerabilities for "
                        "it, but that result is not trustworthy when the module itself can't be "
                        "confirmed to exist — a typo'd or renamed module path silently reads as "
                        "\"clean\" otherwise."
                    ),
                    remediation="Confirm the module path and version in go.mod are correct.",
                    rule=f"{self.id}/unresolvable-module-path",
                    standards=["OWASP:A06"],
                ))
        return out

    def _vuln_findings(
        self, module: str, version: str, vulns: list[dict[str, Any]], source: str = "require",
    ) -> list[Finding]:
        # Alias-dedup: group hits that reference each other via `aliases`, report one
        # finding per underlying vulnerability rather than one per OSV/GHSA/CVE id.
        # `as_list(...)`, not a bare `.get("aliases", [])`: parse() must never raise on an
        # unexpected shape (this codebase's own Runner contract) — a non-list `aliases` value
        # would otherwise raise TypeError on the `*` unpack / iteration below (review L1).
        groups: list[list[dict[str, Any]]] = []
        for v in vulns:
            ids = {v.get("id"), *as_list(v.get("aliases"))}
            placed = False
            for g in groups:
                g_ids = {m.get("id") for m in g} | {a for m in g for a in as_list(m.get("aliases"))}
                if ids & g_ids:
                    g.append(v)
                    placed = True
                    break
            if not placed:
                groups.append([v])

        out: list[Finding] = []
        via = " (pinned by a go.mod `replace` directive)" if source == "replace" else ""
        for group in groups:
            # Prefer a GO-<year>-<n> id (the canonical Go ecosystem id) as the reported rule;
            # otherwise the first id encountered.
            primary = next((m for m in group if str(m.get("id", "")).startswith("GO-")), group[0])
            vid = str(primary.get("id") or "?")
            confirmed = any(m.get("confirmed") for m in group)
            summary = str(primary.get("summary") or "") or next(
                (str(m.get("summary")) for m in group if m.get("summary")), ""
            )
            out.append(Finding(
                check_id=self.id,
                severity="high" if confirmed else "medium",
                title=f"{'Vulnerable' if confirmed else 'Possibly vulnerable'} Go dependency: {module} {version}{via}",
                location=module,
                message=(
                    f"{vid}: {summary[:200]}"
                    if confirmed else
                    f"{vid}: {summary[:200]} — the affected-version boundary is a raw commit "
                    "reference, not a semantic version, so this could not be confirmed against "
                    f"the pinned {version} with certainty. Needs manual review."
                ),
                remediation=(
                    "Review the advisory. If this version is pinned by a go.mod `replace` "
                    "directive, check whether the replace is still needed and update or remove "
                    "it; otherwise upgrade the declared version if it is affected."
                    if source == "replace" else
                    "Review the advisory and upgrade if the pinned version is affected."
                ),
                rule=vid,
                standards=["OWASP:A06"],
            ))
        return out
