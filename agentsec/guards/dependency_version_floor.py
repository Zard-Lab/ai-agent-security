"""Guard: dependencies meet the patched-version floor for known CVEs (checklist §5).

Closes the loop the slow-clock /threat-intake opens: when intake finds a
high-severity CVE in a stack dependency (e.g. LangGrinch in langchain-core, or
BadHost in starlette) it records the fixed-in version in `version_floors.json`;
this guard reads that curated list and flags any project that **pins** the package
below the patched version. Deterministic, zero-dependency, always-on — unlike the
optional pip-audit/npm-audit runners, this enforces the specific floors we curate
for our stack even when no scanner binary is installed.

It fires on two manifest-provable cases (open ranges like `>=`/`^`/`~` stay ambiguous and are
left to the lockfile-resolved path):
  * **exact pin** (`==` / poetry `= "X"`) below the floor → the CVE's own severity;
  * **upper bound** (`<X` / `<=X`, including the blocking half of a compound `>=a,<X`) that
    provably cannot reach the patched floor → HIGH.
Both pip requirements files AND `pyproject.toml` (PEP 621 + poetry tables) are parsed. (The
upper-bound tier + poetry/PEP-621 parsing were folded in from the retired `dependency-version-floors`
guard — PR #226 — so the floors stay single-sourced in `version_floors.json`.)

Severity comes from the floor entry (the CVE's) for exact pins. Suppress an audited case with a
`# security: allow-old-<package>` pragma on the pin line (or anywhere in a TOML manifest). In a
Dockerfile the pragma goes in the `#` comment lines directly above the `FROM` (Docker allows no
trailing comment on an instruction). Only those two paths read it: findings from package.json, the
lockfiles (poetry.lock, package-lock.json, go.sum, Cargo.lock) and the Maven manifests (pom.xml,
build.gradle) point at an expiring `agentsec-exceptions.json` entry instead.

A floor entry may optionally carry `"affected_from"`: a lower bound on the CVE's own affected
range, for an advisory that does not affect every version below `fixed_in` — only a specific
range starting partway through the package's history (e.g. GHSA-w828-4qhx-vxx3 in `anthropic`,
which affects only 0.86.x, not every release before 0.87.0). A declared version below
`affected_from` predates the affected range and is not flagged. Absent (the common case): every
version below `fixed_in` is treated as vulnerable, unchanged from before this field existed.

**2026-09-21: Go ecosystem support added — `"ecosystem": "go"` floors.** Read from
`go.sum` only. go.sum is NOT a one-version-per-package lockfile like poetry.lock: it is an
append-only checksum ledger that can hold several versions of one module plus `/go.mod`-only
module-graph entries, so the resolved version is inferred from it one-sidedly (see
`_go_sum_resolved`). `go.mod`'s own `require` lines are deliberately NOT scanned, since Go's
Minimal Version Selection (MVS) means a `require` line only states a
LOWER bound the resolver can raise if another module in the build graph needs a newer version;
treating it as authoritative would risk the exact false positive this guard already declines to
flag for a pip/npm open range (`>=`/`^`/`~`). `applies()` accepts `"go" in profile.languages`,
which `detect.py` sets from `.go` source files only, OR the `python`/`frontend` features: a repo
whose only Go artifact is `go.mod`/`go.sum` is not scanned, but a Python or frontend repo's stray
`go.sum` is (#937). Java and Rust support landed separately (PR #922, below).

**2026-09-22 correction:** an earlier version of this docstring claimed "Go has no `features`
flag," implying the mapped checklist item's `applies_when` couldn't recognize a Go-only repo
without a code change elsewhere. That claim was wrong — `detect.py`'s own
`feats: set[str] = set(prof.languages)` means `features` IS seeded from `languages`, so `"go"`
legitimately belongs in `5-known-cve-version-floors`'s own `applies_when` (added here; caught
while building the sibling Java/Rust slices, PR #922).

**2026-09-23 (Dean's review):** `_go_sum_resolved`'s max-version fix, see its own
docstring. Also reviewed the `applies()` languages-vs-features gate Dean flagged in the same
message: confirmed no behavior gap exists — `detect.py`'s `feats = set(prof.languages)` means
`"go" in profile.features` is always true whenever `"go" in profile.languages` is, on any real
profile from `detect()`; the two checks are equivalent on production data, and this guard's test
fixtures (built via `mkprofile()`, which does not replicate that seeding) rely on the languages
check specifically, so left as `profile.languages` rather than changed for no functional gain.

**2026-09-22: Java/Maven ecosystem support added — `"ecosystem": "maven"` floors,
keyed by the Maven coordinate `groupId:artifactId`.** Reads `pom.xml`'s own `<dependency>`
`<version>` declarations directly (ElementTree, namespace-qualified) and
`build.gradle`/`build.gradle.kts`'s single-string GAV coordinate form. Unlike Go's `go.mod`
(a genuinely ambiguous lower bound under Minimal Version Selection), a Maven POM's own declared
version is treated as authoritative here: Maven's ecosystem convention overwhelmingly pins an
exact `<version>`, not a range, so this mirrors how the guard already treats an npm
`package.json` exact pin — a `${property}`-substituted version is not resolved (disclosed gap,
matching `agent-audit-kit`'s own real Java-pin scanner this was cross-checked against), and
neither is Gradle's map-notation dependency form (`implementation group: 'x', name: 'y', ...`),
only its single-string GAV form. `applies()` gates on `"java" in profile.languages`, mirroring
the Go slice's own `"go" in profile.languages` gate. Note `detect.py` also seeds
`profile.features` from `profile.languages` (`feats: set[str] = set(prof.languages)`), so
`"java"` legitimately belongs in the mapped checklist item's own `applies_when` too — added
here (`5-known-cve-version-floors`), correcting an earlier, wrong "Go/Java has no features flag"
claim from the Go slice's own docstring/wiki (fixed there in a follow-up commit, #921). Go
(`go.sum`) support landed separately (PR #921).

**Rust/Cargo ecosystem support added in the same pass — `"ecosystem": "cargo"` floors, keyed by
crate name.** Reads `Cargo.lock`'s own `[[package]]` blocks (standard TOML, parsed with the
already-imported `tomllib` rather than a hand-rolled scanner) — the resolved dependency tree,
analogous to `go.sum`/`poetry.lock`. `Cargo.toml`'s own `[dependencies]` declarations are
deliberately NOT scanned: Cargo's default requirement operator is caret (`rmcp = "1.2.0"` means
`^1.2.0`, an open range), the same "ambiguous manifest" shape this guard already declines to
flag from pip/npm/Go manifests alone. `applies()` gates on `"rust" in profile.languages` — a
brand-new detection signal this same change adds to `detect.py` (Rust previously had zero
`languages`/`features` presence, only a threshold-based `foreign_languages` disclosure; `.rs`
was removed from that census table on the same graduation precedent Go/PHP/Ruby/Java already
established, so it is never double-reported in both places).
"""
from __future__ import annotations

import functools
import json
import re
import tomllib
import xml.etree.ElementTree as ET  # noqa: S405  # security: xml-trusted-no-entity-resolution (see _pom_xml_resolved)  # nosec B405
from pathlib import Path
from typing import NamedTuple

from agentsec.detect import _FROM_INSTRUCTION, StackProfile, _bare_image_name, _image_tag
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, go_scan_dirs, iter_files, read, rel

_FLOORS_PATH = Path(__file__).parent / "version_floors.json"
_PIP_MANIFESTS = (".txt", ".in", ".toml", ".lock")  # requirements*.txt/.in, pyproject.toml, *.lock

# A Dockerfile base-image TAG is a claim about a pullable artifact, not a resolved package
# version — closer to Maven's "own declared version is authoritative" convention than to Go's
# ambiguous `go.mod` lower bound, but only once the tag fully commits to an exact major.minor.patch.
# A shorter tag (`php:8.3`, `node:18`) is Docker Hub's own floating-minor/floating-major convention
# and resolves to whatever patch is current *at pull time* — exactly the "ambiguous range, decline
# to flag" case this guard already applies to an open pip/npm version spec (see module docstring).
# `fullmatch`ed, not searched: the ENTIRE tag must be the three numeric components plus, at most,
# a `-`/`_`-led suffix (`-fpm`, `-alpine3.19`) — so `8.3` (two components) and `8.2.35.1` (an
# unconsumed trailing `.1`) both correctly fail to match, while `8.2.35`/`8.2.35-fpm` both do.
#
# **2026-10-27 fix (review H1, PR #1161):** the suffix class used to be `[\w.]*` -- `\w` excludes
# `-`, so a SECOND hyphenated segment (`python:3.12.14-slim-bookworm`, `node:22.23.3-bookworm-
# slim` -- both real, common official-image tags, not an edge case) failed `fullmatch` entirely
# and the guard silently never checked them. Widened to `[\w.-]*` so any number of further
# `-`/`_`-separated segments are consumed. This widens ONLY what comes after the leading
# `[-_]` separator -- the captured release group (`\d+\.\d+\.\d+`) is untouched, so it still
# cannot swallow a second version-shaped segment into the release itself, and a declared version
# is still read from group 1 alone. That matters for a `-rc`/pre-release-flavored suffix: a tag
# like `3.12.14-rc1-bookworm` still fullmatches (as it already did pre-fix for a single-hyphen
# `-rc1` suffix) and is still read as the plain release `3.12.14`, ignoring the `rc1` marker.
# So a pre-release suffix is ignored, not interpreted: `3.12.15-rc1` reads as the final `3.12.15`
# (a narrow, accepted limit). Real CPython and Node pre-release tags carry no hyphen
# (`3.13.0rc2`), so they fail the fullmatch and are never checked at all.
_DOCKER_TAG_EXACT = re.compile(r"(\d+\.\d+\.\d+)(?:[-_][\w.-]*)?")
# The per-package opt-out, filled with `re.escape(pkg)`. A module constant, like every guard's
# pragma, so the anchoring gate can see it (#1040); it is read only as a `#` comment.
_PRAGMA_TEMPLATE = r"#\s*security:\s*allow-old-{pkg}\b"


@functools.lru_cache(maxsize=256)
def _pragma_for(pkg: str) -> re.Pattern[str]:
    """`_PRAGMA_TEMPLATE` filled for `pkg` (escaped). The one place it is compiled, shared by
    the pip and Dockerfile paths, so a new consumer adds no new dynamic `re.*` call site for the
    ReDoS linter's unresolved-site budget (`tests/test_regex_redos_safety.py`)."""
    return re.compile(_PRAGMA_TEMPLATE.format(pkg=re.escape(pkg)))


def _docker_pragma_allows(dockerfile: Path, image: str, tag: str) -> bool:
    """True when every `FROM` line in `dockerfile` that pulls `image:tag` carries the
    `# security: allow-old-<image>` pragma in the run of `#` comment lines directly above it
    (#1134 review M1). Docker has no trailing comments on an instruction line, so the pragma sits
    on its own line above the `FROM`, the same "on the pin" anchoring the pip path uses. It is
    read through `comment_view`, so it counts only as a comment. Fails closed: an unreadable file,
    or one `FROM` of that image:tag without the pragma, keeps the finding."""
    text = read(dockerfile)
    if not text:
        return False
    pragma = _pragma_for(image)
    lines = text.splitlines()
    view = comment_view(text, "hash").splitlines()
    froms = 0
    for i, line in enumerate(lines):
        m = _FROM_INSTRUCTION.fullmatch(line)
        if not m or _bare_image_name(m.group(1)) != image or _image_tag(m.group(1)) != tag:
            continue
        froms += 1
        j = i - 1
        allowed = False
        while j >= 0 and lines[j].lstrip().startswith("#"):
            if pragma.search(view[j]):
                allowed = True
                break
            j -= 1
        if not allowed:
            return False
    return froms > 0


class _Ver(NamedTuple):
    """A comparable PEP 440 version.

    `NamedTuple` orders lexicographically, so this compares the release tuple first and only then
    the pre/post phase — which is PEP 440's rule for every shape a floor uses.

    The parser used to match only a run of digits and dots, which DROPPED the pre-release marker
    entirely: `2.0.0b3` and `2.0.0b2` both parsed to the same `(2, 0, 0)`, so a project pinned to the
    EARLIER prerelease compared `>=` the floor and was reported PATCHED. A false negative on exactly
    the pin a prerelease floor exists to catch, and it made a prerelease unusable as a floor at all,
    not just for one advisory (#492 review / B28).

    (Written in prose rather than by quoting the old pattern: agentsec's own `redos` guard flags a
    doubled-escape rendition of it in a docstring, while correctly ignoring the live regex below.)"""

    release: tuple[int, ...]
    phase: int      # 0 dev, 1 alpha, 2 beta, 3 rc, 4 final, 5 post
    phase_num: int


_PHASE_FINAL = 4
_PRE_RANK = {"alpha": 1, "a": 1, "beta": 2, "b": 2, "preview": 3, "pre": 3, "rc": 3, "c": 3}
# Alternations are longest-first so `rc` is not shadowed by `c`, and `alpha` not by `a`.
_VER_PAT = (
    r"\d+(?:\.\d+)*"
    r"(?:[._-]?(?:alpha|beta|preview|pre|rc|a|b|c)[._-]?\d*)?"
    r"(?:[._-]?(?:post|rev|r)[._-]?\d*)?"
    r"(?:[._-]?dev\d*)?"
)
_VER_RE = re.compile(
    r"(?P<release>\d+(?:\.\d+)*)"
    r"(?:[._-]?(?P<pre>alpha|beta|preview|pre|rc|a|b|c)[._-]?(?P<pre_n>\d+)?)?"
    r"(?:[._-]?(?P<post>post|rev|r)[._-]?(?P<post_n>\d+)?)?"
    r"(?:[._-]?dev(?P<dev_n>\d+)?)?",
    re.IGNORECASE,
)


def _version(s: str) -> _Ver | None:
    """Parse a PEP 440-ish version into a comparable key. Total: returns None if there is no version.

    Residual, stated rather than hidden: a `.devN` attached to a pre- or post-release (`1.0b2.dev1`)
    collapses to that pre/post rank rather than sorting below it. Bare `1.0.devN` IS ordered below
    every prerelease, which is the case that matters for a floor."""
    m = _VER_RE.search(s)
    if m is None:
        return None
    release = tuple(int(p) for p in m.group("release").split("."))
    if m.group("pre"):
        return _Ver(release, _PRE_RANK[m.group("pre").lower()], int(m.group("pre_n") or 0))
    if m.group("post"):
        return _Ver(release, 5, int(m.group("post_n") or 0))
    if m.group("dev_n") is not None or m.group(0).lower().rstrip("0123456789").endswith("dev"):
        return _Ver(release, 0, int(m.group("dev_n") or 0))
    return _Ver(release, _PHASE_FINAL, 0)


def _fixed_versions(floor: dict[str, object]) -> list[_Ver]:
    raw = floor.get("fixed_in", [])
    if not isinstance(raw, list):
        return []
    return [v for v in (_version(str(x)) for x in raw) if v]


def _affected_from(floor: dict[str, object]) -> _Ver | None:
    """Optional lower bound on the floor entry: the advisory's own affected-range floor
    (`introduced`, in OSV terms), for a CVE that does NOT affect every version below
    `fixed_in` — only a specific range starting partway through the package's history (e.g.
    GHSA-w828-4qhx-vxx3 in `anthropic`, which affects only the 0.86.x line, not every release
    before 0.87.0). Without this, a declared version that predates the affected range entirely
    is reported vulnerable to a CVE it was never exposed to — review found `anthropic==0.30.0`
    flagged for a sandbox-escape CVE that only exists in 0.86.0-0.86.x, the common case since
    most real pins predate 0.86.0. `None` (the field absent) means "no known lower bound" —
    every version below `fixed_in` is treated as vulnerable, the original all-versions-below
    semantics, so every floor entry without this field is completely unaffected."""
    raw = floor.get("affected_from")
    if not isinstance(raw, str):
        return None
    return _version(raw)


def _fixed_str(floor: dict[str, object]) -> str:
    raw = floor.get("fixed_in", [])
    return ", ".join(str(x) for x in raw) if isinstance(raw, list) else ""


def _vulnerable(declared: _Ver, fixed_in: list[_Ver], affected_from: _Ver | None = None) -> bool:
    """Patched if declared >= the fix on its own major.minor line, or >= the
    highest fixed version overall (a later line); otherwise vulnerable.

    The same-line test compares `.release` only: a prerelease is on the same major.minor line as its
    final (`2.0.0b3` and `2.0.0` are both the `2.0` line), and the phase is what the `<` then decides.

    `affected_from`, when the floor entry declares one (see `_affected_from`), is checked first:
    a declared version below it predates the CVE's own affected range entirely and is not
    vulnerable, regardless of how far below `fixed_in` it sits."""
    if not fixed_in:
        return False
    if affected_from is not None and declared < affected_from:
        return False
    if declared >= max(fixed_in):
        return False
    for f in fixed_in:
        if len(f.release) >= 2 and len(declared.release) >= 2 and f.release[:2] == declared.release[:2]:
            return declared < f  # same release line: vulnerable iff below its fix
    return True  # no same-line fix and below the highest fix -> vulnerable


# Any version specifier: (op, version). Captures every clause of a compound `>=a,<b`.
# The version group is `_VER_PAT`, not a bare digits-and-dots run: an upper bound of `<2.0.0b3` used
# to capture only `2.0.0`, so the prerelease was dropped a SECOND time, independently of `_version`
# (#492 review / B28).
_SPEC_RE = re.compile(r"(===?|>=|<=|~=|!=|<|>)\s*v?(" + _VER_PAT + r")")


def _specs_for_pkg(spec_string: str, pkg: str) -> list[tuple[str, str]] | None:
    """If `spec_string` starts with `pkg` (optionally with [extras]), return its (op, version)
    constraints; else None. Anchoring to the start ensures the constraints belong to `pkg`
    (not e.g. another package named in a trailing comment)."""
    m = re.match(r"\s*" + re.escape(pkg) + r"(?![\w-])(?:\[[^\]]*\])?(.*)", spec_string, re.IGNORECASE)
    if m is None:
        return None
    return _SPEC_RE.findall(m.group(1))


def _upper_bound_unreachable(
    specs: list[tuple[str, str]], fixed: list[_Ver], affected_from: _Ver | None = None
) -> bool:
    """True if an upper bound (`<X`/`<=X`) among `specs` makes every patched version unreachable.

    When the floor declares `affected_from`, an upper bound that already caps the resolver below
    the affected range's own start is not "capped below the fix" in a way that matters — the
    resolver could never have installed a vulnerable version to begin with, so this is not
    flagged (consistent with `_vulnerable`'s exact-pin handling of the same field)."""
    if not fixed:
        return False
    lo = min(fixed)
    for op, ver in specs:
        v = _version(ver)
        if v is None:
            continue
        if affected_from is not None:
            # `<X` cannot install X itself, so it is safe when X <= affected_from; `<=X` CAN
            # install X, so it is only safe when X < affected_from. Sharing one condition let a
            # spec pinned exactly at the affected range's start (`<=0.86.0`) go unflagged even
            # though it can install the first vulnerable release (review, fix-commit round).
            if op == "<" and v <= affected_from:
                continue
            if op == "<=" and v < affected_from:
                continue
        if op == "<" and v <= lo:
            return True
        if op == "<=" and v < lo:
            return True
    return False


def _load_toml(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _toml_dep_strings(data: dict[str, object]) -> list[str]:
    """PEP 621 [project].dependencies/[optional-dependencies] + poetry [tool.poetry.dependencies]."""
    deps: list[str] = []
    proj = data.get("project")
    if isinstance(proj, dict):
        d = proj.get("dependencies")
        if isinstance(d, list):
            deps += [x for x in d if isinstance(x, str)]
        opt = proj.get("optional-dependencies")
        if isinstance(opt, dict):
            for grp in opt.values():
                if isinstance(grp, list):
                    deps += [x for x in grp if isinstance(x, str)]
    tool = data.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            pd = poetry.get("dependencies")
            if isinstance(pd, dict):
                for pkg, spec in pd.items():
                    if isinstance(spec, str):
                        deps.append(f"{pkg}{spec}")
                    elif isinstance(spec, dict) and isinstance(spec.get("version"), str):
                        deps.append(f"{pkg}{spec['version']}")
    return deps


# `go.sum` line shape: `<module> <version>[/go.mod] <hash>`. A version whose module content was
# verified has a content-hash line (no suffix); a `/go.mod` line only hashes a go.mod consulted
# while building the module graph, so a version can appear with that line alone. The
# version field itself carries Go's "v" module-version prefix (`v1.4.1`), which `_version()`
# already handles: `_VER_RE.search()` finds the first digit run wherever it starts, so the
# leading "v" is simply not part of the match — no format-specific change needed there.
_GO_SUM_LINE = re.compile(r"^(\S+)\s+(\S+)\s+\S+\s*$")


def _go_sum_resolved(text: str) -> dict[str, str]:
    """Module -> the version this guard treats as resolved, from a `go.sum` file's content.

    `go.sum` is NOT a resolved-version lockfile in the `poetry.lock`/`package-lock.json`
    sense (one version per package). It is an append-only checksum ledger: every module
    version the `go` command verified stays in it until `go mod tidy` prunes it, so one
    module routinely appears at several versions, and a `/go.mod` line (see `_GO_SUM_LINE`)
    can name a version that is in the module graph but not in the build. `go.mod` is still
    deliberately not scanned (Go's MVS makes a `require` line a LOWER bound; see the module
    docstring), so `go.sum` is the only Go source this guard reads, and the version is
    inferred from it one-sidedly:

      * a `/go.mod`-suffixed line is skipped outright (graph entry, not a build entry);
      * among the content-hash lines, the MAX version per module is kept.

    A module whose packages are built has a content line for the version MVS selected, so
    that max is an upper bound on the selected version: if even the max is below the floor,
    so is whatever version gets built, and a stale line can never produce a false positive.
    The trade, stated rather than hidden: a downgrade without `go mod tidy` (`go get
    pkg@older`) leaves the newer, patched line behind, the max reports it, and the vulnerable
    build stays silent.

    **2026-09-23 (Dean's review):** the first version parsed every line as a
    build version (stripping the `/go.mod` suffix) and kept the first line per module
    (`setdefault`). go.sum is written sorted ascending, so that was the LOWEST version
    present, graph-only entries included: a CI-gating false positive on an
    upgraded-but-not-tidied repo.
    """
    resolved: dict[str, str] = {}
    for line in text.splitlines():
        m = _GO_SUM_LINE.match(line)
        if not m:
            continue
        module, version = m.group(1), m.group(2)
        if version.endswith("/go.mod"):
            continue
        current = resolved.get(module)
        if current is None or _go_version_gt(version, current):
            resolved[module] = version
    return resolved


def _opt_out(pkg: str, pragma: bool) -> str:
    """The audited-case advice a finding's remediation carries.

    The inline pragma is advertised ONLY where the scanning path reads it (`_scan_pip`: pip
    requirements files and `pyproject.toml`). The package.json, poetry.lock, package-lock.json,
    go.sum, pom.xml, build.gradle and Cargo.lock paths never read a pragma, and JSON and go.sum
    cannot even hold one (`go` rewrites go.sum), so naming it there was a failure that presents as
    success: the user writes the line and the finding keeps firing (#921 review, M3). The
    exception registry applies to any finding."""
    if pragma:
        return f"Suppress an audited case with `# security: allow-old-{pkg}`."
    return (
        "Accept an audited case with an expiring `agentsec-exceptions.json` entry "
        "(no inline pragma is read for this file)."
    )


def _go_version_gt(a: str, b: str) -> bool:
    """True if Go module version `a` outranks `b`, via the same comparable key `_version()`
    already uses for floor comparisons — an unparseable version never outranks a parseable one."""
    va, vb = _version(a), _version(b)
    if va is None:
        return False
    if vb is None:
        return True
    return va > vb


# --- Java/Maven ecosystem support ------------------------------------------------

# Maven POM XML declares a default namespace (`http://maven.apache.org/POM/4.0.0`); every
# element lookup below must qualify with it or ElementTree's `.find`/`.findall` silently match
# nothing. `_pom_namespace` derives it from the root tag itself rather than hardcoding the
# version string, so a future POM schema revision does not silently break this.
def _pom_namespace(root_elem: ET.Element) -> dict[str, str]:
    return {"m": root_elem.tag.split("}")[0].strip("{")} if "}" in root_elem.tag else {}


def _pom_xml_resolved(text: str) -> dict[str, str]:
    """`groupId:artifactId` -> declared `<version>`, from a `pom.xml`'s own `<dependency>`
    blocks (both a direct `<dependencies>` and a `<dependencyManagement><dependencies>` block).

    Maven's dependency-mediation algorithm CAN resolve a transitive conflict to a version other
    than what one POM directly declares — but unlike Go's MVS (which ALWAYS may raise a
    `require` line), a direct dependency's own declared version is the version actually used
    for the overwhelming common case (no competing transitive declaration), and Maven's own
    ecosystem convention overwhelmingly uses an exact `<version>` rather than a range — so,
    unlike `go.mod`, treating the declared version as authoritative here mirrors how this guard
    already treats an npm `package.json` exact pin, not `go.mod`'s ambiguous lower bound.

    Known gap, disclosed rather than silently handled: a `${property}` version placeholder
    (Maven property substitution, e.g. `<version>${mcp.version}</version>`) is not resolved —
    same limitation as `agent-audit-kit`'s own real Java-pin scanner, which this was ported
    from and cross-checked against.

    `xml.etree.ElementTree` does not resolve external entities by default (unlike a naive DOM
    parser) — so this does not contradict agentsec's own `xxe-safe` guard's target (an app
    parsing *untrusted* XML with entity resolution left on), matching `ingest.py::parse_schemathesis`'s
    own identical `ET.fromstring` justification for a real precedent in this codebase. The
    residual risk (an entity-expansion / "billion laughs" DoS against agentsec's own scan, not
    data exfiltration) is accepted: a scan is a bounded, one-shot local process, not a
    persistent service an attacker can repeatedly starve."""
    try:
        root_elem = ET.fromstring(text)  # noqa: S314  # nosec B314
    except ET.ParseError:
        return {}
    ns = _pom_namespace(root_elem)
    dep_xpath = ".//m:dependency" if ns else ".//dependency"
    resolved: dict[str, str] = {}
    for dep in root_elem.findall(dep_xpath, ns) if ns else root_elem.findall(dep_xpath):
        def _child_text(elem: ET.Element, tag: str) -> str:
            node = elem.find(f"m:{tag}", ns) if ns else elem.find(tag)
            return (node.text or "").strip() if node is not None and node.text else ""

        group = _child_text(dep, "groupId")
        artifact = _child_text(dep, "artifactId")
        version = _child_text(dep, "version")
        if group and artifact and version and not version.startswith("${"):
            resolved.setdefault(f"{group}:{artifact}", version)
    return resolved


# Gradle GAV (Group:Artifact:Version) single-string coordinate form — the common, idiomatic
# shape (`implementation 'io.modelcontextprotocol.sdk:mcp-core:1.0.0'` in Groovy DSL, or
# `implementation("...")` in Kotlin DSL). Deliberately does NOT handle Gradle's map-notation
# form (`implementation group: 'x', name: 'y', version: 'z'`) — a disclosed, narrower scope,
# not a silent gap: that form is real but far less common in practice.
_GRADLE_GAV = re.compile(
    r"""['"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['"]"""
)


def _gradle_resolved(text: str) -> dict[str, str]:
    """`groupId:artifactId` -> declared version, from a `build.gradle`/`build.gradle.kts`'s
    single-string GAV coordinate declarations."""
    resolved: dict[str, str] = {}
    for m in _GRADLE_GAV.finditer(text):
        group, artifact, version = m.group(1), m.group(2), m.group(3)
        resolved.setdefault(f"{group}:{artifact}", version)
    return resolved


# --- Rust/Cargo ecosystem support -------------------------------------------------


def _cargo_lock_resolved(text: str) -> dict[str, str]:
    """Crate -> resolved version, from a `Cargo.lock`'s own `[[package]]` blocks — the actual
    resolved dependency tree, analogous to `go.sum`/`poetry.lock`.

    `Cargo.toml`'s own `[dependencies]` entries are deliberately NOT scanned: Cargo's default
    requirement operator is caret (`rmcp = "1.2.0"` means `^1.2.0`, i.e. an open `>=1.2.0,
    <2.0.0` range), exactly the "ambiguous open range" shape this guard already declines to
    flag from a manifest alone for pip/npm/Go. `Cargo.lock` is standard TOML (like
    `pyproject.toml`), so this reuses the already-imported `tomllib` rather than a hand-rolled
    line scanner — more robust than `poetry.lock`'s own regex scan of the same shape."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}
    packages = data.get("package", [])
    if not isinstance(packages, list):
        return {}
    resolved: dict[str, str] = {}
    for pkg in packages:
        if isinstance(pkg, dict) and isinstance(pkg.get("name"), str) and isinstance(pkg.get("version"), str):
            resolved.setdefault(pkg["name"], pkg["version"])
    return resolved


def _in_build_output(root: Path, f: Path) -> bool:
    """True for a manifest under a `target/` build-output directory. `mvn package` copies the POM
    to `target/classes/META-INF/maven/<group>/<artifact>/pom.xml` and `cargo package` writes
    `target/package/<crate>-<version>/Cargo.lock`: each is a generated copy of a manifest the walk
    already reads, so scanning it reports the same CVE twice (#922 re-review). `walk.py` does not
    exclude `target`, so the skip lives here. The parts are taken relative to `root`, which keeps a
    checkout that itself sits under a directory named `target` scanning normally."""
    return "target" in Path(rel(root, f)).parts


class DependencyVersionFloorGuard(Guard):
    id = "dependency-version-floor"
    title = "Dependencies meet the patched-version floor for known CVEs"
    area = "Dependencies"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `requirements.txt`, which several guards trip at once, so the file stays in `canary.py`'s base owned by
    # no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(expects=frozenset({"dependency-version-floor/below-patched-version"}))

    def applies(self, profile: StackProfile) -> bool:
        # `profile.has_docker` (detect.py) is true only for a file named exactly `Dockerfile` or
        # `docker-compose*`. `docker_base_images` is populated by a separate, broader walk that
        # also reads `Dockerfile.<x>`/`*.dockerfile` (detect.py's artifact-layer Go-evidence scan),
        # so a repo whose only Dockerfile is e.g. `Dockerfile.prod` or `worker.Dockerfile` can have
        # a non-empty `docker_base_images` while `has_docker` stays False — this guard would then
        # be skipped even though it collected vulnerable images to check (review H1).
        # Checking `docker_base_images` directly covers that case without widening `has_docker`
        # itself, which gates other docker-only guards and is a separate, bigger change.
        return (
            "python" in profile.features
            or "frontend" in profile.features
            or "go" in profile.languages
            or "java" in profile.languages
            or "rust" in profile.languages
            or profile.has_docker
            or bool(profile.docker_base_images)
        )

    def _floors(self) -> list[dict[str, object]]:
        try:
            data = json.loads(_FLOORS_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        return [f for f in data.get("floors", []) if isinstance(f, dict)]

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        floors = self._floors()
        if not floors:
            return []
        pip = [f for f in floors if f.get("ecosystem") == "pip"]
        npm = [f for f in floors if f.get("ecosystem") == "npm"]
        go = [f for f in floors if f.get("ecosystem") == "go"]
        maven = [f for f in floors if f.get("ecosystem") == "maven"]
        cargo = [f for f in floors if f.get("ecosystem") == "cargo"]
        docker = [f for f in floors if f.get("ecosystem") == "docker"]
        out: list[Finding] = []
        out.extend(self._scan_pip(root, pip))
        out.extend(self._scan_npm(root, npm))
        out.extend(self._scan_lockfiles(root, pip, npm))
        if go:
            out.extend(self._scan_go(root, profile, go))
        if maven:
            out.extend(self._scan_java(root, maven))
        if cargo:
            out.extend(self._scan_rust(root, cargo))
        if docker:
            out.extend(self._scan_docker(root, profile, docker))
        return out

    def _scan_docker(
        self, root: Path, profile: StackProfile, floors: list[dict[str, object]]
    ) -> list[Finding]:
        """`profile.docker_base_images` against the `docker` floors. See
        `_DOCKER_TAG_EXACT`'s own comment for why only a tag that fully commits to an exact
        major.minor.patch is treated as provable — a floating tag is left alone, same as an
        open pip/npm version spec elsewhere in this guard."""
        out: list[Finding] = []
        by_image: dict[str, list[dict[str, object]]] = {}
        for floor in floors:
            by_image.setdefault(str(floor.get("package", "")), []).append(floor)
        # Sorted: `docker_base_images` is a set, and `Finding.sort_key` ties on two findings in one
        # Dockerfile, so set order would leak into the report (#1134 review M2).
        for image, tag, dockerfile in sorted(profile.docker_base_images):
            image_floors = by_image.get(image)
            if not image_floors:
                continue
            m = _DOCKER_TAG_EXACT.fullmatch(tag)
            if not m:
                continue
            declared = _version(m.group(1))
            if declared is None:
                continue
            if _docker_pragma_allows(root / dockerfile, image, tag):
                continue
            for floor in image_floors:
                if _vulnerable(declared, _fixed_versions(floor), _affected_from(floor)):
                    out.append(self._docker_finding(root, floor, image, tag, dockerfile))
        return out

    def _docker_finding(
        self, root: Path, floor: dict[str, object], image: str, tag: str, dockerfile: str
    ) -> Finding:
        cve = str(floor.get("cve", ""))
        fixed = _fixed_str(floor)
        sev = str(floor.get("severity", "high"))
        return Finding(
            check_id=self.id,
            severity=sev,  # type: ignore[arg-type]
            title=f"Docker base image {image}:{tag} is below the patched version ({cve})",
            location=dockerfile,
            message=(
                f"{floor.get('name', image)}. The base image is pinned to {image}:{tag}, which is "
                f"vulnerable to {cve}; patched in {fixed}."
            ),
            remediation=(
                f"Bump the `FROM {image}:{tag}` tag in {dockerfile} to {fixed} or later, then "
                "rebuild and redeploy the image — a patched base-image tag is not retroactively "
                "applied to a running container."
            ),
            rule="dependency-version-floor/docker-base-image-below-floor",
            standards=["OWASP:A06", "OWASP-LLM:LLM03"],
            url=f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
        )

    def _scan_go(
        self, root: Path, profile: StackProfile, floors: list[dict[str, object]]
    ) -> list[Finding]:
        """`go.sum`-resolved versions against the `go` floors (the ecosystem gap
        this guard previously had no Go support at all for). See `_go_sum_resolved`'s own
        docstring for why `go.mod` itself is deliberately not scanned."""
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in go_scan_dirs(root, profile):
            for f in iter_files(d, (".sum",)):
                if f.name != "go.sum" or f in seen:
                    continue
                seen.add(f)
                resolved = _go_sum_resolved(read(f))
                out.extend(self._flag_resolved(root, f, floors, resolved))
        return out

    def _scan_rust(self, root: Path, floors: list[dict[str, object]]) -> list[Finding]:
        """`Cargo.lock`-resolved versions against the `cargo` floors. See
        `_cargo_lock_resolved`'s own docstring for why `Cargo.toml` itself is not scanned."""
        out: list[Finding] = []
        seen: set[Path] = set()
        for f in iter_files(root, (".lock",)):
            if f.name != "Cargo.lock" or f in seen or _in_build_output(root, f):
                continue
            seen.add(f)
            out.extend(self._flag_resolved(root, f, floors, _cargo_lock_resolved(read(f))))
        return out

    def _scan_java(self, root: Path, floors: list[dict[str, object]]) -> list[Finding]:
        """`pom.xml` + `build.gradle`/`build.gradle.kts` declared versions against the `maven`
        floors. See `_pom_xml_resolved`'s own docstring for why the declared version
        is treated as authoritative here, unlike `go.mod`'s ambiguous lower bound.

        **2026-09-23 fix (Dean's review):** this used to walk `java_scan_dirs(root,
        profile)` — the TOP-LEVEL directory containing a `.java` file (e.g. `src`, for a canonical
        Maven `src/main/java/...` layout) — looking for `pom.xml` INSIDE it. A build manifest is a
        repo/module-root artifact, not a source-tree one: on that exact canonical layout,
        `pom.xml` lives at `root/pom.xml`, outside `root/src` entirely, so the scan found nothing.
        `profile` is no longer used for this; scans `root` directly for the manifest files instead,
        matching how `_scan_pip`/`_scan_npm`/`_scan_rust` already scan the whole repo root rather
        than a language-specific source-dir subset."""
        out: list[Finding] = []
        seen: set[Path] = set()
        for f in iter_files(root, (".xml",)):
            if f.name != "pom.xml" or f in seen or _in_build_output(root, f):
                continue
            seen.add(f)
            out.extend(self._flag_resolved(root, f, floors, _pom_xml_resolved(read(f))))
        for f in iter_files(root, (".gradle", ".kts")):
            if f.name not in ("build.gradle", "build.gradle.kts") or f in seen:
                continue
            seen.add(f)
            out.extend(self._flag_resolved(root, f, floors, _gradle_resolved(read(f))))
        return out

    def _flag_resolved(
        self, root: Path, f: Path, floors: list[dict[str, object]], resolved: dict[str, str]
    ) -> list[Finding]:
        out: list[Finding] = []
        for floor in floors:
            v = resolved.get(str(floor.get("package", "")))
            declared = _version(v) if v else None
            if v and declared and _vulnerable(declared, _fixed_versions(floor), _affected_from(floor)):
                out.append(self._finding(root, f, floor, v))
        return out

    def _scan_lockfiles(
        self, root: Path, pip: list[dict[str, object]], npm: list[dict[str, object]]
    ) -> list[Finding]:
        """Resolved versions from poetry.lock / package-lock.json (the v2 path that
        catches an open range like `>=0.3.0` that resolves to a vulnerable version)."""
        out: list[Finding] = []
        # poetry.lock — [[package]] blocks with name = "x" / version = "y"
        for f in iter_files(root, (".lock",)):
            if f.name != "poetry.lock":
                continue
            resolved: dict[str, str] = {}
            name: str | None = None
            for line in read(f).splitlines():
                nm = re.match(r'\s*name\s*=\s*"([^"]+)"', line)
                if nm:
                    name = nm.group(1)
                    continue
                vm = re.match(r'\s*version\s*=\s*"([^"]+)"', line)
                if vm and name:
                    resolved[name] = vm.group(1)
                    name = None
            out.extend(self._flag_resolved(root, f, pip, resolved))
        # package-lock.json — resolved "version" under packages/ or dependencies/
        for f in iter_files(root, (".json",)):
            if f.name != "package-lock.json":
                continue
            try:
                data = json.loads(read(f))
            except ValueError:
                continue
            resolved = {}
            for section in ("packages", "dependencies"):
                node = data.get(section)
                if not isinstance(node, dict):
                    continue
                for key, meta in node.items():
                    if isinstance(meta, dict) and isinstance(meta.get("version"), str):
                        pkg = str(key).split("node_modules/")[-1]
                        if pkg:
                            resolved.setdefault(pkg, str(meta["version"]))
            out.extend(self._flag_resolved(root, f, npm, resolved))
        return out

    def _scan_pip(self, root: Path, floors: list[dict[str, object]]) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _PIP_MANIFESTS):
            text = read(f)
            # The pragma counts only as a `#` comment, never the phrase in a TOML string (#1040).
            # `hash` for every pip manifest, `.in`/`.lock` included: `comment_dialect_for` reads
            # those as comment-less, which would match the raw text. The view is same-length and
            # keeps every line boundary, so its lines pair with the text's.
            view = comment_view(text, "hash")
            # Candidate spec strings: for pyproject.toml the extracted PEP 621 / poetry dep strings;
            # for requirements/.in/.lock each line. `pview` is the view the pragma is checked in:
            # the whole manifest for TOML, the candidate's own line otherwise.
            if f.suffix == ".toml":
                candidates = [(s, view) for s in _toml_dep_strings(_load_toml(f))]
            else:
                candidates = list(zip(text.splitlines(), view.splitlines(), strict=True))
            for cand, pview in candidates:
                for floor in floors:
                    pkg = str(floor.get("package", ""))
                    if _pragma_for(pkg).search(pview):
                        continue
                    specs = _specs_for_pkg(cand, pkg)
                    if not specs:  # pkg absent, or bare name (no constraint) — not flagged
                        continue
                    fixed = _fixed_versions(floor)
                    affected_from = _affected_from(floor)
                    # An exact pin takes precedence (the CVE's own severity).
                    exact = next((v for (op, v) in specs if op in ("==", "===")), None)
                    if exact is not None:
                        dv = _version(exact)
                        if dv and _vulnerable(dv, fixed, affected_from):
                            out.append(self._finding(root, f, floor, exact, pragma=True))
                        continue
                    # Otherwise: an upper bound that provably cannot reach the patched floor -> HIGH.
                    if _upper_bound_unreachable(specs, fixed, affected_from):
                        out.append(self._upper_finding(root, f, floor, cand.strip()))
        return out

    def _upper_finding(self, root: Path, f: Path, floor: dict[str, object], spec: str) -> Finding:
        pkg = str(floor.get("package", ""))
        cve = str(floor.get("cve", ""))
        fixed = _fixed_str(floor)
        return Finding(
            check_id=self.id,
            severity="high",
            title=f"{pkg} upper-bound pin cannot reach the patched floor ({cve})",
            location=rel(root, f),
            message=(
                f"{floor.get('name', pkg)}. The constraint `{spec}` caps {pkg} below the patched "
                f"floor ({fixed}), so the resolver can never install a version that fixes {cve}."
            ),
            remediation=f"Raise the upper bound to allow {pkg} {fixed} or later. {_opt_out(pkg, True)}",
            rule="dependency-version-floor/upper-bound-below-floor",
            standards=["OWASP:A06", "OWASP-LLM:LLM03"],
            url=f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
        )

    def _scan_npm(self, root: Path, floors: list[dict[str, object]]) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".json",)):
            if f.name != "package.json":
                continue
            try:
                data = json.loads(read(f))
            except ValueError:
                continue
            deps: dict[str, object] = {}
            for key in ("dependencies", "devDependencies"):
                d = data.get(key)
                if isinstance(d, dict):
                    deps.update(d)
            for floor in floors:
                pkg = str(floor.get("package", ""))
                spec = deps.get(pkg)
                if not isinstance(spec, str) or not re.match(r"^\d", spec):  # exact pin only
                    continue
                declared = _version(spec)
                fixed = _fixed_versions(floor)
                if declared and _vulnerable(declared, fixed, _affected_from(floor)):
                    out.append(self._finding(root, f, floor, spec))
        return out

    def _finding(
        self, root: Path, f: Path, floor: dict[str, object], declared: str, *, pragma: bool = False
    ) -> Finding:
        pkg = str(floor.get("package", ""))
        cve = str(floor.get("cve", ""))
        fixed = _fixed_str(floor)
        sev = str(floor.get("severity", "high"))
        return Finding(
            check_id=self.id,
            severity=sev,  # type: ignore[arg-type]
            title=f"{pkg} {declared} is below the patched version ({cve})",
            location=rel(root, f),
            message=(
                f"{floor.get('name', pkg)}. The pinned {pkg}=={declared} is vulnerable to {cve}; "
                f"patched in {fixed}."
            ),
            remediation=f"Upgrade {pkg} to {fixed} or later. {_opt_out(pkg, pragma)}",
            rule="dependency-version-floor/below-patched-version",
            standards=["OWASP:A06", "OWASP-LLM:LLM03"],
            url=f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
        )
