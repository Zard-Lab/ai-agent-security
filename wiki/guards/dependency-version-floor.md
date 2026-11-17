---
type: Guard
title: "dependency-version-floor"
description: "Dependencies meet the patched-version floor for known CVEs."
timestamp: "2026-09-23T17:55:57+00:00"
guard_id: "dependency-version-floor"
checklist_section: ["5", "6a"]
standards: ["ASVS:4.2.1", "OWASP-LLM:LLM03", "OWASP:A05", "OWASP:A06", "OWASP:A07", "OWASP:A10", "SOC2:CC7.1"]
---

# Dependencies meet the patched-version floor for known CVEs

Reads a curated list of CVE version floors (`agentsec/guards/version_floors.json`) and flags any
project that **pins** a dependency below its patched version. Closes checklist item
`5-known-cve-version-floors`. This is the enforcement half of the threat-intake loop.

## The threat

A known, high-severity CVE in a stack dependency is exploitable until the dependency is upgraded.
The slow-clock /threat-intake *discovers* these (e.g. LangGrinch CVE-2025-68664 in langchain-core,
BadHost CVE-2026-48710 in starlette) and records the fixed-in version; without this guard, that
knowledge sits in a checklist item that a human has to remember to act on. The guard makes it an
automatic check. OWASP A06 (Vulnerable & Outdated Components), OWASP-LLM:LLM03 (supply chain).

## Exploitability rationale

Severity is taken from the floor entry (the CVE's own severity). The seeds are all CRITICAL
(serialization RCE, auth bypass). The control itself is high value: it turns autonomous discovery
into automatic enforcement.

## Why a guard when pip-audit/npm-audit exist

The audit runners are **optional** (need the binary installed) and scan against the full upstream CVE
DB. This guard is **dependency-free, always-on, and curated**: it enforces the specific floors we
vet for our stack, deterministically, even with no scanner present. The two are complementary
(defense in depth).

## When NOT to flag (and the pragma)

- **Patched pin** — `langchain-core==0.3.81` (at/above the floor) → silent.
- **Backport line** — starlette is fixed in both 0.46.2 (the 0.x line) and 1.0.1; `==0.46.2` is
  patched, `==0.46.1` is not. The version logic treats "patched on its own major.minor line OR at/above
  the highest fix" as safe.
- **Open ranges** — `>=`, `^`, `~`, `>` are ambiguous from the manifest (the resolved version may be
  patched), so they are **not** flagged; the lockfile-resolved path catches those.
- **Bare/unpinned** — a package listed with no constraint resolves to the latest (patched) version, so
  it is **not** flagged (no false positive on unpinned deps).
- **Package not present** → nothing to flag.
- An audited exception → `# security: allow-old-<package>` on the pin line (or anywhere in a TOML manifest),
  as a `#` comment with whitespace before the `#`: the phrase inside a TOML string value does not count
  (#1040), and neither does a comment glued to a closing bracket (`]# …`), which the `#`-comment view
  does not read.
  In a Dockerfile the same `# security: allow-old-<image>` goes in the `#` comment lines directly
  above the `FROM` (Docker allows no trailing comment on an instruction line). Every `FROM` of that
  `image:tag` in the file needs it, or the finding stays.
  Only the pip-manifest and Dockerfile paths read that pragma. `package.json`, the lockfiles (`poetry.lock`,
  `package-lock.json`, `go.sum`, `Cargo.lock`) and the Maven manifests (`pom.xml`, `build.gradle`)
  never do, and JSON and `go.sum` cannot hold a comment anyway, so those findings' remediation
  points at an expiring `agentsec-exceptions.json` entry instead.

## What fires (two manifest-provable cases)

1. **Exact pin below the floor** (`==`/`===`, or poetry `= "==X"`) → the CVE's own severity.
2. **Upper bound that cannot reach the floor** (`<X`/`<=X`, including the blocking clause of a compound
   `>=a,<X`) → **HIGH** (`upper-bound-below-floor` rule). The resolver provably can never install a
   patched version.

Both pip requirements files and `pyproject.toml` (PEP 621 `[project].dependencies` /
`[project.optional-dependencies]` and `[tool.poetry.dependencies]`) are parsed. The upper-bound tier
and the TOML parsing were folded in from the retired `dependency-version-floors` guard (PR #226), so all
floors stay single-sourced in `version_floors.json` (no hardcoded duplicates).

**2026-09-21: Go ecosystem support.** A 3rd path reads `go.sum` for `"ecosystem": "go"`
floors (e.g. `github.com/modelcontextprotocol/go-sdk`, floored
at `1.4.1` for a 3-CVE MCP Go SDK consolidation: DNS-rebinding-default-off, missing `Origin`
validation, case-insensitive JSON-RPC parsing). `go.mod`'s own `require` line is deliberately NOT
scanned: under Go's Minimal Version Selection, a `require` line only states a LOWER bound the
resolver can raise, exactly the "ambiguous open range" shape this guard already declines to flag
for pip/npm. `applies()` accepts `"go" in profile.languages` (which `detect.py` sets from `.go`
source files only) alongside the existing `python`/`frontend` gates. Java and Rust landed separately (PR #922,
below).

**`go.sum` is not a lockfile.** Unlike `poetry.lock`/`package-lock.json` (one resolved version per
package), `go.sum` is an append-only checksum ledger: every module version the `go` command verified
stays until `go mod tidy` prunes it, so one module routinely appears at several versions, and a
`<module> <version>/go.mod h1:` line only hashes a `go.mod` consulted while building the module graph
(that version need not be in the build at all). The guard therefore reads it one-sidedly: `/go.mod`
lines are skipped, and the **max** version among a module's content-hash lines is compared to the
floor. A module whose packages are built has a content line for the version Go selected, so the max
is an upper bound on that version: when even the max is below the floor, so is the built version,
and a stale line cannot produce a false positive. The cost is the downgrade case listed under Known
bypasses.

**2026-09-22 correction (found while building the sibling Java/Rust slices, PR #922):** this
doc previously claimed "Go has no `features` flag," so `agentsec coverage` would show
`5-known-cve-version-floors` N/A on a Go-only repo despite the guard genuinely running there.
That was wrong — `detect.py`'s own `feats = set(prof.languages)` seeds `features` from
`languages`, so `"go"` legitimately belongs in the item's `applies_when` — added.

**2026-09-22: Java/Maven ecosystem support.** A 4th ecosystem path reads `pom.xml`'s own
`<dependency>` `<version>` declarations (ElementTree, namespace-qualified) and
`build.gradle`/`build.gradle.kts`'s single-string GAV coordinate form, for `"ecosystem": "maven"`
floors keyed by `groupId:artifactId` (e.g. `io.modelcontextprotocol.sdk:mcp-core`, floored at
`1.0.1`/`1.1.1` for a 2-CVE MCP Java SDK consolidation: DNS rebinding + hardcoded wildcard CORS).
Unlike Go's `go.mod` (a genuinely ambiguous lower bound under Minimal Version Selection), a Maven
POM's own declared version IS treated as authoritative: Maven's ecosystem convention overwhelmingly
pins an exact `<version>`, not a range, mirroring how this guard already treats an npm
`package.json` exact pin. `applies()` gates on `"java" in profile.languages`, mirroring the Go
slice's own gate. `detect.py` also seeds `profile.features` from `profile.languages`, so `"java"`
is added to the mapped checklist item's own `applies_when` (`5-known-cve-version-floors`) here too
— `agentsec coverage` now correctly reports the item applicable, not N/A, on a Java-only repo. A
`${property}`-substituted `<version>` is not resolved (disclosed gap, matching `agent-audit-kit`'s
own real Java-pin scanner), and neither is Gradle's map-notation dependency form, only its
single-string GAV form.

**Rust/Cargo ecosystem support, same pass.** A 5th path reads `Cargo.lock`'s own `[[package]]`
blocks (standard TOML, parsed with `tomllib`) for `"ecosystem": "cargo"` floors keyed by crate
name (e.g. `rmcp`, the official MCP Rust SDK, floored at `1.4.0`; `apollo-mcp-server`, floored at
`1.7.0`). `Cargo.toml`'s own `[dependencies]` declarations are NOT scanned: Cargo's default
requirement operator is caret (`rmcp = "1.2.0"` means `^1.2.0`, an open range), the same
"ambiguous manifest" shape this guard already declines to flag for pip/npm/Go. `applies()` gates
on `"rust" in profile.languages` — a brand-new detection signal added to `detect.py` in the same
change: Rust previously had zero `languages`/`features` presence, only a threshold-based
`foreign_languages` disclosure; `.rs` was removed from that census table on the same graduation
precedent Go/PHP/Ruby/Java already established (never double-reported in both places).

**2026-10-22: Docker base-image ecosystem support.** A 6th path reads
`StackProfile.docker_base_images` — every Dockerfile `FROM <image>:<tag>` pair that names an
EXPLICIT tag, any language — for `"ecosystem": "docker"` floors keyed by the bare image name
(e.g. `php`, floored at `8.5.12`/`8.4.27`/`8.3.36`/`8.2.35` for the PHP interpreter's
unauthenticated-RCE CVE pair, CVE-2026-109618/CVE-2026-109619, CVSS 9.2 each — the Contabo VPS
patch notice that surfaced this gap; the fixed-in set is the one Fastly's write-up lists,
<https://www.fastly.com/blog/critical-rce-vulnerabilities-discovered-core-php-cve-2026-109618-cve-2026-109619>,
and Unit 42's threat brief describes the pair,
<https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/>). Surfaced during a deep-dive into why agentsec had nothing to
say about that notice: `version_floors.json` had zero runtime/interpreter ecosystem at all — not
a PHP-specific gap, a structural one, since every existing ecosystem keys off a PACKAGE manifest,
and a language interpreter is not a package dependency of itself.

Only a tag that fully commits to an exact major.minor.patch is treated as provable (`8.2.35`,
`8.2.35-fpm`, `8.2.35-alpine3.19`) — a floating tag (`php:8.3`, `node:18`, `latest`) is Docker
Hub's own minor/major-tracking convention and resolves to whatever patch is current *at pull
time*, the same "ambiguous range, decline to flag" rule this guard already applies to an open
pip/npm version spec. **This makes the check narrow in practice, not just in principle:** most
real-world Dockerfiles pin a moving tag like `php:8.3-fpm`, not an exact patch (`php:8.3.36-fpm`)
— those stay completely silent even when the image actually built from that tag is old, because
the Dockerfile alone cannot say which patch got pulled. The exact-pin case this guard DOES catch
(a team that deliberately freezes a full version for reproducibility) is the minority shape. The
PHP floor entry also carries `"affected_from": "5.4.0"` (the #1134 review): PHP versions
below that predate the affected range entirely and are correctly left silent, same mechanism as
the Python/anthropic `affected_from` example in this guard's own module docstring. `applies()`
gates on `profile.has_docker` (any Dockerfile present),
independent of the language gates above — a repo can have no recognized source language at all
and still have a base image worth checking. `profile.docker_base_images` is populated unfiltered
by the SAME `FROM`-line walk `foreign_artifacts` already does (same stage-alias exclusion, same
digest/tag parsing), but unlike `foreign_artifacts` — deliberately curated to a short Go-only list
for a different purpose, disclosing a language the source census can never see — it records every
tagged base image, any language.

This is a static, offline, zero-network check against the curated floor list, deliberately
narrower in scope than `trivy image --image-src remote` (the runner that actually pulls an image
and reads its real installed OS package inventory against a live CVE DB, gated on `--network
tier1`): `trivy`'s own base-image registry scan is currently wired only for the curated Go-image
table (`detect.py::_GO_BASE_IMAGES` / `foreign_artifacts`) — generalizing that mechanism to every
Dockerized stack is a related, larger change (egress-policy-adjacent: more images pulled by
default at tier1) left as a follow-on, not folded into this one.

**2026-10-25 (#1161): extended to `python` and `node`.** The docker ecosystem was extended to
cover `python`/`node`/`postgres` base images too, as a follow-on to #1134. `python` is floored at `3.14.8`/`3.13.16`/
`3.12.15`/`3.11.17`/`3.10.22` for CPython's `ssl`-module use-after-free (CVE-2026-19445, CVSS 9.2
— a server's `sni_callback` swapping `SSLContext` with nothing else holding the original
reference) plus a related hostname-validation gap (CVE-2026-19553, same fixed-in set). `node` is
floored at `26.12.1`/`24.22.1`/`22.23.4` for the October 2026 security release's High-severity
batch: a `node:zlib` Brotli-decoder out-of-bounds write (CVE-2026-111497) plus two DNS/TLS
hostname-confusion bugs, all three fixed on the same release per line.

**`postgres` was deliberately NOT added.** Checked against Docker Hub's real tag list before
writing any floor data (not assumed from php/python/node's pattern): the official `postgres`
image's own tags are 2-component (`16.15`, `16.14`, ...), never 3-component like every ecosystem
`_DOCKER_TAG_EXACT` currently requires (`\d+\.\d+\.\d+`) — so a genuinely exact, pinned postgres
tag could never satisfy that regex, and a floor entry would be silently dead on every real-world
Dockerfile (pinned by `test_version_floor_docker_postgres_tag_shape_cannot_match_today`). Shipping
one anyway would be exactly the "failure that presents as success" this project's review doctrine
calls out: it would read as coverage in the checklist/registry while never actually firing.
Extending `_DOCKER_TAG_EXACT`/`_vulnerable`'s release-line matching to a per-image exactness depth
is a real (small) design change shared with every other docker entry, not a JSON-only addition —
left as a follow-on rather than built unreviewed.

## Known bypasses (honest limits)

- **Lockfiles are read** (v2): `poetry.lock` (`[[package]]` name/version), `package-lock.json`
  (resolved `version` under `packages`/`dependencies`), and `go.sum` (the max content-hash version
  per module, see above) are parsed, so an open range/requirement like `>=0.3.0`, or a Go
  dependency whose every recorded version is below the floor, is still caught. `yarn.lock` /
  `pdm.lock` / `Pipfile.lock` are not yet parsed — the documented next step.
- **Go downgrade without `go mod tidy`** (`go get pkg@older` after a newer version was recorded):
  `go.sum` keeps the newer, patched line, the max reports it, and the vulnerable build stays silent.
  This is the price of never gating on a stale line (pinned by a test).
- **Go major-version module paths** (`.../go-sdk/v2`) are a different module path; a floor entry
  matches its exact `package` path only, so a `/vN` module needs its own entry (pinned by a test).
- **Go pseudo-versions** are compared by their base release: `v0.0.0-<time>-<hash>` (no tag) reads as
  `0.0.0` and fires whatever the commit, while `v1.4.1-0.<time>-<hash>` (a commit after `v1.4.0`,
  before the `v1.4.1` tag) reads as `1.4.1` and stays silent even if it predates the fix.
- **A Go repo with no `.go` file** (only `go.mod`/`go.sum`, e.g. a tools module) is not detected as
  Go, so the guard does not run on it. The `go-osv-hygiene` runner does read that shape, but only
  at `--network tier1` (it queries OSV.dev), so the default offline audit covers neither. The
  guard also applies on `python`/`frontend`, so the same stray `go.sum` in a Python or frontend repo
  IS read and can fire (#937 decides which behaviour is intended).
- **Java/Maven**: `pom.xml` and `build.gradle`/`build.gradle.kts` are parsed for declared versions.
  A `${property}`-substituted `<version>` is not resolved, and Gradle's map-notation dependency form
  is not recognized (only the single-string GAV form).
- **Rust/Cargo**: `Cargo.lock` (the resolved dependency tree) is parsed; `Cargo.toml`'s own
  `[dependencies]` declarations are not, since Cargo's default caret requirement is an
  ambiguous open range, same as `go.mod`.
- **`target/` is skipped for `pom.xml` and `Cargo.lock`**: it is the Maven and Cargo build-output
  directory, where `mvn package` and `cargo package` write copies of the real manifest, and reading
  them reported one CVE twice. A real manifest placed in a directory named `target` is skipped too.
  The path is taken relative to the scanned root, so a checkout under a `target` directory still scans.
- **Docker base image, name matching**: the bare image name is taken from the LAST `/`-path
  segment only (`_bare_image_name`, shared with `foreign_artifacts`), so a custom or private image
  that merely happens to share a curated floor's basename is indistinguishable from the real
  thing — `ghcr.io/acme/php:7.4.33` (an org's own unrelated image, versioned on its own scheme)
  reads as `php` and fires against the PHP floor even though it has nothing to do with the PHP
  interpreter (pinned by `test_version_floor_docker_custom_registry_path_named_php_is_a_known_fp`,
  the #1134 review). Not fixed here: the same tradeoff was already accepted for
  `foreign_artifacts`, just at lower stakes (a disclosure line, not a CRITICAL finding).
- **Docker base image, images with 2-component versioning (e.g. `postgres`) are not covered at
  all** (#1161): `_DOCKER_TAG_EXACT` requires exactly 3 numeric dot-separated components
  (`8.3.36`, `3.12.15`, `22.23.4`), but the official `postgres` image's own real tags are
  2-component (`16.15`) — no real-world postgres tag, however exactly pinned, can ever match. A
  floor entry was deliberately not added for it (see above) rather than ship coverage that can't fire.
- **Docker base image, tag exactness**: only a tag naming an exact major.minor.patch is checked; a floating tag
  (`php:8.3`, `latest`) is not — the build could be pulling a patched or unpatched version and
  the Dockerfile alone can't say which. A base image referenced only by `@digest` is never
  checked either (no version string at all to compare). And this only ever sees what the
  Dockerfile *declares* — it has no way to know what's actually deployed if the running
  container was built from a different, undeclared tag, or never rebuilt after the floor's own
  `FROM` line was bumped (see `5-docker-base-rebuild`, a separate, still-manual checklist item for
  exactly that "rebuild to actually pick up the fix" step).
- A package vendored / installed outside the manifest is invisible.
- The floor list is only as current as `version_floors.json` (the intake loop appends to it).

## What this guard does NOT prove

It proves the **declared pin** meets the floors we curate; it does not prove the **installed** tree is
clean (run pip-audit/npm-audit for the full DB), nor that floors outside our curated list are met.
Absence of a finding ≠ no vulnerable dependency.

# Citations

[1] agentsec checklist item `5-known-cve-version-floors` (§5)
[2] agentsec checklist item `5-pydantic-ai-ssrf-version-floor` (§5)
[3] agentsec checklist item `6a-starlette-host-header-validation` (§6a)
[4] ASVS:4.2.1
[5] OWASP-LLM:LLM03
[6] OWASP:A05
[7] OWASP:A06
[8] OWASP:A07
[9] OWASP:A10
[10] SOC2:CC7.1
