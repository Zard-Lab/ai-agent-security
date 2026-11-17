"""Guard: Go build/install supply-chain footguns in Dockerfiles and CI workflows
(mechanism B — artifact-layer Go risk, JadePuffer defense plan follow-up).

`foreign_artifacts` (PR #601) disclosed that a source-only `.go` census can say "no Go
here" for a repo that runs Go entirely as a prebuilt binary or base image. This guard is
the next layer down: for repos that DO compile Go somewhere in their build pipeline
(a multi-stage Dockerfile, a CI step) rather than only consuming a prebuilt image, it
flags two build-time supply-chain footguns CodeQL and `go help install`/`go env` both
document as real risk, neither of which needs any `.go` SOURCE file present in the
scanned repo to fire — the footgun lives in the Dockerfile/CI text, not in Go code:

  * **`go-install-unpinned`** (HIGH, CWE-829, OWASP:A08) — `go install
    <module-path>@latest`/`@master`/`@main` resolves to whatever the tag currently
    points at, at BUILD time, with no lockfile: identical supply-chain shape to an
    unpinned `curl | bash` or an unpinned GitHub Action (`actions-sha-pin`'s existing
    checklist item) — the ref is mutable, and whoever controls it controls what gets
    compiled into the image. A pinned version (`@v1.2.3`) or a full commit hash is safe.
  * **`go-checksum-verification-disabled`** (HIGH, CWE-345, OWASP:A08) — `GOSUMDB=off`
    (or the legacy `GONOSUMCHECK=1`) disables Go's module checksum database
    verification entirely, the mechanism that would otherwise catch a compromised or
    tampered module before it's compiled in. This is the Go-toolchain equivalent of
    disabling package-manager signature verification.

Scoped to Dockerfiles (`RUN`/`ENV`/`ARG` instructions, gated on `"docker" in
profile.features`, mirroring `curl_pipe_to_shell.py`'s Dockerfile scope exactly) and
top-level GitHub Actions workflow files (`run:` steps and `env:` blocks under
`.github/workflows/*.yml`, mirroring `actions_sha_pin.py`'s scan scope — top-level only,
GitHub never executes a workflow file in a subdirectory). `applies()` is unconditionally
True: a Dockerfile or CI workflow compiling Go can exist in a repo agentsec's own Go-
source detection reports as having none (a builder stage's own vendored/generated
module, a separate CI-only tool build) — the same "artifact-layer, not source-layer"
shape `foreign_artifacts` exists to name, not a detection gap in this guard.

**Deliberately NOT attempted** (documented, not silently skipped — see the other
open mechanisms): missing `-trimpath` on `go build` (a reproducibility/path-disclosure
hygiene item, not a supply-chain integrity one — real FP risk since many legitimate
builds omit it, and it doesn't fit this guard's "the ref/verification is the risk" theme)
and "an unrebuilt `*-builder` base image" (not statically verifiable from Dockerfile
content alone — would need to compare against actual registry freshness, which this
guard's zero-network static-scan posture cannot do).

Suppress an audited exception on the offending line:

    RUN go install golang.org/x/tools/gopls@latest  # security: allow-go-install-unpinned
    ENV GOSUMDB=off  # security: allow-go-checksum-disabled
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_dockerfiles,
    join_dockerfile_continuations,
    pragma_line_set,
    read,
    rel,
    strip_hash_comments,
)

_STANDARDS = ["OWASP:A08", "CWE-829"]
_CHECKSUM_STANDARDS = ["OWASP:A08", "CWE-345"]

# `go install <module-path>@<ref>` — the ref is what matters. A real version tag
# (`v1.2.3`, `v0.1.0-beta.1`) or a full/short commit hash is pinned and safe; `latest`,
# `master`, `main`, or a bare unversioned install (module@ with nothing, rare but treated
# as unpinned) is not. Module path itself is not validated (any `.../pkg@ref` shape).
_GO_INSTALL = re.compile(
    r"\bgo\s+install\s+(?P<module>[^\s@]+)@(?P<ref>latest|master|main)\b", re.IGNORECASE
)
_GO_INSTALL_PRAGMA = re.compile(r"#\s*security:\s*allow-go-install-unpinned")

# `GOSUMDB=off` / `GONOSUMCHECK=1` — Dockerfile ENV/ARG, a `RUN export ...`/`RUN GOSUMDB=off go ...`
# inline assignment, or a CI `env:` mapping value. Matched loosely on the assignment itself,
# not anchored to a specific instruction keyword, so all three shapes are caught by one pattern.
_GOSUMDB_OFF = re.compile(r"\bGOSUMDB\s*[=:]\s*['\"]?off['\"]?", re.IGNORECASE)
_GONOSUMCHECK_ON = re.compile(r"\bGONOSUMCHECK\s*[=:]\s*['\"]?1['\"]?")
_CHECKSUM_PRAGMA = re.compile(r"#\s*security:\s*allow-go-checksum-disabled")


def _scan_lines(root: Path, f: Path, text: str) -> list[Finding]:
    out: list[Finding] = []
    # Detection matches the comment-STRIPPED line (a Dockerfile/CI doc line merely mentioning
    # `go install foo@latest` must not fire); the pragma is read from the `hash` comment view of
    # the same line, since both opt-out pragmas live inside a `#` comment themselves: stripping
    # first would delete the user's own opt-out along with the comment (review-doctrine rule 4),
    # and a raw match would let a quoted string carry it. `hash`, not `yaml`, for a workflow: a
    # `go install` sits in a `run: |` script, whose shell comments the yaml view reads as content.
    # Mirrors curl_pipe_to_shell.py's pragma-on-view / match-on-stripped order.
    install_ok = pragma_line_set(_GO_INSTALL_PRAGMA, text, dialect="hash")
    checksum_ok = pragma_line_set(_CHECKSUM_PRAGMA, text, dialect="hash")
    for i, line in enumerate(text.splitlines(), start=1):
        code = strip_hash_comments(line)
        m = _GO_INSTALL.search(code)
        if m and i not in install_ok:
            out.append(
                Finding(
                    check_id="go-build-supply-chain-footgun",
                    severity="high",
                    title="go install pinned to a mutable ref (@latest/@master/@main)",
                    location=f"{rel(root, f)}:{i}",
                    message=(
                        f"`go install {m.group('module')}@{m.group('ref')}` resolves to whatever "
                        "that tag currently points at, at build time, with no lockfile — identical "
                        "supply-chain shape to an unpinned curl-pipe-to-shell or an unpinned "
                        "GitHub Action. Whoever controls that tag controls what gets compiled in."
                    ),
                    remediation=(
                        "Pin to a specific version (`@v1.2.3`) or a full commit hash instead of "
                        "`@latest`/`@master`/`@main`."
                    ),
                    rule="go-build-supply-chain-footgun/go-install-unpinned",
                    standards=_STANDARDS,
                )
            )
        if (_GOSUMDB_OFF.search(code) or _GONOSUMCHECK_ON.search(code)) and i not in checksum_ok:
            out.append(
                Finding(
                    check_id="go-build-supply-chain-footgun",
                    severity="high",
                    title="Go module checksum verification disabled",
                    location=f"{rel(root, f)}:{i}",
                    message=(
                        "GOSUMDB is disabled (or GONOSUMCHECK is set), turning off the checksum "
                        "database verification that would otherwise catch a compromised or "
                        "tampered Go module before it's compiled into the build."
                    ),
                    remediation=(
                        "Remove the GOSUMDB=off / GONOSUMCHECK=1 override, or scope it narrowly "
                        "to a documented, audited private-module exception (GONOSUMCHECK / "
                        "GOPRIVATE for the specific internal module path)."
                    ),
                    rule="go-build-supply-chain-footgun/checksum-verification-disabled",
                    standards=_CHECKSUM_STANDARDS,
                )
            )
    return out


class GoBuildSupplyChainFootgunGuard(Guard):
    id = "go-build-supply-chain-footgun"
    title = "Go build/install supply-chain footgun in Dockerfile or CI"
    area = "Dependencies"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `Dockerfile.go-build-footgun`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(
        expects=frozenset({
            "go-build-supply-chain-footgun/go-install-unpinned",
            "go-build-supply-chain-footgun/checksum-verification-disabled",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        # Unconditionally relevant — a Dockerfile compiling Go, or a CI step running
        # `go install`, can exist in a repo agentsec's own Go-source detection reports as
        # having none (see module docstring). Mirrors curl_pipe_to_shell.py's rationale.
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []

        if "docker" in profile.features:
            for f in iter_dockerfiles(root):
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(_scan_lines(root, f, join_dockerfile_continuations(read(f))))

        workflows = root / ".github" / "workflows"
        if workflows.is_dir():
            for f in sorted(p for p in workflows.iterdir() if p.is_file() and p.suffix in (".yml", ".yaml")):
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(_scan_lines(root, f, read(f)))

        return out
