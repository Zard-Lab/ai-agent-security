"""Guard: container image build/push with no SBOM or provenance/signing step
(checklist §5 — Dependency & Supply Chain).

Both Google's "Vibe Coding Agent Security and Evaluation" and Wiz's "From Prompts to
Production" reports call for SBOM generation, SLSA provenance, and digital-signature
verification as a standard part of a CI/CD deploy pipeline — the single strongest
unclaimed item from an earlier report-mining pass
(`docs/knowledge/improvement-backlog-vibe-coding-reports.md`, item G4). Until this
guard, agentsec had no guard, runner, or CI template that detected or enforced any of
the three; the only prior trace was remediation prose in `js_supply_chain.py`
suggesting `npm audit signatures`.

Without an SBOM, nobody can answer "which exact dependency versions shipped in this
image" after the fact — the question every post-incident supply-chain investigation
starts with (Log4Shell, xz-utils, the countless typosquat/lifecycle-script worms this
project's own supply-chain guards already track upstream of the build). Without
provenance/signing, nothing proves the image running in production was actually built
by this pipeline from this source, rather than pushed directly to the registry by
anyone holding a push credential.

**Detection — two-stage, workflow-file-scoped:**

1. **Does this workflow build AND push a container image?** `docker/build-push-action`
   with a literal `push: true` in the same step, OR a raw `docker push` in a `run:`
   step. (`push: ${{ ... }}` — a conditional/expression — is deliberately NOT treated
   as evidence of pushing: this guard only fires when it can see the push happens
   unconditionally, the safe direction for a check that can produce a real supply-chain
   gap if wrong.)
2. **If so, is there ANY SBOM or provenance/signing evidence anywhere in the same
   file?** SBOM: `anchore/sbom-action`, a `sbom: true` key (the built-in
   `docker/build-push-action` flag), `syft`, or `cyclonedx`. Provenance/signing:
   `slsa-framework/slsa-github-generator`, `actions/attest-build-provenance`, a
   `provenance: true` key (the built-in `docker/build-push-action` flag), or
   `cosign sign`/`cosign attest`. Presence of EITHER class silences the guard — SBOM
   and provenance are complementary, not required together, and this guard's job is to
   catch a pipeline with neither, not to enforce a specific combination.

**What this does NOT do:** it does not verify the SBOM/provenance step actually
succeeds, runs before the push, or is configured correctly (a `syft` step present but
never invoked is invisible to a presence check) — a repo-wide marker scan, the same
class of check `js_host_header_email_link.py`'s mail-indicator gate and the CSRF-
middleware-absence pattern in `codeql-security-queries-patterns.md` already use for
"is there ANY evidence of X anywhere in this file" checks.

**Suppress:** `# security: allow-missing-sbom-provenance` anywhere in the workflow
file (matches `actions-sha-pin`'s own file-scoped pragma convention).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, pragma_present, read, rel

_PRAGMA = re.compile(r"#\s*security:\s*allow-missing-sbom-provenance")

_BUILD_PUSH_ACTION = re.compile(r"""uses\s*:\s*["']?docker/build-push-action""")
_PUSH_TRUE = re.compile(r"""\bpush\s*:\s*true\b""")
_DOCKER_PUSH_CMD = re.compile(r"""\bdocker\s+push\b""")

_SBOM_EVIDENCE = re.compile(
    r"""uses\s*:\s*["']?anchore/sbom-action|"""
    r"""\bsbom\s*:\s*true\b|"""
    r"""\bsyft\b|"""
    r"""\bcyclonedx\b""",
    re.IGNORECASE,
)
_PROVENANCE_EVIDENCE = re.compile(
    r"""uses\s*:\s*["']?slsa-framework/slsa-github-generator|"""
    r"""uses\s*:\s*["']?actions/attest-build-provenance|"""
    r"""\bprovenance\s*:\s*true\b|"""
    r"""\bcosign\s+(?:sign|attest)\b""",
    re.IGNORECASE,
)


def _builds_and_pushes_image(text: str) -> bool:
    """True if `text` (one workflow file) both invokes `docker/build-push-action`
    with a literal `push: true` step, OR runs a raw `docker push` command — either
    is unconditional evidence this workflow ships an image to a registry."""
    if _DOCKER_PUSH_CMD.search(text):
        return True
    for m in _BUILD_PUSH_ACTION.finditer(text):
        # The `push: true` key belongs to the SAME step block as the `uses:` line —
        # bounded to a short lookahead window (a step's own key list), not the whole
        # file, so an unrelated LATER step's `push: true` (a different action
        # entirely) is never mistaken for this one's.
        window = text[m.end():m.end() + 500]
        if _PUSH_TRUE.search(window):
            return True
    return False


class CiImageBuildNoSbomProvenanceGuard(Guard):
    id = "ci-image-build-no-sbom-provenance"
    title = "Container image build/push with no SBOM or provenance/signing step"
    area = "Build pipeline"

    # .github/workflows/release.yml: docker/build-push-action with push: true, and
    # nothing else in the file mentioning sbom/syft/cyclonedx/slsa/cosign/provenance ->
    # fires ci-image-build-no-sbom-provenance/missing-sbom-and-provenance.
    canary_plant = CanaryPlant(
        files={
            ".github/workflows/release.yml": (
                "name: Release\n"
                "on:\n"
                "  push:\n"
                "    tags: ['v*']\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: docker/build-push-action@v5\n"
                "        with:\n"
                "          push: true\n"
                "          tags: myapp:latest\n"
            ),
        },
        expects=frozenset({"ci-image-build-no-sbom-provenance/missing-sbom-and-provenance"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "docker" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        workflows = root / ".github" / "workflows"
        if not workflows.is_dir():
            return []
        out: list[Finding] = []
        for f in sorted(p for p in workflows.iterdir() if p.is_file() and p.suffix in (".yml", ".yaml")):
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect="yaml"):
                continue
            if not _builds_and_pushes_image(text):
                continue
            if _SBOM_EVIDENCE.search(text) or _PROVENANCE_EVIDENCE.search(text):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=rel(root, f),
                    message=(
                        f"{rel(root, f)} builds and pushes a container image but has no SBOM "
                        "generation step (`anchore/sbom-action`, `syft`, `cyclonedx`, or the "
                        "built-in `sbom: true`) and no provenance/signing step "
                        "(`slsa-framework/slsa-github-generator`, "
                        "`actions/attest-build-provenance`, `cosign sign`, or the built-in "
                        "`provenance: true`) anywhere in the file. Nobody can answer 'what "
                        "exact dependencies shipped in this image' after an incident, and "
                        "nothing proves the running image was actually built by this "
                        "pipeline from this source."
                    ),
                    remediation=(
                        "Add at least one of: `sbom: true` / `provenance: true` on the "
                        "existing `docker/build-push-action` step (both are built-in flags, "
                        "no extra action needed), or a dedicated `anchore/sbom-action` step, "
                        "or `cosign sign` after the push. If this pipeline is intentionally "
                        "unsigned (an internal-only image, a throwaway dev build), add "
                        "`# security: allow-missing-sbom-provenance` to the file."
                    ),
                    rule="ci-image-build-no-sbom-provenance/missing-sbom-and-provenance",
                    standards=["OWASP:A08"],
                )
            )
        return out
