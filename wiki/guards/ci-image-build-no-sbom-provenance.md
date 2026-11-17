---
type: Guard
title: "ci-image-build-no-sbom-provenance"
description: "Container image build/push with no SBOM or provenance/signing step."
timestamp: "2026-09-19T00:00:00+00:00"
guard_id: "ci-image-build-no-sbom-provenance"
checklist_section: ["5"]
standards: ["OWASP:A08"]
---

# Container image build/push with no SBOM or provenance/signing step

**Guard ID:** `ci-image-build-no-sbom-provenance`
**File:** `agentsec/guards/ci_image_build_no_sbom_provenance.py`
**Checklist item:** `5-container-build-sbom-provenance` (covered)
**Standards:** OWASP:A08
**Severity:** MEDIUM
**Applies when:** `docker` in detected features

---

## The threat

Both Google's "Vibe Coding Agent Security and Evaluation" and Wiz's "From Prompts to Production"
reports call for SBOM generation, SLSA provenance, and digital-signature verification as standard
parts of a CI/CD deploy pipeline — this was the strongest unclaimed item from an earlier
report-mining pass and, until this guard, agentsec had zero coverage for it.

Without an SBOM, nobody can answer "which exact dependency versions shipped in this image" after
an incident — the question every real supply-chain investigation starts with. Without
provenance/signing, nothing proves the image running in production was actually built by this
pipeline from this source, rather than pushed directly to the registry by anyone holding a push
credential.

## Detection logic

1. **Scope gate:** `applies()` returns True when `docker` is in `profile.features`.
2. **Build+push detection:** a workflow file must show unconditional evidence of shipping an
   image — `docker/build-push-action` with a literal `push: true` in the same step's key window,
   or a raw `docker push` command in a `run:` step. `push: ${{ ... }}` (a conditional expression)
   is deliberately NOT treated as evidence — the safe direction for a check that produces a real
   supply-chain gap if wrong is to require unconditional proof.
3. **SBOM/provenance evidence, anywhere in the same file:** SBOM —
   `anchore/sbom-action`, `sbom: true` (the built-in `docker/build-push-action` flag), `syft`,
   `cyclonedx`. Provenance/signing — `slsa-framework/slsa-github-generator`,
   `actions/attest-build-provenance`, `provenance: true` (the built-in flag), `cosign sign`/
   `cosign attest`. Either class silences the guard — SBOM and provenance are complementary, not
   both required.
4. Fires MEDIUM when build+push is detected with neither class of evidence present.

**What this does NOT do:** verify the SBOM/provenance step actually succeeds, runs before the
push, or is configured correctly — a repo-wide presence/absence marker scan, the same class of
check several sibling guards already use for "is there ANY evidence of X anywhere in this file."

**Suppress:** `# security: allow-missing-sbom-provenance` anywhere in the workflow file.

---

## Examples

```yaml
# Fires MEDIUM
jobs:
  build:
    steps:
      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: myapp:latest
```

```yaml
# Silent — built-in sbom flag
jobs:
  build:
    steps:
      - uses: docker/build-push-action@v5
        with:
          push: true
          sbom: true
```

---

## FP-bait (must stay silent)

- `provenance: true` or a dedicated `anchore/sbom-action` step present.
- `cosign sign`/`cosign attest` present after a raw `docker push`.
- `push: ${{ github.event_name == 'release' }}` — a conditional, not unconditional evidence.
- `push: false` — builds the image but never ships it, nothing to attach provenance to yet.
- No `.github/workflows/` directory at all.
- The pragma comment present anywhere in the file.

---

## Canary plant

`.github/workflows/release.yml`: `docker/build-push-action` with `push: true` and nothing else in
the file mentioning sbom/syft/cyclonedx/slsa/cosign/provenance → fires
`ci-image-build-no-sbom-provenance/missing-sbom-and-provenance` (MEDIUM).

---

## Checklist coverage

| Item | Before | After |
|---|---|---|
| `5-container-build-sbom-provenance` | manual | **covered** |

---

# Citations

- Google, "Vibe Coding Agent Security and Evaluation" (May 2026) — supply-chain section
  (SBOM/SLSA/signing)
- Wiz, "From Prompts to Production: The Technical Guide to Secure Vibe Coding" (2026)
- The maintainers' vibe-coding-reports improvement backlog, item G4
