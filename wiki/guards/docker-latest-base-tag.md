---
type: Guard
title: "docker-latest-base-tag"
description: "Docker base image not pinned to a version tag."
timestamp: "2026-07-12T00:44:21+08:00"
guard_id: "docker-latest-base-tag"
checklist_section: ["5"]
standards: ["CIS:Docker", "OWASP:A06", "OWASP:A08", "SOC2:CC8.1"]
---

# Docker base image not pinned to a version tag

_Author — 2026-07-12_

---

## The threat

`FROM <image>` with no tag, or an explicit `:latest` tag, points at a mutable registry
reference — the exact content it resolves to can change between any two builds with no
diff visible in the Dockerfile. A rebuild today and a rebuild next month can silently pull
different bytes: usually a benign OS patch bump, but the same mechanism means a
compromised or tampered image published under the same tag (or the tag repointed after a
registry/maintainer change) enters the build with nothing in source control flagging that
anything changed. This is the base-image analog of an unpinned dependency in a lockfile —
both reproducibility and supply-chain integrity are weakened. OWASP:A06 (Vulnerable and
Outdated Components) / CWE-1104 (Use of Unmaintained Third Party Components — pinning
gap class).

Source: `pkg/policies/opa/rego/docker/docker_from/imageVersionnotusinglatest.rego` in
[tenable/terrascan](https://github.com/tenable/terrascan) — verified by direct fetch:

```
{{.prefix}}{{.name}}{{.suffix}}[dockerFrom.id]{
	dockerFrom := input.docker_FROM[_]
    config := dockerFrom.config
    contains(config, ":latest")
}
{{.prefix}}{{.name}}{{.suffix}}[dockerFrom.id]{
	dockerFrom := input.docker_FROM[_]
    config := dockerFrom.config
    not contains(config, ":")
}
```

Both branches — literal `:latest` OR no tag at all — are reproduced here.

## Why this guard fits the stack

Every Dockerfile in the target FastAPI + React + Postgres shape starts with a `FROM`
line, and `FROM python` / `FROM node` (no tag) or `FROM node:latest` are both extremely
common in quick-start / tutorial-derived Dockerfiles — exactly the kind of pattern that
gets copy-pasted into a real project and never revisited.

## Detection design

1. `applies()` — always true; Dockerfiles are stack-agnostic.
2. Scans every file from `iter_dockerfiles(root)`.
3. Every `FROM` instruction is matched by `_FROM_INSTRUCTION` (handles an optional
   `--platform=` flag and an optional `AS <stage>` alias). `_is_unpinned()`:
   - Excludes `FROM scratch` (no registry image to pin).
   - Excludes a reference to an earlier build-stage name (`_stage_names()` collects every
     `AS <name>` alias in the file first) — a later `FROM <stage-name>` isn't a registry
     pull at all.
   - Excludes a digest-pinned reference (`image@sha256:...`) — the strongest form,
     out of scope for this rule (a separate, narrower gap — see checklist item below).
   - Splits the image reference on the LAST `/` first, so a registry host with its own
     port (`registry:5000/app`) isn't mistaken for `image:tag` — only the final path
     segment is checked for a `:tag` suffix.
   - Fires when that final segment has no `:` at all, or the tag after it is (case-
     insensitively) `latest`.
4. Inline opt-out: `# security: allow-latest-tag`.
5. Severity: MEDIUM. Rule: `docker-latest-base-tag/unpinned-from`. Standards:
   `["OWASP:A06", "CWE-1104"]`.

## When NOT to flag

- A `*.example` / `*.user.example` Dockerfile is a user-customization TEMPLATE, not a built image —
  skipped (guard-local, not the shared list; round-2 §D.7). Matched by the shared
  `base.is_example_template_file`, case-INSENSITIVELY: the original `str.endswith(".example")` let
  `Dockerfile.EXAMPLE` fire while the dev-compose pattern beside it was already case-insensitive
  (#484 review).
- A version-tagged image (`python:3.12-slim`) — already a meaningful improvement over
  `:latest`; this guard doesn't require digest-pinning (a stronger, separate practice).
- `FROM scratch` — no image to pin.
- A `FROM <stage-name>` reference to an earlier build stage in a multi-stage Dockerfile.
- `FROM image@sha256:...` — already digest-pinned, the strongest form.
- The `# security: allow-latest-tag` pragma — for an intentional dev-only Dockerfile that
  tracks upstream `latest` on purpose.

## Tests

| Test | What it checks |
|---|---|
| `test_docker_latest_base_tag_no_tag_fires` | `FROM python` (no tag) → fires |
| `test_docker_latest_base_tag_explicit_latest_fires` | `FROM python:latest` → fires |
| `test_docker_latest_base_tag_pinned_version_silent` | `FROM python:3.12-slim` → silent |
| `test_docker_latest_base_tag_digest_pinned_silent` | `FROM python@sha256:...` → silent |
| `test_docker_latest_base_tag_scratch_silent` | `FROM scratch` → silent |
| `test_docker_latest_base_tag_multistage_reference_silent` | `FROM builder` (stage name) → silent (FP-bait) |
| `test_docker_latest_base_tag_registry_port_no_tag_fires` | `FROM registry:5000/app` (no tag; registry port not mistaken for a tag) → fires |
| `test_docker_latest_base_tag_registry_port_pinned_silent` | `FROM registry:5000/app:1.2.3` → silent (FP-bait — registry-port parsing precision) |
| `test_docker_latest_base_tag_pragma_silences` | Pragma present → silent |
| `test_docker_latest_base_tag_applies_always` | `applies()` is `True` for any profile |

## Known bypasses

- **A tag that isn't `latest` but still floats** (e.g. `python:3` or `node:20`, which are
  moving major/minor aliases updated by the maintainer over time) is not flagged — the
  guard only catches the two terrascan-verified cases (no tag / literal `latest`), not the
  broader "any non-exact-patch tag still moves" spectrum. This is a conscious scope
  boundary, not an oversight: flagging every non-digest tag would duplicate the separate,
  broader `5-base-image-digest-pinned` checklist gap this guard only partially closes.
- **`ARG`-parameterized `FROM` image names** (`FROM ${BASE_IMAGE}`) are not resolved —
  the guard sees the literal `${BASE_IMAGE}` token, which contains no `:`, so it currently
  fires as "no tag" even if the ARG's default value (or a `--build-arg` override) supplies
  a fully pinned reference. This is a conservative bias toward false-positive over false-
  negative for this specific shape; not adversarially bypassable in the other direction
  (an attacker can't use this to hide an actually-unpinned `FROM`).

## What this guard does NOT prove

- That the pinned tag/digest itself is free of known CVEs — pairs with Trivy
  (`6c-image-cve-scan`, already `covered`), which does the actual vulnerability scan.
  This guard only proves the reference is reproducible, not that what it resolves to is
  safe.
- That a digest-pinned image was itself built from a trustworthy source — supply-chain
  provenance beyond "this reference is immutable" is out of scope.

# Citations

[1] agentsec checklist item `5-base-image-digest-pinned` (§5)
[2] CIS:Docker
[3] OWASP:A06
[4] OWASP:A08
[5] SOC2:CC8.1
