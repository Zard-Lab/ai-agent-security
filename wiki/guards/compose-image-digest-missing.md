---
type: Guard
title: "compose-image-digest-missing"
description: "Docker-compose service image pinned to a tag but not a digest."
timestamp: "2026-08-16T10:56:38+08:00"
guard_id: "compose-image-digest-missing"
checklist_section: ["5"]
standards: ["CIS:Docker", "OWASP:A06", "OWASP:A08", "SOC2:CC8.1"]
---

# Docker-compose service image pinned to a tag but not a digest

_Author — Marconi, 2026-08-16_

---

## The threat

A version tag can be overwritten on the registry at any time — a pull today and a pull
next week are not guaranteed to return the same bytes. `docker-latest-base-tag` already
flags the weakest end of this spectrum (no tag, or `:latest`) in a Dockerfile's `FROM`;
this guard covers the adjacent gap that guard's own docstring names as explicitly out of
its scope — a compose service pinned to a real version tag (`myapp:1.4.2`) still isn't
immutable without a `@sha256:` digest. CWE-1104 (Use of Unmaintained Third Party
Components), OWASP:A08.

## Why this guard fits the stack

A compose file's `image:` line is the deploy-time equivalent of a Dockerfile `FROM`, and
carries the identical tag-vs-digest supply-chain question, but agentsec had no coverage
for it at all — only the Dockerfile side:

```yaml
services:
  app:
    image: myapp:1.4.2   # a real tag, but not digest-pinned
```

Sourced from compose-lint's `ImageNoDigestRule` (`CL-0019`). **Extends checklist item
`5-base-image-digest-pinned`** (already `partial` via `hadolint`/`docker-latest-base-tag`)
rather than opening a new item — verified against the checklist's own `check_ids` list and
`docker_latest_base_tag.py`'s docstring before classifying: same coverage gap, a different
file type and a narrower tag-vs-digest slice of it. This is a **guard-extension**
candidate, not a new-guard one, even though it lives in its own new module (the scan
target — compose YAML — is different from what `docker_latest_base_tag.py` scans).

## Detection design

1. `applies()` gate — `"docker" in profile.features`.
2. Scans every `docker-compose*.yml`/`.yaml` file via `iter_files_named`, skipping
   `is_dev_compose_file` files.
3. Uses `iter_compose_services()`, then a single-line `image:` match per service.
4. If the ref already contains `@sha256:`, silent. Otherwise `_split_image_ref()`
   extracts the tag (the part after the LAST colon past the last slash, so a registry host
   with its own port — `registry:5000/app` — isn't mistaken for a tag). No tag at all, or
   a mutable-by-convention tag (`latest`/`edge`/`stable`/`main`/`master`/`nightly`), is
   silent — that's `docker-latest-base-tag`'s territory (avoids double-reporting the same
   line under two different guards). Any other explicit tag fires.
5. Inline opt-out: `# security: allow-compose-image-digest` anywhere in the file.
6. Severity: `medium`. Rule id: `compose-image-digest-missing/tag-not-digest`.
   Standards: `["OWASP:A08", "CWE-1104", "CIS:Docker"]`.

## When NOT to flag

- Already digest-pinned (`@sha256:...` present, regardless of what else is set).
- No tag at all, or an explicitly mutable tag (`:latest`, etc.) — `docker-latest-base-
  tag`'s territory.
- A registry host with its own port (`registry:5000/app`) — not mistaken for a tag.
- An audited case, suppressed with `# security: allow-compose-image-digest`.

## Tests

| Test | What it checks |
|---|---|
| `test_versioned_tag_without_digest_fires` | Positive: `myapp:1.4.2` (no digest) fires (**verified_by**). |
| `test_digest_pinned_silent` | FP-bait: `myapp:1.4.2@sha256:...` → silent. |
| `test_latest_tag_out_of_scope` | FP-bait: `:latest` → silent (a different guard's territory). |
| `test_no_tag_out_of_scope` | FP-bait: no tag at all → silent (same reason). |
| `test_registry_with_port_not_mistaken_for_tag` | FP-bait: `registry:5000/myapp` → silent. |
| `test_pragma_silences` | Suppress pragma → silent. |
| `test_applies_gate` / `test_applies_with_docker` | `applies()` gate. |

## Known bypasses

- **`build:` context images** (a compose service built from a local Dockerfile rather than
  pulled by `image:`) are out of scope — `docker-latest-base-tag` covers that Dockerfile's
  own `FROM` line already.
- **Variable indirection**: `image: ${APP_IMAGE}` — an unresolved reference has no literal
  tag to inspect and is silently skipped.

## What this guard does NOT prove

A silent guard does not confirm the pinned digest is actually current or trustworthy
(supply-chain compromise of the digest itself is out of scope), or that the applied
deployment matches the source. This is a presence-based, source-only check.

# Citations

[1] agentsec checklist item `5-base-image-digest-pinned` (§5)
[2] CIS:Docker
[3] OWASP:A06
[4] OWASP:A08
[5] SOC2:CC8.1
