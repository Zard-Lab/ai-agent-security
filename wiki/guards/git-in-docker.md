---
type: Guard
title: "git-in-docker"
description: ".git directory not excluded from Docker image."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "git-in-docker"
checklist_section: ["6a"]
standards: ["ASVS:13.4.1", "OWASP:A05"]
---

# .git directory not excluded from Docker image

## Threat

When a Docker image is built without a `.dockerignore` that excludes `.git`, the entire
git history is copied into the image layer. The `.git` directory contains full commit
history including files that were deleted, author names and email addresses from every
commit, commit messages that may reference internal systems or sensitive decisions, and
crucially — secrets that were accidentally committed and later removed still exist in
the history.

While the `.git` directory is invisible in a normally running container, an attacker who
achieves arbitrary file read or code execution inside the container gains access to all
of this. Additionally, if the image itself is leaked (e.g., via a misconfigured registry),
the history is trivially accessible with `git log`.

References: OWASP A05 (Security Misconfiguration), CWE-312 (Cleartext Storage of Sensitive
Information), OWASP Docker Security Cheat Sheet.

## Detection design

Two patterns are detected, both emitting under the same rule ID:

**Pattern 1 — Missing `.git` in `.dockerignore`**

```
Dockerfile exists at root
AND (
    .dockerignore does not exist
    OR .dockerignore does not contain ".git" on its own line
)
AND no pragma in the relevant file
```

One finding per project (not per Dockerfile), because `.dockerignore` is a project-level
control that applies to all Dockerfiles in the build context.

**Pattern 2 — Explicit `COPY .git` in Dockerfile**

Regex:
```
^\s*COPY\s+\.git\b
```

Flags: `MULTILINE | IGNORECASE`. Fires once per matching line, per Dockerfile. This
catches developers who intentionally copy `.git` to embed a version string — a pattern
that copies far more than intended.

The `.dockerignore` check uses line-by-line string equality after stripping whitespace
(`stripped == ".git"`), not a regex, to avoid matching comment lines or longer paths
like `.github`.

## Severity rationale

**MEDIUM.** The exposure is genuine — git history can contain secrets, PII (email
addresses), and internal architecture information — but exploitability requires a prior
access condition: the attacker must achieve code execution inside the container, or the
container image must be leaked from a registry. A direct credential leak in live config
would be HIGH; this is a defence-in-depth miss that raises blast radius when another
control fails.

## Known bypasses / false negatives

| Bypass | Notes |
|---|---|
| Multi-stage builds with `.git` only in builder stage | If `.git` is not in the final `FROM` stage's layer, it does not ship. Guard does not currently track stage boundaries — may fire on legitimate multi-stage patterns. |
| `.dockerignore` with a glob like `**/.git` | Guard checks for the exact string `.git` on a line; `**/.git` also works but is not recognized as equivalent. A future improvement could add glob-pattern awareness. |
| Dockerfile not at repo root | `rglob("Dockerfile")` catches nested Dockerfiles, but a project with multiple build contexts (monorepo with per-service directories) may have per-directory `.dockerignore` files; the guard only checks the root `.dockerignore`. |
| `.git` negated in `.dockerignore` with `!.git` after an earlier `.*` | A pattern `.*` followed by `!.git` technically includes `.git` again, but the guard would see `.*` is not `.git` and would fire. Complex negation patterns are not parsed. |

## False positive scenarios

| Scenario | Why it fires | Mitigation |
|---|---|---|
| Build-tools image that intentionally needs full history | Guard fires because `.git` is not in `.dockerignore` | Add `# security: allow-git-in-docker` to the Dockerfile |
| CI image that runs `git log` for changelog generation | Same as above | Same pragma |
| Developer environment image where history is desired | Same as above | Same pragma |
| Multi-stage build where `.git` is only in the builder stage | Guard fires on the `COPY .git` line without stage awareness | Add pragma to that Dockerfile |

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| 6a-git-metadata-not-deployed | `uncovered` | `covered` | Guard detects missing `.git` exclusion in `.dockerignore` and explicit `COPY .git` lines in Dockerfiles |

## Tests

| Test | Validates |
|---|---|
| `test_git_in_docker_no_dockerignore_fires` | Dockerfile present, no `.dockerignore` → 1 finding |
| `test_git_in_docker_dockerignore_missing_git_fires` | Dockerfile present, `.dockerignore` exists but lacks `.git` entry → 1 finding |
| `test_git_in_docker_dockerignore_has_git_silent` | Dockerfile present, `.dockerignore` with `.git` entry → no findings |
| `test_git_in_docker_no_dockerfile_silent` | No Dockerfile present → no findings |
| `test_git_in_docker_copy_git_fires` | `COPY .git` line in Dockerfile → 1 finding |
| `test_git_in_docker_pragma_silences` | `# security: allow-git-in-docker` in Dockerfile → no findings |
| `test_git_in_docker_applies_always` | `applies()` returns True for any profile |

# Citations

[1] agentsec checklist item `6a-git-metadata-not-deployed` (§6a)
[2] ASVS:13.4.1
[3] OWASP:A05
