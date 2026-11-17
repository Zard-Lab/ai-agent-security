---
type: Guard
title: "go-build-supply-chain-footgun"
description: "Go build/install supply-chain footgun in Dockerfile or CI."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "go-build-supply-chain-footgun"
checklist_section: ["5"]
standards: ["CWE-829", "OWASP:A08"]
---

# Go build/install supply-chain footgun in Dockerfile or CI

_Author — 2026-08-14_

---

## The threat

An attacker who controls (or compromises) a mutable reference an image build resolves at
build time can get arbitrary code compiled into the image with the privileges of whatever
runs the build (often root, inside a Docker build). Two concrete shapes:

1. **`go install <module>@latest`/`@master`/`@main`** — Go's own module system resolves
   this at build time to whatever commit that tag currently points at. No lockfile, no
   pin, no diff-before-build. Identical supply-chain shape to `curl | bash` piping an
   unpinned URL (this project's existing `curl-pipe-to-shell` guard) or an unpinned
   GitHub Action (`actions-sha-pin`) — the same class of bug, a different toolchain.
2. **`GOSUMDB=off`** (or the legacy `GONOSUMCHECK=1`) — disables the Go module checksum
   database verification wholesale. That verification is the mechanism that would
   otherwise catch a compromised or tampered module before it's compiled in; turning it
   off means a poisoned module (a typosquat, a compromised maintainer account, a
   man-in-the-middle on an unauthenticated proxy) is trusted with no cross-check at all.

Standards: OWASP:A08 (Software and Data Integrity Failures), CWE-829 (unpinned ref),
CWE-345 (checksum verification disabled).

## Why this guard fits the stack

This is a follow-up to `foreign_artifacts` (PR #601): that work disclosed that
a source-only `.go` census says "no Go here" for a repo running Go entirely as a prebuilt
binary or base image. This guard is the next layer down — for repos that DO compile Go
somewhere in their own build pipeline (a multi-stage Dockerfile's builder stage, a CI
step), it flags two build-time footguns that live in the Dockerfile/CI text itself, not
in any `.go` source file. A repo agentsec's own Go-source detection reports as having
zero Go can still have a Dockerfile `RUN go install some-tool@latest` in it (a CI-only
tool build, a vendored generator) — exactly the "artifact-layer, not source-layer" shape
`foreign_artifacts` exists to name.

```dockerfile
FROM golang:1.22 AS builder
RUN go install golang.org/x/tools/gopls@latest    # mutable ref, resolved at build time
ENV GOSUMDB=off                                     # checksum verification off entirely
RUN go build -o /out/app ./cmd/app
```

## Detection design

1. **`applies()`** — unconditionally `True`. A Dockerfile compiling Go, or a CI step
   running `go install`, can exist regardless of what agentsec's own Go-source detection
   reports (see "Why this guard fits the stack" above) — mirrors `curl_pipe_to_shell.py`'s
   own rationale for the identical unconditional gate.
2. **Files scanned** — two scopes:
   - Dockerfiles, via `iter_dockerfiles(root)`, gated on `"docker" in profile.features`
     (mirrors `curl_pipe_to_shell.py`'s Dockerfile scope exactly). Backslash
     line-continuations joined via `join_dockerfile_continuations()` before matching, so
     a `RUN go install \` / `    some/tool@latest` pair (realistic multi-line form) still
     fires.
   - Top-level GitHub Actions workflow files (`.github/workflows/*.yml`/`.yaml`), NOT
     recursive — GitHub never executes a workflow file in a subdirectory, mirroring
     `actions_sha_pin.py`'s scan scope exactly.
3. **Patterns**:
   - `go-install-unpinned`: `\bgo\s+install\s+<module>@(latest|master|main)\b`,
     case-insensitive. A real version tag (`@v1.2.3`, including prerelease suffixes) or a
     commit hash is NOT matched by this alternation and stays silent.
   - `checksum-verification-disabled`: `GOSUMDB=off` (loosely matched — Dockerfile
     `ENV`/`ARG`, an inline `RUN GOSUMDB=off go ...`, or a CI `env:` mapping value all
     share the same assignment shape) OR `GONOSUMCHECK=1`.
4. **Pragma** — per-line, per-rule: `# security: allow-go-install-unpinned` and
   `# security: allow-go-checksum-disabled`, counted only as a real `#` comment (the `hash` comment view, so the phrase inside a quoted string does not count, #1040). A workflow uses the `hash` view
   too, so a shell comment inside a `run: |` script counts.
5. **Severity/rule/standards** — both rules HIGH. `go-build-supply-chain-footgun/go-install-unpinned`
   (`OWASP:A08`, `CWE-829`). `go-build-supply-chain-footgun/checksum-verification-disabled`
   (`OWASP:A08`, `CWE-345`).

## When NOT to flag

- `go install some/tool@v1.2.3` (or a full/short commit hash) — a real pin, the safe
  pattern this guard exists to require.
- `GOSUMDB=sum.golang.org` (or any real non-`off` value, e.g. a private sumdb proxy) —
  verification is still active, just pointed somewhere specific.
- A module path that happens to CONTAIN the word "latest" as a path segment
  (`example.com/latest-tool@v1.0.0`) — the regex requires `@` immediately followed by the
  literal ref `latest`/`master`/`main`, not a substring match anywhere in the line.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_go_install_latest_in_dockerfile` | Core positive: `@latest` in a Dockerfile `RUN` fires HIGH with the right standards |
| `test_fires_on_go_install_master_and_main` | Both `@master` and `@main` are recognized, each its own finding |
| `test_silent_on_go_install_pinned_version` | FP-bait: a real semver pin stays silent |
| `test_silent_on_go_install_pinned_commit_hash` | FP-bait: a commit-hash pin stays silent |
| `test_go_install_pragma_suppresses` | Inline opt-out honored |
| `test_go_install_line_continuation_joined` | Dockerfile backslash-continuation joined before matching |
| `test_fires_on_go_install_latest_in_github_actions` | Same rule fires in a CI `run:` step |
| `test_silent_on_go_install_pinned_in_github_actions` | FP-bait, CI side |
| `test_github_actions_subdirectory_workflow_not_scanned` | Non-executable subdirectory workflows are out of scope |
| `test_fires_on_gosumdb_off_in_dockerfile_env` | Core positive for the checksum rule, Dockerfile `ENV` |
| `test_fires_on_gosumdb_off_inline_run` | Inline `RUN GOSUMDB=off go ...` shape also fires |
| `test_fires_on_gonosumcheck_in_github_actions_env` | Legacy `GONOSUMCHECK=1`, CI `env:` block |
| `test_silent_on_gosumdb_set_to_real_value` | FP-bait: a real (non-off) GOSUMDB value stays silent |
| `test_checksum_pragma_suppresses` | Inline opt-out honored |
| `test_no_dockerfile_no_docker_feature_silent` | No Dockerfile, no docker feature → nothing to scan |
| `test_dockerfile_present_but_docker_feature_absent_not_scanned` | Dockerfile-scope gate is real, not just cosmetic |
| `test_nonproduct_dockerfile_skipped` | `is_nonproduct_path` honored |
| `test_go_install_argument_module_containing_at_symbol_is_not_confused` | Adversarial: "latest" as a path segment, not a ref, doesn't false-positive |
| `test_go_install_ordinary_semver_prerelease_not_flagged` | FP-bait: a prerelease semver tag is still a real pin |
| `test_applies_unconditionally` | `applies()` contract |

## Known bypasses

- A `go install` invoked through a shell wrapper the regex doesn't anchor past (e.g. a
  variable holding the module path, `MOD=example.com/tool@latest; go install "$MOD"`) is
  not detected — the pattern requires the literal `@latest`/`@master`/`@main` token on the
  same line as `go install`.
- `GOSUMDB` set via a `.netrc`-style external config file, a `go env -w` call baked into a
  base image layer this guard never scans, or an org-wide `GOFLAGS`/`GOENV` file outside
  the Dockerfile/CI text, is invisible to this guard — it only reads what's written in the
  Dockerfile/workflow file itself.
- A multi-stage build's builder stage `go install`s a tool that's then COPIED into the
  final stage without the pin ever changing between builds — this guard flags the
  unpinned ref regardless of which stage it's in, which is correct (the risk is at build
  time, not in the final image), but doesn't distinguish "final image binary" risk from
  "throwaway builder tool" risk; both are flagged identically.

## What this guard does NOT prove

- That the resolved module, once pinned, is itself safe — pinning stops the ref from
  drifting later, it says nothing about whether the pinned commit/version was already
  malicious (that's a different question, OSV/advisory-database territory — the foreign-artifact work's
  mechanism C, unbuilt).
- That the base image's OWN Go toolchain or already-compiled binaries are free of the
  same footguns — this guard reads Dockerfile/CI text only, never inspects a built binary
  (mechanism A, `go version -m <binary>` inspection, unbuilt — and likely needs a
  different architecture, since it requires an actual built artifact this static-only
  guard never produces).
- Full coverage of every Go supply-chain footgun — `-trimpath` omission and "unrebuilt
  `*-builder` base image" were considered and deliberately excluded (see module docstring)
  as, respectively, a real-FP-risk hygiene item rather than an integrity one, and not
  statically verifiable from Dockerfile content alone.

# Citations

[1] agentsec checklist item `5-go-build-supply-chain-footgun` (§5)
[2] CWE-829
[3] OWASP:A08
