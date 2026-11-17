---
type: Guard
title: "docker-run-sudo"
description: "Dockerfile RUN instruction invokes sudo."
timestamp: "2026-07-12T00:44:21+08:00"
guard_id: "docker-run-sudo"
checklist_section: ["6c"]
standards: ["CWE-250", "OWASP:A05"]
---

# Dockerfile RUN instruction invokes sudo

_Author — 2026-07-12_

---

## The threat

A `RUN` instruction already executes as the effective build-time user (root, unless an
earlier `USER` switched it), so invoking `sudo` inside a `RUN` line is never functionally
required to install packages or configure the image during the build. Its actual,
persistent effect is installing (and, unless explicitly removed in the same layer, leaving
behind) a working `sudo` binary and configuration in the final image — a privilege-
escalation primitive that becomes live the moment an attacker achieves code execution as a
non-root user inside the *running* container (an app RCE, a compromised dependency, a
prompt-injected shell-out from an LLM agent tool call). Combined with even a mildly
permissive `sudoers` entry (a common footgun: adding the app user to `sudoers` with
`NOPASSWD` "for convenience"), this converts "attacker got a shell as the app user" directly
into "attacker is root," defeating whatever non-root `USER` hardening
(`docker-nonroot-user`, this same batch) the image otherwise has. OWASP:A05 (Security
Misconfiguration) / CWE-250 (Execution with Unnecessary Privileges).

Source: `pkg/policies/opa/rego/docker/docker_run/runWithSudo.rego` in
[tenable/terrascan](https://github.com/tenable/terrascan) — verified by direct fetch:

```
{{.prefix}}{{.name}}{{.suffix}}[run.id]{
    run := input.docker_RUN[_]
    checkSudo(run.config)
}
checkSudo(config) { startswith(config, "sudo") }
checkSudo(config) { contains(config, "&& sudo") }
```

## Why this guard fits the stack

`sudo` inside a `RUN` line shows up most often when a Dockerfile is adapted from a
developer's local shell workflow (where `sudo apt-get install` is muscle memory) without
noticing the build already runs as root — a plausible mistake in any FastAPI/React
Dockerfile that installs OS packages.

## Detection design

1. `applies()` — always true; Dockerfiles are stack-agnostic.
2. Scans every file from `iter_dockerfiles(root)`.
3. Every `RUN` instruction is matched by `_RUN_INSTRUCTION`. The JSON-array exec form
   (`RUN ["sudo", "apt-get", ...]`) is normalized to a plain space-joined string first
   (`_strip_exec_array`) so the same pattern covers both `RUN` forms.
4. `_SUDO_INVOCATION` matches `sudo` as its own shell word: at the very start of the
   command, or immediately after a shell connector (`&&`, `;`, `|`, `||`) — deliberately
   broader than the terrascan source, which only covers `startswith` and `&&` (missing
   `;`/`|`/`||`); this guard generalizes across all four connectors a real Dockerfile RUN
   line can use.
5. Inline opt-out: `# security: allow-sudo-in-docker`.
6. Severity: MEDIUM. Rule: `docker-run-sudo/sudo-invocation`. Standards:
   `["OWASP:A05", "CWE-250"]`.

## When NOT to flag

- A `RUN` line with no `sudo` invocation at all.
- A package or path name that merely CONTAINS the substring "sudo" (e.g. `pseudo-package`)
  must not fire — `_SUDO_INVOCATION` requires `sudo` to be its own shell word (anchored at
  start-of-command or right after a connector), not an arbitrary substring match.
- `sudo` mentioned only in a comment (`# don't use sudo here`) — the guard matches only
  inside `RUN` instruction bodies, not comment text.
- The `# security: allow-sudo-in-docker` pragma — for a documented, reviewed pattern (e.g.
  a build stage that switches users mid-build with a matching teardown), or a local
  dev-only Dockerfile.

## Tests

| Test | What it checks |
|---|---|
| `test_docker_run_sudo_leading_fires` | `RUN sudo apt-get update` → fires |
| `test_docker_run_sudo_after_and_fires` | `RUN x && sudo y` → fires |
| `test_docker_run_sudo_after_semicolon_fires` | `RUN x; sudo y` → fires (generalization beyond the terrascan source, which only covers `&&`) |
| `test_docker_run_sudo_exec_array_fires` | JSON-array `RUN ["sudo", "apt-get", "update"]` → fires |
| `test_docker_run_sudo_no_sudo_silent` | Ordinary `RUN apt-get update && apt-get install` → silent |
| `test_docker_run_sudo_word_boundary_silent` | `RUN apt-get install -y pseudo-package` → silent (FP-bait) |
| `test_docker_run_sudo_pragma_silences` | Pragma present → silent |
| `test_docker_run_sudo_applies_always` | `applies()` is `True` for any profile |

## Known bypasses

- **`sudo` invoked via an intermediate script** (`RUN ./setup.sh`, where `setup.sh` itself
  calls `sudo` inside the image) is invisible to a Dockerfile-only static scan — the guard
  cannot see into shell scripts copied into the image.
- **Backslash line-continuations are handled** (PR #397 review #3): a `RUN` body split across
  physical lines (`RUN apt-get update && \` / `    sudo ...`) is joined into one logical line by
  the shared `base.py::join_dockerfile_continuations` helper before the instruction/connector
  regexes run, so `sudo` on a continuation line fires correctly. The helper preserves line
  numbers (consumed continuation lines become blanks), so the finding still points at the `RUN`'s
  starting line. All five terrascan Dockerfile guards route their reads through it.
- **`sudo -u otheruser` used for an intentional, narrow privilege drop** (rather than
  escalation) inside a `RUN` line still fires — the guard cannot distinguish "used to
  escalate" from "used to de-escalate for one command," since both look identical
  syntactically. A conservative choice: `sudo` itself, present in the final image, is the
  risk this guard flags regardless of the invocation's intent.

## What this guard does NOT prove

- That `sudo` isn't installed WITHOUT being invoked via `RUN` at all (e.g. pulled in
  transitively as a dependency of another package, with no explicit `sudo` command in the
  Dockerfile) — this guard only catches an explicit `sudo` invocation in a `RUN` line, not
  every path `sudo` could end up on disk in the final image.
- That the base image itself doesn't already ship `sudo` pre-installed — a Dockerfile
  that never runs `sudo` explicitly can still produce an image with a working `sudo`
  binary if the base image included it; this guard cannot see the base image's contents.

# Citations

[1] agentsec checklist item `6c-docker-run-sudo` (§6c)
[2] CWE-250
[3] OWASP:A05
