---
type: Guard
title: "compose-no-new-privileges"
description: "Docker-compose service missing no-new-privileges:true in security_opt."
timestamp: "2026-09-05T00:00:00Z"
guard_id: "compose-no-new-privileges"
checklist_section: ["6c"]
standards: ["OWASP:A05", "CIS:Docker"]
---

# Docker-compose service missing no-new-privileges:true in security_opt

_Author — 2026-09-05_

---

## The threat

`no-new-privileges` (backed by the kernel's `PR_SET_NO_NEW_PRIVS` prctl) blocks a process from
gaining additional privileges via `execve()`. Concretely, it neutralizes setuid/setgid binaries
and file capabilities baked into an image — a stray `sudo`, `ping`, or a package's setuid helper
that would otherwise let code running inside the container as an unprivileged user re-elevate to
root on exec. It is Docker's own recommended additive hardening flag and costs nothing when the
image genuinely has no such binaries; when it does, it closes a real local-privilege-escalation
path for anyone who already has code execution inside the container (a dependency RCE, an unsafe
deserialization, a prompt-injected shell-out). Findings carry `OWASP:A05` (security
misconfiguration) and `CIS:Docker`.

## Why it's often introduced / Why this guard fits the stack

`no-new-privileges` is an opt-IN flag with no default — a `docker-compose.yml` that never
mentions `security_opt:` at all (the overwhelming majority of tutorials and starter templates)
simply never gets it, with no error or warning at any point. In the 9_Agent_SaaS shape, the
compose file is usually written once at project scaffolding time and never revisited for this
kind of additive hardening once the app "just works".

```yaml
services:
  app:
    image: myapp:1.0
    # no security_opt: at all -> a setuid binary in the image can still re-elevate on exec
```

## Detection design

1. **applies() gate** — `"docker" in profile.features`.
2. **Files scanned** — `iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml")`,
   skipping `is_dev_compose_file()` names.
3. **Parse** — `iter_compose_services()` splits the file into per-service blocks. Each service's
   `security_opt:` (block-list form or one-line `[...]` flow form) is scanned for a
   `no-new-privileges:true` (or `=true`) entry, case- and quote-insensitive. Comments are
   stripped before matching, so a mention inside a `#` comment does not count as present.
4. **Pragma opt-out** — `# security: allow-no-new-privileges` anywhere in the file.
5. **Severity / rule / standards** — `medium` (an additive protection missing, not an active
   privilege grant — lower confidence than `docker-privileged-flags`' flat findings), rule
   `compose-no-new-privileges/missing`, standards `["OWASP:A05", "CIS:Docker"]`.

## When NOT to flag

- A service whose `security_opt:` list already contains `no-new-privileges:true` — silent,
  regardless of whatever else is also in that list.
- An audited exception — suppress with the pragma.

**Not a duplicate of `docker-privileged-flags`.** That guard fires on a `security_opt` entry
naming an `*:unconfined` profile — actively DISABLING a protection (AppArmor/SELinux) that is
normally ON by default. This guard fires on the ABSENCE of a DIFFERENT flag that is never on by
default. A service can trip both, either, or neither independently; the two guards' fired lines
never overlap by construction (one only ever looks for `unconfined`, the other only ever looks
for `no-new-privileges:true`).

## Tests

| Test | What it checks |
|---|---|
| `test_no_security_opt_at_all_fires` | the common case (no `security_opt:` key) fires; severity/check_id correct |
| `test_security_opt_without_the_flag_fires` | a `security_opt:` list naming something else still fires |
| `test_commented_out_flag_still_fires` | a comment mentioning the flag does not count as set |
| `test_multiple_services_each_evaluated` | each service in a multi-service file is evaluated independently |
| `test_no_new_privileges_present_block_form_silent` | block-list form with the flag present stays silent |
| `test_no_new_privileges_present_flow_form_silent` | one-line `[...]` flow form with the flag present stays silent |
| `test_no_new_privileges_quoted_silent` | a quoted entry is still recognized |
| `test_pragma_silences` | the pragma suppresses the finding |
| `test_dev_compose_out_of_scope` | a `*.dev.yml` compose file is skipped |
| `test_applies_gate` / `test_applies_with_docker` | gated on the `docker` feature |
| `test_no_compose_silent` | no compose file -> no findings |

## Known bypasses

- **Variable indirection** — a `security_opt:` value built from a `${VAR}` interpolation is not
  resolved; the guard only sees the literal text.
- **CLI-only invocation** (`docker run --security-opt=no-new-privileges` outside any compose
  file) is out of this guard's scope entirely — it only reads compose YAML.
- A service that sets the flag via a `deploy:`/Swarm-only construct this guard does not
  specifically parse would be a false negative, though standard compose `security_opt:` is by
  far the common form.

## What this guard does NOT prove

Silence means a `no-new-privileges:true` entry was found in the committed compose file for that
service. It does NOT prove the running container actually launched with that compose file (a
manually-run `docker run` bypasses it entirely), that no OTHER privilege-escalation path exists
(a mounted Docker socket, a `SYS_ADMIN` capability grant — both covered by other guards), or that
the image contains no genuinely-needed setuid binary that this flag would break.

# Citations

[1] OWASP DockSec `compose_scanner.py::_check_no_new_privileges` (source-verified; see the
    project's private `docksec.md` research digest, candidate #1).
[2] OWASP:A05
[3] CIS:Docker
