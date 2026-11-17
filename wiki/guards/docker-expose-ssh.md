---
type: Guard
title: "docker-expose-ssh"
description: "Dockerfile EXPOSEs the SSH port."
timestamp: "2026-07-12T00:44:21+08:00"
guard_id: "docker-expose-ssh"
checklist_section: ["6c"]
standards: ["CWE-1327", "OWASP:A05"]
---

# Dockerfile EXPOSEs the SSH port

_Author — 2026-07-12_

---

## The threat

A container that runs and `EXPOSE`s its own SSH daemon reintroduces a class of attack
surface containers are specifically designed to make unnecessary — a persistent,
independently-patched network service with its own authentication/credential surface,
running inside what is otherwise meant to be a minimal, single-process image. Standard
container operational access (`docker exec`, an orchestrator's `kubectl exec` equivalent)
already covers the legitimate "get an interactive shell in this container" need without a
listening service at all; an `EXPOSE 22` instead gives any network-reachable attacker a
second login surface with its own brute-force/credential-stuffing/CVE exposure, entirely
independent of the application's own auth. OWASP:A05 (Security Misconfiguration) /
CWE-1327 (Binding to an Unrestricted IP Address — the general "unnecessary listening
service" class).

Source: `pkg/policies/opa/rego/docker/docker_expose/exposeport.rego` in
[tenable/terrascan](https://github.com/tenable/terrascan) — verified by direct fetch:

```
checkPort(config) { contains(config, "22") }
checkPortList(config) { contains(config[_], "22") }
```

**Important divergence from the source rule, found during adversarial self-testing:**
terrascan's own check is a naive SUBSTRING match on `"22"` — it also fires on `EXPOSE 2200`,
`EXPOSE 8220`, or any port containing the digits "22" anywhere, none of which is SSH. This
guard reproduces the underlying SECURITY CONCEPT (containers shouldn't expose SSH) but
replaces the substring match with an exact-port parse (`_PORT_TOKEN` + equality against
`"22"`), confirmed by test to stay silent on `2200`/`8220` while still firing on `22`,
`22/tcp`, and `22` anywhere in a multi-port `EXPOSE` line.

## Why this guard fits the stack

Lower priority than the other guards in this batch: a typical FastAPI/React application
Dockerfile has no legitimate reason to touch SSH at all, so this check is expected to fire
rarely. It's included because it's cheap, high-precision (once the substring-match flaw is
fixed), and catches a real, if uncommon, anti-pattern (a bastion/jump-box pattern
accidentally baked into an application image, or an SSH-based remote-debug backdoor left
in from development).

## Detection design

1. `applies()` — always true; Dockerfiles are stack-agnostic.
2. Scans every file from `iter_dockerfiles(root)`.
3. Every `EXPOSE` instruction is matched by `_EXPOSE_INSTRUCTION`. `_exposes_ssh()` splits
   the instruction's argument on whitespace (an `EXPOSE` line can list multiple ports) and
   matches each token against `_PORT_TOKEN` (`^(\d+)(?:/(?:tcp|udp))?$`) — an exact port
   number, with an optional protocol suffix — checking for an EXACT match against `"22"`.
4. Inline opt-out: `# security: allow-ssh-expose`.
5. Severity: MEDIUM. Rule: `docker-expose-ssh/ssh-port-exposed`. Standards:
   `["OWASP:A05", "CWE-1327"]`.

## When NOT to flag

- Any port that merely contains the digits "22" as a substring but isn't the literal port
  22 — `2200`, `8220`, `22200` — must stay silent. This is the precision fix over the
  terrascan source rule's own known false positive, confirmed by two dedicated tests.
- `EXPOSE 8080` or any other ordinary application port — silent.
- The `# security: allow-ssh-expose` pragma — for a bastion/jump-host image where SSH
  access genuinely is the intended function.

## Tests

| Test | What it checks |
|---|---|
| `test_docker_expose_ssh_bare_port_fires` | `EXPOSE 22` → fires |
| `test_docker_expose_ssh_protocol_suffix_fires` | `EXPOSE 22/tcp` → fires |
| `test_docker_expose_ssh_multi_port_fires` | `EXPOSE 8080 443 22` (22 present among several) → fires |
| `test_docker_expose_ssh_substring_2200_silent` | `EXPOSE 2200` → silent (the terrascan source rule's own FP, fixed here) |
| `test_docker_expose_ssh_substring_8220_silent` | `EXPOSE 8220` → silent (same FP class) |
| `test_docker_expose_ssh_normal_port_silent` | `EXPOSE 8080` → silent |
| `test_docker_expose_ssh_pragma_silences` | Pragma present → silent |
| `test_docker_expose_ssh_applies_always` | `applies()` is `True` for any profile |

## Known bypasses

- **A port declared via a build `ARG`** (`ARG SSH_PORT=22` then `EXPOSE $SSH_PORT`) is not
  resolved — the guard sees the literal token `$SSH_PORT`, which doesn't match
  `_PORT_TOKEN`, so it stays silent. Same class of limitation as the other Dockerfile
  guards in this batch.
- **SSH running on a non-standard port with no `EXPOSE` line at all** (the container still
  runs sshd, but relies on `docker run -p <host>:22` at deploy time rather than declaring
  `EXPOSE`) is entirely invisible to a static Dockerfile scan — this guard only catches
  the declarative `EXPOSE` instruction, not runtime port publishing.
- **An `EXPOSE` for a completely different service that happens to run on port 22 by
  misconfiguration** would still fire — the guard has no way to confirm what's actually
  listening, only that port 22 (SSH's IANA-assigned port) is declared exposed.

## What this guard does NOT prove

- That an application NOT exposing port 22 doesn't run an SSH daemon anyway (bound only to
  a Docker network without an `EXPOSE` declaration, or started via a supervisor process
  the Dockerfile doesn't reference) — this is a Dockerfile-declaration check, not a
  runtime port scan.
- That any OTHER port is safe to expose — this guard is narrowly scoped to SSH (port 22)
  and makes no claim about the broader `EXPOSE` surface of the image.

# Citations

[1] agentsec checklist item `6c-docker-expose-ssh` (§6c)
[2] CWE-1327
[3] OWASP:A05
