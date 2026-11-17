---
type: Guard
title: "docker-socket-access"
description: "Code references the Docker socket (container-escape vector)."
timestamp: "2026-07-12T19:08:55+08:00"
guard_id: "docker-socket-access"
checklist_section: ["6c"]
standards: ["CWE-269", "OWASP:A05"]
---

# Code references the Docker socket (container-escape vector)

## Threat

**CWE-269 (Improper Privilege Management), OWASP:A05.** `/var/run/docker.sock` is the Docker
daemon's control API, and the daemon runs as root. Access to it from inside a container is
equivalent to root on the host: code that can talk to the socket can spawn a new, arbitrarily
privileged container with the host filesystem bind-mounted in — a well-documented, reliable
container-escape technique, not a theoretical one.

```python
client = docker.from_env()
client.containers.run("alpine", "sh", privileged=True, volumes={"/": {"bind": "/host"}})
```

Sourced from SkillSpector's `PE4` category ("Docker Socket Access") — a scanner built for AI
agent skill files, where a skill requesting Docker socket access is an especially dangerous
combination (a prompt-injected or malicious skill effectively gets host root). Applied here to
application/deployment code generally, since the same signal is valid regardless of whether the
code originated from an agent skill file or ordinary application code.

## Detection design

1. **`applies()` gate:** universal (`return True`). The source/compose files this scans (and the
   Docker-socket signal) can appear in any project regardless of the detected stack; a `"python"`
   gate silently dropped the YAML/JS/shell socket references on a compose-only or Node-only repo
   (PR #393 review #1, same mis-gating class as the trio). `run()` skips test/fixture/vendor files
   via `is_nonproduct_path`.
2. **Files scanned:** `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.sh`, `.bash`, `.yml`, `.yaml` via
   `iter_files()` — YAML is included specifically for `docker-compose.yml`'s
   `- /var/run/docker.sock:/var/run/docker.sock` bind-mount idiom.
3. **Patterns (any one fires):**
   - `_DOCKER_SOCK_PATH`: a literal `/var/run/docker.sock` reference.
   - `_DOCKER_FROM_ENV`: `docker.from_env()` — the Python Docker SDK's default client.
   - `_DOCKER_CLIENT_CTOR`: `DockerClient(` — the Docker SDK's explicit client constructor.
4. **Skips:** lines starting with `#` or `//` (both Python/shell and YAML comments, and
   JS/TS line comments).
5. **Pragma:** `# security: allow-docker-socket` anywhere in the file skips it entirely.
6. **Severity / rule:** `docker-socket-access/socket-reference`, **HIGH**.

## When NOT to flag

A legitimate CI runner or a Docker-in-Docker build pipeline stage genuinely needs socket
access — this is the real, common exception, not a rare edge case. The guard fires
unconditionally on any match; the pragma is the intended mechanism for this case, isolated to
the specific file/job that needs it rather than a blanket exclusion.

## Tests

| Test | What it checks |
|---|---|
| `test_docker_socket_access_flags_socket_path` | A docker-compose bind-mount of the socket fires HIGH |
| `test_docker_socket_access_flags_docker_from_env` | `docker.from_env()` fires |
| `test_docker_socket_access_flags_docker_client_ctor` | `DockerClient(...)` fires |
| `test_docker_socket_access_silent_unrelated_code` | Unrelated client construction stays silent |
| `test_docker_socket_access_silent_comment` | A `#`-prefixed comment line stays silent |
| `test_docker_socket_access_pragma_silences` | File-level pragma suppresses all findings |
| `test_docker_socket_access_covers_compose_only_repo` | Regression (#393 #1): bind-mount fires on a compose-only repo (no `python` feature) |
| `test_docker_socket_access_skips_nonproduct_path` | Regression (#393 #2): a `docker.from_env()` in a `tests/` file is skipped |
| `test_docker_socket_access_applies_universally` | Guard applies on any stack (universal) |

## Known bypasses

- `docker.DockerClient(base_url=os.environ["DOCKER_HOST"])` where the URL is built dynamically
  and never literally contains `docker.sock` in the scanned file is not caught.
- Node's `dockerode` package's own constructor forms (`new Docker(...)`) are not matched — only
  the Python SDK's `DockerClient(`/`from_env()` and the literal socket path (which would still
  be present in a `dockerode` connection string, so a JS file connecting via the literal path
  string IS still caught by `_DOCKER_SOCK_PATH`).
- A socket proxy (e.g. `tecnativa/docker-socket-proxy`) that scopes down the API surface before
  exposing it is not distinguished from raw unrestricted socket access — this guard flags any
  reference to the pattern, not just genuinely dangerous ones, trading precision for recall on
  an inherently high-severity signal.

## What this guard does NOT prove

A file with no finding may still achieve the same container-escape outcome via an indirect
path — a helper module this guard didn't scan, a subprocess shelling out to the `docker` CLI
with the socket path built from concatenated variables, or a completely different
container-runtime socket (`containerd`, `podman`) this guard doesn't recognize.

# Citations

[1] agentsec checklist item `6c-docker-socket-access` (§6c)
[2] CWE-269
[3] OWASP:A05
