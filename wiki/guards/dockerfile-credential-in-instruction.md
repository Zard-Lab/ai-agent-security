---
type: Guard
title: "dockerfile-credential-in-instruction"
description: "Dockerfile instruction embeds a plaintext credential."
timestamp: "2026-11-04T00:00:00Z"
guard_id: "dockerfile-credential-in-instruction"
checklist_section: ["1"]
standards: ["OWASP:A02", "CWE-798"]
---

# Dockerfile instruction embeds a plaintext credential

_Author — 2026-11-04_

---

## The threat

**CWE-798 (Use of Hard-coded Credentials), OWASP:A02 (Cryptographic Failures).** A credential
passed as a CLI flag or embedded in a probe command is captured in the image's build history
(`docker history`), build logs, and — for `HEALTHCHECK` — in `docker inspect` output for the
life of the running container. **Who reaches it:** anyone with pull access to the image, read
access to the build log, or `docker inspect`/`docker history` access to a running container.
**With what privilege:** whatever the credential itself is scoped to — a registry account, an
internal API token. **To what effect:** registry account takeover (push a malicious image
under a trusted name) or lateral movement via the leaked API token.

Mined from `cr0hn/dockerfile-security`'s declarative rule catalog (`credentials.yaml`
cred-011, `core.yaml` core-010), cross-checked against agentsec's real guard source (
at research time): `build-secret`/`client-side-secret-literal`/`hardcoded-llm-provider-key` all match a
secret-shaped literal VALUE wherever it appears, but none scans specifically for a credential
passed as a `docker login` CLI flag or embedded in a `HEALTHCHECK` probe — two surfaces
confirmed uncovered by grep before building this guard.

## Why it's often introduced

A multi-stage build that needs to push an intermediate image, or a health probe hastily
protected with a shared token rather than left genuinely open internally:

```dockerfile
RUN docker login -u ci-bot -p "${REGISTRY_PASSWORD}"      # the shell substitutes the value into argv
HEALTHCHECK CMD curl -f "http://localhost/health?token=${HEALTH_TOKEN}" || exit 1
```

Both look "fine" because the value comes from a variable, not a literal — but the credential
still lands in the image's layer history / inspect output once the shell expands it, regardless
of where the value originally came from.

## Detection design

1. **`applies()` gate** — `"docker" in profile.features`.
2. **Files scanned** — every Dockerfile found by `iter_dockerfiles(root)`. Comment lines inside
   a backslash-continued instruction are dropped first, as Docker's own parser does
   (`drop_dockerfile_continuation_comments()`), then continuations are joined via
   `join_dockerfile_continuations()`. Line numbers are preserved.
3. **Pattern** — two independent checks:
   - `registry-auth-exposure`: a non-comment line with `docker login` plus a `-p` or
     `--password` flag taking a value (`--password-stdin`, the safe form, is excluded), or a
     `.dockerconfigjson` reference, or a `DOCKER_PASSWORD=<value>` assignment. The assignment
     check is skipped on an `ARG`/`ENV` line, because `build-secret/secret-build-arg` already
     owns secret-shaped ARG/ENV names and a second rule there would bypass a user's existing
     `build-secret` suppression. The other two checks still run on ARG/ENV lines, so
     `ENV DOCKER_CONFIG_FILE=/root/.dockerconfigjson` fires.
   - `healthcheck-credential`: a `HEALTHCHECK` instruction's argument containing a
     password/token/bearer/secret/apitoken/authentication/authorization-shaped value
     (`name[=:]value` or a `Bearer`/`Basic` + token-shaped string), a `-u user:pass` or
     `--user user:pass` pair, or a URL with `user:pass@` userinfo.
4. **Opt-out pragma** — `# security: allow-dockerfile-credential-in-instruction` anywhere in
   the file (whole-file reach) silences both rules. It is read from the file as written, so a
   pragma comment inside a continued `RUN` still counts.
5. **Severity / rules / standards** — both HIGH, `dockerfile-credential-in-instruction/
   registry-auth-exposure` and `dockerfile-credential-in-instruction/healthcheck-credential`,
   standards `["OWASP:A02", "CWE-798"]`.

## When NOT to flag

- `RUN docker login registry.example.com` with no `-p`/`--password` flag at all (interactive
  prompt, or a credential helper) — not flagged, no matching flag on the line.
- `docker login -u ci --password-stdin` — the recommended safe form; the value never reaches
  argv or build history. Not flagged.
- A commented-out line, including a comment inside a continued `RUN`. Not flagged.
- `ENV DOCKER_PASSWORD=...` — flagged by `build-secret/secret-build-arg` instead, not here.
- `HEALTHCHECK CMD curl -u admin http://...` (no password half) or `--user-agent probe:1`. Not
  flagged.
- `HEALTHCHECK CMD curl -f http://localhost/health || exit 1` — a plain, unauthenticated probe.
  Not flagged.
- A documented, reviewed local-dev-only health probe with a throwaway token: suppress with
  `# security: allow-dockerfile-credential-in-instruction`.

## Tests

| Test | What it checks |
|---|---|
| `test_registry_auth_exposure_fires` | `docker login -u ... -p ...` fires HIGH |
| `test_run_inline_password_assignment_still_fires` | `RUN DOCKER_PASSWORD=... ./deploy.sh` fires HIGH here and not in `build-secret` |
| `test_docker_password_env_is_build_secrets_job_not_this_guards` | `ENV DOCKER_PASSWORD=...` stays silent here; `build-secret` fires on it |
| `test_password_stdin_is_the_safe_form_and_stays_silent` | FP-bait: `docker login ... --password-stdin` stays silent |
| `test_long_password_flag_still_fires` | `--password <value>` and `--password=<value>` still fire |
| `test_commented_out_registry_login_stays_silent` | FP-bait: commented-out `docker login -p` / `DOCKER_PASSWORD=` lines stay silent |
| `test_comment_inside_a_continued_run_stays_silent` | FP-bait: a `# docker login -p ...` comment inside a continued `RUN` stays silent |
| `test_login_after_a_comment_in_a_continued_run_still_fires` | a `docker login -p` after such a comment still fires |
| `test_dockerconfigjson_on_an_env_line_still_fires` | `ENV X=/root/.dockerconfigjson` fires here and not in `build-secret` |
| `test_dockerconfigjson_reference_fires` | a `.dockerconfigjson` reference fires HIGH |
| `test_healthcheck_token_in_url_fires` | a `HEALTHCHECK` probe URL embedding `token=...` fires HIGH |
| `test_healthcheck_bearer_header_fires` | a `HEALTHCHECK` probe's `Authorization: Bearer ...` header fires HIGH |
| `test_healthcheck_basic_auth_pair_fires` | `-u user:pass`, `--user=user:pass`, a quoted `--user` pair, `http://user:pass@host` and `-u redis://user:pass@host` fire HIGH |
| `test_healthcheck_without_a_password_half_stays_silent` | FP-bait: `-u admin`, `--user-agent probe:1`, `host:port` URLs, `user@host` and a `-u redis://host:port` URL stay silent |
| `test_ordinary_docker_login_without_password_flag_silent` | FP-bait: `docker login` with no password flag stays silent |
| `test_ordinary_healthcheck_without_credential_silent` | FP-bait: a plain unauthenticated probe stays silent |
| `test_pragma_silences_both_rules` | the pragma silences both rules in one file |
| `test_applies_gate` | `docker` on, `python`-only off |

## Known bypasses

- **Credential delivered via a build secret mount or a credential helper** instead of a CLI
  flag or probe literal — the whole point of the remediation this guard recommends, and
  correctly invisible to it (no literal to match).
- **Indirect construction** — a token assembled via string concatenation or read from a file
  at build time rather than appearing as a literal flag value, is not tracked.
- **A probe command whose credential-shaped word is actually a path segment or parameter
  name with no real secret value** (e.g. `?has_token=true`) — the regex requires an `=`/`:`
  immediately followed by a non-whitespace value, which narrows this but does not eliminate
  every such case.

## What this guard does NOT prove

A silent guard does not mean the running container holds no credentials in its history or
inspect output — only that no `docker login` password flag (other than `--password-stdin`),
`.dockerconfigjson` reference, `DOCKER_PASSWORD=` assignment outside ARG/ENV, or
credential-shaped `HEALTHCHECK` argument appears in a live (non-comment) Dockerfile line.
A credential baked into the image's filesystem by a different mechanism (a `COPY`'d config
file, an `ENV`/`ARG` with a secret-shaped NAME — `build-secret`'s job — or a secret fetched at
runtime and logged) is out of this guard's scope.

# Citations

[1] agentsec checklist item `1-dockerfile-credential-in-instruction` (§1)
[2] OWASP:A02
[3] CWE-798
