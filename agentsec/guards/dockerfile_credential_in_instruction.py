"""Guard: Dockerfile instruction embeds a plaintext credential outside a build-arg/env
literal (dockerfile-credential-in-instruction).

Mined from `cr0hn/dockerfile-security`'s declarative rule catalog (`credentials.yaml`
cred-011, `core.yaml` core-010), cross-checked against agentsec's real guard source before
building: `build-secret`/`client-side-secret-literal`/`hardcoded-llm-
provider-key` all match a secret-shaped LITERAL VALUE wherever it appears, but none scans
specifically for a credential passed as a command-line flag to `docker login`, or embedded in
a `HEALTHCHECK` probe command — two surfaces this guard adds, confirmed uncovered by grep.

Fires on:

  * **`registry-auth-exposure`** (HIGH) — `docker login` with a `-p`/`--password` flag taking
    a value, a `.dockerconfigjson` reference, or a `*_PASSWORD=`-shaped assignment OUTSIDE an
    `ARG`/`ENV` instruction (e.g. a `RUN DOCKER_PASSWORD=... ./deploy.sh` inline shell prefix).
    `--password-stdin` is the safe form (reads from stdin, never touches argv or build
    history) and does not fire. A password passed as a CLI flag is captured in the image's
    build history (`docker history`) and typically in build logs, regardless of whether the
    value itself is a literal or an interpolated variable — the shell substitutes it into
    argv either way. An `ARG`/`ENV` assignment itself is deliberately excluded here —
    `build-secret/secret-build-arg` already fires on any secret-shaped `ARG`/`ENV` name
    (`PASSWORD` included), and duplicating that coverage under a different rule id would let
    this rule fire straight through a user's existing `build-secret` suppression for the same
    line. Only that assignment is excluded on an `ARG`/`ENV` line: `build-secret` keys on the
    NAME, so an `ENV X=/root/.dockerconfigjson` reference still fires here. A commented-out
    line, including a comment inside a continued `RUN`, does not fire.
  * **`healthcheck-credential`** (HIGH) — a `HEALTHCHECK` instruction's probe command embeds a
    password/token/bearer/API-key value (e.g. `curl http://localhost/health?token=...`, an
    `Authorization: Bearer ...` header, `curl -u user:pass`, or a `http://user:pass@host`
    URL). The credential is readable in the image's layer
    history and in `docker inspect` output for the life of the container.

**Suppress:** add `# security: allow-dockerfile-credential-in-instruction` to the Dockerfile
to silence both rules for that file (e.g. a documented, reviewed local-dev-only health probe).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    drop_dockerfile_continuation_comments,
    iter_dockerfiles,
    join_dockerfile_continuations,
    pragma_present,
    read,
    rel,
)

_PRAGMA = "security: allow-dockerfile-credential-in-instruction"

# Mirrors cr0hn/dockerfile-security's cred-011 rule, verified against the real catalog. The
# `--password` branch excludes `--password-stdin` (`(?!-stdin\b)`) — that flag reads the value
# from stdin, so it never reaches argv/build history and is the RECOMMENDED safe form, not a
# finding.
_REGISTRY_AUTH_EXPOSURE = re.compile(
    r"docker\s+login\b.*(?:-p\b|--password(?!-stdin\b)\b)\s*\S+"
    r"|\.dockerconfigjson\b",
    re.IGNORECASE,
)
_DOCKER_PASSWORD_ASSIGNMENT = re.compile(r"DOCKER_PASSWORD\s*=\s*\S+", re.IGNORECASE)

# An `ARG`/`ENV` instruction line — `build-secret/secret-build-arg` already owns any
# secret-shaped ARG/ENV name (PASSWORD included), so `_DOCKER_PASSWORD_ASSIGNMENT` must not
# also fire on one of these, or it fires straight through a user's existing `build-secret`
# suppression for the same line (see module docstring). `_REGISTRY_AUTH_EXPOSURE` still runs
# on these lines: build-secret keys on the name, not on a `.dockerconfigjson` value.
_ARG_OR_ENV_INSTRUCTION = re.compile(r"^\s*(?:ARG|ENV)\s+", re.IGNORECASE)

_HEALTHCHECK_INSTRUCTION = re.compile(r"^[^\S\n]*HEALTHCHECK\s+(.+)$", re.MULTILINE | re.IGNORECASE)
# The first two branches mirror cr0hn/dockerfile-security's core-010 rule, verified against the
# real catalog. The last two go beyond it: a `-u user:pass`/`--user user:pass` pair and a URL
# carrying `user:pass@` userinfo. Both need the colon-separated password half, so a bare
# `-u admin` (curl prompts) stays silent, and `--user-agent probe:1` does too (`--user` must
# be followed by `=` or whitespace). A `-u <scheme>://...` URL (`redis-cli -u redis://host:6379`)
# is not a pair: `(?!//)` rejects the scheme's colon. A URL carrying `user:pass@` still fires
# through the userinfo branch.
_HEALTHCHECK_CREDENTIAL = re.compile(
    r"\b(?:password|bearer|token|apitoken|secret|authentication|authorization)\b"
    r"[=:]\S|\b(?:bearer|basic)\s+[A-Za-z0-9._-]{8,}"
    r"|(?:^|\s)(?:-u|--user)(?:\s+|=)[\"']?[^\s\"':]+:(?!//)[^\s\"']"
    r"|://[^\s/@:]+:[^\s/@]+@",
    re.IGNORECASE,
)

_STANDARDS = ["OWASP:A02", "CWE-798"]


class DockerfileCredentialInInstructionGuard(Guard):
    id = "dockerfile-credential-in-instruction"
    title = "Dockerfile instruction embeds a plaintext credential"
    area = "Secrets"

    # Canary plant: own file.
    canary_plant = CanaryPlant(
        files={
            "Dockerfile.credential-in-instruction": (
                "FROM debian:bookworm-slim\n"
                "RUN docker login -u canaryuser -p canaryPASSWORD123456\n"
                'HEALTHCHECK --interval=5m CMD curl -f '
                '"http://localhost/health?token=canaryTOKEN123456" || exit 1\n'
            ),
        },
        expects=frozenset({
            "dockerfile-credential-in-instruction/registry-auth-exposure",
            "dockerfile-credential-in-instruction/healthcheck-credential",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "docker" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_dockerfiles(root):
            raw = read(f)
            # The pragma reads the file as written; the rules match the text Docker builds, so a
            # comment inside a continued RUN is not folded in as live (CLAUDE.md rule 4).
            if not raw.strip() or pragma_present(
                _PRAGMA, join_dockerfile_continuations(raw), dialect="hash"
            ):
                continue
            text = join_dockerfile_continuations(drop_dockerfile_continuation_comments(raw))
            rel_path = rel(root, f)
            for i, line in enumerate(text.splitlines(), start=1):
                if line.lstrip().startswith("#"):
                    continue  # a commented-out instruction is not a real finding
                if _REGISTRY_AUTH_EXPOSURE.search(line) or (
                    # an ARG/ENV `DOCKER_PASSWORD=` is build-secret/secret-build-arg's job
                    not _ARG_OR_ENV_INSTRUCTION.match(line)
                    and _DOCKER_PASSWORD_ASSIGNMENT.search(line)
                ):
                    out.append(self._registry_finding(rel_path, i))
            for m in _HEALTHCHECK_INSTRUCTION.finditer(text):
                if _HEALTHCHECK_CREDENTIAL.search(m.group(1)):
                    line_no = text.count("\n", 0, m.start()) + 1
                    out.append(self._healthcheck_finding(rel_path, line_no))
        return out

    def _registry_finding(self, rel_path: str, line_no: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel_path}:{line_no}",
            message=(
                "This line passes a registry password as a CLI flag (`docker login ... "
                "-p ...`/`--password ...`), a `.dockerconfigjson` reference, or a "
                "`DOCKER_PASSWORD=` assignment outside an ARG/ENV instruction. A password "
                "exposed this way lands in the image's build history and typically in build "
                "logs, whether the value is a literal or an interpolated variable — the "
                "shell substitutes it into argv either way."
            ),
            remediation=(
                "Use BuildKit's `--mount=type=secret` for registry credentials instead of a "
                "CLI flag, or authenticate outside the Dockerfile entirely (a CI step with "
                "its own credential helper). Suppress an audited case with "
                "`# security: allow-dockerfile-credential-in-instruction`."
            ),
            rule="dockerfile-credential-in-instruction/registry-auth-exposure",
            standards=list(_STANDARDS),
        )

    def _healthcheck_finding(self, rel_path: str, line_no: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel_path}:{line_no}",
            message=(
                "This `HEALTHCHECK` probe command embeds what looks like a plaintext "
                "credential (a token/password/bearer value in a URL or header). It is "
                "readable in the image's layer history and in `docker inspect` output for "
                "the life of the container."
            ),
            remediation=(
                "Use an unauthenticated internal health endpoint, or read the credential "
                "from a mounted secret file at container runtime instead of embedding it in "
                "the instruction. Suppress an audited case with "
                "`# security: allow-dockerfile-credential-in-instruction`."
            ),
            rule="dockerfile-credential-in-instruction/healthcheck-credential",
            standards=list(_STANDARDS),
        )
