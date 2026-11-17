"""Guard: docker-compose env value with an inline connection-string credential (§6c).

    services:
      app:
        environment:
          DATABASE_URL: postgresql://admin:hunter2@db:5432/app

A `scheme://user:password@host` userinfo embedded in an environment value leaks a
credential regardless of the key's own name — `DATABASE_URL`, `MONGO_URL`, `REDIS_URL`
and similar connection-string variables routinely carry one. The exposure surface is
identical to `compose-credential-env-literal`: `docker inspect`, `/proc/<pid>/environ`,
`docker compose config`, process listings, and CI logs. CWE-798 (Use of Hard-coded
Credentials), OWASP:A02.

Sourced from compose-lint's `ConnectionStringCredentialsRule` (`CL-0021`), simplified to a
single bounded regex rather than the real source's manual, ReDoS-hardened userinfo scan —
acceptable here because the pattern is anchored to the `@` delimiter and length-capped,
keeping worst-case cost linear in the value length. A password that is a bare `$VAR`/`${VAR}`
reference, or an empty-fallback default (`${VAR:-}`/`${VAR-}`), or an error-message form
(`${VAR:?msg}`/`${VAR?msg}`) is exempt — no credential is shipped in the file. A
NON-EMPTY-fallback default (`${VAR:-hunter2}`-style) still fires, matching the shipped
literal (#663 review H2; `is_compose_interpolation_only()` in `guards/base.py`, shared with
`compose_credential_env_literal` so the two cannot drift apart).

Fires HIGH on an `environment:` value (any key name) containing a `scheme://` URI whose
userinfo has a password that is not a pure/empty-default/error-message reference.

Suppress an audited case with `# security: allow-compose-connection-string-credential`
anywhere in the compose file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_compose_interpolation_only,
    is_dev_compose_file,
    iter_compose_services,
    iter_files_named,
    pragma_present,
    read,
    rel,
)

_PRAGMA = "# security: allow-compose-connection-string-credential"

_STANDARDS = ["OWASP:A02", "CWE-798"]

# scheme://[user][:password]@host — bounded scheme/user/password lengths keep this linear
# in the value's length rather than backtracking on an attacker-controlled string.
_CONN_STRING = re.compile(
    r"[a-zA-Z][a-zA-Z0-9+.\-]{0,63}://"
    r"(?P<user>[^:/@\s]{0,512})"
    r":(?P<password>[^/@\s]{1,512})"
    r"@"
)

_ENV_DICT_KV = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<value>.*)$")
_ENV_LIST_ITEM = re.compile(r"^-\s*(?:['\"])?(?P<rest>.+?)(?:['\"])?$")


def _find_inline_credential(value: str) -> str | None:
    if "@" not in value:
        return None
    m = _CONN_STRING.search(value)
    if not m:
        return None
    password = m.group("password")
    if is_compose_interpolation_only(password):
        return None
    return m.group(0)


class ComposeConnectionStringCredentialGuard(Guard):
    id = "compose-connection-string-credential"
    title = "Docker-compose env value with an inline connection-string credential"
    area = "Containers"

    canary_plant = CanaryPlant(
        files={
            "docker-compose.conn-string.yml": (
                "services:\n"
                "  canary:\n"
                "    image: alpine:3\n"
                "    environment:\n"
                "      DATABASE_URL: postgresql://admin:hunter2@db:5432/app\n"
            ),
        },
        expects=frozenset({"compose-connection-string-credential/embedded-credential"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "docker" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml"):
            if is_dev_compose_file(f.name):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="yaml"):
                continue
            out.extend(self._scan(text, rel(root, f)))
        return out

    def _check(self, key: str, value: str, service_name: str, line_no: int, location: str) -> Finding | None:
        match = _find_inline_credential(value.strip().strip("'\""))
        if match is None:
            return None
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{location}:{line_no}",
            message=(
                f"Service '{service_name}' has env var '{key}' containing an inline "
                f"credential in a connection string ({match}...). Env vars are exposed "
                "via `docker inspect`, `/proc/<pid>/environ`, `docker compose config`, "
                "process listings, and CI logs."
            ),
            remediation=(
                "Remove the literal password from the connection string. Preferred: "
                "store the credential in Compose `secrets:` and reassemble the URL in "
                "the workload's entrypoint. Acceptable interim step: pull it from "
                "process env via substitution (`${DB_PASSWORD}`). Suppress an audited "
                f"exception with `{_PRAGMA}` anywhere in the compose file."
            ),
            rule="compose-connection-string-credential/embedded-credential",
            standards=list(_STANDARDS),
        )

    def _scan(self, text: str, location: str) -> list[Finding]:
        out: list[Finding] = []
        for service_name, _start, body in iter_compose_services(text):
            in_env = False
            env_indent = -1
            env_is_list: bool | None = None
            for line_no, raw in body:
                if not raw.strip():
                    continue
                indent = len(raw) - len(raw.lstrip())
                key_m = re.match(r"(\s*)environment\s*:\s*(?:#.*)?$", raw)
                if key_m:
                    in_env, env_indent, env_is_list = True, len(key_m.group(1)), None
                    continue
                if not in_env:
                    continue
                if indent <= env_indent:
                    in_env = False
                    continue
                stripped = raw.strip().partition("#")[0].strip()
                if not stripped:
                    continue
                if stripped.startswith("-"):
                    env_is_list = True
                    m = _ENV_LIST_ITEM.match(stripped)
                    if not m:
                        continue
                    rest = m.group("rest")
                    if "=" in rest:
                        k, _, v = rest.partition("=")
                    elif ":" in rest:
                        k, _, v = rest.partition(":")
                    else:
                        continue
                    finding = self._check(k.strip(), v, service_name, line_no, location)
                elif env_is_list is not True:
                    m2 = _ENV_DICT_KV.match(stripped)
                    if not m2:
                        continue
                    finding = self._check(m2.group("key"), m2.group("value"), service_name, line_no, location)
                else:
                    continue
                if finding is not None:
                    out.append(finding)
        return out
