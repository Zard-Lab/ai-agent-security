"""Guard: docker-compose credential-shaped env key with a literal value (checklist §6c).

    services:
      app:
        environment:
          DB_PASSWORD: hunter2      # literal secret, not routed through Compose secrets:

An environment variable whose key name matches a credential convention (`PASSWORD`,
`TOKEN`, `SECRET`, `API_KEY`, `ACCESS_KEY`, `PRIVATE_KEY`, `CREDENTIAL`, `_PASS`, `_PWD`,
`_DSN`, …) and whose value is a non-empty literal string is exposed via `docker inspect`,
`/proc/<pid>/environ`, `docker compose config`, process listings, and CI logs — any
process or operator with daemon access can read it. Compose's `secrets:` primitive
materializes credentials as files under `/run/secrets/` instead, which appears in none of
those surfaces. CWE-798 (Use of Hard-coded Credentials), OWASP:A02.

Sourced from compose-lint's `CredentialEnvKeysRule` (`CL-0020`), simplified: real
compose-lint also exempts a `*_TTL`/`*_TIMEOUT`/quantity-knob family (`TOKEN_TTL_MINUTES:
30` is a duration, not a token — this guard reproduces a representative subset of that
exemption list, not the full one).

Fires HIGH when a service's `environment:` block (dict form `KEY: value` or list form
`- KEY=value`) has a credential-shaped key with a literal, non-empty, non-flag,
non-quantity value that does not end in `_FILE` (the documented file-path opt-out) and is
not a pure Compose variable reference — `$VAR`/`${VAR}`, an empty-fallback default
(`${VAR:-}`/`${VAR-}`), and an error-message form (`${VAR:?msg}`/`${VAR?msg}`) all stay
silent, but a NON-EMPTY-fallback default (`${VAR:-hunter2}`-style) still fires — that
fallback is itself a literal credential shipped in the file (#663 review H1;
`is_compose_interpolation_only()` in `guards/base.py`).

A userinfo-free `scheme://` URL also stays silent (#898): `GOTRUE_HOOK_CUSTOM_ACCESS_TOKEN_URI:
pg-functions://postgres/public/custom_access_token_hook` and `OAUTH_TOKEN_URL:
https://auth.example.com/oauth/token` are locators whose key merely contains `TOKEN`. The
exemption is the `build_secret.py` #447 rule: ANY `@` in the authority keeps the value a
credential, so `postgresql://admin:hunter2@db` and the user-only `https://ghp_x@github.com`
(a bare token that only this guard catches) still fire. A secret embedded in the path or
query of a userinfo-free URL is the accepted trade (see the wiki doc's Known bypasses).

Suppress an audited case with `# security: allow-compose-credential-env-literal` anywhere
in the compose file.
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

_PRAGMA = "# security: allow-compose-credential-env-literal"

_STANDARDS = ["OWASP:A02", "CWE-798"]

_SUBSTRING_PATTERNS = (
    "PASSWORD", "PASSPHRASE", "TOKEN", "SECRET", "API_KEY", "APIKEY",
    "PRIVATE_KEY", "ACCESS_KEY", "SECRET_KEY", "ENCRYPTION_KEY", "CREDENTIAL",
)
_SUFFIX_PATTERNS = ("_PASS", "_PWD", "PASSWD", "_SALT", "_DSN")

_FILE_SUFFIX = "_FILE"
_FLAG_KEY_FRAGMENTS = ("ALLOW_EMPTY_", "RANDOM_")
_FLAG_VALUES = frozenset({"yes", "no", "true", "false", "0", "1", "on", "off"})

# A representative subset of compose-lint's quantity-knob exemption — a key naming a
# lifetime/size/limit whose value is a bare quantity is not a credential.
_QUANTITY_KEY_FRAGMENTS = (
    "TTL", "TIMEOUT", "EXPIRE", "EXPIRY", "EXPIRATION", "MAX_AGE",
    "_SECONDS", "_MINUTES", "_HOURS", "_DAYS", "_MS", "_LIMIT", "_SIZE", "TOKENS",
)
_QUANTITY_VALUE_RE = re.compile(r"^\d+(\.\d+)?(ms|s|m|h|d)?$", re.IGNORECASE)

# A userinfo-free URL is a locator, not a credential (the build_secret.py #447 rule):
# `pg-functions://postgres/public/hook`, `https://auth.example.com/oauth/token` (#898). ANY `@`
# in the authority keeps it a credential — `https://ghp_x@github.com` is a bare token that only
# this guard catches (the sibling's _CONN_STRING needs `:password@`). Anchored + bounded scheme,
# single forward lookahead: linear in the value length (measured 0.6 ms at 100k chars).
_USERINFO_FREE_URL = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]{0,63}://(?![^/\s]*@)\S+$")

_ENV_DICT_KV = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?P<value>.*)$")
_ENV_LIST_ITEM = re.compile(r"^-\s*(?:['\"])?(?P<rest>.+?)(?:['\"])?$")


def _matches_credential_pattern(key_upper: str) -> bool:
    if any(s in key_upper for s in _SUBSTRING_PATTERNS):
        return True
    return any(key_upper.endswith(s) for s in _SUFFIX_PATTERNS)


def _is_exempt_key(key_upper: str) -> bool:
    if key_upper.endswith(_FILE_SUFFIX):
        return True
    return any(fragment in key_upper for fragment in _FLAG_KEY_FRAGMENTS)


def _is_quantity_knob(key_upper: str, value: str) -> bool:
    if not _QUANTITY_VALUE_RE.match(value.strip()):
        return False
    return any(fragment in key_upper for fragment in _QUANTITY_KEY_FRAGMENTS)


def _is_literal_credential_value(value: str) -> bool:
    value = value.strip().strip("'\"")
    if not value:
        return False
    if value.lower() in _FLAG_VALUES:
        return False
    if _USERINFO_FREE_URL.match(value):
        return False
    return not is_compose_interpolation_only(value)


class ComposeCredentialEnvLiteralGuard(Guard):
    id = "compose-credential-env-literal"
    title = "Docker-compose credential-shaped env key with a literal value"
    area = "Containers"

    canary_plant = CanaryPlant(
        files={
            "docker-compose.creds.yml": (
                "services:\n"
                "  canary:\n"
                "    image: alpine:3\n"
                "    environment:\n"
                "      DB_PASSWORD: hunter2\n"
            ),
        },
        expects=frozenset({"compose-credential-env-literal/literal-credential"}),
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

    def _check_kv(self, key: str, value: str, service_name: str, line_no: int, location: str) -> Finding | None:
        key_upper = key.upper()
        if not _matches_credential_pattern(key_upper):
            return None
        if _is_exempt_key(key_upper):
            return None
        value = value.strip()
        if _is_quantity_knob(key_upper, value):
            return None
        if not _is_literal_credential_value(value):
            return None
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{location}:{line_no}",
            message=(
                f"Service '{service_name}' has credential-shaped env key '{key}' with a "
                "literal value. Env vars are exposed via `docker inspect`, "
                "`/proc/<pid>/environ`, `docker compose config`, process listings, and CI "
                "logs — any process or operator with daemon access can read them."
            ),
            remediation=(
                f"Move '{key}' to Compose's `secrets:` primitive, or (if the image "
                f"supports it) set `{key}_FILE: /run/secrets/<name>` and declare the "
                "secret under the top-level `secrets:` block. Suppress an audited "
                f"exception with `{_PRAGMA}` anywhere in the compose file."
            ),
            rule="compose-credential-env-literal/literal-credential",
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
                    finding = self._check_kv(k.strip(), v.strip(), service_name, line_no, location)
                elif env_is_list is not True:
                    m2 = _ENV_DICT_KV.match(stripped)
                    if not m2:
                        continue
                    finding = self._check_kv(m2.group("key"), m2.group("value"), service_name, line_no, location)
                else:
                    continue
                if finding is not None:
                    out.append(finding)
        return out
