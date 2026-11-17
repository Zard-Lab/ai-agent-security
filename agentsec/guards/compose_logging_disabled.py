"""Guard: docker-compose service with logging driver explicitly disabled (checklist §6c).

    services:
      app:
        logging:
          driver: none

Setting the logging driver to `none` disables all log collection for the service — no
stdout/stderr capture, nothing for `docker logs` or a log-shipping sidecar to read. An
incident on a service with logging disabled leaves no forensic trail: no request history,
no error output, no evidence of what an attacker did once inside. CWE-778 (Insufficient
Logging), OWASP:A09.

Sourced from compose-lint's `LoggingDisabledRule` (`CL-0014`).

Fires LOW when a service's `logging:` block sets `driver: none` (quoted or bare).

Suppress an audited case (e.g. a genuinely log-free throwaway sidecar) with
`# security: allow-compose-logging-disabled` anywhere in the compose file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_dev_compose_file,
    iter_compose_services,
    iter_files_named,
    pragma_present,
    read,
    rel,
)

_PRAGMA = "# security: allow-compose-logging-disabled"

_STANDARDS = ["OWASP:A09", "CWE-778"]

_DRIVER_KEY = re.compile(r"^\s*driver\s*:\s*(?:['\"])?(?P<value>[a-zA-Z]+)")


class ComposeLoggingDisabledGuard(Guard):
    id = "compose-logging-disabled"
    title = "Docker-compose service with logging driver explicitly disabled"
    area = "Containers"

    canary_plant = CanaryPlant(
        files={
            "docker-compose.logging.yml": (
                "services:\n"
                "  canary:\n"
                "    image: alpine:3\n"
                "    logging:\n"
                "      driver: none\n"
            ),
        },
        expects=frozenset({"compose-logging-disabled/driver-none"}),
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

    def _scan(self, text: str, location: str) -> list[Finding]:
        out: list[Finding] = []
        for service_name, _start, body in iter_compose_services(text):
            in_logging = False
            logging_indent = -1
            for line_no, raw in body:
                if not raw.strip():
                    continue
                if raw.lstrip().startswith("#"):
                    continue
                indent = len(raw) - len(raw.lstrip())
                key = re.match(r"(\s*)logging\s*:\s*(?:#.*)?$", raw)
                if key:
                    in_logging, logging_indent = True, len(key.group(1))
                    continue
                if not in_logging:
                    continue
                if indent <= logging_indent:
                    in_logging = False
                    continue
                m = _DRIVER_KEY.match(raw)
                if m and m.group("value").lower() == "none":
                    out.append(Finding(
                        check_id=self.id,
                        severity="low",
                        title=self.title,
                        location=f"{location}:{line_no}",
                        message=(
                            f"Service '{service_name}' has logging driver set to "
                            "'none'. No logs will be collected from this container, "
                            "preventing audit trails and incident response."
                        ),
                        remediation=(
                            "Remove `driver: none` to use the default logging driver, "
                            "or configure one explicitly (`json-file` with `max-size`/"
                            f"`max-file`). Suppress an audited exception with "
                            f"`{_PRAGMA}` anywhere in the compose file."
                        ),
                        rule="compose-logging-disabled/driver-none",
                        standards=list(_STANDARDS),
                    ))
        return out
