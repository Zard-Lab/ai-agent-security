"""Guard: docker-compose service with no memory or CPU resource limit (checklist §6c).

    services:
      app:
        image: myapp
        # no mem_limit, no deploy.resources.limits, no cpus -> unbounded

A service with no memory or CPU limit can exhaust the host's resources — Docker imposes
neither by default, so a single compromised or runaway service degrades every other
container on the same host. CWE-770 (Allocation of Resources Without Limits or
Throttling), OWASP:A05.

Sourced from compose-lint's `ResourceLimitsRule` (`CL-0026`), simplified to a flat
service-body text search rather than a structural walk of `deploy.resources.limits`
specifically — acceptable here because `memory:`/`cpus:` under any other key in a service
block is not a real compose shape (the v2 top-level spellings `mem_limit:`/`cpus:` and the
Swarm-style `deploy.resources.limits.memory`/`.cpus` are the only places these keys
legitimately appear). Does not reproduce the real rule's `0`-means-unbounded or
defaulted-interpolation (`${MEM:-0}`) nuance — a positive-looking literal is trusted at
face value here.

Fires LOW when a service declares neither a memory bound (`mem_limit:` or
`deploy.resources.limits.memory:`) nor a CPU bound (`cpus:`, `cpu_quota:`, or
`deploy.resources.limits.cpus:`).

Severity note (#663 review M2): this sits in the project's own auto-exclude noise
category — "DoS, rate-limiting, memory/CPU exhaustion" is named explicitly in
`wiki/methodology/fable-security-fundamentals.md` (F2), `security-audit-behaviors.md`
(B8), and `wiki/research/llm-audit-methodology.md`. A 6-repo measurement found 27
findings with no proven exploit path (an absent limit is not itself evidence a workload
can be driven to exhaust one). Rather than add this guard into that category at `medium`
(implicitly deciding an open doctrinal question — see the sibling `redos` case, #91,
`docs/knowledge/noise-category-guard-doctrine.md`, still open and leaning toward
demote/remove), it is graded LOW: real hardening advice stays visible, but it does not
compete with proven-impact findings for "fix these first" attention.

Suppress an audited case (e.g. a genuinely unbounded local-only sidecar) with
`# security: allow-compose-resource-limits` anywhere in the compose file.
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

_PRAGMA = "# security: allow-compose-resource-limits"

_STANDARDS = ["OWASP:A05", "CWE-770"]

_MEMORY_KEY = re.compile(r"^\s*(?:mem_limit|memory)\s*:\s*(\S.*)$")
_CPU_KEY = re.compile(r"^\s*(?:cpus|cpu_quota)\s*:\s*(\S.*)$")


def _blank_comments(body: list[tuple[int, str]]) -> list[tuple[int, str]]:
    return [(ln, "" if line.lstrip().startswith("#") else line) for ln, line in body]


class ComposeResourceLimitsAbsentGuard(Guard):
    id = "compose-resource-limits-absent"
    title = "Docker-compose service with no memory or CPU resource limit"
    area = "Containers"

    canary_plant = CanaryPlant(
        files={
            "docker-compose.limits.yml": (
                "services:\n"
                "  canary:\n"
                "    image: alpine:3\n"
                "    command: [\"sleep\", \"infinity\"]\n"
            ),
        },
        expects=frozenset({"compose-resource-limits-absent/no-limits"}),
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
        for service_name, start_line, body in iter_compose_services(text):
            blanked = _blank_comments(body)
            has_memory = any(_MEMORY_KEY.match(line) for _ln, line in blanked)
            has_cpu = any(_CPU_KEY.match(line) for _ln, line in blanked)
            if has_memory and has_cpu:
                continue
            if not has_memory and not has_cpu:
                missing = "no memory limit and no CPU limit"
            elif not has_memory:
                missing = "no memory limit"
            else:
                missing = "no CPU limit"
            out.append(Finding(
                check_id=self.id,
                severity="low",
                title=self.title,
                location=f"{location}:{start_line}",
                message=(
                    f"Service '{service_name}' declares {missing}. Docker imposes "
                    "neither by default, so this container can consume the host's "
                    "memory or CPU until other workloads are starved."
                ),
                remediation=(
                    "Bound both, sized from the workload's observed steady state: "
                    "`deploy.resources.limits.memory`/`.cpus`, or the v2 spellings "
                    f"`mem_limit`/`cpus`. Suppress an audited exception with "
                    f"`{_PRAGMA}` anywhere in the compose file."
                ),
                rule="compose-resource-limits-absent/no-limits",
                standards=list(_STANDARDS),
            ))
        return out
