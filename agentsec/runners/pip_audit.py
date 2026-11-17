"""pip-audit — Python dependency CVEs. Parses `.dependencies[].vulns[]`."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.walk import DEFAULT_EXCLUDE_DIRS as _EXCLUDE

from .base import Runner, ScannerExecError, as_list, exec_capture_or_raise


class PipAuditRunner(Runner):
    id = "pip-audit"
    area = "Dependencies"
    binary = "pip-audit"
    install_hint = "pipx install pip-audit"
    tier_required = 1  # queries OSV for advisories — egresses your package names
    egress_dest = "OSV / PyPI"
    egress_sends = "your Python package names+versions"
    deterministic = False  # live: queries the OSV/PyPI advisory DB

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def _requirements(self, root: Path) -> list[Path]:
        out: list[Path] = []
        for f in sorted(root.rglob("requirements*.txt")):
            if any(part in _EXCLUDE for part in f.parts):
                continue
            if "locked" in f.name:  # the locked file duplicates the direct deps
                continue
            out.append(f)
        return out

    def invoke(self, root: Path, profile: StackProfile) -> str:
        deps: list[Any] = []
        reqs = self._requirements(root)
        if not reqs:
            return '{"dependencies": []}'
        failures: list[str] = []
        for req in reqs:
            # Per-file catch: one bad requirements file must not erase the findings
            # already gathered from the others (#432 review). A total failure still
            # raises below so run() records the error instead of reporting clean.
            try:
                _, out, _ = exec_capture_or_raise(
                    ["pip-audit", "-r", str(req), "--format", "json", "--progress-spinner", "off"], cwd=root
                )
            except ScannerExecError as e:
                failures.append(f"{req.name}: {e}")
                continue
            if not out:
                continue
            try:
                d = json.loads(out)
            except json.JSONDecodeError:
                continue
            if isinstance(d, dict):
                deps.extend(as_list(d.get("dependencies")))
        if failures and len(failures) == len(reqs):
            raise ScannerExecError("; ".join(failures))
        for f in failures:
            # A PARTIAL failure was previously discarded entirely: one requirements file
            # timing out next to one that returned a real CVE gave available=True,
            # findings=1, error=None — half the dependency surface unscanned and
            # indistinguishable from a full scan (#432 review).
            self.note_partial_failure(f)
        return json.dumps({"dependencies": deps})

    def parse(self, raw: str) -> list[Finding]:
        data: Any = json.loads(raw)
        out: list[Finding] = []
        for dep in as_list(data.get("dependencies")) if isinstance(data, dict) else []:
            if not isinstance(dep, dict):
                continue
            pkg = str(dep.get("name") or "?")
            ver = str(dep.get("version") or "")
            for v in as_list(dep.get("vulns")):
                if not isinstance(v, dict):
                    continue
                vid = str(v.get("id") or "?")
                aliases = [a for a in as_list(v.get("aliases")) if isinstance(a, str)]
                cve = next((a for a in aliases if a.startswith("CVE-")), None)
                fixes = ", ".join(str(x) for x in as_list(v.get("fix_versions")))
                if cve:
                    url = f"https://nvd.nist.gov/vuln/detail/{cve}"
                elif vid.startswith("GHSA-"):
                    url = f"https://github.com/advisories/{vid}"
                else:
                    url = ""
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=f"Vulnerable dependency: {pkg} {ver}",
                        location=pkg,
                        message=f"{cve or vid}: {str(v.get('description') or '')[:160]}",
                        remediation=f"Upgrade to {fixes}" if fixes else "No fixed version yet",
                        url=url,
                        rule=cve or vid,
                        standards=["OWASP:A06", "OWASP-LLM:LLM03"],
                    )
                )
        return out
