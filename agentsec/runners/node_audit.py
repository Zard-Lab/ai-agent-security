"""npm / pnpm audit — frontend dependency CVEs + registry-signature verification.

Two scans, both fed through one `parse()`:
- `audit --json` — dependency CVEs. Handles both shapes: npm v7 `.vulnerabilities`
  map and the pnpm / npm-v6 `.advisories` map (ported from the donor's parse_npm_audit).
- `audit signatures --json` (npm only) — verifies each installed package's registry
  signature against the maintainer key, catching registry-compromise / typosquat
  tarballs the CVE feed alone misses. Output shape `{"invalid": [...], "missing": [...]}`.

`invoke()` joins the two raw outputs with a record separator; `parse()` splits and
routes each chunk by its shape, so passing a single CVE blob still parses (back-compat).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity, normalize_severity

from .base import Runner, ScannerExecError, as_list, exec_capture_or_raise

# Joins the CVE-audit and signatures-audit JSON blobs in one invoke() return.
_SEP = "\n\x1e\n"


class NodeAuditRunner(Runner):
    id = "node-audit"
    area = "Dependencies"
    binary = "npm"
    install_hint = "npm / pnpm (ships with Node)"
    tier_required = 1  # `npm/pnpm audit` posts your dependency tree to the registry advisory API
    egress_dest = "npm registry"
    egress_sends = "your dependency tree"
    deterministic = False  # live: `npm audit` queries the registry advisory DB

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features

    def binary_name(self, profile: StackProfile) -> str:
        return "pnpm" if "pnpm" in profile.package_managers else "npm"

    def invoke(self, root: Path, profile: StackProfile) -> str:
        fe = root / profile.frontend_dir if profile.frontend_dir else root
        tool = self.binary_name(profile)
        _, cve, _ = exec_capture_or_raise([tool, "audit", "--json"], cwd=fe)
        parts = [cve or "{}"]
        # `audit signatures` is npm-only; pnpm has no equivalent subcommand.
        if tool == "npm":
            # Secondary check: a signatures launch failure must not erase the CVE
            # results already gathered above (#432 review); the primary audit call
            # still raises so a scanner that never ran is recorded, not "clean".
            try:
                _, sig, _ = exec_capture_or_raise([tool, "audit", "signatures", "--json"], cwd=fe)
            except ScannerExecError as e:
                # ...but it must not vanish silently either. This is the registry-compromise /
                # typosquat check; swallowing its failure left the run indistinguishable from
                # one where every signature verified (#432 review).
                self.note_partial_failure(f"npm audit signatures: {e}")
                sig = ""
            if sig:
                parts.append(sig)
        return _SEP.join(parts)

    def parse(self, raw: str) -> list[Finding]:
        out: list[Finding] = []
        for chunk in raw.split(_SEP):
            chunk = chunk.strip()
            if not chunk:
                continue
            try:
                data = json.loads(chunk)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            if "invalid" in data or "missing" in data:
                out.extend(self._parse_signatures(data))
            else:
                out.extend(self._parse_cve(data))
        return out

    def _parse_signatures(self, data: dict[str, Any]) -> list[Finding]:
        out: list[Finding] = []
        for entry in as_list(data.get("invalid")):
            if not isinstance(entry, dict):
                continue
            pkg = str(entry.get("name") or "?")
            ver = str(entry.get("version") or "")
            out.append(Finding(
                check_id=self.id, severity="high",
                title=f"Invalid package signature: {pkg}",
                location=f"{pkg}@{ver}" if ver else pkg,
                message="registry signature invalid — package may have been tampered with",
                remediation="Verify the package source and pin/rotate to a known-good version.",
                rule="node-audit/signature", standards=["OWASP:A08", "OWASP-LLM:LLM03"],
            ))
        for entry in as_list(data.get("missing")):
            if not isinstance(entry, dict):
                continue
            pkg = str(entry.get("name") or "?")
            ver = str(entry.get("version") or "")
            out.append(Finding(
                check_id=self.id, severity="medium",
                title=f"Missing package signature: {pkg}",
                location=f"{pkg}@{ver}" if ver else pkg,
                message="registry published no signature for this package — publisher unverifiable",
                remediation="Prefer registry-signed packages; review the supply-chain risk.",
                rule="node-audit/signature-missing", standards=["OWASP:A08", "OWASP-LLM:LLM03"],
            ))
        return out

    def _parse_cve(self, data: dict[str, Any]) -> list[Finding]:
        out: list[Finding] = []
        advisories = data.get("advisories")
        if isinstance(advisories, dict) and advisories:
            for adv in advisories.values():
                if not isinstance(adv, dict):
                    continue
                out.append(self._finding(
                    sev=normalize_severity(adv.get("severity")),
                    ident=str(adv.get("github_advisory_id") or adv.get("id") or "?"),
                    pkg=str(adv.get("module_name") or "?"),
                    title=str(adv.get("title") or ""),
                    fixed=str(adv.get("patched_versions") or ""),
                    url=str(adv.get("url") or ""),
                ))
            return out
        vulns = data.get("vulnerabilities")
        if isinstance(vulns, dict):
            for name, entry in vulns.items():
                if not isinstance(entry, dict):
                    continue
                via = as_list(entry.get("via"))
                adv = next((v for v in via if isinstance(v, dict)), None)
                # an npm-v7 via-advisory dict may lack "title" — str(None) rendered
                # "lodash: None" (#420), so fall back before stringifying
                title = str(adv.get("title") or "Vulnerable dependency") if adv else "Vulnerable dependency"
                url = str(adv.get("url")) if adv and adv.get("url") else ""
                fa = entry.get("fixAvailable")
                fixed = str(fa.get("version")) if isinstance(fa, dict) else ("available" if fa else "")
                out.append(self._finding(
                    sev=normalize_severity(entry.get("severity")),
                    ident=str(name), pkg=str(name), title=title, fixed=fixed, url=url,
                ))
        return out

    def _finding(self, sev: Severity, ident: str, pkg: str, title: str, fixed: str, url: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity=sev,
            title=f"Vulnerable npm dependency: {pkg}",
            location=pkg,
            message=f"{ident}: {title}"[:200],
            remediation=f"Upgrade to {fixed}" if fixed else "No fix available",
            url=url,
            rule=ident,
            standards=["OWASP:A06", "OWASP-LLM:LLM03"],
        )
