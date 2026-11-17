"""Gitleaks — secret scanning. Parses the JSON report array (PII excluded)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CAPTURE_CAP, Runner, exec_capture_or_raise


class GitleaksRunner(Runner):
    id = "gitleaks"
    area = "Secrets"
    binary = "gitleaks"
    install_hint = "https://github.com/gitleaks/gitleaks/releases"

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True  # secrets are universal

    def invoke(self, root: Path, profile: StackProfile) -> str:  # noqa: ARG002
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            report = tf.name
        # The exec call sits inside the try so a ScannerExecError (launch failure /
        # timeout) still unlinks the report tempfile created above (#432 review).
        try:
            exec_capture_or_raise(
                ["gitleaks", "detect", "--source", str(root), "--no-banner", "--redact",
                 "-f", "json", "-r", report, "--exit-code", "0"],
                cwd=root,
            )
            # Cap the report read like exec_capture caps stdout: a hostile repo can
            # make the report arbitrarily large; a truncated report fails json.loads
            # and degrades to the "could not parse" info finding (#420).
            with open(report, encoding="utf-8", errors="replace") as fh:
                return fh.read(CAPTURE_CAP) or "[]"
        finally:
            Path(report).unlink(missing_ok=True)

    def parse(self, raw: str) -> list[Finding]:
        data: Any = json.loads(raw)
        out: list[Finding] = []
        for r in data if isinstance(data, list) else []:
            if not isinstance(r, dict):
                continue
            file = str(r.get("File") or "?")
            line = r.get("StartLine")
            loc = f"{file}:{line}" if line is not None else file
            commit = str(r.get("Commit") or "")
            if commit:
                loc = f"{loc} @ {commit[:8]}"
            # Deliberately exclude Author/Email/Message (PII).
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=f"Potential secret: {r.get('RuleID') or 'unknown'}",
                    location=loc,
                    message=str(r.get("Description") or "")[:160],
                    remediation="Rotate the secret and remove it from history (or allowlist if intentional).",
                    url=str(r.get("Link") or ""),
                    rule=str(r.get("RuleID") or "gitleaks"),
                    standards=["OWASP:A07", "OWASP-LLM:LLM03"],
                )
            )
        return out
