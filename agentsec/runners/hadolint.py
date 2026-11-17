"""Hadolint — Dockerfile CIS/best-practice lint. Parses the JSON array."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding, normalize_severity
from agentsec.walk import DEFAULT_EXCLUDE_DIRS as _EXCLUDE

from .base import Runner, ScannerExecError, exec_capture_or_raise


class HadolintRunner(Runner):
    id = "hadolint"
    area = "Containers"
    binary = "hadolint"
    install_hint = "https://github.com/hadolint/hadolint#install"

    def applies(self, profile: StackProfile) -> bool:
        return profile.has_docker

    def _dockerfiles(self, root: Path) -> list[Path]:
        out: list[Path] = []
        for f in sorted(root.rglob("Dockerfile*")):
            if any(part in _EXCLUDE for part in f.parts) or not f.is_file():
                continue
            out.append(f)
        return out

    def invoke(self, root: Path, profile: StackProfile) -> str:  # noqa: ARG002
        merged: list[Any] = []
        dockerfiles = self._dockerfiles(root)
        failures: list[str] = []
        for df in dockerfiles:
            # Per-Dockerfile catch: one bad file must not erase the lints already
            # gathered from the others (#432 review). A total failure still raises
            # below so run() records the error instead of reporting clean.
            try:
                _, out, _ = exec_capture_or_raise(["hadolint", "--format", "json", str(df)], cwd=root)
            except ScannerExecError as e:
                failures.append(f"{df.name}: {e}")
                continue
            if not out:
                continue
            try:
                items = json.loads(out)
            except json.JSONDecodeError:
                continue
            if isinstance(items, list):
                merged.extend(items)
        if failures and len(failures) == len(dockerfiles):
            raise ScannerExecError("; ".join(failures))
        for f in failures:
            # See pip_audit: a partial failure must not read as a full scan (#432 review).
            self.note_partial_failure(f)
        return json.dumps(merged)

    def parse(self, raw: str) -> list[Finding]:
        data: Any = json.loads(raw)
        out: list[Finding] = []
        for r in data if isinstance(data, list) else []:
            if not isinstance(r, dict):
                continue
            file = str(r.get("file") or "Dockerfile")
            line = r.get("line")
            out.append(
                Finding(
                    check_id=self.id,
                    severity=normalize_severity(r.get("level")),
                    title=f"{r.get('code') or ''}: Dockerfile lint".strip(),
                    location=f"{file}:{line}" if line else file,
                    message=str(r.get("message") or ""),
                    url=f"https://github.com/hadolint/hadolint/wiki/{r.get('code')}" if r.get("code") else "",
                    rule=str(r.get("code") or "hadolint"),
                    standards=["CIS"],
                )
            )
        return out
