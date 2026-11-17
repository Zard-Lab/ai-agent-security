"""Bandit — Python SAST. Parses `.results[]` (issue_severity / test_id / loc)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding, normalize_severity

from .base import Runner, as_list, bandit_exclude_arg, exec_capture_or_raise, scanner_reported_errors


def _bandit_config(root: Path) -> str | None:
    """A project bandit config to pass via `-c`, if present.

    Looks for a dedicated config (`.bandit`, `bandit.yaml`, `.bandit.yaml`) or a
    `[tool.bandit]` table in `pyproject.toml`. Returns the path, or None to use
    bandit's defaults."""
    for name in (".bandit", "bandit.yaml", ".bandit.yaml"):
        p = root / name
        if p.is_file():
            return str(p)
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            if "[tool.bandit]" in pyproject.read_text(encoding="utf-8", errors="ignore"):
                return str(pyproject)
        except OSError:
            pass
    return None


class BanditRunner(Runner):
    id = "bandit"
    area = "Code safety"
    binary = "bandit"
    install_hint = "pipx install bandit"

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def invoke(self, root: Path, profile: StackProfile) -> str:
        targets = [str(p) for p in profile.python_paths()]
        if not targets:
            return '{"results": []}'
        # `-x` keeps the recursive walk out of vendored/generated trees (`.venv`, `site-packages`,
        # `node_modules`, …). Without it bandit recurses into a gitignored `.venv` under the scan
        # target and reports third-party code under the user's repo path — 664 spurious findings,
        # 3 spurious HIGHs, in the field report (#860). Same `DEFAULT_EXCLUDE_DIRS` policy the guards
        # and the file-enumerating runners (hadolint/pip_audit) honor.
        cmd = ["bandit", "-r", "-f", "json", "-q", "-x", bandit_exclude_arg()]
        # Honor a project bandit config when present so the user controls severity /
        # confidence (e.g. silence the B101-assert / B404-subprocess lows) without us
        # imposing a default filter that would silently drop findings.
        cfg = _bandit_config(root)
        if cfg:
            cmd += ["-c", cfg]
        cmd += targets
        # bandit exits non-zero when it finds issues; stdout still carries JSON.
        _, out, _ = exec_capture_or_raise(cmd, cwd=root)
        return out or '{"results": []}'

    def parse(self, raw: str) -> list[Finding]:
        data: Any = json.loads(raw)
        out: list[Finding] = []
        for item in as_list(data.get("results")) if isinstance(data, dict) else []:
            if not isinstance(item, dict):
                continue
            fn = str(item.get("filename") or "")
            line = item.get("line_number")
            loc = f"{fn}:{line}" if line else fn
            out.append(
                Finding(
                    check_id=self.id,
                    severity=normalize_severity(item.get("issue_severity")),
                    title=str(item.get("test_name") or item.get("test_id") or "Bandit finding"),
                    location=loc,
                    message=str(item.get("issue_text") or ""),
                    url=str(item.get("more_info") or ""),
                    rule=str(item.get("test_id") or "bandit"),
                    standards=["OWASP:A03"],
                )
            )
        # The scanner's OWN error array — files it could not parse, rules it could not
        # load. Dropping it made a partial scan read as a full one (#432 review).
        out.extend(scanner_reported_errors(self.id, data))
        return out
