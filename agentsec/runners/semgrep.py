"""Semgrep — pattern SAST. Parses `.results[]` (check_id / path / severity)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentsec.ai import SEMGREP_RULES_DIR
from agentsec.detect import StackProfile
from agentsec.findings import Finding, normalize_severity

from .base import (
    Runner,
    ScannerExecError,
    as_list,
    exec_capture_or_raise,
    scanner_reported_errors,
    semgrep_exclude_args,
)

# agentsec's custom LLM/RAG/agent rule pack — ships on-disk in the wheel, so it needs
# NO network and is genuinely Tier-0/offline (issue #421).
_LOCAL_CONFIGS = [str(SEMGREP_RULES_DIR)]
# OSS rulesets by Semgrep Registry shorthand. `--config p/...` DOWNLOADS these from
# semgrep.dev on every run (telemetry suppression does not stop the rules fetch), so
# they are a Tier-1 advisory fetch — added only at network tier >= 1 (issue #421).
_REGISTRY_CONFIGS = ["p/python", "p/owasp-top-ten", "p/secrets"]


class SemgrepRunner(Runner):
    id = "semgrep"
    area = "Code safety"
    binary = "semgrep"
    install_hint = "pipx install semgrep"

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def coverage_note(self, profile: StackProfile) -> str | None:
        """Tier 0 runs the local pack ONLY — disclose the rules that are NOT loaded (#434).

        #421 correctly moved the registry packs to tier 1 (they are a network fetch, so
        running them at the "offline" default was dishonest about egress). But the flip
        side is a real detection drop at the DEFAULT tier — `p/python` + `p/owasp-top-ten`
        + `p/secrets` are hundreds of rules versus this pack's handful — and nothing in
        the report said so. Naming the packs (not just "reduced") is the point: the reader
        can look up what they cover and decide whether tier 1 is warranted."""
        if profile.network_tier >= 1:
            return None
        return (
            "running the local LLM/agent rule pack ONLY. The OSS registry packs "
            f"({', '.join(_REGISTRY_CONFIGS)}) are a network fetch, so they need "
            "`--network tier1`; general Python/OWASP/secrets patterns are NOT covered "
            "at this tier"
        )

    def invoke(self, root: Path, profile: StackProfile) -> str:
        targets = [str(p) for p in profile.python_paths()] or [str(root)]
        # Tier 0 (offline default): the pinned on-disk pack only — no network. The remote
        # registry packs join at tier >= 1 (a disclosed advisory fetch), so the Tier-0
        # "offline" promise actually holds and a deterministic/baseline run stays hermetic (#421).
        configs = list(_LOCAL_CONFIGS)
        if profile.network_tier >= 1:
            configs += _REGISTRY_CONFIGS
        cfg: list[str] = []
        for c in configs:
            cfg += ["--config", c]
        rc, out, err = exec_capture_or_raise(
            # --disable-version-check + --metrics=off suppress the version ping + usage
            # metrics. They do NOT stop a registry `--config` fetch — that is why the
            # registry packs are tier-gated above, not passed unconditionally.
            # `--exclude` keeps the walk out of vendored/generated trees. semgrep skips these via
            # its built-in `.semgrepignore` defaults — but a repo shipping its OWN `.semgrepignore`
            # REPLACES those defaults and silently re-exposes `.venv`; the explicit excludes restore
            # the `DEFAULT_EXCLUDE_DIRS` floor the guards enforce (#860). NB: the form is the bare
            # dir name, NOT bandit's `*/name/*` glob — see `semgrep_exclude_args`.
            ["semgrep", "--json", "--quiet", "--error", "--disable-version-check", "--metrics=off",
             *semgrep_exclude_args(), *cfg, *targets],
            cwd=root,
        )
        # semgrep exit codes: 0 = clean, 1 = findings (via --error), >= 2 = a fatal error
        # (e.g. an unreachable/invalid --config). Surface that as a runner error rather than
        # letting the `out or '{...}'` fallback mask a failed run as "ran, clean" — the rc >= 2
        # sibling of the rc == -1 launch-failure path exec_capture_or_raise handles (#421).
        if rc >= 2:
            # Always include rc — it distinguishes error classes in CI logs (e.g. 2 = general
            # error / unreachable registry, 7 = config-resolution failure) when err is terse.
            raise ScannerExecError(f"semgrep exited {rc}: {err}" if err else f"semgrep exited {rc}")
        return out or '{"results": []}'

    def parse(self, raw: str) -> list[Finding]:
        data: Any = json.loads(raw)
        out: list[Finding] = []
        for r in as_list(data.get("results")) if isinstance(data, dict) else []:
            if not isinstance(r, dict):
                continue
            extra = r.get("extra")
            if not isinstance(extra, dict):
                extra = {}
            check_id = str(r.get("check_id") or "?")
            start = r.get("start")
            if not isinstance(start, dict):
                start = {}
            line = start.get("line")
            path = str(r.get("path") or "?")
            loc = f"{path}:{line}" if line is not None else path
            # The custom pack is loaded by absolute path, so semgrep prefixes its
            # check_id with the on-disk rules-dir components — machine-specific. Our
            # rule ids are unique (`agentsec-*`), so reduce them to the bare id for a
            # portable `rule`. OSS registry ids (`python.lang.…`) are already portable.
            leaf = check_id.rsplit(".", 1)[-1]
            rule = leaf if leaf.startswith("agentsec-") else check_id
            out.append(
                Finding(
                    check_id=self.id,
                    severity=normalize_severity(str(extra.get("severity") or "")),
                    title=leaf,
                    location=loc,
                    message=str(extra.get("message") or "")[:200],
                    rule=rule,
                    standards=["OWASP:A03"],
                )
            )
        # The scanner's OWN error array — files it could not parse, rules it could not
        # load. Dropping it made a partial scan read as a full one (#432 review).
        out.extend(scanner_reported_errors(self.id, data))
        return out
