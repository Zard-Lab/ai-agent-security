"""react-doctor — deterministic React codebase scanner.

react-doctor runs many rules across categories (Security, Performance, Architecture,
Accessibility, Dead Code, …). Its **Security** category catches XSS vectors in JSX,
unsafe `dangerouslySetInnerHTML`, and hardcoded secrets/API-keys — so it is a real
(partial) security scanner, not just a quality tool. The 0-100 "health score" is
only a roll-up; the per-rule diagnostics are the substance, so this runner consumes
the structured `--json` output and maps **security-category** diagnostics to real
severities (error→high, warning→medium) while every other category is reported at
`info` (visible, but won't trip `--fail-on high`).

Pinned to **0.5.6** (the version vetted + in use by the flagship). Its `--json` report
is `schemaVersion: 1`: a flat top-level `diagnostics[]` (each with `rule`/`category`/
`severity`/`filePath`/`line`/`message`/`help`), plus `summary.{errorCount,warningCount}`
and `projects[].score.score`. (The pre-0.3 engine nested diagnostics under
`projects[].diagnostics[]`; 0.5.x flattened them when it moved onto an oxlint engine.)

Invoked as `react-doctor . --json --json-compact --no-telemetry -y`:
- `--json` / `--json-compact`  one compact structured report on stdout.
- `--no-telemetry`             0.5.x bundles a Sentry client; a security tool must not
  phone home with scan data, so telemetry is disabled (this replaces the old `--offline`,
  which 0.5.x removed).

Network note (two distinct egress channels; both disabled by this runner — verified against
0.5.6/0.5.8 source):

1. **Score API** — `POST https://www.react.doctor/api/score`. This is the larger, *undocumented*
   egress: it sends your GitHub owner/repo slug, the commit SHA, the default branch, project
   metadata (framework, reactVersion, sourceFileCount, an ephemeral per-run UUID), CI metadata,
   and **per-finding diagnostics** — each finding's rule/severity/title/message and **line/column
   locations** (the top-level `filePath` is stripped but `relatedLocations[]` keep relative paths,
   so secondary paths leak). It sends NO source/file contents/manifest. The README's "rule names
   and counts only" claim does not cover it. `--no-score` (alias `--no-telemetry`, both in `_FLAGS`)
   cleanly blocks it (`shouldComputeScore: !options.noScore` → never calls fetch); it also disables
   Sentry + a local gh-permission lookup. agentsec keys off the diagnostics and discards the 0-100
   score, so this is kept OFF at every tier.

2. **Socket supply-chain** — the `low-supply-chain-score` rule (Security category) queries
   `https://firewall-api.socket.dev/purl` with each direct dependency's **PURL** (name@version —
   public dependency info, not source). A *separate vendor*, unaffected by `--no-score`; it has no
   CLI flag / env var, gated only by `supplyChain.enabled: false` in a config file in the scanned
   dir (no `--config` option). `invoke()` disables it for the run (writing a temp config when the
   repo has none); the signal overlaps the deterministic `node-audit`/`js-supply-chain` checks.

Net: react-doctor contributes its **local** Security/XSS/secrets diagnostics with **zero scan-data
egress** at any tier (RFC #135 / Phase-2 "never leak" decision).

Invocation strategy mirrors the flagship: prefer the **installed** binary
(`<frontend>/node_modules/.bin/react-doctor`, e.g. a pinned devDependency) — a fresh
`pnpm dlx react-doctor@<ver>` resolves the dep tree anew and pnpm 11 blocks it as
`ERR_PNPM_TRUST_DOWNGRADE` (a package-takeover defense). When it isn't installed, fall
back to `npx -y react-doctor@<ver>` (npm's resolver doesn't enforce that trust policy),
so the runner still works ad-hoc and degrades to a skip when the registry is unreachable.

Its Security findings overlap agentsec's `frontend-xss` guard and `gitleaks`/`trivy`
(secrets); they co-report (cross-source dedup is a follow-up).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from agentsec import pins
from agentsec.detect import StackProfile
from agentsec.findings import Finding, normalize_severity

from .base import Runner, as_list, exec_capture_or_raise

# Single source of truth: agentsec/pins.py (shared with the react-doctor CI component).
REACT_DOCTOR_VERSION = pins.version("react-doctor")

# Rule/message keywords that indicate a hardcoded-secret finding (→ OWASP:A07);
# anything else in the Security category is treated as XSS/injection (→ OWASP:A03).
_SECRET_HINTS = ("secret", "api-key", "apikey", "api_key", "token", "credential", "password")

_FLAGS = [".", "--json", "--json-compact", "--no-telemetry", "-y"]


# react-doctor config filenames we recognize (so we don't clobber a user's existing config).
_RD_CONFIG_NAMES = (
    "react-doctor.config.json", "react-doctor.config.js", "react-doctor.json",
    ".react-doctorrc", ".react-doctorrc.json",
)


class ReactDoctorRunner(Runner):
    id = "react-doctor"
    area = "Web & browser"
    binary = "npx"  # node ships npx; the installed binary is preferred when present
    install_hint = f"npx -y react-doctor@{REACT_DOCTOR_VERSION} (needs network at audit time)"
    # Tier 1 only because `npx` fetches the tool (a public package — sends nothing about your code).
    # react-doctor sends NO scan data: `--no-telemetry` blocks the Score API egress, and this runner
    # disables the Socket supply-chain PURL lookup for the run (see invoke()). So it is local-for-your-
    # -data at every tier; it is skipped at Tier 0 only to avoid the npx registry fetch.
    tier_required = 1
    egress_dest = "npm (npx tool fetch)"
    egress_sends = "nothing (Score API + supply-chain lookup disabled; npx fetches the tool)"
    deterministic = False  # live: fetches react-doctor + Socket data at audit time

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features

    def invoke(self, root: Path, profile: StackProfile) -> str:
        fe = root / profile.frontend_dir if profile.frontend_dir else root
        local = fe / "node_modules" / ".bin" / "react-doctor"
        if local.exists():
            args = [str(local), *_FLAGS]  # provenance-clean installed tree (flagship style)
        else:
            args = ["npx", "-y", f"react-doctor@{REACT_DOCTOR_VERSION}", *_FLAGS]
        # Disable the Socket supply-chain PURL lookup. react-doctor (0.5.6/0.5.8, verified) reads a
        # FIXED-name config (`react-doctor.config.json`, JSON5) relative to the SCANNED dir — NOT the
        # CWD, and there is no `--config` flag. So we must place `supplyChain.enabled:false` there. If
        # the repo already has a react-doctor config we respect it (the repo owns the behavior).
        #
        # Concurrency: the fixed name + scanned-dir resolution means two audits on the same frontend
        # dir share one config path. We create it ATOMICALLY (O_EXCL): only the run that wins the
        # create "owns" it and removes it after; a racing run gets FileExistsError, treats it as
        # present, and does NOT remove it — eliminating the double-create / double-remove race. A small
        # residual window remains (owner removes while a racer is mid-load → racer falls back to the
        # default and could egress); it needs two concurrent audits on the *same* dir (rare). The clean
        # fix is upstream: react-doctor exposing `--config <path>` or `--no-supply-chain` (requested).
        cfg_path = fe / "react-doctor.config.json"
        owned = False
        if not any((fe / n).exists() for n in _RD_CONFIG_NAMES):  # respect an existing config
            created = False
            try:
                fd = os.open(cfg_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                created = True
                try:
                    os.write(fd, b'{"supplyChain": {"enabled": false}}\n')
                finally:
                    os.close(fd)
                owned = True
            except FileExistsError:
                owned = False  # a concurrent run created it first — respect it, never remove it
            except OSError:
                # best-effort: if the write failed, remove the empty file we created (else future runs
                # would see the orphan as a user config and silently stop disabling supply-chain egress),
                # then run anyway — never crash the audit.
                owned = False
                if created:
                    cfg_path.unlink(missing_ok=True)
        try:
            _, out, _ = exec_capture_or_raise(args, cwd=fe, timeout=600)
        finally:
            if owned:
                cfg_path.unlink(missing_ok=True)
        return out or "{}"

    def parse(self, raw: str) -> list[Finding]:
        # parse() must be total (never raise): react-doctor can crash and write a non-JSON but
        # truthy string to stdout (e.g. "Fatal error: ..."), which `invoke()`'s `out or "{}"` does
        # not substitute. json.loads would then raise (#255) — treat unparseable output as "nothing".
        try:
            data: Any = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, dict):
            return []
        if data.get("ok") is False:
            return [Finding(
                check_id=self.id, severity="info",
                title="react-doctor scan reported an error (ok: false)",
                message=str(data.get("error") or "")[:200], rule="react-doctor/scan-error",
            )]
        out: list[Finding] = []
        # 0.5.x: a flat top-level `diagnostics[]` (the pre-0.3 nesting under
        # `projects[].diagnostics[]` is gone). A failed/empty run yields no diagnostics.
        for d in as_list(data.get("diagnostics")):
            if not isinstance(d, dict):
                continue
            rule = str(d.get("rule") or "")
            category = str(d.get("category") or "")
            rd_sev = str(d.get("severity") or "").lower()
            file_path = str(d.get("filePath") or "?")
            line = d.get("line")
            loc = f"{file_path}:{line}" if isinstance(line, int) and line > 0 else file_path
            is_security = "security" in category.lower()
            if is_security:
                sev = "high" if rd_sev == "error" else "medium"
                blob = f"{rule} {d.get('message') or ''}".lower()
                standards = ["OWASP:A07"] if any(h in blob for h in _SECRET_HINTS) else ["OWASP:A03"]
            else:
                sev = "info"
                standards = []
            out.append(Finding(
                check_id=self.id,
                severity=normalize_severity(sev),
                title=f"{rule} ({category})" if category else (rule or "react-doctor"),
                location=loc,
                message=str(d.get("message") or "")[:200],
                remediation=str(d.get("help") or "")[:200],
                rule=f"react-doctor/{rule}" if rule else "react-doctor",
                standards=standards,
            ))
        return out
