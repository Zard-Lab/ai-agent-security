"""OpenSSF Scorecard — repo supply-chain health signals.

Wraps the external `scorecard` binary (https://github.com/ossf/scorecard) in
**repo mode**: `scorecard --repo=github.com/<owner>/<repo>`, scoring *this repo's
own posture* — Branch-Protection, Maintained, Signed-Releases, Token-Permissions,
Dangerous-Workflow, Fuzzing, Vulnerabilities, and the rest — the supply-chain
*health* signals that a CVE scanner (pip-audit/node-audit/trivy) can't see: a
dep (or this repo) can be perfectly CVE-clean yet unmaintained, unsigned, and
one merge away from a takeover.

Repo mode needs the GitHub API, so this mirrors `trivy`: `tier_required = 1`
(disclosed-skipped at the default offline Tier 0) and `deterministic = False`
(scores drift as upstream repo metadata + the OSV DB change, so it is excluded
from `--deterministic`/baseline runs). It reads a `GITHUB_AUTH_TOKEN` /
`GITHUB_TOKEN` **from the user's environment** (agentsec never stores or emits
it — `child_env()` inherits it into the child). It **skips cleanly** (returns
nothing) when the binary is absent, the checkout has no GitHub remote, or no
token is present — an audit never fails because Scorecard couldn't run.

Scorecard's *static* checks (Pinned-Dependencies, Dangerous-Workflow,
Token-Permissions) are already covered statically by the `actions-sha-pin` /
`actions-script-injection` / `ci-secret-env-unscoped` guards; the value this
runner adds is the API-only health signals those guards can't reach.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import Runner, as_list, exec_capture_or_raise

# Scorecard's own published per-check risk levels. A failing check inherits its
# documented risk as the finding severity; anything unlisted is a conservative medium.
# Verified against https://github.com/ossf/scorecard/blob/main/docs/checks.md on
# 2026-07-12 — re-audit here if upstream re-levels a check (they have before).
# Only Dangerous-Workflow + Webhooks are Critical; every other tracked check is High.
_RISK: dict[str, Severity] = {
    "Dangerous-Workflow": "critical",
    "Webhooks": "critical",
    "Binary-Artifacts": "high",
    "Branch-Protection": "high",
    "Code-Review": "high",
    "Dependency-Update-Tool": "high",
    "Maintained": "high",
    "Signed-Releases": "high",
    "Token-Permissions": "high",
    "Vulnerabilities": "high",
}

# Emit a finding only for a genuine deficiency. Scorecard scores are 0..10; -1 means
# the check did not run (no data / not applicable) and 10 is a clean pass — neither is
# actionable, so we surface the band in between. A deliberate threshold: a score of 7+
# is treated as an acceptable pass (below Scorecard's own "8+ is good" framing on
# purpose, to keep the runner quiet on repos that are merely-good rather than perfect).
_FAIL_BELOW = 7

# github.com/<owner>/<repo> from an https or ssh remote url. Tolerates a trailing
# ".git", a trailing "/", and an optional ":<port>" (GitHub's ssh-over-HTTPS-port form,
# ssh://git@ssh.github.com:443/owner/repo.git). Does NOT resolve `[url] insteadOf`
# rewrites — a repo that only reaches GitHub via a rewrite reads as non-GitHub (fails
# safe: the runner skips). Pure text; a `git remote get-url` would resolve rewrites but
# breaks the stdlib-only, no-subprocess design.
_REMOTE = re.compile(
    r"github\.com(?::\d+)?[/:]+(?P<slug>[^/\s]+/[^/\s]+?)(?:\.git)?/?\s*$", re.IGNORECASE
)


def _github_slug(root: Path) -> str | None:
    """`owner/repo` parsed from the checkout's git `origin` remote, or None.

    Pure text over `.git/config` — no network, no `git` subprocess. Returns None
    for a non-GitHub remote, a missing config, or an unparseable url. Total.
    """
    try:
        text = (root / ".git" / "config").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    in_origin = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[remote "):
            in_origin = line == '[remote "origin"]'
            continue
        if line.startswith("["):
            in_origin = False
            continue
        if in_origin and line.lower().startswith("url"):
            m = _REMOTE.search(line)
            if m:
                return m.group("slug")
    return None


class ScorecardRunner(Runner):
    id = "scorecard"
    area = "Build pipeline"
    binary = "scorecard"
    install_hint = "https://github.com/ossf/scorecard#installation"
    tier_required = 1  # queries the GitHub API (repo metadata) + deps.dev/OSV
    egress_dest = "GitHub API (api.github.com) + deps.dev + OSV"
    egress_sends = "the repo identifier (owner/repo) + your GITHUB_AUTH_TOKEN; reads repo metadata, no source code"
    deterministic = False  # scores drift with upstream repo metadata + the OSV DB

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True  # real gating (GitHub remote + token) happens in invoke()

    def invoke(self, root: Path, profile: StackProfile) -> str:  # noqa: ARG002
        slug = _github_slug(root)
        if not slug:
            return ""  # not a GitHub checkout → nothing to score
        if not (os.environ.get("GITHUB_AUTH_TOKEN") or os.environ.get("GITHUB_TOKEN")):
            return ""  # scorecard --repo needs a token; skip rather than rate-limit-fail
        _, out, _ = exec_capture_or_raise(
            ["scorecard", f"--repo=github.com/{slug}", "--format=json", "--show-details"],
            cwd=root,
            timeout=600,
        )
        return out or ""

    def parse(self, raw: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            data: Any = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return []  # scorecard printed an error / non-JSON to stdout
        if not isinstance(data, dict):
            return []
        repo = data.get("repo")
        location = str(repo.get("name") if isinstance(repo, dict) else "") or "repo"
        out: list[Finding] = []
        for c in as_list(data.get("checks")):
            if not isinstance(c, dict):
                continue
            score = c.get("score")
            if not isinstance(score, (int, float)) or isinstance(score, bool):
                continue
            if score < 0 or score >= _FAIL_BELOW:
                continue  # -1 = not run; >= _FAIL_BELOW = acceptable pass
            name = str(c.get("name") or "check")
            doc = c.get("documentation")
            out.append(
                Finding(
                    check_id=self.id,
                    severity=_RISK.get(name, "medium"),
                    title=f"OpenSSF Scorecard: {name} scored {int(score)}/10",
                    location=location,
                    message=str(c.get("reason") or "")[:200],
                    remediation="Raise this Scorecard check's score; see its documentation.",
                    url=str(doc.get("url") or "") if isinstance(doc, dict) else "",
                    rule=f"scorecard/{name}",
                    standards=["OWASP:A06", "OWASP-LLM:LLM03"],
                )
            )
        return out
