"""Guard: pin third-party GitHub Actions to a full commit SHA (checklist §1).

A workflow step like `uses: actions/checkout@v4` trusts a *mutable* tag — whoever
controls that tag (or a compromised upstream) can swap in new code that runs with
your CI secrets. Pinning to a 40-char commit SHA freezes the exact code. This is a
supply-chain control (the npm/GHA tag-injection class, e.g. the trivy-action/tag
forcing incident).

Fires HIGH on any `uses:` reference under `.github/workflows/` whose ref is not a
40-hex commit SHA. Local actions (`./...`) and `docker://...@sha256` digests are
not flagged. Suppress an intentional exception (e.g. a first-party action you own)
with the inline pragma:

    uses: my-org/my-action@v1  # security: allow-unpinned-action
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, pragma_line_set, read, rel

# `uses: <ref>@<something>` — capture the whole `owner/repo@ref` token.
_USES = re.compile(r"""\buses\s*:\s*["']?(?P<action>[^"'\s#]+@[^"'\s#]+)""")
_SHA40 = re.compile(r"[0-9a-fA-F]{40}")
_PRAGMA = re.compile(r"#\s*security:\s*allow-unpinned-action")


class ActionsShaPinGuard(Guard):
    id = "actions-sha-pin"
    title = "GitHub Actions pinned to a commit SHA"
    area = "Build pipeline"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted across the canary's shared
    # `.github/workflows/ci.yml` and `.github/workflows/deploy.yml`, each of which several guards trip at
    # once, so those files stay in `canary.py`'s base owned by no guard. The ownership rule this follows
    # is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(expects=frozenset({"actions-sha-pin/unpinned-action"}))

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        # Repo-hygiene check — a `.github/workflows/` dir can exist in any stack.
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        workflows = root / ".github" / "workflows"
        if not workflows.is_dir():
            return []
        out: list[Finding] = []
        # Top level only: GitHub never executes workflow files in subdirectories (`backup/`,
        # `disabled/`, `_archive/`), so a mutable-tag `uses:` there is not exploitable — scanning
        # them only manufactures FPs (round-2 §C.1). Not recursive.
        for f in sorted(p for p in workflows.iterdir() if p.is_file() and p.suffix in (".yml", ".yaml")):
            violations: list[tuple[int, str]] = []  # (line_num, action_ref)
            text = read(f)
            # `hash`, not `yaml`: the yaml view reads a block scalar as content, so it would void a
            # `#` opt-out on a `uses:` line inside a `run: |` script, a line `_USES` still flags.
            pragma_lines = pragma_line_set(_PRAGMA, text, dialect="hash")
            for i, line in enumerate(text.splitlines(), start=1):
                m = _USES.search(line)
                if not m:
                    continue
                action = m.group("action")
                if action.startswith("./") or action.startswith("docker://"):
                    continue  # local action or pinned docker digest — out of scope
                ref = action.rsplit("@", 1)[1]
                if _SHA40.fullmatch(ref):
                    continue  # already pinned to a full commit SHA
                if i in pragma_lines:
                    continue
                violations.append((i, action))
            if not violations:
                continue
            n = len(violations)
            s = "s" if n != 1 else ""
            # Keep each unpinned step's LINE in the bundled message — per-file grouping must not
            # cost the user the precise location of every step beyond the first.
            action_list = ", ".join(f"`{a}` (L{ln})" for ln, a in violations)
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=f"GitHub Actions not pinned to commit SHA{s} ({n} step{s})",
                    location=f"{rel(root, f)}:{violations[0][0]}",
                    message=(
                        f"{n} action{s} pin{'s' if n == 1 else ''} a mutable tag/branch, not a commit SHA: "
                        f"{action_list}. "
                        "Whoever controls those refs can swap in new code that runs with "
                        "your CI secrets (supply-chain / tag-injection risk)."
                    ),
                    remediation=(
                        "Pin each to a full 40-char commit SHA: "
                        "`uses: owner/repo@<sha>  # v4`. "
                        "For a first-party action you control, suppress with "
                        "`# security: allow-unpinned-action`."
                    ),
                    rule="actions-sha-pin/unpinned-action",
                    standards=["OWASP:A08", "OWASP-LLM:LLM03"],
                )
            )
        return out
