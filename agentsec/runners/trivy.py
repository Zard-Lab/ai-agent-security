"""Trivy — filesystem vuln + secret scan, plus (mechanism A) a remote registry scan of
any Go base image `detect.py::foreign_artifacts` found. Parses `.Results[].Vulnerabilities/Secrets`.

**Mechanism A history, condensed** (see `docs/knowledge/rfc-go-binary-buildinfo-inspection.md` for
the full record): `foreign_artifacts` (PR #601) names Go running as a Docker base image — the
`go.mod`/`go.sum` census (`go-osv-hygiene`) can never see it, since there's no Go source in the
repo at all. The RFC that scoped a bespoke `go version -m` buildinfo pipeline for this was made
unnecessary once live-verified: `trivy image --image-src remote <ref>` already reads a compiled Go
binary's embedded buildinfo (linked-stdlib version, full resolved module graph) straight from a
container registry's read-only API — no `docker pull`/`run`/`cp`, and this runner already exists,
already at `tier_required = 1`. The wiring below is that: for each `foreign_artifacts` hit, one
additional `trivy image` invocation, merged into the same `Results` the `fs` scan already produces.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding, normalize_severity

from .base import Runner, ScannerExecError, as_list, exec_capture_or_raise, trivy_skip_dirs_args

# `foreign_artifacts` entries are a prose string with the pullable image ref backtick-quoted —
# `f"{lang} (Docker base image \`{ref}\`)"` (see `detect.py`). Extracted here rather than
# refactoring the field to structured data, which would touch 14+ existing `detect.py` tests and
# 2 `cli.py` display call sites for a purely internal consumer of the one piece already embedded.
_IMAGE_REF_FROM_ARTIFACT = re.compile(r"`([^`]+)`")


# Marker key injected onto every image-scan Result before merging into the filesystem scan's own
# `Results` list (see `invoke()`), so `parse()` can tell the two apart without re-deriving it from
# `Target` alone. Why the distinction matters (the RFC's own "still genuinely open" question,
# resolved here rather than left ambiguous): a CVE in a THIRD-PARTY base image has a fundamentally
# different remediation shape than one in the user's own declared dependency — "Upgrade to X" (the
# fs-scan finding's own remediation) is actively misleading when the user cannot `pip install`/
# `npm install` inside someone else's prebuilt image. `_agentsec_image_scan` is not a real trivy
# field (namespaced so it can never collide with one) — it's agentsec's OWN addition, added after
# trivy's raw output is already parsed and before `invoke()` re-serializes the merged `Results` for
# `parse()` to read, so it round-trips through that one `json.dumps()`/`json.loads()` pair like any
# other key, a plain bool value, nothing fragile about it.
_IMAGE_SCAN_MARKER = "_agentsec_image_scan"


def _image_refs(profile: StackProfile) -> list[str]:
    """The distinct, pullable image refs named in `profile.foreign_artifacts`, sorted for a
    deterministic invocation order (matters for `note_partial_failure` message ordering, not for
    correctness — trivy itself doesn't care what order images are scanned in)."""
    refs: set[str] = set()
    for artifact in profile.foreign_artifacts:
        m = _IMAGE_REF_FROM_ARTIFACT.search(artifact)
        if m and not m.group(1).startswith("-"):
            # A ref starting with `-` would be read as a flag by trivy's own argument parser
            # rather than an image reference — a crafted `FROM -x/caddy:latest` (or a
            # `--cache-dir=...` value whose last path segment happens to match a curated base
            # image name) must not be allowed to steer the auditor's own tool invocation (#684
            # review, Medium 3). Rejected here, independent of the `--` end-of-options marker
            # below, since this check doesn't depend on trivy's own CLI parsing to hold.
            refs.add(m.group(1))
    return sorted(refs)


class TrivyRunner(Runner):
    id = "trivy"
    area = "Dependencies"
    # Per-RULE surfacing, NOT a flat `surfacing = True`: this one runner emits both kinds under
    # `check_id="trivy"`. A CVE inside a third-party base image (`trivy-image/<CVE>`) is a
    # judgment call with no direct code fix, but a bare `<CVE>` from the fs scan is a proven,
    # fixable finding — flagging the whole runner would add `+4` to every fs-scan CVE's
    # `priority_rank` and demote real work out of "Fix these first" (see `parse()` below).
    surfacing_rule_prefixes = ("trivy-image/",)
    binary = "trivy"
    install_hint = "https://trivy.dev/latest/getting-started/installation/"
    tier_required = 1  # downloads the vuln DB; when foreign_artifacts hits exist, also pulls image manifests
    egress_dest = "trivy DB mirror + (when Go base-image evidence is present) the image's own container registry"
    egress_sends = (
        "nothing to the DB mirror (downloads the vuln DB); to the registry, only the base-image "
        "name+tag already named in the report — no source code, no local files"
    )
    deterministic = False  # live: downloads + queries the trivy CVE DB

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def invoke(self, root: Path, profile: StackProfile) -> str:
        # Suppress Trivy's own egress (version-check ping + telemetry) via env vars,
        # not CLI flags: an older Trivy ignores an unknown TRIVY_* var, whereas an
        # unknown flag would make it exit non-zero and drop all output. The vuln-DB
        # fetch remains — it's inherent to CVE scanning and is the user's opt-in.
        env = {"TRIVY_SKIP_VERSION_CHECK": "true", "TRIVY_DISABLE_TELEMETRY": "true"}
        # `--skip-dirs` keeps the recursive `fs` walk out of vendored/generated trees. `secret` +
        # `misconfig` run over the whole walk, so without this trivy anchors findings INSIDE a
        # gitignored `.venv` under the scan root — the same mis-attribution #860 fixes for bandit.
        # The lock/requirements files that carry the authoritative dependency signal live in the
        # user's tree and are NOT skipped (measured), so `vuln` coverage of the real deps is intact.
        _, fs_out, _ = exec_capture_or_raise(
            ["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln,secret,misconfig",
             *trivy_skip_dirs_args(), str(root)],
            cwd=root,
            timeout=600,
            env_extra=env,
        )
        try:
            fs_data: Any = json.loads(fs_out) if fs_out else {}
        except json.JSONDecodeError as e:
            # Mirror the per-image branch below: a malformed payload is a disclosed partial
            # failure, not a silent empty/clean result — a crashed, disk-full, or OOM-killed
            # `trivy fs` that still exits 0 must not read as a clean zero-finding scan (#684 review).
            self.note_partial_failure(f"fs scan: unparseable trivy output ({e})")
            fs_data = {}
        results: list[Any] = list(as_list(fs_data.get("Results"))) if isinstance(fs_data, dict) else []

        # Mechanism A: one additional registry-only scan per distinct Go base image. Per-image
        # try/except (mirrors hadolint.py's per-Dockerfile pattern) — one unreachable/renamed
        # image must not erase the filesystem scan's own results, or the vuln-count-per-image
        # failure of the runner it's piggybacking on. A total image-scan failure here is still a
        # DEGRADATION, not a crash: `run()`'s own try/except around `invoke()` only ever sees the
        # `fs` call directly, so nothing above this loop can turn an image-scan failure into a
        # lost `fs` result.
        for ref in _image_refs(profile):
            try:
                _, img_out, _ = exec_capture_or_raise(
                    # `--` marks the end of options so `ref` is never read as a flag by trivy's
                    # own Cobra-based parser, even if `_image_refs()`'s own `-`-prefix rejection
                    # were ever bypassed (#684 review, Medium 3 — belt-and-braces).
                    ["trivy", "image", "--image-src", "remote", "--quiet", "--format", "json", "--", ref],
                    cwd=root,
                    timeout=300,
                    env_extra=env,
                )
            except ScannerExecError as e:
                self.note_partial_failure(f"{ref}: {e}")
                continue
            try:
                img_data: Any = json.loads(img_out) if img_out else {}
            except json.JSONDecodeError as e:
                self.note_partial_failure(f"{ref}: unparseable trivy output ({e})")
                continue
            if isinstance(img_data, dict):
                # Tag each image-scan Result so `parse()` can give its findings a different
                # remediation shape (see the docstring on `_IMAGE_SCAN_MARKER` for why this
                # can't be "just severity as normal") without a second scan pass or a fragile
                # heuristic re-derivation of "is this Target an image ref" from the string alone.
                for res in as_list(img_data.get("Results")):
                    if isinstance(res, dict):
                        res[_IMAGE_SCAN_MARKER] = True
                results.extend(as_list(img_data.get("Results")))

        return json.dumps({"Results": results})

    def parse(self, raw: str) -> list[Finding]:
        data: Any = json.loads(raw)
        out: list[Finding] = []
        for res in as_list(data.get("Results")) if isinstance(data, dict) else []:
            if not isinstance(res, dict):
                continue
            target = str(res.get("Target") or "")
            is_image_scan = bool(res.get(_IMAGE_SCAN_MARKER))
            for v in as_list(res.get("Vulnerabilities")):
                if not isinstance(v, dict):
                    continue
                vid = str(v.get("VulnerabilityID") or "?")
                if is_image_scan:
                    # A CVE inside a THIRD-PARTY base image: the user cannot upgrade the package
                    # directly (there's no `pip install`/`npm install` into someone else's
                    # prebuilt image), so "Upgrade to X" — correct for the fs scan above — is
                    # actively misleading here. `rule` is prefixed `trivy-image/` (mirrors the
                    # `check_id/rule-suffix` shape the rest of the codebase uses, not the bare
                    # CVE id the fs-scan path emits) so it's both distinguishable in a report and
                    # picked up by `_REVIEW_RULE_PREFIXES` (findings.py) — this is a surfacing
                    # signal for human judgment (bump the tag? rebuild from source? accept it as
                    # a third-party risk?), not an assert-a-bug-fix-this-line finding the way the
                    # fs-scan ones are.
                    remediation = (
                        "This CVE is inside a third-party base image, not your own code — bump "
                        f"the image tag to a version with a newer {v.get('PkgName') or 'package'}, "
                        "rebuild the image from source with a patched dependency, or accept the "
                        "risk explicitly. `Upgrade to X` does not apply directly."
                    )
                    rule = f"trivy-image/{vid}"
                else:
                    remediation = f"Upgrade to {v.get('FixedVersion')}" if v.get("FixedVersion") else ""
                    rule = vid
                out.append(
                    Finding(
                        check_id=self.id,
                        severity=normalize_severity(v.get("Severity")),
                        title=f"{vid}: {v.get('PkgName') or ''} {v.get('InstalledVersion') or ''}".strip(),
                        location=target,
                        message=str(v.get("Title") or v.get("Description") or "")[:160],
                        remediation=remediation,
                        url=str(v.get("PrimaryURL") or ""),
                        rule=rule,
                        standards=["OWASP:A06", "OWASP-LLM:LLM03"],
                    )
                )
            for s in as_list(res.get("Secrets")):
                if not isinstance(s, dict):
                    continue
                line = s.get("StartLine")
                out.append(
                    Finding(
                        check_id=self.id,
                        severity=normalize_severity(s.get("Severity") or "high"),
                        title=f"Secret in layer: {s.get('RuleID') or 'unknown'}",
                        location=f"{target}:{line}" if line else target,
                        message=str(s.get("Title") or "")[:160],
                        rule=str(s.get("RuleID") or "trivy-secret"),
                        standards=["OWASP:A07"],
                    )
                )
            for m in as_list(res.get("Misconfigurations")):
                if not isinstance(m, dict) or str(m.get("Status")) == "PASS":
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity=normalize_severity(m.get("Severity")),
                        title=f"Misconfig: {m.get('ID') or ''} {m.get('Title') or ''}".strip(),
                        location=target,
                        message=str(m.get("Message") or "")[:160],
                        remediation=str(m.get("Resolution") or ""),
                        url=str(m.get("PrimaryURL") or ""),
                        rule=str(m.get("ID") or "trivy-misconfig"),
                        standards=["CIS"],
                    )
                )
        return out
