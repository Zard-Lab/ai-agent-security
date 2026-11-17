"""Guard: literal cloud instance-metadata-endpoint reference (checklist §3a).

    os.system("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")

Cloud instance metadata services (AWS/GCP/Azure/OpenStack's `169.254.169.254`, Alibaba
Cloud's `100.100.100.200`, GCP's `metadata.google.internal`, AWS's IPv6 IMDS at
`fd00:ec2::254`) hand out short-lived cloud credentials to anything running on the
instance, with no authentication beyond network reachability. A literal reference to
one of these addresses — in a shell command, an `os.system`/`subprocess` call built
from a literal string, or an AI agent skill/instruction file — is a strong, direct
signal of an attempt to steal the instance's cloud credentials, independent of
*how* the request gets made.

**Distinct from the existing `ssrf-general` guard**, which only fires when a
server-side fetch URL is built from user-controlled/dynamic input (an f-string,
concatenation, or a `request.`-derived value) feeding a `requests`/`httpx`/`urlopen`
call — by design, it never fires on a bare literal URL, since a hardcoded fetch to a
fixed address isn't attacker-controlled in the traditional SSRF sense. This guard
closes that gap for the metadata-endpoint case specifically: a hardcoded reference to
one of these addresses is inherently suspicious regardless of how it's fetched, since
there is essentially no legitimate reason for application code to hardcode the literal
IMDS address (real cloud SDKs resolve it internally). Sourced from SkillSpector's
SSRF1 category. CWE-918 (Server-Side Request Forgery), OWASP:A10.

Fires HIGH on a literal, non-comment reference to:

  * `169.254.169.254` (AWS / GCP / Azure / OpenStack IMDS);
  * `metadata.google.internal` (GCP's DNS alias for the same);
  * `100.100.100.200` (Alibaba Cloud);
  * `fd00:ec2::254` (AWS IMDS over IPv6).

Suppress an audited case (e.g. a genuine cloud-init/bootstrap script that legitimately
queries the metadata service for instance role assumption) with
`# security: allow-metadata-endpoint` anywhere in the file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
)

_METADATA_ENDPOINTS = re.compile(
    r"169\.254\.169\.254"
    r"|metadata\.google\.internal"
    r"|100\.100\.100\.200"
    r"|fd00:ec2::254",
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-metadata-endpoint")

_SUFFIXES = (".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash")
_STANDARDS = ["OWASP:A10", "CWE-918"]


class CloudMetadataEndpointLiteralGuard(Guard):
    id = "cloud-metadata-endpoint-literal"
    title = "Literal reference to a cloud instance-metadata endpoint"
    area = "Network requests"

    # metadata_theft.py: literal 169.254.169.254 -> fires cloud-metadata-endpoint-literal.
    # Must NOT contain: allow-metadata-endpoint pragma.
    canary_plant = CanaryPlant(
        files={
            "metadata_theft.py": (
                'os.system("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")\n'
            ),
        },
        expects=frozenset({"cloud-metadata-endpoint-literal/hardcoded-reference"}),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        # Universal: the Python/JS/shell source this scans (and its metadata-endpoint
        # signal) can appear in any project regardless of the detected stack — a
        # language-feature gate would silently drop the JS/shell literals on a Node-only
        # or shell-only repo.
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return out
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            m = _METADATA_ENDPOINTS.search(line)
            if not m:
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        f"This line references `{m.group(0)}`, a cloud instance "
                        "metadata endpoint. These services hand out short-lived cloud "
                        "credentials to anything on the instance with no "
                        "authentication beyond network reachability — a literal "
                        "reference is a strong signal of credential theft, since real "
                        "cloud SDKs resolve this address internally rather than "
                        "hardcoding it in application code."
                    ),
                    remediation=(
                        "Remove the hardcoded metadata-endpoint reference. If instance "
                        "role credentials are genuinely needed, use the cloud "
                        "provider's own SDK (boto3, google-cloud, azure-sdk) rather "
                        "than querying the endpoint directly. Suppress an audited "
                        "bootstrap/cloud-init case with "
                        "`# security: allow-metadata-endpoint` anywhere in the file."
                    ),
                    rule="cloud-metadata-endpoint-literal/hardcoded-reference",
                    standards=list(_STANDARDS),
                )
            )
        return out
