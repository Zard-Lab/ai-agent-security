"""Guard: a Claude Code / Claude Agent SDK skill's static shape carries one of three
composition-layer risks — an unpinned external resource reference, a deserialization tag in
frontmatter, or a cross-platform manifest disagreement (checklist §4, new item;
agent-audit-kit's `agentic_skills.py` AAK-AST02-001/AAK-AST04-001/AAK-AST10-001).

Three checks, all on `SKILL.md` + a sibling `skill.json`/`manifest.json` where present:

  1. **`unpinned-external-resource`** (MEDIUM): the skill body references an external script or
     package with no version/commit pin — a bare `curl`/`wget` of a URL with no `@<sha>`/tag in
     the path, or an `npx <pkg>` / `pip install <pkg>` with no `==`/`@` version pin. A skill's
     supply chain moves whenever the unpinned upstream resource changes, silently, on every run.
  2. **`deserialization-tag-in-frontmatter`** (HIGH): frontmatter contains a YAML/JSON
     deserialization tag construct (`!!python/object`, `!!python/module`, a bare `pickle.loads(`/  # security: allow-unsafe-deserialize
     `yaml.load(` without `Loader=SafeLoader`) — an object-construction primitive with no business
     being in a skill's declarative metadata.
  3. **`cross-platform-manifest-disagreement`** (MEDIUM): a sibling `skill.json`/`manifest.json`
     declares a `name`/`version` that disagrees with the `SKILL.md` frontmatter's own `name`/
     `version` — the two platform-visible descriptions of the same skill drift, and whichever one
     a tool-selection or install path trusts may not be the one a human reviewed.

Suppress an audited case with:

    # security: allow-agentic-skills-ast
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files_named, pragma_present, read, rel

# `SKILL.md` (Markdown) and its JSON manifest have no comment syntax a view reads, so its pragma is matched
# on the raw text by contract (`dialect=None`, #1040 T5).
_PRAGMA = re.compile(r"#\s*security:\s*allow-agentic-skills-ast")

_URL_FETCH_RE = re.compile(
    r"\b(?:curl|wget)\s+(?:-\S+\s+)*['\"]?(https?://\S+?)['\"]?(?:\s|$)", re.IGNORECASE,
)
_NPX_RE = re.compile(r"\bnpx\s+(?:--?[A-Za-z][\w-]*\s+)*([A-Za-z0-9@/_.\-]+)\b")
_PIP_INSTALL_RE = re.compile(r"\bpip\s+install\s+(?:(?:--user|-U)\s+)*([A-Za-z0-9_\-\[\]]+)\b")
_PIN_MARKER_RE = re.compile(
    r"@[0-9a-f]{7,40}\b|@v?\d+(?:\.\d+)*\b|#[0-9a-f]{7,40}\b|/[0-9a-f]{7,40}/"
)

_DESER_TAG_RE = re.compile(
    r"!!python/(?:object|module|name)|"
    r"pickle\.loads?\s*\(|"
    r"yaml\.load\s*\((?!\s*[^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)",
)

_NAME_FIELD_RE = re.compile(r'^[^\S\n]*"?name"?\s*:\s*["\']?([^"\'\n,}]+)', re.MULTILINE)
_VERSION_FIELD_RE = re.compile(r'^[^\S\n]*"?version"?\s*:\s*["\']?([^"\'\n,}]+)', re.MULTILINE)

_STD_UNPINNED = ["CWE-829", "OWASP-ASI:ASI04"]
_STD_DESER = ["CWE-502", "OWASP-LLM:LLM06"]
_STD_MANIFEST = ["CWE-706"]


def _parse_frontmatter(text: str) -> tuple[str, str]:
    if not text.startswith("---"):
        return "", text
    try:
        _, fm, body = text.split("---", 2)
    except ValueError:
        return "", text
    return fm, body


def _field(text: str, pattern: re.Pattern[str]) -> str | None:
    m = pattern.search(text)
    if not m:
        return None
    return m.group(1).strip()


_LOOPBACK_HOSTS = frozenset({"localhost", "0.0.0.0", "::1", "[::1]"})  # nosec B104 - a match list, not a bind
_HOST_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://(?:[^@/?#]*@)?(?:\[([^\]]+)\]|([^/:?#]+))", re.IGNORECASE)


def _is_loopback_url(url: str) -> bool:
    """A health check / local-dev call (`http://localhost:8080/health`) fetches nothing an
    attacker controls, so there is no upstream to pin. Manual scheme/host parse: `urllib` is
    banned from guard modules (`guard_sandbox.py::_BANNED_IMPORT_ROOTS`), and bracket/userinfo
    handling matches the pattern already used in `mcp_config_security.py::_url_host`."""
    m = _HOST_RE.match(url)
    if not m:
        return False
    host = (m.group(1) or m.group(2) or "").lower()
    if host in _LOOPBACK_HOSTS:
        return True
    # A strict IP parse, not a string prefix test: `host.startswith("127.")` used to classify
    # `127.attacker.example` as loopback -- any hostname starting with the literal text "127."
    # skipped the unpinned-fetch check regardless of what it actually resolves to.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    # Unwrap an IPv4-mapped IPv6 address (`::ffff:127.0.0.1`) before checking -- `ipaddress`
    # reports `is_loopback` as False for the mapped form unless it is unwrapped first (the exact
    # bypass `ssrf-ipv6-bypass` exists to catch; this guard's own self-audit caught it here). This
    # is the FAIL-SAFE direction to get wrong: a loopback URL classified as remote is over-strict
    # (a false "needs a pin"), not a missed-detection.
    return (getattr(ip, "ipv4_mapped", None) or ip).is_loopback


def _unpinned_hits(body: str) -> list[str]:
    hits: list[str] = []
    for m in _URL_FETCH_RE.finditer(body):
        url = m.group(1)
        if _is_loopback_url(url):
            continue
        if not _PIN_MARKER_RE.search(url):
            hits.append(f"unpinned fetch: {url!r}")
    for m in _NPX_RE.finditer(body):
        pkg = m.group(1)
        if "@" not in pkg or pkg.endswith("@latest"):
            hits.append(f"unpinned npx package: {pkg!r}")
    for m in _PIP_INSTALL_RE.finditer(body):
        pkg = m.group(1)
        if pkg.startswith("-"):
            continue  # `-r requirements.txt`, `--index-strategy ...`: a flag, not a package
        tail = body[m.end():m.end() + 20]
        if "==" not in pkg and not tail.startswith("=="):
            hits.append(f"unpinned pip package: {pkg!r}")
    return hits


def _find_manifest(skill_md: Path) -> Path | None:
    for name in ("skill.json", "manifest.json"):
        candidate = skill_md.parent / name
        if candidate.is_file():
            return candidate
    return None


class AgenticSkillsAstGuard(Guard):
    id = "agentic-skills-ast"
    title = "Skill's static shape carries an unpinned resource, a deserialization tag, or a manifest mismatch"
    area = "AI agent"

    # skills/my-skill/SKILL.md: an unpinned curl-fetched install script -> fires
    # agentic-skills-ast/unpinned-external-resource.
    canary_plant = CanaryPlant(
        files={
            "skills/my-skill/SKILL.md": (
                "---\nname: my-skill\n---\n\n"
                "Setup:\n\ncurl -fsSL https://example.com/install.sh -o install.sh\n"
            ),
        },
        expects=frozenset({
            "agentic-skills-ast/unpinned-external-resource",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for p in iter_files_named(root, "SKILL.md", respect_gitignore=False):
            r = rel(root, p)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            raw = read(p).lstrip("\ufeff")  # a Windows editor's BOM would defeat the `---` frontmatter test
            if not raw or pragma_present(_PRAGMA, raw, dialect=None):
                continue
            fm, body = _parse_frontmatter(raw)

            for hit in _unpinned_hits(body):
                out.append(self._finding(
                    r, "unpinned-external-resource", "medium", _STD_UNPINNED,
                    f"Skill body references an external resource with no version/commit "
                    f"pin ({hit}) — the skill's supply chain can change silently on every run.",
                ))

            if _DESER_TAG_RE.search(fm):
                out.append(self._finding(
                    r, "deserialization-tag-in-frontmatter", "high", _STD_DESER,
                    "Frontmatter contains a deserialization/object-construction primitive "
                    "(a YAML type tag or an unsafe pickle/yaml.load call) with no business "
                    "being in declarative skill metadata.",
                ))

            manifest = _find_manifest(p)
            if manifest is not None:
                manifest_raw = read(manifest)
                if manifest_raw and not pragma_present(_PRAGMA, manifest_raw, dialect=None):
                    out.extend(self._check_manifest_agreement(r, rel(root, manifest), fm, manifest_raw))
        return out

    def _check_manifest_agreement(
        self, skill_rel: str, manifest_rel: str, fm: str, manifest_raw: str,
    ) -> list[Finding]:
        out: list[Finding] = []
        fm_name = _field(fm, _NAME_FIELD_RE)
        fm_version = _field(fm, _VERSION_FIELD_RE)
        try:
            manifest_data = json.loads(manifest_raw.lstrip("\ufeff"))  # BOM-tolerant
        except (ValueError, RecursionError):  # hostile deep nesting: skip the manifest
            return out
        if not isinstance(manifest_data, dict):
            return out
        man_name = manifest_data.get("name")
        man_version = manifest_data.get("version")

        mismatches: list[str] = []
        if (
            fm_name and isinstance(man_name, str) and man_name
            and fm_name.strip().strip("\"'") != man_name.strip()
        ):
            mismatches.append(f"name: SKILL.md={fm_name!r} vs {manifest_rel}={man_name!r}")
        if (
            fm_version and isinstance(man_version, str) and man_version
            and fm_version.strip().strip("\"'") != man_version.strip()
        ):
            mismatches.append(f"version: SKILL.md={fm_version!r} vs {manifest_rel}={man_version!r}")

        if mismatches:
            out.append(self._finding(
                skill_rel, "cross-platform-manifest-disagreement", "medium", _STD_MANIFEST,
                "SKILL.md frontmatter and the sibling manifest disagree on the skill's own "
                f"identity ({'; '.join(mismatches)}) — whichever one a tool-selection or "
                "install path trusts may not be the one a human reviewed.",
            ))
        return out

    def _finding(
        self, r: str, rule_suffix: str, severity: Severity, standards: list[str], message: str,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=r,
            message=message,
            remediation=(
                "Pin every external resource the skill fetches to a specific version/"
                "commit, remove deserialization primitives from frontmatter entirely, and "
                "keep the skill's name/version identical across SKILL.md and any sibling "
                "manifest."
            ),
            rule=f"agentic-skills-ast/{rule_suffix}",
            standards=list(standards),
        )
