"""Guard: MCP `sampling` capability wired up with no consent/elicitation gate anywhere in
the repo (checklist §4, new item — the batch).

MCP servers can request LLM completions back through the connected CLIENT via the
`sampling/createMessage` request (MCP 2025-06-18 §6.3). That makes the SERVER a privileged
caller of the host's own LLM — and any output it receives back must be treated as untrusted
tool input, since the server chose the prompt. The 2025-03-26 spec revision added the
`elicitation/create` consent flow specifically to gate sampling requests: a well-behaved host
is supposed to ask the user before honoring one.

This guard fires when a repo participates in the sampling capability — either declaring `capabilities.sampling`, calling
`sampling/createMessage`/`create_message`, or implementing a `CreateMessageRequestSchema`
handler — and NO consent/elicitation marker (`elicitation/create`, `elicit_*`,
`ElicitRequestSchema`, `requires_consent`, `human_in_the_loop`, `confirmSampling`, etc.) appears
ANYWHERE in the repo. It also fires independently when an MCP config file explicitly lists
`"sampling"` in a per-server `capabilities` block with no sibling `requires_consent`/
`human_in_the_loop` flag — an explicit host-side allow-list with no consent wiring.

Ported from `agent-audit-kit`'s real `mcp_sampling_capability.py` (fetched and read in full;
the marker regex sets are verbatim). Two adaptations, disclosed:

  * The real source additionally requires a dependency-manifest MCP-SDK declaration before
    the source-side check runs. agentsec's own `"mcp" in profile.features` gate (`detect.py`)
    already performs the equivalent anchored SDK/import/config detection, so this guard reuses
    the existing `applies()` gate instead of re-implementing manifest parsing.
  * The real source's escape hatch is a bespoke `.agent-audit-kit.yml` risk-acceptance file
    with a `justification:` field. agentsec has no equivalent convention anywhere in this
    codebase; every other guard uses the shared inline pragma instead, so this guard follows
    that convention (`# security: allow-mcp-sampling-no-consent`) rather than inventing a new
    YAML config file this one guard alone would read.
"""
from __future__ import annotations

import json
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

# 2026-09-23 fix (Dean's review, same class as agentic pre-review H-8): a
# `#`-anchored regex never matches in the JS/TS files this guard also scans (`#` is not that
# language's line-comment marker), so `// security: allow-...` silently never suppressed
# anything there. A plain substring, matching every other JS/TS guard's own pragma convention.
_PRAGMA = "security: allow-mcp-sampling-no-consent"

_STANDARDS = ["OWASP-LLM:LLM01", "OWASP-ASI:ASI01"]

_LANG_EXTS = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".java", ".kt", ".rs")

# Markers that prove the repo participates in MCP sampling — verbatim from the real source.
_SAMPLING_MARKERS = (
    re.compile(r"capabilities\s*[:=]\s*\{[^}]*sampling\s*[:=]"),
    re.compile(r"ServerCapabilities\s*\([^)]*sampling\s*="),
    re.compile(r"SamplingCapability\s*\("),
    re.compile(r"CreateMessageRequestSchema"),
    re.compile(r"\bsampling/createMessage\b"),
    re.compile(r"\bcreate_message\s*\("),
    re.compile(r"\.sampling\.create\s*\("),
    re.compile(r"\bRequestSampling\b"),
)

# Markers that prove a consent / elicitation gate is wired up somewhere in the repo — verbatim.
_CONSENT_MARKERS = (
    re.compile(r"\belicitation/create\b"),
    re.compile(r"\bElicitRequestSchema\b"),
    re.compile(r"\belicit(?:_create|_input|ation)?\s*\("),
    re.compile(r"\bElicitInput\b"),
    re.compile(r"\b(?:requires?_consent|require_consent|user_consent)\b"),
    re.compile(r"\bhuman[_-]?in[_-]?the[_-]?loop\b", re.IGNORECASE),
    re.compile(r"\b(?:confirm|approve)Sampling\b"),
    re.compile(r"\bsamplingConsent\b"),
    re.compile(r"\bhuman_approval\b"),
)

_MCP_CONFIG_FILES = (
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".amazonq/mcp.json",
    ".windsurf/mcp.json",
    ".continue/config.json",
    ".roo/mcp.json",
    ".kiro/mcp.json",
    "mcp.json",
)


class McpSamplingNoConsentGuard(Guard):
    id = "mcp-sampling-no-consent"
    title = "MCP sampling capability wired up with no consent/elicitation gate in the repo"
    area = "AI agent"
    # 2026-09-23 (Dean's review, agentic pre-review M-6): a presence/absence
    # co-occurrence check whose own docs disclose it cannot prove a consent gate is genuinely
    # absent (only that no recognized marker was found) — marked surfacing as an interim
    # CI-gate mitigation for that structural limitation. **2026-09-24 correction (Dean's
    # review):** `surfacing` only changes report ordering, never CI-gate status — it never
    # actually took this guard off `--fail-on high`. Unlike the other 3 guards this round
    # marked surfacing for the same reason, this one's limitation is NOT a fixable precision
    # bug (there is no marker-list widening that proves a genuine absence rather than an
    # unrecognized one) — severity lowered to `medium` instead, which does actually clear the
    # default `--fail-on high` gate; `surfacing_rule_prefixes` kept for report ordering.
    surfacing_rule_prefixes = (
        "mcp-sampling-no-consent/source-participation",
        "mcp-sampling-no-consent/config-declaration",
    )

    # sampling_handler.py: a CreateMessageRequestSchema handler with no consent marker
    # anywhere in the canary tree -> fires mcp-sampling-no-consent/source-participation.
    # Must NOT contain: any consent/elicitation marker anywhere in the canary tree.
    canary_plant = CanaryPlant(
        files={
            "sampling_handler.py": (
                "from mcp.server import Server\n"
                "from mcp.types import CreateMessageRequestSchema\n"
                "\n"
                "server = Server('canary')\n"
                "\n"
                "\n"
                "@server.request_handler(CreateMessageRequestSchema)\n"
                "async def handle_sampling(request):\n"
                "    return await server.sampling.create(request)\n"
            ),
        },
        expects=frozenset({
            "mcp-sampling-no-consent/source-participation",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []

        out.extend(self._config_sampling_findings(root, profile))

        hits = self._sampling_hits(root, profile)
        if not hits:
            return out
        if self._has_consent_marker(root, profile):
            return out

        path, lineno = hits[0]
        out.append(self._source_finding(root, path, lineno))
        return out

    def _iter_lang_files(self, root: Path, profile: StackProfile) -> list[Path]:
        """FINDING-ANCHOR-eligible files only (nonproduct paths excluded) — used for the
        sampling-participation scan, never for the repo-wide consent scan below."""
        files: list[Path] = []
        for f in iter_files(root, _LANG_EXTS):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            files.append(f)
        return files

    def _sampling_hits(self, root: Path, profile: StackProfile) -> list[tuple[Path, int]]:
        hits: list[tuple[Path, int]] = []
        for f in self._iter_lang_files(root, profile):
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            for pat in _SAMPLING_MARKERS:
                m = pat.search(text)
                if m:
                    lineno = text[: m.start()].count("\n") + 1
                    hits.append((f, lineno))
                    break
        return hits

    def _has_consent_marker(self, root: Path, profile: StackProfile) -> bool:
        """Repo-wide: is a consent/elicitation gate wired up ANYWHERE at all?

        **2026-09-23 fix (Dean's review, agentic pre-review H-5, CLAUDE.md
        rule 4):** this used to reuse `_iter_lang_files` (nonproduct-filtered), so a consent
        gate demonstrated only in `examples/consent_demo.py` was invisible to the "no consent
        gate ANYWHERE in the repo" verdict — the repo-wide claim never actually read every
        file it claimed to. A skip must scope where a FINDING may be anchored, not what a
        repo-wide evidence scan is allowed to read; this scans every `.py`/`.ts`/... file,
        `is_nonproduct_path` or not."""
        for f in iter_files(root, _LANG_EXTS):
            text = read(f)
            if not text:
                continue
            if any(p.search(text) for p in _CONSENT_MARKERS):
                return True
        return False

    def _config_sampling_findings(self, root: Path, profile: StackProfile) -> list[Finding]:
        findings: list[Finding] = []
        for name in _MCP_CONFIG_FILES:
            f = root / name
            if not f.is_file():
                continue
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            raw = read(f)
            if not raw or pragma_present(_PRAGMA, raw, dialect=comment_dialect_for(f)):
                continue
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            servers = data.get("mcpServers")
            if not isinstance(servers, dict):
                continue
            for server_name, cfg in servers.items():
                if not isinstance(cfg, dict):
                    continue
                caps = cfg.get("capabilities")
                declares_sampling = (
                    isinstance(caps, list) and "sampling" in caps
                ) or (
                    isinstance(caps, dict) and "sampling" in caps
                )
                if not declares_sampling:
                    continue
                requires_consent = (
                    cfg.get("requires_consent") is True
                    or cfg.get("requiresConsent") is True
                    or cfg.get("consent") is True
                    or cfg.get("human_in_the_loop") is True
                )
                if requires_consent:
                    continue
                lineno = raw[: raw.find("sampling")].count("\n") + 1 if "sampling" in raw else 1
                findings.append(Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{r}:{lineno}",
                    message=(
                        f"Server '{server_name}' declares the `sampling` capability in its "
                        "MCP config with no `requires_consent`/`human_in_the_loop` sibling "
                        "flag. Sampling makes the server a privileged caller of the host's "
                        "own LLM; the 2025-03-26 spec's `elicitation/create` consent flow "
                        "exists specifically to gate this."
                    ),
                    remediation=(
                        "Add `\"requires_consent\": true` (or your client's equivalent flag) "
                        "next to the `sampling` capability declaration, and confirm the host "
                        "actually implements the `elicitation/create` consent flow before "
                        "honoring a sampling request from this server."
                    ),
                    rule="mcp-sampling-no-consent/config-declaration",
                    standards=list(_STANDARDS),
                ))
        return findings

    def _source_finding(self, root: Path, path: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, path)}:{lineno}",
            message=(
                "This repo participates in the MCP `sampling` capability (declares "
                "`capabilities.sampling`, implements a `CreateMessageRequestSchema` "
                "handler, or calls `sampling/createMessage`), but no consent/elicitation "
                "marker (`elicitation/create`, `requires_consent`, `human_in_the_loop`, "
                "etc.) appears anywhere in the repo. Sampling makes the server a "
                "privileged caller of the host's own LLM, and any output it receives "
                "back must be treated as untrusted."
            ),
            remediation=(
                "Wire the MCP 2025-03-26 spec's `elicitation/create` consent flow into "
                "the sampling handler before honoring a `sampling/createMessage` "
                "request, or confirm the consent gate is enforced by the host "
                "application (outside this repo) and suppress with "
                "`# security: allow-mcp-sampling-no-consent`."
            ),
            rule="mcp-sampling-no-consent/source-participation",
            standards=list(_STANDARDS),
        )
