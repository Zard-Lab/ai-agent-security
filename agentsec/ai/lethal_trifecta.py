"""Lethal-trifecta architecture analyzer (Simon Willison's model).

An agent is at high risk of data exfiltration via prompt injection when it
simultaneously has all three legs:
  A. access to **private data**,
  B. exposure to **untrusted content**, and
  C. the ability to **communicate externally**.

This module heuristically inventories the three legs and the mitigations a
well-defended app would have (post-retrieval RAG sanitization, system-prompt-leak
filter, SSRF URL validation, per-user retrieval scoping, input size caps, output
guardrails), then emits review findings + a reasoning scaffold for the
`/security` Claude skill. It is a *heuristic* — it surfaces where to look; the
skill (and a human) confirm.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.guards.base import (
    is_llm_framework_repo,
    is_nonproduct_path,
    iter_files,
    python_scan_dirs,
    read,
    rel,
)

# `is_llm_framework_repo` is defined once in `guards/base.py` (issue #389) and re-exported
# here (imported above) for backward compatibility — the trifecta analyzer's own use below
# and any existing `from agentsec.ai.lethal_trifecta import is_llm_framework_repo` keep working.

# Lowercased substrings. Legs are intentionally broad (presence detection →
# conservative: more likely to demand a defense). Mitigation signals are
# specific (avoid falsely concluding a defense exists).
_LEGS: dict[str, list[str]] = {
    "private_data": [
        "from supabase import", "asyncpg", "psycopg", ".select(", "session.query",
        "vault", "decrypt(", "match_documents", "auth.uid", "read_secret",
    ],
    "untrusted_content": [
        "retrieve", "vectorstore", "rag", "web_search", "uploadfile", "crawl",
        "scrape", "embedding", "load_documents", "get_document",
    ],
    "external_comms": [
        "httpx", "requests.get", "requests.post", "aiohttp", "urllib.request",
        "smtplib", "send_email", "sendgrid", "webhook", "mcpserver", "tavily",
    ],
}
_MITIGATIONS: dict[str, list[str]] = {
    "rag_sanitization": ["rag_sanitiz", "sanitize_retrieved", "retrieved_documents", "wrap_untrusted"],
    "prompt_leak_guard": ["system_prompt_leak", "systempromptleak", "leaks_system_prompt"],
    "ssrf_validation": ["validate_url", "url_security", "is_safe_url", "ssrf"],
    "input_size_cap": ["max_input", "max_length", "max_prompt", "max_tokens", "truncate("],
    "output_guardrails": ["guardrail", "validate_output", "outputvalidator", "moderation"],
    "per_user_scoping": ["row level security", "auth.uid", "user_id", "rls"],
}
_MAX_FILES = 400

# Markers short/ambiguous enough to match inside an unrelated longer word with a totally
# different meaning (issue #638): a bare substring match on "rag" cited a pure bcrypt
# password-hashing file as an untrusted-content leg because its docstring says "for DB
# **storage**" — a real finding's conclusion was right, but the printed evidence was a file with
# no retrieval code at all, which is worse than no citation. "rls" has the same shape ("girls",
# "curls", "hurls" all contain it, with no relation to row-level security). Excludes "crawl" and
# "vault" deliberately: their apparent collisions ("crawler", "crawlspace", "vaulted") are
# semantically CONSISTENT with the marker's own meaning, not a false positive class — narrowing
# those would trade away real detections for no accuracy gain.
_WORD_BOUNDARY_MARKERS = frozenset({"rag", "rls"})
# Boundaried on adjacent-LETTER, not `\b` (which treats `_` as a word character and would reject
# `rag_pipeline`/`my_rag_util` — snake_case identifiers this marker must still match). A digit,
# underscore, punctuation character, or start/end of string all count as a real boundary.
#
# Asymmetric on purpose, and matched against the CASE-PRESERVED text (not the lowercased scan
# copy): the "before" side rejects ANY letter, case-insensitively, so `STORAGE_PATH` (no
# lowercase neighbour at all) still doesn't collide. The "after" side rejects only a strictly
# lowercase letter (`(?-i:...)` turns IGNORECASE back off for just this lookahead), so an
# uppercase letter following — `RAGPipeline`, `RagChain` — reads as a real PascalCase/camelCase
# word boundary and still matches. Mirroring guards/base.py's `(?-i:(?<![a-z]))` idiom here (both
# sides lowercase-only, case-sensitive) is a trap: it only rejects a lowercase neighbour on
# EITHER side, so `STORAGE_PATH`'s uppercase `O`/`E` neighbours would pass both checks and
# reopen the exact FP class this marker exists to close.
_BOUNDARY_PATTERNS: dict[str, re.Pattern[str]] = {
    kw: re.compile(rf"(?<![a-z]){re.escape(kw)}(?-i:(?![a-z]))", re.IGNORECASE) for kw in _WORD_BOUNDARY_MARKERS
}


def _find_kw(low: str, raw: str, kw: str) -> int:
    """Locate `kw`; -1 if absent. Short/ambiguous markers (`_WORD_BOUNDARY_MARKERS`) match
    case-insensitively against `raw` (case-preserved) with the asymmetric boundary above;
    everything else is an unchanged plain substring search against `low` (lowercased).

    NOTE: the two branches return indices into DIFFERENT strings: `raw` for a boundary marker,
    `low` for everything else. `str.lower()` is not length-preserving (U+0130 `İ` lowercases to
    two characters, the only such codepoint below 0x10000), so the caller must count newlines in
    the same string the index came from. Adding a third boundary marker is safe; slicing the
    wrong string is not."""
    pattern = _BOUNDARY_PATTERNS.get(kw)
    if pattern is None:
        return low.find(kw)
    m = pattern.search(raw)
    return m.start() if m else -1


@dataclass
class Signal:
    present: bool = False
    evidence: list[str] = field(default_factory=list)  # up to 3 "file:line"


@dataclass
class TrifectaAssessment:
    legs: dict[str, Signal]
    mitigations: dict[str, Signal]

    @property
    def trifecta_active(self) -> bool:
        return all(self.legs[k].present for k in ("private_data", "untrusted_content", "external_comms"))

    @property
    def has_any_injection_defense(self) -> bool:
        return any(
            self.mitigations[k].present
            for k in ("rag_sanitization", "prompt_leak_guard", "output_guardrails")
        )


def _scan(files: list[tuple[Path, str]], categories: dict[str, list[str]]) -> dict[str, Signal]:
    sig = {name: Signal() for name in categories}
    for relpath, text in files:
        low = text.lower()
        for name, keywords in categories.items():
            s = sig[name]
            if len(s.evidence) >= 3:
                continue
            for kw in keywords:
                idx = _find_kw(low, text, kw)
                if idx != -1:
                    s.present = True
                    # Count newlines in the SAME string the index came from (see `_find_kw`):
                    # a boundary marker searched `text`, everything else searched `low`, and the
                    # two are not index-compatible once a length-changing codepoint appears.
                    src = text if kw in _BOUNDARY_PATTERNS else low
                    line = src[:idx].count("\n") + 1
                    s.evidence.append(f"{relpath}:{line} ({kw})")
                    break
    return sig


def assess(root: Path, profile: StackProfile) -> TrifectaAssessment:
    # If this repo IS the LLM framework library, skip entirely. Framework source uses
    # all three legs by design; checking it produces FPs on every framework repo.
    if is_llm_framework_repo(root, profile):
        return TrifectaAssessment(
            legs={k: Signal() for k in _LEGS},
            mitigations={k: Signal() for k in _MITIGATIONS},
        )
    files: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for d in python_scan_dirs(root, profile):
        for f in iter_files(d, (".py",)):
            if f in seen or len(files) >= _MAX_FILES:
                continue
            rp = rel(root, f)
            if is_nonproduct_path(rp, profile.archive_segments):
                continue
            seen.add(f)
            files.append((Path(rp), read(f)))
    legs = _scan(files, _LEGS)
    mitigations = _scan(files, _MITIGATIONS)
    if profile.has_rls_sql and not mitigations["per_user_scoping"].present:
        mitigations["per_user_scoping"] = Signal(present=True, evidence=["sql: ENABLE ROW LEVEL SECURITY"])
    return TrifectaAssessment(legs=legs, mitigations=mitigations)


def to_findings(assessment: TrifectaAssessment) -> list[Finding]:
    out: list[Finding] = []
    legs, mit = assessment.legs, assessment.mitigations

    def ev(sig: Signal) -> str:
        return "; ".join(sig.evidence[:2])

    if assessment.trifecta_active:
        legs_str = (
            f"private-data ({ev(legs['private_data'])}), "
            f"untrusted-content ({ev(legs['untrusted_content'])}), "
            f"external-comms ({ev(legs['external_comms'])})"
        )
        if not assessment.has_any_injection_defense:
            out.append(Finding(
                check_id="lethal-trifecta",
                severity="high",
                title="Lethal trifecta active with no prompt-injection defense detected",
                message=(
                    "All three legs present and no RAG sanitization / system-prompt-leak filter / "
                    f"output guardrails detected. Legs: {legs_str}."
                ),
                remediation=(
                    "Add layered defenses: wrap retrieved/tool content as untrusted data, an output "
                    "guardrail, per-user retrieval scoping, and an input size cap."
                ),
                rule="lethal-trifecta/no-defense",
                # LLM06 (Excessive Agency) removed 2026-07-05: this finding is about a missing
                # prompt-injection defense given the trifecta's architecture, not about the
                # agent's *tool permissions* being excessive — the tool-permission-scoping claim
                # belongs to `agent-tool-overpermission` (checklist item 4-agent-tool-allowlist).
                # `lethal-trifecta` and `agent-tool-overpermission` no longer double-tag LLM06 on
                # the same architectural signal. (LLM06 legitimately remains on several other,
                # distinct-signal guards — audit-log, circuit-breaker, mcp-tool-description, etc.)
                standards=["OWASP-LLM:LLM01"],
            ))
        else:
            checks = [
                ("rag_sanitization", "post-retrieval RAG sanitization / untrusted-data wrapping",
                 "untrusted_content"),
                ("prompt_leak_guard", "system-prompt-leakage output filter", None),
                ("output_guardrails", "output guardrails", None),
            ]
            for key, label, leg_gate in checks:
                if mit[key].present:
                    continue
                if leg_gate and not legs[leg_gate].present:
                    continue
                out.append(Finding(
                    check_id="lethal-trifecta",
                    severity="medium",
                    title=f"Trifecta active but no {label} detected",
                    message=f"The agent has the full lethal trifecta ({legs_str}) — add {label}.",
                    remediation=f"Implement {label} (heuristic — confirm it isn't present under another name).",
                    rule=f"lethal-trifecta/missing-{key.replace('_', '-')}",
                    standards=["OWASP-LLM:LLM01"],
                ))
        if legs["external_comms"].present and not mit["ssrf_validation"].present:
            out.append(Finding(
                check_id="lethal-trifecta",
                severity="medium",
                title="External-communication leg without SSRF URL validation detected",
                message="The agent can communicate externally but no SSRF/URL allowlist validation was found.",
                remediation="Validate outbound/agent-supplied URLs (block loopback/RFC1918/metadata) or pin endpoints.",
                rule="lethal-trifecta/missing-ssrf-validation",
                # LLM06 removed 2026-07-05 — same reasoning as no-defense above: this is an
                # external-comms/SSRF validation gap, not a tool-permission-scoping claim.
                standards=["OWASP-LLM:LLM02", "OWASP:A10"],
            ))
        if legs["private_data"].present and not mit["per_user_scoping"].present:
            out.append(Finding(
                check_id="lethal-trifecta",
                severity="medium",
                title="Private-data access without per-user scoping (RLS) detected",
                message="Retrieval/DB access found but no RLS / per-user scoping signal — cross-user data exposure risk.",
                remediation="Scope retrieval to the authenticated user (RLS predicates / user_id filters).",
                rule="lethal-trifecta/missing-per-user-scoping",
                standards=["OWASP-LLM:LLM08", "OWASP:A01"],
            ))
    elif legs["untrusted_content"].present and not assessment.has_any_injection_defense:
        out.append(Finding(
            check_id="lethal-trifecta",
            severity="low",
            title="Untrusted-content ingress without prompt-injection defense detected",
            message="The trifecta is not complete, but untrusted content reaches the model with no detected defense.",
            remediation="Treat retrieved/tool content as untrusted and add an output guardrail as defense-in-depth.",
            rule="lethal-trifecta/untrusted-no-defense",
            standards=["OWASP-LLM:LLM01"],
        ))
    return out


def to_scaffold(assessment: TrifectaAssessment) -> str:
    """A reasoning scaffold for the /security Claude skill (and humans)."""
    lines = ["# Lethal-trifecta assessment", ""]
    lines.append(f"**Trifecta active:** {'YES — all three legs present' if assessment.trifecta_active else 'no'}")
    lines.append("")
    lines.append("## Legs")
    for name in ("private_data", "untrusted_content", "external_comms"):
        s = assessment.legs[name]
        mark = "✅ present" if s.present else "— not detected"
        lines.append(f"- **{name.replace('_', ' ')}**: {mark}")
        for e in s.evidence:
            lines.append(f"  - {e}")
    lines.append("")
    lines.append("## Mitigations")
    for name, s in assessment.mitigations.items():
        mark = "✅ detected" if s.present else "❌ not detected"
        lines.append(f"- **{name.replace('_', ' ')}**: {mark}")
        for e in s.evidence:
            lines.append(f"  - {e}")
    lines.append("")
    lines.append("## Review questions for the agent (confirm manually / via the /security skill)")
    lines += [
        "- Is every retrieved RAG chunk / tool result treated as untrusted data (neutralized + delimiter-wrapped)?",
        "- Is retrieval scoped to the authenticated user only (no cross-tenant leakage)?",
        "- Is model output sanitized before it reaches the client, and checked for system-prompt leakage?",
        "- Is there an input size cap on all LLM-backed endpoints?",
        "- Are agent-reachable URLs validated (no SSRF) or pinned to fixed endpoints?",
        "- Does any tool let the model run code / shell / arbitrary SQL? If so, is it sandboxed / read-only?",
    ]
    lines.append("")
    return "\n".join(lines)
