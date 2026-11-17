"""Compounding-risk signal: findings that are individually flagged but WORSE together.

(private research tracker). `CyberStrikeus/CyberStrike`'s skill metadata carries a
`chains_with`/`severity_boost` relational field — e.g. "SQLi + IDOR = Account Takeover, Critical" —
flagging when two findings together are worse than either alone. agentsec's `Finding`s report as flat,
independent results with no equivalent signal: a repo with both a SQL-injection sink AND a
broken-object-level-authorization gap reads as two separate MEDIUM/HIGH findings, not the CRITICAL
account-takeover chain those two facts actually describe together.

**Design.** A small, curated table of `CompoundRisk` entries, each naming a set of REQUIRED GROUPS —
every group must contribute at least one already-present finding (by `check_id`) for the compound to
fire; a group is itself an OR (any one guard from the set counts). `assess()` runs once, after every
guard/runner/enrichment pass has produced its findings, and emits one synthetic `Finding` per satisfied
`CompoundRisk` — `check_id="compounding-risk"`, `rule="compounding-risk/<slug>"`, no `location` (it
describes a repo-wide relationship between findings, not one file:line — the same convention
`lethal-trifecta` already uses for its own architecture-level findings). The synthetic finding flows
through the normal suppression/exception pipeline afterward like any other, so it can be baselined or
excluded the same way.

**Curated, not exhaustive** (mirrors the SOC2/HIPAA/EU-AI-Act checklist-tagging precedent): four
well-established, high-confidence chains to start, not an attempt to enumerate every plausible
combination. Adding one is: pick a genuinely worse-together pair (not "these are both bad," but "the
combination unlocks something neither alone does"), name the real guard ids on each side, and write the
message as the actual attack chain, not a restatement of the two findings.

**Deliberately repo-wide, not same-location.** A precise version would only compound two findings that
are reachable from the SAME request path (e.g. the SQLi sink and the IDOR gap are in the same handler).
This version fires on repo-wide co-occurrence — matching the CyberStrike precedent's own example shape
— which is a real, disclosed precision trade-off: a large monorepo with an isolated SQLi finding in one
service and an unrelated IDOR finding in a completely different one will still compound. Same-location
correlation is a known follow-up, not attempted here (it needs a shared notion of "route"/"request path"
across guards that doesn't exist yet).

**Severity is a curated property of the pair, not computed.** No attempt to algorithmically combine two
severities (the PROB row's own open question) — each `CompoundRisk` states its own severity directly,
chosen for the specific chain it describes.
"""
from __future__ import annotations

from dataclasses import dataclass

from agentsec.findings import Finding, Severity, _is_review_finding

# A contributing finding's review-tier status ("confirm this by hand", not a proven bug) is
# resolved live from what its OWN check declares (`surfacing`/`surfacing_rule_prefixes`, see
# `findings.py::_is_review_finding`) rather than a separately hardcoded id set here — a hardcoded
# subset would silently drift the moment a guard's own `surfacing` declaration changed, or a new
# review-tier guard joined a `CompoundRisk` group without this file being updated to match
# (#683 fix-commit re-review, Low 2). When a contributing leg is review-tier, the synthetic
# finding must carry that caveat forward explicitly: `_is_review_finding()` keys on the FINDING'S
# OWN rule, which for the synthetic finding itself is `compounding-risk/<slug>` — never matching
# `bola/` or `lethal-trifecta/` — so the disclaimer present on the input leg would otherwise be
# silently stripped by the composition (#683 review, High 4).


@dataclass(frozen=True)
class CompoundRisk:
    slug: str
    groups: tuple[frozenset[str], ...]
    severity: Severity
    title: str
    message: str
    remediation: str
    standards: list[str]


_COMPOUND_RISKS: tuple[CompoundRisk, ...] = (
    CompoundRisk(
        slug="sqli-plus-idor-account-takeover",
        groups=(
            frozenset({
                "sqlalchemy-text-parameterized", "js-sql-injection", "go-sql-injection",
                "nosql-metadata-injection",
            }),
            frozenset({"bola"}),
        ),
        severity="critical",
        title="SQL/NoSQL injection combined with broken object-level authorization — likely account takeover",
        message=(
            "A query-injection sink AND a broken-object-level-authorization gap are both present. "
            "Individually these are a data-integrity risk and an access-control gap; together, an "
            "attacker who can inject query logic can also reach records the authorization gap already "
            "fails to scope to the caller — the two facts compose into full account/data takeover, not "
            "just an isolated leak."
        ),
        remediation=(
            "Fix both — parameterize the flagged query AND scope the flagged endpoint to the "
            "authenticated caller — rather than treating either as lower priority because the other "
            "'covers' it. Neither does."
        ),
        standards=[],  # OWASP:A01/A03 would apply but are always stripped at emission -- see the filter below
    ),
    CompoundRisk(
        slug="unauthenticated-route-plus-privileged-write",
        groups=(
            frozenset({"auth-dependency-not-applied"}),
            frozenset({"privileged-field-assignment"}),
        ),
        severity="critical",
        title="Unauthenticated route combined with a privileged-field write — unauthenticated privilege escalation",
        message=(
            "A state-changing route with no auth dependency AND a route that writes a privileged field "
            "(role/is_admin/is_staff-shaped) directly from request input are both present. If they're "
            "the same route, this is a direct anonymous-to-admin escalation; even if they're different "
            "routes, the missing-auth finding means the app's own auth-wiring discipline has at least "
            "one real gap, which raises the odds the privileged-write route has one too."
        ),
        remediation=(
            "Attach the missing auth dependency, and audit the privileged-field write for a matching "
            "authorization check (not just authentication) before that field is ever set from a request."
        ),
        standards=[],  # OWASP:A01 would apply but is always stripped at emission -- see the filter below
    ),
    CompoundRisk(
        slug="exposed-secret-plus-code-execution",
        groups=(
            frozenset({
                "weak-secret-key-literal", "hardcoded-private-key-in-source", "cleartext-secret-storage",
            }),
            frozenset({
                "code-injection-eval-exec", "command-injection", "unsafe-deserialization",
                "obfuscated-payload-execution",
            }),
        ),
        severity="critical",
        title="Exposed secret combined with a code-execution sink — a leaked secret can pivot straight to RCE",
        message=(
            "A hardcoded/exposed secret AND a code-execution sink (eval/exec, shell, unsafe "
            "deserialization, or a decode-then-execute chain) are both present. An attacker who obtains "
            "the exposed secret (source access, a log leak, a repo leak) doesn't stop at whatever that "
            "secret alone grants — the execution sink turns credential exposure into arbitrary code "
            "execution in the same codebase."
        ),
        remediation=(
            "Rotate and externalize the exposed secret (env var / secret manager, not source), and fix "
            "the execution sink independently — closing only one leaves the other's blast radius intact."
        ),
        standards=["CWE-506"],  # OWASP:A03 would also apply but is always stripped at emission
    ),
    CompoundRisk(
        slug="lethal-trifecta-plus-tool-overpermission",
        groups=(
            frozenset({"lethal-trifecta"}),
            frozenset({"agent-tool-overpermission"}),
        ),
        severity="critical",
        title="Lethal trifecta active alongside excessive agent tool permissions — autonomous exfiltration risk",
        message=(
            "The agent has private-data access, untrusted-content ingestion, and external-communication "
            "capability all at once (the lethal trifecta) AND at least one agent tool grants broader "
            "access than its own task needs. A prompt injection riding the untrusted-content leg doesn't "
            "just have a theoretical path to exfiltrate private data externally — the over-permissioned "
            "tool is a concrete mechanism already in place to do it."
        ),
        remediation=(
            "Scope the over-permissioned tool to least privilege (this alone breaks the compound even "
            "before the trifecta itself is addressed), and add the trifecta's own recommended layered "
            "defenses (untrusted-content wrapping, output guardrails, per-user retrieval scoping)."
        ),
        standards=[],  # OWASP-LLM:LLM01/LLM06 would apply but are always stripped at emission
    ),
)


def assess(findings: list[Finding]) -> list[Finding]:
    """Return one synthetic `Finding` per `CompoundRisk` whose every group already has at least one
    contributing finding present in `findings` (by `check_id`). Pure function — does not mutate or
    remove anything from `findings`; the caller `extend()`s the result in, same as any other pass.

    Callers must run this over the finding set they actually want compounded — see the caller in
    `audit.py` for why that is `outcome.kept` (post-suppression), not the raw pre-suppression list
    (#683 review, Critical 1): assessing pre-suppression let two independently-baselined legs
    manufacture a brand-new, unbaselined critical on every subsequent run.
    """
    present_ids = {f.check_id for f in findings}
    out: list[Finding] = []
    for risk in _COMPOUND_RISKS:
        if not all(present_ids & group for group in risk.groups):
            continue
        contributing_ids = frozenset().union(*risk.groups)
        contributing = [f for f in findings if f.check_id in contributing_ids]
        contributing_rules = sorted({f.rule or f.check_id for f in contributing})
        message = risk.message + f" Contributing findings: {', '.join(contributing_rules)}."
        if any(_is_review_finding(f) for f in contributing):
            message += (
                " At least one contributing finding is itself a review-tier signal (confirm by "
                "hand, not a proven bug) — verify that leg manually before treating this chain as "
                "fully proven."
            )
        # Inherit the demotion tags from the legs, not just from this synthetic finding's own
        # (empty) location: `prioritize()` demotes on `f.nonproduct`/`f.superseded`, neither of
        # which this finding sets on its own, so a compound with no genuinely live cross-group
        # chain would otherwise still emit a full-severity CRITICAL, undoing the repo's own triage
        # decision (#683 review, High 5).
        #
        # A `CompoundRisk` is AND-composed over its `groups` (every group needs its own live
        # member for the chain to be real), so the demotion must be too: demote only if there
        # EXISTS a group whose entire membership is nonproduct — that group can never supply a
        # live leg, so no all-live combination across groups is possible, regardless of how live
        # the OTHER groups are. Taking `all()`/`any()` over the flat union of every contributing
        # finding (the original shape) collapses the group structure: it demotes only when EVERY
        # finding anywhere is nonproduct, so one live finding in an unrelated group masks an
        # entirely-nonproduct group and leaves the compound undemoted — reproduced on pair 3
        # (secret leg ONLY in evals/, exec leg live still emitted an undemoted CRITICAL,
        # #683 fix-commit re-review, High 1). Per-group `all()`, then `any()` across groups,
        # verified against that repro plus the both-live and both-fully-nonproduct cases.
        nonproduct = any(
            all(f.nonproduct for f in findings if f.check_id in group) for group in risk.groups
        )
        history_groups = [
            group for group in risk.groups if all(f.superseded for f in findings if f.check_id in group)
        ]
        superseded = bool(history_groups)
        # Name the dump behind the demotion only when the demoting legs agree on one: each dump
        # governs its own subtree, so legs in two apps can be answered by two dumps, and naming
        # either would misstate the other (`findings.history_note` falls back to "a schema dump").
        dumps = {
            f.superseded_by for f in findings
            if f.superseded_by and any(f.check_id in group for group in history_groups)
        }
        superseded_by = next(iter(dumps)) if len(dumps) == 1 else None
        out.append(Finding(
            check_id="compounding-risk",
            severity=risk.severity,
            title=risk.title,
            message=message,
            remediation=risk.remediation,
            rule=f"compounding-risk/{risk.slug}",
            # OWASP-family tokens dropped (non-OWASP tags like CWE-506 kept): `compounding-risk`
            # mints its own check_id with no checklist mapping, by design (see the module's "Why no
            # checklist item" doc) — but the guard↔checklist reflection gate DOES key off the real
            # pipeline's output regardless of registry membership, precisely so a check emitting
            # OWASP-family tokens through any path gets caught. Mapping this into `check_ids` would
            # misrepresent an aggregation as an independently verifiable checklist item; carrying no
            # OWASP-family tag is the honest alternative (#683 review, High 3). `_COMPOUND_RISKS`
            # itself carries no OWASP-family tags any more either (#683 fix-commit re-review, Low 3
            # — the table used to list them purely as documentation even though they were always
            # filtered out here, which read as if they were actually emitted); this filter now
            # exists as a backstop against a future entry re-adding one rather than as the thing
            # doing the day-to-day stripping.
            standards=[s for s in risk.standards if not s.split(":", 1)[0].startswith("OWASP")],
            nonproduct=nonproduct,
            superseded=superseded,
            superseded_by=superseded_by,
        ))
    return out
