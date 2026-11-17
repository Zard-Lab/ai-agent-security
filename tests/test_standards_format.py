"""Standards-token FORMAT gate.

Guards and checklist items both carry `standards` tokens (`OWASP:A05`, `OWASP-LLM:LLM02`,
`CIS:Docker`, `CWE-352`, ...). Two format invariants that need no taxonomy judgment:

1. **CWE tokens are the canonical hyphen form `CWE-<n>`** (MITRE's spelling + the checklist's
   regex-enforced `cwe` field), never the colon form `CWE:<n>`. Guards historically drifted to
   `CWE:` (20 guards, normalized in this change) — this gate keeps them from drifting back.
2. **Every standards token has a sane `NAMESPACE:suffix` shape** (or a known bareword), so a
   malformed tag can't slip in.

Beyond format, a third gate enforces the guard↔checklist *semantic* reflection: every OWASP-family
standard a guard emits must appear on at least one checklist item that maps to it (its `check_ids`).
That's `test_guard_standards_reflected_on_checklist` below — the gate that would have caught #285's
`OWASP-API:` vs guard `OWASP:API` mismatch (both pass the format-only checks). Reconciled in #291
(guard-level "at least one", per #259); CWE/ASVS-exact + CIS/NIST are out of its scope (the checklist
keeps a separate `cwe` scalar; the finer namespaces are a separate curation pass).

That reflection RULE lives in exactly one place — `scripts/validate-checklist.py` — and is imported
below. `scripts/validate-checklist.py` is the fast pre-flight runner for the same rule (this test is
`slow`-marked, so a `-m "not slow"` run misses it); the two differ only in where the `emitted`
mapping comes from (this test computes it fresh from the canary audit; the script reads it from a
guard-source-keyed cache). Do not re-implement the rule here — two implementations that disagree
would be worse than one slow one.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agentsec.audit import AuditResult

from .conftest import SharedAudit, load_validator

_REPO = Path(__file__).resolve().parent.parent

# The single implementation of the reflection rule (see the module docstring), loaded through the
# shared one-instance loader so both test modules hold the SAME module object.
validate_checklist = load_validator()
_GUARDS_DIR = _REPO / "agentsec" / "guards"
_CHECKLIST = _REPO / "agentsec" / "checklist" / "checklist.json"

# A well-formed token: `NAMESPACE:suffix` (e.g. OWASP-LLM:LLM02, CIS:6.3) or a known bareword.
_TOKEN_SHAPE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:[A-Za-z0-9][\w.\-/]*$")
_BAREWORD_ALLOW = frozenset({"PCI-DSS"})
_CWE = re.compile(r"^CWE[:-]")
_CWE_CANONICAL = re.compile(r"^CWE-\d+$")


def _emitted_standards(result: AuditResult) -> set[str]:
    """Every standards token guards actually emit, sourced from the canary audit (the same
    pipeline `run_canary` uses — every guard fires there)."""
    return {s for f in result.findings for s in f.standards}


def _checklist_standards() -> set[str]:
    data = json.loads(_CHECKLIST.read_text(encoding="utf-8"))
    out: set[str] = set()

    def walk(o: object) -> None:
        if isinstance(o, dict):
            for s in o.get("standards", []) or []:
                out.add(s)
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(data)
    return out


def test_cwe_tokens_use_canonical_hyphen_form() -> None:
    """No `CWE:<n>` (colon) anywhere in guard sources or the checklist — CWE IDs are `CWE-<n>`."""
    offenders: list[str] = []
    for p in [*sorted(_GUARDS_DIR.glob("*.py")), _CHECKLIST]:
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"CWE:\d", line):
                offenders.append(f"{p.relative_to(_REPO)}:{i}: {line.strip()}")
    assert not offenders, "CWE tokens must be the hyphen form CWE-<n>, not CWE:<n>:\n" + "\n".join(offenders)


@pytest.mark.slow
def test_all_standards_tokens_are_well_formed(canary_audit: SharedAudit) -> None:
    """Every standards token (guards + checklist) is a `NAMESPACE:suffix` or a known bareword,
    and any CWE token is the canonical `CWE-<n>`."""
    bad: list[str] = []
    for tok in sorted(_emitted_standards(canary_audit.load()) | _checklist_standards()):
        if _CWE.match(tok):
            if not _CWE_CANONICAL.match(tok):
                bad.append(f"{tok!r} (CWE must be CWE-<digits>)")
        elif tok not in _BAREWORD_ALLOW and not _TOKEN_SHAPE.match(tok):
            bad.append(f"{tok!r} (not NAMESPACE:suffix nor a known bareword)")
    assert not bad, "malformed standards tokens:\n  " + "\n  ".join(bad)


def test_project_json_uses_literal_unicode_not_escapes() -> None:
    """No project JSON may carry `\\uXXXX` escapes — the repo writes every JSON with
    `ensure_ascii=False` (config/exceptions/intake/coverage/drift/cli all do; `exceptions.py`
    documents it and names `checklist.json`), so em-dashes/arrows/§ live as literal unicode. A tool
    that re-dumps with the default `ensure_ascii=True` regresses this silently — it happened (113
    `\\u2014` escapes lived in `checklist.json`). Scans `agentsec/` + `docs/` + the root exceptions
    file; `tests/fixtures/` is out of scope (like the linters)."""
    escape = re.compile(r"\\u[0-9a-fA-F]{4}")
    roots = [_REPO / "agentsec-exceptions.json"]
    for d in (_REPO / "agentsec", _REPO / "docs"):
        roots.extend(sorted(d.rglob("*.json")))
    offenders: dict[str, list[str]] = {}
    for p in roots:
        if not p.is_file():
            continue
        found = escape.findall(p.read_text(encoding="utf-8"))
        if found:
            offenders[str(p.relative_to(_REPO))] = sorted(set(found))
    assert not offenders, (
        "project JSON must use literal unicode, not \\uXXXX escapes "
        f"(re-dump with ensure_ascii=False): {offenders}"
    )


# The reflection rule's three pieces, owned by scripts/validate-checklist.py (see module doc).
_owasp_family = validate_checklist.owasp_family
_reflection_drift = validate_checklist.reflection_drift


def _emitted_by_guard(result: AuditResult) -> dict[str, set[str]]:
    """guard-id -> the OWASP-family standards it emits, from the canary audit (every guard fires
    there, so coverage is complete — kept in lockstep with the liveness canary)."""
    out: dict[str, set[str]] = {}
    for f in result.findings:
        out.setdefault(f.check_id, set()).update(s for s in f.standards if _owasp_family(s))
    return out


def _checklist_by_guard() -> dict[str, set[str]]:
    """guard-id -> union of `standards` on every checklist item whose `check_ids` include it."""
    data = json.loads(_CHECKLIST.read_text(encoding="utf-8"))
    return validate_checklist.checklist_standards_by_guard(data)


@pytest.mark.slow
def test_guard_standards_reflected_on_checklist(canary_audit: SharedAudit) -> None:
    """Guard↔checklist reflection (the semantic gate the module doc describes). Every OWASP-family
    standard a guard emits must appear on at least one checklist item that maps to it (`check_ids`).

    Guard-LEVEL "at least one" (per #259), not per-item ⊇: a multi-rule guard (e.g. `ai-docker`,
    whose port rule is LLM01 and volume rule is LLM04) is satisfied as long as each token lands on
    one of its covered items — we don't force every rule's tag onto every item.

    Reconciled in #291 (11 guards). To fix a failure: align the guard's `_STANDARDS` to the taxonomy
    on its item, or add the token to the item — not whichever makes CI green (that launders a wrong
    tag). See .claude/issues/issue-291.md for the decision record.

    The comparison itself is `validate_checklist.reflection_drift` — the one implementation of the
    rule, shared with `scripts/validate-checklist.py`. Change it THERE, not here."""
    adrift = _reflection_drift(_emitted_by_guard(canary_audit.load()), _checklist_by_guard())
    assert not adrift, (
        "guard OWASP-family standards must be reflected on a mapped checklist item "
        "(align the guard `_STANDARDS` or the item — see .claude/issues/issue-291.md):\n  "
        + "\n  ".join(adrift)
    )
