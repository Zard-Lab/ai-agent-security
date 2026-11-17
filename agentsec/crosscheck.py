"""Static ↔ Splinter cross-confirmation — the seam between the two DB-security lenses.

On a `live` audit, the static SQL guards and the ingested Supabase **Splinter** lint cover the
same ground from two lenses with opposite blind spots
(see `docs/knowledge/sql-guards-vs-splinter-division.md`). This pass correlates them and tags
each finding's **provenance**:

- ``confirmed-live`` — a static finding whose issue Splinter also reported (same lint + object).
- ``static-only`` — a Splinter-mapped static finding Splinter did NOT report.
- ``splinter-only`` — a Splinter finding with no static match (object not in the checked-in SQL).

**Tag, don't demote.** A ``static-only`` finding is NOT evidence the issue is absent — it may be
historical OR a Splinter scope/blind gap (the very reason static guards exist; see
[[exposed-schema-rls-blind-spot]]). So provenance is informational; the only ranking effect is a
small BOOST for ``confirmed-live`` (in `prioritize`). Confirmed static+Splinter pairs are
**deduplicated** — the actionable `file:line` static finding is kept and tagged; the duplicate
Splinter entity finding is folded out (disclosed in the footer).

No Splinter findings present → complete no-op. Stdlib-only; pure-ish (reads SQL source lines).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from agentsec.findings import _LOCATION_LINE_SUFFIX, Finding

# Static-guard `check_id` → the Splinter lint(s) it mirrors (documented in each guard-design doc).
# A guard maps to one or more lint names; a match on ANY of them confirms.
_RULE_MAP: dict[str, tuple[str, ...]] = {
    "rls-permissive-policy": ("rls_policy_always_true",),
    "rls-multiple-permissive-policies": ("multiple_permissive_policies",),
    "policy-exists-rls-disabled": ("policy_exists_rls_disabled",),
    "public-table-rls": ("rls_disabled_in_public",),
    "pg-security-definer-view": ("security_definer_view",),
    "auth-users-not-exposed-via-view": ("auth_users_exposed",),
    "pg-extension-in-public": ("extension_in_public",),
    # A definer function granted EXECUTE to anon/public ↔ Splinter's executable-definer lints
    # (anon inherits public, so a `TO public` grant surfaces under both). The function-name match
    # only confirms the genuinely-definer ones, since Splinter only reports definer functions.
    "pg-anon-grant": (
        "anon_security_definer_function_executable",
        "authenticated_security_definer_function_executable",
    ),
}

# Per-guard regex to pull the flagged object (table / view / extension) out of the source line.
# A run of identifier chars incl. `.` (schema qualifier) and `"` (quoting) — flat, no nested
# quantifier (ReDoS-safe); `_norm_object` then drops the schema + quotes.
_OBJ = re.compile(r'[\w".]+')
_OBJ_PATTERNS: dict[str, re.Pattern[str]] = {
    "rls-permissive-policy": re.compile(r"\bON\s+(" + _OBJ.pattern + r")", re.IGNORECASE),
    "rls-multiple-permissive-policies": re.compile(r"\bON\s+(" + _OBJ.pattern + r")", re.IGNORECASE),
    "policy-exists-rls-disabled": re.compile(r"\bON\s+(" + _OBJ.pattern + r")", re.IGNORECASE),
    "public-table-rls": re.compile(
        r"\b(?:ALTER|CREATE)\s+TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(" + _OBJ.pattern + r")", re.IGNORECASE
    ),
    "pg-security-definer-view": re.compile(
        r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:MATERIALIZED\s+)?VIEW\s+(" + _OBJ.pattern + r")", re.IGNORECASE
    ),
    "auth-users-not-exposed-via-view": re.compile(
        r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:MATERIALIZED\s+)?VIEW\s+(" + _OBJ.pattern + r")", re.IGNORECASE
    ),
    "pg-extension-in-public": re.compile(
        r"\bCREATE\s+EXTENSION\s+(?:IF\s+NOT\s+EXISTS\s+)?(" + _OBJ.pattern + r")", re.IGNORECASE
    ),
    # the granted routine's name (only function grants match the definer-fn lints; schema/table
    # grants extract a non-function object that won't match, → static-only, which is correct)
    "pg-anon-grant": re.compile(
        r"\bON\s+(?:ALL\s+)?(?:FUNCTION|ROUTINE|PROCEDURE)S?\s+(" + _OBJ.pattern + r")", re.IGNORECASE
    ),
}


@dataclass
class CrosscheckResult:
    findings: list[Finding]
    confirmed: int = 0       # static findings confirmed live
    static_only: int = 0     # mapped static findings not seen live
    splinter_only: int = 0   # Splinter findings not in the SQL
    splinter_only_objects: int = 0  # distinct (lint, object) among splinter-only (count not inflated by granularity)
    deduped: int = 0         # duplicate Splinter findings folded into a confirmed static one


def _norm_object(raw: str) -> str:
    """Normalize an object name for matching: drop the schema qualifier + quotes, lowercase.
    `"public"."documents_1024"` / `public.documents_1024` / `documents_1024` → `documents_1024`."""
    part = raw.strip().strip(";").split(".")[-1]
    return part.strip().strip('"').strip("'").lower()


def _static_object(f: Finding, root: Path) -> str | None:
    """The object a mapped static finding flags — read from its source line(s)."""
    pat = _OBJ_PATTERNS.get(f.check_id)
    if pat is None or not f.location:
        return None
    suffix = _LOCATION_LINE_SUFFIX.search(f.location)
    rel = f.location[: len(f.location) - len(suffix.group(0))] if suffix else f.location
    lineno = int(suffix.group(0).lstrip(":").split(":")[0]) if suffix else 1
    try:
        lines = (root / rel).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None
    window = "\n".join(lines[lineno - 1 : lineno + 3])  # statement may span a few lines
    m = pat.search(window)
    return _norm_object(m.group(1)) if m else None


def crosscheck(findings: list[Finding], root: Path) -> CrosscheckResult:
    """Tag provenance and dedup confirmed pairs. No-op when no Splinter findings are present."""
    splinter = [f for f in findings if f.check_id == "splinter"]
    if not splinter:
        return CrosscheckResult(findings)

    # Splinter index keyed (lint, object). `rule` is `splinter-<lint>`; `location` is the entity.
    index: dict[tuple[str, str], list[Finding]] = {}
    for sf in splinter:
        lint = (sf.rule or "").removeprefix("splinter-")
        index.setdefault((lint, _norm_object(sf.location)), []).append(sf)

    matched_splinter: set[int] = set()
    res = CrosscheckResult(findings=[])
    for f in findings:
        mapped = _RULE_MAP.get(f.check_id)
        if mapped is None:
            continue
        obj = _static_object(f, root)
        hits = [sf for lint in mapped for sf in index.get((lint, obj), [])] if obj else []
        if hits:
            f.provenance = "confirmed-live"
            res.confirmed += 1
            for sf in hits:
                matched_splinter.add(id(sf))
        else:
            f.provenance = "static-only"
            res.static_only += 1

    kept: list[Finding] = []
    so_objects: set[tuple[str, str]] = set()
    for f in findings:
        if f.check_id == "splinter":
            if id(f) in matched_splinter:
                res.deduped += 1   # folded into a confirmed static finding
                continue
            f.provenance = "splinter-only"
            res.splinter_only += 1
            so_objects.add(((f.rule or ""), _norm_object(f.location)))
        kept.append(f)
    res.splinter_only_objects = len(so_objects)
    res.findings = kept
    return res
