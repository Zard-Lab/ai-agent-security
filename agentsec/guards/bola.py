"""Guard: object-level authorization (BOLA) — fetch not scoped to the caller (§2b).

Broken Object-Level Authorization is OWASP API #1, the most-exploited API class:
a route takes an object id (`GET /orders/{order_id}`) and fetches/returns that
object **without checking it belongs to the authenticated caller**, so user A
reads user B's order by guessing the id (IDOR). Authentication (logged-in) does
not imply authorization (allowed *this* object).

This is a **surfacing** guard, like lethal-trifecta: BOLA can't be proven from
source (the guard can't know an ownership check is correct), so it flags the
*architecture* for human review rather than asserting a bug — hence `partial`
coverage of `2b-authorization-enforced`, severity MEDIUM (review).

Conservative — fires only when a route handler has ALL of:
  * a route decorator (`@app.get(...)` / `@router.post(...)`);
  * an object-id path parameter (`{id}` / `{order_id}` / `{pk}` / `{uuid}`);
  * a fetch-by-id in the body (`.query.get`, `.filter`, `get_object_or_404`,
    `session.get`, `.find_one`, or a supabase `.select(...).eq(...)` chain);
  * **no** authorization/ownership signal anywhere in the function (no
    `current_user`, an auth-named `Depends(get_current_user)`, `user_id`, `owner`, `403`, …;
    a bare non-auth `Depends(get_db)` does NOT count — issue #307).

Suppress an audited handler with `# security: allow-unscoped-fetch`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    AUTH_DEP_SIGNAL,
    CanaryPlant,
    Guard,
    boundaried_stems,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_ROUTE_DECORATOR = re.compile(r"@\s*[\w.]+\.(?:get|post|put|patch|delete)\s*\(")
_ID_IN_PATH = re.compile(r"\{[A-Za-z_]*(?:id|pk|uuid)[A-Za-z_]*\}", re.IGNORECASE)
_FETCH_SIMPLE = re.compile(
    r"get_object_or_404\(|\.query\.get\(|\.filter(?:_by)?\(|session\.get\(|"
    r"\bdb\.get\(|\.find_one\(|\.get_or_404\("
)
# An ownership/authorization signal anywhere in the handler body suppresses the finding. bola's OWN
# collision-prone vocabulary — `permission`, `scope`, `require`, and the ownership terms `owner`/`tenant`
# — is boundary-anchored via `boundaried_stems` so a stem can't bleed into an unrelated identifier
# (`scope`⊄`telescope`, `require`⊄`required`, `tenant`⊄`lieutenant` — issues #307/#345) while legit
# plurals (`scopes`, `permissions`, `owners`) still suppress. Deliberately a NARROW set: this is a free
# body-text scan, so it must NOT inherit the shared `_AUTH_NAME`'s full Depends-naming stem list
# (`token|role|user|login|verify|current`), which silences genuine BOLA routes on an incidental
# `token`/`role`/`user` mention (#345 review). The already-specific literals (`current_user`,
# `request.user`, `user_id`, `\bauth\b`, `is_admin`, `403`, `Forbidden`) and the name-gated
# `Depends(...)` (`AUTH_DEP_SIGNAL`) are kept as-is.
#
# Trade-off of boundary-anchoring (#364 review): the `-ed`/`-ment`/`-ship` derivations of the anchored
# stems are NOT suppressors — only the bare stem and its plural are. That is correct for the non-auth
# ones (`unscoped`, `requirement(s)`, `scoped_session` SHOULD fire), but the `ownership*` family is a
# genuine ownership signal, so it is recovered as an explicit `ownership` literal. `scoped*` is left
# unrecovered on purpose: it is ambiguous (`scoped_session` is a DB construct, not ownership), and
# firing is the safe direction for this false-negative-biased surfacing guard.
_AUTH = re.compile(
    r"current_user|request\.user|get_current_user|user_id|ownership|\bauth\b|is_admin|\b403\b|Forbidden|"
    + AUTH_DEP_SIGNAL + r"|" + boundaried_stems("scope|require|owner|tenant", "permission"),
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-unscoped-fetch")


def _has_fetch(block: str) -> bool:
    if _FETCH_SIMPLE.search(block):
        return True
    return ".select(" in block and ".eq(" in block


class BolaGuard(Guard):
    id = "bola"
    title = "Object-level authorization (BOLA) — fetch not scoped to the caller"
    area = "Login & access"
    # Surfacing: this guard points at an ARCHITECTURE to confirm by hand, it does not prove a
    # bug. Read by `findings._is_review_finding()` (report footer) and `prioritize.confidence()`,
    # which ranks a surfacing finding below a proven one of the same severity.
    surfacing = True

    # a route that fetches an object by id with no ownership check -> bola.
    canary_plant = CanaryPlant(
        files={
            "orders.py": (
                "from fastapi import APIRouter\n\n"
                "router = APIRouter()\n\n\n"
                "@router.get(\"/orders/{order_id}\")\n"
                "async def get_order(order_id: str):\n    return Order.query.get(order_id)\n"
            ),
        },
        expects=frozenset({"bola/unscoped-object-fetch"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "fastapi" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        for lineno, block in iter_functions(read(f), filename=f):
            # A real comment in the route block only, never the phrase in a string there (#1040).
            if pragma_present(_PRAGMA, block, dialect="python"):
                continue
            if not _ROUTE_DECORATOR.search(block):
                continue
            if not _ID_IN_PATH.search(block):
                continue
            if not _has_fetch(block):
                continue
            if _AUTH.search(block):
                continue
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title="Object fetched by id with no ownership check (possible BOLA/IDOR)",
                location=f"{rel(root, f)}:{lineno}",
                message=(
                    "This route looks up an object by an id from the URL but shows no sign of "
                    "checking the object belongs to the authenticated caller — so user A can read "
                    "user B's record by changing the id (OWASP API #1, BOLA/IDOR). Review by hand: "
                    "a finding here means the ownership check is not visible, not that it is absent."
                ),
                remediation=(
                    "Scope the query to the caller (`...filter(owner_id == current_user.id)` / "
                    "supabase `.eq(\"user_id\", current_user.id)`) and return 404 (not 403) when it "
                    "doesn't match, so ids aren't enumerable. If authorization is enforced elsewhere "
                    "(a dependency/middleware), suppress with `# security: allow-unscoped-fetch`."
                ),
                rule="bola/unscoped-object-fetch",
                standards=["OWASP:A01"],
            ))
        return out
