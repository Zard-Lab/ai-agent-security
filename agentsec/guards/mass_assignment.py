"""Guard: ORM mass-assignment from request dict without an explicit field allowlist (§3a).

A common pattern in FastAPI/SQLAlchemy CRUD code is to unpack the full Pydantic
request model directly into a database update:

    # DANGEROUS — every field the caller sends is written to the DB row:
    for field, value in update_data.dict().items():
        setattr(db_user, field, value)

    # DANGEROUS — SQLAlchemy update().values() from the full request body:
    stmt = update(User).values(**body.dict())

When the ORM model has sensitive fields (is_admin, role, is_verified, balance) that
the request schema also exposes, any caller who sends those field names can promote
themselves, zero their balance, or flip their verification status. The risk exists
even when the Pydantic model is "clean" — schema drift, inheritance, or a future
field addition silently widens the attack surface without touching the CRUD code.

The safe pattern is an **explicit allowlist**: copy only the fields you intend to
update, either by naming them individually or by using Pydantic's `include=` /
`exclude=` options:

    # SAFE — explicit field selection:
    user.name = body.name
    user.email = body.email

    # SAFE — SQLAlchemy update with named params only:
    stmt = update(User).values(name=body.name, email=body.email)

Three statically detectable patterns:

    **Pattern 1 — ORM loop + setattr** (HIGH): A `for field, value in
    <var>.dict()/.model_dump().items()` loop immediately followed (same or adjacent
    line) by a `setattr(` call. This is the canonical mass-assignment pattern
    produced by many FastAPI CRUD tutorials and AI code generators.

    **Pattern 2 — update().values(**request.dict())** (HIGH): A SQLAlchemy
    `update(...).values(**<request|body|data|payload>.dict()/model_dump())` call —
    the full request dict splatted into an UPDATE statement.

    **Pattern 3 — field = request.dict()** (HIGH): A model field set to the entire
    return value of `.dict()`/`.model_dump()` on a request object, indicating the
    full payload dict is stored without field-level filtering.

**Why HIGH?** Horizontal privilege escalation via field smuggling is low-effort for
attackers (add a JSON key to an existing request), hard to detect in logs, and
silently exploitable on schema drift. OWASP API3:2023 (Broken Object Property Level
Authorization) lists mass assignment as a critical API-layer risk.

**Suppress:** add `# security: allow-mass-assignment` anywhere in the file to
silence this check for that file (e.g. a migration script or a seeding fixture where
the behavior is intentional and reviewed).

**Checklist item:** `3a-mass-assignment`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, python_scan_dirs, read, rel

_PRAGMA = "security: allow-mass-assignment"

_STANDARDS = ["OWASP:A01", "CWE-915"]

# Pattern 1: for <field>, <value> in <var>.dict()/.model_dump().items()
# Matches the loop header. The loop body is checked for a setattr( call by scanning
# the next few lines of the file (multi-line pattern).
_LOOP_HEADER = re.compile(
    r"for\s+\w+,\s*\w+\s+in\s+\w+\.(?:dict|model_dump)\(\)\.items\(\)",
)

# setattr( anywhere on a line (used as the loop-body check)
_SETATTR = re.compile(r"\bsetattr\s*\(")

# Pattern 2: stmt.values(**<request|body|data|payload>.dict()/.model_dump())
_VALUES_SPLAT = re.compile(
    r"\.values\s*\(\s*\*\*(?:request|body|data|payload)\s*\.\s*(?:dict|model_dump)\s*\(\s*\)",
)

# Pattern 3: <db_obj>.<field> = <var>.dict()/.model_dump()
# e.g.  user.data = body.dict()
_FIELD_ASSIGN_DICT = re.compile(
    r"\b\w+\.\w+\s*=\s*\w+\.(?:dict|model_dump)\s*\(\s*\)",
)


class MassAssignmentGuard(Guard):
    id = "mass-assignment"
    title = "ORM/SQLAlchemy model updated from full request dict without an explicit field allowlist"
    area = "Code safety"

    # user_update.py: setattr(db_user, field, value) in a loop over .dict() items ->
    # fires mass-assignment.
    canary_plant = CanaryPlant(
        files={
            "user_update.py": (
                "def update_user(db_user, update_data):\n"
                "    for field, value in update_data.dict().items():\n"
                "        setattr(db_user, field, value)\n"
                "    return db_user\n"
            ),
        },
        expects=frozenset({"mass-assignment/orm-update-from-request"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()

        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                out.extend(self._check_file(root, f, text))

        return out

    def _check_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()

        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue

            # Pattern 1: loop header followed by setattr in the loop body
            if _LOOP_HEADER.search(line):
                # Scan up to 5 subsequent lines for a setattr call (typical body is 1-3 lines)
                header_indent = len(line) - len(line.lstrip())
                body_end = min(i + 6, len(lines))
                for body_line in lines[i + 1 : body_end]:
                    body_stripped = body_line.lstrip()
                    # Blank and comment lines never end the body scan
                    if not body_stripped or body_stripped.startswith("#"):
                        continue
                    # Stop scanning if we leave the loop body (dedent to the header's level or outer)
                    if len(body_line) - len(body_stripped) <= header_indent:
                        break
                    if _SETATTR.search(body_line):
                        findings.append(self._finding(
                            root, f, i + 1,
                            "ORM mass-assignment loop: `for field, value in obj.dict().items()` "
                            "with `setattr()` in the body writes every request field to the "
                            "database row without an explicit allowlist.",
                            "Replace the loop with explicit field assignments (`db_obj.name = body.name`) "
                            "or use Pydantic's `include=` / `exclude=` options to restrict which fields "
                            "are passed. Never iterate the full request dict into `setattr` on a DB model.",
                        ))
                        break

            # Pattern 2: update().values(**body.dict())
            if _VALUES_SPLAT.search(line):
                findings.append(self._finding(
                    root, f, i + 1,
                    "`update(...).values(**request.dict())` splats the full request payload "
                    "into a SQLAlchemy UPDATE statement. Any field the caller sends is written "
                    "to the database row, including privileged fields like `is_admin` or `role`.",
                    "Pass only the intended columns as named keyword arguments: "
                    "`values(name=body.name, email=body.email)`. If you need to accept a "
                    "variable subset, build an explicit allowlist dict before the call.",
                ))

            # Pattern 3: db_obj.field = body.dict()
            if _FIELD_ASSIGN_DICT.search(line):
                findings.append(self._finding(
                    root, f, i + 1,
                    "A model field is assigned the full return value of `.dict()`/`.model_dump()`. "
                    "Storing an unfiltered request dict as a field value bypasses any "
                    "field-level validation the ORM model provides.",
                    "Assign individual fields explicitly or filter the dict to an allowlist "
                    "before assignment. Never store `body.dict()` directly as a field value "
                    "without field-level selection.",
                ))

        return findings

    def _finding(
        self,
        root: Path,
        f: Path,
        lineno: int,
        message: str,
        remediation: str,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=message,
            remediation=remediation,
            rule="mass-assignment/orm-update-from-request",
            standards=list(_STANDARDS),
        )
