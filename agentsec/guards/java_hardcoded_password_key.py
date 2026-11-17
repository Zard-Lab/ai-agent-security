"""Guard: hardcoded password/key literal passed to a named security-sensitive Java API
(checklist §8, extends `8-hardcoded-private-key-in-source`).

    DriverManager.getConnection(url, "dbuser", "s3cr3tP@ss");

A **constant string literal** passed directly as the password/key argument to one of a small set
of named security-sensitive Java APIs is CWE-321 (Use of Hard-coded Cryptographic Key) — the same
weakness class as agentsec's existing `hardcoded-private-key-in-source` guard, but a genuinely
different code surface and detection mechanism. That guard greps for a literal PEM private-key
header (`-----BEGIN ... PRIVATE KEY-----`) anywhere in any file, language-agnostic — it has no
notion of a Java method call at all. This guard is Java-specific: it recognizes a **named API
call shape** (`DriverManager.getConnection(url, user, password)`, `new PBEKeySpec(...)`,
`new SecretKeySpec(...)`) and fires when the security-sensitive argument is a literal rather than
a variable, env-var lookup, or other runtime value. The two guards complement rather than
duplicate each other; both extend the same checklist item (`8-hardcoded-private-key-in-source`),
which was already declared `applies_when: []` (universal) before this guard existed and is left
that way — a hardcoded JDBC password is just as real outside a full "java" stack detection (e.g.
a lone `.java` utility script in an otherwise non-Java repo).

Pattern verified against Find Security Bugs' real source (sink list
`password-methods/password-methods-all.txt`, rules `HARD_CODE_PASSWORD`/`HARD_CODE_KEY`) — the
file and rule ids are cited for provenance; detection logic and test fixtures here are original,
developed independently against the pattern description, not copied or derived from that (Java)
source.

Fires CRITICAL on:

  * **`DriverManager.getConnection(url, user, "literalPassword")`** — the JDBC 3-argument form,
    when the final (password) argument is a literal string. This is the PRIMARY, most reliable
    pattern (lowest false-positive risk: a 3-arg `getConnection` call's third argument is
    unambiguously the password by the JDBC API contract) and the guard's canary plant.
  * **`new PBEKeySpec("literalPassword".toCharArray(), ...)`** — a literal string converted
    directly to a `char[]` and passed as PBE key material.
  * **`new SecretKeySpec("literalKey".getBytes(), ...)`** — a literal string converted directly to
    a `byte[]` and passed as raw key material.

A password/key that is a variable, a method call result (other than the two literal-to-array
conversions above), or an environment/config lookup (`System.getenv(...)`, `System.getProperty(...)`)
does **not** fire — only a literal string in the sensitive argument position does.

CWE-321, OWASP:A04.

Suppress an audited case (e.g. a documented decoy/test fixture) with:

    DriverManager.getConnection(url, "dbuser", "s3cr3tP@ss"); // security: allow-hardcoded-password-key
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    is_nonproduct_path,
    iter_files,
    java_scan_dirs,
    read,
    rel,
    strip_java_comments,
)

# DriverManager.getConnection(url, user, password) — the 3-argument JDBC form. The first two
# arguments (url, user) may be anything (a variable, a literal, a method call); only the FINAL
# argument (password) must be a plain double-quoted string literal to fire — an escape-aware
# literal so a `\"` inside the password does not terminate the match early. `[^,]+` for the first
# two args is deliberately permissive (they are not the sensitive argument, so over-matching their
# shape costs nothing), but excludes bare commas so nested calls with commas inside are not
# perfectly handled — an accepted textual-scanner limitation (see the wiki doc's Known bypasses).
_JDBC_LITERAL_PASSWORD = re.compile(
    r'\bDriverManager\s*\.\s*getConnection\s*\('
    r'\s*[^,]+,\s*[^,]+,\s*"(?:[^"\\]|\\.)*"\s*\)'
)
# new PBEKeySpec("literal".toCharArray(), ...) — a literal string converted directly to a char[]
# and passed as PBE key material. Escape-aware literal, same rationale as above.
_PBE_KEY_SPEC_LITERAL = re.compile(
    r'\bnew\s+PBEKeySpec\s*\(\s*"(?:[^"\\]|\\.)*"\s*\.\s*toCharArray\s*\(\s*\)'
)
# new SecretKeySpec("literal".getBytes(), ...) — a literal string converted directly to a byte[]
# and passed as raw key material.
_SECRET_KEY_SPEC_LITERAL = re.compile(
    r'\bnew\s+SecretKeySpec\s*\(\s*"(?:[^"\\]|\\.)*"\s*\.\s*getBytes\s*\('
)
_PRAGMA = "security: allow-hardcoded-password-key"

_STANDARDS = ["CWE-321", "OWASP:A04"]


class JavaHardcodedPasswordKeyGuard(Guard):
    id = "java-hardcoded-password-key"
    title = "Hardcoded password/key literal passed to a security-sensitive Java API"
    area = "Secrets"

    # HardcodedJdbcPassword.java: DriverManager.getConnection with a literal password ->
    # java-hardcoded-password-key/literal-jdbc-password.
    canary_plant = CanaryPlant(
        files={
            "HardcodedJdbcPassword.java": (
                "import java.sql.Connection;\n"
                "import java.sql.DriverManager;\n\n"
                "class HardcodedJdbcPassword {\n"
                "    Connection connect() throws Exception {\n"
                '        return DriverManager.getConnection('
                '"jdbc:mysql://db/app", "dbuser", "s3cr3tP@ss");\n'
                "    }\n"
                "}\n"
            ),
        },
        expects=frozenset({"java-hardcoded-password-key/literal-jdbc-password"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "java" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in java_scan_dirs(root, profile):
            for f in iter_files(d, (".java",)):
                if f in seen:
                    continue
                seen.add(f)
                # `credential_scan=True`: skip the fake-credential trees (`src/test/java`,
                # `fixtures/`) but keep DEPLOYMENT trees (`migrations/`, `alembic/`) in scope —
                # a password committed there is a REAL leak. See `is_nonproduct_path` (#483).
                if is_nonproduct_path(rel(root, f), profile.archive_segments, credential_scan=True):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # The pragma check runs on the COMMENT-ONLY view of the line — it IS the comment
        # `strip_java_comments` below would blank, and a string quoting it must not count (#424).
        view_lines = comment_view(text, "java").splitlines()  # same length: comments only (#424)
        # `strip_java_comments` preserves length and splitlines() count exactly (tested), so the
        # two line lists always pair up — `strict=True` documents that invariant.
        code_lines = strip_java_comments(text).splitlines()
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA in view:
                continue
            if _JDBC_LITERAL_PASSWORD.search(line):
                out.append(self._jdbc_finding(root, f, i))
            elif _PBE_KEY_SPEC_LITERAL.search(line):
                out.append(self._pbe_finding(root, f, i))
            elif _SECRET_KEY_SPEC_LITERAL.search(line):
                out.append(self._secret_key_finding(root, f, i))
        return out

    def _jdbc_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title="Hardcoded JDBC password literal in DriverManager.getConnection(...)",
            location=f"{rel(root, f)}:{line}",
            message=(
                "The password argument to DriverManager.getConnection(...) is a literal string, "
                "not a variable or environment/config lookup — the database credential is "
                "committed to version control and readable by anyone who can read this repo."
            ),
            remediation=(
                "Load the password from a secrets manager, environment variable, or config file "
                "excluded from version control instead of embedding it as a literal. Suppress an "
                "audited/intentional case (e.g. a documented decoy fixture) with "
                "`// security: allow-hardcoded-password-key` on the offending line."
            ),
            rule="java-hardcoded-password-key/literal-jdbc-password",
            standards=list(_STANDARDS),
        )

    def _pbe_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title="Hardcoded password literal passed to new PBEKeySpec(...)",
            location=f"{rel(root, f)}:{line}",
            message=(
                "A literal string, converted directly via .toCharArray(), is passed as the "
                "password argument to PBEKeySpec — the key-derivation password is committed to "
                "version control and readable by anyone who can read this repo."
            ),
            remediation=(
                "Load the password from a secrets manager or environment variable instead of "
                "embedding it as a literal. Suppress an audited/intentional case with "
                "`// security: allow-hardcoded-password-key` on the offending line."
            ),
            rule="java-hardcoded-password-key/literal-pbe-key-spec",
            standards=list(_STANDARDS),
        )

    def _secret_key_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title="Hardcoded key literal passed to new SecretKeySpec(...)",
            location=f"{rel(root, f)}:{line}",
            message=(
                "A literal string, converted directly via .getBytes(), is passed as raw key "
                "material to SecretKeySpec — the cryptographic key is committed to version "
                "control and readable by anyone who can read this repo."
            ),
            remediation=(
                "Load the key from a secrets manager or generate it at runtime instead of "
                "embedding it as a literal. Suppress an audited/intentional case with "
                "`// security: allow-hardcoded-password-key` on the offending line."
            ),
            rule="java-hardcoded-password-key/literal-secret-key-spec",
            standards=list(_STANDARDS),
        )
