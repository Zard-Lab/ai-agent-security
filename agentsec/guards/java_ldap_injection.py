"""Guard: LDAP query built from string concatenation in Java application code (checklist §3b).

The Java counterpart to agentsec's existing Python `ldap-injection` guard (same requirement — a
directory search whose base-DN or filter argument is built from untrusted input without escaping
lets an attacker inject LDAP filter/DN syntax, e.g. `*)(uid=*))(|(uid=*`, altering which entries
match; depending on what the query gates this ranges from information disclosure to authentication
bypass), a genuinely different code surface (JNDI's `javax.naming.directory` API / Spring LDAP
instead of `python-ldap`/`ldap3`), so it extends the same `3b-ldap-injection` checklist item rather
than duplicating it. CWE-90, OWASP:A03.

Pattern verified against Find Security Bugs' real source (`LdapInjectionDetector.java`, rule
`LDAP_INJECTION`, sink list `injection-sinks/ldap.txt`, covering `DirContext.search`,
`InitialDirContext.search`, `LdapContext.search`, and Spring LDAP's `LdapTemplate.search`/
`.lookup`) — the class name and rule id are cited for provenance; detection logic and test
fixtures here are original, developed independently against the pattern description, not copied
or derived from that (Java) source. Like every guard in this codebase, this scans text/regex, not
an AST — there is no symbol table, so the receiver of `.search(`/`.lookup(` cannot be resolved to
its declared type. Scoping is done by a receiver **name** convention instead (see below), the same
tradeoff `agentsec/guards/ldap_injection.py` made for ldap3's bare `.search(` (there, gated on
`search_base=`/`search_filter=` kwargs rather than a name).

Fires MEDIUM on a directory search/lookup call whose receiver name suggests it is LDAP-related —
`ctx`, or any identifier containing `DirContext`/`LdapContext` (`.search(` only, matching JNDI's
`DirContext`/`InitialDirContext`/`LdapContext` API), or any identifier containing `LdapTemplate`
(`.search(` or `.lookup(`, matching Spring LDAP) — whose call line also contains a `+`
concatenation. **Deliberate FP-risk tradeoff** (see the wiki doc's "Known bypasses" section): a
bare `.search(`/`.lookup(` is far too generic a method name to trust alone (`re.search`, a cache
client, a `List`/`Map` lookup all share it), so this guard requires the receiver name to look
LDAP-related — a real but narrower net than resolving the declared type would be; a `DirContext`
variable named something other than `ctx`/`*DirContext*`/`*LdapContext*` is missed, and conversely
any non-LDAP object a developer happens to name `ctx` with an unrelated `.search(` method is a
possible false positive. Accepted as the same class of naming-convention tradeoff the sibling
Python guard already makes.

Suppress an audited case (e.g. the concatenated portion is a compile-time constant, or already
escaped by a helper this guard doesn't recognize) with:

    ctx.search(base, "(uid=" + username + ")", controls);  // security: allow-ldap-injection
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

# JNDI's DirContext/InitialDirContext/LdapContext family: <receiver>.search(...). Receiver scoped
# to the literal conventional name `ctx`, or any identifier containing "DirContext"/"LdapContext"
# (covers InitialDirContext, InitialLdapContext, a field/local named dirContext/ldapContext, ...).
# `.lookup(` is intentionally NOT included here — JNDI's plain `Context.lookup(name)` is a much
# broader, non-LDAP-specific API (any JNDI resource), out of scope for this guard.
_DIR_CONTEXT_SEARCH = re.compile(
    r"\b(?:ctx|\w*(?:DirContext|LdapContext)\w*)\s*\.\s*search\s*\(", re.IGNORECASE
)
# Spring LDAP's LdapTemplate: <receiver>.search(...) / <receiver>.lookup(...) — both are real
# LdapTemplate methods that take a filter/name argument.
_LDAP_TEMPLATE_CALL = re.compile(
    r"\b\w*LdapTemplate\w*\s*\.\s*(?:search|lookup)\s*\(", re.IGNORECASE
)
# String concatenation shape: a quoted literal or identifier, `+`, another quoted literal or
# identifier — same shape as the sibling Python `ldap-injection` guard's `_DYNAMIC_ARG` narrowed
# to just the `+` case (Java has no f-string/`.format(` equivalent as prevalent for this sink).
_CONCAT = re.compile(r"""(?:['"][^'"]*['"]|\w[\w.\[\]]*)\s*\+\s*(?:['"][^'"]*['"]|\w[\w.\[\]]*)""")
_PRAGMA = "security: allow-ldap-injection"


class JavaLdapInjectionGuard(Guard):
    id = "java-ldap-injection"
    title = "LDAP query built from string concatenation (Java)"
    area = "Code safety"

    # LdapAuth.java: ctx.search(base, "(uid=" + username + ")", ...) — the filter concatenated
    # inline in the call itself -> fires java-ldap-injection/concatenated-filter.
    canary_plant = CanaryPlant(
        files={
            "LdapAuth.java": (
                "import javax.naming.directory.DirContext;\n"
                "import javax.naming.directory.SearchControls;\n\n"
                "class LdapAuth {\n"
                "    void findUser(DirContext ctx, String username) throws Exception {\n"
                '        ctx.search("ou=users,dc=example,dc=com", "(uid=" + username + ")", '
                "new SearchControls());\n"
                "    }\n"
                "}\n"
            ),
        },
        expects=frozenset({"java-ldap-injection/concatenated-filter"}),
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
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
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
            if not _CONCAT.search(line):
                continue
            if _DIR_CONTEXT_SEARCH.search(line) or _LDAP_TEMPLATE_CALL.search(line):
                out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title="LDAP search built from string concatenation",
            location=f"{rel(root, f)}:{line}",
            message=(
                "This LDAP search/lookup call's base-DN or filter argument is built via string "
                "concatenation (`+`). An attacker who controls the concatenated portion can "
                "inject LDAP filter/DN syntax, altering which directory entries match."
            ),
            remediation=(
                "Avoid building the filter/name via string concatenation. Escape any untrusted "
                "portion before it reaches the query (there is no single standard JNDI escaper — "
                "hand-roll one against RFC 4515/4514, or use Spring LDAP's `LdapQueryBuilder` DSL, "
                "which encodes filter arguments safely). Suppress an audited case with "
                "`// security: allow-ldap-injection`."
            ),
            rule="java-ldap-injection/concatenated-filter",
            standards=["OWASP:A03"],
        )
