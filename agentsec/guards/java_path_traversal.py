"""Guard: no path traversal via a tainted Java file-construction sink (checklist §3a).

The Java counterpart to agentsec's existing `path-traversal` (Python), `js-path-traversal` (JS/TS)
guards — same requirement (a file path assembled from a variable or concatenation, handed to a
file-construction sink, lets `../../etc/passwd` escape the intended directory), a genuinely
different code surface (`java.io.File`/`RandomAccessFile`/`java.nio.file.Paths`/`Files` instead of
`open`/`send_file`/`fs.readFile`), so it extends the same `3a-path-traversal-file-serving`
checklist item rather than duplicating it.

Pattern verified against Find Security Bugs' real source (rule `PATH_TRAVERSAL_IN`, sink list
`injection-sinks/path-traversal-in.txt`) — the rule id and sink list are cited for provenance; the
class names, files, and detection logic here are original, developed independently against the
pattern description, not copied or derived from that (Java) source.

Fires HIGH when one of the following sinks is constructed with an argument that is clearly NOT a
string literal — a bare identifier, a method call, or a concatenation involving a variable:

  * `new File(...)` — the classic file-open sink; `new File(userInput)` or
    `new File(baseDir, userInput)` both read (or, on write, plant) an attacker-chosen path.
  * `new RandomAccessFile(...)` — same shape, random-access file handle.
  * `Paths.get(...)` — `java.nio.file.Paths`, the modern NIO.2 path-construction entry point.
  * `Files.createTempFile(...)` — `java.nio.file.Files`, temp-file creation from a caller-supplied
    prefix/suffix or directory.

This guard fires on the CONSTRUCTION call itself (mirroring the Python `path-traversal` guard's
Rule C philosophy — a "constructor with a dynamic argument" is one step removed from the actual
read/write, but it is the only place a regex-only scanner can anchor without a real dataflow
graph), not on a subsequent stream/read/write operation.

CWE-22, OWASP:A01 (Broken Access Control).

A file-construction call inside a Maven plugin ("Mojo") class — `extends AbstractMojo`,
`implements Mojo`, or annotated `@Mojo(...)` — does NOT fire (#848 corpus scan): its fields are
build-time plugin configuration (populated from a project's `pom.xml` at build time), not runtime
request input, so they are not the same trust boundary this guard targets. This is a whole-file
skip, not per-sink: every file-construction call in a genuine Mojo class shares the same
build-time-only reasoning.

Suppress an audited case (e.g. the argument is validated/canonicalized elsewhere) with:

    new File(userInput);  // security: allow-path-traversal
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

# The four Find Security Bugs PATH_TRAVERSAL_IN sink constructs: `new File(`, `new
# RandomAccessFile(`, `Paths.get(`, `Files.createTempFile(`. Captured so the matched sink name can
# be reported in the finding message.
_SINK = re.compile(
    r"\b(?:new\s+(?P<ctor>File|RandomAccessFile)|(?:Paths\s*\.\s*get|Files\s*\.\s*createTempFile))\s*\("
)
# A bare string literal (no interpolation possible in Java — `"..."` is always fully static content,
# modulo escapes). Used to recognise a SOLE literal argument as safe.
_STR_LITERAL = re.compile(r'"(?:\\.|[^"\\\n])*"')
# A bare identifier / method-call-shaped token (a variable, a field, or a `foo()` call) — used to
# detect that the (literal-blanked) argument still contains a non-literal component.
_BARE_IDENT = re.compile(r"[A-Za-z_]\w*")
_PRAGMA = "security: allow-path-traversal"

# A Maven plugin ("Mojo") class — `extends AbstractMojo`/`implements Mojo`, or the
# `@Mojo(...)` annotation from `maven-plugin-annotations`. Its fields are BUILD-TIME plugin
# configuration (populated from a project's pom.xml at build time, developer-controlled), not
# runtime request input, so a `File`/`Paths.get(...)` constructed from one is not the same trust
# boundary this guard targets (#848 corpus scan: keycloak's own
# `docs/maven-plugin/.../GuideMojo.java` — `Paths.get(sourceDir)` where `sourceDir` is a plugin
# `@Parameter` field, 144 hits across the plugin-tooling tree in one repo). Whole-file, not
# per-line: a Mojo class's file-construction calls are ALL build-time by the same reasoning, and
# scanning whole-file is cheaper than re-deriving the same verdict per sink call.
_MOJO_CLASS = re.compile(r"\bextends\s+AbstractMojo\b|\bimplements\b[^{]*\bMojo\b|@Mojo\s*\(")


def _first_arg(text_after_open: str) -> str:
    """Extract just the first top-level argument from the text following an opening paren.

    Stops at the first unbalanced closing bracket or top-level comma, so a multi-arg call like
    `new File(baseDir, userInput)` yields just `baseDir` here — the taint check below inspects the
    whole original argument list text separately, this is only used to test "is this sink a
    single, literal-only argument."
    """
    depth = 0
    for j, ch in enumerate(text_after_open):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return text_after_open[:j].strip()
            depth -= 1
        elif ch == "," and depth == 0:
            return text_after_open[:j].strip()
    return text_after_open.strip()


def _full_args(text_after_open: str) -> str:
    """Extract the FULL argument list text up to the matching closing paren (depth-aware)."""
    depth = 0
    for j, ch in enumerate(text_after_open):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return text_after_open[:j].strip()
            depth -= 1
    return text_after_open.strip()


def _is_tainted(args: str) -> bool:
    """True when the (single- or multi-arg) call's argument text is NOT purely string-literal.

    A sole string-literal argument (`new File("config.json")`) is safe — nothing to taint. Any
    non-literal component — a bare identifier, a field/method-call token, or a `+` concatenation
    involving one — is treated as dynamic and therefore tainted, mirroring the Python
    `path-traversal` guard's "concat / variable, not a literal" heuristic.
    """
    a = args.strip()
    if not a:
        return False
    # Blank out every string literal first: what remains is punctuation (commas, `+`, whitespace)
    # plus any genuinely dynamic token (identifier, field access, method call). A `+` joining two
    # literals ("a" + "b") leaves no surviving identifier and is correctly read as still static; a
    # `+` joining a literal to a variable leaves the variable, which the identifier check below
    # catches — so no separate concatenation-operator check is needed on top of this.
    stripped = _STR_LITERAL.sub("", a)
    return bool(_BARE_IDENT.search(stripped))


class JavaPathTraversalGuard(Guard):
    id = "java-path-traversal"
    title = "No path traversal via tainted Java file construction"
    area = "Files"

    # TaintedFile.java: `new File(userPath)` -> java-path-traversal/tainted-file-construction.
    canary_plant = CanaryPlant(
        files={
            "TaintedFile.java": (
                "import java.io.File;\n\n"
                "class TaintedFile {\n"
                "    File open(String userPath) {\n"
                "        return new File(userPath);\n"
                "    }\n"
                "}\n"
            ),
        },
        expects=frozenset({"java-path-traversal/tainted-file-construction"}),
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
        # PR #884 review regression (Dean's exact repro): the Mojo check used to run against the
        # RAW text, before comment-stripping — a comment merely MENTIONING `@Mojo(`/`extends
        # AbstractMojo`/`implements ... Mojo` (a migration note, a javadoc) exempted an entire,
        # unrelated, genuinely vulnerable class. Running it on `strip_java_comments`'s output
        # closes that: a real Mojo class still exempts correctly, a comment about one no longer
        # does. Residual, disclosed rather than silently assumed away: `strip_java_comments` does
        # not blank STRING LITERAL bodies, so a token inside a Java string (not a comment) can
        # still exempt — much rarer than the comment case and not the shape this review found.
        if _MOJO_CLASS.search(strip_java_comments(text)):
            return out  # a Maven plugin class -- its fields are build-time config, not request input
        # The pragma check runs on the COMMENT-ONLY view of the line — it IS the comment
        # `strip_java_comments` below would blank, and a string quoting it must not count (#424).
        view_lines = comment_view(text, "java").splitlines()  # same length: comments only (#424)
        # `strip_java_comments` preserves length and splitlines() count exactly (tested), so the
        # two line lists always pair up — `strict=True` documents that invariant.
        code_lines = strip_java_comments(text).splitlines()
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA in view:
                continue
            m = _SINK.search(line)
            if not m:
                continue
            args = _full_args(line[m.end():])
            if _is_tainted(args):
                out.append(self._finding(root, f, i, m.group(0)))
        return out

    def _finding(self, root: Path, f: Path, line: int, sink_text: str) -> Finding:
        sink_name = sink_text.split("(")[0].strip()
        return Finding(
            check_id=self.id,
            severity="high",
            title="File path constructed from tainted (non-literal) input",
            location=f"{rel(root, f)}:{line}",
            message=(
                f"`{sink_name}(...)` is constructed from a variable, method call, or "
                "concatenation rather than a string literal — a caller-controlled "
                '`../../etc/passwd` component escapes the intended directory and reads (or, '
                "on write, plants) arbitrary files."
            ),
            remediation=(
                "Resolve the final path and assert it stays within a hardcoded base directory "
                "(`Path base = Paths.get(BASE_DIR).toAbsolutePath().normalize(); Path p = "
                "base.resolve(userPath).normalize(); if (!p.startsWith(base)) throw ...;`), or "
                "reject any input containing `..`/absolute-path prefixes before construction. "
                "Suppress an audited case with `// security: allow-path-traversal`."
            ),
            rule="java-path-traversal/tainted-file-construction",
            standards=["OWASP:A01"],
        )
