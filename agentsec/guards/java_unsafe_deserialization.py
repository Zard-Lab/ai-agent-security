"""Guard: no unsafe deserialization of untrusted data in Java application code (checklist §3b).

The Java counterpart to agentsec's existing Python/JS `unsafe-deserialization` guard — same
requirement (a deserializing load that lets attacker-controlled bytes decide what code runs is
remote code execution), extending the same `3b-unsafe-deserialization` checklist item rather
than duplicating it, on a genuinely different code surface (`java.io.ObjectInputStream` /
Jackson's polymorphic-typing annotations instead of `pickle`/`yaml.load`/`js-yaml`).

**This guard folds together two reconciled research candidates covering the same root cause**
("attacker picks the class that gets instantiated"), verified during corpus reconciliation as a
duplicate/subset relationship rather than two separate guards:

  * **`ObjectInputStream.readObject()`/`.readUnshared()`** — the classic Java gadget-chain
    deserialization RCE vector (WebLogic, Struts, Jenkins — nearly every headline Java RCE CVE of
    the last decade traces back to this shape). Verified against Find Security Bugs' real source
    (`ObjectDeserializationDetector.java`, rule `OBJECT_DESERIALIZATION`) — class name and file
    cited for provenance; detection logic and test fixtures here are original, developed
    independently against the pattern description, not copied or derived from that (Java) source.
  * **Jackson polymorphic typing** — `@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)` or
    `.Id.MINIMAL_CLASS)` lets the JSON payload itself name the Java class to instantiate during
    deserialization — a distinct API from `ObjectInputStream` but the identical underlying
    weakness (attacker-controlled class selection feeds a gadget chain). Verified against Find
    Security Bugs' `UnsafeJacksonDeserializationDetector.java`, rule
    `JACKSON_UNSAFE_DESERIALIZATION` — same provenance-only citation.
  * graudit's simpler regex signature (`ObjectInputStream`, `readObject(`, `resolveClass(`) was
    reconciled as a pure textual SUBSET of the `ObjectInputStream` pattern above during this same
    research pass — not built as a separate guard. This guard's bare `.readObject()`/
    `.readUnshared()` match (see below) is deliberately not narrower than that simpler signature,
    so graudit's shape is fully covered here.

No real dataflow is available (regex/text-block scanning, not an AST, is this codebase's
zero-runtime-dependency constraint for every guard) — so, mirroring `go_tls_verify_disabled.py`'s
`InsecureSkipVerify` reasoning: `.readObject()`/`.readUnshared()` are distinctive enough Java
method names (the two ObjectInputStream deserialization entry points, not used for anything else
in the standard library or common frameworks) that this guard trusts the bare method call, without
requiring nearby `ObjectInputStream`-typed receiver context — the false-positive risk of a
same-named-but-unrelated method is negligible relative to the false-negative risk of missing a
call whose receiver's declared type sits several lines/a field/a parameter away from the call
site (exactly the case a stricter proximity match would silently miss).

Fires CRITICAL on two distinct shapes, both under the same checklist item:

  * `.readObject()` / `.readUnshared()` called on any receiver — the ObjectInputStream gadget-
    chain RCE vector.
  * `@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)` / `@JsonTypeInfo(use = JsonTypeInfo.Id.MINIMAL_CLASS)`
    (fully-qualified `JsonTypeInfo.Id.CLASS`/`.MINIMAL_CLASS` spelling) — Jackson polymorphic
    deserialization from an attacker-supplied class name. The SAFE `Id.NAME` mode (a
    developer-controlled logical-name-to-class mapping, not an attacker-supplied class name) does
    not fire.

CWE-502, OWASP:A08, OWASP-LLM:LLM03.

Suppress an audited case (e.g. deserializing a value from a fully trusted, internal-only source)
with:

    Object obj = ois.readObject();  // security: allow-unsafe-deserialize
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

# `.readObject()` / `.readUnshared()` — the two ObjectInputStream deserialization entry points.
# Matched on the bare method call, not anchored to an `ObjectInputStream`-typed receiver (see the
# module docstring for the name-trust reasoning) — so this is deliberately not narrower than
# graudit's simpler `readObject(` textual signature, which it folds in.
_OBJECT_INPUT_STREAM_READ = re.compile(r"\.\s*read(?:Object|Unshared)\s*\(")
# `@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)` / `.Id.MINIMAL_CLASS)` — the fully-qualified enum
# spelling (`JsonTypeInfo.Id.CLASS`/`.MINIMAL_CLASS`), which Find Security Bugs' own
# `UnsafeJacksonDeserializationDetector.java` targets. The safe `Id.NAME` mode is a disjoint
# alternation branch, so it can never match this pattern.
_JACKSON_POLYMORPHIC_TYPE = re.compile(
    r"@JsonTypeInfo\s*\([^)]*\bJsonTypeInfo\s*\.\s*Id\s*\.\s*(?:MINIMAL_CLASS|CLASS)\b"
)
_PRAGMA = "security: allow-unsafe-deserialize"


class JavaUnsafeDeserializationGuard(Guard):
    id = "java-unsafe-deserialization"
    title = "No unsafe deserialization of untrusted data (Java)"
    area = "Code safety"

    # Deser.java: ObjectInputStream(...).readObject() -> fires
    # java-unsafe-deserialization/object-input-stream.
    canary_plant = CanaryPlant(
        files={
            "Deser.java": (
                "import java.io.ObjectInputStream;\n"
                "import java.io.InputStream;\n\n"
                "class Deser {\n"
                "    Object load(InputStream in) throws Exception {\n"
                "        ObjectInputStream ois = new ObjectInputStream(in);\n"
                "        return ois.readObject();\n"
                "    }\n"
                "}\n"
            ),
        },
        expects=frozenset({"java-unsafe-deserialization/object-input-stream"}),
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
            if _OBJECT_INPUT_STREAM_READ.search(line):
                out.append(self._ois_finding(root, f, i))
            elif _JACKSON_POLYMORPHIC_TYPE.search(line):
                out.append(self._jackson_finding(root, f, i))
        return out

    def _ois_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title="Java object deserialization (ObjectInputStream.readObject) of untrusted data",
            location=f"{rel(root, f)}:{line}",
            message=(
                "ObjectInputStream.readObject()/readUnshared() reconstructs a Java object graph "
                "from raw bytes, invoking constructors/finalizers/readObject methods along the "
                "way — on attacker-controlled input this is the classic Java gadget-chain remote "
                "code execution vector behind nearly every headline Java deserialization CVE "
                "(WebLogic, Struts, Jenkins)."
            ),
            remediation=(
                "Never deserialize untrusted bytes with ObjectInputStream. Use a non-executing "
                "format (JSON/Protobuf) instead, or if Java serialization is unavoidable, install "
                "a validating ObjectInputFilter (Java 9+ `ObjectInputFilter`, or a "
                "look-ahead-validating subclass on earlier versions) that allowlists expected "
                "classes before calling readObject(). Suppress an audited, fully-trusted-source "
                "case with `// security: allow-unsafe-deserialize`."
            ),
            rule="java-unsafe-deserialization/object-input-stream",
            standards=["OWASP:A08", "OWASP-LLM:LLM03"],
        )

    def _jackson_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title="Jackson polymorphic deserialization from an attacker-supplied class name",
            location=f"{rel(root, f)}:{line}",
            message=(
                "@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS) (or .MINIMAL_CLASS) lets the JSON "
                "payload itself name the Java class Jackson instantiates during deserialization — "
                "an attacker who controls the payload picks the class, the same underlying "
                "\"attacker-controlled class selection feeds a gadget chain\" weakness as "
                "ObjectInputStream, through Jackson's polymorphic-typing feature instead."
            ),
            remediation=(
                "Use Id.NAME with an explicit @JsonSubTypes allowlist instead of Id.CLASS/"
                "MINIMAL_CLASS, so the payload selects from a developer-controlled set of logical "
                "names rather than naming an arbitrary class. Suppress an audited, "
                "fully-trusted-source case with `// security: allow-unsafe-deserialize`."
            ),
            rule="java-unsafe-deserialization/jackson-polymorphic-typing",
            standards=["OWASP:A08", "OWASP-LLM:LLM03"],
        )
