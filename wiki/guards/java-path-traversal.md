---
type: Guard
title: "java-path-traversal"
description: "No path traversal via a Java file-construction sink built from tainted input."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "java-path-traversal"
checklist_section: ["3a"]
standards: ["OWASP:A01"]
---

# No path traversal via tainted Java file construction

Flags `java.io.File`, `RandomAccessFile`, `java.nio.file.Paths.get`, and
`java.nio.file.Files.createTempFile` constructed from a tainted (non-literal) argument. Closes
checklist item `3a-path-traversal-file-serving` — the Java counterpart to the existing
`path-traversal` (Python), `js-path-traversal` (JS/TS) guards, extending the same checklist item
rather than duplicating it. OWASP:A01 (Broken Access Control), CWE-22.

## The threat

Serving or opening a file at a path built from user input — `new File(userInput)` or
`new File(baseDir, userInput)` — lets `userInput = "../../etc/passwd"` escape the intended
directory and read (or, on write, plant) arbitrary files. The classic mitigation is to resolve the
final path and assert it stays within a hardcoded base directory
(`Path p = base.resolve(name).normalize(); if (!p.startsWith(base)) throw ...;`), or reject any
input containing `..`/absolute-path prefixes before construction.

## Exploitability rationale

HIGH. `new File(...)`, `Paths.get(...)`, and friends are the first thing a Java developer reaches
for to turn a request parameter into a filesystem handle, and none of the four sinks this guard
watches do any containment checking themselves — the check is entirely the caller's
responsibility. A single unvalidated request parameter reaching any of them is a direct read/write
primitive against the host filesystem.

## What counts as a hit (and what doesn't)

- **`new File(userInput)`**, **`new File(baseDir, userInput)`** — a bare variable/identifier as any
  argument fires.
- **`new RandomAccessFile(userInput, "r")`** — same shape, random-access handle.
- **`Paths.get(userInput)`** — the NIO.2 path-construction entry point.
- **`Files.createTempFile(prefix, suffix)`** — temp-file creation from a caller-supplied
  prefix/suffix or directory argument.
- **`new File("base/" + userInput)`** — a concatenation where at least one component is a variable
  fires, same as a bare variable.
- **`new File("config.json")`** — a SOLE string-literal argument does **not** fire (nothing to
  taint; Java string literals carry no runtime interpolation).
- **`new File("base", "config.json")`** — a multi-argument constructor where **every** argument is
  a literal does not fire.
- A similarly-spelled but unrelated method (`MyFileHelper.get(userInput)`) does not fire — only the
  four exact sink shapes above are matched.

## When NOT to flag (and the pragma)

- A file on a non-product path (`is_nonproduct_path`) → silent. Maven and Gradle put test
  sources under `src/test/java`, whose `test` segment reads as non-product, alongside the shared
  `fixtures/`/`examples/` list and a repo's own configured `archive_segments`.
- Every argument a string literal → silent (the safe case).
- Commented out (`// new File(userInput)`) → silent; comment stripping is string-aware, so a
  `//`/`/*` inside a genuine string literal on the same line is not mistaken for a comment start.
- Inside a real `/** ... */` Javadoc block mentioning the pattern → silent.
- An audited case where the path is validated/canonicalized elsewhere in the same statement, or the
  input source is trusted → suppress explicitly:

```java
File f = new File(userInput); // security: allow-path-traversal
```

**Maven plugin ("Mojo") classes are exempted whole-file (#848 corpus scan).** A real false
positive found against keycloak/keycloak's own build tooling
(`docs/maven-plugin/.../GuideMojo.java`, 144 hits): a class `extends AbstractMojo`, annotated
`@Mojo(...)`, has its `@Parameter`-annotated fields populated from the enclosing project's
`pom.xml` at BUILD time — developer-controlled, not the runtime request input this guard targets.
Detected structurally (`extends AbstractMojo` / `implements ... Mojo` / `@Mojo(` anywhere in the
file), not by path or filename, so it also covers a Mojo class living outside a conventionally
named `maven-plugin` directory. An ordinary (non-Mojo) class using the identical
`Paths.get(field)` shape still fires — confirmed directly (verified both directions).

## Known bypasses (honest limits)

- **No dataflow, no context.** This guard fires on the sink's argument shape directly (literal vs.
  non-literal), with no attempt to trace whether the variable ultimately comes from user input or
  is already validated/canonicalized upstream. The pragma is the intended correction, not a guard
  limitation to fix later.
- **Single-line, textual.** A sink call whose argument is assembled across several lines, or built
  via a helper method that itself concatenates unsafely, is not traced — same textual scope as the
  sibling `path-traversal`/`js-path-traversal` guards.
- **No containment-check recognition.** Unlike the Python `path-traversal` guard, this guard does
  not look for a nearby `.normalize()`/`.toRealPath()`/`.startsWith()` safety marker on the same
  line and suppress on that basis — the false-positive rate of a marker-recognition pass across
  Java's more varied NIO.2 idioms was not validated, so an audited-but-safe call site must use the
  explicit pragma rather than relying on an inferred safety pattern. Tracked as a possible future
  refinement, not silently assumed covered.
- **Regex/text-block scanning only — no AST.** Like every guard in this codebase (zero-runtime-
  dependency constraint: no `javalang`/tree-sitter), detection is pattern-based over
  comment-stripped source text, not a real parse tree. An unusual formatting or a macro-generated
  call site can evade or false-positive.

## What this guard does NOT prove

A clean scan means no `File`/`RandomAccessFile`/`Paths.get`/`Files.createTempFile` call-site with a
non-literal argument was found in the scanned Java source — it says nothing about traversal reached
via a native library, a dependency that wraps file access internally without going through these
four sinks directly, reflection-based file access, or a path assembled and validated correctly one
step removed from the construction call this guard anchors on.

## Canary plant

`TaintedFile.java` — `new File(userPath)` inside a method body taking a `String userPath`
parameter, no pragma. Expected rule: `java-path-traversal/tainted-file-construction`.

# Citations

[1] agentsec checklist item `3a-path-traversal-file-serving` (§3a)
[2] OWASP:A01 (Broken Access Control)
[3] CWE-22 (Improper Limitation of a Pathname to a Restricted Directory / Path Traversal)
[4] Find Security Bugs — rule `PATH_TRAVERSAL_IN`, sink list
    `injection-sinks/path-traversal-in.txt` (provenance only; detection logic here is original)
