---
type: Guard
title: "java-unsafe-deserialization"
description: "No unsafe deserialization of untrusted data (ObjectInputStream gadget chains, Jackson polymorphic typing) in Java application code."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "java-unsafe-deserialization"
checklist_section: ["3b"]
standards: ["OWASP:A08", "OWASP-LLM:LLM03"]
---

# No unsafe deserialization of untrusted data (Java)

Flags two distinct Java deserialization shapes that both let attacker-controlled input decide
what class gets instantiated during deserialization. Closes checklist item
`3b-unsafe-deserialization` — the Java counterpart to the existing `unsafe-deserialization`
(Python/JS) guard, extending the same checklist item rather than duplicating it. CWE-502,
OWASP:A08, OWASP-LLM:LLM03.

## The threat

Java's built-in object serialization reconstructs an object graph from raw bytes by invoking
constructors, `readObject()` methods, and finalizers along the way. If an attacker controls the
bytes handed to `ObjectInputStream.readObject()`, they can supply a serialized instance of any
class on the classpath — chained together ("gadget chains"), a sequence of otherwise-harmless
classes' side effects during deserialization can be composed into arbitrary code execution. This
is the mechanism behind nearly every headline Java deserialization RCE of the last decade
(WebLogic, Apache Struts, Jenkins, and many more) — it is THE canonical Java RCE class, not a
theoretical concern.

Jackson's polymorphic typing feature (`@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)` or
`.MINIMAL_CLASS`) is a second, distinct API surface with the identical root cause: it embeds the
concrete Java class name to instantiate directly in the JSON payload, so an attacker who controls
the payload picks the class — the same "attacker-controlled class selection feeds a gadget chain"
weakness, through Jackson instead of raw object serialization.

## Exploitability rationale

CRITICAL for both shapes — this is remote code execution, not a lesser weakness, whenever the
input is attacker-reachable (an upload, an API request body, a message-queue payload, a cache/
session store an attacker can poison). Likelihood is real: Java serialization is opt-in by design
(implementing `Serializable`) but ubiquitous across the ecosystem (RMI, JMS, HTTP session
replication, caching layers), and gadget chains have been published against dozens of common
libraries (Commons Collections, Spring, Groovy, and more) — an application does not need to ship
its own exploitable class for this to be dangerous, only a vulnerable class *somewhere* on its
classpath.

## What counts as a hit (and what doesn't)

- **`.readObject()` / `.readUnshared()`** called on any receiver fires
  (`java-unsafe-deserialization/object-input-stream`). Matched on the bare method call, not
  anchored to an `ObjectInputStream`-typed receiver in the same line — these two method names are
  distinctive enough in Java (the two ObjectInputStream deserialization entry points, not reused
  for anything else in the standard library or common frameworks) that the guard trusts the name
  alone, the same reasoning `go-tls-verify-disabled` uses for `InsecureSkipVerify`. This
  deliberately makes the guard no narrower than graudit's simpler `ObjectInputStream`/
  `readObject(`/`resolveClass(` regex signature — verified as a pure subset during research
  reconciliation and folded in here rather than built as a separate guard.
- **`@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)`** or **`.Id.MINIMAL_CLASS)`** (the fully-qualified
  enum spelling) fires (`java-unsafe-deserialization/jackson-polymorphic-typing`).
- `@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)` does **not** fire — `Id.NAME` maps a
  developer-controlled logical name to a class via an explicit `@JsonSubTypes` allowlist; the
  payload never names a class directly, so there is no attacker-controlled class selection.
- A `readObject()`/`readUnshared()` call guarded by a validating `ObjectInputFilter` is not
  distinguished from an unguarded one — see "Known bypasses."

## When NOT to flag (and the pragma)

- A file on a non-product path (`is_nonproduct_path`) → silent. Maven and Gradle put test
  sources under `src/test/java`, whose `test` segment reads as non-product, alongside the shared
  `fixtures/`/`examples/` list and a repo's own configured `archive_segments`.
- `@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)` → silent (the safe mode).
- Commented out (`// ois.readObject() is dangerous`) → silent; comment stripping is string-aware.
- Inside a real `/** ... */` Javadoc block mentioning the pattern → silent.
- A fully audited, trusted-source case (e.g. deserializing an internal-only cache written by the
  same process) → suppress explicitly:

```java
Object obj = ois.readObject();  // security: allow-unsafe-deserialize
```

## Known bypasses (honest limits)

- **No dataflow, no context.** Like every sibling guard in this codebase, this fires on the API
  call/annotation shape directly, with no attempt to prove the deserialized bytes are actually
  attacker-reachable, or that the classpath contains an exploitable gadget chain. The pragma is
  the intended correction, not a guard limitation to fix later.
- **`ObjectInputFilter` is not detected.** A properly configured Java 9+ `ObjectInputFilter` (or a
  look-ahead-validating `ObjectInputStream` subclass on earlier Java) genuinely neutralizes this
  vector by allowlisting expected classes before `readObject()` runs — this guard does not look
  for one, so a hardened call site still fires. Suppress with the pragma once verified.
- **Single-line, textual.** A receiver constructed and typed across several lines, or passed in as
  a parameter/field whose declared type isn't visible on the matched line, is not traced — the
  guard fires on the method-call name alone rather than attempting that trace (see "What counts as
  a hit" for why this is a deliberate trade, not an oversight).
- **Java 17+ text blocks are not comment/string-aware.** `strip_java_comments` deliberately does
  not special-case triple-double-quoted text blocks — see its docstring for the exact, documented
  residual (shared with every other guard that uses this helper).
- **Other Java deserialization surfaces are out of scope.** XStream, Kryo, Hessian/Burlap, and
  SnakeYAML's unsafe `Constructor` mode are all separate, real Java (de)serialization RCE
  surfaces with the same root cause but different APIs — not ported here; tracked as possible
  future guard extensions, not silently assumed covered.

## What this guard does NOT prove

A clean scan means no `.readObject()`/`.readUnshared()` call or `Id.CLASS`/`Id.MINIMAL_CLASS`
annotation was found in the scanned Java source — it says nothing about a vulnerable gadget chain
actually being reachable on the classpath, whether a `readObject()` call site is already
protected by an `ObjectInputFilter`, or a deserialization surface reached through a different API
(XStream, Kryo, SnakeYAML, native RMI) entirely.

## Canary plant

`Deser.java` — `ObjectInputStream ois = new ObjectInputStream(in); ois.readObject();` inside a
method body, no pragma. Expected rule: `java-unsafe-deserialization/object-input-stream`.

# Examples

Fires (ObjectInputStream):

```java
ObjectInputStream ois = new ObjectInputStream(untrustedInputStream);
Object obj = ois.readObject();
```

Fires (Jackson):

```java
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
public abstract class Payload {}
```

Does not fire (safe Jackson mode):

```java
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)
@JsonSubTypes({ @JsonSubTypes.Type(value = Dog.class, name = "dog") })
public abstract class Animal {}
```

# Citations

[1] agentsec checklist item `3b-unsafe-deserialization` (§3b)
[2] OWASP:A08 (Software and Data Integrity Failures)
[3] OWASP-LLM:LLM03 (Supply Chain Vulnerabilities)
[4] CWE-502 (Deserialization of Untrusted Data)
[5] Find Security Bugs — `ObjectDeserializationDetector.java`, rule `OBJECT_DESERIALIZATION`
    (provenance only; detection logic here is original)
[6] Find Security Bugs — `UnsafeJacksonDeserializationDetector.java`, rule
    `JACKSON_UNSAFE_DESERIALIZATION` (provenance only; detection logic here is original)
[7] graudit's `ObjectInputStream`/`readObject(`/`resolveClass(` signature — verified as a pure
    textual subset of pattern [5] during research reconciliation, folded into this guard rather
    than built separately
