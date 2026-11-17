---
type: Guard
title: "java-xxe-unsafe-parsing"
description: "Java XML parser used to parse XML without a hardened (disallow-DOCTYPE / external-entity-off) feature set anywhere in the file."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "java-xxe-unsafe-parsing"
checklist_section: ["3a"]
standards: ["OWASP:A05", "OWASP-LLM:LLM03"]
---

# Java XML parser used without a hardened (XXE-safe) feature set

Third sibling for checklist item `3a-xxe-safe-parsing`, alongside `xxe-safe` (Python: XXE-capable
import present without `defusedxml`) and `js-xxe-unsafe-parsing` (JS/TS: `libxmljs`'s
`noent: true`). CWE-611, OWASP:A05 (Security Misconfiguration), OWASP-LLM:LLM03 (Training Data
Poisoning / Supply Chain — XML ingestion is a common untrusted-input path into RAG/agent tool
pipelines).

## The threat

Java's built-in XML APIs (`javax.xml.parsers`, `org.xml.sax`, `javax.xml.transform`) are
**unsafe by default**: DOCTYPE processing and external entity resolution are both ON unless the
caller explicitly hardens the factory/builder before parsing. An attacker who controls the XML
document handed to `.parse(...)` can then:

- read arbitrary local files (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`)
- reach internal network endpoints (SSRF) via an external entity pointing at an internal URL
- exhaust memory/CPU via entity expansion ("billion laughs")

Unlike Python's `xxe-safe` guard (a safe *library* — `defusedxml` — either is or isn't imported)
or JS's `js-xxe-unsafe-parsing` guard (a single dominant unsafe *option* — `noent: true`), Java has
no single safe-by-default alternative and no single unsafe flag: the caller must actively harden
the stock JDK factory, and there are several equally valid ways to do it.

## Exploitability rationale

HIGH. XXE is a well-understood, actively exploited class (file disclosure, SSRF, DoS) and Java's
default-unsafe posture means any code that feeds external/attacker-influenced XML into
`DocumentBuilder`/`SAXParser`/`XMLReader`/`Transformer` without hardening is vulnerable by
default, not by mistake in an edge case.

## What counts as a hit (and what doesn't)

A file is flagged when **both** are true:

1. It contains one of the recognized construction/use call-sites:
   - `SAXParserFactory.newInstance()` → `.newSAXParser()`
   - `DocumentBuilderFactory.newInstance()` → `.newDocumentBuilder()`
   - `XMLReaderFactory.createXMLReader()`
   - `TransformerFactory.newInstance()`
2. The file also calls `.parse(...)` (or `.transform(...)` for the `Transformer` shape) somewhere
   — i.e. the parser is actually used to consume XML, not merely constructed.

...and **none** of the recognized hardening calls appears anywhere in the same file:

```java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
builderFactory.setExpandEntityReferences(false);
```

Any ONE of these anywhere in the file silences the whole file's findings. A parser that is
constructed but never actually used to `.parse(...)` anything does **not** fire — no untrusted
input is deserialized.

## The pragma

A file on a non-product path (`is_nonproduct_path`) is silent without any pragma at all.
Maven and Gradle put test sources under `src/test/java`, whose `test` segment reads as
non-product, alongside the shared `fixtures/`/`examples/` list and a repo's own configured
`archive_segments` — an unhardened parser in a test is not a production XXE.

```java
DocumentBuilder b = dbf.newDocumentBuilder();  // security: allow-java-xxe
```

## Detection scope — same-file, not same-method (an honest, documented limitation)

Find Security Bugs' own `XxeDetector.java` (see Citations) ties the hardening call to the
*specific* factory instance via real dataflow analysis, scoped to the enclosing method. This
codebase has **no Java AST or dataflow engine** — `agentsec/guards/base.py`'s function-scoping
helpers (`iter_functions`/`enclosing_function_span`) are Python-`ast`-based and do not apply to
Java source, and hand-rolling an equivalent Java method-boundary walker (brace-balance tracking,
handling nested classes/lambdas/anonymous inner classes) was judged a materially bigger and more
fragile undertaking than every other guard on this branch, for a proportionally small accuracy
gain given this guard's presence/absence philosophy.

The choice made here, deliberately, is the **coarser but honest "anywhere earlier — or later — in
the same file" scope**: a hardening call anywhere in the file silences every finding in that file,
regardless of which method or which factory instance it was actually applied to. This is
documented explicitly rather than claimed as function-precise.

**What this trades away:**

- **False negatives**: a file with TWO factories, one hardened and one not, is entirely silenced
  by the hardened one — the unhardened factory's real vulnerability is missed.
- **What it still catches**: the overwhelmingly common real-world case — a file that never
  hardens ANY XML parser at all — which is also the shape Find Security Bugs' own detectors most
  often report in practice.

This mirrors the documented scope choice in `java-weak-crypto`'s design doc ("no dataflow, no
context — fires on the pattern directly") and `xxe-safe`'s own presence/absence philosophy; it is
the same tradeoff class the whole Java-guard family on this branch makes, made explicit here
because the specific fan-out (4 construction shapes x file-wide, not statement-wide, absence
check) is wider than a single-pattern guard's.

## Known bypasses (honest limits)

- **Same-file, not same-method** (above) — the dominant limitation.
- **No dataflow.** Like every sibling guard, this does not trace whether the XML source is
  actually attacker-controlled; it fires on the unhardened-parser-used-to-parse pattern directly.
  The pragma is the intended correction.
- **Textual, not semantic.** A factory obtained through a wrapper method (e.g. a
  `XmlUtils.newSafeDocumentBuilder()` helper that internally hardens) is not recognized unless the
  hardening call syntactically appears in the SAME file being scanned.
- **Java 17+ text blocks** are not comment/string-aware in `strip_java_comments` (a rare,
  documented residual — see that helper's own docstring).
- **Recognized hardening call list is not exhaustive.** Other valid mitigations exist (e.g.
  disabling DTDs entirely via a SAX `EntityResolver`, or XInclude-specific features); only the
  handful most commonly recommended (and most commonly seen in Find Security Bugs' own detector
  logic) are recognized. An unrecognized-but-valid mitigation would false-positive.

## What this guard does NOT prove

A clean scan means no unhardened parse-call-site pattern was found in the scanned Java source — it
says nothing about XML parsed via a native library, a dependency that wraps an unhardened parser
internally, or XML the application receives pre-parsed from an external service. It also does not
prove that a hardening call found elsewhere in the file was actually applied to the SAME factory
instance used at the parse site (see "Detection scope" above).

## Canary plant

`UnsafeXxe.java` — `DocumentBuilderFactory.newInstance()` → `.newDocumentBuilder()` →
`.parse(...)` inside a method body, no hardening call anywhere in the file, no pragma. Expected
rule: `java-xxe-unsafe-parsing/doctype-decl-allowed`.

# Citations

[1] agentsec checklist item `3a-xxe-safe-parsing` (§3a)
[2] OWASP:A05 (Security Misconfiguration)
[3] OWASP-LLM:LLM03
[4] CWE-611 (Improper Restriction of XML External Entity Reference)
[5] Find Security Bugs — `XxeDetector.java`, rules `XXE_SAXPARSER`/`XXE_XMLREADER`/`XXE_DOCUMENT`/
    `XXE_XPATH` (provenance only; detection logic here is original, developed independently
    against the pattern description, not copied or derived from that Java source)
