---
type: Guard
title: "xxe-safe"
description: "XML parsed without defusedxml (XXE risk)."
timestamp: "2026-06-12T10:08:45Z"
guard_id: "xxe-safe"
checklist_section: ["3a"]
standards: ["OWASP-LLM:LLM03", "OWASP:A05"]
---

# XML parsed without defusedxml (XXE risk)

_Backfilled 2026-06-12 — documents Dean's guard to the shared guard-design convention._

---

## The threat

Python's stdlib XML parsers (`xml.etree`, `xml.dom`, `xml.sax`, `xml.parsers.expat`,
`xml.dom.minidom`) and `lxml` resolve external entities and expand nested entities by
default. An attacker who can supply XML — an uploaded document, a SOAP/SAML body, an
RSS/sitemap feed, an LLM tool that ingests XML — can mount:

- **XXE (XML External Entity)** — `<!ENTITY xxe SYSTEM "file:///etc/passwd">` to exfiltrate
  local files or perform SSRF against internal endpoints;
- **Billion-laughs / quadratic-blowup** — entity-expansion DoS that exhausts memory.

In a FastAPI + LLM/RAG app the high-risk surface is document ingestion (the RAG pipeline)
and any webhook/callback that accepts XML. Findings carry **OWASP A05** and
**OWASP-LLM:LLM03** (the parser is part of the data-supply path).

## Why it's often introduced

`import xml.etree.ElementTree as ET` is the obvious, documented way to parse XML in Python,
and nothing in the stdlib API warns that it is unsafe on untrusted input. The hardened
replacement, `defusedxml`, is a drop-in but a third-party dependency most developers don't
know to reach for.

## Detection design

1. **`applies()` gate** — `"python" in profile.features`.
2. **Scan** — every `.py` under `python_scan_dirs(root, profile)` (deduped).
3. **File-level escape hatch** — if the file text contains `defusedxml` anywhere, it is
   assumed to route real parsing through the safe library and is skipped entirely. This is a
   deliberate per-file global check (cheap, low-FP).
4. **Pattern** — `_UNSAFE_XML_IMPORT` matches `import`/`from` lines pulling in an
   XXE-capable module (`xml.etree|dom|sax|parsers.expat`, `xml.dom.minidom`, `lxml[.*]`).
5. **Opt-out** — a line carrying `# nosec B4xx` (Bandit's XML rule family) or
   `# security: xml-<reason>` is skipped — for type-hints-only imports or trusted/internal
   XML.
6. **Finding** — severity **medium**, rule `xxe-safe/unsafe-xml-import`, standards
   `["OWASP:A05", "OWASP-LLM:LLM03"]`.

## When NOT to flag

When the file also imports `defusedxml` (it has chosen the safe parser), or when the import
is annotated as deliberate (`# security: xml-trusted-config`, `# nosec B405`). The annotation
is the right tool when XML is only ever produced internally from trusted data, or the symbol
is imported solely for type hints.

## Tests

| Test | What it checks |
|---|---|
| `test_xxe_flags_stdlib_xml` | a stdlib `xml.*` import with no defusedxml → MEDIUM |
| `test_xxe_passes_defusedxml_and_pragma` | file using defusedxml, and a pragma-annotated import → silent |

## Known bypasses

- **Defusedxml present but unused** — the file-level check is satisfied by the *string*
  `defusedxml`; a file that imports it but still parses untrusted XML with the stdlib parser
  is not flagged (false negative by design — favours low FP).
- **Indirect / lazy import** — `importlib.import_module("xml.etree.ElementTree")` or a
  re-export through another module evades the import-line regex.
- **Aliased third-party parsers** — XML libraries other than `lxml` (e.g. `xmltodict`,
  `BeautifulSoup` with an XML backend) aren't in the pattern set.

## What this guard does NOT prove

That XML parsing is actually safe — only that an XXE-capable import is *accompanied by*
`defusedxml` or an explicit waiver. It checks the import line, not the parse call or its
configuration (e.g. it does not verify `resolve_entities=False` on an `lxml` parser).

# Citations

[1] agentsec checklist item `3a-xxe-safe-parsing` (§3a)
[2] OWASP-LLM:LLM03
[3] OWASP:A05
