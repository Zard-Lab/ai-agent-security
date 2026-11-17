---
type: Guard
title: "langchain-load-prompt-traversal"
description: "LangChain load_prompt path not validated (CWE-22 / CVE-2026-34070)."
timestamp: "2026-06-27T10:52:11+08:00"
guard_id: "langchain-load-prompt-traversal"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM02", "OWASP:A01"]
---

---
guard_id: langchain-load-prompt-traversal
checklist_item: 4-langchain-load-prompt-traversal
status: partial
severity: high
cve: CVE-2026-34070
standards:
  - OWASP:A01
  - OWASP-LLM:LLM02
applies_when:
  - langchain
---

# LangChain load_prompt path not validated (CWE-22 / CVE-2026-34070)

## Threat

`langchain.prompts.load.load_prompt(path)` and `load_prompt_from_config(config)` load YAML/JSON
prompt templates from disk at the caller-supplied path. When the path originates from LLM output
or user input without a base-directory constraint, an attacker can supply `../../etc/passwd` to
read arbitrary files (CWE-22 Path Traversal).

CVE-2026-34070 demonstrated this on LangChain ≤ 0.3.24: agent-generated template file paths
passed directly to `load_prompt()` escaped the intended template directory.

OWASP-LLM:LLM02 (Sensitive Information Disclosure, 2025) applies: an attacker-controlled path
that flows into a file-system read can disclose arbitrary repo/host files (CWE-22).

## Detection

Scan Python files in the repo for `load_prompt(` or `load_prompt_from_config(` where the
argument is not a **trusted** value. Trusted shapes (not flagged): a string literal, `Path(...)`,
an UPPER_SNAKE module constant, `os.path.join(...)` of all-literal segments, or a config-object
attribute (`settings.` / `config.` / `conf.` / `cfg.`). Flag as HIGH if no **containment** guard
(`is_relative_to` or `safe_join`) appears on the call line or anywhere further back through the
START of the enclosing function (`enclosing_function_span()` — a 4-line look-back
fallback when no enclosing function is found). Look-BACK only, never forward: a containment
check written AFTER the call has already run doesn't mitigate it. The inline
`# security: allow-path-traversal` pragma suppresses the finding.

> **Containment, not normalization.** A bare `.resolve()` / `realpath` is *not* a safety check —
> `Path("../../etc/passwd").resolve()` resolves fine and still escapes. Only a containment check
> (`is_relative_to` / `safe_join`) actually restrains the path, so only those suppress.

### Known false negatives

Aliased imports are not matched — `from langchain.prompts import load_prompt as lp; lp(name)`
calls the sink under a name the regex doesn't recognize. Resolving aliases needs dataflow the
guard deliberately avoids; the pragma and a code-review pass cover the rare alias case.

### Precision note

This is a **heuristic** (partial coverage) — it detects dynamic argument usage but cannot
determine via pure static analysis whether the path truly originates from untrusted input. False
positives are expected when the dynamic argument is a config value from a trusted source.
Developers should verify whether the path is user-/LLM-derived and suppress with the pragma
if not.

## Safe patterns

```python
# 1. Static string literal — safe, not flagged
prompt = load_prompt("templates/system.yaml")

# 2. Path validated before call — safe, not flagged
BASE = Path("templates")
p = (BASE / template_name).resolve()
assert p.is_relative_to(BASE)
prompt = load_prompt(p)

# 3. Audited dynamic path — suppress with pragma
prompt = load_prompt(template_name)  # security: allow-path-traversal

# 4. Trusted in-repo constant / config — safe, not flagged
prompt = load_prompt(PROMPT_PATH)                         # UPPER_SNAKE module constant
prompt = load_prompt(os.path.join("templates", "x.yaml"))  # all-literal os.path.join
prompt = load_prompt(settings.template)                  # config-object attribute
```

## Remediation

Before calling `load_prompt(path)`, validate that the resolved path stays under a hardcoded
allowed directory:

```python
from pathlib import Path

TEMPLATE_DIR = Path(__file__).parent / "templates"

def load_template(name: str):
    # Strip any directory components from user/LLM-supplied names
    safe_name = Path(name).name
    target = (TEMPLATE_DIR / safe_name).resolve()
    if not target.is_relative_to(TEMPLATE_DIR):
        raise ValueError(f"Template path escapes allowed directory: {name}")
    return load_prompt(target)
```

Or maintain a fixed allowlist of valid template names and reject anything not in the list.

# Citations

[1] agentsec checklist item `4-langchain-load-prompt-traversal` (§4)
[2] OWASP-LLM:LLM02
[3] OWASP:A01
