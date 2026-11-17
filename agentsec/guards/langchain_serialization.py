# security: allow-unsafe-deserialize — guard docstring + remediation text contain pattern
# examples for langchain_core.load.loads; the unsafe-deserialization finding is self-referential.
"""Guard: LangChain unsafe serialization — secrets_from_env or langchain-core dumps/loads (checklist §4).

Two dangerous LangChain serialization vectors, both related to CVE-2025-68664 (LangGrinch, CVSS 9.3):

  **secrets_from_env=True** — enables automatic secret injection into chain configs at
  deserialisation time. If an attacker controls a serialised chain (e.g. from a user-supplied
  template or LLM output), they can exfiltrate environment variables by referencing them in the
  chain config JSON. Disable by omitting or explicitly setting `secrets_from_env=False`.

  **langchain_core.load.dumps/loads on dynamic content** — `langchain_core.load.dumps` serialises
  arbitrary Python objects including function references; `loads` executes them. Passing LLM
  output or user input to `loads()` is equivalent to `pickle.loads` on untrusted bytes — remote
  code execution. OWASP-LLM:LLM01 / OWASP:A08.

Both patterns require a `langchain` import, so the guard is gated on that import.

Suppress a reviewed case with `# security: allow-langchain-serialization`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_PRAGMA = "security: allow-langchain-serialization"
_STANDARDS = ["OWASP-LLM:LLM01", "OWASP:A08", "CWE-502"]

# No trailing \b: it would fail between `langchain` and `_core`, gating out the canonical modern
# import `from langchain_core.load import loads` — the exact code the loads rule targets (PR #206 review).
_LANGCHAIN_IMPORT = re.compile(
    r"\b(?:import\s+langchain|from\s+langchain)"
)
_SECRETS_FROM_ENV = re.compile(r"\bsecrets_from_env\s*=\s*True\b")
_LANGCHAIN_LOADS = re.compile(
    r"\bfrom\s+langchain_core\.load\s+import\b.*\bload[s]?\b"
    r"|\bfrom\s+langchain_core\s+import\b.*\bload[s]?\b"
    r"|\blangchain_core\.load\.loads?\s*\("
    r"|\bload_from_json\s*\("
)


class LangchainSerializationGuard(Guard):
    id = "langchain-serialization"
    title = "LangChain unsafe serialization — secrets_from_env=True or langchain-core loads on dynamic content"
    area = "AI agent"

    # langchain_chain.py: langchain import + secrets_from_env=True -> secrets-from-env.
    # Must NOT contain: allow-langchain-serialization, secrets_from_env=False.
    canary_plant = CanaryPlant(
        files={
            "langchain_chain.py": (
                "from langchain.chains import LLMChain\n"
                "\n"
                "\n"
                "def load_chain(path: str) -> LLMChain:\n"
                "    return LLMChain.load(path, secrets_from_env=True)\n"
            ),
        },
        expects=frozenset({"langchain-serialization/secrets-from-env"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        # langchain-core detection: llm_framework is set to the FIRST framework detected
        # (pydantic-ai wins in mixed repos). Gate only on python; the guard's import scan
        # provides the langchain-specific gate internally.
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
                if not _LANGCHAIN_IMPORT.search(text):
                    continue
                out.extend(self._check_file(root, f, text))
        return out

    def _check_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        r = rel(root, f)
        # Blank triple-quoted strings (preserves line numbers) + skip comments, so a docstring/comment
        # that merely mentions a pattern doesn't fire CRITICAL (PR #206 review).
        for i, line in enumerate(strip_python_strings(text, filename=f).splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if _SECRETS_FROM_ENV.search(line):
                out.append(Finding(
                    check_id=self.id,
                    severity="critical",
                    title="secrets_from_env=True — attacker-controlled chain can exfiltrate env secrets",
                    location=f"{r}:{i}",
                    message=(
                        "`secrets_from_env=True` enables automatic environment-variable injection "
                        "into chain configs at deserialisation time. If an attacker can supply "
                        "a serialised chain (via LLM output or user upload), they can reference "
                        "any env var in the config and exfiltrate it. CVE-2025-68664 (CVSS 9.3)."
                    ),
                    remediation=(
                        "Remove `secrets_from_env=True` or explicitly set `secrets_from_env=False`. "
                        "Pass secrets through explicit constructor args instead. "
                        "Suppress with `# security: allow-langchain-serialization` only after "
                        "confirming the deserialised source is fully trusted."
                    ),
                    rule="langchain-serialization/secrets-from-env",
                    standards=list(_STANDARDS),
                ))
            if _LANGCHAIN_LOADS.search(line):
                out.append(Finding(
                    check_id=self.id,
                    severity="critical",
                    title="langchain_core.load.loads() called — may execute untrusted Python objects",
                    location=f"{r}:{i}",
                    message=(
                        "`langchain_core.load.loads()` deserialises Python objects including "
                        "function references. Passing LLM output or user-controlled JSON to "
                        "this function is equivalent to pickle deserialization on untrusted bytes — "
                        "remote code execution if the input can be influenced by an attacker."
                    ),
                    remediation=(
                        "Avoid deserialising LLM output or user input with `langchain_core.load.loads`. "
                        "If you must deserialise chain configs, use a strict allowlist of permitted "
                        "types and verify the source is trusted before deserialising. "
                        "Use `langchain_core.load.load` only with configs from your own storage."
                    ),
                    rule="langchain-serialization/loads-dynamic-content",
                    standards=list(_STANDARDS),
                ))
        return out
