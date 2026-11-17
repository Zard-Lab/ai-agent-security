"""Guard: LLM app defines a system prompt but ships no leak filter (checklist §4).

§4 of the checklist: "System prompt leakage protection — output filter blocks
verbatim prompt fragments". An app that hides instructions in a system prompt but
never filters its own output is open to "repeat your instructions above"-style
extraction: the model emits its hidden prompt verbatim and the secret leaks.

Like `security-headers`, this guard proves an **absence** — there is no
leak-filter code anywhere — which is inherently false-positive-prone (the filter
may live behind a wrapper, or leakage may be acceptable for the app). The design
is therefore deliberately conservative:

  * ANY sign of a leak filter anywhere in the scanned Python (a known marker like
    `leaks_system_prompt` / `system_prompt_leak` / `prompt_leak` / a redaction or
    shingle helper) silences the guard.
  * A single repo-level pragma opts out (leakage acceptable):
        # security: allow-unfiltered-system-prompt
  * The finding is MEDIUM severity — below the default `--fail-on high` CI gate —
    matching the checklist item and OWASP-LLM:LLM01.

It emits at most ONE finding (filter coverage is an app-wide property), anchored
at the first place a system prompt is defined, and fires ONLY when a system
prompt is actually present (no prompt → nothing to leak → silent).

It is **complementary to lethal-trifecta** (see the design doc): that guard's
`missing-prompt-leak-guard` fires only under the full trifecta; this one fires
whenever a system prompt exists with no filter. The full-trifecta overlap is two
framings of the same gap — documented, not engineered away.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-unfiltered-system-prompt"
_RULE = "system-prompt-leak/no-leak-filter"
_STANDARDS = ["OWASP-LLM:LLM01", "OWASP-LLM:LLM07"]

# A system prompt is DEFINED (any of these). Case-insensitive. Covers Pydantic-AI
# (`system_prompt=` / `@agent.system_prompt`), LangChain (`SystemMessage(`), and
# the OpenAI `messages` `{"role": "system"}` dict shape.
_SYSTEM_PROMPT = re.compile(
    r"system_prompt|SystemMessage\s*\(|\binstructions\s*=|"
    r"""role\s*["']?\s*[:=]\s*["']system["']""",
    re.IGNORECASE,
)

# Evidence a leak filter EXISTS (ANY hit anywhere silences the guard — FP-safe).
# Superset of lethal_trifecta._MITIGATIONS["prompt_leak_guard"] — keep the two in
# sync so both detect a filter the same way.
_LEAK_FILTER = re.compile(
    r"leaks_system_prompt|system_prompt_leak|systempromptleak|"
    r"prompt[_-]?leak|redact[_a-z]*\s*\(|scrub[_a-z]*prompt|shingle",
    re.IGNORECASE,
)


class SystemPromptLeakGuard(Guard):
    id = "system-prompt-leak"
    title = "System prompt defined with no leak-filter on model output"
    area = "AI agent"
    # Surfacing: this guard points at an ARCHITECTURE to confirm by hand, it does not prove a
    # bug. Read by `findings._is_review_finding()` (report footer) and `prioritize.confidence()`,
    # which ranks a surfacing finding below a proven one of the same severity.
    surfacing = True

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared `agent.py`,
    # which several guards trip at once, so the file stays in `canary.py`'s base owned by no guard. The
    # ownership rule this follows is documented on `xxe_safe.py`.
    # agent.py defines a system_prompt= and carries no leak-filter marker, so this fires
    # alongside lethal-trifecta/no-defense (the planted prompt text adds no defense marker).
    canary_plant = CanaryPlant(expects=frozenset({"system-prompt-leak/no-leak-filter"}))

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        # The non-product skip applies to the ANCHOR pass only, never to the pragma/mitigation pass.
        #
        # It used to sit inside this collection loop, which meant the pragma/mitigation pass below
        # only ever saw the surviving files. Two consequences, both of them the guard firing at
        # someone who had already handled it (#484 review): a
        # `# security: allow-unfiltered-system-prompt` living in `tests/` stopped working, and a
        # leak-filter helper under `e2e/` stopped counting as mitigation. Opting a tree into
        # `archive_paths` did the same thing, so a repo-level opt-out could be revoked by an
        # unrelated FP-reduction setting. A repo-level pragma is repo-level wherever it lives, and a
        # mitigation is a mitigation wherever it is defined.
        #
        # So the filter/pragma test runs on EVERY scanned file, inline and short-circuiting, while
        # only product files are retained for anchoring. That also keeps this cheaper than the
        # original, which read every product file into a list before testing any of them: the
        # early return now happens on the first mitigated file, and non-product text is never
        # retained.
        #
        # Testing before anchoring is still required for the original reason: the filter markers
        # contain the substring `system_prompt`, so `_SYSTEM_PROMPT` would otherwise match them too.
        product: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                if _LEAK_FILTER.search(text) or pragma_present(_PRAGMA, text, dialect="python"):
                    return []
                # A prompt literal in reference/example/test code (e.g. `.agents/examples/agent.py`)
                # is not the deployed app's system prompt — it may not ANCHOR a finding (round-2
                # §C.2), but it has already been searched for a filter/pragma above.
                if not is_nonproduct_path(rel(root, f), profile.archive_segments):
                    product.append((f, text))

        # No filter — fire only if a system prompt is actually defined in product code.
        anchor = self._anchor(product, _SYSTEM_PROMPT)
        if anchor is None:
            return []
        f, lineno = anchor
        return [self._finding(f"{rel(root, f)}:{lineno}")]

    @staticmethod
    def _anchor(files: list[tuple[Path, str]], pat: re.Pattern[str]) -> tuple[Path, int] | None:
        for f, text in files:
            m = pat.search(text)
            if m:
                return f, text[: m.start()].count("\n") + 1
        return None

    def _finding(self, loc: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=loc,
            message=(
                "This app defines a system prompt but no system-prompt-leak output "
                "filter was found anywhere — an attacker can use a 'repeat your "
                "instructions above' prompt to extract the hidden system prompt "
                "verbatim, disclosing internal rules, tool wiring and any secrets "
                "baked into it."
            ),
            remediation=(
                "Add an output filter that blocks responses sharing a verbatim run of "
                "N consecutive words (~12) with the system prompt (a shingle check: "
                "reject any response whose N-word window matches the prompt). If verbatim "
                "prompt disclosure is acceptable, suppress with "
                "`# security: allow-unfiltered-system-prompt`."
            ),
            rule=_RULE,
            standards=list(_STANDARDS),
        )
