"""Guard: user input reaches an LLM call with no delimiter wrapping (checklist §3b).

§3b of the checklist: "External user input wrapped in delimiters (XML/JSON tags)
before prompts". Unwrapped user input is the precondition for the simplest
prompt injection — the model can't distinguish "the user's data" from
"instructions about the user's data", so an `Ignore previous instructions and …`
smuggled inside user content is obeyed. Wrapping untrusted input in explicit
delimiters (`<user_input>…</user_input>`) is OWASP-LLM's Layer-1 deterministic
defense.

Like `security-headers` and `system-prompt-leak`, this guard proves an
**absence** — no delimiter-wrapping anywhere — which is inherently
false-positive-prone (the wrapping may live behind a helper, or the model may be
called only with constant prompts). It is therefore deliberately conservative:

  * ANY sign of delimiter wrapping anywhere in the scanned Python (a known tag
    like `<user_input>` / `<untrusted>`, or a helper like `wrap_untrusted` /
    `delimit`) silences the guard.
  * It fires ONLY when BOTH an LLM-invocation call site AND a user-input signal
    are present — an app that calls the model only with constant/system prompts
    has no user input to delimit and stays silent.
  * A single repo-level pragma opts out (delimiting handled elsewhere / accepted):
        # security: allow-undelimited-input
  * The finding is MEDIUM severity — below the default `--fail-on high` CI gate —
    because LLM call-site recognition is heuristic (detection confidence is
    decoupled from the checklist item's HIGH control importance, exactly as
    `security-headers` decouples its low finding from a medium item).

It emits at most ONE finding (delimiter coverage is an app-wide property),
anchored at the first LLM call site.

It is **complementary to lethal-trifecta** (see the design doc): that guard flags
untrusted *retrieved* content only under the full trifecta and frames it as RAG
sanitization; this fires on the user-input→model flow regardless of the trifecta.
The overlap in the full-trifecta case is two framings of the same gap —
documented, not engineered away.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    LLM_CALL,
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-undelimited-input"
_RULE = "input-delimiters/unwrapped-user-input"
_STANDARDS = ["OWASP-LLM:LLM01"]

# The LLM-invocation call site (the anchor) is the shared `base.LLM_CALL`, which carries the
# receiver-scoped `.run(` arm and the reasons for each runner exclusion (#717, #725, #726).

# A user-input signal must co-occur (same scanned source) for the anchor to count —
# keeps the guard from firing on apps that call the model only with constant prompts.
_USER_INPUT = re.compile(
    r"\brequest\b|\buser_|\bmessage\b|\bquery\b|\buser_input\b|\bquestion\b|"
    r"\bprompt\b|\.body\b|\bform\b|\bpayload\b",
    re.IGNORECASE,
)
# Evidence of delimiter wrapping (ANY hit anywhere silences the guard — FP-safe).
# `wrap_untrusted` is shared with lethal_trifecta._MITIGATIONS["rag_sanitization"].
_DELIMITER = re.compile(
    r"<user_input|</user_input|<untrusted|</untrusted|<documents|</documents|"
    # `\bdelimit`, not `delimit`: the bare token matched the guard's OWN pragma phrase
    # (`allow-UNdelimited-input`), so quoting the opt-out anywhere in a file read as delimiter
    # evidence and silenced it (#424 E1). A boundary keeps `delimiter`/`delimit_input` matching.
    r"<user_data|<context>|wrap_untrusted|wrap_user_input|\bdelimit|in_delimiters|"
    r"<input>|</input>",
    re.IGNORECASE,
)


class InputDelimitersGuard(Guard):
    id = "input-delimiters"
    title = "User input reaches an LLM call without delimiter wrapping"
    area = "AI agent"
    # Surfacing: this guard points at an ARCHITECTURE to confirm by hand, it does not prove a
    # bug. Read by `findings._is_review_finding()` (report footer) and `prioritize.confidence()`,
    # which ranks a surfacing finding below a proven one of the same severity.
    surfacing = True

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared `agent.py`,
    # which several guards trip at once, so the file stays in `canary.py`'s base owned by no guard. The
    # ownership rule this follows is documented on `xxe_safe.py`.
    # agent.py calls agent.run_sync(question) — user input straight to the model with no
    # delimiter wrapping — so this fires alongside lethal-trifecta/no-defense and
    # system-prompt-leak/no-leak-filter.
    canary_plant = CanaryPlant(expects=frozenset({"input-delimiters/unwrapped-user-input"}))

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        # The non-product skip applies to the ANCHOR and user-input passes, never to the
        # pragma/mitigation pass. It used to sit inside this collection loop, so the pass below only
        # saw the surviving files: a `# security: allow-undelimited-input` in `tests/` stopped
        # working and a delimiter helper under `e2e/` stopped counting as mitigation, both of which
        # fire the guard at someone who had already handled it. Opting a tree into `archive_paths`
        # revoked the pragma the same way (#484 review).
        #
        # The three passes below are scoped deliberately differently, which is the whole fix:
        #
        #   * `_DELIMITER` / `_PRAGMA` (MITIGATION)   -> every scanned file, inline, short-circuiting.
        #     A repo-level pragma is repo-level wherever it lives.
        #   * `_USER_INPUT` (PRECONDITION)            -> product files only. This one is NOT a
        #     mitigation: it asks whether the deployed app handles untrusted input at all. User input
        #     appearing only in test fixtures must not make a product LLM call fire.
        #   * `LLM_CALL` (ANCHOR)                     -> product files only. LLM-input framing does
        #     not apply to migration plumbing / test / example code (round-2 §A.2).
        #
        # Testing mitigation first is still required for the original reason: some wrapping markers
        # contain user-input tokens, so short-circuiting here makes the overlap harmless.
        product: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                if _DELIMITER.search(text) or pragma_present(_PRAGMA, text, dialect="python"):
                    return []
                if not is_nonproduct_path(rel(root, f), profile.archive_segments):
                    product.append((f, text))

        # No user input in product code → nothing to delimit → silent (the key FP guard).
        if not any(_USER_INPUT.search(text) for _f, text in product):
            return []

        # Fire only if an LLM call site is actually present in product code.
        anchor = self._anchor(product, LLM_CALL)
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
                "User-derived input reaches an LLM call with no delimiter wrapping "
                "found anywhere in this app. Without an explicit boundary the model "
                "cannot tell the user's data from instructions about it, so an "
                "'ignore previous instructions and …' payload smuggled into user "
                "content is obeyed (prompt injection, Layer 1)."
            ),
            remediation=(
                "Wrap untrusted user input in explicit delimiters before it enters "
                "the prompt — e.g. embed it inside `<user_input>…</user_input>` (or "
                "JSON-tagged) boundaries and instruct the model to treat their "
                "contents as data, never instructions (checklist §3b). If the "
                "wrapping is handled elsewhere or undelimited input is acceptable, "
                "suppress with `# security: allow-undelimited-input`."
            ),
            rule=_RULE,
            standards=list(_STANDARDS),
        )
