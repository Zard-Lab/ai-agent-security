"""Guard: never capture/store/log a raw card number or CVV (checklist 9-no-pan-stored).

With Stripe (or any modern PSP) the raw card number (PAN) and CVV must never touch
your server — Stripe.js / Elements tokenizes them in the browser and you only ever
handle a token (`pm_…`, `tok_…`) or the last four. A server-side field, column, or
log line named `card_number` / `cvv` / `cvc` means the app is capturing or
persisting the actual card data, which is a PCI-DSS violation and the difference
between SAQ A and a full audit (and a breach-class liability). Storing the CVV is
prohibited outright, even encrypted.

Fires HIGH on a `.py` line that assigns/declares a raw-card field
(`card_number`, `card_no`, `cvv`, `cvc`, …) or logs one. The fix is to tokenize
client-side and store only the Stripe token / last4. A reviewed case (e.g. a field
that genuinely holds only the last four) can suppress the line with
`# security: allow-card-field`.

OWASP:A02 (Cryptographic Failures) + PCI-DSS. Gated on `payments`.
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
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

# Raw cardholder data field names (NOT last4/brand/expiry, which are storable).
_RAW_CARD = re.compile(r"\b(?:card_number|cardnumber|card_no|cvv|cvc|card_cvc|card_cvv)\b", re.I)
# Harvest a card field name from a log call's "code view" (issue #424): string-literal PROSE is
# removed, but f-string `{…}` interpolations are kept — a `{cvv}` interpolated into a log message
# IS a leaked value, whereas a field name inside plain message text is not. Mirrors the same
# technique in `sensitive_logging._code_view`.
_FSTRING_INTERP = re.compile(r"\{([^{}]+)\}")
_STRING_LIT = re.compile(
    r"""[fFrRbBuU]*(?:\"\"\"[\s\S]*?\"\"\"|'''[\s\S]*?'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
)
_FSTRING_LIT = re.compile(
    r"""(?:[rR][fF]|[fF][rR]?)(?:\"\"\"[\s\S]*?\"\"\"|'''[\s\S]*?'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
)


def _keeps_as_subscript_key(line: str, start: int, end: int) -> bool:
    """Whether the string literal at `line[start:end]` is a SUBSCRIPT KEY rather than prose.

    `data["card_number"]` reads the field; `logger.info("card_number removed")` merely names
    it. Deleting every literal before the check erased the first along with the second, so a
    PAN/CVV read through a string-keyed index — the commonest real leak shape — went silent
    (#439 review)."""
    return line[:start].rstrip().endswith("[") and line[end:].lstrip().startswith("]")


def _code_view(line: str) -> str:
    """A log line with string-literal PROSE removed but f-string `{…}` interpolations kept, so a
    card field NAME in a message string (`logger.info("card_number removed")`) doesn't fire while a
    logged value — a bare identifier, an interpolated `{cvv}`, or a string-keyed index read
    (`row["card_number"]`) — still does (issue #424, #439 review)."""
    fstrings = " ".join(_FSTRING_LIT.findall(line))
    interps = " ".join(_FSTRING_INTERP.findall(fstrings))
    code = _STRING_LIT.sub(
        lambda m: m.group() if _keeps_as_subscript_key(line, m.start(), m.end()) else " ", line
    )
    return code + " " + interps
# Capture/store context: the field is an assignment target, dict key/index, or column/annotation.
# Two forms, kept distinct rather than one loose [:=] class: a dict-literal key needs the colon
# directly after the (optionally quoted) name (`{"card_number": v}`); an assignment allows an
# optional closing `]` first for dict/index writes (`row["card_number"] = v`) and excludes `==`
# via the negative lookahead, so an equality check/read (`if card_number == x:`,
# `elif row["card_number"]:`) is never mistaken for a store.
_STORE = re.compile(
    r'["\']?\b(?:card_number|cardnumber|card_no|cvv|cvc|card_cvc|card_cvv)\b["\']?\s*:'
    r'|["\']?\b(?:card_number|cardnumber|card_no|cvv|cvc|card_cvc|card_cvv)\b["\']?\s*\]?\s*=(?!=)',
    re.I,
)
# Logging context (the field is passed to a logger/print).
_LOG = re.compile(r"\b(?:print|log|logger|logging)\b", re.I)
_PRAGMA = re.compile(r"#\s*security:\s*allow-card-field")


class NoPanStoredGuard(Guard):
    id = "no-pan-stored"
    title = "Raw card number / CVV captured, stored, or logged — PCI violation"
    area = "Payments"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `stripe_webhook.py`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # The Stripe payments pack (stripe_webhook.py plants: client-set amount, a
    # fulfilment branch on a *.created event, and a raw card_number capture).
    canary_plant = CanaryPlant(expects=frozenset({"no-pan-stored/raw-card-data"}))

    def applies(self, profile: StackProfile) -> bool:
        return "payments" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                # Blank triple-quoted docstring CONTENT so this guard's own module docstring
                # (which names `card_number` next to the word "log") doesn't self-match (#424).
                text = strip_python_strings(read(f), filename=f)
                # The pragma counts only as a real comment on the line, never quoted in a string
                # there (#1040), numbered on the text walked below (a form feed in a docstring
                # shifts the raw count, #1132).
                pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
                for i, line in enumerate(text.splitlines(), start=1):
                    if line.lstrip().startswith("#") or i in pragmas:
                        continue
                    # STORE keeps the string literal intact so a dict-key/index write
                    # (`row["card_number"] = v`) still fires; LOGGED uses the code-view (prose
                    # removed, f-string interpolations kept) so a field name inside a log MESSAGE
                    # is not a false positive but an interpolated `{cvv}` value still fires (#424).
                    stored = _STORE.search(line)
                    logged = _RAW_CARD.search(_code_view(line)) and _LOG.search(line)
                    if stored or logged:
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title=self.title,
                                location=f"{rel(root, f)}:{i}",
                                message=(
                                    "This handles a raw card number / CVV server-side (a field, "
                                    "column, or log). Raw PAN/CVV must never reach the server: it is "
                                    "a PCI-DSS violation and storing the CVV is prohibited outright."
                                ),
                                remediation=(
                                    "Tokenize card data in the browser with Stripe.js / Elements and "
                                    "store only the token (`pm_`/`tok_`) or the last four. If this "
                                    "field truly holds only last4, suppress with "
                                    "`# security: allow-card-field`."
                                ),
                                rule="no-pan-stored/raw-card-data",
                                standards=["OWASP:A02"],
                            )
                        )
        return out
