"""Guard: an unauthenticated external trigger (inbound email / webhook) resumes an AI agent
session with an elevated permission mode, with no verified sender check (checklist §4).

**CVE-2026-57495** (AgenticMail, `@agenticmail/core` and siblings): any external email routed to
the bridge inbox caused the dispatcher to RESUME the operator's Claude Code session with
``permissionMode: 'bypassPermissions'``, embedding the attacker-controlled `from`/`subject`/
`preview` verbatim into the prompt the resumed agent reads — an indirect prompt injection into a
FULLY-privileged agent (Bash/Write/Edit/WebFetch + the platform's own tool belt) running as the
operator's own OAuth identity, reachable by anyone who can send an email to the address. No
sender verification gated the resume call at all.

This is structurally the SAME class `webhook_signature_not_verified.py` catches for data-forgery
(an external trigger trusted with no signature check) — but here the payload isn't a forged
event, it's a PERMISSION ESCALATION: the trigger doesn't just get processed, it gets to resume an
agent session with guardrails explicitly disabled. Grepped `bypassPermissions`/`permissionMode`
across every guard and the checklist before building this — zero hits; nothing in this codebase
already covers agent-permission-mode elevation from an external trigger.

**Detection (co-occurrence within one candidate scope — a function block in Python, a whole file
in JS/TS, mirroring `webhook_signature_not_verified.py`'s per-language scoping exactly):**

  * an INBOUND-TRIGGER signal: a route/webhook decorator or registration (the same
    `_PY_ROUTE_DECORATOR`/`_JS_ROUTE_MARKER` shapes `webhook_signature_not_verified.py` uses)
    co-occurring with an inbound-mail/webhook word (``inbound``, ``webhook``, ``mailgun``,
    ``sendgrid``, ``postmark``, ``ses`` + ``receive``, or the bare word ``email`` alongside a
    route/handler shape);
  * an ELEVATED-PERMISSION agent-resume signal: ``bypassPermissions``,
    ``permissionMode\\s*[:=]\\s*['"]bypassPermissions``, ``dangerouslySkipPermissions``,
    ``--dangerously-skip-permissions``, or ``skip_permissions``;
  * **no** sender-verification signal anywhere in the same scope — reuses
    `webhook_signature_not_verified.py`'s own HMAC/Ed25519/secret-token verification patterns
    (a legitimately-verified trigger elevating permissions after confirming the sender is a
    DIFFERENT, correctly-designed system), plus an explicit sender-allowlist check
    (``sender\\s*(?:not\\s+)?in\\b``, ``verify_sender(``, ``allowed_sender``).

In JS/TS, a verification signal and the route marker count only when they are live code, tested on
the shared anchor mask (`js_code_matches`, #1055). A verifier spelled out in a log string no longer
clears the finding, and a real one inside a `${...}` substitution still does.

Fires **CRITICAL** — this is privilege escalation plus prompt injection into a fully-privileged
agent, not merely a forgeable webhook payload. Suppress an audited case with
`# security: allow-unverified-agent-resume` (Python) / `// security: allow-unverified-agent-resume`
(JS/TS).

**Checklist item:** new — `4-agent-resume-trigger-verified`, no existing item covers external-
trigger-driven agent permission elevation (confirmed via grep of checklist.json before starting).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    js_code_matches,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_js_comments,
    strip_python_line_comment,
)

_PRAGMA = "security: allow-unverified-agent-resume"
_STANDARDS = ["OWASP:A01", "OWASP-LLM:LLM01"]

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")

# Route/handler registration — the same shapes `webhook_signature_not_verified.py` uses.
_PY_ROUTE_DECORATOR = re.compile(r"@\s*[\w.]+\.(?:route|post|api_route)\s*\(", re.IGNORECASE)
_JS_ROUTE_MARKER = re.compile(r"\b\w*(?:router|app)\s*\.\s*post\s*\(", re.IGNORECASE)

# The scope must ALSO name an inbound email/webhook trigger — bare "webhook", a named inbound-mail
# provider, an SES-style receive hook, or "email" itself (co-occurring with the route marker above,
# so an unrelated route mentioning "email" in prose alone does not count).
_INBOUND_TRIGGER = re.compile(
    r"\bwebhook\b|\binbound\b|\bmailgun\b|\bsendgrid\b|\bpostmark\b|\bses\b[\s\S]{0,80}\breceive\b|\bemail\b",
    re.IGNORECASE,
)

# The elevated-permission agent-resume signal. `bypassPermissions` alone is Claude Code's own
# documented flag name; the others are the CLI/SDK equivalents named in the CVE writeup.
_ELEVATED_PERMISSION = re.compile(
    r"\bbypassPermissions\b"
    r"|permissionMode\s*[:=]\s*['\"]bypassPermissions['\"]"
    r"|\bdangerouslySkipPermissions\b"
    r"|--dangerously-skip-permissions"
    r"|\bskip_permissions\b",
    re.IGNORECASE,
)

# Sender-verification signals: the HMAC/Ed25519/secret-token primitives
# `webhook_signature_not_verified.py` already recognizes (a legitimately-verified trigger source),
# plus an explicit sender-identity allowlist check — this guard's own concern, since the CVE's
# actual gap was "no check on WHO the email/webhook came from," not just "no HMAC."
_SIGNATURE_VERIFY = re.compile(
    r"\bhmac\s*\.\s*(?:compare_digest|new)\s*\(|\bcrypto\s*\.\s*timingSafeEqual\s*\(|\bcreateHmac\s*\("
    r"|\bverify_key\s*\.\s*verify\s*\(|\bVerifyKey\s*\(|\bnacl\s*\.\s*sign\s*\.\s*detached\s*\.\s*verify\s*\("
    r"|\bverifyKey\s*\(|\bed25519\s*\.\s*verify\s*\(",
    re.IGNORECASE,
)
_SENDER_ALLOWLIST_CHECK = re.compile(
    r"\bsender\s*(?:not\s+)?in\b|\bverify_sender\s*\(|\ballowed_sender\b|\ballowlisted_sender\b"
    r"|\bfrom_\s*(?:not\s+)?in\b|\btrusted_sender\b",
    re.IGNORECASE,
)


def _has_verification(scope: str) -> bool:
    return bool(_SIGNATURE_VERIFY.search(scope) or _SENDER_ALLOWLIST_CHECK.search(scope))


def _is_candidate(scope: str, route_marker: re.Pattern[str]) -> bool:
    return bool(
        route_marker.search(scope)
        and _INBOUND_TRIGGER.search(scope)
        and _ELEVATED_PERMISSION.search(scope)
    )


# The JS/TS twins of the two predicates above, which test the anchor mask as well (#1055). A
# verifier spelled out in a log or error string (`log.info('TODO: crypto.createHmac(sha256) check')`)
# used to clear the finding exactly like a real call, so a credit now counts only when its call `(`,
# or the first character of the allowlist phrase, is live code, including code inside a `${...}`.
# On the trigger side only the route's `(` must be code: the inbound word usually sits in the route
# path string, and `'bypassPermissions'` is a string value on purpose.
def _js_has_verification(code: str, mask: str) -> bool:
    return any(js_code_matches(_SIGNATURE_VERIFY, code, mask, anchor=lambda m: m.end() - 1)) or any(
        js_code_matches(_SENDER_ALLOWLIST_CHECK, code, mask, anchor=lambda m: m.start())
    )


def _js_has_route(code: str, mask: str) -> bool:
    return any(js_code_matches(_JS_ROUTE_MARKER, code, mask, anchor=lambda m: m.end() - 1))


class AgentResumeUnverifiedTriggerGuard(Guard):
    id = "agent-resume-unverified-trigger"
    title = "Unauthenticated external trigger resumes an agent session with elevated permissions"
    area = "AI agent"

    # bridge_dispatch.py: an inbound-email webhook handler resumes a Claude Code session with
    # bypassPermissions and no sender check -> fires
    # agent-resume-unverified-trigger/unverified-trigger-elevated-permission.
    canary_plant = CanaryPlant(
        files={
            "bridge_dispatch.py": (
                "from fastapi import APIRouter, Request\n"
                "router = APIRouter()\n\n\n"
                '@router.post("/inbound/email-webhook")\n'
                "async def handle_inbound_email(request: Request):\n"
                "    payload = await request.json()\n"
                "    resume_session(\n"
                "        session_id=payload['thread_id'],\n"
                "        prompt=f\"New mail from {payload['from']}: {payload['subject']}\",\n"
                "        permissionMode='bypassPermissions',\n"
                "    )\n"
            ),
        },
        expects=frozenset(
            {"agent-resume-unverified-trigger/unverified-trigger-elevated-permission"}
        ),
    )

    def applies(self, profile: StackProfile) -> bool:
        return bool({"python", "javascript", "typescript"} & profile.features)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        if "python" in profile.features:
            out += self._scan_python(root, profile)
        if {"javascript", "typescript"} & profile.features:
            out += self._scan_js(root, profile)
        return out

    def _scan_python(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                text = read(f)
                if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                    continue
                out.extend(self._scan_python_file(root, f, text))
        return out

    def _scan_python_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        code_text = "\n".join(strip_python_line_comment(ln) for ln in text.splitlines())
        for def_lineno, block in iter_functions(text, filename=f):
            code_block = "\n".join(strip_python_line_comment(ln) for ln in block.splitlines())
            if not _is_candidate(code_block, _PY_ROUTE_DECORATOR):
                continue
            # Verification is checked across the WHOLE FILE, not just this function's block —
            # mirrors webhook_signature_not_verified.py's own leniency for a same-file
            # verify_sender()/HMAC helper a route handler delegates to.
            if _has_verification(code_text):
                continue
            block_start = self._block_start_line(block, def_lineno)
            m = _ELEVATED_PERMISSION.search(code_block)
            relative_line = code_block.count("\n", 0, m.start()) + 1 if m else 1
            lineno = block_start + relative_line - 1
            out.append(self._finding(root, f, lineno))
        return out

    @staticmethod
    def _block_start_line(block: str, def_lineno: int) -> int:
        """1-based line where `block` starts — mirrors `webhook_signature_not_verified.py`'s
        own helper of the same name/shape."""
        lines_before_def = 0
        for ln in block.splitlines():
            if re.match(r"[ \t]*(?:async[ \t]+)?def[ \t]", ln):
                break
            lines_before_def += 1
        return def_lineno - lines_before_def

    def _scan_js(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _JS_SUFFIXES):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            code = strip_js_comments(text)
            if not _is_candidate(code, _JS_ROUTE_MARKER):
                continue
            mask = strip_js_comments(text, strip_strings=True, keep_substitutions=True)
            if not _js_has_route(code, mask) or _js_has_verification(code, mask):
                continue
            m = _ELEVATED_PERMISSION.search(code)
            lineno = code.count("\n", 0, m.start()) + 1 if m else 1
            out.append(self._finding(root, f, lineno))
        return out

    def _finding(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "This handler receives an external, unauthenticated trigger (email/webhook) and "
                "resumes an agent session with an elevated permission mode (bypassPermissions or "
                "equivalent) — with no sign of verifying who sent the trigger. Anyone who can "
                "reach the endpoint or send an email to the bridge address can embed instructions "
                "in the trigger's content (subject/body/from) that the resumed, fully-privileged "
                "agent reads as part of its prompt — indirect prompt injection into an agent "
                "running with the operator's own credentials and guardrails disabled "
                "(CVE-2026-57495's exact shape)."
            ),
            remediation=(
                "Verify the trigger's sender before resuming any privileged session: an HMAC/"
                "signature check for a webhook (see `webhook-signature-not-verified`'s "
                "remediation), or a DKIM/sender-allowlist check for inbound mail. Never resume a "
                "session with an elevated permission mode from an unauthenticated trigger — drop "
                "to the default (non-bypassing) permission mode unless the sender is verified. "
                "Suppress with `# security: allow-unverified-agent-resume` "
                "(Python) / `// security: allow-unverified-agent-resume` (JS/TS) only when "
                "verification is provably handled at a different layer."
            ),
            rule="agent-resume-unverified-trigger/unverified-trigger-elevated-permission",
            standards=list(_STANDARDS),
        )
