"""Guard: bare except: pass or except Exception: pass silently swallows exceptions (§8).

A common coding shortcut in Python is to catch exceptions broadly and do nothing:

  try:
      check_permission(user)
  except:
      pass   # <-- permission check silently fails open

  try:
      verify_auth_token(token)
  except Exception:
      pass   # <-- authentication failure swallowed

When the swallowed exception came from a security enforcement point
(authentication, authorization, permission check), the caller continues as if the
check had passed. This is a classic "fail open" defect: the system is designed to
enforce access control but the exception path silently grants access instead.

Three patterns are flagged:

  **`bare-except-pass`** (MEDIUM): A bare `except:` clause (catches everything,
  including SystemExit and KeyboardInterrupt) whose body is only `pass`. No logging,
  no re-raise — the failure is invisible.

  **`bare-except-pass`** (MEDIUM): `except Exception: pass` — broader than necessary
  and still completely silent.

  **`bare-except-pass`** (MEDIUM): `except <SecurityExceptionName>: pass` where
  the exception name contains Auth, Permission, Forbidden, Unauthorized, or Security —
  the developer explicitly caught a security exception and threw the information away.

**Why MEDIUM?** A silent swallow by itself does not prove exploitation. In non-security
paths the impact is reliability only. But when the surrounding logic enforces access
control, the risk is equivalent to a missing authorization check (OWASP:A05, CWE-390).
The rule fires on the structural pattern; a human confirms whether the try-block is
actually a security gate.

**False-negative scope:** Multi-line handler bodies (e.g., `logger.info(...)` then
nothing else meaningful) are not caught. The guard only fires when the handler body
is a single `pass` statement, keeping the false-positive rate very low at the cost
of missing more complex silent-swallow patterns.

**Suppress:** `# security: allow-bare-except` anywhere in a file silences this check
for that file. Use only when the try-block is demonstrably not a security gate and
the bare-pass is intentional (e.g., a best-effort cleanup path with documented
rationale).
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

_PRAGMA = "security: allow-bare-except"

_STANDARDS = ["OWASP:A05", "CWE-390"]

# Pattern 1: bare `except:` (no exception type) followed by `pass` on next line.
_BARE_EXCEPT = re.compile(r"^(\s*)except\s*:\s*$")

# Pattern 2: `except Exception:` followed by `pass` on next line.
_EXCEPT_EXCEPTION = re.compile(r"^(\s*)except\s+Exception\s*:\s*$")

# Pattern 3: `except <SecurityName>:` where the name suggests a security exception.
_EXCEPT_SECURITY = re.compile(
    r"^(\s*)except\s+\w*(?:Auth|Permission|Forbidden|Unauthorized|Security)\w*\s*:\s*$",
    re.IGNORECASE,
)

# Combined set of patterns that flag an `except` header line.
_EXCEPT_PATTERNS = (_BARE_EXCEPT, _EXCEPT_EXCEPTION, _EXCEPT_SECURITY)

# Matches a line whose only meaningful content is `pass` (optionally followed by a comment).
_PASS_ONLY = re.compile(r"^\s*pass\s*(?:#.*)?$")

# For BROAD patterns (bare except / except Exception) we require positive evidence of a
# security operation in the try-block before firing — cleanup/enrichment/script code that
# uses `except: pass` for resilience is NOT a fail-open defect.
# _EXCEPT_SECURITY already fires unconditionally because the exception name itself is evidence.
_BROAD_PATTERNS = (_BARE_EXCEPT, _EXCEPT_EXCEPTION)
_SECURITY_OP = re.compile(
    r"\b(?:"
    r"authenticate|authoriz[e]?|check_permission|require_(?:auth|role|perm|access)|"
    r"verify_token|validate_token|decode_token|"
    r"get_current_user|current_user|has_permission|is_authorized|"
    r"login_required|access_control|permission_check|"
    r"jwt\.decode|bearer|api_key_check|credential"
    r")\b",
    re.IGNORECASE,
)
_TRY_BLOCK_LOOKAHEAD = 25  # lines to scan before the except: for security context


class FailSafeExceptionGuard(Guard):
    id = "fail-safe-exception"
    title = "Silent exception swallow — security check may fail open"
    area = "Reliability"

    # exception_handler.py: bare except: pass around authenticate() -> fires
    # fail-safe-exception/bare-except-pass.
    canary_plant = CanaryPlant(
        files={
            "exception_handler.py": (
                "def process_request(data):\n"
                "    try:\n"
                "        authenticate(data)\n"
                "    except:\n"
                "        pass\n"
            ),
        },
        expects=frozenset({"fail-safe-exception/bare-except-pass"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[Path] = set()

        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue  # best-effort try/except in tests/fixtures is not a fail-open gate

                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue

                lines = text.splitlines()
                for i, line in enumerate(lines):
                    matched_pat = None
                    for pat in _EXCEPT_PATTERNS:
                        if pat.match(line):
                            matched_pat = pat
                            break
                    if matched_pat is None:
                        continue

                    # The handler body must be `pass` on the very next line.
                    next_idx = i + 1
                    if next_idx >= len(lines):
                        continue
                    if not _PASS_ONLY.match(lines[next_idx]):
                        continue

                    # For broad patterns (bare except / except Exception), only fire when
                    # the preceding try-block shows evidence of a security operation.
                    # Cleanup/enrichment/script code using except:pass for resilience is
                    # not a fail-open defect — requiring security context avoids those FPs.
                    if matched_pat in _BROAD_PATTERNS:
                        start = max(0, i - _TRY_BLOCK_LOOKAHEAD)
                        look_back = "\n".join(lines[start:i])
                        if not _SECURITY_OP.search(look_back):
                            continue

                    lineno = i + 1  # 1-based line number of the except: line
                    findings.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title="Silent exception swallow — security check may fail open",
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                "An exception handler catches exceptions broadly (`except:`, "
                                "`except Exception:`, or a security-named exception type) and "
                                "silently discards them with `pass`. If the protected try-block "
                                "is a security gate (authentication, authorization, permission "
                                "check), a failure will be swallowed and the caller will "
                                "continue as if the check passed — a classic fail-open defect."
                            ),
                            remediation=(
                                "At minimum, log the exception before discarding it so failures "
                                "are visible in monitoring. For security gates, re-raise or "
                                "return a safe default that denies access. Replace "
                                "`except: pass` / `except Exception: pass` with a specific "
                                "exception type + a logged handler. Suppress with "
                                "`# security: allow-bare-except` only after confirming the "
                                "try-block is not a security enforcement point."
                            ),
                            rule="fail-safe-exception/bare-except-pass",
                            standards=list(_STANDARDS),
                        )
                    )

        return findings
