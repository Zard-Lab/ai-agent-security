---
type: Guard
title: "fail-safe-exception"
description: "Silent exception swallow — security check may fail open."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "fail-safe-exception"
checklist_section: ["8"]
standards: ["ASVS:16.5.3", "OWASP:A05", "OWASP:A10"]
---

# Silent exception swallow — security check may fail open

## Threat

When a security enforcement point (authentication check, permission verification, authorization gate)
raises an exception and that exception is silently swallowed by a broad `except: pass` or
`except Exception: pass` block, the caller receives no indication that the check failed. Execution
continues as if the check had passed, effectively granting access unconditionally whenever the check
throws. This is the canonical "fail open" defect: the system was designed to enforce a security
invariant, but the error path bypasses it entirely.

Security-named exception types (e.g. `AuthenticationError`, `PermissionDenied`, `ForbiddenError`)
being silenced in a `pass`-only handler are an especially direct signal: the developer explicitly
modelled a security failure as an exception type and then discarded it.

Standards: **OWASP:A05** (Security Misconfiguration / broken access control), **CWE-390** (Detection
of Error Condition Without Action).

## Detection design

The guard scans every Python file reachable from `python_scan_dirs`. For each file it applies three
regex patterns against each line, then checks whether the immediately following line is `pass`-only.

### Regex patterns (applied to the `except` header line)

```
# Pattern 1 — bare except (catches everything)
^(\s*)except\s*:\s*$

# Pattern 2 — broad Exception catch
^(\s*)except\s+Exception\s*:\s*$

# Pattern 3 — security-named exception type (case-insensitive)
^(\s*)except\s+\w*(?:Auth|Permission|Forbidden|Unauthorized|Security)\w*\s*:\s*$
```

The next-line check:

```python
stripped = next_line.strip()
stripped == "pass" or stripped.startswith("pass  ") or stripped.startswith("pass\t") or stripped.startswith("pass #")
```

A finding fires only when both conditions hold: the `except` header matches one of the three patterns
AND the body's first line is `pass`. This keeps the false-positive rate very low.

### Feature gate

```python
def applies(self, profile: StackProfile) -> bool:
    return "python" in profile.features
```

### Pragma suppress

Any file carrying a `# security: allow-bare-except` comment is skipped entirely (a string literal quoting
the phrase does not count, #424).

## Severity rationale

**MEDIUM.** The structural pattern (broad silent catch) does not prove exploitation on its own.
Impact depends on whether the protected try-block is actually a security gate. In non-security paths
the defect is a reliability issue only. MEDIUM reflects the ambiguity: the pattern is almost always
a code-quality problem and sometimes a critical security bypass, warranting prompt review without
triggering a CI hard-fail by default.

## Known bypasses / false negatives

| Bypass | Why missed | Mitigation |
|---|---|---|
| `pass` not on the immediately next line (blank line between) | Guard looks only at line `i+1` | Low real-world impact; indentation prevents blanks inside a handler |
| Multi-statement handler: `logger.debug("x")` then `pass` | Body has more than one line; guard fires only on single-`pass` bodies | Acceptable trade-off for low FP rate |
| Silent swallow via `return None` instead of `pass` | Different token; guard does not match `return` | Would require a second rule |
| Broad catch with comment only: `except Exception:  # ok` | No body line; guard checks the following line for `pass` | Not flagged; rare pattern |
| Exception name not matching the keyword list | `CredentialError` (no Auth/Permission/...) missed | Keyword list can be extended |

## False positive scenarios

| Scenario | Why it fires | How to resolve |
|---|---|---|
| Best-effort cleanup: `try: os.unlink(tmpfile) / except: pass` | Matches bare-except-pass structurally | Add `# security: allow-bare-except` with a comment explaining it is cleanup-only |
| Optional feature probe: `try: import ujson / except Exception: pass` | Matches except-Exception-pass | Same pragma; this is idiomatic Python for optional imports |
| Test teardown: `except Exception: pass` in a pytest fixture | Matches in any `.py` file | Pragma on the fixture file, or move teardown to a dedicated helper |

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| 8-fail-safe-on-exception | uncovered | covered | Guard detects bare-except-pass and except-Exception-pass patterns that allow security checks to fail open silently |

## Tests

| Test | Validates |
|---|---|
| `test_fail_safe_exception_flags_bare_except_pass` | True positive: `except: / pass` fires one finding with the correct rule |
| `test_fail_safe_exception_flags_except_exception_pass` | True positive: `except Exception: / pass` fires |
| `test_fail_safe_exception_flags_security_named_exception` | True positive: `except PermissionDenied: / pass` fires |
| `test_fail_safe_exception_silent_logged_reraise` | False positive guard: `except Exception: / logger.exception(...) / raise` stays silent |
| `test_fail_safe_exception_silent_specific_with_reraise` | False positive guard: `except ValueError as e: / raise HTTPException(...)` stays silent |
| `test_fail_safe_exception_pragma_silences` | Pragma: file with pragma is skipped entirely |
| `test_fail_safe_exception_not_applicable_without_python` | Feature gate: guard does not apply when `python` not in features |

# Citations

[1] agentsec checklist item `8-fail-safe-on-exception` (§8)
[2] ASVS:16.5.3
[3] OWASP:A05
[4] OWASP:A10
