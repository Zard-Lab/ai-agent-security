---
type: Guard
title: "jwt-claims-validated"
description: "JWT decode disables a required claim check (exp/aud/iss/signature)."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "jwt-claims-validated"
checklist_section: ["2a"]
standards: ["ASVS:9.2.1", "ASVS:9.2.3", "OWASP:A02", "OWASP:A07", "SOC2:CC6.1"]
---

# JWT decode disables a required claim check (exp/aud/iss/signature)

## Threat

JWT libraries such as PyJWT expose an `options` dict that can individually disable
every claim check the library would otherwise enforce. Developers disable these
checks during testing or to perform non-security metadata reads, but the same code
paths reach production when the guard is not in place.

The concrete attack shapes enabled by each disabled key:

| Disabled key | Attack enabled |
|---|---|
| `verify_exp: False` | Token replay — an expired (possibly revoked) token is accepted indefinitely |
| `verify_aud: False` | Cross-service escalation — a token minted for service B is accepted by service A |
| `verify_iss: False` | Rogue issuer — a token signed by an attacker-controlled key is accepted |
| `verify_signature: False` | Full forgery — anyone can craft any payload with any claims |

Standards: OWASP:A07 (Identification and Authentication Failures), CWE:345 (Insufficient
Verification of Data Authenticity).

## Detection design

The guard performs a paren-depth walk over the full argument list of every `jwt.decode(`
or `PyJWT().decode(` call (multi-line safe). It fires when both conditions are true:

1. `options=` kwarg is present in the call.
2. At least one of the four verification keys appears with value `False`.

Regex shown (applied to the extracted call-args string):

```python
# Detects any of the four disabled keys
_VERIFY_DISABLED = re.compile(
    r'"(?:verify_exp|verify_aud|verify_iss|verify_signature)"\s*:\s*False',
    re.I,
)
```

The guard deliberately does **not** flag calls that lack `algorithms=` — that is the
`jwt-alg` guard's responsibility (no duplicate findings).

Pragma: `# security: allow-jwt-no-verify` anywhere in the file suppresses all findings
in that file.

## Severity rationale

HIGH. All four disabled checks directly enable token forgery or replay attacks that
bypass authentication entirely. This is not a misconfiguration risk — it is an active
authentication bypass. OWASP A07 maps to a broad category; CWE:345 is specific to
verification failure. HIGH (not CRITICAL) because exploitation requires the attacker to
hold or forge a token, not just send an unauthenticated request.

## Known bypasses (table)

| Bypass | Status |
|---|---|
| Options dict built dynamically (`options = build_opts()`) | Not detected — static analysis only |
| Key name in a variable (`verify_exp_key = "verify_exp"; options={verify_exp_key: False}`) | Not detected |
| Calling a jose-compatible library with a different decode function name | Not detected unless function is named `jwt.decode` or `PyJWT().decode` |
| Inline pragma on the decode line | Not applicable — pragma is file-level |

## FP scenarios (table)

| Scenario | Outcome | Notes |
|---|---|---|
| `jwt.decode(token, key, algorithms=["RS256"])` | Silent | No `options=` kwarg — guard skips |
| `options={"verify_exp": True, "verify_aud": True}` | Silent | All checks enabled |
| `options={"leeway": 10}` | Silent | No verification key set to False |
| Test helper with `# security: allow-jwt-no-verify` | Silent | File-level pragma suppresses |
| `jwt.decode` call in a file containing the pragma anywhere | Silent | Correct — file is opted out |

## Checklist items flipped (table)

| Item ID | Section | Description | Status |
|---|---|---|---|
| `2a-jwt-claims-validated` | §2a Authentication | JWT claims (exp/aud/iss/sig) are validated on every decode | covered |

## Tests (table)

| Test function | Scenario | Expected result |
|---|---|---|
| `test_jwt_claims_flags_verify_exp_false` | `options={"verify_exp": False, "verify_aud": True}` | 1 finding, rule `jwt-claims-validated/verify-disabled`, severity HIGH |
| `test_jwt_claims_flags_verify_signature_false` | `options={"verify_signature": False}` | 1 finding, severity HIGH |
| `test_jwt_claims_silent_on_safe_decode` | `jwt.decode(token, key, algorithms=["RS256"])` — no options | 0 findings |
| `test_jwt_claims_silent_on_all_true` | `options={"verify_exp": True}` | 0 findings |
| `test_jwt_claims_pragma_suppresses` | File contains `# security: allow-jwt-no-verify` | 0 findings |
| `test_jwt_claims_not_applicable_without_python` | `features={"frontend"}` | `applies()` returns False |

# Citations

[1] agentsec checklist item `2a-jwt-claims-validated` (§2a)
[2] ASVS:9.2.1
[3] ASVS:9.2.3
[4] OWASP:A02
[5] OWASP:A07
[6] SOC2:CC6.1
