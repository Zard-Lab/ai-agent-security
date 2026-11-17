---
type: Guard
title: "cfn-cognito-mfa-off"
description: "No CloudFormation Cognito User Pool with multi-factor authentication disabled."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-cognito-mfa-off"
checklist_section: ["6c"]
standards: ["OWASP:A07", "CWE-308"]
---

# Cognito User Pool with MFA disabled (CloudFormation)

Flags `AWS::Cognito::UserPool` resources whose `MfaConfiguration` is `OFF` — explicitly, or by
omission. Closes checklist item `6c-cfn-cognito-mfa-off` (§6c, Container & Deployment Hardening).
This is a **new** checklist item — no existing agentsec item covered Cognito MFA configuration
before this guard.

## The threat

Amazon Cognito User Pools authenticate end users of an application. `MfaConfiguration` decides
whether those users must (`ON`) or may (`OPTIONAL`) enrol a second factor, or are never asked for
one at all (`OFF`). A user pool stuck at `OFF` means every account in it is protected by a
password alone. Credential stuffing, phishing, and password reuse are the most common initial-
access vectors in the wild, and MFA is the single strongest deterministic mitigation against all
three — an account whose only defense is a password is one leaked credential away from full
takeover. CWE-308 (Use of Single-Factor Authentication).

## Exploitability rationale

HIGH. This is not itself an exploit primitive, but it is a direct account-takeover risk
amplifier for every user in the pool: it removes the one control that would otherwise stop a
compromised or guessed password from becoming a full account compromise. Unlike a defense-in-depth
gap several steps removed from impact, disabled MFA sits directly in the account-takeover chain.

## What counts as a hit (and what doesn't)

- `AWS::Cognito::UserPool` with `MfaConfiguration: OFF` (YAML) or `"MfaConfiguration": "OFF"`
  (JSON), explicit → fires.
- `AWS::Cognito::UserPool` with **no** `MfaConfiguration` property at all → fires. AWS's own
  `AWS::Cognito::UserPool` resource documentation states the property defaults to `OFF` when
  omitted, so an author who never sets it gets the vulnerable state silently, not a safe default —
  the same "missing means insecure" shape as `EnableKeyRotation` on `AWS::KMS::Key`
  (`cfn-kms-key-rotation-not-enabled`). This mirrors cfn_nag's own rule name for this exact check,
  `CognitoUserPoolMfaConfigurationOnorOptionalRule` — a rule that PASSES only when the value is
  explicitly `ON` or `OPTIONAL`, i.e. treats both missing and `OFF` as failures.
- `MfaConfiguration: ON` → silent (MFA required).
- `MfaConfiguration: OPTIONAL` → silent (MFA offered; users may enrol).
- Any other resource type → silent.
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).

## When NOT to flag (and the pragma)

- `MfaConfiguration: ON` or `MfaConfiguration: OPTIONAL` → silent (both are acceptable states).
- A throwaway/internal pool by design → suppress explicitly (YAML templates only — JSON has no
  comment syntax, so a JSON-authored template cannot carry this pragma at all, a known limitation
  shared by every CFN guard in this batch):

```yaml
Resources:
  InternalTestPool:
    Type: AWS::Cognito::UserPool
    Properties:
      UserPoolName: internal-smoke-test  # security: allow-cfn-cognito-mfa-off
```

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the property's absence/value directly;
  textual/regex-only, same as every guard in this batch.
- **File-level location, not line-level** — the finding reports the template file, not a specific
  line (see `agentsec/cfn.py`'s module docstring for why: a JSON block is a `json.dumps`
  reconstruction with no original line mapping to report).
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **A value driven by a CloudFormation parameter or `Fn::If`** (e.g.
  `MfaConfiguration: !Ref MfaSetting`) is not resolved — the guard sees the literal text, not the
  parameter's effective value at deploy time, so a template that always deploys with MFA on via a
  parameter default could still be flagged (or, if the default resolves to `OFF`, correctly not
  distinguished from a hardcoded `OFF`).
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.

## What this guard does NOT prove

A clean scan means no `AWS::Cognito::UserPool` resource in the scanned templates has MFA fully
disabled — it says nothing about a user pool created outside CloudFormation entirely (the AWS
Console, a different IaC tool, a nested stack this scan didn't independently discover), whether
MFA is actually enforced end-to-end in the application's sign-in flow, or whether the configured
MFA factors (`SoftwareTokenMfaConfiguration`, `SmsConfiguration`) are themselves correctly wired.

## Canary plant

`cfn_cognito_pool.yaml` — `AWS::Cognito::UserPool` with `MfaConfiguration: OFF`. Expected rule:
`cfn-cognito-mfa-off/mfa-disabled`.

# Examples

Vulnerable (fires):

```yaml
Resources:
  AppUserPool:
    Type: AWS::Cognito::UserPool
    Properties:
      UserPoolName: app-users
      MfaConfiguration: OFF
```

Also vulnerable (fires — implicit default):

```yaml
Resources:
  AppUserPool:
    Type: AWS::Cognito::UserPool
    Properties:
      UserPoolName: app-users
```

Fixed (silent):

```yaml
Resources:
  AppUserPool:
    Type: AWS::Cognito::UserPool
    Properties:
      UserPoolName: app-users
      MfaConfiguration: ON
      EnabledMfas:
        - SOFTWARE_TOKEN_MFA
```

# Citations

[1] agentsec checklist item `6c-cfn-cognito-mfa-off` (§6c)
[2] OWASP:A07 (Identification and Authentication Failures)
[3] CWE-308 (Use of Single-Factor Authentication)
[4] cfn_nag (`stelligent/cfn_nag`) — `CognitoUserPoolMfaConfigurationOnorOptionalRule.rb`, rule
    `F78` (provenance only; detection logic here is original)
[5] AWS `AWS::Cognito::UserPool` resource documentation — `MfaConfiguration` property, default
    `OFF`
