---
type: Guard
title: "cfn-waf-default-allow"
description: "CloudFormation classic WAF WebACL whose DefaultAction is ALLOW rather than BLOCK."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-waf-default-allow"
checklist_section: ["6a"]
standards: ["OWASP:A05"]
---

# WAF WebACL DefaultAction is not ALLOW (CloudFormation)

Flags `AWS::WAF::WebACL` (classic WAF) resources whose `DefaultAction.Type` is `ALLOW`. This is a
**new** checklist item — no existing agentsec item covered WAF WebACL default-action configuration
before this guard — added alongside it rather than reusing an unrelated one.

## The threat

A WAF WebACL's `DefaultAction` governs any request that doesn't match one of the WebACL's own
configured rules. When that default is `ALLOW`, the WebACL's protection is opt-in per rule rather
than a real default-deny posture: unmatched traffic — in practice, most traffic nobody wrote a
specific rule for — passes straight through the WAF as if it weren't there. This is the
misconfiguration a security review catches by reading the WebACL definition, not something an
attacker triggers directly.

## Exploitability rationale

MEDIUM, not HIGH. A `DefaultAction: ALLOW` WebACL doesn't stop enforcing anything it was
specifically configured to block — the rules that ARE attached still fire. The gap is everything
those rules don't cover, which is a posture weakness (silent under-protection) rather than a direct
bypass of an active control. Same severity class the codebase gives other "the control is present
but configured to fail open" findings.

## What counts as a hit (and what doesn't)

- `AWS::WAF::WebACL` with `DefaultAction.Type: ALLOW` (or `"DefaultAction": {"Type": "ALLOW"}` in
  JSON) → fires.
- `DefaultAction.Type: BLOCK` → silent (the fix — unmatched traffic is denied by default).
- `AWS::WAFv2::WebACL` (the newer WAFv2 resource type) → out of scope for this guard; only the
  classic `AWS::WAF::WebACL` resource type is checked.
- A `Rules` list entry's own `Action`/`OverrideAction` (e.g. `Type: ALLOW` on one specific rule) →
  silent. That's an individual rule's action, not the WebACL's default — see "Detection scope"
  below for how the regex tells the two apart.
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).

## Detection scope (the anchoring choice, and why)

This guard's regex requires `Type: ALLOW` / `"Type": "ALLOW"` to appear **immediately** after a
`DefaultAction` key — only whitespace, line breaks, and an optional opening `{` (the
JSON-reconstruction shape) are allowed in between. That mirrors the real CloudFormation shape:
`AWS::WAF::WebACL`'s `DefaultAction` is a `WafAction` object whose only property is `Type`, so a
real template's `DefaultAction` is always followed directly by its own `Type` key.

A wider "`DefaultAction` and `Type: ALLOW` both present somewhere within N characters of each
other" span was tried first and produces a real false positive: a WebACL with `DefaultAction:
BLOCK` whose separate `Rules` list contains an entry with its own `Action: {Type: ALLOW}` (an
entirely normal, safe pattern — one specific rule explicitly allowing traffic that matched it,
while everything unmatched still gets the `BLOCK` default) gets flagged anyway, because the regex
just finds *some* `Type: ALLOW` after the `DefaultAction` keyword appears earlier in the block. The
immediate-adjacency anchor used here does not have that failure mode — verified in an adversarial
self-test before this guard's formal tests were written — without requiring a real nested-object
parse, which this codebase's CFN guards don't do (see `agentsec/cfn.py`'s module docstring).

## When NOT to flag (and the pragma)

- `DefaultAction.Type: BLOCK` → silent (the fix).
- A WebACL that is intentionally monitor-only, with real enforcement done elsewhere → suppress
  explicitly (YAML templates only — JSON has no comment syntax, so a JSON-authored template cannot
  carry this pragma at all, a known limitation shared by every CFN guard in this batch):

```yaml
Resources:
  MonitorOnlyWebAcl:
    Type: AWS::WAF::WebACL
    Properties:
      DefaultAction:  # security: allow-waf-default-allow
        Type: ALLOW
```

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the property's textual shape directly;
  does not resolve a `DefaultAction` driven by a CloudFormation parameter or condition.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding
  reports the template file, not a specific line (see `agentsec/cfn.py`'s module docstring for
  why: a JSON block is a `json.dumps` reconstruction with no original line mapping to report).
- **Textual/regex-only, not a real structural parse.** The immediate-adjacency anchor handles the
  common `Rules`-list false positive described above, but an unusual authoring style that puts
  other content directly between `DefaultAction` and its `Type` key (not standard for this
  resource's schema, but text is text) could in principle evade or misfire.
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **`AWS::WAFv2::WebACL` is not covered.** The newer WAFv2 resource has a differently-shaped
  `DefaultAction` (`{Allow: {}}` / `{Block: {}}`, not a `Type` string) and is out of scope for this
  guard entirely — a separate check would be needed for it.

## What this guard does NOT prove

A clean scan means no `AWS::WAF::WebACL` resource in the scanned templates sets `DefaultAction.Type:
ALLOW` textually — it says nothing about whether the WebACL's attached `Rules` actually cover the
traffic that matters, whether the WebACL is associated with the resource it's meant to protect at
all, or a WAFv2 WebACL configured the same way (out of scope, see above).

## Canary plant

`cfn_waf_webacl.yaml` — `AWS::WAF::WebACL` with `DefaultAction: {Type: ALLOW}`. Expected rule:
`cfn-waf-default-allow/default-action-allow`.

# Examples

Fires:

```yaml
Resources:
  MyWebAcl:
    Type: AWS::WAF::WebACL
    Properties:
      Name: my-web-acl
      MetricName: myWebAcl
      DefaultAction:
        Type: ALLOW
```

Silent (the fix):

```yaml
Resources:
  MyWebAcl:
    Type: AWS::WAF::WebACL
    Properties:
      DefaultAction:
        Type: BLOCK
```

# Citations

[1] agentsec checklist item `6a-cfn-waf-default-allow` (§6a)
[2] OWASP:A05 (Security Misconfiguration)
[3] cfn_nag (`stelligent/cfn_nag`) — `WafWebAclDefaultActionRule.rb`, rule `F665` (provenance only;
    detection logic here is original)
