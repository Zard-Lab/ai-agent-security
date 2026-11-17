---
type: Research
title: AI-Agent Workload IAM Policy Patterns
description: Statically-detectable AWS IAM risk patterns for AI-agent execution-role policies, distilled from a static IAM policy linter targeting Bedrock/SageMaker agent workloads.
tags: [research, llm, iam, aws, bedrock, sagemaker]
status: stable
generated: { by: agent:research-cycle, at: 2026-10-08T00:00:00Z }
stale_after: 2027-01-06
---

# AI-Agent Workload IAM Policy Patterns

## What this covers

An AI agent's AWS execution-role IAM policy is a distinct review surface from a human operator's
role: the policy is reachable by anything that can prompt-inject or otherwise influence the
agent's behavior, and it is routinely copy-pasted from deployment tooling into the agent's own
runtime role without re-scoping. This page covers patterns specific to that surface, distilled
from poojakira/aws-agent-identity-guard [1], a static IAM policy linter targeting Bedrock/SageMaker
agent workloads (provenance and licence below).

## Format note: bare policy JSON vs. Terraform

Several of these patterns were already checkable in Terraform `.tf` source; the gap was that an
AI agent's IAM policy frequently ships as a standalone JSON document (the body passed to
`boto3.create_policy()`, or committed for review alongside an agent definition) with no
Terraform/CloudFormation wrapper at all. Any IAM-policy static check limited to one infrastructure
format misses the policies that ship the other way.

## Detection patterns

| Pattern | What it catches | How |
|---|---|---|
| `NotAction`/`NotResource` + `Allow` | "Allow every action except these few": the grant silently widens as AWS adds new actions/services | Statement carries both keys under `Effect: Allow` |
| Escalation action without the RIGHT condition | `iam:PassRole` with a `Condition` present but missing `iam:PassedToService` still lets the role be passed to any service; presence of *some* condition isn't the same as presence of the *correct* one | Action-specific condition-key check, not just "any Condition" |
| Partial wildcard expanding to a dangerous action | `iam:*Role*` doesn't look like a wildcard-everything grant, but glob matching (`fnmatch`, the same semantics AWS's own policy evaluation uses) shows it covers `iam:PassRole` | Match the action pattern against a known-dangerous-action set via shell-glob semantics |
| Trust-policy confused deputy | A service that assumes a role on behalf of ANOTHER resource (SNS, S3, EventBridge, CloudTrail, Config, CloudWatch Logs) trusted with no `aws:SourceArn`/`SourceAccount`/`SourceOrg*` condition, which is AWS's documented cross-service confused-deputy mitigation. The source tool's broader form (every service principal, and every account ARN without `sts:ExternalId`) fired on ordinary Lambda/ECS/EC2 service roles and same-account trusts, so agentsec ships only the delivery-service subset (PR #1051 review) | Service-principal list plus a source-scoping condition-key check, on statements that grant `sts:AssumeRole*` |
| Control-plane action on a runtime role | An agent that only needs to RUN inference holds the action to CREATE/MODIFY what it runs on (`bedrock:CreateAgent`, `sagemaker:CreateTrainingJob`), so it can reconfigure its own capabilities or disable its own guardrails | Action-name membership in a control-plane action set, distinct from the data-plane action set |
| Unscoped tool-execution/data-access action | `Resource: "*"` on a tool-invocation action (Lambda, Bedrock model invoke) or a data-access action (S3 write, DynamoDB scan) hands the agent every matching resource in the account, not just its intended tool/table/model | Per-service resource-scoping check (ARN prefix, model-ID ARN segment, row/attribute condition) |
| Cross-statement kill-chain combination | No single statement looks dangerous, but credential-READ actions (`secretsmanager:GetSecretValue`) combined with identity-PIVOT actions (`sts:AssumeRole`, `iam:PassRole`) elsewhere in the same policy describe the two steps of a credential-theft-then-pivot chain | Pool every granted action across the whole policy document; check for 2-of-3 category combinations |

## Coverage status

Three new agentsec checklist items (§6c, Container & Deployment Hardening): control-plane action
exposure, unscoped tool/data-access actions, and the cross-statement kill-chain combination. Four
existing checklist items widened to also cover bare IAM policy JSON documents, not just Terraform.
All seven guards are dependency-free (standard library `re`/`fnmatch` only) and scan both `.tf` and
`.json` files via a shared, format-agnostic statement-block walker.

## Provenance and licence

- **Upstream:** poojakira/aws-agent-identity-guard, https://github.com/poojakira/aws-agent-identity-guard,
  module `src/aws_agent_identity_guard/scanner.py` [1]. The action lists and check designs behind
  `agent-iam-control-plane-exposure` (`BEDROCK_CONTROL_PLANE`/`SAGEMAKER_CONTROL_PLANE`),
  `agent-iam-tool-resource-unscoped` (`TOOL_EXECUTION_PATTERNS`, AIG006/014/015/018),
  `agent-iam-killchain-combination` (`_scan_killchain_combinations`, AIG019/020/021) and the
  `iam-wildcard` partial-wildcard set were adapted from it on 2026-10-08. The upstream commit read
  was not recorded; `8e6fa80e` (2026-10-07) is the upstream head at that date and is cited as the
  reference version. The identifiers above were re-checked at that commit on 2026-10-18.
- **Licence at that version: MIT**, `Copyright (c) 2026 Pooja Kiran` (the repository's `LICENSE` from
  the initial commit `b4799d64` through `8e6fa80e`, re-checked 2026-10-18).
- **Licence change:** on 2026-10-13 (upstream commit `a7a9afdb`) the repository adopted a
  proprietary, all-rights-reserved licence for new material. Its notice states that licences
  validly granted for earlier versions remain effective and are not retroactively withdrawn, and
  the prior MIT text is preserved upstream at `docs/license-history/LICENSE-BEFORE-2026-10-13.txt`.
  The material adapted here predates the change. Anything taken from upstream after 2026-10-13
  would need the owner's written permission, so a re-sync from upstream is NOT covered by this
  notice.
- **MIT notice**, reproduced as its terms require for copies or substantial portions:

```text
MIT License

Copyright (c) 2026 Pooja Kiran

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- **Divergences from upstream** (PR #1051 review): upstream rates the trust-policy ExternalId gap as
  a MEDIUM advisory (AIG-TP002); agentsec does not ship that rule at all, and ships the
  source-scoping rule only for delivery services. The partial-wildcard set drops upstream's data
  reads, the kill-chain check skips trust statements and judges one policy document at a time, and
  the S3 write check no longer flags a single bucket's objects. Each guard's own doc has the detail.

# Citations

[1] poojakira/aws-agent-identity-guard, https://github.com/poojakira/aws-agent-identity-guard,
    `src/aws_agent_identity_guard/scanner.py` at commit `8e6fa80e1bdea96072a7c2077feda3a3ec1dd423`
    (2026-10-07), MIT licence at that version, Copyright (c) 2026 Pooja Kiran.
[2] The same repository's licence change, commit `a7a9afdb` (2026-10-13), root `LICENSE` section 5
    ("Third-party material and prior rights") and `docs/license-history/LICENSE-BEFORE-2026-10-13.txt`.
[3] AWS IAM User Guide, "The confused deputy problem",
    https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html (fetched 2026-10-18).
