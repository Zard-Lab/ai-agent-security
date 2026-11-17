---
type: Guard
title: "cfn-s3-public-access-canned-acl"
description: "S3 bucket resource in a CloudFormation template sets a legacy public canned ACL (PublicRead/PublicReadWrite)."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-s3-public-access-canned-acl"
checklist_section: ["6a"]
standards: ["OWASP:A01", "CWE-284"]
---

# S3 bucket AccessControl set to a public canned ACL (CloudFormation)

Flags `AWS::S3::Bucket` resources whose `AccessControl` property is set to one of the two public
canned ACLs, `PublicRead` or `PublicReadWrite`. Closes checklist item
`6a-cfn-s3-public-access-canned-acl` (§6a). This is a **new** checklist item, not an extension of
the existing `6a-s3-bucket-policy-wildcard-principal` guard — see "A different mechanism" below.

## The threat

S3's legacy **canned ACL** mechanism predates bucket policies and IAM as the primary access-control
tool for buckets and objects. `AccessControl: PublicRead` grants read access (list + get) to
everyone on the internet, including fully anonymous, unauthenticated requests; `PublicReadWrite`
additionally grants write (put/delete), which lets any anonymous party overwrite or delete objects
and — depending on what the bucket serves — plant content, corrupt data, or stage further attacks.
Both are a well-known, high-impact data-exposure and integrity misconfiguration class (OWASP A01 —
Broken Access Control; CWE-284 — Improper Access Control).

## A different mechanism from `s3-bucket-policy-wildcard-principal`

agentsec already has `6a-s3-bucket-policy-wildcard-principal`, which looks for an explicit bucket
**policy statement** granting an action to `Principal: "*"` without a narrowing `Condition` — a
JSON policy document attached to the bucket. This guard looks at a completely different property:
the bucket resource's own `AccessControl` attribute, S3's older **canned ACL** system. A template
can set neither, either, or both — an `AccessControl: Private` bucket can still be made public
through its `BucketPolicy`, and vice versa. Each mechanism gets its own checklist item and its own
guard because each is independently sufficient to make a bucket public, and a template author who
fixes one without knowing about the other is still exposed.

## Exploitability rationale

HIGH. Unlike a rotation-hygiene gap, a public canned ACL is directly exploitable the moment the
stack deploys — no additional compromise is required. Any internet client can enumerate and read
(or, for `PublicReadWrite`, write) the bucket's contents immediately.

## What counts as a hit (and what doesn't)

- `AWS::S3::Bucket` with `AccessControl: PublicRead` (YAML) or `"AccessControl": "PublicRead"`
  (JSON) → fires `cfn-s3-public-access-canned-acl/public-read`.
- `AWS::S3::Bucket` with `AccessControl: PublicReadWrite` / `"AccessControl": "PublicReadWrite"` →
  fires `cfn-s3-public-access-canned-acl/public-read-write`.
- `AccessControl: Private`, `AccessControl: AuthenticatedRead`, `AccessControl:
  BucketOwnerFullControl`, or any other named (non-public) canned ACL → silent.
- No `AccessControl` property at all → silent (CFN's implicit default for `AWS::S3::Bucket` is
  private; this guard does not flag absence, only an explicit dangerous value).
- A non-`AWS::S3::Bucket` resource, even one that happens to contain the literal text
  `AccessControl: PublicReadWrite` somewhere unrelated → silent (the guard filters by
  `resource.resource_type` first).
- `PublicRead` is a strict string prefix of `PublicReadWrite`. The guard checks for
  `PublicReadWrite` first and only falls through to the `PublicRead` pattern when that first check
  fails, and both patterns require a trailing word boundary — so `PublicReadWrite` never also
  satisfies the `PublicRead` rule, and a hypothetical unrelated value that merely starts with the
  substring "Public" cannot be mistaken for either of these two specific enum values.
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).

## When NOT to flag (and the pragma)

A deliberately public bucket (e.g. a static website's content bucket) is a real, audited exception,
not a bug. Suppress it with a comment anywhere in the resource's block (YAML templates only — JSON
has no comment syntax, so a JSON-authored template cannot carry this pragma at all, a known
limitation shared by every CFN guard in this batch):

```yaml
Resources:
  WebsiteBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead  # security: allow-s3-public-access-canned-acl
```

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the property's literal value directly;
  does not resolve a `!Ref`/`!Sub`/CFN Parameter/Condition that might compute the ACL value
  dynamically.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding reports
  the template file, not a specific line (see `agentsec/cfn.py`'s module docstring for why: a JSON
  block is a `json.dumps` reconstruction with no original line mapping to report).
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **Textual/regex-only.** A bucket made public through a mechanism this guard doesn't scan for (a
  bucket policy statement, an ACL grant set outside the template entirely, e.g. via the AWS
  Console or CLI after deploy, or S3 Access Points) is invisible to this specific guard — see
  `s3-bucket-policy-wildcard-principal` for the policy-statement case.
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.

## What this guard does NOT prove

A clean scan means no `AWS::S3::Bucket` resource in the scanned templates sets a public canned ACL
directly — it says nothing about a bucket made public via its `BucketPolicy` (a separate guard's
job), a bucket created outside CloudFormation entirely, S3 Block Public Access settings at the
account/bucket level, or an ACL applied out-of-band after the stack deploys.

## Canary plant

`cfn_s3_public_acl.yaml` — `AWS::S3::Bucket` with `AccessControl: PublicReadWrite` and no other
properties. Expected rule: `cfn-s3-public-access-canned-acl/public-read-write`.

# Examples

Fires:

```yaml
Resources:
  LeakyBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicReadWrite
```

Silent (private, the fix):

```yaml
Resources:
  SafeBucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: Private
```

# Citations

[1] agentsec checklist item `6a-cfn-s3-public-access-canned-acl` (§6a)
[2] OWASP:A01 (Broken Access Control)
[3] CWE-284 (Improper Access Control)
[4] cfripper (`Skyscanner/cfripper`) — `s3_public_access.py` (provenance only; detection logic
    here is original)
