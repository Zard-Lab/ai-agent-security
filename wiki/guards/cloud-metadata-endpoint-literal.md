---
type: Guard
title: "cloud-metadata-endpoint-literal"
description: "Literal reference to a cloud instance-metadata endpoint."
timestamp: "2026-07-12T19:12:34+08:00"
guard_id: "cloud-metadata-endpoint-literal"
checklist_section: ["3a"]
standards: ["CWE-918", "OWASP:A10"]
---

# Literal reference to a cloud instance-metadata endpoint

## Threat

**CWE-918 (Server-Side Request Forgery), OWASP:A10.** Cloud instance metadata services
(`169.254.169.254` on AWS/GCP/Azure/OpenStack, `100.100.100.200` on Alibaba Cloud,
`metadata.google.internal`, AWS's IPv6 IMDS at `fd00:ec2::254`) hand out short-lived cloud
credentials to anything running on the instance, with no authentication beyond network
reachability. A literal reference to one of these addresses is a strong, direct signal of an
attempt to steal the instance's cloud credentials — real cloud SDKs (boto3, google-cloud,
azure-sdk) resolve this address internally, so application code has essentially no legitimate
reason to hardcode it.

```python
os.system("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")
```

Sourced from SkillSpector's `SSRF1` category, built for scanning AI agent skill files — a
malicious or prompt-injected skill instructing an agent to "read the instance metadata
service" is exactly this pattern applied to natural-language instructions instead of code.

## Detection design

1. **`applies()` gate:** universal (`return True`). The Python/JS/shell source this scans (and
   its metadata-endpoint signal) can appear in any project regardless of the detected stack; a
   language-feature gate silently dropped the JS/shell literals on a Node-only or shell-only repo
   (PR #393 review #1). `run()` skips test/fixture/vendor files via `is_nonproduct_path`.
2. **Files scanned:** `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.sh`, `.bash` via `iter_files()`.
3. **Pattern:** a single regex alternation matching any of the four literal endpoint strings,
   anywhere on a non-comment line.
4. **Skips:** lines starting with `#` or `//`.
5. **Pragma:** `# security: allow-metadata-endpoint` anywhere in the file skips it entirely.
6. **Severity / rule:** `cloud-metadata-endpoint-literal/hardcoded-reference`, **HIGH**.

## Relationship to `ssrf-general`

`ssrf-general` fires when a server-side fetch URL is built from **dynamic/user-controlled**
input (an f-string, concatenation, or a `request.`-derived value) feeding a
`requests`/`httpx`/`urlopen` call — by design it does not fire on a bare literal URL, since a
hardcoded fetch target isn't attacker-controlled in the traditional SSRF sense that guard
targets. This guard closes the metadata-endpoint-specific gap that leaves open: a **hardcoded**
reference to one of these four addresses is inherently suspicious regardless of how it's
fetched (or even if it's never actually fetched — a literal mention in a skill file's
instructions is just as much a signal). The two guards are complementary, not overlapping:
`ssrf-general` catches "this code fetches an attacker-influenced URL that MIGHT be the
metadata endpoint"; this guard catches "this code (or instruction) explicitly names the
metadata endpoint."

## When NOT to flag

A genuine cloud-init/bootstrap script legitimately querying the metadata service for instance
role assumption during VM startup is the real exception — the pragma exists for this case,
scoped to the specific bootstrap file rather than a blanket exclusion.

## Tests

| Test | What it checks |
|---|---|
| `test_cloud_metadata_endpoint_flags_aws_imds` | `169.254.169.254` in a `curl` command fires HIGH |
| `test_cloud_metadata_endpoint_flags_gcp_alias` | `metadata.google.internal` fires |
| `test_cloud_metadata_endpoint_flags_alibaba` | `100.100.100.200` fires |
| `test_cloud_metadata_endpoint_silent_unrelated_ip` | An unrelated private IP stays silent |
| `test_cloud_metadata_endpoint_silent_comment` | A `#`-prefixed comment line stays silent |
| `test_cloud_metadata_endpoint_pragma_silences` | File-level pragma suppresses all findings |
| `test_cloud_metadata_endpoint_covers_shell_only_repo` | Regression (#393 #1): shell literal fires on a repo with no `python` feature |
| `test_cloud_metadata_endpoint_skips_nonproduct_path` | Regression (#393 #2): a metadata literal in a `tests/` file is skipped |
| `test_cloud_metadata_endpoint_applies_universally` | Guard applies on any stack (universal) |

## Known bypasses

- A URL built by string concatenation across variables so the literal `169.254.169.254`
  substring never appears whole on one line (`"169.254." + "169.254"`) is not matched.
- Alternate historical/vendor-specific metadata endpoints not in this curated list (e.g. a
  less-common cloud provider's own IMDS address) are not covered.
- A base64-encoded or otherwise obfuscated reference (common in genuinely malicious payloads
  trying to evade exactly this kind of static scan) is not decoded or matched.

## What this guard does NOT prove

A file with no finding may still perform SSRF against the metadata endpoint via a dynamically
constructed URL — that class is `ssrf-general`'s responsibility, not this guard's; the two are
meant to be read together, not as substitutes for each other.

# Citations

[1] agentsec checklist item `3a-cloud-metadata-endpoint-literal` (§3a)
[2] CWE-918
[3] OWASP:A10
