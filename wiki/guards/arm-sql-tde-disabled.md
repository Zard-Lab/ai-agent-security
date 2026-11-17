---
type: Guard
title: "arm-sql-tde-disabled"
description: "ARM-templated Azure SQL Database transparent data encryption (TDE) not enabled."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "arm-sql-tde-disabled"
checklist_section: ["7"]
standards: ["OWASP:A02", "CWE-311"]
---

# ARM template Azure SQL Database transparent data encryption (TDE) not enabled

Flags `Microsoft.Sql/servers/databases/transparentDataEncryption` child resources whose
`properties.state` is not exactly `"Enabled"`, including when `state` is absent entirely. Closes
a new checklist item — no existing agentsec item covers Azure SQL TDE for any format. This is
agentsec's second Azure Resource Manager (ARM)-format guard (2/5), built on the
`agentsec.arm` resource parser and `arm-redis-ssl-disabled`'s reference shape.

## The threat

A SQL database without transparent data encryption stores its data and backup files
unencrypted at rest. Anyone who can access the underlying storage media directly — a stolen
disk, a misconfigured storage account, an improperly disposed backup, or a snapshot exported
outside the normal SQL access path — can read the data without ever authenticating to the
database engine. CWE-311 (Missing Encryption of Sensitive Data).

## Exploitability rationale

MEDIUM. Requires access to the storage layer or a backup artifact outside the normal database
connection path — not itself remotely exploitable through the SQL endpoint, the same severity
class as the encryption-at-rest guards this mirrors (`rds-storage-not-encrypted`,
`7-encryption-at-rest`).

## What counts as a hit (and what doesn't)

- `Microsoft.Sql/servers/databases/transparentDataEncryption` with `properties.state` set to
  anything other than the exact literal `"Enabled"` (e.g. `"Disabled"`) → fires.
- `Microsoft.Sql/servers/databases/transparentDataEncryption` with no `state` property at all →
  fires (TDE must be affirmatively turned on; an omitted attribute is not evidence it is on).
- `Microsoft.Sql/servers/databases/transparentDataEncryption` with `properties.state` set to
  exactly `"Enabled"` → silent (the fix). The comparison is case-sensitive, matching the
  documented Azure API literal.
- Any resource whose `name` contains the literal substring `master` (case-insensitive) → silent,
  regardless of `state` — see "When NOT to flag" below.
- Any other resource type, including the parent `Microsoft.Sql/servers/databases` resource
  itself → silent (the guard only ever looks inside a
  `Microsoft.Sql/servers/databases/transparentDataEncryption` resource's own `block`).
- **Both ARM authoring styles fire identically.** The TDE resource declared flat with a
  fully-qualified `type`, and the same resource declared as an inline child (`"type":
  "transparentDataEncryption"` nested under a `databases` nested under a `Microsoft.Sql/servers`),
  deploy to the same thing — `agentsec.arm` resolves an inline child's relative `type` and `name`
  against its parent, so the guard sees one canonical form. The `master` exemption reads that
  resolved name, which is what lets it recognize a nested `master` database whose TDE child is
  named only `current`.

## When NOT to flag (and the pragma)

- `state` is exactly `"Enabled"` → silent (the fix).
- The resource's `name` contains `master` (case-insensitive) → silent. Azure's `master` system
  database does not support TDE the same way user databases do, and would be a guaranteed false
  positive if flagged. A TDE child resource's `name` is typically an ARM expression like
  `"[concat(parameters('sqlServerName'), '/', parameters('databaseName'), '/current')]"` —
  parsing the literal database name out of that expression is fragile, so this guard takes the
  safer, narrower path: it looks for the literal substring `master` anywhere in the raw `name`
  string (covering the common hand-authored case, e.g.
  `"[concat(parameters('sqlServerName'), '/master/current')]"`) and stays silent on ambiguity
  rather than risk flagging Azure's own system database.
- **No suppression pragma exists for this guard.** ARM templates are pure JSON, which has no
  comment syntax — a known, documented limitation shared by every guard built on `agentsec.arm`
  (see that module's docstring). There is no equivalent to the CFN guards' YAML-only
  `# security: allow-...` pragma here.

## Tests

| Test | What it checks |
|---|---|
| `test_arm_sql_tde_flags_state_not_enabled` | `state: "Disabled"` fires `medium`. |
| `test_arm_sql_tde_flags_state_absent` | `state` entirely absent also fires. |
| `test_arm_sql_tde_silent_when_enabled` | `state: "Enabled"` stays silent. |
| `test_arm_sql_tde_flags_inline_nested_child_authoring_style` | The same violation authored as an inline child (relative `type`) fires identically to the flat fully-qualified form. |
| `test_arm_sql_tde_silent_on_nested_child_when_enabled` | FP bait: nested form, correctly encrypted, stays silent. |
| `test_arm_sql_tde_silent_on_nested_master_database` | FP bait: the `master` exemption survives the nested form, where `master` is the PARENT database's name. |
| `test_arm_sql_tde_silent_on_master_database_even_with_bad_state` | FP bait: the `master` system database is never flagged. |
| `test_arm_sql_tde_silent_on_unrelated_resource_type` | FP bait: the parent `databases` resource itself, not the TDE child. |
| `test_arm_sql_tde_not_applicable_without_arm` | `applies()` is `False` without the `arm` feature. |

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the property's value (or absence)
  directly; does not confirm the resource is actually deployed under a real, reachable SQL
  server.
- **File-level location, not line-level** — like every guard built on `agentsec.arm`, the finding
  reports the template file, not a specific line (a `block` is a `json.dumps` reconstruction with
  no original line mapping to report).
- **Template expressions are not evaluated.** If `state` were set via
  `"[parameters('tdeState')]"` rather than a literal string, this guard would not recognize it
  either way — see `agentsec.arm`'s module docstring for the same posture.
- **The `master`-name exclusion is a substring match on the raw `name` string, not a resolved
  database name.** A non-`master` database whose ARM expression happens to contain the substring
  `master` elsewhere (an unlikely but possible naming collision) would also be silently excluded.
  This errs toward NOT flagging, the correct direction for avoiding a guaranteed false positive
  on Azure's own system database.
- **Nested/linked templates** (`Microsoft.Resources/deployments` referencing a separate template
  file or URI) are not followed — each template file is scanned independently.

## What this guard does NOT prove

A clean scan means no `Microsoft.Sql/servers/databases/transparentDataEncryption` resource in the
scanned templates has `properties.state` set to anything other than `"Enabled"` — it says nothing
about a database created outside this template entirely (the Azure Portal, a different IaC tool,
a linked template this scan didn't independently discover), nor about the database's actual
runtime TDE configuration if it was changed out-of-band after deployment.

## Canary plant

`arm_sql_tde.json` — a `Microsoft.Sql/servers/databases/transparentDataEncryption` resource with
`properties.state: "Disabled"`. Expected rule: `arm-sql-tde-disabled/tde-not-enabled`.

# Citations

[1] OWASP:A02 (Cryptographic Failures)
[2] CWE-311 (Missing Encryption of Sensitive Data)
[3] Azure/template-analyzer — `SQL.EnableTDE` (`TA-000027`, provenance only; detection logic
    here is original)
