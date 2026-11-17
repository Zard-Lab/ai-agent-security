---
type: Guard
title: "mcp-tasks-lifecycle"
description: "An MCP Tasks primitive is missing an owner check, retains credentials, has no TTL/cancellation, or accepts unbounded creation."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "mcp-tasks-lifecycle"
checklist_section: ["4"]
standards: ["OWASP:A01", "CWE-863", "CWE-459", "CWE-400"]
---

# MCP Tasks primitive has an owner/credential/lifecycle/quota gap

_Author — 2026-09-26_

---

## The threat

SEP-1686 makes long-running operations ("Tasks") a first-class MCP primitive, and SEP-2663
(the 2026-07-28 spec-ahead extension) formalizes `tasks/create`. Four real, distinct
failure classes recur: a task-read endpoint with no owner check (CWE-863, cross-tenant
task-result leakage), a task object that stores a credential and never clears it on
completion (CWE-459, Incomplete Cleanup), a Tasks primitive with no lifetime bound
(unbounded resource accumulation), and an unbounded task-creation path (CWE-400,
Uncontrolled Resource Consumption — a task-flood DoS). Sourced from `agent-audit-kit`'s
`mcp_tasks.py` (AAK-TASKS-001..004), verified against the real repo source.

## Why it's often introduced

Tasks are a newer MCP primitive with no established, battle-tested implementation pattern
yet (unlike, say, REST resource ownership checks) — a first implementation commonly gets
the "does it work" path right (create, poll, read result) while the four hardening
properties above are easy to defer as "we'll add auth/cleanup/limits later."

## Detection design

1. `applies()` gates on `"mcp" in profile.features`.
2. Scans every `.py`/`.ts`/`.tsx`/`.js`/`.jsx`/`.mjs` file (`iter_files`), gated first by a
   Tasks-primitive HINT (a `Task`-named class, a Manager/Store/Queue/Runner suffix, the
   literal `SEP-1686`, a `/tasks/{id}`-shaped path, or `task_id`) — a bare job-queue mention
   alone does not qualify a file.
3. **no-owner-check** (HIGH): a task-read function (`get_task`/`read_task`/`task_read`/
   `get_by_id`/`findTask`) has no owner/tenant-check identifier
   (`owner`/`owner_id`/`user_id`/`requesting_user`/`current_user`/`authenticated_user`/
   `principal`/`tenant_id`/`caller_id`) within its first ~1200 characters.
4. **credentials-not-zeroized** (HIGH): the file matches the NARROWER `_TASK_PRIMITIVE`
   shape (a `Task`-named class other than a `TaskQueue`/`TaskRunner`/`TaskWorker`/
   `TaskScheduler`/`TaskExecutor`, a `TaskManager`/`TaskStore`/`TaskPrimitive`, `SEP-1686`,
   a `/tasks/{id}` path or a `tasks/*` method), stores a credential field
   (`self.credentials`/`self.api_key`/`self.token`/`self.secret`/`self.password`), AND
   references a terminal state as a whole word (completed/failed/cancelled/done/finished) —
   but never zeroizes the credential (`= None`, `del self.X`, `clear_secret(`, `zeroize(`).
5. **no-ttl-or-cancellation** (MEDIUM): the `_TASK_PRIMITIVE` shape with neither a
   TTL/expiry field (`ttl`, `ttl_ms`, `ttlMs`, `expires_at`, ...) nor a cancellation-shaped
   function (`def *cancel*`/`*abort*`/`*terminate*`, a `cancelTask(` call, or the
   `tasks/cancel` method) anywhere in the file's directory (the "package": sibling modules
   are read too, because the model, client and settings of one implementation routinely
   live in different files).
6. **unbounded-task-creation** (MEDIUM): the `_TASK_PRIMITIVE` shape with a task-creation
   path (`tasks/create`, or a `create_task`/`enqueue*`/`submit*`/`add_task`/`spawn_task`/
   `start_task` function/call) but no quota/concurrency-bound identifier anywhere in the
   file's directory (`max_tasks`/`quota`/`concurrency_limit`/`rate_limit`/`Semaphore`/...) — distinct from
   rule 5, since a server can have a TTL and a cancel endpoint yet still accept unlimited
   concurrent task creation.
7. Inline opt-out: a `# security: allow-mcp-tasks-lifecycle` comment (`// …` in JS/TS) anywhere in
   the file silences the file (a string literal quoting the phrase does not count, #424).
8. Standards vary per rule: `["OWASP:A01", "CWE-863"]` (owner), `["CWE-459", "OWASP:A02"]`
   (credentials), `["CWE-400", "OWASP-ASI:ASI04"]` (lifecycle/quota).

## When NOT to flag

- A task-read function with a real owner/tenant check present.
- A task object with no credential field at all — rule 2 doesn't apply.
- Credentials explicitly cleared on terminal-state transition.
- A TTL field or a cancellation function present anywhere in the same directory.
- A quota/concurrency-bound identifier present anywhere in the same directory as a file with
  a creation path.
- A bare `class TaskQueue:` (or Runner/Worker/Scheduler/Executor): a job queue, not an MCP
  Tasks primitive.
- `user_id` compared to the task's owner: recognised as an owner check.
- The word "abandoned" (or any word merely containing "done"/"failed") in a comment.
- A bare job-queue/Celery worker that merely uses the word "task" or a `task_id` variable —
  the narrower `_TASK_PRIMITIVE` gate (a real class/store/manager/SEP-1686 marker/`/tasks/`
  path) keeps rules 2-4 from firing on unrelated code.

## Tests

| Test | What it checks |
|---|---|
| `test_no_owner_check_fires` | `get_task()` with no owner check — fires |
| `test_owner_check_present_is_safe` | A real owner check — silent |
| `test_credentials_not_zeroized_fires` | Credential field, terminal state, no zeroize — fires |
| `test_credentials_zeroized_on_completion_is_safe` | Zeroized on completion — silent |
| `test_no_credential_field_is_safe` | No credential field at all — rule 2 doesn't apply |
| `test_no_ttl_or_cancellation_fires` | No TTL, no cancel — fires |
| `test_ttl_present_is_safe` | A TTL field — silent |
| `test_cancel_function_present_is_safe` | A cancel function — silent |
| `test_unbounded_task_creation_fires` | Creation path, no quota — fires |
| `test_quota_bound_present_is_safe` | A quota check — silent |
| `test_no_task_creation_path_is_safe` | No creation function — rule 4 doesn't apply |
| `test_unrelated_celery_worker_is_not_flagged` | Bare job-queue code — out of scope entirely |
| `test_user_id_owner_check_is_recognised` / `test_owner_check_absent_still_fires_with_user_id_regex` | `user_id` owner check, both directions |
| `test_bare_task_queue_is_not_a_tasks_primitive` / `test_task_manager_without_ttl_still_fires_after_queue_carveout` | `TaskQueue` carve-out, both directions |
| `test_abandoned_in_a_comment_is_not_a_terminal_state` | Word boundary on terminal states |
| `test_ttl_ms_field_counts_as_a_ttl` | `ttl\w*` |
| `test_ttl_and_cancel_in_sibling_modules_count_for_the_package` / `test_ttl_in_a_different_package_does_not_count` | Package-level resolution, per directory not repo-wide |
| `test_quota_in_sibling_module_bounds_creation` | Package-level quota |
| `test_pragma_suppresses_all_findings` | Inline pragma silences all 4 rules |
| `test_mcp_tasks_lifecycle_pragma_quoted_in_a_string_does_not_suppress`, `test_mcp_tasks_lifecycle_pragma_quoted_in_a_string_does_not_suppress_ts`, `test_mcp_tasks_lifecycle_ts_slash_comment_pragma_suppresses` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6); a `//` comment now opts a JS/TS file out too, and a TS string quoting either form does not |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` gates correctly |

## Known bypasses

- Rules 1 and 2 are single-file, text/regex-based — a check split across a base class in a
  different file, or an owner check performed by a decorator this guard's vocabulary
  doesn't recognize, is invisible. Rules 3 and 4 resolve TTL, cancellation and quota across
  the file's own directory only (not the wider package tree, not the repo): a mitigation
  that lives in a different directory is still reported as missing. A sibling only credits
  the directory when it is not itself test/fixture-named (`is_nonproduct_path`) — a real
  implementation split (the model carries `ttl_ms`, a settings module carries the quota cap)
  still counts, but an unrelated `test_*.py`/`conftest.py`/`*_test.py` sibling's own,
  unconnected `ttl`/`cancel` mention no longer silences the finding just by sharing a
  directory.
- The credential-field, owner-check, and quota-marker vocabularies are fixed lists.
- Rule 2's 1200-character window is a heuristic; an unusually long function signature or
  docstring before the real owner check could push it outside the window.

## What this guard does NOT prove

Silence does not prove the owner check is applied CORRECTLY (constant-time comparison,
scoped to the right tenant field) — only that a recognized identifier is present nearby.
Similarly, a recognized quota/TTL marker's presence is not verified to actually enforce a
bound at runtime.

# Citations

[1] agentsec checklist item `4-mcp-tasks-lifecycle` (§4)
[2] MCP spec SEP-1686 (Tasks primitive), SEP-2663 (2026-07-28 task-creation extension)
[3] CWE-863, CWE-459, CWE-400, OWASP:A01, OWASP-ASI:ASI04
[4] agent-audit-kit `mcp_tasks.py`, rules AAK-TASKS-001..004
