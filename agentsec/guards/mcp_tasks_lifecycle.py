"""Guard: an MCP Tasks primitive (SEP-1686 long-running tasks, SEP-2663's 2026-07-28
extension) is missing an owner check, retains credentials past completion, has no
TTL/cancellation, or accepts unbounded task creation (checklist §4, new item;
agent-audit-kit's `mcp_tasks.py` AAK-TASKS-001..004).

SEP-1686 makes long-running operations ("Tasks") a first-class MCP primitive: a client
creates a task, polls or is notified of its status, and reads its result once complete.
Four failure classes recur in real implementations:

  1. **`no-owner-check`** (HIGH, SEP-1686 leakage): a task-read function
     (`get_task`/`read_task`/`task_read`/`get_by_id`/`findTask`) has no owner/tenant check
     (`owner`/`requesting_user`/`current_user`/`authenticated_user`/`principal`/
     `tenant_id`/`caller_id`/`user_id`/`owner_id`) in its first ~1200 characters — any caller who knows or
     guesses a task ID can read another user's task result.
  2. **`credentials-not-zeroized`** (HIGH, SEP-1686 leakage): a task object stores a
     credential field (`self.credentials`/`self.api_key`/`self.token`/`self.secret`/
     `self.password`) and the same file references a terminal state
     (completed/failed/cancelled/done/finished), but never zeroizes the credential
     (`= None`, `del self.X`, `clear_secret(`, `zeroize(`) on transition.
  3. **`no-ttl-or-cancellation`** (MEDIUM, SEP-1686 lifecycle): a Tasks primitive (a `Task`
     class, a Manager/Store/Queue/Runner, or the SEP-1686 marker) defines neither a
     TTL/expiry field (`ttl`/`expires_at`/`expiry`/`deadline`) nor a cancellation-shaped
     function (`cancel*`/`abort*`/`terminate*`) — a task with no lifetime bound accumulates
     forever.
  4. **`unbounded-task-creation`** (MEDIUM, SEP-2663 task-flood DoS): a task-creation path
     (`tasks/create`, or a `create_task`/`enqueue*`/`submit*`/`add_task`/`spawn_task`/
     `start_task` function/call) exists with no per-caller quota/concurrency bound anywhere
     in the file (`max_tasks`/`quota`/`concurrency_limit`/`rate_limit`/`Semaphore`/...) —
     distinct from rule 3 (a server can have a TTL and a cancel endpoint yet still accept
     unlimited concurrent task creation).

All four are gated on the file first matching a Tasks-primitive hint (a `Task`-named
class, a Manager/Store/Queue/Runner suffix, the literal `SEP-1686`, a `/tasks/{id}`-shaped
path, or `task_id`) — a bare job-queue/Celery-worker mention that merely uses the word
"task" does not, by itself, qualify a file as an MCP Tasks primitive for rules 2-4 (which
require the narrower `_TASK_PRIMITIVE` shape, and which exclude a bare
`TaskQueue`/`TaskRunner`/`TaskWorker`/`TaskScheduler`/`TaskExecutor` class).

Rules 3 and 4 resolve their mitigation (TTL `ttl*`/`expires_at`/..., a cancel function or
the `tasks/cancel` method, a quota/concurrency bound) across the file's own DIRECTORY, since
the model, client and settings of one implementation are routinely separate modules. The
resolution is per directory, not per repo. Rules 1-2 stay single-file; the terminal-state
words are word-bounded (so "abandoned" is not "done").

Suppress an audited case with a comment anywhere in the file (a string quoting it does not count):

    # security: allow-mcp-tasks-lifecycle
    // security: allow-mcp-tasks-lifecycle   (JS/TS)
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
)

_PRAGMA = re.compile(r"(?:#|//)\s*security:\s*allow-mcp-tasks-lifecycle")

_TASK_HINT = re.compile(
    r"\b(?:Task|task)\s*(?:Manager|Store|Queue|Runner|Primitive|SEP[_-]?1686)\b|"
    r"class\s+\w*Task\w*\b|"
    r"/tasks/[{:<]|task_id",
)
# A bare job-queue / worker class (`TaskQueue`, `TaskRunner`, `TaskWorker`) is NOT an MCP Tasks
# primitive by itself, so those suffixes are excluded from the narrow shape used by rules 2-4
# (they still satisfy the broader `_TASK_HINT`, which only gates the owner-check rule).
_TASK_PRIMITIVE = re.compile(
    r"class\s+\w*Task(?!Queue|Runner|Worker|Scheduler|Executor)\w*\b|"
    r"\b(?:Task|task)\s*(?:Manager|Store|Primitive)\b|"
    r"\bSEP[_-]?1686\b|"
    r"/tasks/[{:<]|"
    r"\btasks/(?:create|get|list|cancel|result)\b",
)
_TASK_GET_RE = re.compile(
    r"""(?:def|async\s+def)\s+(?:get_task|read_task|task_read|get_by_id|findTask)\s*\([^)]*\)[^:]*:""",
    re.DOTALL,
)
_OWNER_CHECK_RE = re.compile(
    r"\b(?:owner|owner_id|user_id|requesting_user|current_user|authenticated_user|principal|"
    r"tenant_id|caller_id)\b",
    re.IGNORECASE,
)
_CREDENTIAL_FIELD_RE = re.compile(
    r"""\bself\.(?:credentials?|api_key|token|secret|password)\s*=""",
    re.IGNORECASE,
)
# Word-bounded: without `\b` "done" matched inside "abandoned" and "failed" inside "unfailedly".
_TERMINAL_STATE_RE = re.compile(r"\b(?:completed|failed|cancelled|done|finished|terminal)\b", re.IGNORECASE)
_ZEROIZE_RE = re.compile(
    r"""(?:\bself\.(?:credentials?|api_key|token|secret|password)\s*=\s*None\b|"""
    r"""\bdel\s+self\.(?:credentials?|api_key|token|secret|password)\b|"""
    r"""\bclear_secret\s*\(|"""
    r"""\bzero_?ize\s*\()""",
)
# `ttl\w*` covers `ttl_ms` / `ttlMs` / `ttl_seconds` (a real Tasks model spells it that way).
_TTL_RE = re.compile(r"""\b(?:ttl\w*|expires_at|expiry|deadline)\s*[:=]""", re.IGNORECASE)
_CANCEL_RE = re.compile(
    r"""\b(?:async\s+)?def\s+\w*(?:cancel|abort|terminate)\w*\s*\("""
    r"""|\b(?:cancel|abort|terminate)\w*Task\s*\(|\btasks/cancel\b"""
)
_TASK_CREATE_RE = re.compile(
    r"""(?ix)
    \btasks/create\b
  | (?:def|async\s+def)\s+(?:create_task|enqueue_?\w*|submit_?\w*|add_task|spawn_task|start_task)\s*\(
  | \b(?:create_task|enqueueTask|submitTask|addTask)\s*\(
    """,
)
_QUOTA_RE = re.compile(
    r"""(?ix)
    \bmax[_-]?tasks\b | \bmaxTasks\b | \btask[_-]?limit\b
  | \bquota\b | \bmax[_-]?concurren\w* | \bconcurrency[_-]?limit\b
  | \bmax[_-]?in[_-]?flight\b | \bmax[_-]?pending\b
  | \brate[_-]?limit\w* | \bratelimit\b | \bbackpressure\b
  | \bSemaphore\b | \basyncio\.Semaphore\b | \bBoundedSemaphore\b
    """,
)

_STANDARDS_OWNER = ["OWASP:A01", "CWE-863"]
_STANDARDS_CRED = ["CWE-459", "OWASP:A02"]
_STANDARDS_LIFECYCLE = ["CWE-400", "OWASP-ASI:ASI04"]


class McpTasksLifecycleGuard(Guard):
    id = "mcp-tasks-lifecycle"
    title = "MCP Tasks primitive has an owner/credential/lifecycle/quota gap"
    area = "AI agent"

    # tasks_store.py: get_task() has no owner check -> fires
    # mcp-tasks-lifecycle/no-owner-check.
    canary_plant = CanaryPlant(
        files={
            "tasks_store.py": (
                "# SEP-1686 Task primitive\n"
                "class TaskStore:\n"
                "    def get_task(self, task_id):\n"
                "        return self._tasks[task_id]\n"
            ),
        },
        expects=frozenset({
            "mcp-tasks-lifecycle/no-owner-check",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        # Pass 1: read everything and record, per directory ("package"), which lifecycle
        # mitigations exist anywhere in it. A Tasks implementation is routinely split across
        # sibling modules (the model carries `ttl_ms`, the client carries `cancel()`, the
        # settings module carries the concurrency cap), so a per-file absence check flags
        # implementations that have all three. Files skipped as ANCHORS (pragma only, checked in
        # pass 2) are still read for the mitigation markers here; a test/fixture-NAMED file
        # (`is_nonproduct_path`) is excluded from crediting a directory at all, so an unrelated
        # test helper cannot silence a real implementation's finding just by sharing a directory.
        files: list[tuple[Path, str, str]] = []
        pkg_marks: dict[Path, set[str]] = {}
        for f in iter_files(root, (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs")):
            text = read(f)
            if not text:
                continue
            r = rel(root, f)
            files.append((f, r, text))
            # A test/fixture-named sibling never CREDITS the directory (`is_nonproduct_path`,
            # filename-anchored: `test_*.py`/`conftest.py`/`*_test.py`/`*.spec.*`) -- an unrelated
            # file (a billing test helper with its own unrelated `cancel_subscription()`) sitting
            # next to the real implementation used to silence a genuine missing-ttl/cancel finding
            # just by sharing a directory. A settings/config module (`MAX_TASKS = 100`) is a real,
            # deliberate cross-file split and is NOT excluded by this -- only a test-shaped name is.
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            marks = pkg_marks.setdefault(f.parent, set())
            if _TTL_RE.search(text):
                marks.add("ttl")
            if _CANCEL_RE.search(text):
                marks.add("cancel")
            if _QUOTA_RE.search(text):
                marks.add("quota")

        out: list[Finding] = []
        for f, r, text in files:
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            if not _TASK_HINT.search(text) or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            out.extend(self._check_file(r, text, pkg_marks.get(f.parent, set())))
        return out

    def _check_file(self, r: str, text: str, pkg: set[str] | None = None) -> list[Finding]:
        if pkg is None:  # standalone call: this file is the whole "package"
            pkg = {
                name for name, rx in (("ttl", _TTL_RE), ("cancel", _CANCEL_RE), ("quota", _QUOTA_RE))
                if rx.search(text)
            }
        out: list[Finding] = []

        m_get = _TASK_GET_RE.search(text)
        if m_get:
            window = text[m_get.start(): m_get.start() + 1200]
            if not _OWNER_CHECK_RE.search(window):
                out.append(self._finding(
                    f"{r}:{text.count(chr(10), 0, m_get.start()) + 1}",
                    "high", "no-owner-check", _STANDARDS_OWNER,
                    f"Task read function {m_get.group(0)!r} has no owner/tenant check in "
                    "the first ~1200 characters — any caller who knows or guesses a task "
                    "ID can read another user's task result.",
                ))

        if (
            _TASK_PRIMITIVE.search(text)
            and _CREDENTIAL_FIELD_RE.search(text)
            and _TERMINAL_STATE_RE.search(text)
            and not _ZEROIZE_RE.search(text)
        ):
            m_cred = _CREDENTIAL_FIELD_RE.search(text)
            line = text.count("\n", 0, m_cred.start()) + 1 if m_cred else 1
            out.append(self._finding(
                f"{r}:{line}", "high", "credentials-not-zeroized", _STANDARDS_CRED,
                "Task object stores a credential field but never zeroizes it on "
                "terminal state — a completed task row keeps a live credential in "
                "memory/storage indefinitely.",
            ))

        m_prim = _TASK_PRIMITIVE.search(text)
        if m_prim and not ({"ttl", "cancel"} & pkg):
            out.append(self._finding(
                f"{r}:{text.count(chr(10), 0, m_prim.start()) + 1}", "medium", "no-ttl-or-cancellation", _STANDARDS_LIFECYCLE,
                "MCP Tasks primitive defines no TTL/expiry field and no cancellation "
                "function — a task with no lifetime bound accumulates forever.",
            ))

        m_create = _TASK_CREATE_RE.search(text)
        if m_prim and m_create and "quota" not in pkg:
            line = text.count("\n", 0, m_create.start()) + 1
            out.append(self._finding(
                f"{r}:{line}", "medium", "unbounded-task-creation", _STANDARDS_LIFECYCLE,
                "MCP Tasks creation path has no per-caller quota, max-in-flight, or "
                "concurrency bound — unbounded task creation is a task-flood DoS "
                "(SEP-2663).",
            ))

        return out

    def _finding(
        self,
        location: str,
        severity: Literal["high", "medium"],
        rule_suffix: str,
        standards: list[str],
        message: str,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=location,
            message=message,
            remediation=(
                "Add the missing control: an owner/tenant check on task reads, credential "
                "zeroization on terminal state, a TTL + cancellation endpoint, or a "
                "per-caller quota/concurrency bound on task creation, as applicable."
            ),
            rule=f"mcp-tasks-lifecycle/{rule_suffix}",
            standards=list(standards),
        )
