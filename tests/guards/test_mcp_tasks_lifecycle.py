"""Tests for McpTasksLifecycleGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

import pytest

from agentsec.guards.mcp_tasks_lifecycle import McpTasksLifecycleGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "python"}, python_dirs=["."])


# ── no-owner-check ────────────────────────────────────────────────────────

def test_no_owner_check_fires(tmp_path: Path) -> None:
    (tmp_path / "tasks_store.py").write_text(
        "# SEP-1686 Task primitive\n"
        "class TaskStore:\n"
        "    def get_task(self, task_id):\n"
        "        return self._tasks[task_id]\n",
        encoding="utf-8",
    )
    findings = McpTasksLifecycleGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "mcp-tasks-lifecycle/no-owner-check")
    assert hit.severity == "high"


def test_owner_check_present_is_safe(tmp_path: Path) -> None:
    (tmp_path / "tasks_store.py").write_text(
        "# SEP-1686 Task primitive\n"
        "class TaskStore:\n"
        "    def get_task(self, task_id, current_user):\n"
        "        task = self._tasks[task_id]\n"
        "        if task.owner != current_user:\n"
        "            raise PermissionError()\n"
        "        return task\n",
        encoding="utf-8",
    )
    findings = McpTasksLifecycleGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tasks-lifecycle/no-owner-check" for f in findings)


# ── credentials-not-zeroized ──────────────────────────────────────────────

def test_credentials_not_zeroized_fires(tmp_path: Path) -> None:
    (tmp_path / "task.py") .write_text(
        "class Task:\n"
        "    def __init__(self, token):\n"
        "        self.token = token\n"
        "        self.status = 'pending'\n\n"
        "    def complete(self):\n"
        "        self.status = 'completed'\n",
        encoding="utf-8",
    )
    findings = McpTasksLifecycleGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-tasks-lifecycle/credentials-not-zeroized" for f in findings)


def test_credentials_zeroized_on_completion_is_safe(tmp_path: Path) -> None:
    (tmp_path / "task.py").write_text(
        "class Task:\n"
        "    def __init__(self, token):\n"
        "        self.token = token\n"
        "        self.status = 'pending'\n\n"
        "    def complete(self):\n"
        "        self.status = 'completed'\n"
        "        self.token = None\n",
        encoding="utf-8",
    )
    findings = McpTasksLifecycleGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tasks-lifecycle/credentials-not-zeroized" for f in findings)


def test_no_credential_field_is_safe(tmp_path: Path) -> None:
    """FP-bait: a Task class with no credential field at all -- rule 2 doesn't apply."""
    (tmp_path / "task.py").write_text(
        "class Task:\n"
        "    def __init__(self, payload):\n"
        "        self.payload = payload\n"
        "        self.status = 'pending'\n\n"
        "    def complete(self):\n"
        "        self.status = 'completed'\n"
        "    def cancel(self):\n"
        "        self.status = 'cancelled'\n",
        encoding="utf-8",
    )
    findings = McpTasksLifecycleGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tasks-lifecycle/credentials-not-zeroized" for f in findings)


# ── no-ttl-or-cancellation ────────────────────────────────────────────────

def test_no_ttl_or_cancellation_fires(tmp_path: Path) -> None:
    (tmp_path / "task_manager.py").write_text(
        "class TaskManager:\n"
        "    def __init__(self):\n"
        "        self.tasks = {}\n",
        encoding="utf-8",
    )
    findings = McpTasksLifecycleGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-tasks-lifecycle/no-ttl-or-cancellation" for f in findings)


def test_ttl_present_is_safe(tmp_path: Path) -> None:
    (tmp_path / "task_manager.py").write_text(
        "class TaskManager:\n"
        "    def __init__(self):\n"
        "        self.tasks = {}\n"
        "        self.ttl = 3600\n",
        encoding="utf-8",
    )
    findings = McpTasksLifecycleGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tasks-lifecycle/no-ttl-or-cancellation" for f in findings)


def test_cancel_function_present_is_safe(tmp_path: Path) -> None:
    (tmp_path / "task_manager.py").write_text(
        "class TaskManager:\n"
        "    def __init__(self):\n"
        "        self.tasks = {}\n\n"
        "    def cancel_task(self, task_id):\n"
        "        del self.tasks[task_id]\n",
        encoding="utf-8",
    )
    findings = McpTasksLifecycleGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tasks-lifecycle/no-ttl-or-cancellation" for f in findings)


# ── unbounded-task-creation ───────────────────────────────────────────────

def test_unbounded_task_creation_fires(tmp_path: Path) -> None:
    (tmp_path / "task_manager.py").write_text(
        "class TaskManager:\n"
        "    def create_task(self, payload):\n"
        "        task = Task(payload)\n"
        "        self.tasks[task.id] = task\n"
        "        return task\n",
        encoding="utf-8",
    )
    findings = McpTasksLifecycleGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-tasks-lifecycle/unbounded-task-creation" for f in findings)


def test_quota_bound_present_is_safe(tmp_path: Path) -> None:
    (tmp_path / "task_manager.py").write_text(
        "class TaskManager:\n"
        "    MAX_TASKS = 100\n\n"
        "    def create_task(self, payload):\n"
        "        if len(self.tasks) >= self.MAX_TASKS:\n"
        "            raise QuotaExceeded()\n"
        "        task = Task(payload)\n"
        "        self.tasks[task.id] = task\n"
        "        return task\n",
        encoding="utf-8",
    )
    findings = McpTasksLifecycleGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tasks-lifecycle/unbounded-task-creation" for f in findings)


def test_no_task_creation_path_is_safe(tmp_path: Path) -> None:
    """FP-bait: a Tasks primitive with no creation function at all -- rule 4 doesn't apply."""
    (tmp_path / "task_manager.py").write_text(
        "class TaskManager:\n"
        "    def get_status(self, task_id):\n"
        "        return self.tasks[task_id].status\n"
        "    def cancel_task(self, task_id):\n"
        "        del self.tasks[task_id]\n",
        encoding="utf-8",
    )
    findings = McpTasksLifecycleGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-tasks-lifecycle/unbounded-task-creation" for f in findings)


# ── scope / suppression ───────────────────────────────────────────────────

def test_unrelated_celery_worker_is_not_flagged(tmp_path: Path) -> None:
    """FP-bait: a bare job-queue worker that merely uses the word 'task' (task_id as a
    plain variable) doesn't qualify as an MCP Tasks primitive for rules 2-4."""
    (tmp_path / "worker.py").write_text(
        "def process(task_id, payload):\n"
        "    result = do_work(payload)\n"
        "    return result\n",
        encoding="utf-8",
    )
    findings = McpTasksLifecycleGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_all_findings(tmp_path: Path) -> None:
    (tmp_path / "tasks_store.py").write_text(
        "# security: allow-mcp-tasks-lifecycle\n"
        "# SEP-1686 Task primitive\n"
        "class TaskStore:\n"
        "    def get_task(self, task_id):\n"
        "        return self._tasks[task_id]\n",
        encoding="utf-8",
    )
    findings = McpTasksLifecycleGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpTasksLifecycleGuard().applies(prof) is False


# ── review round: keyword-presence FPs ────────────────────────────────────

def _rules(root: Path) -> set[str]:
    return {f.rule.split("/")[-1] for f in McpTasksLifecycleGuard().run(root, _mcp_prof(root))}


def test_user_id_owner_check_is_recognised(tmp_path: Path) -> None:
    """A textbook `task.user_id != user_id` check used to be missing from the owner regex."""
    (tmp_path / "tasks.py").write_text(
        "def get_task(task_id, user_id):\n"
        "    task = STORE[task_id]\n"
        "    if task.user_id != user_id:\n"
        "        raise PermissionError()\n"
        "    return task\n",
        encoding="utf-8",
    )
    assert "no-owner-check" not in _rules(tmp_path)


def test_owner_check_absent_still_fires_with_user_id_regex(tmp_path: Path) -> None:
    (tmp_path / "tasks.py").write_text(
        "def get_task(task_id):\n    return STORE[task_id]\n", encoding="utf-8"
    )
    assert "no-owner-check" in _rules(tmp_path)


def test_bare_task_queue_is_not_a_tasks_primitive(tmp_path: Path) -> None:
    """The module docstring promises a bare job-queue class does not qualify for rules 2-4."""
    (tmp_path / "queue.py").write_text(
        "class TaskQueue:\n"
        "    def __init__(self):\n        self.items = []\n"
        "    def push(self, item):\n        self.items.append(item)\n",
        encoding="utf-8",
    )
    assert _rules(tmp_path) == set()


def test_task_manager_without_ttl_still_fires_after_queue_carveout(tmp_path: Path) -> None:
    (tmp_path / "mgr.py").write_text(
        "class TaskManager:\n    def __init__(self):\n        self.tasks = {}\n", encoding="utf-8"
    )
    assert "no-ttl-or-cancellation" in _rules(tmp_path)


def test_abandoned_in_a_comment_is_not_a_terminal_state(tmp_path: Path) -> None:
    (tmp_path / "task.py").write_text(
        "class Task:\n"
        "    def __init__(self, token):\n"
        "        self.token = token  # abandoned callers keep their handle\n"
        "        self.ttl = 60\n",
        encoding="utf-8",
    )
    assert "credentials-not-zeroized" not in _rules(tmp_path)


def test_ttl_ms_field_counts_as_a_ttl(tmp_path: Path) -> None:
    (tmp_path / "models.py").write_text(
        "class Task:\n    ttl_ms: int | None = None\n    status = 'working'\n",
        encoding="utf-8",
    )
    assert "no-ttl-or-cancellation" not in _rules(tmp_path)


def test_ttl_and_cancel_in_sibling_modules_count_for_the_package(tmp_path: Path) -> None:
    """fastmcp's Tasks implementation: the model has `ttl_ms`, the client has `cancel()`."""
    pkg = tmp_path / "tasks_pkg"
    pkg.mkdir()
    (pkg / "handlers.py").write_text(
        "class TaskHandlers:\n    def get_status(self, task_id):\n        return task_id\n",
        encoding="utf-8",
    )
    (pkg / "models.py").write_text("class Task:\n    ttl_ms: int | None = None\n", encoding="utf-8")
    (pkg / "client.py").write_text(
        "class TaskClient:\n    async def cancel(self):\n        return None\n", encoding="utf-8"
    )
    assert "no-ttl-or-cancellation" not in _rules(tmp_path)


def test_unrelated_test_helper_sibling_does_not_silence_the_real_implementation(tmp_path: Path) -> None:
    """The review's repro: an unrelated test-named sibling (its own, unconnected
    `cancel_subscription()`) sharing a directory with the real Task implementation must not
    silence a genuine missing-ttl/cancel finding just by matching the marker regex."""
    pkg = tmp_path / "tasks_pkg"
    pkg.mkdir()
    (pkg / "task_store.py").write_text(
        "class TaskStore:\n"
        "    def get_task(self, task_id, user_id): ...\n"
        "    def create_task(self, payload): ...\n",
        encoding="utf-8",
    )
    (pkg / "test_billing_helpers.py").write_text(
        'def cancel_subscription(user):\n'
        '    """totally unrelated billing test helper, nothing to do with MCP Tasks"""\n'
        '    return True\n',
        encoding="utf-8",
    )
    assert "no-ttl-or-cancellation" in _rules(tmp_path)


def test_ttl_in_a_different_package_does_not_count(tmp_path: Path) -> None:
    """Direction traded against: the resolution is per directory, not repo-wide."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "handlers.py").write_text(
        "class TaskHandlers:\n    def get_status(self, task_id):\n        return task_id\n",
        encoding="utf-8",
    )
    (tmp_path / "b" / "models.py").write_text(
        "class Task:\n    ttl_ms: int = 1\n    async def cancel(self):\n        return None\n",
        encoding="utf-8",
    )
    findings = McpTasksLifecycleGuard().run(tmp_path, _mcp_prof(tmp_path))
    hit = [f for f in findings if f.rule.endswith("no-ttl-or-cancellation")]
    assert len(hit) == 1
    assert hit[0].location.replace("\\", "/") == "a/handlers.py:1"


def test_quota_in_sibling_module_bounds_creation(tmp_path: Path) -> None:
    pkg = tmp_path / "tasks_pkg"
    pkg.mkdir()
    (pkg / "creation.py").write_text(
        "class TaskManager:\n    ttl = 1\n    def cancel(self):\n        pass\n"
        "    def create_task(self, p):\n        return p\n",
        encoding="utf-8",
    )
    assert "unbounded-task-creation" in _rules(tmp_path)
    (pkg / "settings.py").write_text("MAX_TASKS = 100\n", encoding="utf-8")
    assert "unbounded-task-creation" not in _rules(tmp_path)


# ── #424 E6 (#1000): the pragma counts only as a real comment, in the file's own grammar ──

_PY_FIRING = (
    "# SEP-1686 Task primitive\n"
    "class TaskStore:\n"
    "    def get_task(self, task_id):\n"
    "        return self._tasks[task_id]\n"
)
_TS_FIRING = (
    "export class TaskManager {\n"
    "  private tasks = new Map<string, unknown>();\n"
    "}\n"
)


def _rule_list(root: Path, name: str, text: str) -> list[str]:
    (root / name).write_text(text, encoding="utf-8")
    return sorted(f.rule for f in McpTasksLifecycleGuard().run(root, _mcp_prof(root)))


def test_mcp_tasks_lifecycle_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): the whole-file opt-out reads the comment-only view, so a Python string quoting
    # the pragma is content; only a real `#` comment (`test_pragma_suppresses_all_findings`) opts out.
    text = 'HELP = "opt out with # security: allow-mcp-tasks-lifecycle"\n' + _PY_FIRING
    assert _rule_list(tmp_path, "tasks_store.py", text) == [
        "mcp-tasks-lifecycle/no-owner-check",
        "mcp-tasks-lifecycle/no-ttl-or-cancellation",
    ]


@pytest.mark.parametrize("marker", ["//", "#"], ids=["slash-form", "hash-form"])
def test_mcp_tasks_lifecycle_pragma_quoted_in_a_string_does_not_suppress_ts(
    tmp_path: Path, marker: str
) -> None:
    # #424 E6 (#1000): D2 widened the pragma to `//`, so a TS string quoting either comment form must
    # stay content (the CLAUDE.md rule-1 test for that widening).
    text = f'const help = "opt out with {marker} security: allow-mcp-tasks-lifecycle";\n' + _TS_FIRING
    assert _rule_list(tmp_path, "task_manager.ts", text) == ["mcp-tasks-lifecycle/no-ttl-or-cancellation"]


def test_mcp_tasks_lifecycle_ts_slash_comment_pragma_suppresses(tmp_path: Path) -> None:
    # #424 E6 (#1000) D2: TS comments are `//`, and the old `#`-only regex never saw one, so the
    # documented opt-out could not be written in a .ts file at all.
    assert _rule_list(tmp_path, "task_manager.ts", _TS_FIRING) == ["mcp-tasks-lifecycle/no-ttl-or-cancellation"]
    text = "// security: allow-mcp-tasks-lifecycle\n" + _TS_FIRING
    assert _rule_list(tmp_path, "task_manager.ts", text) == []
