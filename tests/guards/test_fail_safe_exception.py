from __future__ import annotations

from agentsec.guards.fail_safe_exception import FailSafeExceptionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fail_safe_exception_flags_bare_except_pass(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "def check(user):\n"
        "    try:\n"
        "        check_permission(user)\n"
        "    except:\n"
        "        pass\n",
        encoding="utf-8",
    )
    profile = _fastapi_prof(tmp_path)
    findings = FailSafeExceptionGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "fail-safe-exception/bare-except-pass"
    assert findings[0].severity == "medium"

def test_fail_safe_exception_flags_except_exception_pass(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        "def verify(token):\n"
        "    try:\n"
        "        validate_token(token)\n"
        "    except Exception:\n"
        "        pass  # swallow all errors\n",
        encoding="utf-8",
    )
    profile = _fastapi_prof(tmp_path)
    findings = FailSafeExceptionGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "fail-safe-exception/bare-except-pass"

def test_fail_safe_exception_flags_security_named_exception(tmp_path: Path) -> None:
    (tmp_path / "access.py").write_text(
        "def gate(user):\n"
        "    try:\n"
        "        require_permission(user)\n"
        "    except PermissionDenied:\n"
        "        pass\n",
        encoding="utf-8",
    )
    profile = _fastapi_prof(tmp_path)
    findings = FailSafeExceptionGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "fail-safe-exception/bare-except-pass"

def test_fail_safe_exception_silent_logged_reraise(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text(
        "def check(user):\n"
        "    try:\n"
        "        verify(user)\n"
        "    except Exception:\n"
        "        logger.exception('Unexpected error')\n"
        "        raise\n",
        encoding="utf-8",
    )
    profile = _fastapi_prof(tmp_path)
    findings = FailSafeExceptionGuard().run(tmp_path, profile)
    assert findings == []

def test_fail_safe_exception_silent_specific_with_http_raise(tmp_path: Path) -> None:
    (tmp_path / "safe2.py").write_text(
        "def handler(val):\n"
        "    try:\n"
        "        parse(val)\n"
        "    except ValueError as e:\n"
        "        logger.warning(f'Invalid input: {e}')\n"
        "        raise HTTPException(status_code=400)\n",
        encoding="utf-8",
    )
    profile = _fastapi_prof(tmp_path)
    findings = FailSafeExceptionGuard().run(tmp_path, profile)
    assert findings == []

def test_fail_safe_exception_pragma_silences(tmp_path: Path) -> None:
    content = (
        "# security: allow-bare-except\n"
        "def cleanup(f):\n"
        "    try:\n"
        "        os.unlink(f)\n"
        "    except:\n"
        "        pass\n"
    )
    (tmp_path / "cleanup.py").write_text(content, encoding="utf-8")
    profile = _fastapi_prof(tmp_path)
    findings = FailSafeExceptionGuard().run(tmp_path, profile)
    assert findings == []

def test_fail_safe_exception_not_applicable_without_python(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"fastapi"}, python_dirs=["."])
    assert FailSafeExceptionGuard().applies(profile) is False

def test_fail_safe_exception_cleanup_code_silent(tmp_path: Path) -> None:
    # Precision fix: broad except:pass / except Exception:pass in cleanup/enrichment
    # code with no security operations in the try-block is NOT a fail-open defect.
    (tmp_path / "tasks.py").write_text(
        "def cleanup_session(db):\n"
        "    try:\n"
        "        db.rollback()\n"
        "        db.close()\n"
        "    except Exception:\n"
        "        pass  # best-effort cleanup\n",
        encoding="utf-8",
    )
    profile = _fastapi_prof(tmp_path)
    assert FailSafeExceptionGuard().run(tmp_path, profile) == []

def test_fail_safe_exception_security_named_exc_fires_unconditionally(tmp_path: Path) -> None:
    # Security-named exception types (_EXCEPT_SECURITY) fire regardless of context —
    # the exception name itself is evidence. Only the broad patterns require context.
    (tmp_path / "pipeline.py").write_text(
        "def enrich(data):\n"
        "    try:\n"
        "        data['label'] = fetch_label(data['id'])\n"
        "    except PermissionDenied:\n"
        "        pass  # ignore, proceed without label\n",
        encoding="utf-8",
    )
    profile = _fastapi_prof(tmp_path)
    findings = FailSafeExceptionGuard().run(tmp_path, profile)
    assert len(findings) >= 1 and findings[0].rule == "fail-safe-exception/bare-except-pass"

