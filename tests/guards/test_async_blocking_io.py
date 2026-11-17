from __future__ import annotations

from agentsec.guards.async_blocking_io import AsyncBlockingIoGuard
from tests.guards._common import *  # noqa: F401,F403


def test_async_blocking_io_flags_requests_get(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        'async def get_data():\n    resp = requests.get("https://api.example.com")\n    return resp\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = AsyncBlockingIoGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "async-blocking-io/sync-call-in-async-def"
    assert findings[0].severity == "medium"
    assert "routes.py:2" in findings[0].location

def test_async_blocking_io_flags_time_sleep(tmp_path: Path) -> None:
    (tmp_path / "tasks.py").write_text(
        "async def wait_a_bit():\n    time.sleep(5)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = AsyncBlockingIoGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "async-blocking-io/sync-call-in-async-def"

def test_async_blocking_io_flags_urllib_urlopen(tmp_path: Path) -> None:
    (tmp_path / "fetch.py").write_text(
        "async def fetch(url: str):\n    resp = urllib.request.urlopen(url)\n    return resp.read()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"fastapi"}, python_dirs=["."])
    findings = AsyncBlockingIoGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "async-blocking-io/sync-call-in-async-def"

def test_async_blocking_io_silent_httpx_async(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "async def get_data(url: str):\n    async with httpx.AsyncClient() as client:\n        resp = await client.get(url)\n    return resp\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = AsyncBlockingIoGuard().run(tmp_path, profile)
    assert findings == []

def test_async_blocking_io_silent_sync_func(tmp_path: Path) -> None:
    (tmp_path / "utils.py").write_text(
        "def sync_func(url: str):\n    resp = requests.get(url)  # not async, ok\n    return resp\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = AsyncBlockingIoGuard().run(tmp_path, profile)
    assert findings == []

def test_async_blocking_io_pragma_silences(tmp_path: Path) -> None:
    content = (
        "# security: allow-blocking-io\n"
        "async def get_data():\n"
        '    resp = requests.get("https://api.example.com")\n'
        "    return resp\n"
    )
    (tmp_path / "routes.py").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = AsyncBlockingIoGuard().run(tmp_path, profile)
    assert findings == []

def test_async_blocking_io_applies_gate(tmp_path: Path) -> None:
    profile_no_python = mkprofile(tmp_path, features={"llm", "supabase"}, python_dirs=["."])
    assert not AsyncBlockingIoGuard().applies(profile_no_python)

    profile_fastapi = mkprofile(tmp_path, features={"fastapi"}, python_dirs=["."])
    assert AsyncBlockingIoGuard().applies(profile_fastapi)

    profile_python = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert AsyncBlockingIoGuard().applies(profile_python)

def test_async_blocking_io_scripts_dir_silent(tmp_path: Path) -> None:
    # FP fix: blocking calls inside scripts/ are intentional (no shared event loop).
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "seed.py").write_text(
        "import requests\n\nasync def fetch_data():\n"
        '    resp = requests.get("https://example.com/data")\n'
        "    return resp.json()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["scripts"])
    assert AsyncBlockingIoGuard().run(tmp_path, profile) == []

def test_async_blocking_io_tools_dir_silent(tmp_path: Path) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "migrate.py").write_text(
        "import time\n\nasync def wait_for_db():\n    time.sleep(2)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["tools"])
    assert AsyncBlockingIoGuard().run(tmp_path, profile) == []

def test_async_blocking_io_app_dir_still_fires(tmp_path: Path) -> None:
    # Regression: app/ directory must still fire (not a scripts dir).
    app = tmp_path / "app"
    app.mkdir()
    (app / "routes.py").write_text(
        "import requests\n\nasync def get_user():\n"
        '    resp = requests.get("https://api.example.com/user")\n'
        "    return resp.json()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["app"])
    findings = AsyncBlockingIoGuard().run(tmp_path, profile)
    assert any(f.rule == "async-blocking-io/sync-call-in-async-def" for f in findings)

def test_async_blocking_io_silent_on_docstring_inside_async(tmp_path: Path) -> None:
    # FP-bait (#424): a `requests.get(` example inside an async function's OWN docstring
    # (which sits inside the tracked async region) must not fire.
    app = tmp_path / "app"
    app.mkdir()
    (app / "routes.py").write_text(
        "async def get_user():\n"
        '    """Do not call requests.get("https://x") here — it blocks the loop."""\n'
        "    return None\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["app"])
    assert AsyncBlockingIoGuard().run(tmp_path, profile) == []

def test_async_blocking_io_silent_on_lookalike_module(tmp_path: Path) -> None:
    # #424: a module whose name merely ends in "requests" (`myrequests.get`) is not the blocking
    # `requests` library and must not fire (the `\brequests\.` anchor).
    app = tmp_path / "app"
    app.mkdir()
    (app / "routes.py").write_text(
        "import myrequests\n\nasync def get_user():\n"
        '    resp = myrequests.get("https://api.example.com/user")\n'
        "    return resp\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["app"])
    assert AsyncBlockingIoGuard().run(tmp_path, profile) == []

