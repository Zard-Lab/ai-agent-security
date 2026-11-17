from __future__ import annotations

from agentsec.guards.api_docs_exposed import ApiDocsExposedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_api_docs_flags_bare_fastapi(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    findings = ApiDocsExposedGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].rule == "api-docs-exposed/unconditional-docs-route"

def test_api_docs_passes_docs_url_none(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI(docs_url=None, redoc_url=None)\n", encoding="utf-8"
    )
    assert ApiDocsExposedGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_api_docs_passes_inside_env_guard(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "import os\n"
        "if not os.getenv('DEBUG'):\n"
        "    app = FastAPI()\n", encoding="utf-8"
    )
    assert ApiDocsExposedGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_api_docs_passes_with_pragma(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()  # security: allow-api-docs\n", encoding="utf-8"
    )
    assert ApiDocsExposedGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_api_docs_passes_is_production_idiom(tmp_path: Path) -> None:
    # T2e precision: the `is_production` / `is_prod` predicate idiom guards the constructor —
    # `\bproduction\b` alone missed it (the `_` before `p` blocks the word boundary).
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from settings import settings\n"
        "if not settings.is_production:\n"
        "    app = FastAPI()\n", encoding="utf-8"
    )
    assert ApiDocsExposedGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_api_docs_skips_test_app(tmp_path: Path) -> None:
    # T2e precision: a FastAPI() built in a test file is not a production docs exposure.
    sub = tmp_path / "tests"
    sub.mkdir()
    (sub / "test_app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    assert ApiDocsExposedGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_api_docs_silent_on_commented_and_docstring_constructor(tmp_path: Path) -> None:
    # FP-bait (#424): a `# app = FastAPI()` comment or a docstring FastAPI() example must not fire.
    (tmp_path / "main.py").write_text(
        '"""Example: app = FastAPI() with no docs_url."""\n'
        "# app = FastAPI()\n"
        "x = 1\n",
        encoding="utf-8",
    )
    assert ApiDocsExposedGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_api_docs_na_without_fastapi_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert ApiDocsExposedGuard().applies(prof) is False

def test_api_docs_exposed_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the FastAPI( line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-api-docs"):
        (tmp_path / "main.py").write_text(
            f'from fastapi import FastAPI\napp = FastAPI(); _note = "{note}"\n', encoding="utf-8"
        )
        assert len(ApiDocsExposedGuard().run(tmp_path, _fastapi_prof(tmp_path))) == 1, note

