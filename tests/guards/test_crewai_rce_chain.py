"""Tests for CrewaiRceChainGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

from agentsec.guards.crewai_rce_chain import CrewaiRceChainGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python", "llm"}, python_dirs=["."])


# ── unsafe-code-interpreter ───────────────────────────────────────────────────

def test_unsafe_mode_true_fires_critical(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "from crewai_tools import CodeInterpreterTool\n\n"
        "interpreter = CodeInterpreterTool(unsafe_mode=True)\n",
        encoding="utf-8",
    )
    findings = CrewaiRceChainGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "crewai-rce-chain/unsafe-code-interpreter")
    assert hit.severity == "critical"


def test_default_code_interpreter_is_safe(tmp_path: Path) -> None:
    """FP-bait: the default (sandboxed) CodeInterpreterTool() with no unsafe_mode is not flagged."""
    (tmp_path / "tools.py").write_text(
        "from crewai_tools import CodeInterpreterTool\n\n"
        "interpreter = CodeInterpreterTool()\n",
        encoding="utf-8",
    )
    findings = CrewaiRceChainGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_unsafe_mode_false_is_safe(tmp_path: Path) -> None:
    """FP-bait: unsafe_mode=False is the explicit safe/sandboxed choice."""
    (tmp_path / "tools.py").write_text(
        "from crewai_tools import CodeInterpreterTool\n\n"
        "interpreter = CodeInterpreterTool(unsafe_mode=False)\n",
        encoding="utf-8",
    )
    findings = CrewaiRceChainGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# ── json-tool-path-traversal ──────────────────────────────────────────────────

def test_json_search_tool_dynamic_path_fires_high(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "from crewai_tools import JSONSearchTool\n\n"
        "def make_tool(user_path):\n"
        "    return JSONSearchTool(json_path=user_path)\n",
        encoding="utf-8",
    )
    findings = CrewaiRceChainGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "crewai-rce-chain/json-tool-path-traversal")
    assert hit.severity == "high"


def test_json_loader_dynamic_path_fires_high(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "from crewai_tools import JSONLoader\n\n"
        "def make_loader(path):\n"
        "    return JSONLoader(path)\n",
        encoding="utf-8",
    )
    findings = CrewaiRceChainGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "crewai-rce-chain/json-tool-path-traversal" for f in findings)


def test_json_search_tool_static_path_is_safe(tmp_path: Path) -> None:
    """FP-bait: a fixed, literal file path is not attacker-influenceable."""
    (tmp_path / "tools.py").write_text(
        "from crewai_tools import JSONSearchTool\n\n"
        "tool = JSONSearchTool(json_path='data/catalog.json')\n",
        encoding="utf-8",
    )
    findings = CrewaiRceChainGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_json_search_tool_no_args_is_safe(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "from crewai_tools import JSONSearchTool\n\n"
        "tool = JSONSearchTool()\n",
        encoding="utf-8",
    )
    findings = CrewaiRceChainGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# ── rag-tool-dynamic-url-ssrf ─────────────────────────────────────────────────

def test_rag_tool_dynamic_url_fires_high(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "from crewai_tools import RagTool\n\n"
        "def make_tool(user_url):\n"
        "    return RagTool(website=user_url)\n",
        encoding="utf-8",
    )
    findings = CrewaiRceChainGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "crewai-rce-chain/rag-tool-dynamic-url-ssrf")
    assert hit.severity == "high"


def test_website_search_tool_dynamic_url_fires_high(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "from crewai_tools import WebsiteSearchTool\n\n"
        "def make_tool(url):\n"
        "    return WebsiteSearchTool(url)\n",
        encoding="utf-8",
    )
    findings = CrewaiRceChainGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "crewai-rce-chain/rag-tool-dynamic-url-ssrf" for f in findings)


def test_rag_tool_static_url_is_safe(tmp_path: Path) -> None:
    """FP-bait: a fixed, literal URL is not attacker-influenceable."""
    (tmp_path / "tools.py").write_text(
        "from crewai_tools import RagTool\n\n"
        "tool = RagTool(website='https://docs.example.com')\n",
        encoding="utf-8",
    )
    findings = CrewaiRceChainGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# ── suppression / applies() ──────────────────────────────────────────────────

def test_pragma_suppresses_all_findings(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "# security: allow-crewai-rce-chain\n"
        "from crewai_tools import CodeInterpreterTool\n\n"
        "interpreter = CodeInterpreterTool(unsafe_mode=True)\n",
        encoding="utf-8",
    )
    findings = CrewaiRceChainGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_applies_requires_python_and_llm(tmp_path: Path) -> None:
    guard = CrewaiRceChainGuard()
    assert guard.applies(mkprofile(tmp_path, features={"python", "llm"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is False
    assert guard.applies(mkprofile(tmp_path, features={"llm"})) is False


# ── trusted (configuration-derived) arguments ─────────────────────────────────

def test_module_constant_path_and_settings_url_are_safe(tmp_path: Path) -> None:
    """FP-bait: a module constant joined with a literal, and a read of a module-level settings
    object, are the normal way to configure these tools, not LLM-supplied data."""
    (tmp_path / "tools.py").write_text(
        "import os\n"
        "from pathlib import Path\n"
        "from crewai_tools import JSONSearchTool, RagTool\n"
        "from app.config import settings\n\n"
        "BASE_DIR = Path(__file__).parent\n\n"
        "catalog = JSONSearchTool(json_path=os.path.join(BASE_DIR, 'catalog.json'))\n"
        "docs = RagTool(website=settings.DOCS_URL)\n"
        "more = JSONSearchTool(json_path=BASE_DIR / 'other.json')\n"
        "fmt = RagTool(website=f'{settings.HOST}/docs')\n",
        encoding="utf-8",
    )
    assert CrewaiRceChainGuard().run(tmp_path, _prof(tmp_path)) == []


def test_parameter_local_and_shadowed_settings_still_fire(tmp_path: Path) -> None:
    """Still fires (the traded-against direction): a function parameter, a local built from one,
    a lower-case module variable, and a parameter that shadows the `settings` name all stay
    dynamic, whether or not a constant is mixed in."""
    (tmp_path / "tools.py").write_text(
        "import os\n"
        "from crewai_tools import JSONSearchTool, RagTool\n"
        "from app.config import settings\n\n"
        "BASE_DIR = '/srv'\n"
        "user_dir = get_dir()\n\n"
        "def a(name):\n"
        "    return JSONSearchTool(json_path=os.path.join(BASE_DIR, name))\n\n"
        "def b(name):\n"
        "    p = os.path.join(BASE_DIR, name)\n"
        "    return JSONSearchTool(json_path=p)\n\n"
        "def c():\n"
        "    return JSONSearchTool(json_path=os.path.join(user_dir, 'x.json'))\n\n"
        "def d(settings):\n"
        "    return RagTool(website=settings.DOCS_URL)\n\n"
        "def e(url):\n"
        "    return RagTool(website=f'{url}/docs')\n",
        encoding="utf-8",
    )
    findings = CrewaiRceChainGuard().run(tmp_path, _prof(tmp_path))
    assert {f.location for f in findings} == {
        "tools.py:9", "tools.py:13", "tools.py:16", "tools.py:19", "tools.py:22",
    }


def test_crewai_rce_chain_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): the whole-file opt-out reads the Python comment view, so a string literal
    # quoting the pragma is content. Only a real `#` comment (`..._suppresses_all_findings`) opts out.
    (tmp_path / "tools.py").write_text(
        'HELP = "opt out with # security: allow-crewai-rce-chain"\n'
        "from crewai_tools import CodeInterpreterTool\n\n"
        "interpreter = CodeInterpreterTool(unsafe_mode=True)\n",
        encoding="utf-8",
    )
    findings = CrewaiRceChainGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["crewai-rce-chain/unsafe-code-interpreter"]
