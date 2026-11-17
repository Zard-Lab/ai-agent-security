from __future__ import annotations

from pathlib import Path

from agentsec.guards.agent_tool_url_fetch_ssrf import AgentToolUrlFetchSsrfGuard
from tests.conftest import mkprofile


def _llm_prof(root: Path) -> object:
    return mkprofile(root, features={"llm", "python"}, python_dirs=["."])


_TOOL_HEADER = (
    "from langchain_community.document_loaders import WebBaseLoader\n"
    "from pydantic_ai import Agent\n"
    "\n"
    "agent = Agent('openai:gpt-4o')\n"
    "\n"
    "\n"
)


def _run(tmp_path: Path, code: str) -> list:
    (tmp_path / "tools.py").write_text(code, encoding="utf-8")
    return AgentToolUrlFetchSsrfGuard().run(tmp_path, _llm_prof(tmp_path))


# --- planted violation -------------------------------------------------------------------

def test_fires_on_dynamic_url_in_tool(tmp_path: Path) -> None:
    code = _TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch_page(ctx, url: str) -> str:\n"
        "    loader = WebBaseLoader(url)\n"
        "    return loader.load()[0].page_content\n"
    )
    findings = _run(tmp_path, code)
    assert len(findings) == 1
    assert findings[0].rule == "agent-tool-url-fetch-ssrf/webbaseloader-dynamic-url"
    assert findings[0].severity == "high"


def test_fires_on_dynamic_kwarg_url(tmp_path: Path) -> None:
    code = _TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch_page(ctx, target: str) -> str:\n"
        "    loader = WebBaseLoader(web_path=target)\n"
        "    return loader.load()[0].page_content\n"
    )
    findings = _run(tmp_path, code)
    assert len(findings) == 1


def test_fires_on_list_wrapped_variable(tmp_path: Path) -> None:
    # A list literal wrapping a variable is still dynamic — must fire.
    code = _TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch_pages(ctx, target: str) -> str:\n"
        "    loader = WebBaseLoader([target])\n"
        "    return loader.load()[0].page_content\n"
    )
    findings = _run(tmp_path, code)
    assert len(findings) == 1


def test_fires_on_fstring_url(tmp_path: Path) -> None:
    # Adversarial case: an f-string interpolation looks textually "quoted" but is dynamic.
    code = _TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch_internal(ctx, host: str) -> str:\n"
        '    loader = WebBaseLoader(f"http://{host}/status")\n'
        "    return loader.load()[0].page_content\n"
    )
    findings = _run(tmp_path, code)
    assert len(findings) == 1


# --- LangChain's own bare @tool decorator (distinct from the pydantic-ai/mcp @x.tool style) ---

def test_fires_on_bare_tool_decorator(tmp_path: Path) -> None:
    # LangChain's actual idiomatic decorator (`from langchain_core.tools import tool`) has no
    # dot-prefix, unlike pydantic-ai's `@agent.tool` — must still be recognised as registration.
    code = (
        "from langchain_community.document_loaders import WebBaseLoader\n"
        "from langchain_core.tools import tool\n"
        "\n"
        "\n"
        "@tool\n"
        "def fetch_page(url: str) -> str:\n"
        "    loader = WebBaseLoader(url)\n"
        "    return loader.load()[0].page_content\n"
    )
    findings = _run(tmp_path, code)
    assert len(findings) == 1
    assert findings[0].rule == "agent-tool-url-fetch-ssrf/webbaseloader-dynamic-url"


def test_fires_on_bare_tool_decorator_with_args(tmp_path: Path) -> None:
    code = (
        "from langchain_community.document_loaders import WebBaseLoader\n"
        "from langchain_core.tools import tool\n"
        "\n"
        "\n"
        "@tool(parse_docstring=True)\n"
        "def fetch_page(url: str) -> str:\n"
        "    loader = WebBaseLoader(url)\n"
        "    return loader.load()[0].page_content\n"
    )
    findings = _run(tmp_path, code)
    assert len(findings) == 1


def test_silent_on_unrelated_toolkit_decorator(tmp_path: Path) -> None:
    # `@toolkit` must NOT be mistaken for the bare `@tool` marker.
    code = (
        "from langchain_community.document_loaders import WebBaseLoader\n"
        "\n"
        "\n"
        "@toolkit\n"
        "def fetch_page(url: str) -> str:\n"
        "    loader = WebBaseLoader(url)\n"
        "    return loader.load()[0].page_content\n"
    )
    assert _run(tmp_path, code) == []


# --- adversarial bypass: aliased import ---------------------------------------------------

def test_fires_on_aliased_import_bypass(tmp_path: Path) -> None:
    code = (
        "from langchain_community.document_loaders import WebBaseLoader as WBL\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "async def fetch_page(ctx, url: str) -> str:\n"
        "    loader = WBL(url)\n"
        "    return loader.load()[0].page_content\n"
    )
    findings = _run(tmp_path, code)
    assert len(findings) == 1
    assert findings[0].rule == "agent-tool-url-fetch-ssrf/webbaseloader-dynamic-url"


# --- FP-bait: safe-looking cases that must stay silent -------------------------------------

def test_silent_on_literal_url(tmp_path: Path) -> None:
    code = _TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch_docs(ctx) -> str:\n"
        '    loader = WebBaseLoader("https://docs.example.com/page")\n'
        "    return loader.load()[0].page_content\n"
    )
    assert _run(tmp_path, code) == []


def test_silent_on_literal_url_list(tmp_path: Path) -> None:
    code = _TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch_docs(ctx) -> str:\n"
        '    loader = WebBaseLoader(["https://docs.example.com/a", "https://docs.example.com/b"])\n'
        "    return loader.load()[0].page_content\n"
    )
    assert _run(tmp_path, code) == []


def test_silent_without_tool_registration(tmp_path: Path) -> None:
    # A plain RAG-ingestion script — no @tool/Tool(/StructuredTool/BaseTool anywhere — is a
    # different, much lower-risk pattern (developer-controlled URL, not agent-controlled).
    code = (
        "from langchain_community.document_loaders import WebBaseLoader\n"
        "\n"
        "def ingest(url: str) -> str:\n"
        "    loader = WebBaseLoader(url)\n"
        "    return loader.load()[0].page_content\n"
    )
    assert _run(tmp_path, code) == []


def test_silent_when_allowlist_marker_present(tmp_path: Path) -> None:
    code = _TOOL_HEADER + (
        "ALLOWED_HOSTS = {\"docs.example.com\"}\n"
        "\n"
        "@agent.tool\n"
        "async def fetch_page(ctx, url: str) -> str:\n"
        "    loader = WebBaseLoader(url)\n"
        "    return loader.load()[0].page_content\n"
    )
    assert _run(tmp_path, code) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    code = "# security: allow-tool-url-fetch-ssrf\n" + _TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch_page(ctx, url: str) -> str:\n"
        "    loader = WebBaseLoader(url)\n"
        "    return loader.load()[0].page_content\n"
    )
    assert _run(tmp_path, code) == []


# --- applies() gating ----------------------------------------------------------------------

def test_silent_on_literal_url_with_benign_kwarg(tmp_path: Path) -> None:
    # #423 FP-bait: the URL is a hardcoded literal; a trailing benign kwarg (verify_ssl=False,
    # encoding=...) must not make the call look dynamic.
    code = _TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch_page(ctx) -> str:\n"
        '    loader = WebBaseLoader("https://example.com/docs", verify_ssl=False)\n'
        "    return loader.load()[0].page_content\n"
    )
    assert _run(tmp_path, code) == []


def test_fires_on_literal_url_with_dynamic_kwarg(tmp_path: Path) -> None:
    # regression: a DYNAMIC value on a kwarg (web_path=target) is still dynamic.
    code = _TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch_page(ctx, target: str) -> str:\n"
        '    loader = WebBaseLoader(web_path=target, verify_ssl=False)\n'
        "    return loader.load()[0].page_content\n"
    )
    assert len(_run(tmp_path, code)) == 1


def test_not_applicable_without_llm_feature(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"})
    assert AgentToolUrlFetchSsrfGuard().applies(profile) is False


def test_applicable_with_llm_feature(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"llm", "python"})
    assert AgentToolUrlFetchSsrfGuard().applies(profile) is True


# --- widened sinks: agent-tool-url-fetch-ssrf/http-client-dynamic-url --------------------
# Closes the gap where `requests.*`/`httpx.*`/`urlopen`/sibling LangChain URL loaders were
# not recognized at all — the bare-tool-parameter `requests.get(url)` case fell through both
# this guard (only WebBaseLoader) and ssrf-general (deliberately silent on a bare variable).

_HTTP_TOOL_HEADER = (
    "import requests\n"
    "from pydantic_ai import Agent\n"
    "\n"
    "agent = Agent('openai:gpt-4o')\n"
    "\n"
    "\n"
)


def test_fires_on_bare_requests_get_url_in_tool(tmp_path: Path) -> None:
    # THE gap this rule closes: a bare tool parameter passed straight into requests.get().
    code = _HTTP_TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch_url(ctx, url: str) -> str:\n"
        "    return requests.get(url).text\n"
    )
    findings = _run(tmp_path, code)
    assert len(findings) == 1
    assert findings[0].rule == "agent-tool-url-fetch-ssrf/http-client-dynamic-url"
    assert findings[0].severity == "high"


def test_fires_on_bare_httpx_post_url_in_tool(tmp_path: Path) -> None:
    code = (
        "import httpx\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "async def post_url(ctx, target: str, body: str) -> str:\n"
        "    return httpx.post(target, data=body).text\n"
    )
    findings = _run(tmp_path, code)
    assert len(findings) == 1
    assert findings[0].rule == "agent-tool-url-fetch-ssrf/http-client-dynamic-url"


def test_fires_on_bare_urlopen_url_in_tool(tmp_path: Path) -> None:
    code = (
        "from urllib.request import urlopen\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "async def fetch_url(ctx, url: str) -> str:\n"
        "    return urlopen(url).read()\n"
    )
    findings = _run(tmp_path, code)
    assert len(findings) == 1
    assert findings[0].rule == "agent-tool-url-fetch-ssrf/http-client-dynamic-url"


def test_fires_on_sibling_url_loader_dynamic_url(tmp_path: Path) -> None:
    # AsyncHtmlLoader/SeleniumURLLoader/PlaywrightURLLoader are functionally identical
    # SSRF sinks to WebBaseLoader but were previously not in the recognized name list.
    code = (
        "from langchain_community.document_loaders import AsyncHtmlLoader\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "async def fetch_pages(ctx, url: str) -> str:\n"
        "    loader = AsyncHtmlLoader([url])\n"
        "    return loader.load()[0].page_content\n"
    )
    findings = _run(tmp_path, code)
    assert len(findings) == 1
    assert findings[0].rule == "agent-tool-url-fetch-ssrf/http-client-dynamic-url"


def test_fires_on_fstring_host_position_http_client(tmp_path: Path) -> None:
    # An interpolation in HOST position (right after the scheme) is still dynamic, even for
    # the widened sinks.
    code = _HTTP_TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch_internal(ctx, host: str) -> str:\n"
        '    return requests.get(f"http://{host}/status").text\n'
    )
    findings = _run(tmp_path, code)
    assert len(findings) == 1
    assert findings[0].rule == "agent-tool-url-fetch-ssrf/http-client-dynamic-url"


def test_silent_on_commented_out_http_client_call(tmp_path: Path) -> None:
    # FP-bait (review M7): a commented-out call is not live code and must not fire.
    code = _HTTP_TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch(ctx, url: str) -> str:\n"
        "    # return requests.get(url).text\n"
        '    return "disabled"\n'
    )
    assert _run(tmp_path, code) == []


def test_fires_on_http_client_call_with_trailing_comment(tmp_path: Path) -> None:
    # Narrowing must not overshoot: a live call with a trailing comment on the same line
    # still fires -- only the comment text itself is stripped.
    code = _HTTP_TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch(ctx, url: str) -> str:\n"
        "    return requests.get(url).text  # fetch it\n"
    )
    findings = _run(tmp_path, code)
    assert len(findings) == 1
    assert findings[0].rule == "agent-tool-url-fetch-ssrf/http-client-dynamic-url"


def test_silent_without_tool_registration_http_client(tmp_path: Path) -> None:
    # Same co-occurrence requirement as WebBaseLoader: no tool-registration marker, no fire.
    code = (
        "import requests\n"
        "\n"
        "def fetch(url: str) -> str:\n"
        "    return requests.get(url).text\n"
    )
    assert _run(tmp_path, code) == []


def test_silent_when_allowlist_marker_present_http_client(tmp_path: Path) -> None:
    code = _HTTP_TOOL_HEADER + (
        "ALLOWED_HOSTS = {\"api.example.com\"}\n"
        "\n"
        "@agent.tool\n"
        "async def fetch_url(ctx, url: str) -> str:\n"
        "    return requests.get(url).text\n"
    )
    assert _run(tmp_path, code) == []


def test_pragma_suppresses_http_client(tmp_path: Path) -> None:
    code = "# security: allow-tool-url-fetch-ssrf\n" + _HTTP_TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch_url(ctx, url: str) -> str:\n"
        "    return requests.get(url).text\n"
    )
    assert _run(tmp_path, code) == []


def test_known_fp_interpolated_base_url_still_fires(tmp_path: Path) -> None:
    # Documents a known FP (review M8): `f"{BASE_URL}/resource/{id}"` has no LITERAL
    # scheme+host prefix (the string opens on a brace), so it does NOT qualify for the
    # path-vs-host exemption above and still fires -- even though BASE_URL is typically a
    # fixed module constant, not attacker input. Pinned so a future change to the exemption
    # doesn't silently start covering this shape without the wiki doc being updated to match.
    code = _HTTP_TOOL_HEADER + (
        "BASE_URL = 'https://api.example.com'\n"
        "\n"
        "@agent.tool\n"
        "async def fetch(ctx, resource_id: str) -> str:\n"
        '    return requests.get(f"{BASE_URL}/resource/{resource_id}").text\n'
    )
    findings = _run(tmp_path, code)
    assert len(findings) == 1
    assert findings[0].rule == "agent-tool-url-fetch-ssrf/http-client-dynamic-url"


# --- FP-bait: isolating the URL argument from unrelated kwargs (json=/params=/headers=) ----

def test_silent_on_literal_url_with_dynamic_kwarg_http_client(tmp_path: Path) -> None:
    # Main FP risk this rule must avoid: a literal, developer-fixed URL with a DYNAMIC
    # unrelated kwarg (a payload body) must not be mistaken for a dynamic URL.
    code = _HTTP_TOOL_HEADER + (
        "@agent.tool\n"
        "async def notify(ctx, message: str) -> str:\n"
        "    payload = {\"text\": message}\n"
        '    return requests.post("https://hooks.slack.com/services/T00/B00/XXX", '
        "json=payload).text\n"
    )
    assert _run(tmp_path, code) == []


def test_silent_on_fstring_path_segment_only_http_client(tmp_path: Path) -> None:
    # FP-bait: interpolation confined to a PATH segment appended to a literal, fixed
    # scheme+host — an ordinary REST-client call, not an SSRF-controllable host.
    code = _HTTP_TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch_resource(ctx, resource_id: str) -> str:\n"
        '    return requests.get(f"https://api.example.com/resource/{resource_id}").text\n'
    )
    assert _run(tmp_path, code) == []


def test_silent_on_literal_url_http_client(tmp_path: Path) -> None:
    code = _HTTP_TOOL_HEADER + (
        "@agent.tool\n"
        "async def fetch_status(ctx) -> str:\n"
        '    return requests.get("https://status.example.com/health").text\n'
    )
    assert _run(tmp_path, code) == []
