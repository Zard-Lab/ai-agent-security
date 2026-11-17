from __future__ import annotations

from agentsec.guards.plugin_security import PluginSecurityGuard
from tests.guards._common import *  # noqa: F401,F403

# ── PLG003: tool-no-auth-check ───────────────────────────────────────────────

def test_plugin_security_tool_no_auth_db_query_fires(tmp_path: Path) -> None:
    """@tool function with cursor.execute but no auth param fires HIGH."""
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_data(query: str) -> list:\n"
        "    result = cursor.execute(query)\n"
        "    return result.fetchall()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "plugin-security/tool-no-auth-check"
    assert findings[0].severity == "high"
    assert findings[0].check_id == "plugin-security"
    assert "OWASP-LLM:LLM06" in findings[0].standards  # confused deputy / excessive agency


def test_plugin_security_tool_no_auth_requests_fires(tmp_path: Path) -> None:
    """@tool function calling requests.get without auth param fires."""
    (tmp_path / "tools.py").write_text(
        "import requests\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def fetch_resource(url: str) -> str:\n"
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/tool-no-auth-check" for f in findings)


def test_plugin_security_tool_with_current_user_silent(tmp_path: Path) -> None:
    """@tool function with current_user in signature stays silent (FP-bait)."""
    (tmp_path / "tools.py").write_text(
        "from fastapi import Depends\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_data(query: str, current_user: dict = Depends(get_current_user)) -> list:\n"
        "    return cursor.execute(query, user_id=current_user['id']).fetchall()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "plugin-security/tool-no-auth-check" for f in findings)


def test_plugin_security_tool_with_user_id_silent(tmp_path: Path) -> None:
    """@tool function with user_id param stays silent (FP-bait)."""
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def search_docs(query: str, user_id: str) -> list:\n"
        "    return db.query(Doc).filter(Doc.owner == user_id).all()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "plugin-security/tool-no-auth-check" for f in findings)


def test_plugin_security_tool_no_auth_pragma_silences(tmp_path: Path) -> None:
    """Pragma suppresses the tool-no-auth-check finding."""
    (tmp_path / "tools.py").write_text(
        "# security: allow-plugin-security\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_data(query: str) -> list:\n"
        "    return cursor.execute(query).fetchall()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []


# ── PLG008: tool-shared-service-identity ─────────────────────────────────────

def test_plugin_security_shared_identity_allcaps_constant_fires(tmp_path: Path) -> None:
    """An auth-named param defaulted to a bare SCREAMING_SNAKE module constant fires HIGH.

    `api_key` satisfies PLG003's auth-param check (so PLG003 stays silent), but the constant
    it's bound to never varies per caller — a hardcoded shared service credential."""
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "SERVICE_API_KEY = 'shared-service-key'\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_data(query: str, api_key: str = SERVICE_API_KEY) -> list:\n"
        "    return cursor.execute(query).fetchall()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/tool-shared-service-identity" for f in findings)
    match = next(f for f in findings if f.rule == "plugin-security/tool-shared-service-identity")
    assert match.severity == "high"
    assert "OWASP-LLM:LLM06" in match.standards
    # PLG003 must stay silent for this same function — `api_key` matches its auth-param check.
    assert not any(f.rule == "plugin-security/tool-no-auth-check" for f in findings)


def test_plugin_security_shared_identity_env_getenv_fires(tmp_path: Path) -> None:
    """An auth-named param defaulted to `os.getenv(...)` fires HIGH — evaluated once at import
    time, not per request, so every caller shares the same env-sourced credential."""
    (tmp_path / "tools.py").write_text(
        "import os\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_data(query: str, token: str = os.getenv('ADMIN_TOKEN')) -> list:\n"
        "    return cursor.execute(query).fetchall()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/tool-shared-service-identity" for f in findings)


def test_plugin_security_shared_identity_depends_silent(tmp_path: Path) -> None:
    """An auth param defaulted to `Depends(...)` (per-request DI) must NOT fire (FP-bait).

    This is the exact pattern PLG003's remediation recommends — the distinguishing feature
    between a per-request identity injection and a baked-in service credential."""
    (tmp_path / "tools.py").write_text(
        "from fastapi import Depends\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_data(query: str, api_key: str = Depends(get_service_api_key)) -> list:\n"
        "    return cursor.execute(query, key=api_key).fetchall()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "plugin-security/tool-shared-service-identity" for f in findings)


def test_plugin_security_shared_identity_no_sensitive_call_silent(tmp_path: Path) -> None:
    """An auth-named param bound to an ALL-CAPS constant with NO sensitive call in the body
    must NOT fire (FP-bait) — same gate PLG003 itself requires."""
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "SERVICE_API_KEY = 'shared-service-key'\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def describe(query: str, api_key: str = SERVICE_API_KEY) -> int:\n"
        "    return len(query)\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "plugin-security/tool-shared-service-identity" for f in findings)


def test_plugin_security_shared_identity_third_party_http_call_silent(tmp_path: Path) -> None:
    """FP-bait (review H4): an env-sourced API key sent to a THIRD-PARTY provider's own HTTP API
    is the guard's own documented safe pattern ("reserve module-level constants and env vars for
    the service's OWN infrastructure credentials"), not a confused deputy — must NOT fire."""
    (tmp_path / "tools.py").write_text(
        "import os\n"
        "import requests\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def web_search(query: str, api_key: str = os.getenv('BRAVE_API_KEY')) -> str:\n"
        "    return requests.get(\n"
        "        'https://api.search.brave.com/res/v1/web/search',\n"
        "        headers={'X-Subscription-Token': api_key},\n"
        "    ).text\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "plugin-security/tool-shared-service-identity" for f in findings)


def test_plugin_security_shared_identity_service_charge_call_silent(tmp_path: Path) -> None:
    """FP-bait (review H4): a module-constant service key sent to a third-party payments API is
    the service's own upstream provider credential, not a per-caller identity — must NOT fire."""
    (tmp_path / "tools.py").write_text(
        "import requests\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "STRIPE_API_KEY = 'sk_live_placeholder'\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def charge(amount: int, token: str = STRIPE_API_KEY) -> str:\n"
        "    return requests.post('https://api.stripe.com/v1/charges').text\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "plugin-security/tool-shared-service-identity" for f in findings)


def test_plugin_security_shared_identity_auth_mode_param_silent(tmp_path: Path) -> None:
    """A param named `auth_mode` (NOT `auth` — a longer identifier merely containing the
    substring) bound to an ALL-CAPS constant must NOT fire the new rule (FP-bait).

    `_AUTH_PARAM`'s `\\b...\\b` word boundaries do not match "auth" as a substring of a longer
    identifier like `auth_mode` (no boundary exists between the "h" and the "_"), so this
    parameter never satisfies the auth-param precondition in the first place."""
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "STRICT_AUTH = True\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_data(query: str, auth_mode: str = STRICT_AUTH) -> list:\n"
        "    return cursor.execute(query).fetchall()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "plugin-security/tool-shared-service-identity" for f in findings)


def test_plugin_security_shared_identity_pragma_silences(tmp_path: Path) -> None:
    """Pragma suppresses the tool-shared-service-identity finding."""
    (tmp_path / "tools.py").write_text(
        "# security: allow-plugin-security\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "SERVICE_API_KEY = 'shared-service-key'\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_data(query: str, api_key: str = SERVICE_API_KEY) -> list:\n"
        "    return cursor.execute(query).fetchall()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []


# ── PLG001: tool-unvalidated-input ───────────────────────────────────────────

def test_plugin_security_tool_dict_param_fires(tmp_path: Path) -> None:
    """@tool function with dict-typed param fires MEDIUM."""
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def search(query: dict) -> list:\n"
        "    return []\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/tool-unvalidated-input" for f in findings)
    match = next(f for f in findings if f.rule == "plugin-security/tool-unvalidated-input")
    assert match.severity == "medium"


def test_plugin_security_tool_any_param_fires(tmp_path: Path) -> None:
    """@tool function with Any-typed param fires MEDIUM."""
    (tmp_path / "tools.py").write_text(
        "from typing import Any\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def process(data: Any) -> str:\n"
        "    return str(data)\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/tool-unvalidated-input" for f in findings)


def test_plugin_security_tool_untyped_param_fires(tmp_path: Path) -> None:
    """@tool function with bare untyped param fires MEDIUM."""
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def process(data) -> str:\n"
        "    return str(data)\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/tool-unvalidated-input" for f in findings)


def test_plugin_security_tool_pydantic_model_silent(tmp_path: Path) -> None:
    """@tool with a Pydantic model param stays silent (FP-bait)."""
    (tmp_path / "tools.py").write_text(
        "from pydantic import BaseModel\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "class SearchInput(BaseModel):\n"
        "    query: str\n"
        "    limit: int = 10\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def search(input: SearchInput) -> list:\n"
        "    return []\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "plugin-security/tool-unvalidated-input" for f in findings)


def test_plugin_security_tool_str_param_silent(tmp_path: Path) -> None:
    """@tool with str param stays silent (simple tools with primitive types are OK)."""
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def search(query: str) -> list:\n"
        "    return []\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "plugin-security/tool-unvalidated-input" for f in findings)


# ── PLG005: wildcard-capabilities ────────────────────────────────────────────

def test_plugin_security_wildcard_cap_star_fires(tmp_path: Path) -> None:
    """Plugin manifest with 'capabilities': '*' fires HIGH."""
    (tmp_path / "plugin.json").write_text(
        '{\n  "name": "my-plugin",\n  "capabilities": "*"\n}\n',
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/wildcard-capabilities" for f in findings)
    match = next(f for f in findings if f.rule == "plugin-security/wildcard-capabilities")
    assert match.severity == "high"


def test_plugin_security_wildcard_permissions_array_fires(tmp_path: Path) -> None:
    """Plugin manifest with 'permissions': ['*'] fires HIGH."""
    (tmp_path / "tools.json").write_text(
        '{\n  "name": "my-plugin",\n  "permissions": ["*"]\n}\n',
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/wildcard-capabilities" for f in findings)


def test_plugin_security_wildcard_all_fires(tmp_path: Path) -> None:
    """Plugin manifest with 'permissions': 'all' fires HIGH."""
    (tmp_path / "plugin.json").write_text(
        '{\n  "name": "my-plugin",\n  "permissions": "all"\n}\n',
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/wildcard-capabilities" for f in findings)


def test_plugin_security_explicit_capabilities_silent(tmp_path: Path) -> None:
    """Plugin manifest with specific capability list stays silent (FP-bait)."""
    (tmp_path / "plugin.json").write_text(
        '{\n  "name": "my-plugin",\n  "capabilities": ["read_documents", "write_files"]\n}\n',
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "plugin-security/wildcard-capabilities" for f in findings)


def test_plugin_security_ai_plugin_json_wildcard_fires(tmp_path: Path) -> None:
    """Well-known ai-plugin.json with wildcard access fires."""
    wk = tmp_path / ".well-known"
    wk.mkdir()
    (wk / "ai-plugin.json").write_text(
        '{\n  "name_for_human": "My Plugin",\n  "access": "*"\n}\n',
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/wildcard-capabilities" for f in findings)


# ── PLG007: tool-data-overexposure ───────────────────────────────────────────

def test_plugin_security_tool_model_dump_fires(tmp_path: Path) -> None:
    """@tool returning model_dump() without filter fires MEDIUM."""
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_user(user_id: str) -> dict:\n"
        "    user = db.query(User).filter(User.id == user_id).first()\n"
        "    return user.model_dump()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/tool-data-overexposure" for f in findings)
    match = next(f for f in findings if f.rule == "plugin-security/tool-data-overexposure")
    assert match.severity == "medium"


def test_plugin_security_tool_dict_method_fires(tmp_path: Path) -> None:
    """@tool returning .dict() fires MEDIUM."""
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_item(item_id: str) -> dict:\n"
        "    item = db.query(Item).get(item_id)\n"
        "    return item.dict()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/tool-data-overexposure" for f in findings)


def test_plugin_security_tool_filtered_dump_silent(tmp_path: Path) -> None:
    """@tool returning model_dump(exclude={...}) stays silent (FP-bait)."""
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_user(user_id: str) -> dict:\n"
        "    user = db.query(User).filter(User.id == user_id).first()\n"
        "    return user.model_dump(exclude={'password_hash', 'api_key'})\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "plugin-security/tool-data-overexposure" for f in findings)


def test_plugin_security_tool_include_dump_silent(tmp_path: Path) -> None:
    """@tool returning model_dump(include={...}) stays silent (FP-bait)."""
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_user(user_id: str, current_user: dict) -> dict:\n"
        "    user = db.query(User).filter(User.id == user_id).first()\n"
        "    return user.model_dump(include={'id', 'name', 'email'})\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "plugin-security/tool-data-overexposure" for f in findings)


# ── FP-bait regressions (review fixes) ────────────────────────────────────

def test_plugin_security_response_json_silent(tmp_path: Path) -> None:
    """`resp.json()` (the universal HTTP body-parse idiom) must NOT fire PLG007.

    Regression: `_MODEL_DUMP` used to match any `.json()`, so every network @tool
    that parsed an HTTP response false-fired MEDIUM.
    """
    (tmp_path / "tools.py").write_text(
        "import httpx\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_weather(city: str, current_user: str) -> dict:\n"
        "    resp = httpx.get(f'https://api.example.com/wx?q={city}')\n"
        "    return resp.json()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []


def test_plugin_security_os_path_build_silent(tmp_path: Path) -> None:
    """A @tool that only builds a path with os.path.* must NOT fire PLG003.

    Regression: `_SENSITIVE_CALL` matched bare `os.path`, so `os.path.dirname`/`join`
    (pure path construction, no resource access) false-fired HIGH.
    """
    (tmp_path / "tools.py").write_text(
        "import os\n"
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def template_dir() -> str:\n"
        "    return os.path.join(os.path.dirname(__file__), 'templates')\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []


def test_plugin_security_keyword_only_separator_silent(tmp_path: Path) -> None:
    """A fully-annotated @tool with a keyword-only `*` separator must NOT fire PLG001.

    Regression: the bare `*` separator (no `:`) was treated as an un-annotated param.
    """
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def echo(text: str, *, upper: bool = False) -> str:\n"
        "    return text.upper() if upper else text\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []


def test_plugin_security_wildcard_yaml_fires(tmp_path: Path) -> None:
    """PLG005 fires on a YAML manifest with a wildcard permissions value."""
    (tmp_path / "plugin.yaml").write_text(
        "name: my-plugin\n"
        'permissions: "*"\n',
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/wildcard-capabilities" for f in findings)
    assert next(f for f in findings if f.rule == "plugin-security/wildcard-capabilities").severity == "high"


def test_plugin_security_yaml_all_substring_silent(tmp_path: Path) -> None:
    """A YAML manifest value like `all_users` is not a wildcard — must NOT fire PLG005."""
    (tmp_path / "plugin.yaml").write_text(
        "name: my-plugin\n"
        "access: all_users\n"
        "scopes:\n"
        "  - read_docs\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "plugin-security/wildcard-capabilities" for f in findings)


# ── Issue #422 S1: black-wrapped multi-line signatures ──────────────────────

def test_plugin_security_multiline_signature_no_auth_fires(tmp_path: Path) -> None:
    """A black-wrapped @tool signature is still scanned (regression, issue #422 S1).

    The def's closing paren is on a later line; the guard used to match `_FUNC_DEF`
    per single line, so the whole function was invisible to all three Python rules.
    """
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_data(\n"
        "    query: str,\n"
        "    limit: int = 10,\n"
        ") -> list:\n"
        "    result = cursor.execute(query)\n"
        "    return result.fetchall()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/tool-no-auth-check" for f in findings)


def test_plugin_security_multiline_signature_compliant_silent(tmp_path: Path) -> None:
    """A compliant black-wrapped signature (typed params, auth param) stays silent (FP-bait)."""
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_data(\n"
        "    query: str,\n"
        "    current_user: str,\n"
        ") -> list:\n"
        "    return cursor.execute(query, user=current_user).fetchall()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []


# ── Cross-cutting: guard does not apply when llm not in features ───────────

def test_plugin_security_not_llm_stack_does_not_apply(tmp_path: Path) -> None:
    """Guard does not apply when llm is not in profile features."""
    prof = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert not PluginSecurityGuard().applies(prof)


def test_plugin_security_llm_stack_applies(tmp_path: Path) -> None:
    """Guard applies when llm is in profile features."""
    prof = _llm_prof(tmp_path)
    assert PluginSecurityGuard().applies(prof)

def test_plugin_security_comment_paren_in_signature_fires(tmp_path: Path) -> None:
    # Regression (#437 review High-2): a stray `)` inside a `#` comment within the wrapped
    # signature ended the paren-balance join early, dropping the whole @tool function from
    # scan scope for all three Python rules.
    (tmp_path / "tools.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "@agent.tool\n"
        "def get_data(\n"
        "    # legacy note: replaced old handler)\n"
        "    query: str,\n"
        ") -> list:\n"
        "    result = cursor.execute(query)\n"
        "    return result.fetchall()\n",
        encoding="utf-8",
    )
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "plugin-security/tool-no-auth-check" for f in findings)


# ── #425: one finding per @tool / per manifest, not one per repo ─────────────────────

_NO_AUTH = "plugin-security/tool-no-auth-check"
_SHARED_ID = "plugin-security/tool-shared-service-identity"
_UNVALIDATED = "plugin-security/tool-unvalidated-input"
_WILDCARD = "plugin-security/wildcard-capabilities"
_OVEREXPOSED = "plugin-security/tool-data-overexposure"
_PS_HDR = (
    "import os\n"
    "from fastapi import Depends\n"
    "from pydantic_ai import Agent\n"
    "\n"
    "SERVICE_API_KEY = 'shared-service-key'\n"
    "agent = Agent('openai:gpt-4o')\n"
)
_QUERY = "    return cursor.execute(q).fetchall()"
_DUMP = "    user = db.get(user_id)\n    return user.model_dump()"


def _ps_tool(name: str, sig: str, body: str) -> str:
    return f"\n\n@agent.tool\ndef {name}({sig}) -> list:\n{body}\n"


def _ps_write(path: Path, *tools: str) -> None:
    path.write_text(_PS_HDR + "".join(tools), encoding="utf-8")


def _ps_decorators(root: Path, *names: str) -> set[str]:
    """`<file>:<line>` of every `@agent.tool` decorator in the named files: the anchor of a tool rule."""
    return {
        f"{name}:{i}"
        for name in names
        for i, line in enumerate((root / name).read_text(encoding="utf-8").splitlines(), 1)
        if line.startswith("@agent.tool")
    }


def _ps_hits(root: Path, rule: str) -> list[str]:
    findings = PluginSecurityGuard().run(root, _llm_prof(root))
    return sorted(f.location.replace("\\", "/") for f in findings if f.rule == rule)


def test_plugin_security_reports_every_unauthenticated_tool(tmp_path: Path) -> None:
    # Regression for #425 (the issue's own repro): _check_tool_no_auth returned its first hit
    # from inside the all-files loop, so three unauthenticated tools over two files reported
    # one, and an exception on that one hid the other two. Each tool reports at its decorator.
    _ps_write(tmp_path / "tools_a.py", _ps_tool("a1", "q: str", _QUERY), _ps_tool("a2", "q: str", _QUERY))
    _ps_write(tmp_path / "tools_b.py", _ps_tool("b1", "q: str", _QUERY))
    hits = _ps_hits(tmp_path, _NO_AUTH)
    assert len(hits) == 3
    assert set(hits) == _ps_decorators(tmp_path, "tools_a.py", "tools_b.py")


def test_plugin_security_safe_tools_after_an_unauthenticated_one_stay_silent(tmp_path: Path) -> None:
    # FP-bait for the #425 widening: tools after the first hit used to be unreachable. A tool
    # taking the caller's identity, and one touching no data at all, after an unauthenticated
    # tool in the same file, must not become extra findings.
    _ps_write(
        tmp_path / "tools.py",
        _ps_tool("a1", "q: str", _QUERY),
        _ps_tool("a2", "q: str, current_user: User = Depends(get_current_user)", _QUERY),
        _ps_tool("a3", "q: str", "    return [q.upper()]"),
    )
    assert _ps_hits(tmp_path, _NO_AUTH) == ["tools.py:9"]


def test_plugin_security_reports_every_shared_identity_tool(tmp_path: Path) -> None:
    # Regression for #425 (PLG008 re-copied the idiom after filing): one finding per tool.
    _ps_write(
        tmp_path / "tools_a.py",
        _ps_tool("a1", "q: str, api_key: str = SERVICE_API_KEY", _QUERY),
        _ps_tool("a2", "q: str, token: str = os.getenv('ADMIN_TOKEN')", _QUERY),
    )
    _ps_write(tmp_path / "tools_b.py", _ps_tool("b1", "q: str, api_key: str = SERVICE_API_KEY", _QUERY))
    hits = _ps_hits(tmp_path, _SHARED_ID)
    assert len(hits) == 3
    assert set(hits) == _ps_decorators(tmp_path, "tools_a.py", "tools_b.py")


def test_plugin_security_shared_identity_one_finding_per_tool_with_two_bad_params(tmp_path: Path) -> None:
    # The anchor is the tool, so two shared-credential params on one tool give one finding,
    # not two at the same location (#425: the `break` out of the params loop).
    _ps_write(
        tmp_path / "tools.py",
        _ps_tool("a1", "q: str, api_key: str = SERVICE_API_KEY, token: str = os.getenv('T')", _QUERY),
    )
    assert _ps_hits(tmp_path, _SHARED_ID) == ["tools.py:9"]


def test_plugin_security_per_request_identity_after_a_shared_one_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the #425 widening: a per-request `Depends(...)` identity, after a tool bound to
    # a shared service credential in the same file, must not become a second finding.
    _ps_write(
        tmp_path / "tools.py",
        _ps_tool("a1", "q: str, api_key: str = SERVICE_API_KEY", _QUERY),
        _ps_tool("a2", "q: str, api_key: str = Depends(get_caller_api_key)", _QUERY),
    )
    assert _ps_hits(tmp_path, _SHARED_ID) == ["tools.py:9"]


def test_plugin_security_reports_every_unvalidated_input_tool(tmp_path: Path) -> None:
    # Regression for #425: both branches of _check_tool_unvalidated_input (dict/Any annotation,
    # and a bare untyped param) returned their first hit. One finding per tool, either branch.
    _ps_write(
        tmp_path / "tools_a.py",
        _ps_tool("a1", "query: dict", "    return []"),
        _ps_tool("a2", "payload: Any", "    return []"),
    )
    _ps_write(tmp_path / "tools_b.py", _ps_tool("b1", "query", "    return []"))
    hits = _ps_hits(tmp_path, _UNVALIDATED)
    assert len(hits) == 3
    assert set(hits) == _ps_decorators(tmp_path, "tools_a.py", "tools_b.py")


def test_plugin_security_unvalidated_input_one_finding_per_tool(tmp_path: Path) -> None:
    # A tool that is both dict-typed and has a bare param, and a tool with two bare params, each
    # give exactly one finding (#425: `continue` past the bare-param pass, `break` inside it).
    _ps_write(
        tmp_path / "tools.py",
        _ps_tool("a1", "query: dict, limit", "    return []"),
        _ps_tool("a2", "query, limit", "    return []"),
    )
    assert _ps_hits(tmp_path, _UNVALIDATED) == ["tools.py:14", "tools.py:9"]


def test_plugin_security_typed_tools_after_an_unvalidated_one_stay_silent(tmp_path: Path) -> None:
    # FP-bait for the #425 widening: fully typed tools, including a keyword-only separator,
    # after a dict-typed tool in the same file, must not become extra findings.
    _ps_write(
        tmp_path / "tools.py",
        _ps_tool("a1", "query: dict", "    return []"),
        _ps_tool("a2", "query: str, limit: int = 10", "    return []"),
        _ps_tool("a3", "*, query: str", "    return []"),
    )
    assert _ps_hits(tmp_path, _UNVALIDATED) == ["tools.py:9"]


def test_plugin_security_reports_every_wildcard_manifest(tmp_path: Path) -> None:
    # Regression for #425: _check_wildcard_capabilities returned its first wildcard manifest.
    # One finding per manifest file.
    (tmp_path / "plugin.json").write_text('{\n  "name": "p1",\n  "capabilities": "*"\n}\n', encoding="utf-8")
    (tmp_path / "tools.json").write_text('{\n  "name": "p2",\n  "permissions": ["*"]\n}\n', encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "plugin.json").write_text(
        '{\n  "name": "p3",\n  "permissions": "all"\n}\n', encoding="utf-8"
    )
    assert _ps_hits(tmp_path, _WILDCARD) == ["plugin.json", "sub/plugin.json", "tools.json"]


def test_plugin_security_scoped_manifest_next_to_a_wildcard_one_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the #425 widening: a manifest with an explicit capability list must not fire
    # just because another manifest in the repo is a wildcard one.
    (tmp_path / "plugin.json").write_text('{\n  "name": "p1",\n  "capabilities": "*"\n}\n', encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "plugin.json").write_text(
        '{\n  "name": "p2",\n  "capabilities": ["read_documents"]\n}\n', encoding="utf-8"
    )
    assert _ps_hits(tmp_path, _WILDCARD) == ["plugin.json"]


def test_plugin_security_reports_every_overexposing_tool(tmp_path: Path) -> None:
    # Regression for #425: _check_tool_data_overexposure returned its first hit. One per tool.
    _ps_write(
        tmp_path / "dump_a.py",
        _ps_tool("d1", "user_id: str", _DUMP),
        _ps_tool("d2", "user_id: str", _DUMP),
    )
    _ps_write(tmp_path / "dump_b.py", _ps_tool("d3", "user_id: str", _DUMP))
    hits = _ps_hits(tmp_path, _OVEREXPOSED)
    assert len(hits) == 3
    assert set(hits) == _ps_decorators(tmp_path, "dump_a.py", "dump_b.py")


def test_plugin_security_filtered_dump_after_a_full_one_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the #425 widening: a field-limited dump, after a full model dump in the same
    # file, must not become a second finding.
    _ps_write(
        tmp_path / "dump.py",
        _ps_tool("d1", "user_id: str", _DUMP),
        _ps_tool("d2", "user_id: str", "    user = db.get(user_id)\n    return user.model_dump(include={'id'})"),
    )
    assert _ps_hits(tmp_path, _OVEREXPOSED) == ["dump.py:9"]


def test_plugin_security_per_file_pragma_still_scopes_to_its_file(tmp_path: Path) -> None:
    # The pragma is per FILE. After #425 a pragma'd file must still contribute nothing while the
    # other file keeps contributing every rule's findings.
    tools = (
        _ps_tool("t1", "q: str", _QUERY),
        _ps_tool("t2", "q: str, api_key: str = SERVICE_API_KEY", _QUERY),
        _ps_tool("t3", "query: dict", "    return []"),
        _ps_tool("t4", "user_id: str", _DUMP),
    )
    (tmp_path / "tools_a.py").write_text(
        "# security: allow-plugin-security\n" + _PS_HDR + "".join(tools), encoding="utf-8"
    )
    _ps_write(tmp_path / "tools_b.py", *tools)
    findings = PluginSecurityGuard().run(tmp_path, _llm_prof(tmp_path))
    assert {f.location.split(":")[0] for f in findings} == {"tools_b.py"}
    assert {_NO_AUTH, _SHARED_ID, _UNVALIDATED, _OVEREXPOSED} <= {f.rule for f in findings}
