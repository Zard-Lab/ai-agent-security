"""Tests for McpMarketplaceFetchStdioSpawnGuard — planted-violation + FP-bait."""
from __future__ import annotations

import pytest

from agentsec.guards.mcp_marketplace_fetch_stdio_spawn import McpMarketplaceFetchStdioSpawnGuard
from tests.guards._common import *  # noqa: F401,F403


def _mcp_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"mcp", "llm", "python"}, python_dirs=["."])


def test_fires_on_fetch_then_stdio_server_parameters(tmp_path: Path) -> None:
    """HIGH: requests.get(...).json() feeds command/args straight into
    StdioServerParameters(...) in the same function — the Cloudflare-flagged shape."""
    (tmp_path / "mcp_marketplace_client.py").write_text(
        "import requests\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "\n"
        "def load_server(manifest_url: str) -> StdioServerParameters:\n"
        "    config = requests.get(manifest_url).json()\n"
        "    return StdioServerParameters(command=config['cmd'], args=config['args'])\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn" for f in findings)
    hit = next(f for f in findings if f.rule == "mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn")
    assert hit.severity == "high"


def test_fires_on_httpx_then_stdio_client_transport(tmp_path: Path) -> None:
    """HIGH: httpx.get(...) feeding StdioClientTransport(...) also fires."""
    (tmp_path / "mcp_registry.py").write_text(
        "import httpx\n"
        "from mcp import StdioClientTransport\n"
        "\n"
        "\n"
        "def connect(registry_url: str):\n"
        "    manifest = httpx.get(registry_url).json()\n"
        "    return StdioClientTransport(command=manifest['command'])\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn" for f in findings)


def test_fires_on_ts_fetch_then_stdio_transport(tmp_path: Path) -> None:
    """HIGH: await fetch(...) followed by new StdioClientTransport(...) fires in TS."""
    (tmp_path / "marketplace.ts").write_text(
        "import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio';\n"
        "\n"
        "async function loadServer(manifestUrl: string) {\n"
        "  const resp = await fetch(manifestUrl);\n"
        "  const config = await resp.json();\n"
        "  return new StdioClientTransport({ command: config.command, args: config.args });\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn" for f in findings)


def test_hash_verified_manifest_is_safe(tmp_path: Path) -> None:
    """(agentic pre-review M-4): the finding's own remediation suggests pinning the
    manifest to a hash-verified release -- applying exactly that fix must actually clear it."""
    (tmp_path / "client.py").write_text(
        "import hashlib\n"
        "import requests\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "TRUSTED_HASH = 'abc123'\n"
        "\n"
        "def load_server(manifest_url: str) -> StdioServerParameters:\n"
        "    resp = requests.get(manifest_url)\n"
        "    if hashlib.sha256(resp.content).hexdigest() != TRUSTED_HASH:\n"
        "        raise ValueError('manifest hash mismatch')\n"
        "    config = resp.json()\n"
        "    return StdioServerParameters(command=config['cmd'], args=config['args'])\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn" for f in findings)


def test_comment_only_mitigation_still_fires(tmp_path: Path) -> None:
    """Narrowing safety check (Dean's review, round 2 -- a regression the M-4 fix above
    introduced): a bare comment naming a mitigation, with no real verification code, must NOT
    clear the finding -- the mitigation check now runs on comment-stripped source."""
    (tmp_path / "client.py").write_text(
        "import requests\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "def load_server(manifest_url: str) -> StdioServerParameters:\n"
        "    # TODO: verify signature before trusting this manifest\n"
        "    resp = requests.get(manifest_url)\n"
        "    config = resp.json()\n"
        "    return StdioServerParameters(command=config['cmd'], args=config['args'])\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn" for f in findings)


def test_comment_only_mitigation_still_fires_ts(tmp_path: Path) -> None:
    """Same shape, TS/JS side: a comment naming a mitigation is not real code. The comment sits
    BETWEEN `fetch(` and the spawn, inside the lookahead window the mitigation scan reads (PR
    #923 round-3 M2: placed above `fetch(`, it was never scanned, so the test passed against the
    raw-text guard too)."""
    (tmp_path / "client.ts").write_text(
        "import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio';\n"
        "\n"
        "async function loadServer(manifestUrl: string) {\n"
        "  const resp = await fetch(manifestUrl);\n"
        "  // TODO: add signature verification here\n"
        "  const config = await resp.json();\n"
        "  return new StdioClientTransport({ command: config.command, args: config.args });\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn" for f in findings)


@pytest.mark.parametrize(
    ("docstring", "statement"),
    [
        pytest.param(
            '    """Load a marketplace server. Callers must verify signature before trusting."""\n',
            "",
            id="docstring",
        ),
        pytest.param(
            '    """Load a marketplace server.\n'
            "\n"
            "    Callers must verify signature before trusting this manifest.\n"
            '    """\n',
            "",
            id="multi-line-docstring",
        ),
        pytest.param(
            "",
            "    log.warning('manifest not yet checked: add signature verification')\n",
            id="log-string",
        ),
    ],
)
def test_string_only_mitigation_still_fires(tmp_path: Path, docstring: str, statement: str) -> None:
    """Still-fires (PR #923 round-3 H3): a docstring or a log message that NAMES a mitigation is
    not verification code. Both were silent at e6f95e89, because only comments were stripped."""
    (tmp_path / "client.py").write_text(
        "import requests\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "def load_server(manifest_url: str) -> StdioServerParameters:\n"
        f"{docstring}"
        "    resp = requests.get(manifest_url)\n"
        f"{statement}"
        "    config = resp.json()\n"
        "    return StdioServerParameters(command=config['cmd'], args=config['args'])\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn" for f in findings)


_TS_CLIENT = (
    "import {{ StdioClientTransport }} from '@modelcontextprotocol/sdk/client/stdio';\n"
    "\n"
    "async function loadServer(manifestUrl: string) {{\n"
    "  const resp = await fetch(manifestUrl);\n"
    "  const config = await resp.json();\n"
    "{between}"
    "  return new StdioClientTransport({{ command: config.command, args: config.args }});\n"
    "}}\n"
)


@pytest.mark.parametrize(
    "between",
    [
        pytest.param("  log.warn('manifest not yet checked: add signature verification');\n", id="quoted"),
        pytest.param("  log.warn(`TODO: verify the signature of ${manifestUrl}`);\n", id="template"),
    ],
)
def test_string_only_mitigation_still_fires_ts(tmp_path: Path, between: str) -> None:
    """Still-fires, TS form of round-3 H3: a prose string between `fetch(` and the spawn was
    enough to clear the finding at e6f95e89."""
    (tmp_path / "client.ts").write_text(_TS_CLIENT.format(between=between), encoding="utf-8")
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert any(f.rule == "mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn" for f in findings)


@pytest.mark.parametrize(
    "between",
    [
        pytest.param(
            "  if (createHash('sha256').update(JSON.stringify(config)).digest('hex') !== PINNED) throw new Error('x');\n",
            id="createHash-sha256",
        ),
        pytest.param(
            "  if (createHash(PINNED_ALGORITHM).update(JSON.stringify(config)).digest('hex') !== PINNED) throw 1;\n",
            id="createHash-algorithm-variable",
        ),
        pytest.param("  await verifySignature(config, resp.headers.get('x-signature'));\n", id="verifySignature"),
        pytest.param("  await verifyManifestSignature(config, PUBLIC_KEY);\n", id="camelCase-verify-signature"),
        pytest.param(
            "  if (!(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, body))) throw 1;\n",
            id="subtle-verify",
        ),
        pytest.param("  if (!timingSafeEqual(Buffer.from(got), Buffer.from(PINNED))) throw 1;\n", id="timingSafeEqual"),
        pytest.param("  if (resp.headers.get('x-manifest-sha256') !== PINNED) throw 1;\n", id="token-string-only"),
    ],
)
def test_real_ts_verification_is_safe(tmp_path: Path, between: str) -> None:
    """FP-bait for blanking strings (PR #923 round-3 H3): blanking strings alone made
    `createHash('sha256')` and `verifySignature(..., headers.get('x-signature'))` fire, because
    their only evidence was inside a string. Each real verification form must stay silent: via a
    code-level marker, or via a string literal that is a single token."""
    (tmp_path / "client.ts").write_text(_TS_CLIENT.format(between=between), encoding="utf-8")
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_token_string_verification_is_safe_python(tmp_path: Path) -> None:
    """FP-bait, Python side of the same widening: a single-token header name is still evidence
    once prose strings are blanked."""
    (tmp_path / "client.py").write_text(
        "import requests\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "def load_server(manifest_url: str) -> StdioServerParameters:\n"
        "    resp = requests.get(manifest_url)\n"
        "    if resp.headers['X-Manifest-Sha256'] != PINNED_DIGEST:\n"
        "        raise ValueError('manifest digest mismatch')\n"
        "    config = resp.json()\n"
        "    return StdioServerParameters(command=config['cmd'], args=config['args'])\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_user_confirmation_gate_is_safe(tmp_path: Path) -> None:
    """FP-bait companion: the finding's other suggested fix, an explicit user-confirmation gate
    before spawning, must also clear it."""
    (tmp_path / "client.ts").write_text(
        "import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio';\n"
        "\n"
        "async function loadServer(manifestUrl: string) {\n"
        "  const resp = await fetch(manifestUrl);\n"
        "  const config = await resp.json();\n"
        "  if (!(await confirm('Spawn new MCP server ' + config.command + '?'))) {\n"
        "    throw new Error('rejected');\n"
        "  }\n"
        "  return new StdioClientTransport({ command: config.command, args: config.args });\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert not any(f.rule == "mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn" for f in findings)


def test_fetch_with_no_stdio_spawn_is_safe(tmp_path: Path) -> None:
    """FP-bait: a fetch that never feeds a stdio spawn (an ordinary API call) stays silent."""
    (tmp_path / "api_client.py").write_text(
        "import requests\n"
        "\n"
        "\n"
        "def get_user_profile(user_id: str) -> dict:\n"
        "    return requests.get(f'https://api.example.com/users/{user_id}').json()\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_stdio_spawn_with_static_command_is_safe(tmp_path: Path) -> None:
    """FP-bait: a StdioServerParameters spawn with a static, hardcoded command in a
    function that ALSO happens to do an unrelated fetch elsewhere in the codebase (a
    different function) does not fire — the check is same-function only."""
    (tmp_path / "mcp_server.py").write_text(
        "import requests\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "\n"
        "def fetch_analytics() -> dict:\n"
        "    return requests.get('https://analytics.example.com/ping').json()\n"
        "\n"
        "\n"
        "def spawn_local_server() -> StdioServerParameters:\n"
        "    return StdioServerParameters(command='npx', args=['-y', 'my-mcp-server'])\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_stdio_spawn_before_fetch_is_safe(tmp_path: Path) -> None:
    """FP-bait: a stdio spawn that happens BEFORE the fetch call in the same function
    (not fed by it) does not match the fetch-then-spawn sequence."""
    (tmp_path / "mcp_mixed.py").write_text(
        "import requests\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "\n"
        "def do_both(manifest_url: str):\n"
        "    local = StdioServerParameters(command='npx', args=['-y', 'local-server'])\n"
        "    requests.get(manifest_url)  # unrelated telemetry ping, result unused\n"
        "    return local\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "mcp_marketplace_client.py").write_text(
        "import requests\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "\n"
        "def load_server(manifest_url: str) -> StdioServerParameters:\n"
        "    config = requests.get(manifest_url).json()  # security: allow-mcp-marketplace-fetch-stdio-spawn\n"
        "    return StdioServerParameters(command=config['cmd'], args=config['args'])\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_pragma_suppresses_finding_in_ts_file(tmp_path: Path) -> None:
    # (agentic pre-review H-8): the `#`-anchored regex never matched in a `.ts` file,
    # so `// security: allow-...` silently never suppressed anything there.
    (tmp_path / "marketplace.ts").write_text(
        "// security: allow-mcp-marketplace-fetch-stdio-spawn\n"
        "import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio';\n"
        "\n"
        "async function loadServer(manifestUrl: string) {\n"
        "  const resp = await fetch(manifestUrl);\n"
        "  const config = await resp.json();\n"
        "  return new StdioClientTransport({ command: config.command, args: config.args });\n"
        "}\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


def test_guard_not_applicable_without_mcp_feature(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert McpMarketplaceFetchStdioSpawnGuard().applies(prof) is False


def test_guard_applicable_with_mcp_feature(tmp_path: Path) -> None:
    assert McpMarketplaceFetchStdioSpawnGuard().applies(_mcp_prof(tmp_path)) is True


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "mcp_marketplace_client.py").write_text(
        "import requests\n"
        "from mcp import StdioServerParameters\n"
        "\n"
        "\n"
        "def load_server(manifest_url: str) -> StdioServerParameters:\n"
        "    config = requests.get(manifest_url).json()\n"
        "    return StdioServerParameters(command=config['cmd'], args=config['args'])\n",
        encoding="utf-8",
    )
    findings = McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))
    assert findings == []


# --- #1055: the TS fetch and spawn count only when they are live code -----------------------------

_TS_RULE = "mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn"


def _ts_rules(tmp_path: Path, src: str) -> list[str]:
    (tmp_path / "client.ts").write_text(src, encoding="utf-8")
    return [f.rule for f in McpMarketplaceFetchStdioSpawnGuard().run(tmp_path, _mcp_prof(tmp_path))]


@pytest.mark.parametrize(
    "src",
    [
        pytest.param(
            "async function load(u: string) {\n"
            "  // const resp = await fetch(u);\n"
            "  // return new StdioClientTransport({ command: cfg.command });\n"
            "}\n",
            id="commented-out-pair",
        ),
        pytest.param(
            "const DOC = `\n"
            "  const resp = await fetch(manifestUrl);\n"
            "  return new StdioClientTransport({ command: config.command });\n"
            "`;\n",
            id="pair-in-a-docs-template",
        ),
        pytest.param(
            "async function load(u: string) {\n"
            "  const resp = await fetch(u);\n"
            "  log.warn('never call new StdioClientTransport on a fetched manifest');\n"
            "}\n",
            id="spawn-only-in-a-string",
        ),
        pytest.param(
            "async function load(u: string) {\n"
            "  log.info('use await fetch(u) for the manifest');\n"
            "  return new StdioClientTransport({ command: LOCAL_COMMAND });\n"
            "}\n",
            id="fetch-only-in-a-string",
        ),
    ],
)
def test_ts_fetch_or_spawn_spelled_out_stays_silent(tmp_path: Path, src: str) -> None:
    assert _ts_rules(tmp_path, src) == []


@pytest.mark.parametrize(
    "between",
    [
        pytest.param("", id="plain"),
        # A quoted spawn earlier in the window must not hide the real one after it.
        pytest.param("  log.debug('new StdioClientTransport next');\n", id="quoted-spawn-first"),
        # Substitution TEXT around a quoted marker is still a string: no credit.
        pytest.param("  log.warn(`manifest ${'add signature verification'} pending`);\n", id="prose-in-substitution"),
    ],
)
def test_ts_real_fetch_then_spawn_still_fires(tmp_path: Path, between: str) -> None:
    assert _ts_rules(tmp_path, _TS_CLIENT.format(between=between)) == [_TS_RULE]


def test_ts_real_fetch_after_a_quoted_fetch_still_fires(tmp_path: Path) -> None:
    src = _TS_CLIENT.format(between="").replace(
        "  const resp = await fetch(manifestUrl);\n",
        "  log('await fetch(x)'); const resp = await fetch(manifestUrl);\n",
    )
    assert _ts_rules(tmp_path, src) == [_TS_RULE]


def test_ts_verifier_nested_in_a_substitution_clears_the_finding(tmp_path: Path) -> None:
    # The shortcut-separating case for the credit: plain `strip_strings=True` blanked a real
    # verifier nested in a `${...}`, so a verified manifest fired HIGH (#1055).
    between = "  log.info(`verified=${await verifyManifestSignature(config, PUBLIC_KEY)}`);\n"
    assert _ts_rules(tmp_path, _TS_CLIENT.format(between=between)) == []


def test_ts_pragma_still_suppresses_a_code_anchored_finding(tmp_path: Path) -> None:
    src = _TS_CLIENT.format(between="")
    assert _ts_rules(tmp_path, src) == [_TS_RULE]
    assert _ts_rules(tmp_path, src + "// security: allow-mcp-marketplace-fetch-stdio-spawn\n") == []
