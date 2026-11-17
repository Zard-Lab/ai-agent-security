from __future__ import annotations

import pytest

from agentsec.guards.llm_tool_result_leak import LlmToolResultLeakGuard
from tests.guards._common import *  # noqa: F401,F403


def _guard() -> LlmToolResultLeakGuard:
    return LlmToolResultLeakGuard()


# The OpenAI/Anthropic function-calling tool-context marker a RAG app actually uses — a
# {"type": "function", ...} schema dict in the same module as the executor functions.
_SCHEMA = '_TOOL = {"type": "function", "function": {"name": "search_videos"}}\n'


def test_llm_tool_result_leak_openai_schema_exception_return_fires(tmp_path: Path) -> None:
    # The exact RAG-app shape: an OpenAI tool schema + an executor whose except
    # block returns the stringified exception in the {"ok": False, "error": ...} tool result.
    (tmp_path / "tools.py").write_text(
        _SCHEMA
        + "async def execute_search_hybrid(raw):\n"
        "    try:\n"
        "        return await retrieve(raw)\n"
        "    except Exception as exc:\n"
        '        return {"ok": False, "error": f"search failed: {exc}"}\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = [f.rule for f in findings]
    assert "llm-tool-result-leak/exception-in-tool-return" in rules
    assert all(f.severity == "medium" for f in findings)


def test_llm_tool_result_leak_langchain_decorator_fires(tmp_path: Path) -> None:
    # The langchain/pydantic-ai decorator style is also a tool context.
    (tmp_path / "agent.py").write_text(
        "from langchain_core.tools import tool\n"
        "@tool\n"
        "def lookup(q: str) -> str:\n"
        "    try:\n"
        "        return do(q)\n"
        "    except Exception as e:\n"
        '        return f"lookup failed: {e}"\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "llm-tool-result-leak/exception-in-tool-return" for f in findings)


def test_llm_tool_result_leak_traceback_return_fires(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        _SCHEMA
        + "import traceback\n"
        "def run_tool(a):\n"
        "    try:\n"
        "        return work(a)\n"
        "    except Exception:\n"
        '        return {"ok": False, "error": traceback.format_exc()}\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "llm-tool-result-leak/exception-in-tool-return" for f in findings)


def test_llm_tool_result_leak_non_tool_file_silent(tmp_path: Path) -> None:
    # FP-bait / partition with error-info-leak: the SAME error-dict return in a plain helper
    # module with NO tool context must stay silent — this guard only fires on LLM-tool surfaces.
    (tmp_path / "helpers.py").write_text(
        "def parse(raw):\n"
        "    try:\n"
        "        return load(raw)\n"
        "    except Exception as exc:\n"
        '        return {"ok": False, "error": f"parse failed: {exc}"}\n',
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_llm_tool_result_leak_generic_message_silent(tmp_path: Path) -> None:
    # A tool that returns a fixed generic error (does NOT stringify the exception) is the fix —
    # must stay silent.
    (tmp_path / "tools.py").write_text(
        _SCHEMA
        + "def run_tool(a):\n"
        "    try:\n"
        "        return work(a)\n"
        "    except Exception as exc:\n"
        '        return {"ok": False, "error": "search failed"}\n',
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_llm_tool_result_leak_sanitized_silent(tmp_path: Path) -> None:
    # A redaction/sanitize call between the exception and the return suppresses.
    #
    # FIXTURE REWRITTEN (#469 review): the previous one was VACUOUS — neutering `_SANITIZE` in
    # the guard left the whole suite green. It used `safe = redact(str(exc))`, which never
    # matches the `safe = str(exc)` assignment form the guard tracks, so `safe` was never an
    # exception-derived variable and the case was silent for an unrelated reason. This fixture
    # puts `str(exc)` directly in the returned expression, so the sink IS recognised and the
    # sanitize gate is the only thing suppressing it — see the companion test below, which
    # proves the same fixture fires once the redaction is removed.
    (tmp_path / "tools.py").write_text(
        _SCHEMA
        + "def run_tool(a):\n"
        "    try:\n"
        "        return work(a)\n"
        "    except Exception as exc:\n"
        '        return {"ok": False, "error": redact(str(exc))}\n',
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_llm_tool_result_leak_same_fixture_fires_without_the_redaction(tmp_path: Path) -> None:
    # The other half of the pair above: identical fixture with `redact(...)` removed. If this
    # ever stops firing, the sanitize test above has gone vacuous again and is proving nothing.
    (tmp_path / "tools.py").write_text(
        _SCHEMA
        + "def run_tool(a):\n"
        "    try:\n"
        "        return work(a)\n"
        "    except Exception as exc:\n"
        '        return {"ok": False, "error": str(exc)}\n',
        encoding="utf-8",
    )
    assert len(_guard().run(tmp_path, _llm_prof(tmp_path))) == 1


def test_llm_tool_result_leak_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        _SCHEMA
        + "# security: allow-llm-tool-result-leak\n"
        "def run_tool(a):\n"
        "    try:\n"
        "        return work(a)\n"
        "    except Exception as exc:\n"
        '        return {"ok": False, "error": str(exc)}\n',
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_llm_tool_result_leak_not_applicable_without_llm(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"fastapi", "python"})
    assert _guard().applies(prof) is False


def test_llm_tool_result_leak_unrelated_mask_var_does_not_suppress(tmp_path: Path) -> None:
    # Regression (review #469, High FN): a local whose NAME merely contains a sanitize word
    # (`mask`) but is not a redaction CALL must not suppress a real leak on a later return.
    (tmp_path / "tools.py").write_text(
        _SCHEMA
        + "def run_tool(a):\n"
        "    try:\n"
        "        return work(a)\n"
        "    except Exception as exc:\n"
        "        mask = compute_bitmask(a)\n"
        '        return {"ok": False, "error": str(exc)}\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "llm-tool-result-leak/exception-in-tool-return" for f in findings)


def test_llm_tool_result_leak_prefix_var_not_flagged(tmp_path: Path) -> None:
    # Regression (review #469, Medium FP): a different variable sharing the bound name's prefix
    # ({exc_type} when the bound exception is `exc`) must NOT be treated as the exception itself.
    (tmp_path / "tools.py").write_text(
        _SCHEMA
        + "def run_tool(a):\n"
        "    try:\n"
        "        return work(a)\n"
        "    except Exception as exc:\n"
        "        exc_type = type(exc).__name__\n"
        '        return {"ok": False, "error": f"failed: {exc_type}"}\n',
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_llm_tool_result_leak_tools_kwarg_context_fires(tmp_path: Path) -> None:
    # The `tools=[...]` kwarg on a generation call is also a tool-context signal.
    (tmp_path / "agent.py").write_text(
        "def run(client, a):\n"
        "    resp = client.chat.completions.create(model='x', tools=[SEARCH_TOOL])\n"
        "    try:\n"
        "        return work(a)\n"
        "    except Exception as exc:\n"
        '        return {"ok": False, "error": str(exc)}\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "llm-tool-result-leak/exception-in-tool-return" for f in findings)


def test_llm_tool_result_leak_assigned_var_then_return_fires(tmp_path: Path) -> None:
    # One-hop: str(exc) assigned to a local, that local returned in the tool result.
    (tmp_path / "tools.py").write_text(
        _SCHEMA
        + "def run_tool(a):\n"
        "    try:\n"
        "        return work(a)\n"
        "    except Exception as exc:\n"
        "        msg = str(exc)\n"
        '        return {"ok": False, "error": msg}\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "llm-tool-result-leak/exception-in-tool-return" for f in findings)


def test_llm_tool_result_leak_test_path_silent(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_tools.py").write_text(
        _SCHEMA
        + "def run_tool(a):\n"
        "    try:\n"
        "        return work(a)\n"
        "    except Exception as exc:\n"
        '        return {"ok": False, "error": str(exc)}\n',
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_llm_tool_result_leak_mcp_low_level_call_tool_fires(tmp_path: Path) -> None:
    # MCP's low-level server API: no @tool decorator and no schema dict, but @server.call_tool()
    # registers a real tool dispatcher, so the stringified exception lands in the model's context.
    (tmp_path / "mcp_server.py").write_text(
        "import mcp.server\n"
        "\n"
        "server = mcp.server.Server('demo')\n"
        "\n"
        "@server.call_tool()\n"
        "async def call_tool(name, args):\n"
        "    try:\n"
        "        return await dispatch(name, args)\n"
        "    except Exception as exc:\n"
        '        return {"ok": False, "error": str(exc)}\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "llm-tool-result-leak/exception-in-tool-return" for f in findings)


def test_llm_tool_result_leak_mcp_client_wrapper_silent(tmp_path: Path) -> None:
    # FP-bait: a pure MCP *client* wrapper defines no tool. An `mcp` IMPORT is not a tool signal —
    # only a definition/registration/dispatch site is (see guard-design item 3).
    (tmp_path / "mcp_client.py").write_text(
        "from mcp import ClientSession\n"
        "from mcp.client.stdio import stdio_client\n"
        "\n"
        "async def fetch_remote(url):\n"
        "    try:\n"
        "        async with stdio_client(url) as (r, w):\n"
        "            return {'ok': True, 'data': await ClientSession(r, w).initialize()}\n"
        "    except Exception as exc:\n"
        '        return {"ok": False, "error": str(exc)}\n',
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_llm_tool_result_leak_mcp_type_only_import_silent(tmp_path: Path) -> None:
    # FP-bait: a type-only `mcp.types` import plus a bare `FastMCP` mention in prose. Neither
    # defines, registers or dispatches a tool, so this is the plain-helper case the guard excludes;
    # it must stay silent for the SAME reason the no-import control does.
    (tmp_path / "helpers.py").write_text(
        '"""Helpers. Someday we may port these to FastMCP."""\n'
        "from mcp.types import TextContent\n"
        "\n"
        "def render(payload) -> TextContent:\n"
        "    return TextContent(type='text', text=payload)\n"
        "\n"
        "def load_config(path):\n"
        "    try:\n"
        "        return parse(path)\n"
        "    except Exception as exc:\n"
        '        return {"ok": False, "error": f"load failed: {exc}"}\n',
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _llm_prof(tmp_path)) == []


# --- Imperative (undecorated) registration sites ------------------------------------------
# The invariant: a file is a tool surface iff it contains a site where a callable is DEFINED,
# REGISTERED or DISPATCHED as a tool. Dropping the import-level MCP signals was right, but
# `mcp.add_tool(fn)` — FastMCP's first-class registration API, no decorator — had only ever been
# covered ACCIDENTALLY by the bare `FastMCP` mention, so it went silent with it.


def test_llm_tool_result_leak_mcp_add_tool_imperative_fires(tmp_path: Path) -> None:
    # Planted violation: FastMCP's imperative `mcp.add_tool(search)` registers `search` as a real
    # tool with no decorator, so the stringified exception lands in the model's tool-result context.
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        'mcp = FastMCP("demo")\n'
        "\n"
        "async def search(q):\n"
        "    try:\n"
        "        return do(q)\n"
        "    except Exception as exc:\n"
        '        return {"ok": False, "error": str(exc)}\n'
        "\n"
        "mcp.add_tool(search)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["llm-tool-result-leak/exception-in-tool-return"]


def test_llm_tool_result_leak_add_tool_indented_and_partial_fire(tmp_path: Path) -> None:
    # The same registration site inside a method (`self.mcp.add_tool(...)`) and wrapping the
    # callable in `functools.partial(...)` — both still register a tool.
    (tmp_path / "srv.py").write_text(
        "import functools\n"
        "\n"
        "class Server:\n"
        "    def setup(self):\n"
        "        self.mcp.add_tool(functools.partial(self.search, cfg=CFG))\n"
        "\n"
        "    def search(self, q, cfg):\n"
        "        try:\n"
        "            return do(q, cfg)\n"
        "        except Exception as exc:\n"
        '            return {"ok": False, "error": repr(exc)}\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["llm-tool-result-leak/exception-in-tool-return"]


@pytest.mark.parametrize(
    "label,head",
    [
        # THE REGRESSION THIS PINS (#469 re-gate 2). The AST rewrite hardened the `add_tool` branch
        # (SDK keyword allow-list + a required callable argument) but left its sibling constructor
        # branch asking only for a `name=` keyword on any `*Tool(...)` call. The regex it replaced
        # was already loose, but required `name=` to be the LITERAL LEADING token and could not
        # cross a `.`; the AST version dropped both constraints and added no callable check, so an
        # ordinary CI/deployment module became an "LLM-tool surface" and every except-return in it
        # became a finding. Measured 0 -> 1 against c3a881a8 on the first two.
        #
        # None of the three axes -- a non-leading `name=`, a missing callable, a dotted receiver --
        # had a test anywhere in this file, which is why the rewrite passed 102 tests with the
        # defect in it.
        ("CI tool, name= not leading",
         "def mk(cfg):\n    step = BuildTool(target=cfg.target, name='compile')\n"),
        ("dotted receiver constructor", "def mk():\n    step = mod.MyTool(name='x')\n"),
        # No callable argument at all. This one also fired at c3a881a8, so it is a pre-existing FP
        # the same fix happens to close rather than a regression -- recorded so the distinction is
        # in the record and not just in the diff.
        ("no callable argument", "def mk():\n    step = BuildTool(name='compile')\n"),
    ],
)
def test_llm_tool_result_leak_tool_constructor_needs_a_callable(
    tmp_path: Path, label: str, head: str
) -> None:
    assert _reg(tmp_path, head) == 0, label


def test_llm_tool_result_leak_langchain_imperative_constructors_fire(tmp_path: Path) -> None:
    # LangChain's imperative constructors are the same class of registration site.
    # `StructuredTool.from_function` was only ever matched by the bare `StructuredTool` MENTION;
    # `Tool.from_function` / `Tool(name=...)` had no coverage at all.
    for name, reg in (
        ("a.py", "T = Tool.from_function(func=lookup, name='lookup', description='d')\n"),
        ("b.py", "T = Tool(name='lookup', func=lookup, description='d')\n"),
        # Keyword ORDER is not part of the signature here either. The regex required `name=` to be
        # the literal leading token, so this spelling was a false negative; the AST check is
        # order-free. Pinned as the TP half of the constructor fix above -- that fix requires BOTH
        # `name=` and a callable `func=`/`fn=`, and this proves the requirement is a SET and not a
        # sequence.
        ("c.py", "T = Tool(func=lookup, name='lookup', description='d')\n"),
    ):
        (tmp_path / name).write_text(
            "from langchain_core.tools import Tool\n"
            "\n"
            "def lookup(q):\n"
            "    try:\n"
            "        return fetch(q)\n"
            "    except Exception as exc:\n"
            '        return {"ok": False, "error": str(exc)}\n'
            "\n" + reg,
            encoding="utf-8",
        )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert sorted(f.location.split(":")[0] for f in findings) == ["a.py", "b.py", "c.py"]


def test_llm_tool_result_leak_add_tool_mention_is_not_a_site_silent(tmp_path: Path) -> None:
    # FP-bait, the mistake the reverted import-level signals made: a MENTION of a registration
    # call in a comment, in a usage string, or in prose is not a registration SITE. Each of these
    # differs from the silent plain-helper control only by that mention.
    for i, mention in enumerate(
        (
            "# TODO: someday call mcp.add_tool(search) here\n",
            "USAGE = 'call mcp.add_tool(search) to register'\n",
            '"""Helpers. Later we will wire these up with Tool.from_function(fn)."""\n',
            "# build it with Tool(name='q', func=q)\n",
        )
    ):
        (tmp_path / f"m{i}.py").write_text(
            mention + "\n"
            "def load_config(path):\n"
            "    try:\n"
            "        return parse(path)\n"
            "    except Exception as exc:\n"
            '        return {"ok": False, "error": str(exc)}\n',
            encoding="utf-8",
        )
    assert _guard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_llm_tool_result_leak_non_llm_add_tool_api_silent(tmp_path: Path) -> None:
    # FP-bait: `add_tool` is not unique to MCP. matplotlib's ToolManager and a wx toolbar both
    # expose one, and both are called with a string/widget rather than a callable — that is what
    # separates a tool registration from a toolbar button.
    for i, reg in enumerate(
        (
            "fig.canvas.manager.toolmanager.add_tool('zoom', ZoomTool)\n",
            "toolbar.add_tool(icon, 'Zoom')\n",
            "toolbar.add_tool(wx.ID_ANY, 'Zoom', bmp)\n",
        )
    ):
        (tmp_path / f"ui{i}.py").write_text(
            reg + "\n"
            "def load_config(path):\n"
            "    try:\n"
            "        return parse(path)\n"
            "    except Exception as exc:\n"
            '        return {"ok": False, "error": str(exc)}\n',
            encoding="utf-8",
        )
    assert _guard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_llm_tool_result_leak_mcp_resource_and_prompt_out_of_scope_silent(tmp_path: Path) -> None:
    # SCOPE DECISION (see guard-design "Scope decision: MCP resources and prompts"): a
    # resources-only / prompts-only MCP server is NOT a tool surface. Resources and prompts are a
    # different MCP primitive, and this guard — `exception-in-tool-return`, checklist
    # `4-tool-result-no-raw-exception` — is scoped to tool results. Pinned so the scope is a
    # decision, not a silent loss; a server that also registers a tool is caught by that signal.
    for i, dec in enumerate(("@mcp.resource('cfg://app')\n", "@mcp.prompt()\n")):
        (tmp_path / f"r{i}.py").write_text(
            "from mcp.server.fastmcp import FastMCP\n"
            "\n"
            'mcp = FastMCP("demo")\n'
            "\n" + dec + "def handler(x):\n"
            "    try:\n"
            "        return render(x)\n"
            "    except Exception as exc:\n"
            '        return {"ok": False, "error": str(exc)}\n',
            encoding="utf-8",
        )
    assert _guard().run(tmp_path, _llm_prof(tmp_path)) == []


_LEAK_BODY = (
    "    try:\n        pass\n"
    "    except Exception as exc:\n"
    '        return {"ok": False, "error": str(exc)}\n'
)


def _reg(tmp_path: Path, head: str) -> int:
    (tmp_path / "ui.py").write_text(head + _LEAK_BODY, encoding="utf-8")
    return len(_guard().run(tmp_path, _llm_prof(tmp_path)))


@pytest.mark.parametrize(
    ("label", "head"),
    [
        # The #469 gate's CRITICAL, measured 0 -> 1. `add_tool` is not MCP's alone, and the
        # "requires a callable" guardrail accepted ANY identifier followed by ANY `,<kw>=` --
        # which is wx's normal signature, so it never enforced the property it named.
        ("wx bitmap kwarg", "import wx\ndef b(toolbar, icon):\n    toolbar.add_tool(wx.ID_ANY, bitmap=icon)\n"),
        ("wx shortHelp kwarg", "import wx\ndef b(toolbar):\n    toolbar.add_tool(TOOL_ID, shortHelp='Zoom')\n"),
        ("wx camelCase kwarg", "import wx\ndef b(tb, myBitmap):\n    tb.add_tool(myBitmap, label='x')\n"),
        ("wx positional string", "import wx\ndef b(toolbar, icon):\n    toolbar.add_tool(icon, 'Zoom')\n"),
        ("matplotlib toolmanager", "def b(tm):\n    tm.add_tool('zoom', ZoomTool)\n"),
        ("a comment, not a site", "def b(mcp, search):\n    # TODO: call mcp.add_tool(search)\n"),
        # ---- The trailing-comma WIDENING's traded-against direction (#469 gate finding 3). That
        # half of the previous commit shipped only TP tests, so the autoformatted spelling of every
        # FP above was unpinned. These three already held; they are pinned so a future widening
        # cannot quietly take them, the way the single-line ones were taken before.
        ("wx MULTILINE ID_ANY + bitmap kwarg",
         "import wx\ndef b(toolbar, icon):\n    toolbar.add_tool(\n        wx.ID_ANY,\n        bitmap=icon,\n    )\n"),
        ("wx MULTILINE lowercase id + label kwarg",
         "import wx\ndef b(toolbar, tool_id):\n    toolbar.add_tool(\n        tool_id,\n        label='Zoom',\n    )\n"),
        ("matplotlib MULTILINE",
         "def b(tm):\n    tm.add_tool(\n        'zoom',\n        ZoomTool,\n    )\n"),
        # ---- The LEADING-KEYWORD collision (#469 gate finding 5). The old branch accepted a bare
        # identifier before ANY `=`, so wx's own first keyword was a finding. Only the two names
        # the SDKs give their callable/tool parameter (`fn=` for mcp, `tool=` for fastmcp) are
        # admitted now -- and neither may match as a mere PREFIX of a longer keyword.
        ("wx bitmap= leading kwarg", "import wx\ndef b(toolbar, icon):\n    toolbar.add_tool(bitmap=icon)\n"),
        ("wx shortHelp= leading kwarg", "import wx\ndef b(toolbar):\n    toolbar.add_tool(shortHelp='Zoom')\n"),
        ("wx longHelp= leading kwarg", "import wx\ndef b(toolbar):\n    toolbar.add_tool(longHelp='Zoom out')\n"),
        ("wx clientData= leading kwarg", "import wx\ndef b(toolbar, d):\n    toolbar.add_tool(clientData=d)\n"),
        ("wx MULTILINE bitmap= leading kwarg",
         "import wx\ndef b(toolbar, icon):\n    toolbar.add_tool(\n        bitmap=icon,\n        label='Zoom',\n    )\n"),
        ("`tool` as a mere PREFIX: tool_id=", "def b(tb, x):\n    tb.add_tool(tool_id=x)\n"),
        ("`tool` as a mere PREFIX: toolbar=", "def b(tb, x):\n    tb.add_tool(toolbar=x)\n"),
        ("`fn` as a mere PREFIX: fn_name=", "def b(tb, x):\n    tb.add_tool(fn_name=x)\n"),
        # ---- The Tool-OBJECT branch must not read any constructor as a tool. It keys on an
        # identifier ENDING in `Tool` immediately before the `(`, so a widget constructor -- and
        # `Toolbar`/`ToolBar`/`Toolkit`, where `Tool` is only a prefix -- stay out.
        ("wx Bitmap() constructor first", "import wx\ndef b(tb):\n    tb.add_tool(Bitmap('x.png'), 'Zoom')\n"),
        ("MyToolbar() constructor first", "def b(tb):\n    tb.add_tool(MyToolbar('x'), 'Zoom')\n"),
        ("ToolBar() constructor first", "def b(tb):\n    tb.add_tool(ToolBar('x'), 'Zoom')\n"),
        # ---- The documented CamelCase trade: a BARE uncalled class is still not a registration.
        ("CamelCase bare class", "def b(mcp):\n    mcp.add_tool(SearchTool)\n"),
        ("CamelCase bare class + name=", "def b(mcp):\n    mcp.add_tool(SearchTool, name='x')\n"),
        # ---- mention-not-a-site, for the two NEW branches specifically
        ("a comment holding the Tool() form", "def b(mcp, f):\n    # mcp.add_tool(Tool(name='s'))\n"),
        ("a docstring holding the fn= form", 'def b(mcp, f):\n    """call mcp.add_tool(fn=f)"""\n'),
        ("not statement position", "def b(mcp, f):\n    x = [1, mcp.add_tool(fn=f)]\n"),
        # ---- EVERY keyword must be the SDK's, not merely SOME. The keyword-set rule replaced a
        # leading-keyword rule, and the way to get that wrong in the other direction is to accept a
        # call because ONE recognised name appears in it. wx's own signature takes `label`, so a
        # widget call carrying both is the discriminating case.
        ("SDK keyword mixed with a wx one",
         "import wx\ndef b(tb, i):\n    tb.add_tool(name='Zoom', bitmap=i)\n"),
        ("SDK keyword mixed with a wx one, fn= present",
         "import wx\ndef b(tb, i, f):\n    tb.add_tool(fn=f, bitmap=i)\n"),
        # ---- `**kwargs` carries unknown names, so it is not evidence of an SDK-shaped call.
        ("**kwargs splat", "def b(mcp, cfg):\n    mcp.add_tool(**cfg)\n"),
    ],
)
def test_llm_tool_result_leak_add_tool_is_not_mcps_alone(tmp_path: Path, label: str, head: str) -> None:
    assert _reg(tmp_path, head) == 0, label


@pytest.mark.parametrize(
    ("label", "head"),
    [
        # THE TRADED-AGAINST DIRECTION. Both tests NARROW what counts as a registration site, so
        # their risk is losing the FastMCP imperative registration this alternative exists to
        # cover -- the false negative that opening the whole `add_tool` question created.
        ("bare", "from mcp import FastMCP\ndef b(mcp, search):\n    mcp.add_tool(search)\n"),
        ("mcp kwarg", "from mcp import FastMCP\ndef b(mcp, search):\n    mcp.add_tool(search, name='x')\n"),
        ("dotted receiver and arg", "from mcp import FastMCP\ndef b(self, search):\n    self.mcp.add_tool(self.search)\n"),
        ("functools.partial", "import functools\ndef b(mcp, f):\n    mcp.add_tool(functools.partial(f, 1))\n"),
        # black / ruff-format add a trailing comma whenever the call wraps. This was silent.
        ("autoformatted, trailing comma",
         "from mcp import FastMCP\ndef b(mcp, search):\n    mcp.add_tool(\n        search,\n    )\n"),
        ("wrapped, no trailing comma",
         "from mcp import FastMCP\ndef b(mcp, search):\n    mcp.add_tool(\n        search\n    )\n"),
    ],
)
def test_llm_tool_result_leak_imperative_registration_still_fires(
    tmp_path: Path, label: str, head: str
) -> None:
    assert _reg(tmp_path, head) == 1, label


@pytest.mark.parametrize(
    ("label", "head"),
    [
        # EVERY KEYWORD THE MCP SDK ACTUALLY TAKES. The allow-list is the load-bearing
        # discriminator against wx/matplotlib, so it has to BE the SDK's -- an enumeration that is
        # merely plausible makes the discriminator arbitrary and loses coverage silently (#469
        # gate finding 1: `icons`/`meta`/`structured_output` were absent, five measured 1 -> 0).
        # Read from the published wheels: mcp 1.19.0 `mcp/server/fastmcp/server.py` and mcp 2.0.0
        # `mcp/server/mcpserver/server.py` (identical), and each version's `tools/tool_manager.py`:
        #   add_tool(fn, name=, title=, description=, annotations=, icons=, meta=,
        #            structured_output=)
        # If a future SDK adds a parameter, add it here AND to the guard's allow-list.
        ("kw name=", "def b(mcp, search):\n    mcp.add_tool(search, name='x')\n"),
        ("kw title=", "def b(mcp, search):\n    mcp.add_tool(search, title='Search')\n"),
        ("kw description=", "def b(mcp, search):\n    mcp.add_tool(search, description='d')\n"),
        ("kw annotations=", "def b(mcp, search, a):\n    mcp.add_tool(search, annotations=a)\n"),
        ("kw icons=", "def b(mcp, search, i):\n    mcp.add_tool(search, icons=[i])\n"),
        ("kw meta=", "def b(mcp, search):\n    mcp.add_tool(search, meta={'a': 1})\n"),
        ("kw structured_output=", "def b(mcp, search):\n    mcp.add_tool(search, structured_output=True)\n"),
        ("kw icons=, autoformatted",
         "def b(mcp, search, i):\n    mcp.add_tool(\n        search,\n        icons=[i],\n    )\n"),
        ("kw structured_output=, dotted receiver and arg",
         "def b(self):\n    self.mcp.add_tool(self.search, structured_output=True)\n"),
        # THE SDK'S OWN CALLABLE/TOOL PARAMETER AS A LEADING KEYWORD. `fn` is mcp's first
        # parameter name and `tool` is fastmcp's, so both are legal spellings; every OTHER leading
        # keyword is rejected by the FP block above.
        ("leading fn= (mcp)", "def b(mcp, search):\n    mcp.add_tool(fn=search)\n"),
        ("leading tool= (fastmcp)", "def b(mcp, t):\n    mcp.add_tool(tool=t)\n"),
        ("leading fn=, autoformatted", "def b(mcp, search):\n    mcp.add_tool(\n        fn=search,\n    )\n"),
        # KEYWORD ORDER IS NOT PART OF THE SIGNATURE (#469 re-gate finding 1). All eight of mcp's
        # parameters are positional-or-keyword, so Python accepts them in ANY order and every line
        # below is a legal first-party call. The previous rule admitted `fn=`/`tool=` only as the
        # LEADING keyword -- the SDK's first parameter NAME rather than its parameter SET -- so all
        # nine of these were measured 1 -> 0 silent false negatives. This is the third round of the
        # same failure (narrow an enumeration, lose coverage silently), and the reason the check is
        # now an AST pass: `call.keywords` is order-free, so this class cannot recur by ordering.
        ("name= before fn=", "def b(mcp, search):\n    mcp.add_tool(name='s', fn=search)\n"),
        ("description= before fn=", "def b(mcp, search):\n    mcp.add_tool(description='d', fn=search)\n"),
        ("title= before fn=", "def b(mcp, search):\n    mcp.add_tool(title='T', fn=search)\n"),
        ("annotations= before fn=", "def b(mcp, search, a):\n    mcp.add_tool(annotations=a, fn=search)\n"),
        ("icons= before fn=", "def b(mcp, search, i):\n    mcp.add_tool(icons=[i], fn=search)\n"),
        ("meta= before fn=", "def b(mcp, search):\n    mcp.add_tool(meta={'a': 1}, fn=search)\n"),
        ("structured_output= before fn=",
         "def b(mcp, search):\n    mcp.add_tool(structured_output=True, fn=search)\n"),
        ("name= before fn=, autoformatted",
         "def b(mcp, search):\n    mcp.add_tool(\n        name='s',\n        fn=search,\n    )\n"),
        ("name= before fn=, dotted receiver and arg",
         "def b(self):\n    self.mcp.add_tool(name='s', fn=self.search)\n"),
        # A TOOL OBJECT AS THE ARGUMENT. fastmcp 2.11.3 `fastmcp/server/server.py` is
        # `add_tool(self, tool: Tool) -> Tool` -- a Tool OBJECT, not a function -- and fastmcp
        # 3.4.5 (code ships as `fastmcp-slim`, same path) widened it to `Tool | Callable`. So
        # `add_tool(Tool(...))` is that API's primary spelling, not an out-of-scope shape (#469
        # gate finding 2). It previously fired only when black happened to wrap the call, so the
        # verdict turned on autoformatter width; both spellings are pinned here.
        ("Tool(name=) object", "def b(mcp, f):\n    mcp.add_tool(Tool(name='s', fn=f))\n"),
        ("Tool(fn=) object, kwargs the other way round", "def b(mcp, f):\n    mcp.add_tool(Tool(fn=f, name='s'))\n"),
        ("Tool() object, assignment form", "def b(mcp, f):\n    t = mcp.add_tool(Tool(name='s', fn=f))\n"),
        ("Tool() object, autoformatted",
         "def b(mcp, f):\n    mcp.add_tool(\n        Tool(\n            name='s',\n            fn=f,\n        ),\n    )\n"),
        ("a <X>Tool subclass object", "def b(mcp, f):\n    mcp.add_tool(SearchTool(name='s', fn=f))\n"),
        ("Tool.from_function as the argument", "def b(mcp, f):\n    mcp.add_tool(Tool.from_function(f))\n"),
    ],
)
def test_llm_tool_result_leak_add_tool_covers_every_sdk_spelling(
    tmp_path: Path, label: str, head: str
) -> None:
    # THE INVARIANT, TP half: every spelling the mcp / fastmcp `add_tool` signatures accept must
    # be recognised as a registration site. Resolved from the wheels, not from the guard's comment.
    assert _reg(tmp_path, head) == 1, label


@pytest.mark.parametrize(
    ("label", "head"),
    [
        # A single LOWERCASE POSITIONAL argument is textually identical in wx, matplotlib and mcp
        # (`toolbar.add_tool(icon)` vs `mcp.add_tool(search)`), so no regex can separate them and
        # closing it would cost the primary true positive this branch exists for.
        ("wx bare lowercase positional", "import wx\ndef b(toolbar, icon):\n    toolbar.add_tool(icon)\n"),
        ("wx bare lowercase positional, autoformatted",
         "import wx\ndef b(toolbar, icon):\n    toolbar.add_tool(\n        icon,\n    )\n"),
        ("wx bare lowercase positional, assigned",
         "import wx\ndef b(toolbar, icon):\n    t = toolbar.add_tool(\n        icon,\n    )\n"),
        ("matplotlib lowercase positional var", "def b(tm, zoom_tool):\n    tm.add_tool(\n        zoom_tool,\n    )\n"),
        # A lowercase CALL is the same family as a lowercase name, and the list previously said
        # "positional", which understates it (#469 re-gate finding 4c).
        ("lowercase call expression", "def b(tb):\n    tb.add_tool(load_bitmap('x'))\n"),
        # An SDK keyword alongside a lowercase positional, from ANY receiver. `meta=` was disclosed
        # only in a PR comment and reached neither the code nor the doc until now (finding 4a);
        # `name=`/`description=` were pre-existing and are pinned beside it as the same family.
        ("lowercase positional + meta=", "def b(tb, icon):\n    tb.add_tool(icon, meta={'a': 1})\n"),
        ("lowercase positional + name=", "def b(tb, icon):\n    tb.add_tool(icon, name='Zoom')\n"),
        # A `*Tool(...)` CONSTRUCTOR from any receiver. This is the half of finding 2 that stays
        # open: it is textually identical to fastmcp's primary spelling `add_tool(Tool(...))`, so a
        # non-LLM tool registry registering a `*Tool` object matches. The earlier claim that a
        # CamelCase first argument "stays out" generalised from three baits (`Bitmap`, `ToolBar`,
        # `MyToolbar`) in which `Tool` is a PREFIX or absent, and is false for the suffixed shape.
        ("*Tool() constructor, single arg", "def b(menu, canvas):\n    menu.add_tool(PaintTool(canvas))\n"),
        ("*Tool() constructor + name=",
         "def b(registry, cfg):\n    registry.add_tool(BuildTool(cfg), name='build')\n"),
        # `tool` is BOTH fastmcp's parameter and the FIRST parameter of matplotlib's
        # ToolContainerBase.add_tool (backend_bases.py:3478), so the bare one-keyword call is
        # genuinely ambiguous. Its 2- and 3-argument spellings ARE closed; see the test below.
        ("bare tool= keyword", "def b(container, t):\n    container.add_tool(tool=t)\n"),
    ],
)
def test_llm_tool_result_leak_add_tool_documented_residuals_still_fire(
    tmp_path: Path, label: str, head: str
) -> None:
    # HONESTY PIN, not an endorsement. "The wx/matplotlib add_tool collision is closed" was an
    # OVERSTATEMENT (#469 gate finding 3): what is closed is the collision for a dotted/constant/
    # CamelCase first argument and for a non-SDK keyword. These shapes remain ambiguous and still
    # fire from any library. They are pinned so the residual is a recorded decision rather than an
    # undiscovered surface, and so that narrowing it later is a deliberate, measured change.
    assert _reg(tmp_path, head) == 1, label


def test_llm_tool_result_leak_add_tool_docstring_code_example_now_silent(tmp_path: Path) -> None:
    # The other residual the AST move closes. A multi-line docstring whose OWN LINE is an indented
    # `mcp.add_tool(search)` satisfied the line-based `^[ \t]*` position anchor, so a documentation
    # example read as a registration site. The design doc recorded this as needing "a Python
    # comment/string stripper, which the guard base does not have" — a docstring is a string
    # constant rather than a call node, so an AST closes it without one.
    #
    # The control below is the same call at the same indentation OUTSIDE the docstring: it must
    # still fire, or this test would pass by breaking the signal rather than by scoping it.
    body = (
        "def setup(mcp):\n"
        '    """Register the tools.\n'
        "\n"
        "    Example:\n"
        "        mcp.add_tool(search)\n"
        '        mcp.add_tool(name="s", fn=search)\n'
        '    """\n'
        "    return None\n"
    )
    assert _reg(tmp_path, body) == 0
    assert _reg(tmp_path, "def setup(mcp):\n    mcp.add_tool(search)\n") == 1


@pytest.mark.parametrize(
    "label,head",
    [
        # matplotlib's ToolManager.add_tool(name, tool) names its second parameter `tool`, the same
        # name fastmcp gives its Tool argument, so no keyword-based rule can separate the two. What
        # separates them is the ARGUMENT: `ZoomTool` is an uncalled CamelCase class, and neither SDK
        # documents passing one.
        ("matplotlib tool= CamelCase class", "def b(tm):\n    tm.add_tool(tool=ZoomTool)\n"),
        ("matplotlib name= with no tool argument", "def b(tm):\n    tm.add_tool(name='zoom')\n"),
        # The half of #469 re-gate finding 2 the AST move closes: a `*Tool(...)` constructor with a
        # SECOND positional is a widget/registry call shape, not an SDK one. (The single-argument
        # form stays open and is pinned in the residuals test above.)
        ("*Tool() constructor + 2nd positional",
         "def b(tb):\n    tb.add_tool(BitmapTool('x.png'), 'Zoom')\n"),
        ("*Tool() constructor + 2nd positional, matplotlib",
         "def b(tm, fig):\n    tm.add_tool(ZoomTool(fig), 'zoom')\n"),
        ("lowercase call + 2nd positional", "def b(tb):\n    tb.add_tool(get_icon('x'), 'Zoom')\n"),
        # matplotlib ToolContainerBase.add_tool(tool, group, position) -- `group` is not an SDK
        # keyword, and a second positional is rejected, so only the bare `tool=` spelling survives.
        ("ToolContainerBase tool= with group=",
         "def b(container, t):\n    container.add_tool(tool=t, group='nav')\n"),
        ("ToolContainerBase two positionals", "def b(container, t):\n    container.add_tool(t, 'nav')\n"),
    ],
)
def test_llm_tool_result_leak_add_tool_ast_closed_residuals_now_silent(
    tmp_path: Path, label: str, head: str
) -> None:
    # THE DELIBERATE, MEASURED NARROWING the pin above invites. Every shape here previously fired
    # and was recorded as a residual; the AST pass closes them, because it can require the tool
    # ARGUMENT to denote a callable and can count positionals, rather than only inspecting keyword
    # names and their order.
    #
    # The first two matter beyond themselves: the keyword-set fix proposed for #469's finding 1
    # (widen branch B's alternation to the SDK's whole parameter set) would have made BOTH fire,
    # trading nine restored true positives for two new false positives. The AST route pays neither
    # half of that price, which is why it was taken instead.
    assert _reg(tmp_path, head) == 0, label


# --- the from_function receiver is a curated allowlist, not a suffix (#469 re-gate 3) -----------
# The branch accepted any receiver whose name ends in `Tool`, so an ordinary CI module's
# `BuildTool.from_function(...)` made the whole file an LLM-tool surface. Requiring a callable does
# NOT close it: the argument is `cfg.name`, an ast.Attribute, syntactically identical to a real
# dotted function reference like `mod.my_func`. `endswith` is unsound in principle here, because
# `BuildTool` and `FunctionTool` cannot be told apart by suffix.


@pytest.mark.parametrize(
    ("label", "head"),
    [
        ("dotted-attr arg", "T = BuildTool.from_function(cfg.name)\ndef run(x):\n"),
        ("dotted receiver", "import ci\nT = ci.BuildTool.from_function(cfg.name)\ndef run(x):\n"),
        ("string arg", "T = BuildTool.from_function('compile')\ndef run(x):\n"),
        ("extra positional", "T = BuildTool.from_function(cfg.target, 1)\ndef run(x):\n"),
        ("unlisted *Tool class", "T = MyCustomTool.from_function(fn)\ndef run(x):\n"),
    ],
)
def test_llm_tool_result_leak_from_function_receiver_not_in_allowlist_is_silent(
    tmp_path: Path, label: str, head: str
) -> None:
    assert _reg(tmp_path, head) == 0, label


@pytest.mark.parametrize(
    ("label", "head"),
    [
        ("langchain Tool", "from lc import Tool\nT = Tool.from_function(fn)\ndef run(x):\n"),
        (
            "langchain StructuredTool",
            "from lc import StructuredTool\nT = StructuredTool.from_function(fn)\ndef run(x):\n",
        ),
        ("FunctionTool", "from li import FunctionTool\nT = FunctionTool.from_function(fn)\ndef run(x):\n"),
        # `_final_name` takes the last dotted segment, so the fully-qualified import path real code
        # uses must still resolve to `Tool` and match. This is the direction the allowlist trades
        # against: too strict a receiver test would silence genuine registrations.
        (
            "fully-qualified",
            "import langchain_core.tools\nT = langchain_core.tools.Tool.from_function(fn)\ndef run(x):\n",
        ),
        ("lambda arg", "from lc import Tool\nT = Tool.from_function(lambda x: x)\ndef run(x):\n"),
    ],
)
def test_llm_tool_result_leak_from_function_allowlisted_receiver_still_fires(
    tmp_path: Path, label: str, head: str
) -> None:
    assert _reg(tmp_path, head) == 1, label


# --- one discriminator: the tool-class question is answered in exactly one place ----------------
# Every defect round on this guard was the same shape: a path decided "LLM-tool surface" on a
# `*Tool` SUFFIX, so an ordinary `BuildTool` in a CI module made every except-return a finding. It
# recurred because the question was answered independently in four places. These pin all of them at
# once, including the two that a suffix-based fix left open (the constructor's dotted `func=`, and
# the regex fallback that runs when a file will not parse).

_UNPARSEABLE = "def broken(:\n    pass\n"


@pytest.mark.parametrize(
    ("label", "head"),
    [
        # AST path, from_function form.
        ("from_function dotted arg", "T = BuildTool.from_function(cfg.name)\ndef run(x):\n"),
        ("from_function dotted receiver", "import ci\nT = ci.BuildTool.from_function(cfg.name)\ndef run(x):\n"),
        # AST path, CONSTRUCTOR form. `func=cfg.name` is an ast.Attribute, which the callable check
        # admits because it cannot be told from a real `mod.my_func`. The class name is the only
        # sound discriminator, so the constructor branch must consult the same allowlist.
        ("constructor dotted func=", "T = BuildTool(name='compile', func=cfg.name)\ndef run(x):\n"),
        ("constructor dotted fn=", "T = BuildTool(name='compile', fn=cfg.target)\ndef run(x):\n"),
    ],
)
def test_llm_tool_result_leak_non_tool_class_is_silent_on_parseable_files(
    tmp_path: Path, label: str, head: str
) -> None:
    assert _reg(tmp_path, head) == 0, label


@pytest.mark.parametrize(
    ("label", "head"),
    [
        ("fallback from_function", _UNPARSEABLE + "T = BuildTool.from_function(cfg.name)\ndef run(x):\n"),
        ("fallback constructor", _UNPARSEABLE + "T = BuildTool(name='x', func=cfg.name)\ndef run(x):\n"),
    ],
)
def test_llm_tool_result_leak_fallback_regex_agrees_with_the_ast_path(
    tmp_path: Path, label: str, head: str
) -> None:
    """A file that merely fails to parse must not reach a verdict the AST path declines. The
    fallback's class alternation is generated from `_TOOL_CLASSES`, so the two cannot drift."""
    assert _reg(tmp_path, head) == 0, label


@pytest.mark.parametrize(
    ("label", "head"),
    [
        ("real Tool constructor", "from lc import Tool\nT = Tool(name='s', func=search)\ndef run(x):\n"),
        (
            "real StructuredTool constructor",
            "from lc import StructuredTool\nT = StructuredTool(name='s', func=search)\ndef run(x):\n",
        ),
        ("real Tool from_function", "from lc import Tool\nT = Tool.from_function(search)\ndef run(x):\n"),
        (
            "fallback keeps real registrations",
            _UNPARSEABLE + "from lc import Tool\nT = Tool.from_function(search)\ndef run(x):\n",
        ),
    ],
)
def test_llm_tool_result_leak_allowlisted_tool_class_still_fires(
    tmp_path: Path, label: str, head: str
) -> None:
    """The direction traded against: naming the classes must not silence genuine registrations,
    on either the AST path or the fallback."""
    assert _reg(tmp_path, head) == 1, label


def test_llm_tool_result_leak_fallback_misses_a_fully_qualified_receiver(tmp_path: Path) -> None:
    """DOCUMENTED RESIDUAL, pinned so closing it is a deliberate act rather than an accident.

    The AST path resolves a dotted receiver through `_final_name`, so
    `langchain_core.tools.Tool.from_function(fn)` is detected on a parseable file. The fallback's
    generated alternation has no provision for a dotted prefix, so on an UNPARSEABLE file the same
    spelling is missed. Needs an unparseable file AND a fully-qualified receiver.

    If a change makes this fire, that is the residual being closed and this test should be inverted,
    not deleted. The design doc's "Known residual" paragraph is the prose half of this assertion, and
    an earlier version of it overstated the coverage -- which is why the claim is now executable.
    """
    qualified = "import langchain_core.tools\nT = langchain_core.tools.Tool.from_function(fn)\ndef run(x):\n"
    # Parseable: the AST path resolves the dotted receiver and fires.
    assert _reg(tmp_path, qualified) == 1
    # Unparseable: the fallback runs instead, and misses it.
    assert _reg(tmp_path, _UNPARSEABLE + qualified) == 0
    # Control: the bare receiver is caught on BOTH paths, so the gap is the dotted prefix
    # specifically and not the fallback being broken in general.
    bare = "from lc import Tool\nT = Tool.from_function(fn)\ndef run(x):\n"
    assert _reg(tmp_path, bare) == 1
    assert _reg(tmp_path, _UNPARSEABLE + bare) == 1
