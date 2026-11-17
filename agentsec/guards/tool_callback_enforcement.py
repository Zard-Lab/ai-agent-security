"""Guard: LLM agent or tool missing confirmation callback for dangerous operations.

An agentic workflow that can delete records, drop tables, or purge files without any
human-in-the-loop confirmation gives a prompt-injection attacker a direct path to
irreversible data loss (OWASP-LLM:LLM06 Excessive Agency). Tool functions that *return*
credentials read from the environment leak them to any caller (OWASP-LLM:LLM02 Sensitive
Information Disclosure).

Five statically detectable patterns:

  1. **`no-interrupt-before`** (MEDIUM): An `AgentExecutor(...)` (or
     `AgentExecutor.from_agent_and_tools(...)`) call with no interception hook in its
     first ~600 chars — none of `callbacks` (the classic LangChain mechanism),
     `interrupt_before` / `checkpoint` (LangGraph), `before_tool_call`,
     `human_in_the_loop`, or `require_confirm`. MEDIUM (informational): presence of a
     human-in-the-loop gate cannot be statically proven, and the classic `AgentExecutor`
     does not accept the LangGraph kwargs — so this is a nudge to confirm a gate exists,
     not a hard finding. Loop/limit concerns are covered by `agent-loop-circuit-breaker`.
     a call built from a `**kwargs`-unpacked dict (`AgentExecutor(**config)`) carries
     no literal parameter names for the ~600-char scan to see, which used to always flag it even
     when `config` genuinely sets `callbacks=`. The guard now tries to resolve `config`'s own
     dict/`dict(...)` literal in the enclosing function (`enclosing_function_span()`) and checks
     it for a confirm-signal key; when the source can't be resolved at all (a parameter, an
     import, a dict assembled elsewhere), it stays silent rather than guess — the same
     FN-biased default this rule already documents for the absence case in general.

  2. **`destructive-tool-no-confirm`** (HIGH): A `@tool` / `@<agent>.tool`-decorated
     function whose body performs a destructive operation against a real target — a SQL
     `DELETE FROM` / `DROP TABLE…` / `TRUNCATE`, an ORM `session/db/query.delete(...)` /
     `destroy_all(...)`, or a filesystem delete (`os.remove/unlink/rmdir`,
     `shutil.rmtree`) — and contains no confirmation pattern (confirm, approve, "are you
     sure", hitl, human_review, require_approval, double_check). The bare verb alone does
     NOT fire (so `df.drop(columns=...)`, `list.remove(x)`, `cache.delete(k)` stay silent).

  3. **`tool-credential-env-access`** (MEDIUM): A `@tool` function that **returns** a
     credential-like environment variable (API_KEY, SECRET, PASSWORD, TOKEN, CREDENTIAL)
     read via `os.environ` / `os.getenv` — directly or via a returned variable. A
     credential merely *consumed* inside the tool (e.g. `OpenAI(api_key=os.getenv(...))`)
     does NOT fire; only one that leaves the tool as output does.

  4. **`explicit-approval-disabled`** (HIGH): A literal keyword-argument assignment that
     explicitly *disables* a framework's default approval/confirmation gate —
     `auto_approve=True`, `human_in_the_loop=False`, or `confirm_before_action=False`.
     This is a PRESENCE-based signal, complementary to rule 1's ABSENCE-based one: rule 1
     fires when no confirmation mechanism was ever wired up (possibly just not built yet);
     this rule fires when someone deliberately turned OFF a safety mechanism the framework
     had ON by default — a stronger, more precise signal of intent. Adapted from
     `llmarmor/llmarmor`'s LLM08 (Excessive Agency) static rule
     (`src/llmarmor/rules/llm08_excessive_agency.py`). Does NOT re-detect
     `allow_dangerous_requests=True` — that flag (RequestsToolkit / PlaywrightBrowserToolkit
     network-access bypass) is already covered by `agent-tool-overpermission`'s
     `allow-dangerous-requests` rule.

  5. **`trust-config-wildcard-bypass`** (HIGH, added 2026-08-04 batch, mined from
     `agent-threat-rules`): An IDE/agent settings file (`.vscode/settings.json`,
     `.cursor/settings.json`, `.claude/settings.json`, etc.) sets a blanket auto-approval
     key — `trustedCommands`/`allowedCommands` to a wildcard, `autoApprove` to `true`/`*`,
     `requireApproval`/`requireConfirmation` to `false`, `skipConfirmation` to `true`, or
     `autonomyMode` to `"full"`. The config-file variant of rule 4: same removed-safety-gate
     intent, different surface (a settings file an indirect prompt injection can instruct the
     agent to WRITE, rather than a kwarg a developer writes). Mined from AWS Security Bulletin
     AWS-2025-019 (Amazon Q Developer / Kiro IDE — Embrace The Red's "Arbitrary Code Execution
     via Indirect Prompt Injection" research).

**Relationship to other guards:**
  * `agent-loop-circuit-breaker`: AgentExecutor max_iterations/max_execution_time limits.
  * `agent-tool-overpermission`: PythonREPLTool/ShellTool/subprocess in @tool.
  * `plugin-security`: @tool auth/validation/overexposure. This guard adds the
    confirmation-gate and credential-leak vectors.

**Suppress:** `# security: allow-tool-callback` anywhere in the file (per-file).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    enclosing_function_span,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    split_call_args,
)

_PRAGMA = "security: allow-tool-callback"

# Per-rule standards.
# TC001 / TC004 / Rule 4 (explicit-approval-disabled) all carry OWASP-ASI:ASI02 (Tool Misuse &
# Exploitation, OWASP Top 10 for Agentic Applications 2026): a tool call — including a destructive
# one — that runs with no confirmation gate, or an approval gate explicitly turned off, is a
# legitimate tool bent toward an illegitimate outcome via unsafe chaining. See
# wiki/research/owasp-asi-2026.md.
_STD_AGENCY = ["OWASP-LLM:LLM06", "OWASP:A01", "OWASP-ASI:ASI02"]  # TC001/TC004/Rule 4: excessive agency / missing gate
_STD_CRED = ["OWASP-LLM:LLM02", "OWASP:A01"]    # EXA004: sensitive information disclosure
_STD_TRUST_CONFIG = ["OWASP-LLM:LLM06", "OWASP:A01"]  # Rule 5: config-file approval-gate bypass

# --- Rule 5 (trust-config-wildcard-bypass) — IDE/agent config file, not Python source -----
#
# A config-file variant of Rule 4: instead of a Python kwarg turning a framework's approval
# gate off, an IDE/agent settings file grants blanket auto-approval directly. Mined from AWS
# Security Bulletin AWS-2025-019 (Amazon Q Developer / Kiro IDE plugins) — indirect prompt
# injection embedded in project source instructed Kiro to add
# `"kiroAgent.trustedCommands": ["*"]` to `.vscode/settings.json`, permanently removing the
# human-in-the-loop gate for every future command in that workspace.
_TRUST_CONFIG_DIRS = (".vscode", ".cursor", ".windsurf", ".continue", ".claude", ".gemini", ".kiro")
_TRUST_CONFIG_NAME = "settings.json"

_TRUST_BYPASS_PATTERNS = (
    (
        re.compile(r"\b(?:trustedCommands|allowedCommands)\b[\s\S]{0,6}[:=][\s\S]{0,6}\*"),
        "trustedCommands/allowedCommands",
    ),
    (
        re.compile(r"\bautoApprove\b[\s\S]{0,6}[:=][\s\S]{0,6}(?:\*|true\b)", re.IGNORECASE),
        "autoApprove",
    ),
    (
        re.compile(r"\b(?:requireApproval|requireConfirmation)\b[\s\S]{0,6}[:=][\s\S]{0,6}false\b",
                   re.IGNORECASE),
        "requireApproval/requireConfirmation",
    ),
    (
        re.compile(r"\bskipConfirmation\b[\s\S]{0,6}[:=][\s\S]{0,6}true\b", re.IGNORECASE),
        "skipConfirmation",
    ),
    (
        re.compile(r"\bautonomyMode\b[\s\S]{0,10}[:=][\s\S]{0,10}full\b", re.IGNORECASE),
        "autonomyMode",
    ),
)

# --- Rule 1 patterns (TC001) -------------------------------------------------

# AgentExecutor(...) or AgentExecutor.from_agent_and_tools(...) — just the opener; the
# arg window is examined from the match start so nested parens don't truncate the search.
_AGENT_EXECUTOR = re.compile(
    r"AgentExecutor(?:\.from_agent_and_tools)?\s*\(",
    re.IGNORECASE,
)
_AGENT_EXECUTOR_WINDOW = 600

# Interception / confirmation signals that make the call safe. `callbacks` is the classic
# LangChain mechanism; the rest are LangGraph / framework-specific.
_CONFIRM_PARAM = re.compile(
    r"interrupt_before|before_tool_call|checkpoint|human_in_the_loop|require_confirm|callbacks",
    re.IGNORECASE,
)

# A bare `**name` kwargs-unpack argument (`**config`, `** cfg`) — as opposed to `**{...}` (an
# inline dict literal, which is already visible to the plain `_CONFIRM_PARAM` window scan) or an
# ordinary `key=value` keyword argument.
_KWARGS_UNPACK_ARG = re.compile(r"^\s*\*\*\s*([A-Za-z_]\w*)\s*$")

# A simple dict-literal / dict(...) assignment: `config = {`, `config: dict = {`, `config = dict(`.
_DICT_ASSIGN = re.compile(
    r"^[ \t]*([A-Za-z_]\w*)\s*(?::[^=\n]*)?=\s*(\{|dict\s*\()", re.IGNORECASE | re.MULTILINE
)


def _kwargs_unpack_names(args: list[str]) -> list[str]:
    """The variable names of every bare `**name` argument in a split argument list."""
    names: list[str] = []
    for a in args:
        m = _KWARGS_UNPACK_ARG.match(a)
        if m:
            names.append(m.group(1))
    return names


def _balanced_bracket_end(text: str, open_idx: int) -> int | None:
    """Index just past the bracket that closes the ``(``/``{``/``[`` opened at `open_idx`.

    Quote-aware (a bracket inside a string literal doesn't count), like `split_call_args`, but
    generalised to `{}`/`[]` for a dict-literal body rather than only a call's `()`. Returns
    ``None`` on unbalanced input rather than guessing."""
    open_ch = text[open_idx]
    close_ch = {"(": ")", "{": "}", "[": "]"}.get(open_ch)
    if close_ch is None:
        return None
    depth = 0
    i, n = open_idx, len(text)
    quote = ""
    while i < n:
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"":
            quote = ch
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def _resolve_kwargs_confirm_signal(
    text: str, call_start: int, var_names: list[str], funcs: list[tuple[int, str]]
) -> bool | None:
    """Whether a `**kwargs`-unpacked `AgentExecutor(...)` call carries a confirm-signal key.

    For each unpacked variable, looks for its OWN `{...}`/`dict(...)` literal assignment in the
    enclosing function, above the call (`enclosing_function_span()`), and searches the
    resolved literal for a `_CONFIRM_PARAM` key. Returns ``True`` if at least one resolved dict
    carries a confirm signal, ``False`` if every named variable resolved and NONE did, or
    ``None`` if any variable's source could not be located at all — the deliberately FN-biased
    default (a dict assembled from a parameter, an import, or another module, none of which this
    guard can see) rather than risk flagging a call that IS actually gated."""
    call_lineno = text[:call_start].count("\n") + 1
    span = enclosing_function_span(text, call_lineno, functions=funcs)
    scope_start_offset = 0
    if span is not None:
        for ln in text.splitlines(keepends=True)[: span[0] - 1]:
            scope_start_offset += len(ln)
    found_confirm_key = False
    for var in var_names:
        dict_text: str | None = None
        for dm in _DICT_ASSIGN.finditer(text, scope_start_offset, call_start):
            if dm.group(1) != var:
                continue
            open_idx = dm.end() - 1  # the `{` or the `(` of `dict(` just matched
            end = _balanced_bracket_end(text, open_idx)
            if end is not None:
                dict_text = text[open_idx:end]  # keep the LAST (most recent) assignment
        if dict_text is None:
            return None
        if _CONFIRM_PARAM.search(dict_text):
            found_confirm_key = True
    return found_confirm_key


# --- Rule 2 patterns (TC004) -------------------------------------------------

# @tool / @<name...>.tool decorator (allows args and dotted prefixes: @tool, @tool(...),
# @agent.tool, @app.agent.tool).
_TOOL_DECORATOR = re.compile(r"^[^\S\n]*@(?:\w+\.)*tool\b", re.IGNORECASE | re.MULTILINE)

# Destructive operation bound to a real DB / ORM / filesystem target (not the bare verb).
_DESTRUCTIVE_OP = re.compile(
    r"\bDELETE\s+FROM\b"
    r"|\bDROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|COLLECTION)\b"
    r"|\bTRUNCATE\b"
    r"|\bos\.(?:remove|unlink|rmdir)\s*\("
    r"|\bshutil\.rmtree\s*\("
    r"|\b(?:session|db|conn|cursor|query|objects)\.delete\s*\("
    r"|\bdestroy_all\s*\(",
    re.IGNORECASE,
)

# Confirmation patterns that make the destructive pattern safe.
_CONFIRM_PATTERN = re.compile(
    r"\bconfirm(?:ed|ation)?\b|"
    r"\bapprove[d]?\b|"
    r"are you sure|"
    r"\bhitl\b|"
    r"\bhuman_review\b|"
    r"\brequire_approval\b|"
    r"\bdouble_check\b",
    re.IGNORECASE,
)

# --- Rule 3 patterns (EXA004) ------------------------------------------------

# ENV access for credential-like names via os.environ[...] / os.environ.get(...) / os.getenv(...).
_CRED_ENV_ACCESS = re.compile(
    r"os\.(?:environ(?:\.get)?|getenv)\s*[\[(]\s*['\"][^'\"]*"
    r"(?:api_key|secret|password|token|credential)[^'\"]*['\"]",
    re.IGNORECASE,
)
_ASSIGN_LHS = re.compile(r"^\s*([A-Za-z_]\w*)\s*=")

# The `def` / `async def` header line that ends a block's own decorator stack.
_DEF_HEADER = re.compile(r"^\s*(?:async\s+)?def\s")


def _tool_decorated_defs(text: str, *, filename: str | Path = "<unknown>") -> frozenset[int] | None:
    """Line numbers of `def`s whose OWN decorator stack contains an `@tool`, straight from the AST.

    This replaces a hand-rolled lexical scan of the block text, which was wrong three different
    ways in three consecutive rounds of #452: it read a backslash in a `#` comment as a line
    continuation, then read a `#` inside a continued string as a comment, then got the quote parity
    wrong on the line that CLOSES a continued string. Each spelling closed the reported shape and
    opened an adjacent one, because deciding "where does this decorator stack end?" from physical
    lines is tokenizing by hand.

    `ast` already did that work. `node.decorator_list` belongs to exactly one function, so the
    question the guard actually asks — "is THIS block a tool, or an enclosing factory that merely
    registers one?" — is answered structurally, with no continuation logic at all.

    Returns None when the module does not parse, which is the caller's signal to fall back to the
    text scan (`iter_functions` degrades the same way, for the same files).
    """
    tree = safe_ast_parse(text, filename=filename)
    if tree is None:
        return None
    out: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if any(_decorator_is_tool(d) for d in node.decorator_list):
            out.add(node.lineno)
    return frozenset(out)


def _decorator_is_tool(dec: ast.expr) -> bool:
    r"""Whether one decorator expression is an `@tool` in any of its spellings.

    Covers what `_TOOL_DECORATOR` (`^\s*@(?:\w+\.)*tool\b`) covered: `@tool`, `@tool(...)`,
    `@agent.tool`, `@app.agent.tool`, `@mcp.tool()`. The final attribute is what names the
    decorator, so a `@register("@app.post")` that merely QUOTES one cannot match: the AST sees a
    string argument, not a name.

    It is deliberately NOT an exact mirror, and the divergences were measured rather than assumed
    (#452 round 4). Wider than the regex, all of them genuine tool decorators the text scan missed:
    `@get_registry().tool`, `@buttons[0].tool`, `@(agent).tool`, and `@ tool` (a legal space after
    the `@`). Narrower in two, both of which the regex got wrong: `@a.b.tool[0]` is a subscript,
    not a call, and `@tool.setter` is a property setter on an object named `tool`, not a tool.
    """
    if isinstance(dec, ast.Call):
        dec = dec.func
    if isinstance(dec, ast.Attribute):
        return dec.attr.lower() == "tool"
    if isinstance(dec, ast.Name):
        return dec.id.lower() == "tool"
    return False


def _is_tool_block(def_line: int, block: str, tool_defs: frozenset[int] | None) -> bool:
    """Whether an `iter_functions` block is itself `@tool`-decorated.

    `tool_defs` is `_tool_decorated_defs`' answer for the whole module, so the common path is a set
    membership test on `node.lineno` — the same line number `iter_functions` reports. Only an
    unparseable module falls through to the text scan.
    """
    if tool_defs is not None:
        return def_line in tool_defs
    return bool(_TOOL_DECORATOR.search(_own_header(block)))


def _own_header(block: str) -> str:
    """An `iter_functions` block's own decorator stack, up to and including its `def` line.

    FALLBACK ONLY: used when the module does not parse, so `_tool_decorated_defs` cannot answer.
    On the AST path this is not called at all.

    `iter_functions` emits a nested `def` as its own block **and** used to leave it inside the
    enclosing function's block, so a factory that registers an `@tool` had that `@tool` line in its
    own block text. Matching `_TOOL_DECORATOR` against the whole block therefore promoted the
    FACTORY to a "@tool function": ordinary setup code in the factory body fired as if it were the
    tool's, and on a real finding the sorted output returned the factory first, anchoring a HIGH on
    a `def` carrying no decorator at all (#452 review). Since #502, `iter_functions` blanks a nested
    registration-decorated `def` out of its enclosing block, which covers the common shape. This
    helper still decides the shapes that blanking misses: a decorated nested CLASS (blanking covers
    `def`s only), and a module whose parse failure leaves a bracket open above the factory, where
    the line walker loses scope and never records the nested `def` as nested (#1066).

    Deliberately simple, because the elaborate version is what kept breaking: the header ends at
    the first `def` **at the block's own base indentation**. The indentation test belongs on the
    `def`, not on an early break: breaking at the first more-indented line instead truncated the
    header at any decorator whose ARGUMENTS span lines, so an ordinary

        @retry(
            attempts=3,
        )
        @tool
        def delete_user(uid: str) -> str: conn.execute("DELETE FROM users")

    lost the `@tool` and the destructive tool with it, silently (#452 round 4). (The parameter is
    annotated because `plugin-security` reads this docstring as a real unvalidated tool otherwise,
    which is our own guard working correctly on our own source.)

    Known residuals on this path: a backslash-continued string inside a decorator argument whose
    continuation line begins `def `, and any `def`-looking line at base indentation inside a
    string. Both need an unparseable module AND the shape; the real fix for either is to make the
    file parse. `test_tool_callback_fallback_*` reach this function through the guard on
    unparseable fixtures, because at one point every test that named it used a PARSEABLE fixture,
    so they all took the AST path and the helper could be replaced with `return block` —
    reinstating the factory-promotion bug — with the full suite still green (#452 round 4). The
    fixture added then went vacuous again after #502's blanking (#1066), so
    `test_tool_callback_fallback_fixture_makes_own_header_load_bearing` now pins that each fixture's
    factory block carries a `@tool` line only this helper scopes out.
    """
    lines = block.splitlines()
    if not lines:
        return ""
    base = len(lines[0]) - len(lines[0].lstrip())
    out: list[str] = []
    for line in lines:
        out.append(line)
        if _DEF_HEADER.match(line) and (len(line) - len(line.lstrip())) <= base:
            break
    return "\n".join(out)


# --- Rule 4 (explicit-approval-disabled) — AST-based -------------------------

# The disable-kwargs: kwarg name -> the dangerous literal value it must equal (auto_approve=True /
# human_in_the_loop=False / confirm_before_action=False). Deliberately excludes
# `allow_dangerous_requests=True`: that flag is `agent-tool-overpermission`'s `allow-dangerous-requests`
# rule (RequestsToolkit / PlaywrightBrowserToolkit bypass).
_DISABLE_KWARGS: dict[str, bool] = {
    "auto_approve": True,
    "human_in_the_loop": False,
    "confirm_before_action": False,
}


def _is_disabling_value(value: object, disabling: bool) -> bool:
    """Whether a literal kwarg value means the approval gate is OFF.

    Compared by TRUTHINESS, not identity. An `is True` / `is False` check matched only the
    bool singletons, so `auto_approve=1` and `human_in_the_loop=None` — both perfectly ordinary
    spellings, and both disabling — slipped through (#454 review). A non-bool, non-int, non-None
    literal (a string, a list) is not a recognisable on/off value and is left alone."""
    if value is None:
        return disabling is False          # `human_in_the_loop=None` is not "in the loop"
    if isinstance(value, bool):
        return value is disabling
    if isinstance(value, int):             # 1/0 spellings of the same switch
        return bool(value) is disabling
    return False


# The agent/LLM-orchestration frameworks whose constructors carry those kwargs. The gate
# (#451/#454 review) is AST-based: the disable-kwarg must be passed to a CALL whose function is
# BOUND from one of these frameworks (an import, not a name coincidence). Detecting the actual call
# target on the parse tree — instead of matching text — is what makes this precise: a framework name
# in a comment/string, a plain `class Agent` business object, a `dict(auto_approve=True)` CI flag,
# `auto_approve=flag` (a variable, not a literal), and compound framework class names (AutoGen's
# `ConversableAgent`, Semantic Kernel's `ChatCompletionAgent`) are all handled correctly.
# `anthropic` is intentionally absent: its tool-use is API-parameter driven, not a constructor
# disable-kwarg, so it does not fit this rule's shape.
#
# ---------------------------------------------------------------------------------------------
# INVARIANT: a module is an agent-framework module IFF its top-level import name is EXACTLY a
# member of this set, or it is a dotted submodule of one. Membership is by IDENTITY against a
# closed enumeration — never by constructing a name from a prefix plus an arbitrary suffix.
# ---------------------------------------------------------------------------------------------
#
# Why identity, not prefix construction: an open-ended `<framework>_<anything>` rule tries to
# approximate a FINITE set of published distributions with an INFINITE set of strings, so every
# in-house module named after the framework it wraps became a HIGH. `langchain_helpers`,
# `haystack_utils`, `crewai_internal`, `langgraph_config` and — worst — `autogen_migrations`
# (`autogen` is the standard Alembic/Django term, `alembic revision --autogenerate`) all fired.
# Excluding one prefix from that rule (`agents`, #454 re-review) fixed one reported instance and
# left the identical flaw in the six prefixes it kept. Enumeration removes the flaw by construction:
# a name that is not in the set cannot match, whatever it is spelled like.
#
# THE INVARIANT IS ONLY HALF THE CONTRACT (#454 gate, 2026-08-03). It fixes HOW membership is
# tested; it says nothing about WHAT the set must contain. Identity matching cannot make an absent
# name match, so every completeness bug lives in the unguarded half and no test of `_is_agent_module`
# can catch one. The other half is the entry criterion below plus a FORWARD audit against the real
# published namespace — the direction that keeps being skipped, twice now: the set was built by
# checking that each cited name EXISTS (`llama_index_client` does not) and never by asking which
# published siblings exist that the set is missing.
#
# ENTRY CRITERION (how the set is bounded): a real, verified TOP-LEVEL IMPORT NAME (not the PyPI
# distribution name — they differ) of a FIRST-PARTY package that exports an agent/executor
# constructor. All three clauses are load-bearing:
#   * top-level — a distribution that installs INTO a listed namespace (`langgraph-prebuilt` ->
#     `langgraph.prebuilt`) is already covered by the dotted rule and needs no entry;
#   * first-party TO A FRAMEWORK THIS SET ALREADY COVERS — published by the same org as a listed
#     root, verified from the wheel's METADATA/repo URL. The test is PROVENANCE, never the name,
#     and it cuts both ways: `deepagents` is langchain-ai's own package and shares no prefix with
#     any root, while anyone may publish `langgraph-<word>` (144 such distributions were on PyPI
#     on 2026-08-04 and all but a handful are third-party; the 152/153 this line carried before was
#     the `langgraph*` count, which also matches `langgraph`, `langgraph_agents`, `langgraphics`
#     and the underscore-form checkpointers, so it did not measure the claim it was supporting).
#     A framework that is first-party only
#     to ITSELF (`agno`, `atomic-agents`, `llama_deploy`) is a different framework, not a sibling
#     — it is the separate cross-framework FN below, and adding one is a scope decision, not an
#     application of this criterion;
#   * exports an agent constructor — a guardrail/toolset/CLI/runtime side-package does not qualify
#     even when it is first-party (`pydantic_ai_harness` exports `InputGuardrail`/`CodeMode`/
#     `Shell` and no agent; `langgraph_cli`, `langgraph_api`, `langgraph_executor` are plumbing).
# Provider/integration side-packages are deliberately OUT: `langchain_openai`, `langchain_anthropic`,
# `langchain_aws`, `langchain_google_genai` and the rest of the partner fleet export models and
# embeddings (`ChatOpenAI`), never an agent with an approval kwarg, and there are hundreds of them —
# enumerating them is neither possible nor useful. Missing one is a false NEGATIVE on this rule only
# (rules 1-3 still scan the file), which is far cheaper than a HIGH false positive on first-party
# code. Every ADDITION costs exact-name collision surface (see the design doc's residual-FP bullet),
# so the criterion is applied as a gate, not as a wish list.
#
# HOW THE FORWARD AUDIT IS RUN (repeat it when re-auditing; the procedure, not the result, is what
# has to be reproducible): pull the full PyPI simple index, filter to the covered framework prefixes,
# resolve each survivor's real top-level import name and provenance FROM ITS WHEEL, then apply the
# clauses above. Last run 2026-08-03: 863,251 distributions -> 2,755 prefix matches -> 650 wheels
# read. It found five first-party siblings the set was missing (added below) and confirmed every
# other prefix match fails a clause.
#
# THE PREFIX FILTER IS THE SEARCH STRATEGY, NOT A CLAUSE (#454 re-gate). It is how the candidate
# pool is made tractable out of ~863k distributions; it is not part of the entry criterion, and it
# systematically UNDER-SELECTS — a first-party package whose name happens not to start with a
# covered root never enters the pool to be judged at all. That is not hypothetical: it is exactly
# how `deepagents` (langchain-ai's own, `create_deep_agent`) was missed by two consecutive audits
# that each described themselves as forward. So step 2 is prefix-filter FOR THE BULK, then walk
# each covered org's own published package list directly — a name-shaped search cannot find a
# name-shaped blind spot, and reporting a prefix sweep as if it enumerated the criterion's extent
# is the defect this comment exists to stop repeating.
#
# What the audit still does NOT cover, so this comment is not read as a completeness proof: agent
# frameworks first-party to no framework in this set (`llama_deploy`, `agno`, `atomic-agents`) —
# the separate cross-framework FN documented in the design doc, not a sibling gap.
_AGENT_MODULE_ROOTS: frozenset[str] = frozenset({
    # LangChain: `langchain` + the 0.2+ core lines. Verified top-level names. `langchain_classic`
    # (`langchain-classic` v1.0.8, Repository: github.com/langchain-ai/langchain) is LangChain 1.0's
    # own home for the legacy agent stack — the wheel has `agents/agent.py:1012 class AgentExecutor`,
    # `agents/initialize.py:24 def initialize_agent` and `agents/react/agent.py:16 def
    # create_react_agent`, i.e. the exact constructs Rule 1's regex is built around. Top-level, so
    # the dotted rule provably does not reach it.
    "langchain", "langchain_core", "langchain_community", "langchain_experimental",
    "langchain_classic",
    # LangGraph. NOTE: `langgraph-checkpoint` / `langgraph-prebuilt` install INTO the `langgraph`
    # namespace (`langgraph.checkpoint`, `langgraph.prebuilt`) — there is no top-level
    # `langgraph_checkpoint`, so the dotted rule already covers them. `langgraph_sdk` is real.
    # The rest are separate langchain-ai distributions that DO install top-level, so the dotted rule
    # does not reach them; each name below was read out of the wheel, not guessed from the dist name:
    #   langgraph-supervisor v0.0.31 -> `langgraph_supervisor`, `supervisor.py:211 create_supervisor`
    #   langgraph-swarm      v0.1.0  -> `langgraph_swarm`, `swarm.py:170 def create_swarm`
    #                                   (the public surface is `create_swarm` / `SwarmState` /
    #                                   `create_handoff_tool` / `add_active_agent_router`; there is
    #                                   NO `Swarm` class — an earlier revision of this comment cited
    #                                   one that does not exist)
    #   langgraph-bigtool   v0.0.3  -> `langgraph_bigtool`, `graph.py:45 def create_agent`
    #   langgraph-codeact   v0.1.3  -> `langgraph_codeact`, `__init__.py:55 def create_codeact`
    #   langgraph-cua       v0.0.1  -> `langgraph_cua`, `graph.py:76 def create_cua`
    #   langgraph-reflection v0.0.1 -> `langgraph_reflection`, `__init__.py:24 def
    #                                   create_reflection_graph`
    # Provenance (all github.com/langchain-ai): supervisor -> langgraph-supervisor-py (project URL);
    # swarm/bigtool -> langchain-ai links in the wheel METADATA; codeact -> maintainer
    # nuno@langchain.dev; cua -> METADATA cites langchain-ai/langgraph-cua.git (repo now
    # langchain-ai/langgraph-cua-py); reflection -> author Harrison Chase, repo
    # langchain-ai/langgraph-reflection.
    # `langgraph_reflection` is the WEAKEST entry in this block and is not peer to `create_cua`
    # (#454 re-gate): its upstream repo is ARCHIVED (last push 2025-03-18) and its wheel METADATA
    # carries no langchain-ai URL at all — the provenance is the author string alone. It stays
    # because abandoned upstream does not mean absent downstream (old code still imports dead
    # packages, and this rule reads what a repo imports), but a future narrowing should reconsider
    # this one first, not last.
    "langgraph", "langgraph_sdk", "langgraph_supervisor", "langgraph_swarm",
    "langgraph_bigtool", "langgraph_codeact", "langgraph_cua", "langgraph_reflection",
    # CrewAI.
    "crewai", "crewai_tools",
    # AutoGen: legacy 0.2 (`autogen`) + the 0.4+ split distributions.
    "autogen", "autogen_core", "autogen_agentchat", "autogen_ext",
    # Haystack 2: `haystack-ai` installs top-level `haystack`; every `*-haystack` integration
    # installs into the `haystack_integrations` namespace package. `haystack-experimental` is
    # deepset's own second distribution, top-level, and ships an `Agent` with a human-in-the-loop
    # confirmation strategy — the same `_experimental` convention already listed for LangChain.
    "haystack", "haystack_integrations", "haystack_experimental",
    # LlamaIndex: `llama-index-core` installs the `llama_index` namespace. (The `llama_index_client`
    # sibling previously cited here DOES NOT EXIST — `llama-index-client` is a 404 on PyPI. The real
    # `_`-suffixed sibling is `llama_index_instrumentation`, an observability package that exports
    # no agent constructor, so it fails the entry criterion and is deliberately absent.)
    "llama_index", "llama_agents",
    # Single-package frameworks. `deepagents` is langchain-ai's own deep-agent harness (sub-agent
    # spawning + todo list + mock filesystem, built on LangGraph; it depends on `langchain>=1.3.14`).
    # Read from the `deepagents-0.7.2` wheel: top-level `deepagents`, `graph.py:268 def
    # create_deep_agent(`, `middleware/subagents.py:333 def create_sub_agent(`, and
    # `Project-URL: Repository https://github.com/langchain-ai/deepagents`. It satisfies all three
    # clauses — top-level, first-party to a covered framework, exports an agent constructor — and
    # shares no prefix with any listed root, which is precisely why the prefix-filtered audits kept
    # missing it (#454 re-gate). Reachability today is ZERO (wheel grep for the three disable
    # kwargs: 0 hits), same as the siblings added above; this is an enumeration-completeness entry,
    # not a live detection.
    "semantic_kernel", "pydantic_ai", "smolagents", "deepagents",
    # `openai-agents` (OpenAI Agents SDK) installs top-level `agents`.
    "agents",
    # `google-adk` installs into the `google` namespace as `google.adk`; the dotted form keeps
    # sibling `google.cloud` / `google.generativeai` out.
    "google.adk",
})


def _is_agent_module(module: str) -> bool:
    """True if `module` is exactly a known agent-framework module, or a dotted submodule of one.

    The whole predicate, and the invariant it enforces: membership in `_AGENT_MODULE_ROOTS` is by
    IDENTITY. `langchain_core` matches because it IS in the set; `langchain_helpers` does not,
    because a name is never assembled from a root plus an arbitrary suffix. The dotted form is the
    only widening, and it is sound: `langchain_core.agents` really is part of `langchain_core`,
    whereas `langchain_helpers` is not part of `langchain` in any sense Python recognises.

    So `google.adk.agents` matches while `google.cloud` / `google.generativeai` do not, and
    `autogen_core` matches while `autogen_migrations` and Alembic's `autogenerate` do not."""
    return any(module == r or module.startswith(r + ".") for r in _AGENT_MODULE_ROOTS)


def _dotted_path(func: ast.expr) -> list[str] | None:
    """`crewai.Agent` -> `["crewai", "Agent"]`; `google.adk.Agent` -> `["google", "adk", "Agent"]`.
    `None` if the attribute chain is not rooted in a bare Name (e.g. `get_agent().configure`)."""
    parts: list[str] = []
    node: ast.expr = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return list(reversed(parts))
    return None


def _agent_bindings(tree: ast.AST) -> tuple[set[str], set[str]]:
    """`(names, module_roots)`. `names` = symbols bound from a framework via `from <fw> import X`
    (or `import <fw> as X`) — used as `X(...)` or `X.attr(...)`. `module_roots` = the bound root of a
    plain `import <fw>` (`import crewai` -> `crewai`; `import google.adk` -> `google`) — used as a
    fully-qualified `root...(...)` call whose module path is re-verified against `_is_agent_module`.
    Relative imports (`from .agents import ...`) are skipped: they bind the caller's OWN package."""
    names: set[str] = set()
    module_roots: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            if n.level == 0 and n.module and _is_agent_module(n.module):
                names.update(a.asname or a.name for a in n.names)
        elif isinstance(n, ast.Import):
            for a in n.names:
                if _is_agent_module(a.name):
                    if a.asname:
                        names.add(a.asname)                     # import crewai as c -> c.Agent
                    else:
                        module_roots.add(a.name.split(".", 1)[0])  # import crewai / import google.adk
    return names, module_roots


def _call_is_agent_construction(func: ast.expr, names: set[str], module_roots: set[str]) -> bool:
    """True if a Call's `.func` is an agent-framework constructor: a name imported from a framework
    (`Agent(...)`, or `c.Agent(...)` for an aliased module), or a fully-qualified call rooted in a
    plain-imported framework module whose dotted path is itself an agent module (`crewai.Agent(...)`,
    `google.adk.Agent(...)` — but not `google.cloud.storage(...)`)."""
    if isinstance(func, ast.Name):
        return func.id in names
    if isinstance(func, ast.Attribute):
        parts = _dotted_path(func)
        if parts is None:
            return False
        if parts[0] in names:
            return True
        if parts[0] in module_roots:
            return _is_agent_module(".".join(parts[:-1]))
    return False


def _disabled_agent_gates(text: str, *, filename: str | Path = "<unknown>") -> list[tuple[int, str]]:
    """`(lineno, kwarg)` for each call to an agent-framework constructor that passes a disable-kwarg
    as a literal. AST-based, so string/comment mentions, non-literal values (`auto_approve=flag`),
    and non-framework calls (`dict(...)`, a local `class Agent`) do not match, and every match is
    reported at its real line. Total: a file that does not parse yields `[]` (via `safe_ast_parse`)."""
    tree = safe_ast_parse(text, filename=filename)
    if tree is None:
        return []
    names, module_roots = _agent_bindings(tree)
    if not names and not module_roots:
        return []
    out: list[tuple[int, str]] = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call) or not _call_is_agent_construction(n.func, names, module_roots):
            continue
        for kw in n.keywords:
            if (
                kw.arg in _DISABLE_KWARGS
                and isinstance(kw.value, ast.Constant)
                and _is_disabling_value(kw.value.value, _DISABLE_KWARGS[kw.arg])
            ):
                out.append((kw.value.lineno, kw.arg))
    return out


class ToolCallbackEnforcementGuard(Guard):
    id = "tool-callback-enforcement"
    title = "LLM agent or tool missing confirmation callback for dangerous operations"
    area = "AI agent"

    # .vscode/settings.json: trustedCommands wildcard -> fires
    # tool-callback-enforcement/trust-config-wildcard-bypass (HIGH).
    # Must NOT contain: security: allow-tool-callback pragma.
    # agent_executor.py (stays in the canary base): AgentExecutor(...) with no interception hook
    # -> fires tool-callback-enforcement/no-interrupt-before (MEDIUM). tool_callback.py carries
    # the same plant and is shadowed by it — the guard reports the rule once, alphabetically first.
    canary_plant = CanaryPlant(
        files={
            ".vscode/settings.json": (
                '{\n'
                '  "kiroAgent.trustedCommands": ["*"]\n'
                '}\n'
            ),
        },
        expects=frozenset({
            "tool-callback-enforcement/no-interrupt-before",
            "tool-callback-enforcement/trust-config-wildcard-bypass",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                files.append((f, read(f)))

        out: list[Finding] = []
        out += self._check_no_interrupt_before(root, files)
        out += self._check_destructive_tool_no_confirm(root, files)
        out += self._check_tool_credential_env(root, files)
        out += self._check_explicit_approval_disabled(root, files)
        out += self._check_trust_config_wildcard_bypass(root, profile)
        return out

    def _check_trust_config_wildcard_bypass(
        self, root: Path, profile: StackProfile
    ) -> list[Finding]:
        out: list[Finding] = []
        for d in _TRUST_CONFIG_DIRS:
            f = root / d / _TRUST_CONFIG_NAME
            if not f.is_file():
                continue
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            for pattern, key_desc in _TRUST_BYPASS_PATTERNS:
                m = pattern.search(text)
                if not m:
                    continue
                lineno = text[: m.start()].count("\n") + 1
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="IDE/agent config grants blanket auto-approval, bypassing human confirmation",
                    location=f"{r}:{lineno}",
                    message=(
                        f"``{r}`` sets ``{key_desc}`` to a blanket-trust value — a wildcard, "
                        "``true``, or ``full`` autonomy — removing the human-in-the-loop gate "
                        "for every future command the agent runs in this workspace. Unlike a "
                        "single bypassed confirmation, this is persistence-style "
                        "self-privilege-escalation: an indirect prompt injection in project "
                        "source (a README, a code comment, a fetched doc) can instruct the "
                        "agent to write this value itself (AWS Security Bulletin AWS-2025-019, "
                        "Amazon Q Developer / Kiro IDE)."
                    ),
                    remediation=(
                        "Remove the blanket-trust setting and require per-command or "
                        "per-session approval instead. If broad trust is genuinely intended, "
                        "scope it to specific, reviewed commands rather than a wildcard, and "
                        "treat any unreviewed change to this file (especially one written by "
                        "the agent itself) as a potential compromise indicator."
                    ),
                    rule="tool-callback-enforcement/trust-config-wildcard-bypass",
                    standards=list(_STD_TRUST_CONFIG),
                ))
                break  # one finding per file is enough signal
        return out

    def _check_no_interrupt_before(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        # One finding per unguarded AgentExecutor call, every file (#425): returning the first
        # capped the rule at one finding repo-wide, so an exception on it hid all the others.
        out: list[Finding] = []
        for f, text in files:
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            # Line numbers are counted forward from the previous finding, so many calls in one
            # file stay linear.
            pos, lineno = 0, 1
            # Parsed lazily: only the **kwargs-resolution path below needs funcs, and only when an
            # AgentExecutor call unpacks a dict. iter_functions() is a full safe_ast_parse +
            # strip_python_strings — skip it entirely on files with no AgentExecutor call, or whose
            # calls all pass literal params (issue #771). Memoized after the first parse.
            funcs: list[tuple[int, str]] | None = None
            for m in _AGENT_EXECUTOR.finditer(text):
                window = text[m.start(): m.start() + _AGENT_EXECUTOR_WINDOW]
                if _CONFIRM_PARAM.search(window):
                    continue
                # The pattern itself matches through the opening `(`, so m.end() - 1 is its index.
                open_idx = m.end() - 1
                args = split_call_args(text, open_idx, python=True)
                kwargs_vars = _kwargs_unpack_names(args) if args is not None else []
                if kwargs_vars:
                    # a `**kwargs`-unpacked call has no literal parameter names for the
                    # window scan above to see. Try to resolve the dict's own definition instead
                    # of assuming it is unguarded.
                    if funcs is None:
                        funcs = iter_functions(text, filename=f)
                    resolved = _resolve_kwargs_confirm_signal(text, m.start(), kwargs_vars, funcs)
                    if resolved is not False:
                        # True (a confirm key was found) or None (unresolved — stay silent,
                        # FN-biased): either way, this call is not flagged.
                        continue
                    # resolved is False: every unpacked variable's dict was found and NONE
                    # carried a confirm-signal key — fall through and fire with real evidence.
                lineno += text.count("\n", pos, m.start())
                pos = m.start()
                out.append(Finding(
                    check_id=self.id,
                    severity="medium",
                    title="AgentExecutor without an interception/confirmation callback",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "`AgentExecutor` is instantiated without any interception hook "
                        "(`callbacks=`, or a LangGraph `interrupt_before`/`checkpoint`). "
                        "Without a callback that can gate or review tool calls, a prompt "
                        "injection can direct the agent to invoke any registered tool "
                        "automatically. This is advisory (MEDIUM): a human-in-the-loop gate "
                        "may be wired elsewhere and cannot be proven statically."
                    ),
                    remediation=(
                        "Pass `callbacks=[handler]` with a `BaseCallbackHandler` whose "
                        "`on_tool_start` enforces an approval signal, or build the agent on "
                        "LangGraph and pause with `interrupt_before`/a `checkpoint` before "
                        "tool nodes. (The classic `AgentExecutor` does NOT accept "
                        "`interrupt_before` directly.) Suppress with "
                        "`# security: allow-tool-callback` when an out-of-band approval "
                        "mechanism is in place."
                    ),
                    rule="tool-callback-enforcement/no-interrupt-before",
                    standards=list(_STD_AGENCY),
                ))
        return out

    def _check_destructive_tool_no_confirm(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        # One finding per offending @tool, every file (#425): returning the first capped the
        # rule at one finding repo-wide.
        out: list[Finding] = []
        for f, text in files:
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            # issue #771: a finding here requires a destructive op inside a @tool body, so a file
            # with no destructive-op token at all can produce none — skip both the
            # _tool_decorated_defs parse and the iter_functions parse. The whole-text search is a
            # safe superset of the per-block search below (a destructive op is code, not string
            # content, so it survives iter_functions' string-blanking identically): it can only
            # over-approximate and trigger an unnecessary parse, never miss a real finding.
            if not _DESTRUCTIVE_OP.search(text):
                continue
            # Scan each @tool function's REAL body (AST-delimited): a fixed 30-line window
            # crossed into a FOLLOWING non-tool helper, attributing ITS destructive op to the
            # @tool above (#423). iter_functions' block starts at the decorator stack, so the
            # @tool decorator and the body are both inside it.
            tool_defs = _tool_decorated_defs(text, filename=f)
            for def_line, block in iter_functions(text, filename=f):
                # "Is THIS block a tool?" comes from the AST's own decorator_list, never from
                # scanning the block text: an enclosing factory can contain its nested `@tool` line
                # too (#452 review, and three failed lexical spellings after it; #502's blanking
                # removes it only for a nested `def` the walker tracked, see `_own_header`).
                if not _is_tool_block(def_line, block, tool_defs):
                    continue
                if not _DESTRUCTIVE_OP.search(block):
                    continue
                if _CONFIRM_PATTERN.search(block):
                    continue
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="@tool function performs destructive operation without confirmation",
                    location=f"{rel(root, f)}:{def_line}",
                    message=(
                        "A `@tool`-decorated function performs a destructive operation "
                        "against a database, ORM, or the filesystem (DELETE FROM / DROP "
                        "TABLE / TRUNCATE / session.delete / os.remove / shutil.rmtree) "
                        "with no confirmation gate. An LLM executing this tool in response "
                        "to a prompt injection can irreversibly delete data — with no chance "
                        "for a human to intervene."
                    ),
                    remediation=(
                        "Add a `confirmed: bool = False` parameter and return an "
                        "explanation when `confirmed` is False (e.g. 'Pass confirmed=True "
                        "to execute'). Alternatively gate on a `require_approval()` call or "
                        "an explicit human-review step before the destructive operation. "
                        "Suppress with `# security: allow-tool-callback`."
                    ),
                    rule="tool-callback-enforcement/destructive-tool-no-confirm",
                    standards=list(_STD_AGENCY),
                ))
        return out

    def _check_tool_credential_env(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        # One finding per leaking @tool, every file (#425): returning the first capped the
        # rule at one finding repo-wide.
        out: list[Finding] = []
        for f, text in files:
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            # issue #771: a finding here requires a credential-env access inside a @tool body, so a
            # file with no such token anywhere can produce none — skip both parses. The whole-text
            # search is a safe superset of the per-line search below (an os.environ/os.getenv access
            # is code, not string content): it can only over-approximate, never miss a real finding.
            if not _CRED_ENV_ACCESS.search(text):
                continue
            # Scan each @tool function's REAL body (AST-delimited) rather than a fixed 30-line
            # window that could cross into a following function (#423).
            tool_defs = _tool_decorated_defs(text, filename=f)
            for def_line, block in iter_functions(text, filename=f):
                # AST decorator_list, same as the TC004 arm — see `_tool_decorated_defs`.
                if not _is_tool_block(def_line, block, tool_defs):
                    continue
                body_lines = block.splitlines()
                for j, bline in enumerate(body_lines):
                    if not _CRED_ENV_ACCESS.search(bline):
                        continue
                    # Only flag when the credential LEAVES the tool as output. A credential
                    # consumed in-place (e.g. OpenAI(api_key=os.getenv(...))) does not fire.
                    if not _cred_is_returned(bline, body_lines[j + 1:]):
                        continue
                    out.append(Finding(
                        check_id=self.id,
                        severity="medium",
                        title="@tool function returns a credential read from the environment",
                        location=f"{rel(root, f)}:{def_line}",
                        message=(
                            "A `@tool`-decorated function returns a credential-like "
                            "environment variable (API_KEY, SECRET, PASSWORD, TOKEN, "
                            "CREDENTIAL) read via `os.environ` / `os.getenv`. Any caller of "
                            "this tool — including an LLM acting on injected instructions — "
                            "receives the raw credential value as the tool's output."
                        ),
                        remediation=(
                            "Do not return raw credentials from a tool. Inject the "
                            "credential as a dependency-bound client object and have the "
                            "tool return only the result of using it. If the value must be "
                            "exposed, add a `user`/`auth` parameter and validate the caller "
                            "before returning. Suppress with `# security: allow-tool-callback`."
                        ),
                        rule="tool-callback-enforcement/tool-credential-env-access",
                        standards=list(_STD_CRED),
                    ))
                    # The finding is anchored at the tool's def line, so a second leaking line
                    # in the same tool would duplicate it: one finding per tool.
                    break
        return out

    def _check_explicit_approval_disabled(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        out: list[Finding] = []
        for f, text in files:
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            # AST-based (#451/#454 review): each disable-kwarg passed as a literal to a call whose
            # function is bound from an agent framework. Emits every match at its real line — a
            # violation in one file no longer drops the rest (the old regex `.search()`+`return` did).
            for lineno, _kwarg in _disabled_agent_gates(text, filename=f):
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="Agent/tool approval gate explicitly disabled",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "A keyword argument explicitly disables a framework's default "
                        "approval/confirmation gate (`auto_approve=True`, "
                        "`human_in_the_loop=False`, or `confirm_before_action=False`) on an "
                        "agent-framework constructor. Unlike the absence of a callback — which "
                        "may simply mean one hasn't been wired up yet — this is a deliberate "
                        "opt-out of a safety mechanism the framework enables by default. A "
                        "prompt injection can now drive tool calls with zero human review."
                    ),
                    remediation=(
                        "Remove the override (or restore the framework default) so the "
                        "built-in approval/confirmation gate stays active. If "
                        "auto-approval is genuinely required for a specific low-risk "
                        "tool, scope it narrowly instead of disabling the gate for the "
                        "whole agent. Suppress with `# security: allow-tool-callback`."
                    ),
                    rule="tool-callback-enforcement/explicit-approval-disabled",
                    standards=list(_STD_AGENCY),
                ))
        return out


def _cred_is_returned(access_line: str, rest_body: list[str]) -> bool:
    """True if the credential read on `access_line` flows out of the tool as output.

    Covers (a) the credential read directly in a `return` statement, and (b) the
    credential assigned to a variable that a later `return` references.
    """
    if access_line.strip().startswith("return "):
        return True
    m = _ASSIGN_LHS.match(access_line)
    if m:
        # Only treat the LHS var as holding the credential when the RHS *is* the env
        # access (`key = os.getenv("API_KEY")`), not when the access is nested inside
        # another call (`client = OpenAI(api_key=os.getenv(...))` — var holds the client).
        rhs = access_line.split("=", 1)[1].strip()
        if rhs.startswith(("os.environ", "os.getenv")):
            var = m.group(1)
            var_re = re.compile(r"\breturn\b[^\n]*\b" + re.escape(var) + r"\b")
            return any(var_re.search(b) for b in rest_body)
    return False
