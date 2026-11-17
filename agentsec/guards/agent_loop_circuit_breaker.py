"""Guard: LLM agent loop runs without an iteration or time limit (OWASP-LLM:LLM06).

An agentic LLM loop that can run forever is an integrity-amplification risk before it is a
cost one: each additional iteration is another round of autonomous tool calls against real
state (writes, sends, purchases), not merely another billed API request, so a runaway loop
compounds unauthorized actions, not just dollars — the cost/DoS angle still applies on top
(review H6: a pure cost/DoS framing risks the F2 bar's "not just a DoS finding" exclusion).
LangChain's `AgentExecutor` has a default safety ceiling of 15 iterations
(`max_iterations=15`), but developers sometimes set `max_iterations=None` to "let the
model keep going" — which allows a prompt injection or a runaway tool loop to consume
unbounded LLM API calls, dollars, and wall-clock time.

The companion parameter `max_execution_time=None` disables the wall-clock timeout
(default: also None, but explicitly setting both to None after reading a warning is the
dangerous pattern). When `max_iterations=None` AND `max_execution_time=None` appear
together in the same `AgentExecutor(` call, the agent has zero automatic stopping
conditions.

Four statically detectable patterns:

  1. **`langchain-no-iteration-limit`** (HIGH): `AgentExecutor(` with `max_iterations=None`
     on the same logical line. This is the primary circuit-breaker removal. With this set,
     an injected prompt can instruct the agent to loop through every tool, every API, every
     DB row — without bound.

  2. **`langchain-no-time-limit`** (MEDIUM): `AgentExecutor(` with `max_execution_time=None`
     on the same line. The default is already None, so this only fires when the developer
     is explicitly acknowledging and ignoring the timeout (otherwise they would have omitted
     the argument). Alone it is MEDIUM because `max_iterations` still applies; combined with
     the first check it escalates the risk to critical.

  3. **`recursive-no-depth-limit`** (HIGH): A Python function (async or sync) that BOTH
     makes an LLM API call in its body AND calls itself recursively, WITHOUT a `depth` or
     `max_depth` parameter in its signature OR a depth-check guard (`if depth >= N`). A
     recursive agent function without a depth cap has no stopping condition if the model
     keeps returning instructions to recurse.

  4. **`custom-loop-no-iteration-cap`** (HIGH): A hand-rolled `while True:` / `while 1:`
     loop whose body calls an LLM with no counter, no `max_iterations`-style limit variable,
     and no bounded `break`. This is the modern default way people hand-write agent loops
     outside LangChain (pydantic-ai, the OpenAI Agents SDK, or a bare orchestration loop) —
     none of which use `AgentExecutor` or self-recursion, so checks 1-3 miss them entirely.
     A loop whose body calls `input(` (or reads from stdin, or BLOCKS on an external queue —
     `queue.get(`, `.recv(`, `receive_message(`, `basic_consume(`, `blpop(`/`brpop(`, or a
     receiver-qualified Kafka `consumer.poll(`/`consumer.consume(`) is carved out: a human or an external event must act between iterations, so injected
     content cannot cascade unattended (the classic interactive chat REPL, and a
     message-queue worker blocking on the next message, are syntactically identical to a
     runaway loop but safe for this reason). Each iteration of an unbounded loop is not just
     a cost/DoS risk — it is another round of autonomous tool calls against real state, so a
     runaway loop is an INTEGRITY amplifier (repeated unauthorized actions), not only a
     resource-exhaustion one.
     A `break` only counts as the loop's own exit if it actually belongs to THIS loop, not to
     a `for`/`while` nested inside it (tracked by indentation scope) — and a counter/step/turn
     -shaped variable name only counts as a real bound when it appears in an actual
     comparison — against a literal or a named constant/config attribute alike
     (`turn >= 10`, `turn >= MAX_TURNS`, `turn >= self.max_turns`, `len(steps) >= 10`) — and
     not merely by existing somewhere in the body: an accumulator that is only ever appended to (`steps = []`;
     `steps.append(response)`) caps nothing. The bound must additionally be LOOP-INVARIANT,
     resolved on the AST: a counter compared against a name the body itself rewrites
     (`if turn >= last_turn:` with `last_turn = turn` inside) is not a circuit breaker, and
     neither is `turn >= len(history)` where the body appends to `history` (#777). A file that
     will not parse falls back to the pre-#777 regex, which accepts any name-shaped bound.

**Checklist item:** `4-agent-loop-circuit-breaker` (covers LangChain AgentExecutor,
recursive agent functions, and hand-rolled `while True:` agent loops).

**Suppress:** `# security: allow-agent-loop-no-limit` in any file silences all checks.
Only appropriate in intentional long-running pipeline scripts (batch embeddings, crawlers)
where a human operator monitors wall-clock cost and the code has out-of-band cost guards.
"""
from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, python_scan_dirs, read, rel

# ---------------------------------------------------------------------------
# EXA009 — Recursive agent function without depth limit
# ---------------------------------------------------------------------------
# Match a Python function definition: captures the function name.
# We use a simple pattern to split source into per-function blocks.
_FUNC_DEF = re.compile(
    r"^(?:async\s+)?def\s+(\w+)\s*\(",
    re.MULTILINE,
)

# LLM API call patterns inside a function body. Deliberately LLM-specific: bare `.run(`
# / `.chat(` / `.complete(` / `.generate(` are NOT matched (they hit `asyncio.run(`,
# `subprocess.run(`, etc.). `.run(`/`.arun(` are accepted only on an LLM-shaped receiver
# (agent/llm/chain/...), which keeps pydantic-ai `agent.run(...)` while excluding
# `asyncio.run(...)`.
_LLM_CALL = re.compile(
    r"\.(?:ainvoke|invoke|run_sync)\s*\("
    r"|\b(?:agent|llm|chain|model|graph|runner|executor|client)\w*\.(?:a?run|chat|complete|generate)\s*\("
    r"|chat\.completions\.create\s*\("
    r"|\.messages\.create\s*\(",
    re.IGNORECASE,
)

# Depth/recursion guard: a depth param OR a recognised limit-idiom name OR an explicit
# numeric base-case comparison. Broader than just `depth` so a function bounded by
# `level`/`max_iterations`/`remaining`/... is not flagged HIGH (the over-suppression
# direction is the safe one for a HIGH rule).
_DEPTH_GUARD = re.compile(
    r"\b(?:depth|max_depth|level|max_level|max_iterations|max_steps|max_turns|"
    r"max_recursion|recursion_limit|remaining|budget|steps_left|turns_left|n_steps|limit)\b"
    r"|\bif\s+\w+\s*(?:>=|>|<=|<|==)\s*\d+\s*:",
    re.IGNORECASE,
)

_PRAGMA = "security: allow-agent-loop-no-limit"

_STANDARDS = ["OWASP-LLM:LLM06"]

# AgentExecutor( ... max_iterations=None ...) on a single logical line.
# The [^)]{0,400} bound avoids catastrophic backtracking on long call expressions
# while still covering typical multi-arg calls.
_NO_ITERATION_LIMIT = re.compile(
    r"\bAgentExecutor\s*\([^)]{0,400}max_iterations\s*=\s*None",
    re.IGNORECASE | re.DOTALL,
)

# AgentExecutor( ... max_execution_time=None ...) on a single logical line.
_NO_TIME_LIMIT = re.compile(
    r"\bAgentExecutor\s*\([^)]{0,400}max_execution_time\s*=\s*None",
    re.IGNORECASE | re.DOTALL,
)

# ---------------------------------------------------------------------------
# custom-loop-no-iteration-cap — hand-rolled `while True:` agent loop
# ---------------------------------------------------------------------------
# An unconditional loop header: `while True:` or `while 1:`, any leading indentation.
_WHILE_TRUE = re.compile(
    r"^(?P<indent>[ \t]*)while\s+(?:True|1)\s*:",
    re.MULTILINE,
)

# Human/external-event-in-the-loop carve-out: a loop body that reads from a human or BLOCKS
# on an external event source before its next iteration cannot cascade unattended, because
# something outside the model must act between calls. This is the primary FP class —
# `while True: user_input = input(); response = llm.invoke(user_input)` is a syntactically
# identical, but safe, interactive chat REPL — and so is a message-queue worker blocking on
# its next message (`sqs.receive_message(`, RabbitMQ's `basic_consume(`, Redis's
# `.blpop(`/`.brpop(`): review H6 found the original narrower list (input/stdin/queue.get/
# .recv only) fired HIGH on an SQS worker while staying silent on an otherwise-identical
# worker written against `queue.get()`, purely because of which broker client it called.
#
# BLOCKING is the property that earns the exemption, so the method name alone is not enough
# to grant it. H6 was implemented with bare `.poll(` and `.consume(` tokens, which silenced
# the guard on `subprocess.Popen.poll()`, `select.poll()` and any object with a `consume`
# method — `poll()` is the NON-blocking variant by definition (round-4 review F2). Kafka's
# blocking `consumer.poll(...)` / `consumer.consume(...)` is kept, qualified by its receiver
# name (also `channel`/`subscriber`), which is what carries the blocking property.
#
# That qualification must be a TOKEN test, not a CONTAINMENT one. Round 5 wrote it as
# `\w*(?:consumer|channel|subscriber)\w*`, whose `\w*` on either side matches any identifier
# merely CONTAINING a broker word, so `channel_name.poll()`, `consumer_count.consume()` and
# `my_subscriber_registry.poll()` earned the exemption while blocking on nothing — the exact
# FN the receiver qualification exists to prevent (#778). The token is therefore anchored as a
# whole trailing word (`\b` on its right) and its prefix restricted to underscore-delimited
# qualifiers, which is what compound broker names actually look like:
#   admitted  — `consumer`, `kafka_consumer`, `self._consumer`, `pubsub_channel`, `consumers`
#   rejected  — `channel_name`, `consumer_count`, `subscriber_list`, `channelsubscriber`
# A trailing NUMERIC suffix is also admitted (`(?:_\d+)?`): `consumer_1`, `kafka_consumer_1` and
# `channel_2` are per-partition broker receivers, the same client with a disambiguator, not a
# status flag. An ALPHABETIC continuation stays rejected because the `\b` then follows a word
# char, not `_<digits>`, so `channel_name`/`consumer_count`/`channel_id` keep firing (#794).
# `_?` keeps private attributes (`self._consumer`) and `s?` keeps plurals (`self.channels`):
# both are real broker receivers, so excluding them would re-open the H6 FP class. Note this
# is also cheaper than the containment form — one bounded quantifier instead of two unbounded
# ones (measured ~10x faster on underscore-heavy near-matches).
_HUMAN_IN_LOOP = re.compile(
    r"\binput\s*\(|sys\.stdin\b|\.readline\s*\(|queue\.get\s*\(|\.recv\s*\("
    r"|\.receive_message\s*\(|\bbasic_consume\s*\("
    r"|\b_?(?:\w+_)?(?:consumer|channel|subscriber)s?(?:_\d+)?\b\.(?:poll|consume)\s*\("
    r"|\.blpop\s*\(|\.brpop\s*\(",
    re.IGNORECASE,
)

# The right-hand side of a bound comparison: a literal (`turn >= 10`) OR a named constant or
# config attribute (`turn >= MAX_TURNS`, `turn >= self.max_turns`). Naming the bound is the MORE
# disciplined form — it is exactly what this guard's own remediation text asks for — so requiring
# a literal digit made the guard fire HIGH on correctly bounded loops whose exit is `return`/
# `raise` rather than `break` (round-4 review F1). The two alternatives are disjoint on their
# first character (digit vs letter/underscore), so this adds no backtracking ambiguity.
#
# LEXICALLY, though, `[A-Za-z_][\w.]*` cannot tell a bound from any other name: `MAX_TURNS` and
# `last_turn` are the same token shape, so a counter compared against a variable that the loop
# itself rewrites read as a circuit breaker and silenced the finding (#777). "Is this a bound?"
# is a DATAFLOW question — does the value change within the loop? — and no regex can answer it.
# `_while_has_iteration_cap` below answers it on the AST; this pattern survives as the fallback
# for a file that will not parse, where today's behaviour is still better than none.
_BOUND_RHS = r"(?:\d+|[A-Za-z_][\w.]*)"

# The counter/accumulator-shaped name stem. Shared by the regex fallback and the AST path so the
# two cannot drift apart — a name the fallback treats as a counter must be one the AST path does
# too, or the same loop would be judged differently depending only on whether the file parsed.
_COUNTER_STEM = r"\w*(?:iteration|count|step|turn|attempt|retr(?:y|ies)|budget|remaining)\w*"
_COUNTER_NAME = re.compile(_COUNTER_STEM, re.IGNORECASE)

# Iteration-cap idiom inside a `while True:` body: an explicit BOUND check — a
# counter/step/turn/attempt-shaped name (or its `len(...)`, for an accumulator list) compared
# against a limit, or the generic `if <var> <op> <number>:` base-case shape. Deliberately
# requires an actual comparison, not just the bare keyword appearing anywhere in the body: an
# accumulator that is only ever appended to (`steps = []`; `steps.append(response)`) reads as
# a counter-shaped name but caps nothing, and previously silenced the finding regardless
# (review H6). It is the COMPARISON requirement that keeps that accumulator firing, not the
# shape of the right-hand side — `steps.append(r)` has no comparison operator either way — so
# admitting a named bound above does not re-open H6.
#
# The third branch stays literal-only on purpose: `if <var> <op> <named>:` with no
# counter-shaped name on the left is just "any two-variable comparison", which would suppress
# nearly every loop.
_LOOP_GUARD = re.compile(
    r"\b" + _COUNTER_STEM
    + r"\s*(?:>=|>|<=|<|==)\s*" + _BOUND_RHS
    + r"|\blen\s*\(\s*\w+\s*\)\s*(?:>=|>|<=|<|==)\s*" + _BOUND_RHS
    + r"|\bif\s+\w+\s*(?:>=|>|<=|<|==)\s*\d+\s*:",
    re.IGNORECASE,
)


def _has_own_break(body_lines: list[str]) -> bool:
    """True if `body_lines` (the immediate body of a `while True:`) contains a `break` that
    actually exits THIS loop — not one that belongs to a `for`/`while` nested inside it.

    Tracks nested loop headers by indentation: entering a `for`/`while` line pushes its own
    indentation; any line indented deeper than the innermost open header belongs to that
    inner loop (a `break` there does not exit the outer one), and dedenting back to or below
    a header's indentation pops it. A `break` reached while no inner loop is open — including
    one nested inside a plain `if`/`try`, which doesn't own its own break scope — does exit
    the outer loop (review H6: a break belonging to an inner `for` loop was previously
    treated as bounding the outer `while True:`, which it does not)."""
    inner_loop_indents: list[int] = []
    for ln in body_lines:
        if not ln.strip():
            continue
        indent = len(ln) - len(ln.lstrip())
        while inner_loop_indents and indent <= inner_loop_indents[-1]:
            inner_loop_indents.pop()
        if re.match(r"(?:for|while)\b", ln.strip()):
            inner_loop_indents.append(indent)
            continue
        if inner_loop_indents:
            continue
        if re.search(r"\bbreak\b", ln):
            return True
    return False


# ---------------------------------------------------------------------------
# Loop-invariant bound resolution (#777)
# ---------------------------------------------------------------------------
# A counter comparison caps a loop only when the thing it is compared against CANNOT MOVE
# within that loop. `turn >= MAX_TURNS` caps; `turn >= last_turn` — where the body does
# `last_turn = turn` — does not, and neither does `turn >= len(history)` where the body appends
# to `history`. The regex above sees one token shape for all three. These helpers answer the
# real question on the AST: resolve the comparison's operands, then ask whether the bound side
# is rebound anywhere inside the loop body.
#
# Deliberately a REBINDING test, not a full constant-propagation or reaching-definitions pass.
# The property that matters is local and cheap ("could this name's value differ between two
# iterations of THIS loop?"), and the cost of being wrong is asymmetric: treating a real bound
# as mutable costs one false positive on a HIGH rule, so the test errs toward accepting a name
# as a bound and only rejects it on direct evidence of rebinding in the body.

# Comparison operators that can express a cap. `!=` is excluded: `while turn != MAX` is a cap
# only if the counter lands exactly on the bound, which a `+= 2` step or a reset breaks.
_CAP_OPS = (ast.GtE, ast.Gt, ast.LtE, ast.Lt, ast.Eq)


def _dotted_path(node: ast.expr) -> str | None:
    """`config.limits.max_turns` -> `"config.limits.max_turns"`; `None` if the chain does not
    bottom out in a plain name (a call or subscript in the middle makes the path unresolvable)."""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _root_name(node: ast.expr) -> str | None:
    """The receiver a dotted chain hangs off: `config.max_turns` -> `"config"`."""
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        current = current.value
    return current.id if isinstance(current, ast.Name) else None


def _add_bound_target(target: ast.expr, out: set[str]) -> None:
    """Record every name `target` binds, destructuring tuple/list/starred targets.

    An attribute target contributes its full dotted path ONLY — `self.max_turns = n`
    disqualifies `self.max_turns` as a bound, but `self.last_response = r` must NOT disqualify
    `self.max_turns`. Adding the root here read every write to any attribute as a write to the
    whole object, which fired HIGH on the entirely ordinary shape of a bounded loop that also
    stores something on `self` (review of #792). Rebinding the OBJECT (`config = reload()`) is a
    `Name` target and still lands in the branch above, so `_is_loop_invariant`'s root check keeps
    catching it."""
    if isinstance(target, ast.Name):
        out.add(target.id)
    elif isinstance(target, ast.Attribute):
        dotted = _dotted_path(target)
        if dotted is not None:
            out.add(dotted)
    elif isinstance(target, ast.Starred):
        _add_bound_target(target.value, out)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            _add_bound_target(element, out)


# Scopes whose LOCAL bindings do not rebind anything in the loop's own scope. Descending into
# them is how #772's AST rewrite shipped a false-positive class: a nested `def` that happens to
# reuse the bound's name is SHADOWING it, not moving it, and treating that as a rebind fires HIGH
# on a correctly bounded loop.
_NESTED_SCOPES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.ClassDef,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)
_COMPREHENSION_SCOPES = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _leaked_bindings(scope: ast.AST) -> Iterator[ast.AST]:
    """The only two ways a nested scope reaches back out and rebinds an enclosing name:
    an explicit `global`/`nonlocal` declaration, and a walrus inside a COMPREHENSION (which by
    language rule binds in the enclosing scope, not the comprehension's)."""
    leaks_walrus = isinstance(scope, _COMPREHENSION_SCOPES)
    for node in ast.walk(scope):
        if isinstance(node, (ast.Global, ast.Nonlocal)) or (
            leaks_walrus and isinstance(node, ast.NamedExpr)
        ):
            yield node


def _iter_loop_scope(node: ast.AST) -> Iterator[ast.AST]:
    """`ast.walk`, but stopping at a nested scope boundary.

    The scope node itself is still yielded — a nested `def`/`class` binds its own NAME in our
    scope even though its body does not — and so is anything its body leaks back out via
    `_leaked_bindings`."""
    yield node
    if isinstance(node, _NESTED_SCOPES):
        yield from _leaked_bindings(node)
        return
    for child in ast.iter_child_nodes(node):
        yield from _iter_loop_scope(child)


def _names_bound_in(node: ast.AST) -> set[str]:
    """Every name rebound anywhere inside `node` — the loop body, for our purposes.

    Covers all of Python's binding forms, not just `=`: augmented and annotated assignment, the
    walrus, `for` targets, `with ... as`, `except ... as`, `import ... as`, nested `def`/
    `class` names, and `match`/`case` capture patterns. Missing a binding form is the failure
    that matters (it would let a mutable name pass as a bound and re-open #777), so the list is
    exhaustive rather than minimal — `match` was itself a review catch on #792.

    SCOPE-AWARE: a binding inside a nested `def`/`lambda`/comprehension/`class` is local to that
    scope and does NOT count, unless the scope declares the name `global`/`nonlocal` or leaks it
    through a comprehension walrus. See `_iter_loop_scope`."""
    out: set[str] = set()
    for child in _iter_loop_scope(node):
        if isinstance(child, ast.Assign):
            for target in child.targets:
                _add_bound_target(target, out)
        elif isinstance(
            child, (ast.AugAssign, ast.AnnAssign, ast.NamedExpr, ast.For, ast.AsyncFor)
        ):
            _add_bound_target(child.target, out)
        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(child.name)
        elif isinstance(child, ast.withitem) and child.optional_vars is not None:
            _add_bound_target(child.optional_vars, out)
        elif isinstance(child, ast.ExceptHandler) and child.name is not None:
            out.add(child.name)
        elif isinstance(child, (ast.Global, ast.Nonlocal)):
            out.update(child.names)
        elif isinstance(child, (ast.MatchAs, ast.MatchStar)) and child.name is not None:
            out.add(child.name)          # `case {...} as cap:` / `case [*rest]:`
        elif isinstance(child, ast.MatchMapping) and child.rest is not None:
            out.add(child.rest)          # `case {"limit": cap, **rest}:`
        elif isinstance(child, (ast.Import, ast.ImportFrom)):
            for alias in child.names:
                out.add(alias.asname or alias.name.split(".")[0])
    return out


def _is_number(node: ast.expr) -> bool:
    """A numeric literal. `bool` is excluded despite subclassing `int` — `turn >= True` is not
    a cap anyone wrote on purpose."""
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, (int, float))
        and not isinstance(node.value, bool)
    )


def _is_loop_invariant(node: ast.expr, bound_names: set[str]) -> bool:
    """Can `node`'s value be relied on not to move between iterations?

    A numeric literal always can. A name or dotted attribute can unless the body rebinds it
    (for an attribute, either the full path or its root disqualifies it). Anything else — a
    call like `len(history)`, an arithmetic expression, a subscript — cannot be resolved this
    way and is NOT accepted, which is what keeps `turn >= len(history)` firing."""
    if _is_number(node):
        return True
    if isinstance(node, ast.Name):
        return node.id not in bound_names
    if isinstance(node, ast.Attribute):
        dotted = _dotted_path(node)
        root = _root_name(node)
        if dotted is None or root is None:
            return False
        return dotted not in bound_names and root not in bound_names
    return False


def _is_counter_shaped(node: ast.expr) -> bool:
    """The counting side of a cap comparison: a counter-shaped name (`turn`, `n_attempts`,
    `self.step_count`) or `len(...)` over an accumulator."""
    if isinstance(node, ast.Name):
        return _COUNTER_NAME.fullmatch(node.id) is not None
    if isinstance(node, ast.Attribute):
        return _COUNTER_NAME.fullmatch(node.attr) is not None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id == "len"
    return False


def _is_base_case_test(test: ast.expr) -> bool:
    """The generic `if <var> <op> <number>:` base-case shape — the AST twin of `_LOOP_GUARD`'s
    third branch, kept at exactly its width. The name is NOT required to be counter-shaped, so
    this stays literal-only: admitting a named right-hand side here would suppress essentially
    every loop, since `if a > b:` appears in almost all of them."""
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return False
    if not isinstance(test.ops[0], _CAP_OPS):
        return False
    return isinstance(test.left, ast.Name) and _is_number(test.comparators[0])


def _while_has_iteration_cap(loop: ast.While) -> bool:
    """True if `loop`'s body contains a genuine iteration cap.

    Two accepted shapes, mirroring the three `_LOOP_GUARD` branches:
      1. a counter-shaped operand compared against a loop-invariant bound, either way round
         (`turn >= MAX_TURNS`, `MAX_TURNS <= turn`, `len(steps) >= cfg.max_steps`);
      2. the generic `if <var> <op> <number>:` base case.
    `bound_names` is computed once from the body and shared by every comparison in it."""
    bound_names: set[str] = set()
    for statement in loop.body:
        bound_names |= _names_bound_in(statement)

    # Scoped to `loop.body`, not `ast.walk(loop)`: the latter would also sweep the loop's own
    # test and its `else:` clause. The indentation slice the regex path uses stops at the
    # dedent to `else:`, so including it here would make the two paths disagree — and a
    # `while True: ... else:` clause is unreachable anyway (only a non-`break` exit runs it).
    for node in (descendant for statement in loop.body for descendant in ast.walk(statement)):
        if isinstance(node, ast.If) and _is_base_case_test(node.test):
            return True
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        if not isinstance(node.ops[0], _CAP_OPS):
            continue
        left, right = node.left, node.comparators[0]
        if _is_counter_shaped(left) and _is_loop_invariant(right, bound_names):
            return True
        if _is_counter_shaped(right) and _is_loop_invariant(left, bound_names):
            return True
    return False


def _while_nodes_by_line(text: str, path: Path) -> dict[int, ast.While] | None:
    """Every `while` node in `text`, keyed by its 1-based header line. `None` if the file will
    not parse, which is the caller's signal to fall back to the regex.

    Built ONCE per file and reused for every `while True:` in it. Parsing and walking the whole
    module per match is the shape — the same super-linear re-walk that cost
    `forwarded_header_blind_trust.py` a 9.5x regression, caught here in review of #792 (measured
    7.4x on a 100-loop file before this)."""
    tree = safe_ast_parse(text, path)
    if tree is None:
        return None
    return {n.lineno: n for n in ast.walk(tree) if isinstance(n, ast.While)}


def _has_iteration_cap(
    while_nodes: dict[int, ast.While] | None, header_line: int, body: str
) -> bool:
    """Does the `while True:` whose header is at 1-based `header_line` cap its iterations?

    AST-first, with the pre-#777 regex as the fallback for a file that will not parse (the
    house convention — see `forwarded_header_blind_trust.py`). Degrading to the regex restores
    exactly today's behaviour for that file rather than losing the suppression entirely, so an
    unparseable file cannot turn this into a false-positive machine."""
    if while_nodes is not None:
        loop = while_nodes.get(header_line)
        if loop is not None:
            return _while_has_iteration_cap(loop)
    return _LOOP_GUARD.search(body) is not None


class AgentLoopCircuitBreakerGuard(Guard):
    id = "agent-loop-circuit-breaker"
    title = "LLM agent loop has no iteration or time limit"
    area = "AI agent"

    # recursive_agent.py has one agent-loop-circuit-breaker plant (EXA009):
    #   async def agent_step(...) with llm.invoke() + recursive self-call, no depth param
    #   -> recursive-no-depth-limit (HIGH)
    # custom_loop_agent.py has one agent-loop-circuit-breaker plant:
    #   def run_agent(...): while True: llm.invoke(...) with no counter/break/depth guard
    #   -> custom-loop-no-iteration-cap (HIGH)
    # Must NOT contain: allow-agent-loop-no-limit pragma — it silences the check repo-wide.
    # Uses llm.invoke() (not chat.completions.create) to avoid firing llm-input-size-cap.
    # Uses no f-string interpolation to avoid firing prompt-string-interp.
    # Uses no vectorstore patterns to avoid firing rag-trust-boundary or rag-no-instruction-filter.
    # agent_executor.py: AgentExecutor(max_iterations=None) -> langchain-no-iteration-limit,
    # AgentExecutor(max_execution_time=None) -> langchain-no-time-limit.
    # recursive_agent.py: agent_step() calls llm.invoke() and itself with no depth param
    # -> recursive-no-depth-limit.
    # custom_loop_agent.py: run_agent() has a `while True:` body that calls llm.invoke()
    # with no `input(`/stdin carve-out, no break, and no iteration-cap idiom
    # -> custom-loop-no-iteration-cap.
    canary_plant = CanaryPlant(
        files={
            "recursive_agent.py": (
                "from langchain_openai import ChatOpenAI\n"
                "\n"
                "llm = ChatOpenAI(model='gpt-4o')\n"
                "\n"
                "\n"
                "async def agent_step(task: str, memory: list) -> str:\n"
                "    response = llm.invoke(task)\n"
                "    return await agent_step(str(response), memory)\n"
            ),
            "custom_loop_agent.py": (
                "from langchain_openai import ChatOpenAI\n"
                "\n"
                "llm = ChatOpenAI(model='gpt-4o')\n"
                "\n"
                "\n"
                "def run_agent(task: str) -> str:\n"
                "    while True:\n"
                "        response = llm.invoke(task)\n"
                "        task = str(response)\n"
            ),
        },
        expects=frozenset({
            "agent-loop-circuit-breaker/langchain-no-iteration-limit",
            "agent-loop-circuit-breaker/langchain-no-time-limit",
            "agent-loop-circuit-breaker/recursive-no-depth-limit",
            "agent-loop-circuit-breaker/custom-loop-no-iteration-cap",
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
                files.append((f, read(f)))

        for _f, text in files:
            if pragma_present(_PRAGMA, text, dialect="python"):
                return []

        out: list[Finding] = []
        out += self._check_no_iteration_limit(root, files)
        out += self._check_no_time_limit(root, files)
        out += self._check_recursive_no_depth_limit(root, files)
        out += self._check_custom_loop_no_iteration_cap(root, files)
        return out

    def _check_no_iteration_limit(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        # One finding per `AgentExecutor` call, every file (#425): returning the first
        # match capped the rule at one finding repo-wide. Line numbers are counted forward
        # from the previous match so many calls in one file stay linear.
        out: list[Finding] = []
        for f, text in files:
            pos, lineno = 0, 1
            for m in _NO_ITERATION_LIMIT.finditer(text):
                lineno += text.count("\n", pos, m.start())
                pos = m.start()
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="AgentExecutor with max_iterations=None — no loop circuit breaker",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "`AgentExecutor` is instantiated with `max_iterations=None`, "
                        "disabling LangChain's default 15-iteration ceiling. Without a "
                        "hard stop, a prompt injection or a runaway tool loop can cause "
                        "the agent to call tools and the LLM indefinitely — burning API "
                        "credits and compute with no automatic recovery. If the agent "
                        "operates on untrusted input (user queries, RAG content), an "
                        "attacker can inject instructions that force the agent into an "
                        "infinite tool-call cycle."
                    ),
                    remediation=(
                        "Remove `max_iterations=None` and rely on the default (15), or "
                        "set an explicit low ceiling: `AgentExecutor(agent=agent, "
                        "tools=tools, max_iterations=10, max_execution_time=30)`. "
                        "For intentional long-running batch agents, add a monitoring "
                        "callback that enforces a cost ceiling, then suppress with "
                        "`# security: allow-agent-loop-no-limit`."
                    ),
                    rule="agent-loop-circuit-breaker/langchain-no-iteration-limit",
                    standards=list(_STANDARDS),
                ))
        return out

    def _check_no_time_limit(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        # One finding per `AgentExecutor` call, every file (#425); same shape as above.
        out: list[Finding] = []
        for f, text in files:
            pos, lineno = 0, 1
            for m in _NO_TIME_LIMIT.finditer(text):
                lineno += text.count("\n", pos, m.start())
                pos = m.start()
                out.append(Finding(
                    check_id=self.id,
                    severity="medium",
                    title="AgentExecutor with max_execution_time=None — no wall-clock timeout",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "`AgentExecutor` is instantiated with `max_execution_time=None`, "
                        "explicitly disabling the wall-clock safety timeout. Although "
                        "`max_iterations` still applies (if set), a slow tool or a stuck "
                        "network call can hold a thread indefinitely. Combined with "
                        "`max_iterations=None`, the agent has no stopping condition at all."
                    ),
                    remediation=(
                        "Set `max_execution_time=<seconds>` (e.g. 30–120) to cap "
                        "wall-clock time per agent run. Combine with `max_iterations` "
                        "for defense-in-depth. Suppress with "
                        "`# security: allow-agent-loop-no-limit` only in monitored "
                        "batch jobs with out-of-band cost controls."
                    ),
                    rule="agent-loop-circuit-breaker/langchain-no-time-limit",
                    standards=list(_STANDARDS),
                ))
        return out

    def _check_recursive_no_depth_limit(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        """EXA009: async/sync function that calls an LLM AND calls itself recursively
        without a depth parameter or depth-check guard."""
        out: list[Finding] = []
        for f, text in files:
            lines = text.splitlines()
            # _FUNC_DEF only matches column-0 (top-level) defs, so a function's body is
            # the run of following lines that are blank or indented deeper than column 0,
            # stopping at the first non-blank column-0 line. This EXCLUDES module-level
            # trailing code (notably `if __name__ == "__main__": asyncio.run(main())`),
            # which previously leaked into the last function's body and made every
            # entry-point `main()` false-fire.
            for func_match in _FUNC_DEF.finditer(text):
                func_name = func_match.group(1)
                func_start = func_match.start()
                def_line0 = text[:func_start].count("\n")  # 0-based line of `def`
                body_buf: list[str] = []
                for k in range(def_line0 + 1, len(lines)):
                    ln = lines[k]
                    if not ln.strip():
                        body_buf.append(ln)
                        continue
                    if len(ln) - len(ln.lstrip()) == 0:  # back to column 0 → end of function
                        break
                    body_buf.append(ln)
                # Region = the def line(s) (signature) + the indented body, so a depth
                # param in a multi-line signature is still seen.
                region = lines[def_line0] + "\n" + "\n".join(body_buf)

                # (a) An LLM API call inside the function.
                if not _LLM_CALL.search(region):
                    continue
                # (b) A genuine in-body recursive call (the name invoked, not just referenced).
                if not re.search(r"\b" + re.escape(func_name) + r"\s*\(", "\n".join(body_buf)):
                    continue
                # (c) A depth/limit guard anywhere in the signature or body → safe.
                if _DEPTH_GUARD.search(region):
                    continue

                lineno = text[:func_start].count("\n") + 1
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title=f"Recursive agent function `{func_name}` has no depth limit",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        f"The function `{func_name}` makes an LLM API call and calls "
                        "itself recursively without a `depth` or `max_depth` parameter "
                        "in its signature and without a depth-check guard (`if depth >= N`). "
                        "A prompt injection or a runaway model response can cause the "
                        "function to recurse indefinitely, exhausting the call stack, "
                        "burning API credits, and producing a denial-of-service condition."
                    ),
                    remediation=(
                        f"Add a `depth: int = 0` parameter to `{func_name}` and guard "
                        "the recursive call: `if depth >= MAX_DEPTH: return <fallback>`. "
                        "Pass `depth + 1` at every recursive call site. Choose a MAX_DEPTH "
                        "appropriate to the task (e.g. 10). Suppress with "
                        "`# security: allow-agent-loop-no-limit` only when an out-of-band "
                        "cost monitor enforces an equivalent hard stop."
                    ),
                    rule="agent-loop-circuit-breaker/recursive-no-depth-limit",
                    standards=list(_STANDARDS),
                ))
        return out

    def _check_custom_loop_no_iteration_cap(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        """A hand-rolled `while True:`/`while 1:` agent loop that calls an LLM with no
        iteration cap, counter, or bounded break. Covers pydantic-ai, the OpenAI Agents
        SDK, and bare while-loop orchestration — the shapes `langchain-no-iteration-limit`
        and `recursive-no-depth-limit` above cannot see because there is no AgentExecutor
        and no self-recursion, just a plain loop statement."""
        out: list[Finding] = []
        for f, text in files:
            lines = text.splitlines()
            # Parsed lazily on the first `while True:` in this file and reused for the rest:
            # files with no match never pay for a parse, files with many pay once.
            while_nodes: dict[int, ast.While] | None = None
            parsed = False
            # Body = the run of following lines that are blank or indented strictly
            # deeper than the `while` header, stopping at the first line back at or
            # above that indent — same indentation-bounding approach as the function
            # body extraction above (naturally stays inside any enclosing function too,
            # since a dedent back to the function's own body level also stops it).
            for m in _WHILE_TRUE.finditer(text):
                base_indent = len(m.group("indent"))
                header_line0 = text[: m.start()].count("\n")  # 0-based line of `while`
                body_buf: list[str] = []
                for k in range(header_line0 + 1, len(lines)):
                    ln = lines[k]
                    if not ln.strip():
                        body_buf.append(ln)
                        continue
                    if len(ln) - len(ln.lstrip()) <= base_indent:
                        break
                    body_buf.append(ln)
                body = "\n".join(body_buf)

                # (a) Human/external-event-in-the-loop carve-out: something outside the
                # model must act between iterations, so injected content cannot cascade
                # unattended (the interactive chat REPL FP class).
                if _HUMAN_IN_LOOP.search(body):
                    continue
                # (b) Must actually call an LLM.
                if not _LLM_CALL.search(body):
                    continue
                # (c) A `break` that belongs to THIS loop (not a nested for/while) is a
                # bounded exit — safe.
                if _has_own_break(body_buf):
                    continue
                # (d) A genuine iteration cap in the body → safe. The bound must be
                # loop-INVARIANT, not merely name-shaped: a counter compared against a
                # variable the body itself rewrites caps nothing (#777).
                if not parsed:
                    while_nodes = _while_nodes_by_line(text, f)
                    parsed = True
                if _has_iteration_cap(while_nodes, header_line0 + 1, body):
                    continue

                lineno = header_line0 + 1
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="Custom `while True:` agent loop has no iteration cap",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "This hand-rolled agent loop (`while True:` / `while 1:`) calls "
                        "an LLM repeatedly with no counter, no `max_iterations`-style "
                        "limit variable, and no bounded `break`. Frameworks like "
                        "pydantic-ai, the OpenAI Agents SDK, or a bare orchestration "
                        "loop written this way have no automatic stopping condition — a "
                        "prompt injection or a runaway model response can keep the loop "
                        "running indefinitely. Each iteration is another round of "
                        "autonomous tool calls against real state, not just an LLM API "
                        "charge — so an unbounded loop is an integrity amplifier "
                        "(repeated unauthorized actions), on top of the API-credit and "
                        "compute cost."
                    ),
                    remediation=(
                        "Replace `while True:` with a bounded loop, e.g. "
                        "`for turn in range(MAX_TURNS):`, or track a counter and break "
                        "when it is exceeded: `if turn >= MAX_TURNS: break`. If the loop "
                        "is a human-driven REPL (reads from `input()`/stdin/a queue "
                        "between iterations), no change is needed — that carve-out is "
                        "already recognised. Otherwise suppress with "
                        "`# security: allow-agent-loop-no-limit` only when an "
                        "out-of-band cost monitor enforces an equivalent hard stop."
                    ),
                    rule="agent-loop-circuit-breaker/custom-loop-no-iteration-cap",
                    standards=list(_STANDARDS),
                ))
        return out
