from __future__ import annotations

from agentsec.guards.forwarded_header_blind_trust import ForwardedHeaderBlindTrustGuard
from tests.guards._common import *  # noqa: F401,F403


def test_forwarded_header_blind_trust_fires(tmp_path: Path) -> None:
    (tmp_path / "rate.py").write_text(
        "from fastapi import Request\n\ndef check_rate_limit(req: Request) -> bool:\n"
        "    ip = req.headers.get('X-Forwarded-For')\n    return apply_rate_limit(ip)\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)

def test_forwarded_header_blind_trust_get_with_default_fires(tmp_path: Path) -> None:
    # Regression (#422): .get() with a default argument must pass the file pre-filter.
    (tmp_path / "rate.py").write_text(
        "from fastapi import Request\n\ndef check_rate_limit(req: Request) -> bool:\n"
        "    ip = req.headers.get('X-Forwarded-For', '')\n    return apply_rate_limit(ip)\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)

def test_forwarded_header_blind_trust_get_with_default_no_sec_ctx_silent(tmp_path: Path) -> None:
    # FP-bait for the widened .get arm: no security-context keyword nearby stays silent.
    (tmp_path / "logmw.py").write_text(
        "def log_request(req):\n"
        "    origin = req.headers.get('X-Forwarded-For', '')\n"
        "    logger.info('request from %s', origin)\n",
        encoding="utf-8",
    )
    assert ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []

def test_forwarded_header_blind_trust_proxy_aware_silent(tmp_path: Path) -> None:
    (tmp_path / "rate.py").write_text(
        "from starlette.middleware.trustedhost import TrustedHostMiddleware\n"
        "def check_rate_limit(req):\n    ip = req.headers.get('X-Forwarded-For')\n    return apply_rate_limit(ip)\n",
        encoding="utf-8",
    )
    assert ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []


# ── enclosing-function-span + same-variable-flow ──────────────────────────────────

def test_forwarded_header_blind_trust_fires_via_sink_beyond_fixed_window(tmp_path: Path) -> None:
    # Previously-missed true positive: the header value is assigned to `ip`, then flows into a
    # rate-limit sink more than 5 lines below the assignment (padding lines in between) — the old
    # fixed +/-5 line window could not reach it, so the guard reported clean on an actually
    # vulnerable pattern. enclosing_function_span() now searches the whole enclosing function.
    (tmp_path / "rate.py").write_text(
        "from fastapi import Request\n"
        "\n"
        "\n"
        "def check_request(req: Request) -> bool:\n"
        "    ip = req.headers.get('X-Forwarded-For')\n"
        "    a = 1\n"
        "    b = 2\n"
        "    c = 3\n"
        "    d = 4\n"
        "    e = 5\n"
        "    return apply_rate_limit(ip)\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_unrelated_keyword_nearby_silent(tmp_path: Path) -> None:
    # FP-bait: a security-context keyword sits within the old +/-5 line window but is attached to
    # a DIFFERENT variable than the one the header value was assigned to — proximity coincidence,
    # not real flow. Must stay silent now that the guard requires the SAME variable at the sink.
    (tmp_path / "handler.py").write_text(
        "from fastapi import Request\n"
        "\n"
        "\n"
        "def handle(req: Request) -> None:\n"
        "    ip = req.headers.get('X-Forwarded-For')\n"
        "    logger.info('handling request')\n"
        "    if user_is_over_rate_limit(other_id):\n"
        "        block()\n"
        "    return ip\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_fires_through_one_hop_rename(tmp_path: Path) -> None:
    # #685 fix-commit round, High 3: the same-variable requirement didn't follow a rename --
    # `ip = raw` after `raw = req.headers.get(...)` went silent because the sink search only
    # ever looked for the header's ORIGINAL binding (`raw`), never the renamed reference
    # (`ip`) the security-context keyword actually co-occurs with.
    (tmp_path / "rate.py").write_text(
        "from fastapi import Request\n"
        "\n"
        "\n"
        "def check(req: Request) -> bool:\n"
        "    raw = req.headers.get('X-Forwarded-For')\n"
        "    ip = raw\n"
        "    return apply_rate_limit(ip)\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_unrelated_rename_does_not_leak_into_tracked_set(
    tmp_path: Path,
) -> None:
    # FP-bait for the alias fix itself: a bare rename of a DIFFERENT, unrelated variable (not
    # the header's own binding) must not be swept into the tracked-name set just because it
    # shares the "bare rename" shape.
    (tmp_path / "handler.py").write_text(
        "from fastapi import Request\n"
        "\n"
        "\n"
        "def handle(req: Request) -> None:\n"
        "    raw = req.headers.get('X-Forwarded-For')\n"
        "    other = 5\n"
        "    other2 = other\n"
        "    if user_is_over_rate_limit(other2):\n"
        "        block()\n"
        "    return raw\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_two_hop_rename_is_a_disclosed_gap(tmp_path: Path) -> None:
    # Disclosed, accepted limitation: the alias fix is deliberately ONE-HOP only (Dean's own
    # suggested scope). A second rename (`ip2 = ip` after `ip = raw`) is not tracked. Pinned
    # here so a future change to the alias search doesn't silently start or stop catching this
    # shape without anyone noticing either way.
    (tmp_path / "rate.py").write_text(
        "from fastapi import Request\n"
        "\n"
        "\n"
        "def check(req: Request) -> bool:\n"
        "    raw = req.headers.get('X-Forwarded-For')\n"
        "    ip = raw\n"
        "    ip2 = ip\n"
        "    return apply_rate_limit(ip2)\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_inline_same_line_still_fires(tmp_path: Path) -> None:
    # The header value passed directly (no intermediate variable) still fires when the
    # security-context keyword is on the same line/statement — real flow, no window needed.
    (tmp_path / "rate.py").write_text(
        "from fastapi import Request\n"
        "\n"
        "\n"
        "def check(req: Request) -> bool:\n"
        "    return apply_rate_limit(req.headers.get('X-Forwarded-For'))\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)



# ── #772: AST-resolved one-hop alias, scope- / order- / liveness-aware ───────────────────────
#
# The alias set is resolved from the AST (any receiver-rooted chain on the header var), not a
# bare `name = name` line regex. Restores the spellings the regex missed (below), and the AST
# rewrite newly opened three axes a text regex never reasoned about — whose assignment it is
# (scope), when it happens (order/liveness) — each with an FP-bait here. See issue-772 RCA.


def test_forwarded_header_blind_trust_fires_through_derived_split_idiom(tmp_path: Path) -> None:
    # THE canonical X-Forwarded-For idiom (round-3 F3, the missed detection this issue re-lands):
    # the bare-rename regex could not see `first = raw.split(",")[0].strip()`, so the guard was
    # silent on the most common real spelling. The AST reads the receiver root (`raw`) regardless
    # of the transform.
    (tmp_path / "rate.py").write_text(
        "from fastapi import Request\n\n\n"
        "def check(req: Request) -> bool:\n"
        "    raw = req.headers.get('X-Forwarded-For')\n"
        "    first = raw.split(',')[0].strip()\n"
        "    return is_rate_limited(first)\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_fires_through_every_one_hop_spelling(tmp_path: Path) -> None:
    # An annotation, parentheses, a multi-line RHS, or a trailing comment each defeated the
    # `$`-anchored identifier-only regex. None of them is a distinction the AST draws.
    for name, rename in (
        ("annotated", "    ip: str = raw\n"),
        ("parenthesised", "    ip = (raw)\n"),
        ("trailing_comment", "    ip = raw  # normalize\n"),
        ("multiline_rhs", "    ip = (\n        raw.split(',')[0].strip()\n    )\n"),
    ):
        d = tmp_path / name
        d.mkdir()
        (d / "rate.py").write_text(
            "from fastapi import Request\n\n\n"
            "def check(req: Request) -> None:\n"
            "    raw = req.headers.get('X-Forwarded-For')\n" + rename + "    apply_rate_limit(ip)\n",
            encoding="utf-8",
        )
        findings = ForwardedHeaderBlindTrustGuard().run(d, _python_nodirs_prof(d))
        assert any(
            f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings
        ), f"the {name} one-hop spelling went undetected"


def test_forwarded_header_blind_trust_assignment_sink_still_fires(tmp_path: Path) -> None:
    # Regression guard for the liveness fix: a genuine security DECISION that happens to be an
    # assignment (`blocked = is_rate_limited(ip)`) must still fire. The sanitizer-kill rule below
    # is scoped to reassignments of an ALREADY-tracked name, so it must not swallow this.
    (tmp_path / "rate.py").write_text(
        "from fastapi import Request\n\n\n"
        "def check(req: Request) -> bool:\n"
        "    ip = req.headers.get('X-Forwarded-For')\n"
        "    blocked = is_rate_limited(ip)\n"
        "    return blocked\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_kwarg_in_multiline_call_is_not_an_alias(
    tmp_path: Path,
) -> None:
    # FP-bait for the widening, and the trap that sank the earlier line-regex attempt: a keyword
    # argument on its own line inside a multi-line call is character-for-character an assignment to
    # a line regex. `user_id=raw` is a kwarg to audit_log and rebinds nothing; an `ast.keyword` is
    # not an `ast.Assign`, so it cannot reach the alias set by construction.
    (tmp_path / "handler.py").write_text(
        "from fastapi import Request\n\n\n"
        "def handle(req: Request, user_id: str) -> None:\n"
        "    raw = req.headers.get('X-Forwarded-For')\n"
        "    audit_log(\n        user_id=raw,\n        method='GET',\n    )\n"
        "    apply_rate_limit(user_id)\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_assignment_inside_string_literal_is_not_an_alias(
    tmp_path: Path,
) -> None:
    # FP-bait: a rename written inside a triple-quoted prompt/docstring is `ast.Constant`, not an
    # assignment, so it cannot contribute an alias — an LLM system prompt carrying example code is
    # exactly the shape this repo's stacks contain.
    (tmp_path / "handler.py").write_text(
        "from fastapi import Request\n\n\n"
        "def handle(req: Request) -> str:\n"
        "    raw = req.headers.get('X-Forwarded-For')\n"
        '    prompt = """\n    Example config:\n        ip = raw\n        apply_rate_limit(ip)\n    """\n'
        "    return prompt\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_nested_def_param_shadow_is_not_an_alias(
    tmp_path: Path,
) -> None:
    # #772 High 1 (nested-def half): a nested `def` parameter that SHADOWS the header name is a
    # different scope with no dataflow relationship to the header value. The binding
    # `pieces = forwarded.split(";")` inside `_split` must not alias the outer `forwarded`.
    (tmp_path / "handler.py").write_text(
        "from fastapi import Request\n\n\n"
        "async def handler(request: Request):\n"
        "    forwarded = request.headers.get('X-Forwarded-For', '')\n"
        "    log.info('xff=%s', forwarded)\n"
        "    def _split(forwarded: str) -> list:\n"
        "        pieces = forwarded.split(';')\n"
        "        return apply_rate_limit_rules(pieces)\n"
        "    return {'rules': _split(POLICY_HEADER)}\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_nested_def_sink_on_shadowed_param_is_silent(
    tmp_path: Path,
) -> None:
    # Stronger nested-def bait: the sink inside the nested scope references the SHADOWING parameter
    # `forwarded` by name. A scope-blind, line-regex sink search would fire on it; the scope-scoped
    # sweep skips the nested function's own body entirely.
    (tmp_path / "handler.py").write_text(
        "from fastapi import Request\n\n\n"
        "async def handler(request: Request):\n"
        "    forwarded = request.headers.get('X-Forwarded-For', '')\n"
        "    def _split(forwarded: str):\n"
        "        return apply_rate_limit(forwarded)\n"
        "    return _split(POLICY_HEADER)\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_comprehension_shadow_is_not_an_alias(tmp_path: Path) -> None:
    # #772 High 1 (comprehension half): `denied = [ip for ip in load_denied()]` re-binds `ip`
    # inside its own scope, provably unrelated to the header value. A comprehension is not a
    # receiver-rooted chain, so it is never credited as a derivation of the header var it shadows.
    (tmp_path / "handler.py").write_text(
        "from fastapi import Request\n\n\n"
        "async def handler(request: Request):\n"
        "    ip = request.headers.get('X-Forwarded-For', '')\n"
        "    log.info('xff=%s', ip)\n"
        "    denied = [ip for ip in load_denied()]\n"
        "    return {'policy': build_rate_limit(denied)}\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_sanitized_reassignment_kills_the_taint(
    tmp_path: Path,
) -> None:
    # #772 High 2 (liveness): the header value is reassigned through a sanitizer, so it is dead at
    # the sink. A scanner that fires on the remediation is worse than one that misses the bug —
    # the user's rational response is to blanket-suppress it.
    (tmp_path / "handler.py").write_text(
        "from fastapi import Request\n\n\n"
        "async def handler(request: Request):\n"
        "    forwarded = request.headers.get('X-Forwarded-For', '')\n"
        "    client = forwarded.split(',')[0].strip()\n"
        "    client = trusted_client_ip(request, client)\n"
        "    await apply_rate_limit(client)\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_hand_rolled_proxy_check_is_silent(tmp_path: Path) -> None:
    # #772 High 2 (the proxy-aware branch): a hand-rolled trusted-proxy check guards the
    # header-derived binding; the safe else-branch reassigns `client` to a non-header value, which
    # kills the taint. (Disclosed limitation: this analysis is source-order, not control-flow.)
    (tmp_path / "handler.py").write_text(
        "from fastapi import Request\n\n\n"
        "async def handler(request: Request):\n"
        "    forwarded = request.headers.get('X-Forwarded-For', '')\n"
        "    if _peer_is_trusted(request):\n"
        "        client = forwarded.split(',')[0].strip()\n"
        "    else:\n"
        "        client = request.client.host\n"
        "    await apply_rate_limit(client)\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_alias_and_sink_before_header_read_is_silent(
    tmp_path: Path,
) -> None:
    # #772 Medium 1 (ordering): an alias and its sink that sit entirely BEFORE the header read are
    # unrelated code — here `raw` at the top is the function PARAMETER, not the header value the
    # last line binds. Dataflow is forward; the alias search must be directional like the sink one.
    (tmp_path / "handler.py").write_text(
        "from fastapi import Request\n\n\n"
        "def handler(request: Request, raw: str = ''):\n"
        "    addr = raw.upper()\n"
        "    apply_rate_limit(addr)\n"
        "    raw = request.headers.get('X-Forwarded-For', '')\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_unparseable_module_degrades_to_bare_rename(
    tmp_path: Path,
) -> None:
    # #772 Low: when `ast` cannot parse the module the guard degrades to the bare one-hop-rename
    # text scan rather than going silent. Pinned in BOTH directions: the bare rename `ip = raw`
    # still fires through the fallback, and a receiver-rooted derivation (which only the AST path
    # resolves) does NOT — proving the fallback path, not the AST path, is what ran.
    bare = (
        "from fastapi import Request\n\n\n"
        "def check(req: Request) -> bool:\n"
        "    raw = req.headers.get('X-Forwarded-For')\n"
        "    ip = raw\n"
        "    apply_rate_limit(ip)\n"
        "def broken(:\n"  # syntax error -> safe_ast_parse returns None
        "    pass\n"
    )
    (tmp_path / "bare.py").write_text(bare, encoding="utf-8")
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)

    derived = bare.replace("    ip = raw\n", "    ip = raw.split(',')[0].strip()\n")
    d2 = tmp_path / "sub"
    d2.mkdir()
    (d2 / "derived.py").write_text(derived, encoding="utf-8")
    findings2 = ForwardedHeaderBlindTrustGuard().run(d2, _python_nodirs_prof(d2))
    assert not any(
        f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings2
    )


def test_forwarded_header_blind_trust_pragma_silences(tmp_path: Path) -> None:
    # The file-level opt-out: `# security: allow-forwarded-header-trust` anywhere in the file
    # silences it, for when proxy validation is confirmed at the infrastructure layer.
    (tmp_path / "rate.py").write_text(
        "from fastapi import Request\n\n\n"
        "def check_rate_limit(req: Request) -> bool:\n"
        "    # security: allow-forwarded-header-trust\n"
        "    ip = req.headers.get('X-Forwarded-For')\n"
        "    return apply_rate_limit(ip)\n",
        encoding="utf-8",
    )
    assert ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path)) == []


# ── #772 review fix-round: lambda scope, same-line liveness, walrus ──────────────────────────
#
# Findings from the PR #791 clean-context review. Each carries both directions: the FP/FN it fixes
# AND the neighbour that must keep its verdict (a closure over the header is real flow, not a shadow).


def test_forwarded_header_blind_trust_lambda_param_shadow_is_not_a_sink(tmp_path: Path) -> None:
    # Review Issue 1: a lambda parameter that shadows the header name is a different scope. The
    # docstring claimed def/lambda were handled but only def/async-def were; a lambda-shadow FP
    # fired. Masked now by the parameter, like a nested def.
    (tmp_path / "h.py").write_text(
        "from fastapi import Request\n\n\n"
        "def handler(request: Request):\n"
        "    forwarded = request.headers.get('X-Forwarded-For', '')\n"
        "    cb = lambda forwarded: apply_rate_limit(forwarded)\n"
        "    return cb(get_trusted_ip(request))\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_closure_over_header_still_fires(tmp_path: Path) -> None:
    # The other direction, and the reason scope handling is name-level masking rather than
    # excluding the whole nested span: a lambda (or nested def) that CLOSES OVER the header value
    # without rebinding it is real flow and must still fire. Excluding the span would silence this.
    for name, inner in (
        ("lambda", "    cb = lambda: apply_rate_limit(forwarded)\n    return cb()\n"),
        ("nested_def", "    def _f():\n        return apply_rate_limit(forwarded)\n    return _f()\n"),
    ):
        d = tmp_path / name
        d.mkdir()
        (d / "h.py").write_text(
            "from fastapi import Request\n\n\n"
            "def handler(request: Request):\n"
            "    forwarded = request.headers.get('X-Forwarded-For', '')\n" + inner,
            encoding="utf-8",
        )
        findings = ForwardedHeaderBlindTrustGuard().run(d, _python_nodirs_prof(d))
        assert any(
            f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings
        ), f"the {name} closure over the header value should fire"


def test_forwarded_header_blind_trust_nested_def_local_rebind_is_silent(tmp_path: Path) -> None:
    # Completeness of the scope model: a nested def that REASSIGNS the header name to a local
    # (`forwarded = other()`) makes it local throughout that def (Python scoping), so a sink there
    # is not the outer header value. Masked by the nested scope's own bound name, not just its params.
    (tmp_path / "h.py").write_text(
        "from fastapi import Request\n\n\n"
        "def handler(request: Request):\n"
        "    forwarded = request.headers.get('X-Forwarded-For', '')\n"
        "    def _f():\n"
        "        forwarded = compute_local()\n"
        "        return apply_rate_limit(forwarded)\n"
        "    return _f()\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_same_line_kill_does_not_mask_other_sink(
    tmp_path: Path,
) -> None:
    # Review Issue 2 (missed-detection regression vs the pre-fix line-granular kill): when a
    # semicolon-joined line rebinds an unrelated alias to a sanitized value AND passes the still-live
    # header value into a real sink, only the reassigned name is dropped from that line's sink check,
    # not the whole line. The header `ip` must still fire.
    (tmp_path / "h.py").write_text(
        "from fastapi import Request\n\n\n"
        "def handler(request: Request):\n"
        "    ip = request.headers.get('X-Forwarded-For', '')\n"
        "    alt = ip\n"
        "    alt = sanitize(alt); apply_rate_limit(ip)\n"
        "    return None\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_walrus_sanitizer_kills_taint(tmp_path: Path) -> None:
    # Review Issue 3: a sanitizer applied via the walrus operator (`ip := sanitize(ip)`) inside the
    # security predicate's own argument is a reassignment to a non-derivation, so it kills the taint.
    # Must not fire on this remediated shape.
    (tmp_path / "h.py").write_text(
        "from fastapi import Request\n\n\n"
        "def handler(request: Request):\n"
        "    ip = request.headers.get('X-Forwarded-For', '')\n"
        "    if is_rate_limited(ip := sanitize(ip)):\n"
        "        block()\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert not any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)


def test_forwarded_header_blind_trust_walrus_derivation_of_raw_header_fires(tmp_path: Path) -> None:
    # The other direction: a walrus that captures the RAW header value (`x := ip`) and feeds it to
    # the rate limiter is a genuine vulnerability and must fire — the walrus is tracked as a
    # derivation, not silently ignored.
    (tmp_path / "h.py").write_text(
        "from fastapi import Request\n\n\n"
        "def handler(request: Request):\n"
        "    ip = request.headers.get('X-Forwarded-For', '')\n"
        "    if is_rate_limited(x := ip):\n"
        "        block(x)\n",
        encoding="utf-8",
    )
    findings = ForwardedHeaderBlindTrustGuard().run(tmp_path, _python_nodirs_prof(tmp_path))
    assert any(f.rule == "forwarded-header-blind-trust/xff-in-security-context" for f in findings)
