"""Direct unit tests for shared helpers in `agentsec.guards.base` — the route-block walker
`iter_functions` (#281) and the lexer-aware `strip_python_strings` (#366).

The `iter_functions` section:

These lock the observable contract that the four FastAPI route guards (bola,
auth-dependency-not-applied, unauthenticated-file-download, privileged-field-assignment)
depend on, so a rewrite of the walker (issue #281: line heuristic -> ast) can be proven
equivalent. The contract:

  (a) each returned lineno is the 1-based physical line of the `def`;
  (b) the block is the decorator stack + full (possibly multi-line) signature + indented body;
  (c) comment lines (pragmas) survive verbatim in the block, in the stack AND the body tail;
  (d) triple-quoted string content is blanked (line numbers preserved) so docstring examples
      don't leak and stray brackets don't skew boundaries;
  (e) adjacent routes are never merged and an unrelated multi-line expr above a decorator is
      never absorbed.

There were NO direct tests of this function before #281 — parity was only covered indirectly
through the four guards. This file is the walker's own net.
"""
from __future__ import annotations

import ast
import itertools
import random
import re
from collections.abc import Callable
from pathlib import Path

import pytest

from agentsec.detect import StackProfile
from agentsec.guards import base as base_module
from agentsec.guards.base import (
    _STRING_ABUTTING_KEYWORDS,
    AUTH_CALL_ANY,
    AUTH_CALL_NAMED,
    AUTH_CALL_PRIVILEGED,
    LLM_CALL,
    LLM_SDK_CREATE,
    PER_ROUTE_AUTH_FACTORY,
    PER_ROUTE_PRIV_FACTORY,
    RATE_LIMIT_CALL,
    RateLimitWiring,
    _find_sql_close,
    _is_registration,
    _last_unescaped_quotes,
    auth_call_named_with_aliases,
    blank_block_comments,
    blank_disabled_security_schemes,
    blank_line_comments,
    blank_policy_names,
    blank_sql_literals,
    close_paren_map,
    conditional_nodes,
    cross_file_authed_routers,
    enclosing_function,
    enclosing_function_span,
    find_statement_end,
    go_scan_dirs,
    include_router_ref,
    is_dev_compose_file,
    is_example_template_file,
    is_http_middleware,
    is_llm_framework_repo,
    is_llm_sdk_create_call,
    is_nonproduct_path,
    is_reference_sql_path,
    iter_bounded_matches,
    iter_functions,
    iter_statement_spans,
    java_scan_dirs,
    join_dockerfile_continuations,
    js_anchor_is_code,
    js_code_matches,
    js_in_identifier_literal,
    matching_close_paren,
    middleware_scope,
    opens_sql_escape_string,
    php_scan_dirs,
    python_scan_dirs,
    rate_limit_wiring,
    rate_limited_routes,
    registered_middleware_scopes,
    registered_names,
    route_decorator_aliases,
    route_deps_carry_auth,
    route_receiver,
    router_code_view,
    router_resolver_view,
    ruby_scan_dirs,
    same_file_authed_routers,
    security_scheme_var_names,
    split_call_args,
    strip_go_comments,
    strip_hash_comments,
    strip_java_comments,
    strip_js_comments,
    strip_php_comments,
    strip_php_heredocs,
    strip_python_line_comment,
    strip_python_strings,
    strip_ruby_comments,
    strip_sql_comments,
)
from agentsec.guards.dom_xss_sinks import DomXssSinksGuard
from agentsec.guards.js_command_injection import JsCommandInjectionGuard
from agentsec.guards.postmessage_origin import PostmessageOriginGuard
from tests._timing import TimingBudget, assert_growth, assert_within, register
from tests.conftest import mkprofile


def test_strip_js_comments_blanks_line_and_block_preserving_layout() -> None:
    src = "const x = 1; // note\n/* a\n b */\nfoo();\n"
    out = strip_js_comments(src)
    assert len(out) == len(src) and out.count("\n") == src.count("\n")  # layout preserved
    assert "note" not in out and "b */" not in out
    assert out.splitlines()[0].rstrip() == "const x = 1;"  # code kept, trailing comment blanked
    assert out.splitlines()[3] == "foo();"


def test_blank_block_comments_blanks_preserving_layout() -> None:
    src = 'a = 1\n/* a\n b */\nb = "keep"\n'
    out = blank_block_comments(src)
    assert len(out) == len(src) and out.count("\n") == src.count("\n")  # layout preserved
    assert "b */" not in out
    assert out.splitlines()[0] == "a = 1" and out.splitlines()[3] == 'b = "keep"'


def test_blank_block_comments_ignores_openers_inside_strings_and_line_comments() -> None:
    # Regression (#441 CRITICAL): a `/*` inside a string or a line comment is data, not an opener —
    # a naive `/\*.*?\*/` re.sub pairs it with the next `*/` and blanks all the real code between.
    src = 'p = "configs/*catalog"\nreal = true\n/* note */\n'
    assert "real = true" in blank_block_comments(src)
    assert 'p = "configs/*catalog"' in blank_block_comments(src)
    src2 = "# see /* elsewhere\nreal = true\n/* note */\n"
    assert "real = true" in blank_block_comments(src2)
    # a genuine block comment is still blanked
    assert "secret" not in blank_block_comments("a = 1 /* secret */")


def test_blank_block_comments_caps_an_unterminated_opener() -> None:
    # An opener with no `*/` anywhere in the tail must be left inert, never blanked to EOF —
    # the blast-radius cap, so a stray/mis-read `/*` can't delete every finding below it.
    assert blank_block_comments("/* dangling\nreal = true\n") == "/* dangling\nreal = true\n"
    assert blank_block_comments("a = 1 /* dangling") == "a = 1 /* dangling"
    # (A `/*` that DOES have a later `*/` is lexically one comment and is blanked — correct; the
    # phantom-opener classes are covered by the string / line-comment test above.)


def test_blank_block_comments_closing_marker_is_not_string_aware() -> None:
    # THE INVARIANT (#441 re-review): a block comment runs from the first `/*` in CODE context to
    # the first `*/` after it, whatever that `*/` sits in. Quote state is live outside a comment
    # and dead inside one — C99 6.4.9, and HCL/Go, JS and SQL lex it identically. This test pins
    # the closing half; changing it to "string-aware" breaks the next test.
    #
    # Direction A — the input that LOOKS like it wants string-awareness. The `"` is unterminated,
    # so this file is a syntax error in every one of these languages; there is no right answer to
    # give it, only the reference lexer's. Verified byte-for-byte against `gcc -E -P`.
    src = 'a = 0\n/* old HCL used a "*/" delimiter\nb = 1\n*/\nc = 2\n'
    out = blank_block_comments(src)
    assert out.splitlines()[1] == '                     " delimiter'  # comment ended at that `*/`
    assert out.splitlines()[2] == "b = 1"  # ... so the rest is live code, exactly as gcc reads it
    assert len(out) == len(src) and out.count("\n") == src.count("\n")


def test_blank_block_comments_odd_quote_in_a_comment_does_not_run_on() -> None:
    # Direction B, and the reason direction A must stay as it is. This file is ORDINARY, VALID
    # HCL: a comment is allowed to contain one `"`. Were the closing search string-aware, that
    # lone quote would swallow the `*/`, run the comment on to the next `*/` further down, and
    # blank the live `publicly_accessible = true` below it — a silent HIGH miss. Trading a false
    # negative on valid input for a cosmetic gain on invalid input is the wrong trade.
    src = '/* use a " to quote strings */\npublicly_accessible = true\n/* a later comment */\n'
    out = blank_block_comments(src)
    assert out.splitlines()[1] == "publicly_accessible = true"  # survives — still findable
    assert "quote strings" not in out and "a later comment" not in out  # both comments blanked


def test_blank_block_comments_hcl_strings_never_cross_a_line() -> None:
    # An HCL quoted template may not contain a newline, so an unterminated `"` is capped at the
    # line end — including one held open by a trailing backslash (`"a \` + newline).
    assert blank_block_comments('s = "a\nreal = 1 /* z */\n') == 's = "a\nreal = 1        \n'
    # (the backslash form used to hold the string open across the newline, so the `/* z */` on the
    # next line was swallowed as string content and left live — an FP the caller then reports on)
    assert blank_block_comments('s = "a \\\nreal = 1 /* z */\n') == 's = "a \\\nreal = 1        \n'
    # ... while a genuine escaped quote keeps the string open, so its `/*` stays inert.
    assert blank_block_comments('s = "a \\" /* b"\nreal = 1\n') == 's = "a \\" /* b"\nreal = 1\n'


def test_blank_block_comments_preserves_layout_with_crlf() -> None:
    # Finding line numbers are computed off the blanked copy, so CRLF must survive untouched.
    src = 'resource "x" {\r\n  /* publicly_accessible = true */\r\n  ok = false\r\n}\r\n'
    out = blank_block_comments(src)
    assert len(out) == len(src) and out.count("\r\n") == src.count("\r\n")
    assert len(out.splitlines()) == len(src.splitlines())
    assert "publicly_accessible = true" not in out and out.splitlines()[2] == "  ok = false"


def test_blank_block_comments_sql_dialect() -> None:
    # The SQL guards can adopt the same helper (issue #500) via ONE preset — `dialect="sql"` —
    # never by hand-picking `quotes`/`line_comments` and inheriting HCL's other two string rules.
    src = "select '/*' as x -- /* note\n, 1 /* real */ , 2\n"
    out = blank_block_comments(src, dialect="sql")
    assert "'/*' as x" in out and "-- /* note" in out and ", 1" in out and ", 2" in out
    assert "real" not in out


def test_blank_block_comments_sql_string_rules_are_postgres_not_hcl() -> None:
    # Three undisclosed assumptions the SQL knobs used to carry (#441 re-review). Each probe is a
    # real .sql shape whose live `create policy` must NOT be blanked — i.e. a false-negative probe.
    live = "create policy p on t using (true);"
    # (a) a quote is escaped by DOUBLING it, not with a backslash ...
    assert live in blank_block_comments(f"insert into t values ('it''s /*');\n{live}\n/* z */\n",
                                        dialect="sql")
    # (b) ... and a backslash is an ordinary character (standard_conforming_strings), so it must
    #     not eat the closing quote of `'C:\'` and leave the rest of that line mis-read as string
    #     content — there, a real block comment goes unrecognised and its commented-OUT policy
    #     stays live for the caller to report on.
    out_b = blank_block_comments(
        f"update t set p = 'C:\\'; /* create policy q on t using (true); */\n{live}\n", dialect="sql"
    )
    assert "create policy q" not in out_b and live in out_b
    # (c) a Postgres literal MAY span lines; bailing at the newline re-enters "code" mode inside
    #     the literal, where the `/*` of `docs/*.md` pairs with a later `*/` and blanks live SQL.
    spanning = f"comment on table t is 'line one\nsee docs/*.md for details';\n{live}  /* audited */\n"
    assert live in blank_block_comments(spanning, dialect="sql")
    # ... capped in the other direction too: a quote with no partner before EOF is data, not a
    # licence to skip the whole tail (so the `/* z */` below it is still recognised and blanked).
    capped = blank_block_comments(f"select 'unclosed\n{live}\n/* z */\n", dialect="sql")
    assert live in capped and "z" not in capped
    # and a genuinely commented-out policy is still blanked
    assert "using (true)" not in blank_block_comments(f"/* {live} */\n", dialect="sql")


def test_blank_block_comments_sql_honors_pg_escape_strings() -> None:
    # Issue #500. Postgres `E'…'` honors a backslash escape REGARDLESS of
    # standard_conforming_strings, so `E'it\'s'` closes at its FINAL quote. Reading the escaped
    # quote as the close resumed code-mode lexing INSIDE the literal, where its own `/*` became a
    # real opener and blanked live SQL through to the next `*/` — the exact shape that silenced
    # rls-permissive-policy and rls-multiple-permissive-policies.
    live = "create policy p on t using (true);"
    poisoned = f"comment on table t is E'it\\'s a note /* a fake opener';\n{live}\n/* z */\n"
    out = blank_block_comments(poisoned, dialect="sql")
    assert live in out, "an E'…' escape string blanked a live statement"
    assert "z" not in out, "the genuine trailing comment must still be blanked"
    # Lowercase prefix too.
    assert live in blank_block_comments(poisoned.replace("E'", "e'", 1), dialect="sql")
    # FP-bait, kept adjacent so the two can never be traded: an ORDINARY literal still does not
    # honor the backslash, so `'C:\'` closes at its own quote (#441's false positive).
    out_fp = blank_block_comments(
        f"update t set p = 'C:\\'; /* create policy q on t using (true); */\n{live}\n", dialect="sql"
    )
    assert "create policy q" not in out_fp and live in out_fp
    # Length/line preservation is the whole reason this blanks rather than deletes.
    assert len(out) == len(poisoned) and out.count("\n") == poisoned.count("\n")


def test_blank_block_comments_hcl_heredoc_body_is_not_an_opener() -> None:
    # Issue #602, case 1 of its measured table: the `/*` of an unquoted shell glob inside a
    # heredoc body paired with an ordinary trailing comment and blanked the live resource between
    # them — 1 finding to 0, exit 0, nothing said. A heredoc body is raw data to HCL's lexer, so
    # it is SKIPPED (left live, never blanked): nothing inside one can open a comment.
    src = (
        'resource "aws_instance" "b" {\n'
        "  user_data = <<USERDATA\n"
        "#!/bin/sh\n"
        "cp -r /opt/app/* /srv/app/\n"
        "USERDATA\n"
        "}\n"
        "publicly_accessible = true\n"
        "/* managed by platform-team */\n"
    )
    out = blank_block_comments(src)
    assert "publicly_accessible = true" in out  # the live attribute survives — the #602 miss
    assert "cp -r /opt/app/*" in out  # the body is skipped, not blanked — still readable
    assert "managed by" not in out  # ... while the genuine trailing comment is still blanked
    assert len(out) == len(src) and out.count("\n") == src.count("\n")


def test_blank_block_comments_hcl_heredoc_variants() -> None:
    # `<<-EOT` with an INDENTED terminator — the `_tf_line_scan` terminator rule: a line whose
    # STRIPPED content equals the tag, for both intro forms.
    src = "x = <<-EOT\n  /* not a comment\n  EOT\nreal = true\n/* z */\n"
    out = blank_block_comments(src)
    assert "real = true" in out and "not a comment" in out and "z" not in out
    # A tag-LOOKALIKE line with trailing text does not terminate.
    src2 = "x = <<EOT\nEOT is coming\nEOT\nreal = true\n/* z */\n"
    out2 = blank_block_comments(src2)
    assert "real = true" in out2 and "z" not in out2
    # A heredoc opened mid-expression (`base64encode(<<EOF`) counts — the `=`-anchored
    # `_TF_HEREDOC_OPEN` shape would miss it, and a blanking pass must not.
    src3 = "x = base64encode(<<EOF\ncp /opt/app/*\nEOF\n)\nreal = true\n/* z */\n"
    out3 = blank_block_comments(src3)
    assert "real = true" in out3 and "z" not in out3
    # CRLF intro/terminator lines survive with layout intact.
    src4 = "x = <<EOT\r\n/* raw\r\nEOT\r\nreal = true\r\n/* z */\r\n"
    out4 = blank_block_comments(src4)
    assert "real = true" in out4 and "z" not in out4 and len(out4) == len(src4)


def test_blank_block_comments_hcl_heredoc_caps_and_phantom_baits() -> None:
    # An intro with NO terminator line anywhere is data, never a licence to skip the tail — the
    # same no-partner cap every span in this scanner carries. With no `*/` either, the
    # unmatched-opener cap then keeps the whole tail intact ...
    src = "x = <<EOF\nbody /* still scanned\nreal = true\n"
    assert blank_block_comments(src) == src
    # ... and WITH a later `*/`, the unterminated body's `/*` pairs with it exactly as pre-#602.
    # An unterminated heredoc is an HCL syntax error: it earns no opaqueness, only the caps.
    src2 = "x = <<EOF\nbody /* opener\nreal = true\n*/ tail\n"
    assert "real = true" not in blank_block_comments(src2)
    # Phantom-intro baits (the widening direction): `<<` inside a string, a line comment, or a
    # block comment is never a body-skip — the genuine comment that follows must still be blanked.
    for bait in (
        's = "y <<EOF"\n/* note */\nreal = true\n',
        "# x = <<EOF\n/* note */\nreal = true\n",
        "/* x = <<EOF */\nreal = true\n/* note */\n",
    ):
        out = blank_block_comments(bait)
        assert "note" not in out and "real = true" in out
    # `1 <<2` is the phantom the brace-walkers' `=`-anchor exists to kill; here the
    # identifier-shaped tag (no digit lead) kills it instead — line `2` below is NOT a terminator.
    src3 = "a = 1 <<2\n2\n/* note */\nreal = true\n"
    out3 = blank_block_comments(src3)
    assert "note" not in out3 and "real = true" in out3


def test_blank_block_comments_sql_dollar_quoted_body_is_not_an_opener() -> None:
    # Issue #602's SQL half, measured through rls-permissive-policy: dollar-quoted PROSE is not a
    # string context to the scanner, so the `/*` of `docs/*.md` opened, a trailing comment
    # closed, and the live policy between them was blanked. Same treatment as the heredoc: the
    # body is raw data, skipped and left live.
    live = "create policy p on t using (true);"
    src = f"insert into help values ('f', $$See docs/*.md for details$$);\n{live}\n/* z */\n"
    out = blank_block_comments(src, dialect="sql")
    assert live in out and "docs/*.md" in out and "z" not in out
    # The tagged form; a `$$` INSIDE a `$tag$` body belongs to the body (Postgres closes only on
    # the exact same tag), and a `/*` in the body stays inert.
    src2 = f"create function f() as $fn$ select 1; /* $$ docs/*.md $$ */ $fn$;\n{live}\n/* z */\n"
    out2 = blank_block_comments(src2, dialect="sql")
    assert live in out2 and "z" not in out2 and "docs/*.md" in out2
    assert len(out2) == len(src2) and out2.count("\n") == src2.count("\n")


def test_blank_block_comments_sql_dollar_quote_caps_and_phantom_baits() -> None:
    live = "create policy p on t using (true);"
    # `$1` positional parameters and a lone `$` are data, not delimiters (a tag cannot start with
    # a digit) — the genuine comment right after must still be blanked.
    out = blank_block_comments(f"execute 'q' using $1; /* note */\n{live}\n", dialect="sql")
    assert "note" not in out and live in out
    # An UNCLOSED `$tag$` is data, never a licence to skip the tail: the commented-OUT policy
    # below it stays blanked (the FP-bait) while the live one still survives.
    src2 = f"select $body$ unclosed\n/* {live} */\n{live}\n"
    out2 = blank_block_comments(src2, dialect="sql")
    assert out2.count("using (true)") == 1 and live in out2
    # `$$` inside a quoted string or a line comment is inert — no phantom body from either.
    src3 = f"select '$$ not a body $$'; -- $$ nope\n/* note */\n{live}\n"
    out3 = blank_block_comments(src3, dialect="sql")
    assert live in out3 and "'$$ not a body $$'" in out3 and "note" not in out3
    # ... and the residual the cap leaves, pinned on purpose (the SQL mirror of the heredoc caps
    # test, #825 review): an unterminated body earns no opaqueness, so a bare `/*` in it pairs
    # with a genuine later `*/` exactly as pre-#602. An unclosed `$tag$` is a SQL syntax error;
    # malformed input gets the caps, not a completeness guarantee.
    src4 = f"select $body$ opener /* \n{live}\n*/ tail\n"
    assert "using (true)" not in blank_block_comments(src4, dialect="sql")


@pytest.mark.slow
def test_blank_block_comments_opaque_body_close_search_is_linear() -> None:
    """Distinct unterminated tags, the shape a per-opener close-search is quadratic on.

    HCL: n intros each rescanning the remaining lines for a terminator; SQL: n failed `str.find`s
    each walking to EOF. This scanner runs over untrusted repos (audit, corpus-scan), so the
    lazily-built one-pass indexes answer every close search instead — measured naive forms at
    n=30000: 76.3s (hcl line-rescan) / 4.1s (sql find) against ~0.2s healthy. Growth-ratio
    assertion, not a wall-clock budget: the healthy-to-regression window on the SQL half is too
    narrow for MIN_HEADROOM (tests/_timing.py), and machine speed cancels out of a ratio."""
    # Four sizes, not three: `classify`'s median only discards an outlier from THREE ratios up
    # (at two it is their mean, which is #758). NOT halved with its siblings (2026-10-23): at
    # (500..32000) the SQL per-opener `find` mutant read ~5.5/10/10.5 under load and escaped once in
    # eight runs (an inflated smallest reading), where these sizes caught it every time. #1145 review.
    sizes = (1000, 4000, 16000, 64000)
    tail = "real = true\n/* z */\n"
    hcl_texts = {n: "".join(f"x = <<T{i}\n" for i in range(n)) + tail for n in sizes}
    sql_texts = {n: "".join(f"select $t{i}$ " for i in range(n)) + "\n" + tail for n in sizes}
    out_hcl: dict[int, str] = {}
    out_sql: dict[int, str] = {}

    def scan_hcl(n: int) -> None:
        out_hcl[n] = blank_block_comments(hcl_texts[n])

    def scan_sql(n: int) -> None:
        out_sql[n] = blank_block_comments(sql_texts[n], dialect="sql")

    assert_growth(scan_hcl, sizes, expected="linear")
    assert_growth(scan_sql, sizes, expected="linear")
    # A scan that stopped recognising comments would also be fast, so assert it still did the
    # work: the genuine trailing comment is blanked, the live line and every tag survive.
    for n in sizes:
        for out, src in ((out_hcl[n], hcl_texts[n]), (out_sql[n], sql_texts[n])):
            assert "real = true" in out and "z" not in out
            assert len(out) == len(src) and out.count("\n") == src.count("\n")
        assert f"<<T{n - 1}" in out_hcl[n] and f"$t{n - 1}$" in out_sql[n]


def test_opens_sql_escape_string_requires_a_bare_prefix() -> None:
    # The `E` prefix must be BARE, not the tail of an identifier — SQL is full of keywords ending
    # in `e` (`case`, `date`, `value`, `type`, `true`) that can sit directly against a quote in a
    # typed-literal (`date'2020-01-01'`). Treating those as escape strings would silently start
    # honoring backslashes in ordinary literals, which is the `'C:\'` false positive coming back.
    assert opens_sql_escape_string("E'x'", 1) is True
    assert opens_sql_escape_string("e'x'", 1) is True
    assert opens_sql_escape_string("is E'x'", 4) is True      # preceded by a space
    assert opens_sql_escape_string("(E'x')", 2) is True       # preceded by punctuation
    assert opens_sql_escape_string("date'x'", 4) is False     # identifier tail
    assert opens_sql_escape_string("case'x'", 4) is False
    assert opens_sql_escape_string("t1e'x'", 3) is False      # digits are identifier-ish too
    assert opens_sql_escape_string("_e'x'", 2) is False
    assert opens_sql_escape_string("'x'", 0) is False         # nothing before the quote
    assert opens_sql_escape_string("x'y'", 1) is False        # not an `e` at all


def test_strip_sql_comments_honors_pg_escape_strings() -> None:
    # Issue #500, the same blind spot in the OTHER SQL scanner in this module. `strip_sql_comments`
    # is used by 9 guard modules; before the fix an `E'…'` literal mis-closed, the `/*` in its text
    # was lexed as a real opener, and the live SQL below it was DELETED (measured: public-table-rls
    # and pg-anon-grant both went 1 finding → 0).
    live = "grant select on public.docs to anon;"
    poisoned = f"comment on table docs is E'it\\'s a note /* x';\n{live}\n/* trailing */\n"
    out = strip_sql_comments(poisoned)
    assert live in out, "an E'…' escape string deleted a live statement"
    assert "trailing" not in out, "the genuine trailing comment must still be stripped"
    # FP-bait: a backslash in an ordinary literal is not an escape.
    assert live in strip_sql_comments(f"update t set p = 'C:\\';\n{live}\n")
    # The #435 direction must not be undone: a commented-out hardening statement still gets
    # stripped, including when the stray quote sits inside an E-string payload.
    src = (
        "create table public.notes (id int, body text);\n"
        "COPY public.notes (id, body) FROM stdin;\n1\t{p}\n\\.\n"
        "-- ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
    )
    for payload in ("don't panic", r"E'don\'t panic'"):
        assert "ENABLE ROW LEVEL SECURITY" not in strip_sql_comments(src.format(p=payload))


def test_blank_sql_literals_is_same_length_and_keeps_delimiters() -> None:
    # #801 / #827 round 3 H1: the shared literal blanker composes `_find_sql_close` +
    # `opens_sql_escape_string`; its contract is "same length, content spaced, delimiters kept".
    src = "USING (x = 'a OR b)' AND y = \"or\" AND z = $$c)$$)"
    out = blank_sql_literals(src)
    assert len(out) == len(src)
    assert out == "USING (x = '       ' AND y = \"or\" AND z = $$  $$)"
    # `"…"` identifiers are left in place by default, space-filled on request — same length both ways.
    ident = blank_sql_literals(src, identifiers=True)
    assert len(ident) == len(src)
    assert ident == "USING (x = '       ' AND y = \"  \" AND z = $$  $$)"


@pytest.mark.parametrize(
    ("src", "expected"),
    [
        # a doubled quote stays INSIDE the literal — one literal, not two
        ("x = 'it''s' OR t", "x = '     ' OR t"),
        # E'…' honours backslash escapes: the OR after it is code, whatever the escape parity
        (r"x = E'a\'b' OR t", "x = E'    ' OR t"),
        (r"x = E'a\'b\'c' OR t", "x = E'       ' OR t"),
        # an ordinary literal does NOT: `'C:\'` closes at its own quote (issue #441 direction)
        (r"p = 'C:\' OR t", "p = '   ' OR t"),
        # dollar quoting, anonymous and tagged; the tag itself is the delimiter and stays
        ("x = $$auth.uid()$$ OR t", "x = $$          $$ OR t"),
        ("x = $t$auth.uid()$t$ OR t", "x = $t$          $t$ OR t"),
        # a `$$` INSIDE an ordinary literal is content, not a dollar quote (#827 round 4)
        ("x = 'a$$b' OR t", "x = '    ' OR t"),
        # a quote inside a dollar body is content too — the body is consumed as one unit
        ("x = $$it's a trap$$ OR t", "x = $$           $$ OR t"),
        # a `$$` glued to an identifier is part of the identifier, not a dollar-quote opener
        ("x$$ = 1 OR t", "x$$ = 1 OR t"),
        # a `'` inside a `"…"` identifier never opens a literal
        ("\"it's\" = 1 OR t", "\"it's\" = 1 OR t"),
        # an unclosed literal blanks to the end of text (never resumes code mode inside it)
        ("x = 'oops OR t", "x = '         "),
        ("x = $$oops OR t", "x = $$         "),
        # a newline inside a literal is kept, so line counting on the view stays aligned
        ("x = 'a\nb' OR t", "x = ' \n ' OR t"),
    ],
)
def test_blank_sql_literals_pairing(src: str, expected: str) -> None:
    out = blank_sql_literals(src)
    assert out == expected
    assert len(out) == len(src)


def test_blank_sql_literals_composes_with_strip_sql_comments_length_preserving() -> None:
    src = "CREATE POLICY p ON t /* c */ USING (x = 'a--b' -- note\n  AND y = E'q\\'r');\n"
    stripped = strip_sql_comments(src, blank=True)
    out = blank_sql_literals(stripped)
    assert len(out) == len(src)
    assert "AND y" in out and "note" not in out and "a--b" not in out


def test_find_sql_close_miss_is_not_monotone_by_doubling_parity() -> None:
    # Pins the counterexample behind the corrected comment in `strip_sql_comments` (#500 review).
    # The quote-close caches are MISS caches, not proofs of monotonicity: a scan that finds no
    # close from one start can be followed by a later start that does close, by quote-DOUBLING
    # parity alone — no backslash escapes involved. The comment used to assert the opposite, which
    # is the same "a comment states the opposite of the truth" class this PR exists to fix.
    #
    # If a future change makes the pairing genuinely monotone, this test fails and the comment
    # should be revisited — that is the point of pinning it rather than leaving it as prose.
    sql = "'''aaa''"
    assert _find_sql_close(sql, 1, "'", len(sql)) == -1
    assert _find_sql_close(sql, 2, "'", len(sql)) == 2
    # The bound is not tight in the safe direction: an over-eager -1 emits the quote as ordinary
    # text, so nothing is hidden that a live scan would have shown. The visible output is unchanged.
    assert strip_sql_comments(sql) == sql


def test_strip_sql_escape_cache_would_have_hidden_a_real_comment() -> None:
    # THE discriminating counterexample for the removed escape-scan miss cache (#603 fresh-eyes
    # review). Nine characters, and unlike its siblings below it FAILS against both the cached
    # round-1 implementation and pre-#500 `main`, so it is evidence rather than decoration.
    #
    # With the cache: the unterminated `e'\` records a genuine full-tail miss, the next `e''` is
    # served -1 from the latched boolean without a scan, its quote is emitted as ordinary text, and
    # its sibling is released to the main loop to pair with the trailing `'`. That parity shift
    # swallows the `--` as phantom string content, so a REAL comment reaches the consumer as
    # apparently-live SQL. Removing the cache was therefore a correctness fix, not a tidy-up.
    assert strip_sql_comments("e'e''--\\'") == "e'e''"
    # The same shape with something worth hiding inside it: a commented-out statement must never
    # reach a guard as live SQL.
    assert "DROP POLICY" not in strip_sql_comments("e'e''--\\' DROP POLICY p;")


def test_strip_sql_escape_string_miss_does_not_silence_a_later_statement() -> None:
    # #603 review, Medium 1. The escape scan used to carry a miss cache: once one `E'…` found no
    # close, every later E-literal was served -1 without being scanned. These are the shapes that
    # READ that cache, which the deleted wall-clock test never reached.
    #
    # HONEST LIMIT, measured: reading the cache is NOT the same as being sensitive to its presence,
    # and this input family is not. It passes unchanged against pre-#500 `main`, against the cached
    # round-1 code, and here, because no `--`/`/*` sits between the mis-paired positions in this
    # shape, so the bad pairing has nothing visible to swallow. It pins current behaviour and
    # nothing more. The discriminator is `test_strip_sql_escape_cache_would_have_hidden_a_real_comment`
    # above; do not read a green run here as evidence about the cache.
    live = "grant select on public.docs to anon;"
    for prefix in (r"E'\'", r"E'\' E''", r"E'\'" + " E''" * 50):
        out = strip_sql_comments(f"select {prefix};\n{live}\n/* trailing */\n")
        assert live in out, f"an unterminated E-string deleted a live statement after {prefix!r}"
        assert "trailing" not in out, "the genuine trailing comment must still be stripped"


def test_strip_sql_repeated_escape_string_misses_stay_linear() -> None:
    # Pins the BOUND the removed cache was supposed to provide, on an input that actually exercises
    # it. `E'\'` leaves an unterminated escape string, and each following `E''` is an E-quote the
    # first scan skipped, which is the only shape that could ever have read the cache: 32,000 reads
    # at n=32,000. Measured 4.0x growth per 4x of input with and without the cache, worst case 30ms
    # against this 1.0s budget, so this fails on a genuinely quadratic escape scan and not on the
    # presence or absence of a cache (#603).
    import time

    start = time.monotonic()
    strip_sql_comments(r"E'\'" + " E''" * 32_000)
    assert time.monotonic() - start < 1.0, "repeated escape-string misses went superlinear"


def test_strip_js_comments_ignores_delimiters_inside_strings() -> None:
    # A `//` or `/*` inside a string/template literal is NOT a comment.
    assert strip_js_comments('const u = "http://x"; a();') == 'const u = "http://x"; a();'
    assert strip_js_comments("const s = '/* x */'; b();") == "const s = '/* x */'; b();"


def test_strip_js_comments_regex_literal_is_not_misread_as_a_comment() -> None:
    # Regression (PR #407 fixup review, CRITICAL): a regex literal ending in an escaped slash
    # (`/\//`, or the Express path matcher `/^\/api\//`) embeds a `//` that a naive scanner blanks
    # as a comment, swallowing the rest of the line. The regex must be kept as code.
    src = r"const re = /\//g; nodeIntegration: true"
    assert "nodeIntegration: true" in strip_js_comments(src)
    assert "nodeIntegration: true" in strip_js_comments(r"app.use(/^\/api\//, h); nodeIntegration: true")
    # a genuine trailing comment after a regex literal is still stripped
    assert "secret" not in strip_js_comments(r"const re = /a\/b/g; // secret")
    # a real division is not misread as a regex that swallows a following comment
    assert "note" not in strip_js_comments("const r = a / b; // note") and \
        "a / b" in strip_js_comments("const r = a / b; // note")


def test_strip_js_comments_regex_after_control_paren_is_not_division() -> None:
    # Regression (PR #407 r3, CRITICAL): a regex right after a control-flow head's `)` — `if (x) /re/`
    # — must be read as a regex, not division, so its internal `/` doesn't re-trigger comment blanking.
    assert "nodeIntegration: true" in strip_js_comments(r"if (isApi) /\//.test(p); nodeIntegration: true")
    # ...while a CALL's `)` is still division, so a genuine trailing comment is still stripped.
    assert "secret" not in strip_js_comments("const r = fn() / 2; // secret")


def test_strip_js_comments_unterminated_block_comment_is_not_blanked_to_eof() -> None:
    # Regression (PR #407 r3, CRITICAL blast-radius cap): a `/*` with no closing `*/` (e.g. produced by
    # a mis-classified regex like `/^\/*api/`) must NOT blank across the file and drop a finding on a
    # LATER line. An unterminated /* is left intact.
    src = (
        "const a = 'nodeIntegration: true';\n"
        "if (x) { } /^\\/*api/.test(p);\n"
        "const b = 'webSecurity: false';\n"
    )
    out = strip_js_comments(src)
    assert "webSecurity: false" in out  # the later line survives — no cross-file blanking


def test_strip_js_comments_postfix_incdec_before_division_strips_trailing_comment() -> None:
    # Regression (PR #407 r3, Minor): `x++ / y` is division (postfix ++ yields a value), so a trailing
    # `//` comment after it must still be stripped rather than swallowed as fake regex content.
    assert "secret" not in strip_js_comments("const z = i++ / y; // secret")
    assert "secret" not in strip_js_comments("const z = i-- / y; // secret")


def test_strip_js_comments_preserves_splitlines_count_for_boundary_chars() -> None:
    # Regression (PR #407 fixup review, Minor): blanking must never replace a `str.splitlines()`
    # boundary char (\v \f \x1c-\x1e \x85    ) with a space, else raw/stripped line lists
    # diverge and every downstream line number shifts.
    for bad in ("\x0b", "\x0c", "\x1c", "\x85", " ", " "):
        src = f"a(); /* c{bad}d */ b();\nfoo();\n"
        out = strip_js_comments(src)
        assert len(out.splitlines()) == len(src.splitlines()), f"boundary {bad!r} shifted line count"


def test_strip_php_heredocs_preserves_splitlines_count_for_boundary_chars() -> None:
    # PR #884 review regression (reproduced): _blank_line_keep_terminator blanked any splitlines()
    # boundary char that was not \n/\r (\v \f \x1c-\x1e \x85 LS/PS) when it terminated a heredoc-body
    # fragment. php_code_injection/php_command_injection pair text.splitlines() with
    # strip_php_heredocs(text).splitlines() under zip(..., strict=True); a dropped split point raised
    # ValueError and disabled the WHOLE guard on that file's repo. Same invariant the JS/HCL/SQL
    # strippers above hold — a blanked char is a space, a boundary char is left intact.
    for bad in ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " "):
        src = f"<?php\n$x = <<<EOT\nbody{bad}more\nEOT;\n"
        out = strip_php_heredocs(src)
        assert len(out.splitlines()) == len(src.splitlines()), f"boundary {bad!r} shifted line count"
        assert len(out) == len(src), f"boundary {bad!r} changed length"


def test_strip_js_comments_invariants_hold_under_fuzz() -> None:
    # Property-style: length and splitlines()-count are preserved for arbitrary JS-ish input, so the
    # line-number/pragma alignment every guard relies on can never silently drift. Stdlib `random`
    # with a fixed seed (deterministic, zero-dep) — the hand-picked cases missed the regex class.
    import random

    rng = random.Random(1234)
    alphabet = list("abc/*'\"`\\ \n\r\t;=(){}[].req123gimnodeIntegration:true \x0b\x0c")
    for _ in range(4000):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        for kw in (
            {}, {"strip_strings": True}, {"strip_regex": True}, {"strip_strings": True, "strip_regex": True},
            {"strip_strings": True, "keep_substitutions": True},
        ):
            out = strip_js_comments(s, **kw)  # type: ignore[arg-type]
            assert len(out) == len(s)
            assert len(out.splitlines()) == len(s.splitlines())


def test_strip_js_comments_strip_strings_blanks_contents_not_delimiters() -> None:
    out = strip_js_comments("const s = 'req.count'; const q = req.query.x;", strip_strings=True)
    assert "req.count" not in out            # string contents blanked
    assert "req.query.x" in out              # real member access survives
    assert out.count("'") == 2               # delimiters kept
    # an escaped quote does not prematurely close the string
    out2 = strip_js_comments(r'const s = "a\"req.x"; y();', strip_strings=True)
    assert "req.x" not in out2 and out2.endswith("y();")


def test_strip_js_comments_pathological_unterminated_block_is_linear() -> None:
    # Regression (PR #407 r4, Major): the unterminated-`/*` blast-radius cap must stay O(n). A failed
    # `find("*/")` guarantees failure for every later `/*`, so the miss is cached; without that, a
    # `"/*x"*N` input re-scans the whole tail at each `/*` — an O(n^2) DoS on untrusted target-repo
    # source (agentsec scans attacker-controllable files, incl. inside a `ci add self-audit` gate).
    # The same cap inside a `${…}` substitution (#543) shares the miss cache, so both are measured.
    # A growth ratio, not a wall-clock budget: #1124 put both scans under one 3.0 s budget, which
    # flaked under load (Batch 273 review); machine speed cancels out of a ratio.
    # Small enough that a regression fails on its "measured quadratic" verdict, not on the pytest timeout
    # (PR #1136 review, L1).
    sizes = [8_000, 16_000, 32_000, 64_000]
    plain = {n: "/*x" * n for n in sizes}  # no closing */ anywhere
    sub = {n: "`${" + plain[n] for n in sizes}
    for n in sizes:
        assert len(strip_js_comments(plain[n])) == len(plain[n])  # invariant still holds
        assert len(strip_js_comments(sub[n], strip_strings=True)) == len(sub[n])

    def scan_plain(n: int) -> None:
        strip_js_comments(plain[n])

    def scan_sub(n: int) -> None:
        strip_js_comments(sub[n], strip_strings=True)

    assert_growth(scan_plain, sizes, expected="linear")
    assert_growth(scan_sub, sizes, expected="linear")


def test_strip_js_comments_reserved_word_as_member_name_is_not_a_control_head() -> None:
    # Regression (PR #407 r4, Minor): `obj.if(x)` uses a reserved word as a MEMBER name (legal JS),
    # so its `(` is not a control-flow head — a following `/` is division, and the trailing `//`
    # comment must be stripped rather than swallowed as fake regex content (FP-noise, not data loss).
    assert "secret" not in strip_js_comments(r"obj.if(x) / y; // secret")
    assert "note" not in strip_js_comments(r"foo . while(x) / y; // note")  # whitespace around the dot
    # ...while a REAL control head (`if (...)` at statement start) is still regex-aware, unchanged.
    assert "nodeIntegration: true" in strip_js_comments(r"if (isApi) /\//.test(p); nodeIntegration: true")
    # Same class at the SIBLING keyword site (PR #407 r5, Medium): `_REGEX_PRECEDING_KEYWORDS`
    # (`return`/`in`/`new`/`delete`/...) as a MEMBER name is a value too, so `/` after it is division.
    assert "secret" not in strip_js_comments(r"obj.return / 2; // secret")
    assert "leak" not in strip_js_comments(r"x.in / 2; // leak")
    assert "z" not in strip_js_comments(r"foo . delete / 2; // z")  # whitespace around the dot
    # ...while a REAL regex-preceding keyword (`return /re/` at statement start) is still a regex.
    assert "nodeIntegration: true" in strip_js_comments(r"return /\//g; nodeIntegration: true")


def test_strip_js_comments_same_line_brace_regex_residual_stays_line_scoped() -> None:
    # Characterization (PR #407 r4, Minor / documented residual): a regex immediately after `}` is read
    # as division (block-vs-object ambiguity), so a same-line `}`-regex embedding `/.../ ` can truncate
    # its OWN line — a known, line-scoped residual. The invariant that must hold: it never crosses lines.
    src = "if (x) { } /^\\d+\\//.test(p); flag\nconst b = 'webSecurity: false';\n"
    out = strip_js_comments(src)
    assert "webSecurity: false" in out                 # the LATER line always survives (no cross-file)
    assert len(out.splitlines()) == len(src.splitlines())  # alignment invariant intact
    # Pin the residual ITSELF (characterization of TODAY's known behavior, not a desired one): the
    # same-line `}`-regex truncation drops `flag` from line 1. If a future change to the state machine
    # fixes OR widens this, update this assertion knowingly rather than letting it shift silently.
    assert "flag" not in out.splitlines()[0]


# ── nested template literals (#541) ──────────────────────────────────────────────────────────
# Split deliberately into two groups. The FIRST group pins shapes that pass TODAY, several of
# them *by accident* — they work precisely because everything between a template's backticks is
# treated as string content, so a `}` in `${ {a:1}.a }` is inert. The fix removes that accident by
# making substitution nesting real, so these are the direction it trades against (rule 1) and they
# are written BEFORE the fix so a regression cannot hide behind a green suite. The SECOND group is
# the defect itself.

_SINK = "el.innerHTML = user_input;"


def test_strip_js_comments_substitution_braces_that_pass_today_still_pass() -> None:
    # FP-bait for the #541 widening. Each `}` here must NOT be read as ending the substitution.
    # An object literal inside a substitution: the `}` of `{a:1}` is not the substitution's `}`.
    assert _SINK in strip_js_comments("const s = `${ {a:1}.a }`; " + _SINK)
    # A `}` inside a STRING inside a substitution is not a `}` at all.
    assert _SINK in strip_js_comments('const s = `${ "}" }//z`; ' + _SINK)
    # A `}` inside a nested template's own text, one level down.
    assert _SINK in strip_js_comments("const s = `${ `}` }`; " + _SINK)
    # An empty substitution, and a substitution holding only a comment.
    assert _SINK in strip_js_comments("const s = `${}`; " + _SINK)


def test_strip_js_comments_template_text_is_still_string_content() -> None:
    # The whole reason this helper exists: a `//` between backticks is TEXT, never a comment.
    # Unchanged by #541, and the load-bearing case for the seven whole-file consumers.
    assert _SINK in strip_js_comments("const s = `see https://x.example/docs`; " + _SINK)
    assert _SINK in strip_js_comments("const s = `a /* not a comment */ b`; " + _SINK)
    # An escaped backtick does not close the literal.
    assert _SINK in strip_js_comments("const s = `a \\` b`; " + _SINK)


def test_strip_js_comments_commented_out_sink_is_still_silenced() -> None:
    # The FP direction the stripper exists for (#424). A widening that recovered detections by
    # letting commented-out examples through would trade the bug for the bug it was built to fix.
    assert _SINK not in strip_js_comments("// " + _SINK)
    assert _SINK not in strip_js_comments("/* " + _SINK + " */")
    # ...including after a template literal on the same line.
    assert _SINK not in strip_js_comments("const s = `card ${x}`; // " + _SINK)
    assert _SINK not in strip_js_comments("const s = `card ${ `${y}` }`; // " + _SINK)


def test_strip_js_comments_nested_template_does_not_close_the_outer_literal() -> None:
    # #541: `quote` is a single char, so a NESTED template's opening backtick hits `c == quote`
    # and closes the OUTER literal. The scanner is then in code mode while physically inside a
    # string, a `//` in the body reads as a real comment, and the rest of the physical line is
    # blanked — deleting a genuine sink. Found by @ptigroup reviewing #440; pre-existing on main.
    assert _SINK in strip_js_comments("const s = `card ${x ? `${y}//z` : \"w\"}`; " + _SINK)
    # The realistic shape needs no contrived `//`: an ordinary URL in a conditionally-built
    # template is the idiom, and `https://` supplies the `//`.
    assert _SINK in strip_js_comments("const s = `${x ? `https://a.b` : y}`; " + _SINK)
    # Two levels of nesting.
    assert _SINK in strip_js_comments("const s = `${ `${ `//x` }` }`; " + _SINK)
    # ...and the same under strip_strings, which shares the quote tracking.
    assert _SINK in strip_js_comments(
        "const s = `card ${x ? `${y}//z` : \"w\"}`; " + _SINK, strip_strings=True
    )


def test_strip_js_comments_lone_quote_in_a_substitution_stays_line_scoped() -> None:
    # #542 review H1 — the direction the #541 widening traded against, and the half its own FP-bait
    # missed. Substitution content is not lexed as code, so an apostrophe inside a REGEX (`/'/g`) or
    # a comment (`// don't`) reached the delimiter test looking like a string opener; opening one
    # swallowed the rest of the FILE, deleting real sinks with no error and no skip.
    src = ("const safe = `${items.map(i => i.replace(/'/g, \"&#39;\")).join(\"\")}`;\n"
           "const re = new RegExp(req.query.pattern);\n")
    assert "req.query.pattern" in strip_js_comments(src, strip_strings=True)
    assert "req.query.pattern" in strip_js_comments(src)
    # ...and the same for an apostrophe inside a COMMENT in the substitution.
    src2 = "const s = `${ /* don't */ x }`;\nel.innerHTML = user_input;\n"
    assert "el.innerHTML = user_input;" in strip_js_comments(src2, strip_strings=True)
    # FP-bait for THIS narrowing: a genuine, properly-paired string in a substitution must still be
    # recognised, so its braces stay inert and cannot end the substitution early.
    assert _SINK in strip_js_comments('const s = `${ "}" }//z`; ' + _SINK)
    assert _SINK in strip_js_comments("const s = `${ '}' }//z`; " + _SINK)


def test_strip_js_comments_continued_string_in_a_substitution_still_opens() -> None:
    # The line-scoped rule above must use the LOGICAL line. ES2023 12.9.4.1: a `\` + LineTerminator
    # inside a '..'/".." literal is legal and carries the literal onto the next physical line, so a
    # quote with no partner before the raw newline can still be a real opener. Refusing it is the
    # exact class #440's re-gate found on the sibling predicate; this pins that it is not reopened.
    # Pinned via the FP direction, which is where the branch is actually OBSERVABLE once the
    # blast-radius cap exists. The template below closes, so the cap does not fire. If the quote is
    # refused, the backtick inside the continued literal opens a phantom nested template, the frame
    # never unwinds, the cap DOES fire, and the trailing commented-out sink survives — a false
    # positive of exactly the kind #424 built this helper to prevent.
    #
    # Proven by mutation, not by reasoning: deleting the continuation branch flips both assertions
    # (measured). The obvious "the sink must survive" assertion is VACUOUS here — the cap rescues it
    # either way — which is how the previous version of this test pinned nothing while looking right
    # (#542 re-gate M1). Re-check by mutation, never by reading, if this is ever edited.
    src = 'const s = `${ "a\\\n`b" }`;\n// ' + _SINK + "\n"
    assert _SINK not in strip_js_comments(src)
    assert _SINK not in strip_js_comments(src, strip_strings=True)


def test_strip_js_comments_unterminated_template_is_not_blanked_to_eof() -> None:
    # BLAST-RADIUS CAP (#542 re-gate H1). A template still open at EOF either never closed or WE
    # mis-tracked it; either way nothing from its opener on was reliably classified, so blanking it
    # would delete source on a guess. Same call this function already makes for an unterminated `/*`.
    # This is what makes a misparse structurally unable to lose MORE than the pre-#541 code did.
    src = "const s = `never closed ${ x }\n" + _SINK + "\n"
    assert _SINK in strip_js_comments(src)
    assert _SINK in strip_js_comments(src, strip_strings=True)


def test_strip_js_comments_desync_shapes_cannot_delete_a_sink() -> None:
    # Every desync class found across #541/#542 and its two review rounds, pinned together because
    # they share one root: a mis-tracked frame that never unwinds. Each one deleted a real sink at
    # some commit in that history, and each was `main`-correct only by accident of the cap until
    # #543 started consuming a substitution's regexes and comments whole (the FP direction for
    # those shapes is pinned by `..._brace_in_a_substitution_regex_or_comment_keeps_the_frame`).
    shapes = [
        'const s = `${ a.replace(/\'/g, "") }`;\n',                 # H1  lone quote in a regex
        'const s = `${ a.replace(/\'/g, "") } - it\'s ready`;\n',   # H1b two stray quotes, one line
        'const o = `${ a.replace(/\'/g,"") }` + `x\'y` + `${ b }`;\n',  # H1c stray quote in tpl text
        'const o = `${ a.replace(/\'/g,"") + \'{\' } tail`;\n',     # H1d quote then a `{` literal
        'const s = `${ v.replace(/{/g, "") }`;\n',                  # M1/#543 unbalanced { in a regex
        'const s = `${ /* } */ v }`;\n',                            # M1b unbalanced } in a comment
        'const s = `${ f(\'it\\\'s ok) } tail`;\n',                 # L1 escaped partner quote
    ]
    for prefix in shapes:
        assert _SINK in strip_js_comments(prefix + _SINK), prefix
        assert _SINK in strip_js_comments(prefix + _SINK, strip_strings=True), prefix


# The three views a guard reads: default, `strip_strings`, and the #749 anchor mask.
_JS_VIEWS: list[dict[str, bool]] = [
    {}, {"strip_strings": True}, {"strip_strings": True, "keep_substitutions": True},
]

# #543: a brace, quote or backtick inside a regex or comment within a `${…}`. Each closes its template
# at the real backtick only if the sub-lexer consumes the regex or comment whole.
_SUBSTITUTION_REGEX_OR_COMMENT_SHAPES = [
    'const s = `${ v.replace(/{/g, "") }`;\n',       # the issue's shape, an unbalanced { in a regex
    'const s = `${ v.replace(/}/g, "") }`;\n',       # an unbalanced } in a regex
    'const s = `${ v.replace(/`/g, "") }`;\n',       # a backtick in a regex
    'const s = `${ v // {\n}`;\n',                   # a { in a line comment
    'const s = `${ v // `\n}`;\n',                   # a backtick in a line comment
    'const s = `${ /* { */ v }`;\n',                 # a { in a block comment
    'const s = `${ /* } */ v }`;\n',                 # a } in a block comment
    'const s = `${ /* ` */ v }`;\n',                 # a backtick in a block comment
    'const s = `${ /{/.test(x) }`;\n',               # a regex as the substitution's first token
    'const s = `${ /}/.test(x) }`;\n',               # the same, a }
    'const s = `${ !/}/.test(v) }`;\n',              # a regex after a real negation (the #1124 H2 trade)
    'const s = `${ ok && !/{/.test(v) }`;\n',        # the same, after an operator
    'const s = `${ a.map(e => { return!/{/.test(e) }) }`;\n',  # minified: a keyword glued to the `!`
    'const s = `${ v.replace(/\\d{3}/g, "") }`;\n',  # control: a balanced { in a regex
    'const s = `${ v.replace(/\\{/g, "") }`;\n',     # control: an escaped { in a regex
]


@pytest.mark.parametrize("prefix", _SUBSTITUTION_REGEX_OR_COMMENT_SHAPES)
def test_strip_js_comments_brace_in_a_substitution_regex_or_comment_keeps_the_frame(prefix: str) -> None:
    # #543, the FP direction (#424: a commented-out sink must stay silenced). Before the fix the
    # unbalanced shapes kept the template open, so the comment on the next line read as template text
    # in every view and was never blanked; the controls were already right.
    for view in _JS_VIEWS:
        assert _SINK not in strip_js_comments(prefix + "// " + _SINK + "\n", **view), view
    # Rule 1, the direction this widening trades against: a REAL sink after the shape still survives.
    for view in _JS_VIEWS:
        assert _SINK in strip_js_comments(prefix + _SINK + "\n", **view), view


@pytest.mark.parametrize("expr", [
    "${ a / b }", "${ x[0] / n }", "${ f() / 2 }", "${ typeof a / 2 }", "${ `${a}` / b }", "${ a++ / 2 }",
    "${ list.map(x => x / 2) }", "${ (a) / b }", "${ 1 / b }", "${ obj.return / 2 }",
    "${ a! / 2 }", "${ el.w!/2 }", "${ (a)! / b }", "${ x[0]! / n }",   # a TypeScript non-null `!`
])
def test_strip_js_comments_division_in_a_substitution_is_not_a_regex(expr: str) -> None:
    # #543 runs the regex-vs-division heuristic inside substitutions. A division misread as a regex
    # would be consumed up to the next `/` on the line, here the one in `n / 2`, hiding the
    # substitution's `}` and closing backtick, and the trailing comment would come back as template
    # text. Proven by mutation: forcing every `/` in a substitution to open a regex fails every case.
    src = "const s = `" + expr + "` + n / 2; // " + _SINK + "\n"
    for view in _JS_VIEWS:
        assert _SINK not in strip_js_comments(src, **view), view


def test_strip_js_comments_regex_in_a_substitution_is_blanked_by_view() -> None:
    # Substitution content is string content under `strip_strings`, so the whole regex goes. The
    # anchor mask keeps it as code but still blanks every `\`-escape pair, the #749 contract, and
    # `strip_regex` blanks the body only, keeping the delimiters and flags as in code mode.
    src = "x = `${ s.replace(/\\s+a/g, '-') }`;"
    assert strip_js_comments(src) == src
    assert "/\\s+a/g" not in strip_js_comments(src, strip_strings=True)
    assert strip_js_comments(src, strip_strings=True, keep_substitutions=True) == (
        "x = `   s.replace(/  +a/g, ' ')  `;"
    )
    assert "replace(/    /g," in strip_js_comments(src, strip_regex=True)


def test_strip_js_comments_jsx_closing_tag_in_a_substitution_is_not_a_regex() -> None:
    # A `/` right after `<` passes the regex-start heuristic, but in `</b>` it closes a JSX tag.
    # Consuming `/b> }` as a regex would hide the substitution's `}`, so the sub-lexer refuses a regex
    # start wherever `_regex_body_may_blank` does (found while implementing #543).
    src = "const s = `${ <b>x</b> }` + n / 2; // " + _SINK + "\n"
    for view in _JS_VIEWS:
        assert _SINK not in strip_js_comments(src, **view), view


def test_strip_js_comments_unterminated_block_comment_in_a_substitution_is_not_consumed() -> None:
    # The code-mode cap, inside a substitution: a `/*` with no `*/` before EOF is not a comment run,
    # so it cannot hide the substitution's `}` and closing backtick. Nor is its `/` retried as a regex
    # opener (a `,` allows one), which would run to the `/` in `n / 2` and hide them just the same
    # (measured by mutation). Linearity is pinned by
    # `test_strip_js_comments_pathological_unterminated_block_is_linear`.
    src = "const s = `${ a, /* never closed }` + n / 2;\n" + _SINK + "\n// " + _SINK + "\n"
    for view in _JS_VIEWS:
        out = strip_js_comments(src, **view)
        assert out.count(_SINK) == 1, view   # the real sink kept, the commented one blanked


def test_strip_js_comments_well_formed_source_still_blanks_comments() -> None:
    # The ordinary case, and the one that matters for real repos: when the template closes, the cap
    # never fires and a commented-out example is blanked exactly as before (#424). Deliberately NOT
    # named "the cap does not revive comments" — it does, and the next test pins that. This one is
    # vacuous with respect to the cap by design (replacing the cap with `pass` leaves it green);
    # it exists to prove the cap is not firing on healthy input, which is the property that keeps
    # the trade below rare.
    assert _SINK not in strip_js_comments('const s = `card ${x}`; // ' + _SINK)
    assert _SINK not in strip_js_comments('const s = `card ${ `${y}` }`; // ' + _SINK)
    assert _SINK not in strip_js_comments('const s = `${ a.replace(/x/g, "") }`; // ' + _SINK)
    assert _SINK not in strip_js_comments("// " + _SINK)
    assert _SINK not in strip_js_comments("/* " + _SINK + " */")


def test_strip_js_comments_the_cap_revives_comments_after_a_desync_accepted_trade() -> None:
    # THE DIRECTION THE CAP TRADES AGAINST (rule 1), recorded as a decision rather than discovered
    # later as a surprise. Restoring raw text un-blanks whatever is in the restored region, so in the
    # SAME cases where the cap rescues a real sink it also brings back a commented-out one. Measured
    # 1:1 over a 40k-case differential: 4,322 sinks recovered, 4,322 comments revived, same case set.
    #
    # Accepted deliberately: a revived comment is a VISIBLE false positive, a deleted sink is an
    # invisible false negative, and this file prefers the former everywhere. Rare in practice — the
    # cap fires on 16 of 112,514 real js/ts files, all vendor, and 0 of the 2,131 the walk scans.
    # If this assertion ever flips, the trade was changed; make sure that was on purpose.
    # The fixture used to be the #543 shape (`${ v.replace(/{/g, "") }`), which no longer desyncs.
    # A substitution that genuinely never closes still does: the comment inside it is blanked by the
    # scan (#543 consumes it as a comment) and then restored by the cap.
    src = "const s = `${ f(x,\n// " + _SINK + "\n"
    assert _SINK in strip_js_comments(src, strip_strings=True)
    assert _SINK in strip_js_comments(src, strip_strings=True, keep_substitutions=True)


def test_strip_js_comments_cap_radius_is_bounded_to_the_open_template() -> None:
    # The "radius" half of "blast-radius cap": it restores from the OUTERMOST open backtick, never
    # the whole file. Without this, `tpl_root = 0` would pass the entire suite (measured) — the one
    # thing stopping the cap from being a whole-file escape hatch had no test at all.
    src = "// " + _SINK + "\nconst s = `never closed ${ x }\nconst t = 1;\n"
    out = strip_js_comments(src, strip_strings=True)
    assert _SINK not in out           # a comment BEFORE the opener is still blanked
    assert "const t = 1;" in out      # from the opener on, verbatim


def test_strip_js_comments_nested_template_push_is_pinned_in_the_fp_direction() -> None:
    # The #541 fix itself — the nested-template push — is observable ONLY in the FP direction now,
    # because the cap rescues the positive direction either way. Deleting the push left the whole
    # 4,868-test suite green before this test existed (#542 gate 3, F2/G).
    assert _SINK not in strip_js_comments('const s = `${ `}` }`; // ' + _SINK)
    assert _SINK not in strip_js_comments('const s = `${ `}` }`; // ' + _SINK, strip_strings=True)


def test_strip_js_comments_same_line_quote_rule_is_pinned_in_the_fp_direction() -> None:
    # Same for `_closes_on_this_line`: deleting it entirely left the suite green (#542 gate 3, F2/K).
    # With it, the template closes and the trailing comment is blanked; without it the quote opens a
    # phantom string, the frame never unwinds, the cap fires and the comment comes back.
    src = 'const s = `${ a.replace(/\'/g, "") }`; // ' + _SINK
    assert _SINK not in strip_js_comments(src)
    assert _SINK not in strip_js_comments(src, strip_strings=True)
    # Since #543 the sub-lexer consumes that regex whole, so the fixture above no longer reaches the
    # rule. An apostrophe the sub-lexer does not place inside a regex still does: JSX text in a
    # substitution. Deleting `_closes_on_this_line` flips these two (measured).
    src = "const s = `${ <b>it's</b> }`; // " + _SINK
    assert _SINK not in strip_js_comments(src)
    assert _SINK not in strip_js_comments(src, strip_strings=True)


def test_strip_js_comments_strip_strings_still_blanks_substitutions() -> None:
    # The documented conservative limitation (a false NEGATIVE, never a false positive) must
    # survive #541: `${expr}` is string content under strip_strings, so `req.x` inside a template
    # stays blanked. Making substitutions real code here would be a silent WIDENING for the four
    # strip_strings consumers, which is a different change than the one #541 asks for.
    out = strip_js_comments("const s = `a ${req.query.x} b`; const q = req.query.y;", strip_strings=True)
    assert "req.query.x" not in out    # substitution blanked, as documented
    assert "req.query.y" in out        # real member access outside the template survives
    # Same for a nested substitution.
    out2 = strip_js_comments("const s = `${ `${req.query.z}` }`; ok();", strip_strings=True)
    assert "req.query.z" not in out2 and "ok();" in out2


def test_strip_js_comments_stray_opener_cannot_delete_a_sink_before_the_next_backtick() -> None:
    # #910 (the FN direction). A stray backtick — a missing closer on a CSS-in-JS template, or a
    # lone backtick in JSX prose — pairs with the next unrelated backtick and everything between
    # them is blanked as template TEXT. That pairing CLOSES, so the #542 EOF cap never reaches it
    # (`tpl_root` points at the LAST opener), and a real timer sink in the span was deleted from the
    # scan of every strip_strings consumer: a silent CRITICAL false negative with a clean exit.
    # Bounded by the PARITY cap: a single stray delimiter always leaves the delimiter count odd.
    timer = 'setTimeout("doSomething(" + userInput + ")", 100);'
    css = ("const cardStyle = styled.div`\n  display: flex;\n  padding: 8px;\n\n"
           "export function scheduleRun(userInput) {\n  " + timer + "\n}\n\n"
           "const tooltipStyle = styled.span`color: red;`;\n")
    jsx = "function C() { return <p>It`s fine</p>; }\n" + timer + "\nconst s = `ok`;\n"
    for src in (css, jsx):
        assert "setTimeout(" in strip_js_comments(src, strip_strings=True), src
        assert "setTimeout(" in strip_js_comments(src), src


def test_strip_js_comments_parity_revive_keeps_code_mode_comments_blanked() -> None:
    # THE DIRECTION THE PARITY CAP TRADES AGAINST (rule 1). The cap revives only spans the scanner
    # blanked as template text; a comment it blanked in CODE mode is not in that set and stays
    # blanked. A naive "revive verbatim from the FIRST opener" passes every single-opener cap test
    # above (:766/:808/:822 — measured) and fails THIS one: it brings back an earlier, valid
    # template's trailing `// example`, the exact FP #424 built this helper to prevent. Also pins
    # that the #542 EOF cap still restores the still-open tail of the same file.
    # Vacuous against UNMODIFIED code by design (the :794 pattern): the fixture is unaffected by the
    # cap's absence; it distinguishes this implementation from Candidate A, not from no fix at all.
    src = "const a = `t`; // " + _SINK + "\nconst b = `never closed ${x}\nconst t = 1;\n"
    out = strip_js_comments(src, strip_strings=True)
    assert _SINK not in out
    assert _SINK not in strip_js_comments(src)
    assert "const t = 1;" in out


def test_strip_js_comments_closed_template_holding_code_text_is_still_string_content() -> None:
    # The parity cap must not fire on VALID source. This fixture is the #910 RCA's "even-count
    # residual", and it is not a residual: the backtick-semicolon on line 3 CLOSES the template, so
    # the `setTimeout` between them is string content (any parser agrees) and blanking it is correct.
    # One stray delimiter always flips a valid file to ODD parity; an even count with blanked code
    # is either two or more lexical errors or exactly this — code-shaped text inside a real string.
    src = 'const cardStyle = styled.div`\nsetTimeout("doSomething()", 100);\n`;\nconst label = `ready`;\n'
    assert "setTimeout(" not in strip_js_comments(src, strip_strings=True)
    assert "setTimeout(" in strip_js_comments(src)   # default mode never blanked it


def test_strip_js_comments_parity_revive_restores_earlier_templates_accepted_trade() -> None:
    # THE COST, recorded as a decision (the :808 pattern). On an odd-parity file the scanner cannot
    # tell WHICH pairing the stray broke, so it restores every closed template span — including a
    # valid one BEFORE the stray, whose string content then reaches a strip_strings consumer. A
    # visible false positive over an invisible deletion, confined to files whose delimiter count is
    # odd, i.e. files that are not valid JS. Measured over 65,480 real js/ts files (21,427 with a
    # backtick): the cap changes 2, both vendor, none the repo walk scans.
    # The sink sits in the CLOSED mis-paired span, so both assertions are the parity cap's own work,
    # not the EOF cap's (which only restores from the last opener, `x`).
    # If the first assertion ever flips, the trade was changed; make sure that was on purpose.
    src = ("const label = `req.query.count total`;\nconst s = styled.div`\n"
           + _SINK + "\nconst t = `x`;\n")
    out = strip_js_comments(src, strip_strings=True)
    assert "req.query.count" in out    # an earlier VALID template's content comes back
    assert _SINK in out                # ...which is the price of never deleting the sink


def test_strip_js_comments_parity_cap_is_a_no_op_in_default_mode() -> None:
    # In default mode template text is never blanked, so there is nothing to revive: the parity cap
    # is observable ONLY under strip_strings=True, like the #542 cap. Vacuous with respect to the
    # cap by design (the :794 pattern): it exists to prove the cap never widens default mode, where
    # the sink already survived and a code-mode comment already did not.
    timer = 'setTimeout("doSomething(" + userInput + ")", 100);'
    src = ("const a = `t`; // " + _SINK + "\nconst cardStyle = styled.div`\n  display: flex;\n"
           + timer + "\nconst tooltipStyle = styled.span`color: red;`;\n")
    out = strip_js_comments(src)
    assert "setTimeout(" in out and _SINK not in out


# --- strip_regex (#909): opt-in blanking of regex literal BODIES --------------------------------
# For a consumer that walks bracket/quote structure: the `}` of `/}/g` closed a timer callback's
# body early, and the `'` of `/'/g` opened a phantom string, in VALID files. Every test below that
# asserts "unchanged" is the direction this flag trades against: a `/` the heuristic misreads as a
# regex start must never blank real code.


def test_strip_js_comments_strip_regex_blanks_the_body_keeping_delimiters_and_flags() -> None:
    src = 'x = s.replace(/}\'"`{/gi, "");\n'
    assert strip_js_comments(src, strip_regex=True) == 'x = s.replace(/     /gi, "");\n'
    # Independent of strip_strings, and off by default: neither other mode touches a regex body.
    assert strip_js_comments(src) == src
    assert strip_js_comments(src, strip_strings=True) == src
    # An escape and a char class holding a `/` stay inside the body, as the lexer already models.
    assert strip_js_comments(r"a = /\}/g;", strip_regex=True) == "a = /  /g;"
    assert strip_js_comments("a = /[/]}/;", strip_regex=True) == "a = /    /;"
    # After a control-flow head's `)` a `/` is a regex (the #407 r3 rule), so it is blanked too.
    assert strip_js_comments("if (x) /}/.test(s);", strip_regex=True) == "if (x) / /.test(s);"


def test_strip_js_comments_strip_regex_leaves_an_unterminated_regex_untouched() -> None:
    # Blank only once the closing `/` is found ON ITS OWN LINE. A misread `/` with no partner on
    # its line must not blank the rest of the line, and an escaped terminator (which the lexer's `\`
    # branch steps over) must not carry the blanking onto the next line, where it would delete a sink.
    src = 'x = (/}abc\nsetTimeout("run(" + u + ")", 0);\n'
    assert strip_js_comments(src, strip_regex=True) == src
    src = 'x = (/a\\\nsetTimeout("run(" + u + ")", 0); /;\n'
    assert strip_js_comments(src, strip_regex=True) == src


@pytest.mark.parametrize(
    "src",
    [
        # `</label>`: `<` before the `/` reads as a regex start, and the "body" runs to the next
        # closing tag's `/` on the line, over the sink between the two tags.
        '<label>Name</label><button onClick={() => setTimeout("go(" + x + ")", 0)}>Go</button>\n',
        # a JSX string close: the lexer sets `prev` to `)` there, and the stale control-head flag
        # from `if (ok)` turns the self-closing `/>` into a regex start (seen in a real .tsx file).
        'if (ok) render(<A b="c" />, <button onClick={() => setTimeout("go(" + x + ")", 0)} />);\n',
        # JSX text that starts with `/`: a bare `>` before it.
        '<nav>/ {setTimeout("go(" + x + ")", 0)} / Docs</nav>\n',
    ],
)
def test_strip_js_comments_strip_regex_never_blanks_a_misread_regex(src: str) -> None:
    # Each "regex" here is a misread whose body is real code. Blanking it deleted a CRITICAL sink.
    assert 'setTimeout("go("' in strip_js_comments(src, strip_regex=True)
    assert 'setTimeout("' in strip_js_comments(src, strip_strings=True, strip_regex=True)


def test_strip_js_comments_strip_regex_still_blanks_after_an_arrow() -> None:
    # The `>` refusal above must not cover `=>`: `s => /re/.test(s)` is the common real form.
    assert strip_js_comments("f(s => /}'/.test(s));", strip_regex=True) == "f(s => /  /.test(s));"


def test_strip_js_comments_strip_regex_leaves_division_alone() -> None:
    for src in (
        "r = a / b / c;\n",
        'w = x / 2 + "px";\n',
        "v = f({}) / 2 / k;\n",
        "t = arr[0] / 2 / 3;\n",
        "z = i++ / y / 2;\n",
    ):
        assert strip_js_comments(src, strip_regex=True) == src, src


# --- the #749 anchor mask: strip_strings=True, keep_substitutions=True -------------------------------


def _anchor_mask(src: str) -> str:
    return strip_js_comments(src, strip_strings=True, keep_substitutions=True)


def test_strip_js_comments_anchor_mask_keeps_substitution_code_and_blanks_string_text() -> None:
    # #749: the one view that tells inert string TEXT from live substitution CODE. Plain
    # `strip_strings=True` blanks both (pinned by
    # `test_strip_js_comments_strip_strings_still_blanks_substitutions`), which is why a guard cannot
    # filter its anchors against it without deleting every sink nested in a `${...}`.
    src = "const s = `a ${req.body.id} b`; const t = 'req.count';"
    # template text `a ` and the `${` (4), the code, the `}` and ` b` (3); a plain string's content (9)
    expected = "const s = `" + " " * 4 + "req.body.id" + " " * 3 + "`; const t = '" + " " * 9 + "';"
    assert _anchor_mask(src) == expected


def test_strip_js_comments_anchor_mask_blanks_strings_and_nested_text_inside_a_substitution() -> None:
    # Only a substitution's own CODE is kept. A plain string inside it is still string content, with
    # BOTH delimiters kept as in code mode, and a nested template's text is still template text,
    # while that nested template's own substitution is code again.
    src = "x = `${ f('pool.query(a)', `exec(b) ${req.query.d}`) }`;"
    out = _anchor_mask(src)
    assert "f(" in out and "req.query.d" in out
    assert "pool.query" not in out and "exec(b)" not in out
    assert out.count("'") == 2
    assert out.count("`") == 4


def test_strip_js_comments_anchor_mask_is_opt_in_and_only_ever_unblanks() -> None:
    # The flag cannot change what the two existing modes blank: relative to `strip_strings=True` it
    # may only RESTORE source characters, so the anchor mask's blanked set lies between default
    # mode's and `strip_strings=True`'s, and equals the latter when there is no substitution at all.
    # Without `strip_strings` it is a no-op. (Byte-identity of the two existing modes against the
    # pre-#749 lexer was measured over 131 110 inputs at implementation time, 0 differences.)
    rng = random.Random(749)
    alphabet = list("ab/*'\"`\\ \n;=(){}[].$req")

    def blanked(src: str, out: str) -> set[int]:
        return {i for i, (a, b) in enumerate(zip(src, out, strict=True)) if a != b}

    for _ in range(4000):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        default, mask = strip_js_comments(s), _anchor_mask(s)
        strings = strip_js_comments(s, strip_strings=True)
        assert strip_js_comments(s, keep_substitutions=True) == default, s
        assert blanked(s, default) <= blanked(s, mask) <= blanked(s, strings), s
        if "${" not in s:
            assert mask == strings, s


def test_strip_js_comments_anchor_mask_restore_caps_leave_source_as_code() -> None:
    # Both restore caps apply in this mode too: a template still open at EOF comes back verbatim from
    # its opener, so every anchor in that desynced region reads as code, today's behaviour for an
    # unfiltered guard. A desync that rebalances is not covered by either cap; see the #543 test below.
    src = 'const s = `open ${x} "db.query(a)"\nexec(cmd);\n'
    start = src.index("`")
    assert _anchor_mask(src)[start:] == src[start:]


def test_strip_js_comments_anchor_mask_rebalancing_regex_pair_reads_as_code() -> None:
    # #543, formerly the accepted trade `..._anchor_mask_balanced_desync_masks_code_accepted_trade`
    # (PR #1057 round-1 review). A `{` in a regex or comment inside one substitution used to shift
    # the frame and a `}` in a later one shifted it back, so the file ended balanced, neither restore
    # cap fired, and the code between the two read as template text: the four anchor-mask guards
    # dropped an anchor there, and plain `strip_strings=True` blanked the sink too. Comments and
    # regexes are now consumed whole inside a substitution, so their braces are inert. The guard-level
    # pins are the four `*_between_two_desyncing_substitutions_*` tests of those guards.
    sink = "execSync(cmd);\n"
    pairs = [
        ("const t = `a ${ s.replace(/{/g, '') } b`;\n", "const u = `a ${ s.replace(/}/g, '') } b`;\n"),
        ("const t = `a ${ s /* { */ } b`;\n", "const u = `a ${ s /* } */ } b`;\n"),
    ]

    def anchor_is_code(src: str) -> bool:
        line = strip_js_comments(src).splitlines()[1]
        return js_anchor_is_code(line, _anchor_mask(src).splitlines()[1], line.index("("))

    for opens, closes in pairs:
        assert anchor_is_code(opens + sink + closes), opens
        assert anchor_is_code(opens + sink), opens         # a single construct, as before
        assert sink.strip() in strip_js_comments(opens + sink + closes, strip_strings=True), opens


def test_js_anchor_is_code_tells_a_quoted_call_from_a_real_one() -> None:
    line = 'log("db.query(x)"); db.query(`q ${id}`); s = `${db.query(y)}`;'
    parens = [m.end() - 1 for m in re.finditer(r"\.query\(", line)]
    assert [js_anchor_is_code(line, _anchor_mask(line), p) for p in parens] == [False, True, True]


def test_js_anchor_is_code_fails_open_without_evidence() -> None:
    # A whitespace anchor, an out-of-range position and a misaligned pair of lines carry no evidence,
    # so each answers "code": misuse can keep a finding, never silently drop one.
    line = 'x("a b")'
    mask = _anchor_mask(line)
    assert mask == 'x("   ")'
    assert js_anchor_is_code(line, mask, 3) is False        # the control: quoted `a`
    assert js_anchor_is_code(line, mask, 4) is True         # a whitespace anchor
    assert js_anchor_is_code(line, mask, 99) is True
    assert js_anchor_is_code(line, mask, -1) is True
    assert js_anchor_is_code(line, mask[:-1], 3) is True    # views of different lengths


def test_js_code_matches_drops_quoted_matches_and_keeps_substitution_code() -> None:
    # #1055: one quoted call, one real call, one real call in a `${...}`; the helper yields the two
    # real ones, in order, and every match is visited, so the quoted FIRST hit hides neither.
    line = 'log("db.query(x)"); db.query(a); s = `${db.query(y)}`;'
    pattern = re.compile(r"\.query\(")
    found = [m.start() for m in js_code_matches(pattern, line, _anchor_mask(line), anchor=lambda m: m.end() - 1)]
    assert found == [m.start() for m in pattern.finditer(line)][1:]


def test_js_code_matches_fails_open_on_misaligned_views() -> None:
    line = 'log("db.query(x)");'
    pattern = re.compile(r"\.query\(")
    assert list(js_code_matches(pattern, line, _anchor_mask(line), anchor=lambda m: m.end() - 1)) == []
    kept = list(js_code_matches(pattern, line, _anchor_mask(line)[:-1], anchor=lambda m: m.end() - 1))
    assert len(kept) == 1


def test_js_code_matches_whole_text_offsets_agree_with_per_line_offsets() -> None:
    # The differential behind the whole-file adopters (#1055): the four #749 adopters test anchors
    # one LINE at a time, and agent-resume / mcp-transport test them on the WHOLE text. That is
    # sound only if the views have the same length, the same line breaks, and the same verdict at
    # every offset either way. Checked exhaustively, at every position of every random input.
    rng = random.Random(1055)
    alphabet = list("ab/*'\"`\\ \n\r;=(){}[].$q")
    for _ in range(3000):
        src = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 80)))
        code, mask = strip_js_comments(src), _anchor_mask(src)
        assert len(code) == len(mask) == len(src), src
        code_lines, mask_lines = code.splitlines(keepends=True), mask.splitlines(keepends=True)
        assert [len(c) for c in code_lines] == [len(m) for m in mask_lines], src
        start = 0
        for cl, ml in zip(code_lines, mask_lines, strict=True):
            for k in range(len(cl)):
                assert js_anchor_is_code(code, mask, start + k) == js_anchor_is_code(cl, ml, k), (src, start + k)
            start += len(cl)


# --------------------------------------------------------------------------- #
# strip_go_comments / go_scan_dirs (feat/go-scan-infra, Phase 3 of the stack-coverage plan)
# --------------------------------------------------------------------------- #


def test_strip_go_comments_blanks_line_and_block_preserving_layout() -> None:
    src = "x := 1 // note\n/* a\n b */\nfoo()\n"
    out = strip_go_comments(src)
    assert len(out) == len(src) and out.count("\n") == src.count("\n")  # layout preserved
    assert "note" not in out and "b */" not in out
    assert out.splitlines()[0].rstrip() == "x := 1"  # code kept, trailing comment blanked
    assert out.splitlines()[3] == "foo()"


def test_strip_go_comments_ignores_delimiters_inside_double_quoted_strings() -> None:
    src = 'msg := "see // not a comment"\nreal := 1\n'
    out = strip_go_comments(src)
    assert "real := 1" in out
    assert 'msg := "see // not a comment"' in out  # the string survives untouched (not blanked)


def test_strip_go_comments_ignores_delimiters_inside_rune_literals() -> None:
    # A bare `'` always opens a rune literal in Go — there is no other use for it — so a `/` right
    # after one must not be misread as starting a comment.
    src = "r := '/'\nreal := 1\n"
    out = strip_go_comments(src)
    assert "real := 1" in out
    assert "r := '/'" in out


def test_strip_go_comments_raw_string_spans_multiple_lines_and_is_never_a_comment() -> None:
    # THE Go-specific behavior strip_js_comments has no equivalent for: a backtick raw string can
    # contain a literal "//" or "/*" across several physical lines, and none of it is ever a
    # comment — unlike a "..." string, which must not span a line at all (next test).
    src = "s := `line one // not a comment\nline two /* also not */\nstill inside`\nreal := 1\n"
    out = strip_go_comments(src)
    assert "not a comment" in out and "also not" in out  # raw string content untouched
    assert "real := 1" in out
    assert len(out) == len(src) and out.count("\n") == src.count("\n")


def test_strip_go_comments_raw_string_has_no_backslash_escape() -> None:
    # Go spec: a raw string has NO escape processing at all -- a backslash is a literal character,
    # not an escape, so it can never hold the closing backtick open (unlike "..."/'.' below).
    src = "s := `a\\`\nreal := 1 // gone\n"
    out = strip_go_comments(src)
    assert "real := 1" in out
    assert "gone" not in out  # the raw string closed at the first backtick, so this IS a real comment


def test_strip_go_comments_double_quoted_string_does_not_span_lines() -> None:
    # Unlike a raw string, an unterminated "..." bails at end-of-line and re-enters code mode --
    # mirrors blank_block_comments' HCL-string rule, for the same reason (real Go: syntax error
    # either way, so there is no correct answer except "don't run the string on forever").
    src = 's := "a\nreal := 1 /* z */\n'
    out = strip_go_comments(src)
    assert "real := 1" in out.splitlines()[1]
    assert "z" not in out  # the block comment on line 2 is correctly still recognized as a comment


def test_strip_go_comments_unterminated_block_comment_is_not_blanked_to_eof() -> None:
    # Blast-radius cap, same as strip_js_comments/blank_block_comments: an opener with no later
    # `*/` anywhere must be left inert, never blanked to EOF.
    src = "/* dangling\nreal := 1\n"
    assert strip_go_comments(src) == src


def test_strip_go_comments_preserves_splitlines_count_for_boundary_chars() -> None:
    for bad in ("\x0b", "\x0c", "\x1c", "\x85", " "):
        src = f"a(); /* c{bad}d */ b()\nfoo()\n"
        out = strip_go_comments(src)
        assert len(out.splitlines()) == len(src.splitlines()), f"boundary {bad!r} shifted line count"


def test_strip_go_comments_pathological_unterminated_block_is_linear() -> None:
    # Same DoS concern as strip_js_comments (PR #407 r4): the failed-close cache must keep this
    # O(n), not O(n^2), on untrusted target-repo source.
    import time

    src = "/*x" * 200_000  # ~585 KB, no closing */ anywhere
    start = time.monotonic()
    strip_go_comments(src)
    elapsed = time.monotonic() - start
    assert elapsed < 3.0, f"took {elapsed:.2f}s — quadratic block-comment scan reintroduced"


def test_strip_go_comments_invariants_hold_under_fuzz() -> None:
    # Property-style, mirrors strip_js_comments' fuzz test: length and splitlines()-count must be
    # preserved for arbitrary Go-ish input, so line-number alignment can never silently drift.
    import random

    rng = random.Random(4321)
    alphabet = list("abc/*'\"`\\ \n\r\t;:=(){}[].req123gonotacomment \x0b\x0c")
    for _ in range(4000):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        out = strip_go_comments(s)
        assert len(out) == len(s)
        assert len(out.splitlines()) == len(s.splitlines())


def test_strip_go_comments_unterminated_raw_string_is_not_blanked_to_eof() -> None:
    # #555 review, Dean, Critical 1 (verified): an unterminated backtick used to set in_raw with
    # no cap and no restore, silencing everything after it for the rest of the file — including a
    # commented-out secret that should have been blanked. Same blast-radius-cap treatment as the
    # /* */ case: the stray backtick is left as ordinary code, and scanning continues normally.
    src = "q := `SELECT 1\nfunc main() {\n\t// apiKey := \"AKIAIOSFODNN7EXAMPLE\"\n}\n"
    out = strip_go_comments(src)
    assert "AKIAIOSFODNN7EXAMPLE" not in out  # the commented-out secret IS blanked
    assert len(out) == len(src) and out.count("\n") == src.count("\n")


def test_strip_go_comments_no_op_fails_this_test() -> None:
    # Meta-check for the class of bug #555's review caught (Dean, Major 4): replacing the whole
    # function body with `return text` passed 11 of the 14 original tests. This one is written so
    # a no-op cannot pass it — if `strip_go_comments` is ever reduced to an identity function
    # again, the secret above stays in the output and this assertion catches it directly, rather
    # than relying on a human to think to re-run the no-op experiment.
    src = "q := `x\n// apiKey := \"AKIAIOSFODNN7EXAMPLE\"\n"
    assert "AKIAIOSFODNN7EXAMPLE" not in strip_go_comments(src)


def test_strip_go_comments_js_line_terminator_in_string_does_not_desync_single_line() -> None:
    # #555 review, Dean, Critical 2a (verified): _JS_LINE_TERMINATORS (borrowed from
    # strip_js_comments) includes U+2028/U+2029, which are ordinary characters in Go — not line
    # terminators. Using them to decide when a "..." string bails let a string containing one cut
    # short mid-literal, re-entering code mode INSIDE the string, so a "//" in the remaining string
    # content blanked a real sink on the same physical line.
    src = 'u := "sep //x" ; exec.Command(userInput)\n'
    out = strip_go_comments(src)
    assert "exec.Command(userInput)" in out


def test_strip_go_comments_js_line_terminator_in_string_does_not_desync_across_lines() -> None:
    # #555 review, Dean, Critical 2b (verified) — the worse half: the same desync can make a "/*"
    # inside a string look real, which then cross-matches a distant, unrelated "*/" later in the
    # file, blanking everything in between (real sinks) while code past the fake close survives
    # untouched, so the file still looks plausible.
    src = (
        'pat := "a /*b"\n'
        "func vulnerable() {\n"
        "\texec.Command(userInput)\n"
        '\tdb.Exec("DROP TABLE users")\n'
        "}\n"
        "/* an ordinary block comment */\n"
        'func afterward() { fmt.Println("still here") }\n'
    )
    out = strip_go_comments(src)
    assert "exec.Command(userInput)" in out
    assert 'db.Exec("DROP TABLE users")' in out
    assert 'fmt.Println("still here")' in out


def test_strip_go_comments_js_line_boundary_chars_do_not_survive_inside_a_real_comment() -> None:
    # #555 review, Dean, Major 3 (verified) — the false-positive direction: _JS_LINE_BOUNDARIES
    # (borrowed from strip_js_comments) includes \v/\f/\x1c-\x1e, which are not Go line-comment
    # stop characters. Using them as the "//"-blanking loop's stop condition let the loop exit
    # early inside a real Go comment, leaving the comment's tail (here, a secret) live in the
    # output instead of blanked.
    for boundary_char in ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e"):
        src = f"// apiKey{boundary_char}AKIAIOSFODNN7EXAMPLE\nreal := 1\n"
        out = strip_go_comments(src)
        assert "AKIAIOSFODNN7EXAMPLE" not in out, f"comment survived past {boundary_char!r}"
        assert "real := 1" in out


def test_go_scan_dirs_resolves_detected_dirs(tmp_path: Path) -> None:
    (tmp_path / "cmd").mkdir()
    prof = mkprofile(tmp_path, go_dirs=["cmd"])
    dirs = go_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path / "cmd"]


def test_go_scan_dirs_falls_back_to_root_when_empty(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, go_dirs=[])
    dirs = go_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path]


def test_go_scan_dirs_root_dot_resolves_to_root(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, go_dirs=["."])
    dirs = go_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path]


def test_go_scan_dirs_skips_nonexistent_dirs(tmp_path: Path) -> None:
    # A detected dir that doesn't actually exist on disk (stale profile, or the caller built one
    # by hand) must be filtered out rather than returned as a dead path a guard would fail to read.
    prof = mkprofile(tmp_path, go_dirs=["cmd", "ghost"])
    (tmp_path / "cmd").mkdir()
    dirs = go_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path / "cmd"]


# --------------------------------------------------------------------------- #
# strip_php_comments / php_scan_dirs (graudit research batch) — mirrors
# strip_go_comments' tests, minus the raw-string cases PHP has no equivalent for, plus PHP's
# extra `#` line-comment form and the `#[Attribute]` exception.
# --------------------------------------------------------------------------- #


def test_strip_php_comments_blanks_line_and_block_preserving_layout() -> None:
    src = "$x = 1; // note\n/* a\n b */\nfoo();\n"
    out = strip_php_comments(src)
    assert len(out) == len(src) and out.count("\n") == src.count("\n")
    assert "note" not in out and "b */" not in out
    assert out.splitlines()[0].rstrip() == "$x = 1;"
    assert out.splitlines()[3] == "foo();"


def test_strip_php_comments_blanks_hash_line_comment() -> None:
    src = "# apiKey: AKIAIOSFODNN7EXAMPLE\nreal();\n"
    out = strip_php_comments(src)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "real();" in out


def test_strip_php_comments_does_not_blank_attribute_syntax() -> None:
    # #[Attribute(...)] is real PHP 8 code (e.g. a framework route/permission annotation), not a
    # comment — the one deliberate exception to the bare-# rule.
    src = "#[Route('/admin')]\nfunction admin() {}\n"
    out = strip_php_comments(src)
    assert "#[Route('/admin')]" in out


def test_strip_php_comments_ignores_delimiters_inside_double_quoted_strings() -> None:
    src = '$msg = "see // not a comment";\n$real = 1;\n'
    out = strip_php_comments(src)
    assert "$real = 1;" in out
    assert '$msg = "see // not a comment";' in out


def test_strip_php_comments_ignores_delimiters_inside_single_quoted_strings() -> None:
    src = "$msg = 'see # not a comment';\n$real = 1;\n"
    out = strip_php_comments(src)
    assert "$real = 1;" in out
    assert "$msg = 'see # not a comment';" in out


def test_strip_php_comments_unterminated_block_comment_is_not_blanked_to_eof() -> None:
    src = "/* dangling\n$real = 1;\n"
    assert strip_php_comments(src) == src


def test_strip_php_comments_preserves_splitlines_count_for_boundary_chars() -> None:
    for bad in ("\x0b", "\x0c", "\x1c", "\x85", " "):
        src = f"a(); /* c{bad}d */ b();\nfoo();\n"
        out = strip_php_comments(src)
        assert len(out.splitlines()) == len(src.splitlines()), f"boundary {bad!r} shifted line count"


def test_strip_php_comments_pathological_unterminated_block_is_linear() -> None:
    import time

    src = "/*x" * 200_000  # ~585 KB, no closing */ anywhere
    start = time.monotonic()
    strip_php_comments(src)
    elapsed = time.monotonic() - start
    # 5.0s ceiling: matches the measured-headroom precedent set for strip_java_comments'
    # identical pathological-block test — a 3.0s ceiling measured under this repo's
    # MIN_HEADROOM=10.0x gate (tests/test_timing_budgets.py) on this hardware; 5.0s clears it
    # with comfortable margin while still leaving seconds below the actual quadratic regression
    # this guards against.
    assert elapsed < 5.0, f"took {elapsed:.2f}s — quadratic block-comment scan reintroduced"


def test_strip_php_comments_invariants_hold_under_fuzz() -> None:
    import random

    rng = random.Random(4321)
    alphabet = list("abc/*'\"#\\ \n\r\t;:=(){}[].$req123gonotacomment \x0b\x0c")
    for _ in range(4000):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        out = strip_php_comments(s)
        assert len(out) == len(s)
        assert len(out.splitlines()) == len(s.splitlines())


def test_strip_php_comments_no_op_fails_this_test() -> None:
    src = "$q = 'x';\n// apiKey := \"AKIAIOSFODNN7EXAMPLE\"\n"
    assert "AKIAIOSFODNN7EXAMPLE" not in strip_php_comments(src)


# strip_php_heredocs (PR #884 review regression, Dean's #848 corpus-scan follow-up) — must run
# BEFORE strip_php_comments so a heredoc/nowdoc body's ordinary prose can never desync a caller's
# own cross-line quote tracking (php_code_injection.py / php_command_injection.py).


def test_strip_php_heredocs_blanks_body_preserving_layout() -> None:
    src = "$x = <<<EOT\nhello world\nEOT;\nfoo();\n"
    out = strip_php_heredocs(src)
    assert len(out) == len(src) and out.count("\n") == src.count("\n")
    assert "hello world" not in out
    assert "foo();" in out


def test_strip_php_heredocs_blanks_body_with_odd_quote_count() -> None:
    # The exact regression: an apostrophe (or any odd count of quote characters) inside the body
    # must be gone entirely, not just "not read as opening a string" — a downstream cross-line
    # quote tracker that runs on this output can never see it at all.
    src = "$x = <<<EOT\nThis isn't escaped.\nEOT;\n"
    out = strip_php_heredocs(src)
    assert "'" not in out
    assert out.count("'") == 0


def test_strip_php_heredocs_preserves_real_code_on_closing_line() -> None:
    # Only the identifier itself is blanked on the closing line -- real PHP after it (here, `. $x`)
    # must survive untouched, not be swallowed as if it were still heredoc body.
    src = "$x = <<<EOT\nbody\nEOT . $suffix;\n"
    out = strip_php_heredocs(src)
    assert "$suffix" in out
    assert "body" not in out


def test_strip_php_heredocs_handles_nowdoc_single_quoted_tag() -> None:
    src = "$x = <<<'EOT'\ndon't interpolate this\nEOT;\n"
    out = strip_php_heredocs(src)
    assert "interpolate" not in out
    assert len(out) == len(src)


def test_strip_php_heredocs_handles_indented_closing_marker() -> None:
    # PHP 7.3+ flexible heredoc syntax: the closing identifier may be indented.
    src = "    $x = <<<EOT\n    body\n    EOT;\n"
    out = strip_php_heredocs(src)
    assert "body" not in out
    assert out.splitlines()[2].rstrip().endswith(";")


def test_strip_php_heredocs_ignores_shift_operator() -> None:
    # `<<` alone (bitwise shift) must never be mistaken for a heredoc opener -- the opener requires
    # `<<<` plus a bare identifier as the LAST token on the line.
    src = "$x = 1 << 2;\nfoo();\n"
    assert strip_php_heredocs(src) == src


def test_strip_php_heredocs_unterminated_blanks_to_eof_not_raise() -> None:
    src = "$x = <<<EOT\nnever closes\nstill going\n"
    out = strip_php_heredocs(src)  # must not raise
    assert len(out) == len(src)
    assert "never closes" not in out and "still going" not in out


def test_strip_php_heredocs_then_comments_composition_matches_real_guard_usage() -> None:
    # The exact composition the two guards use: strip_php_heredocs FIRST, strip_php_comments on
    # its output. A `//`-looking sequence inside a heredoc body must not be read as a real comment
    # by the second pass, since it's already blanked to spaces by the first.
    src = "$x = <<<EOT\nsee // not a comment, just heredoc text\nEOT;\nreal();\n"
    out = strip_php_comments(strip_php_heredocs(src))
    assert "not a comment" not in out
    assert "real();" in out


def test_strip_php_heredocs_invariants_hold_under_fuzz() -> None:
    import random

    rng = random.Random(8765)
    alphabet = list("abc<>'\"\n\r\t;:=(){}[].$req123EOTgonotaheredoc ")
    for _ in range(4000):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        out = strip_php_heredocs(s)
        assert len(out) == len(s)
        assert len(out.splitlines()) == len(s.splitlines())


def test_php_scan_dirs_resolves_detected_dirs(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    prof = mkprofile(tmp_path, php_dirs=["src"])
    dirs = php_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path / "src"]


def test_php_scan_dirs_falls_back_to_root_when_empty(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, php_dirs=[])
    dirs = php_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path]


def test_php_scan_dirs_root_dot_resolves_to_root(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, php_dirs=["."])
    dirs = php_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path]


def test_php_scan_dirs_skips_nonexistent_dirs(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, php_dirs=["src", "ghost"])
    (tmp_path / "src").mkdir()
    dirs = php_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path / "src"]


# --------------------------------------------------------------------------- #
# strip_java_comments / java_scan_dirs (find-sec-bugs research batch) — mirrors
# strip_go_comments' tests, minus the raw-string cases Java has no equivalent for.
# --------------------------------------------------------------------------- #


def test_strip_java_comments_blanks_line_and_block_preserving_layout() -> None:
    src = "int x = 1; // note\n/* a\n b */\nfoo();\n"
    out = strip_java_comments(src)
    assert len(out) == len(src) and out.count("\n") == src.count("\n")
    assert "note" not in out and "b */" not in out
    assert out.splitlines()[0].rstrip() == "int x = 1;"
    assert out.splitlines()[3] == "foo();"


def test_strip_java_comments_blanks_javadoc_block() -> None:
    src = "/**\n * secret: AKIAIOSFODNN7EXAMPLE\n */\nreal();\n"
    out = strip_java_comments(src)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "real();" in out


def test_strip_java_comments_ignores_delimiters_inside_double_quoted_strings() -> None:
    src = 'String msg = "see // not a comment";\nint real = 1;\n'
    out = strip_java_comments(src)
    assert "int real = 1;" in out
    assert 'String msg = "see // not a comment";' in out


def test_strip_java_comments_ignores_delimiters_inside_char_literals() -> None:
    # A bare `'` always opens a char literal in Java — there is no other use for it — so a `/`
    # right after one must not be misread as starting a comment.
    src = "char c = '/';\nint real = 1;\n"
    out = strip_java_comments(src)
    assert "int real = 1;" in out
    assert "char c = '/';" in out


def test_strip_java_comments_double_quoted_string_does_not_span_lines() -> None:
    src = 'String s = "a\nint real = 1; /* z */\n'
    out = strip_java_comments(src)
    assert "int real = 1;" in out.splitlines()[1]
    assert "z" not in out  # the block comment on line 2 is correctly still recognized as a comment


def test_strip_java_comments_unterminated_block_comment_is_not_blanked_to_eof() -> None:
    src = "/* dangling\nint real = 1;\n"
    assert strip_java_comments(src) == src


def test_strip_java_comments_preserves_splitlines_count_for_boundary_chars() -> None:
    for bad in ("\x0b", "\x0c", "\x1c", "\x85", " "):
        src = f"a(); /* c{bad}d */ b();\nfoo();\n"
        out = strip_java_comments(src)
        assert len(out.splitlines()) == len(src.splitlines()), f"boundary {bad!r} shifted line count"


def test_strip_java_comments_pathological_unterminated_block_is_linear() -> None:
    import time

    src = "/*x" * 200_000  # ~585 KB, no closing */ anywhere
    start = time.monotonic()
    strip_java_comments(src)
    elapsed = time.monotonic() - start
    # 5.0s ceiling (not 3.0s): measured worst-case elapsed ~0.31s across 5 repeats on this
    # hardware, giving ~16x headroom at 5.0s vs. only ~9.6x at 3.0s — under this repo's
    # MIN_HEADROOM=10.0x gate (tests/test_timing_budgets.py). Still leaves seconds of margin
    # below the actual quadratic regression this guards against.
    assert elapsed < 5.0, f"took {elapsed:.2f}s — quadratic block-comment scan reintroduced"


def test_strip_java_comments_invariants_hold_under_fuzz() -> None:
    import random

    rng = random.Random(4321)
    alphabet = list("abc/*'\"\\ \n\r\t;:=(){}[].req123gonotacomment \x0b\x0c")
    for _ in range(4000):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        out = strip_java_comments(s)
        assert len(out) == len(s)
        assert len(out.splitlines()) == len(s.splitlines())


def test_strip_java_comments_no_op_fails_this_test() -> None:
    src = 'String q = "x";\n// apiKey := "AKIAIOSFODNN7EXAMPLE"\n'
    assert "AKIAIOSFODNN7EXAMPLE" not in strip_java_comments(src)


def test_java_scan_dirs_resolves_detected_dirs(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    prof = mkprofile(tmp_path, java_dirs=["src"])
    dirs = java_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path / "src"]


def test_java_scan_dirs_falls_back_to_root_when_empty(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, java_dirs=[])
    dirs = java_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path]


def test_java_scan_dirs_root_dot_resolves_to_root(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, java_dirs=["."])
    dirs = java_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path]


def test_java_scan_dirs_skips_nonexistent_dirs(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, java_dirs=["src", "ghost"])
    (tmp_path / "src").mkdir()
    dirs = java_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path / "src"]

# --------------------------------------------------------------------------- #
# strip_ruby_comments / ruby_scan_dirs (brakeman research batch)
# --------------------------------------------------------------------------- #

def test_strip_ruby_comments_blanks_line_comment_preserving_layout() -> None:
    src = "x = 1 # note\nreal = 2\n"
    out = strip_ruby_comments(src)
    assert len(out) == len(src) and out.count("\n") == src.count("\n")
    assert "note" not in out
    assert out.splitlines()[0].rstrip() == "x = 1"
    assert out.splitlines()[1] == "real = 2"


def test_strip_ruby_comments_ignores_hash_inside_double_quoted_string() -> None:
    src = 'msg = "see # not a comment"\nreal = 1\n'
    out = strip_ruby_comments(src)
    assert "real = 1" in out
    assert 'msg = "see # not a comment"' in out  # the string survives untouched


def test_strip_ruby_comments_ignores_hash_inside_single_quoted_string() -> None:
    src = "msg = 'see # not a comment'\nreal = 1\n"
    out = strip_ruby_comments(src)
    assert "real = 1" in out
    assert "msg = 'see # not a comment'" in out


def test_strip_ruby_comments_blanks_begin_end_block() -> None:
    src = "=begin\nblock comment with code() inside\n=end\nreal = 1\n"
    out = strip_ruby_comments(src)
    assert len(out) == len(src) and out.count("\n") == src.count("\n")
    assert "code()" not in out
    assert "real = 1" in out


def test_strip_ruby_comments_begin_marker_must_start_a_line() -> None:
    # `=begin` mid-line is ordinary code (an assignment to a var named `begin`-ish), not a
    # block-comment opener — the Ruby spec's own rule.
    src = "x =begin_value\nreal = 1 # gone\n"
    out = strip_ruby_comments(src)
    assert "x =begin_value" in out
    assert "gone" not in out  # the # comment on line 2 is still recognized normally


def test_strip_ruby_comments_unterminated_begin_block_blanks_to_eof() -> None:
    # No matching =end anywhere: honestly blank to EOF (documented, not a silent miss) — same
    # "no correct answer" reasoning as strip_go_comments' unterminated-raw-string cap, just the
    # opposite choice, since an unterminated =begin really does swallow the rest of a real
    # Ruby file (there's nothing after it to preserve, unlike a stray backtick mid-expression).
    src = "=begin\nnever closed\nstill in it\n"
    out = strip_ruby_comments(src)
    assert "never closed" not in out and "still in it" not in out


def test_strip_ruby_comments_preserves_splitlines_count_for_boundary_chars() -> None:
    for bad in ("\x0b", "\x0c", " "):
        src = f"a = 1 # c{bad}d\nreal = 2\n"
        out = strip_ruby_comments(src)
        assert len(out.splitlines()) == len(src.splitlines()), f"boundary {bad!r} shifted line count"


def test_ruby_scan_dirs_resolves_detected_dirs(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    prof = mkprofile(tmp_path, ruby_dirs=["app"])
    dirs = ruby_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path / "app"]


def test_ruby_scan_dirs_falls_back_to_root_when_empty(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, ruby_dirs=[])
    dirs = ruby_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path]


def test_ruby_scan_dirs_root_dot_resolves_to_root(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, ruby_dirs=["."])
    dirs = ruby_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path]


def test_ruby_scan_dirs_skips_nonexistent_dirs(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, ruby_dirs=["app", "ghost"])
    (tmp_path / "app").mkdir()
    dirs = ruby_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path / "app"]


def _linenos(src: str) -> list[int]:
    return [ln for ln, _ in iter_functions(src)]


def _block_at(src: str, lineno: int) -> str:
    for ln, block in iter_functions(src):
        if ln == lineno:
            return block
    raise AssertionError(f"no block reported at line {lineno}: got {_linenos(src)}")


# --- (a) lineno + (b) basic block ------------------------------------------------------------

def test_simple_decorated_route() -> None:
    src = (
        "@router.get('/orders/{order_id}')\n"   # 1
        "def get_order(order_id):\n"            # 2
        "    return Order.query.get(order_id)\n"  # 3
    )
    assert _linenos(src) == [2]
    block = _block_at(src, 2)
    assert "@router.get('/orders/{order_id}')" in block
    assert "Order.query.get(order_id)" in block


def test_undecorated_function_still_emitted() -> None:
    src = (
        "# just a helper\n"                      # 1
        "def load(order_id):\n"                  # 2
        "    return Order.query.get(order_id)\n"  # 3
    )
    assert _linenos(src) == [2]


# --- multi-line decorator (PR #268 round 1) --------------------------------------------------

def test_multiline_decorator_lineno_is_def_and_block_has_all_deco_lines() -> None:
    src = (
        "@router.get(\n"                         # 1
        "    '/orders/{order_id}',\n"            # 2
        "    response_model=Order,\n"            # 3
        ")\n"                                     # 4
        "def get_order(order_id):\n"            # 5
        "    return Order.query.get(order_id)\n"  # 6
    )
    assert _linenos(src) == [5]
    block = _block_at(src, 5)
    assert "response_model=Order" in block
    assert "@router.get(" in block


# --- multi-line signature (body not truncated) -----------------------------------------------

def test_multiline_signature_body_included() -> None:
    src = (
        "@router.get('/x/{id}')\n"               # 1
        "def f(\n"                                # 2
        "    id: int,\n"                          # 3
        "    q: str = None,\n"                    # 4
        ") -> dict:\n"                            # 5
        "    return db.get(id)\n"                 # 6
    )
    assert _linenos(src) == [2]
    assert "return db.get(id)" in _block_at(src, 2)


# --- (d) triple-quoted string blanking -------------------------------------------------------

def test_triple_quoted_description_blanked_and_route_not_split() -> None:
    src = (
        "@router.get(\n"                         # 1
        "    '/x/{id}',\n"                        # 2
        '    description="""\n'                   # 3
        "    fetch one order (see foo(bar for the id\n"  # 4  (stray brackets in docstring)
        '    """,\n'                              # 5
        ")\n"                                     # 6
        "def f(id):\n"                            # 7
        "    return db.get(id)\n"                 # 8
    )
    assert _linenos(src) == [7]                  # exactly one route, not dropped/merged
    block = _block_at(src, 7)
    assert "foo(bar" not in block                # docstring content blanked
    assert "@router.get(" in block


def test_docstring_body_content_is_blanked() -> None:
    src = (
        "@router.get('/x/{id}')\n"               # 1
        "def f(id):\n"                            # 2
        '    """example: user.role = body.role"""\n'  # 3
        "    return db.get(id)\n"                 # 4
    )
    assert _linenos(src) == [2]
    assert "user.role = body.role" not in _block_at(src, 2)


# --- single-line string edge cases (PR #268 round 3) -----------------------------------------

def test_escaped_quote_and_stray_bracket_in_decorator_string() -> None:
    src = (
        "@router.get(\n"                         # 1
        "    '/x/{id}',\n"                        # 2
        '    summary="a \\" then (",\n'          # 3  escaped quote + stray '(' in string
        ")\n"                                     # 4
        "def f(id):\n"                            # 5
        "    return db.get(id)\n"                 # 6
    )
    assert _linenos(src) == [5]


def test_bracket_in_comment_inside_multiline_decorator() -> None:
    src = (
        "@router.get(\n"                         # 1
        "    '/x/{id}',   # danger ( unbalanced\n"  # 2  '(' inside a comment
        ")\n"                                     # 3
        "def f(id):\n"                            # 4
        "    return db.get(id)\n"                 # 5
    )
    assert _linenos(src) == [4]


def test_bracket_delta_via_line_fallback_when_ast_fails() -> None:
    # #376 review (Low): `_bracket_delta` is reached ONLY from `_iter_functions_lines`, the
    # AST-parse-failure fallback. The other bracket tests use valid syntax and hit the AST path,
    # so they never exercise the refactored `_bracket_delta`. Force the fallback with a syntax
    # error, then plant a stray `(` AND a `#` inside a single-line string on a decorator
    # continuation line: the string-aware strip must keep the balance correct so the route below
    # is still discovered (a broken `_bracket_delta` would miscount and drop it).
    src = (
        "@router.get(\n"                         # 1
        "    '/x/{id}',\n"                        # 2
        '    summary="oops ( and # not a comment",\n'  # 3  stray '(' + '#' inside a string
        ")\n"                                     # 4
        "def f(id):\n"                            # 5
        "    return db.get(id)\n"                 # 6
        "x = = 5\n"                               # 7  syntax error -> ast.parse fails -> fallback
    )
    assert 5 in _linenos(src)  # the route survives the stray bracket/hash-in-string


# --- (c) pragmas survive in the block --------------------------------------------------------

def test_pragma_interleaved_between_decorator_and_def() -> None:
    src = (
        "@router.get('/x/{id}')\n"               # 1
        "# security: allow-unscoped-fetch\n"     # 2
        "def f(id):\n"                            # 3
        "    return db.get(id)\n"                 # 4
    )
    assert _linenos(src) == [3]
    block = _block_at(src, 3)
    assert "security: allow-unscoped-fetch" in block
    assert "@router.get('/x/{id}')" in block


def test_pragma_on_same_line_as_decorator() -> None:
    src = (
        "@router.get('/x/{id}')  # security: allow-unscoped-fetch\n"  # 1
        "def f(id):\n"                            # 2
        "    return db.get(id)\n"                 # 3
    )
    assert _linenos(src) == [2]
    assert "security: allow-unscoped-fetch" in _block_at(src, 2)


def test_pragma_in_body_tail_after_last_statement() -> None:
    # Nuance #1 (the ast rewrite's `end_lineno` stops at the last statement; a trailing body
    # comment must still be pulled in, else a suppressed route wrongly fires).
    src = (
        "@router.get('/x/{id}')\n"               # 1
        "def f(id):\n"                            # 2
        "    x = db.get(id)\n"                    # 3
        "    return x\n"                          # 4
        "    # security: allow-unscoped-fetch\n"  # 5
    )
    assert _linenos(src) == [2]
    assert "security: allow-unscoped-fetch" in _block_at(src, 2)


# --- (e) no merge / no absorb ----------------------------------------------------------------

def test_adjacent_routes_not_merged() -> None:
    src = (
        "@router.get('/a/{id}')\n"               # 1
        "def a(id):\n"                            # 2
        "    return db.get(id)\n"                 # 3
        "\n"                                       # 4
        "\n"                                       # 5
        "@router.post('/b/{id}')\n"              # 6
        "def b(id):\n"                            # 7
        "    return db.get(id)\n"                 # 8
    )
    assert _linenos(src) == [2, 7]
    assert "/b/" not in _block_at(src, 2)
    assert "/a/" not in _block_at(src, 7)


def test_unrelated_multiline_expr_above_decorator_not_absorbed() -> None:
    src = (
        "result = some_call(\n"                  # 1
        "    Depends(x),\n"                       # 2
        ")\n"                                     # 3
        "@router.post('/wipe/{id}')\n"          # 4
        "def wipe(id):\n"                         # 5
        "    return db.delete(id)\n"              # 6
    )
    assert _linenos(src) == [5]
    assert "Depends(" not in _block_at(src, 5)   # the unrelated expr is not folded in
    assert "@router.post('/wipe/{id}')" in _block_at(src, 5)


# --- nesting + classes -----------------------------------------------------------------------

def test_nested_function_is_emitted_as_its_own_block() -> None:
    # UPDATED for the #452 review. This previously asserted a nested `def` is NOT its own entry,
    # on the reasoning that the surfacing guards analyse the enclosing route rather than its
    # inner closures. That collapse is what hid a factory-registered tool: an `@tool`-decorated
    # `wipe_users` defined inside `make_tools(db)` folded into the factory's block, so any
    # `confirm`-ish token anywhere in that factory — a local helper, or a `# TODO: add a
    # confirmation step` forty lines below — suppressed it. Same shape hid an unguarded nested
    # upload route behind a `max_size` name elsewhere in its factory.
    #
    # Emitting both was believed safe for those guards because they gate on a DECORATOR: an
    # undecorated enclosing factory does not match their route/tool patterns. Its `def` line does
    # not; its BLOCK TEXT does, and that is what those guards search — see the #502 tests below,
    # which is the other half of what makes emitting both safe.
    src = (
        "@router.get('/x/{id}')\n"               # 1
        "def outer(id):\n"                        # 2
        "    def helper(y):\n"                    # 3
        "        return y\n"                       # 4
        "    return db.get(id)\n"                 # 5
    )
    assert _linenos(src) == [2, 3]


def test_class_nested_in_function_body_is_emitted() -> None:
    # Same change, same reasoning: descending into a function body reaches a class defined
    # inside it, and a method of that class is a perfectly ordinary analysable block.
    src = (
        "def factory():\n"                       # 1
        "    class Inner:\n"                      # 2
        "        def method(self):\n"             # 3
        "            return 1\n"                   # 4
        "    return Inner\n"                       # 5
    )
    assert _linenos(src) == [1, 3]


def test_ast_and_line_walker_agree_on_nested_defs() -> None:
    # The two paths must stay construct-for-construct identical: `_iter_functions_lines` is the
    # never-raising fallback for input that does not parse, and a silent disagreement between
    # them means the same file is analysed differently depending on whether it happens to be
    # syntactically valid (#452 review).
    from agentsec.guards.base import _iter_functions_lines

    src = (
        "def outer():\n"
        "    def inner():\n"
        "        pass\n"
        "    class Inner:\n"
        "        def method(self):\n"
        "            pass\n"
        "    return inner\n"
    )
    assert [ln for ln, _ in iter_functions(src)] == [ln for ln, _ in _iter_functions_lines(src)]


# --- #502: an enclosing block must not inherit its nested route's decorator -------------------

_FACTORY_ROUTE = (
    "def make_app():\n"                          # 1  the factory — NOT a route
    "    app = FastAPI()\n"                      # 2
    "    @app.post('/upload')\n"                 # 3
    "    async def upload_endpoint(file):\n"     # 4  the route
    "        return file.read()\n"               # 5
    "    return app\n"                           # 6
)


def test_registered_nested_def_is_blanked_from_its_enclosing_block() -> None:
    """The factory's block must not contain the route's decorator (#502).

    `iter_functions` emits both blocks, which makes the enclosing one a strict superset of the
    nested one. Every decorator-gated consumer asks "is this a route?" by searching the WHOLE
    block, so the factory matched too and the same route was reported twice — the first copy
    anchored on a `def` carrying no decorator at all.
    """
    factory = _block_at(_FACTORY_ROUTE, 1)
    assert "@app.post" not in factory
    assert "upload_endpoint" not in factory
    assert "app = FastAPI()" in factory          # the factory's OWN body is untouched
    assert "return app" in factory
    # The route's own block keeps everything: the fix removes the child from the parent, never
    # the parent's context from the child (that direction is #452, which must not reopen).
    route = _block_at(_FACTORY_ROUTE, 4)
    assert "@app.post('/upload')" in route
    assert "return file.read()" in route


def test_undecorated_closure_stays_in_its_enclosing_block() -> None:
    """FN-bait for #502: only REGISTRATION-decorated nested defs are blanked.

    A plain closure is never emitted as a route/tool of its own, so its parent has to keep seeing
    it. Blanking every nested def — the obvious reading of "exclude nested defs" — would trade the
    duplicate for a silent miss: this route's only sink lives in `_load`, and the route would stop
    firing for `bola` entirely.
    """
    src = (
        "@router.get('/orders/{order_id}')\n"    # 1
        "def get_order(order_id):\n"             # 2
        "    def _load():\n"                     # 3  a closure, not a registration
        "        return Order.query.get(order_id)\n"   # 4
        "    return _load()\n"                   # 5
    )
    block = _block_at(src, 2)
    assert "Order.query.get(order_id)" in block
    assert "def _load():" in block


def test_blanking_preserves_line_numbers_and_line_count() -> None:
    """Blanked to EMPTY LINES, never deleted, so no consumer's offsets move (#502)."""
    factory = _block_at(_FACTORY_ROUTE, 1)
    assert len(factory.splitlines()) == 6                    # lines 1-6, none dropped
    assert factory.splitlines()[2:5] == ["", "", ""]         # lines 3-5 blanked in place
    assert factory.splitlines()[0] == "def make_app():"
    assert factory.splitlines()[5] == "    return app"


def test_blanking_reaches_every_enclosing_block_not_only_the_parent() -> None:
    """A route registered two scopes down is blanked out of BOTH ancestors (#502)."""
    src = (
        "def outer():\n"                         # 1
        "    def inner():\n"                     # 2
        "        @app.get('/x')\n"               # 3
        "        def route():\n"                 # 4
        "            return 1\n"                 # 5
        "        return route\n"                 # 6
        "    return inner\n"                     # 7
    )
    assert "@app.get" not in _block_at(src, 1)
    assert "@app.get" not in _block_at(src, 2)
    assert "@app.get('/x')" in _block_at(src, 4)


_NESTED_SIBLING_ROUTES = (
    "@router.post('/admin/delete')\n"                # 1
    "async def delete_outer(user_id: str):\n"        # 2  registered, and encloses another
    "    @router.post('/admin/delete2')\n"           # 3
    "    async def delete_inner(user_id: str):\n"    # 4  registered, nested
    "        return db.delete(user_id)\n"            # 5
    "    return db.delete(user_id)\n"                # 6
)


def test_a_registered_route_nested_in_another_registered_route_is_blanked_from_it() -> None:
    """Both spans are registrations, in a two-level chain — a different topology from the factory.

    The enclosing block here is itself a route, so it keeps its own decorator and body while losing
    the inner one. This is the shape behind the widening the #605 gate measured: before the
    blanking, `auth-dependency-not-applied` read the INNER route's `Depends(...)` as the OUTER's
    auth signal and reported nothing for a genuinely unauthenticated state-changing route.
    """
    outer = _block_at(_NESTED_SIBLING_ROUTES, 2)
    assert "@router.post('/admin/delete')" in outer          # its OWN decorator survives
    assert "delete2" not in outer                            # the nested route's does not
    assert "delete_inner" not in outer
    assert "    return db.delete(user_id)" in outer          # its own body survives
    inner = _block_at(_NESTED_SIBLING_ROUTES, 4)
    assert "@router.post('/admin/delete2')" in inner


@pytest.mark.parametrize("include_closures", [True, False])
def test_ast_and_line_walker_agree_on_nested_sibling_routes(include_closures: bool) -> None:
    """Parity on the registered-inside-registered chain, block TEXT included.

    Called out by the #605 gate as the one topology its adversarial parity sweep did not cover by
    name: both spans land in `nested_registered`, and the outer is both a container and a block in
    its own right, so the two walkers have to agree about which of them owns which lines.
    """
    from agentsec.guards.base import _iter_functions_lines

    assert iter_functions(_NESTED_SIBLING_ROUTES, include_closures=include_closures) == \
        _iter_functions_lines(_NESTED_SIBLING_ROUTES, include_closures=include_closures)


@pytest.mark.parametrize("include_closures", [True, False])
def test_ast_and_line_walker_agree_on_a_factory_registered_route(include_closures: bool) -> None:
    """Parity on the #502 shape, block TEXT included — not only the line numbers.

    The line walker has no parse tree, so it identifies the nested registrations itself. A silent
    disagreement here means the same file is analysed differently depending on whether it happens
    to be syntactically valid.
    """
    from agentsec.guards.base import _iter_functions_lines

    assert iter_functions(_FACTORY_ROUTE, include_closures=include_closures) == \
        _iter_functions_lines(_FACTORY_ROUTE, include_closures=include_closures)


def test_include_closures_false_drops_only_unregistered_nested_defs() -> None:
    # `include_closures=False` (#452 re-review) is for consumers that decide "is this a route?"
    # from something other than the decorator stack — today only `upload-no-size-limit`, which
    # gates on a `: UploadFile` parameter annotation an inner helper inherits by receiving it.
    # A *closure* is a nested def that is NOT REGISTERED as an entry point. A nested def carrying
    # a REGISTRATION decorator (a route/tool decorator) is a factory registration, not a closure,
    # and must survive.
    src = (
        "def factory():\n"                        # 1  top-level      -> kept
        "    def helper(x):\n"                    # 2  closure        -> dropped
        "        return x\n"                      # 3
        "\n"                                       # 4
        "    @router.post('/a')\n"                # 5
        "    async def route(x):\n"               # 6  nested+decorated -> kept
        "        def inner(y):\n"                 # 7  closure        -> dropped
        "            return y\n"                  # 8
        "        return inner(x)\n"               # 9
        "\n"                                       # 10
        "    class Local:\n"                      # 11
        "        def method(self):\n"             # 12 closure (class INSIDE a func) -> dropped
        "            return 1\n"                  # 13
        "\n"                                       # 14
        "    return route\n"                      # 15
        "\n"                                       # 16
        "\n"                                       # 17
        "class Top:\n"                            # 18
        "    def method(self):\n"                 # 19 top-level class method -> kept
        "        return 1\n"                      # 20
    )
    assert _linenos(src) == [1, 2, 6, 7, 12, 19]
    assert [ln for ln, _ in iter_functions(src, include_closures=False)] == [1, 6, 19]


def test_include_closures_false_ignores_a_non_registration_decorator() -> None:
    # Regression (#452 re-review, HIGH): the nested-def test was `child.decorator_list` — truthy
    # for ANY decorator. That is fine for the six consumers that re-check decorator CONTENT, but
    # `include_closures=False` exists precisely for the consumer that does NOT, so an unrelated
    # `@functools.lru_cache` / `@staticmethod` / `@retry` on a private helper resurrected the
    # exact false positive the flag was added to kill. Only a REGISTRATION decorator promotes a
    # nested def back into the output.
    from agentsec.guards.base import _iter_functions_lines

    src = (
        "import functools\n"                      # 1
        "\n"                                       # 2
        "def factory(router):\n"                  # 3  top-level          -> kept
        "    @functools.lru_cache\n"              # 4
        "    def _peek(x):\n"                     # 5  decorated, NOT registered -> dropped
        "        return x\n"                      # 6
        "\n"                                       # 7
        "    @staticmethod\n"                     # 8
        "    def _s(x):\n"                        # 9  ditto              -> dropped
        "        return x\n"                      # 10
        "\n"                                       # 11
        "    @patch('mod.thing')\n"               # 12 unittest.mock, not a PATCH route
        "    def _mocked(x):\n"                   # 13                    -> dropped
        "        return x\n"                      # 14
        "\n"                                       # 15
        "    @router.post('/a')\n"                # 16
        "    async def real_route(x):\n"          # 17 REGISTERED         -> kept
        "        return x\n"                      # 18
        "\n"                                       # 19
        "    return real_route\n"                 # 20
    )
    assert _linenos(src) == [3, 5, 9, 13, 17]
    assert [ln for ln, _ in iter_functions(src, include_closures=False)] == [3, 17]
    # …and the never-raising fallback must reach the same verdict.
    assert [ln for ln, _ in _iter_functions_lines(src, include_closures=False)] == [3, 17]


def test_line_walker_multi_line_signature_does_not_leak_bracket_depth() -> None:
    # Regression (#452 re-review, HIGH): `_iter_functions_lines` reused the name `depth` for the
    # signature-consuming walk, CLOBBERING the outer `depth` that carries bracket balance across
    # physical lines. The outer loop advances one line at a time, so the next iteration read the
    # signature-local leftover as the true per-line state. When a multi-line signature's closing
    # line sits at the `def`'s own indent — black's layout for a trailing-comma parameter list,
    # and any top-level `def` at column 0 — the def's scope was popped before its body, so a
    # genuinely nested closure saw `in_func=False` and was emitted anyway.
    from agentsec.guards.base import _iter_functions_lines

    src = (
        "def multi_line_sig(\n"                   # 1
        "    a,\n"                                # 2
        "    b,\n"                                # 3
        ") -> int:\n"                             # 4  closes at the def's OWN indent
        "    def after():\n"                      # 5  a closure -> must be dropped
        "        pass\n"                          # 6
        "    return after\n"                      # 7
    )
    assert [ln for ln, _ in iter_functions(src, include_closures=False)] == [1]
    assert [ln for ln, _ in _iter_functions_lines(src, include_closures=False)] == [1]


def test_include_closures_parity_over_multi_line_signature_shapes() -> None:
    # Blast-radius lock for the clobber above: the ast path and the never-raising line fallback
    # must agree construct-for-construct on every multi-line-signature shape, under BOTH settings
    # and under CRLF — else a file is analysed differently depending on whether it happens to
    # parse (which is exactly what a guard's fallback path is for).
    from agentsec.guards.base import _iter_functions_lines

    shapes = [
        # two top-level multi-line sigs back to back
        "def one(\n    a,\n) -> int:\n    return a\n\n\ndef two(\n    b,\n) -> int:\n"
        "    def helper():\n        return b\n    return helper\n",
        # a method's multi-line sig, then a module-level def
        "class C:\n    def m(\n        self,\n        a,\n    ) -> int:\n        def h():\n"
        "            return a\n        return h\n\n\ndef top():\n    def h2():\n"
        "        return 1\n    return h2\n",
        # multi-line sigs nested three deep, with a registration in the middle
        "def a(\n    p,\n):\n    def b(\n        q,\n    ):\n        @router.post(\n"
        "            '/z',\n        )\n        def c(\n            r,\n        ):\n"
        "            def d():\n                return 1\n            return d\n"
        "        return c\n    return b\n",
        # decorator call spanning lines above a multi-line signature
        "def factory(router):\n    @router.post(\n        '/a',\n        status_code=201,\n"
        "    )\n    async def handler(\n        x,\n    ) -> dict:\n        def inner():\n"
        "            return x\n        return inner\n    return handler\n",
    ]
    for shape in shapes:
        for src in (shape, shape.replace("\n", "\r\n")):
            for flag in (True, False):
                assert [ln for ln, _ in iter_functions(src, include_closures=flag)] == [
                    ln for ln, _ in _iter_functions_lines(src, include_closures=flag)
                ], f"walkers disagree with include_closures={flag} on {shape!r}"


def test_is_registration_accepts_routes_and_tools_only() -> None:
    # The decorator-CONTENT test `include_closures=False` now depends on. Over-matching here
    # re-opens the false positive; under-matching hides a factory-registered route.
    from agentsec.guards.base import _is_registration

    for accepted in (
        "@app.post('/upload')", "@router.get('/x')", "@router.patch('/x')",
        "@app.websocket('/ws')", "@app.api_route('/x')", "@bp.route('/x')",
        "@self.app.post('/x')", "@APP.POST('/x')", "@tool", "@mcp.tool()",
        "@agent.tool_plain",
    ):
        assert _is_registration([accepted]), accepted
    for rejected in (
        "@functools.lru_cache", "@staticmethod", "@classmethod", "@property",
        "@retry(times=3)", "@app.on_event('startup')", "@app.middleware('http')",
        "@x.getter", "@x.router", "@toolz.curry", "@x.tool_choice",
        # `patch` the HTTP verb vs `unittest.mock.patch` — the bare and dotted mock forms
        "@patch('mod.thing')", "@patch.object(Cls, 'm')", "@mock.patch('mod.thing')",
        "@unittest.mock.patch('m')",
        # a route decorator quoted as a STRING argument, or commented out, is not a decorator
        "@register(\"@app.post\")", "# @app.post('/x')",
        # HEAD/OPTIONS carry no request body, so they are deliberately not registrations
        "@app.head('/x')", "@app.options('/x')",
        "", "   ", "# a plain comment",
    ):
        assert not _is_registration([rejected]), rejected


def test_include_closures_false_keeps_the_two_walkers_in_step() -> None:
    # The ast path and the never-raising line fallback must agree construct-for-construct under
    # BOTH settings, or a file is analysed differently depending on whether it happens to parse.
    from agentsec.guards.base import _iter_functions_lines

    src = (
        "def a():\n"
        "    def b():\n"
        "        @deco\n"
        "        def c():\n"
        "            def d():\n"
        "                pass\n"
        "        return c\n"
        "    class Inner:\n"
        "        def method(self):\n"
        "            pass\n"
        "    return b\n"
        "\n"
        "if TYPE_CHECKING:\n"
        "    def module_level(x):\n"
        "        pass\n"
    )
    for flag in (True, False):
        assert [ln for ln, _ in iter_functions(src, include_closures=flag)] == [
            ln for ln, _ in _iter_functions_lines(src, include_closures=flag)
        ], f"walkers disagree with include_closures={flag}"


def test_class_methods_emitted_with_correct_linenos() -> None:
    src = (
        "class C:\n"                              # 1
        "    @router.get('/a/{id}')\n"           # 2
        "    def a(self, id):\n"                  # 3
        "        return db.get(id)\n"             # 4
        "\n"                                       # 5
        "    @router.post('/b/{id}')\n"          # 6
        "    def b(self, id):\n"                  # 7
        "        return db.get(id)\n"             # 8
    )
    assert _linenos(src) == [3, 7]


def test_async_def_supported() -> None:
    src = (
        "@router.get('/x/{id}')\n"               # 1
        "async def f(id):\n"                      # 2
        "    return await db.get(id)\n"           # 3
    )
    assert _linenos(src) == [2]


# --- totality: never raise on bad input ------------------------------------------------------

def test_syntactically_invalid_file_does_not_raise() -> None:
    # Guards must stay total (never crash on bad input). A file that doesn't parse must still
    # return a list, not raise.
    bad = "def broken(:\n    return 1\n"
    result = iter_functions(bad)
    assert isinstance(result, list)


def test_empty_and_no_functions() -> None:
    assert iter_functions("") == []
    assert iter_functions("x = 1\ny = 2\n") == []


def test_deeply_nested_parse_time_expression_does_not_raise() -> None:
    # Totality (#367): ast.parse raises MemoryError/RecursionError ("parser stack overflowed") on a
    # deeply nested expression. That must be caught and fall back, not escape and empty a guard.
    src = "x = " + "-" * 7000 + "1\n"
    result = iter_functions(src)
    assert isinstance(result, list)


def test_deeply_nested_module_level_expression_does_not_raise() -> None:
    # Totality (#367): a module-level operator chain PARSES fine, so the walker's own recursion
    # (not ast.parse) is what would overflow. It must not raise. A real def in the same module must
    # still be found (the walker skips the expression tree, so it doesn't fall back for the file).
    src = "BIG = " + "+".join("1" for _ in range(4000)) + "\n" + "def f(id):\n    return db.get(id)\n"
    result = iter_functions(src)
    assert isinstance(result, list)
    assert any(block.strip().startswith("def f(") or "def f(" in block for _, block in result)


# --- enclosing_function: fixed-window-to-enclosing-body migration ------------------

def test_enclosing_function_finds_check_outside_a_fixed_window() -> None:
    # The exact shape this search targets: a mitigating check sits further from the anchor line than
    # any fixed N-line window would reach, but is still inside the same function.
    src = (
        "def extract(zf, dest):\n"                # 1
        "    total = 0\n"                          # 2
        "    for m in zf.infolist():\n"            # 3
        "        total += m.file_size\n"           # 4
        "        if total > MAX_SIZE:\n"           # 5
        "            raise ValueError('too big')\n"  # 6
        "    # padding to push the call past a small look-back window\n"  # 7
        "    print(1)\n" * 20 +                    # 8-27
        "    zf.extractall(dest)\n"                # 28
    )
    scope = enclosing_function(src, 28)
    assert scope is not None
    assert "MAX_SIZE" in scope


def test_enclosing_function_returns_none_at_module_level() -> None:
    src = "import zipfile\nzf.extractall(dest)\n"
    assert enclosing_function(src, 2) is None


def test_enclosing_function_returns_innermost_when_nested() -> None:
    src = (
        "def make_tools(db):\n"                   # 1
        "    MAX_SIZE = 100\n"                     # 2
        "    def inner(zf, dest):\n"               # 3
        "        zf.extractall(dest)\n"            # 4
        "    return inner\n"                       # 5
    )
    scope = enclosing_function(src, 4)
    assert scope is not None
    # The INNERMOST block is returned, not the outer factory's superset. Returning the outermost
    # span let a mitigation (or any unrelated token) sitting in the enclosing factory — or in a
    # SIBLING closure it also encloses — silence a genuinely unprotected nested function, a silent
    # false-negative regression (#685 review, Critical 1). The anchor's own closure body is still
    # fully visible.
    assert "inner" in scope
    assert "zf.extractall" in scope
    assert "make_tools" not in scope
    assert "MAX_SIZE" not in scope


def test_enclosing_function_sibling_mitigation_does_not_suppress_unmitigated_sibling() -> None:
    # Regression test for #685 review Critical 1: two sibling closures registered by the same
    # factory, one mitigated, one not. A token that only appears in the MITIGATED sibling must not
    # leak into the span returned for an anchor sitting in the UNMITIGATED sibling — the bug that
    # let one hardened route/tool in a `create_app()`/`register_tools()` factory silence a
    # genuinely unprotected one right next to it.
    src = (
        "def build_extractors():\n"                  # 1
        "    def safe_extract(zf, dest):\n"           # 2
        "        os.path.realpath(dest)\n"            # 3
        "        zf.extractall(dest)\n"               # 4
        "    def unsafe_extract(zf, dest):\n"         # 5
        "        zf.extractall(dest)\n"               # 6
        "    return safe_extract, unsafe_extract\n"   # 7
    )
    scope = enclosing_function(src, 6)
    assert scope is not None
    assert "unsafe_extract" in scope
    assert "realpath" not in scope


def test_enclosing_function_handles_decorated_def_correctly() -> None:
    # Regression guard for the span-recovery math itself: a decorator stack shifts the block's
    # true first line above the returned `def` lineno. A wrong offset here would either miss the
    # anchor (false None) or overshoot into a following, unrelated function.
    src = (
        "@app.post('/upload')\n"                  # 1
        "@log_call\n"                              # 2
        "def upload(f):\n"                         # 3
        "    zf.extractall('/tmp')\n"               # 4
        "\n"                                        # 5
        "def unrelated():\n"                        # 6
        "    SAFE_TOKEN = 1\n"                       # 7
    )
    scope = enclosing_function(src, 4)
    assert scope is not None
    assert "SAFE_TOKEN" not in scope  # must not overshoot into the next function
    assert "@app.post" in scope       # must include the full decorator stack


def test_enclosing_function_out_of_range_anchor_returns_none() -> None:
    assert enclosing_function("def f():\n    return 1\n", 0) is None
    assert enclosing_function("def f():\n    return 1\n", 999) is None


def test_enclosing_function_never_raises_on_unparseable_input() -> None:
    bad = "def broken(:\n    zf.extractall(x)\n"
    result = enclosing_function(bad, 2)
    assert result is None or isinstance(result, str)


def test_enclosing_function_span_matches_enclosing_function_text() -> None:
    # enclosing_function() is a thin wrapper over enclosing_function_span() — the slice it takes
    # from the span must equal what enclosing_function() itself returns, or a directional caller
    # slicing by span would silently disagree with the bidirectional convenience wrapper.
    src = "@app.post('/x')\ndef f(a):\n    zf.extractall(a)\n"
    span = enclosing_function_span(src, 3)
    assert span == (1, 3)
    text = enclosing_function(src, 3)
    assert text == "\n".join(src.splitlines()[span[0] - 1 : span[1]])


def test_enclosing_function_span_returns_none_at_module_level() -> None:
    assert enclosing_function_span("x = 1\ny = 2\n", 1) is None


# --- strip_python_strings (#366): blank triple-quoted content, never real code ---------------


def test_strip_blanks_a_real_docstring_but_keeps_surrounding_code() -> None:
    src = (
        "def f(id):\n"
        '    """example: password = "hunter2" (do NOT do this)"""\n'
        "    return db.get(id)\n"
    )
    out = strip_python_strings(src)
    assert "hunter2" not in out          # docstring example content blanked
    assert "db.get(id)" in out           # real code kept
    assert out.count("\n") == src.count("\n")   # line numbers preserved


def test_strip_leaves_single_line_strings_intact() -> None:
    # Contract: only triple-quoted strings are stripped; single-line strings stay (an unlikely
    # but accepted FP). A guard relying on this must keep seeing single-line string content.
    src = 'x = "not a triple quote"  # keep me\n'
    assert strip_python_strings(src) == src


def test_strip_blanks_single_line_triple_quoted_string() -> None:
    src = 'DOC = """secret = leaked"""\n'
    out = strip_python_strings(src)
    assert "leaked" not in out
    assert out.startswith("DOC = ")


def test_strip_does_not_mispair_triple_quote_inside_a_comment() -> None:
    # Regression (#366): a `"""` inside a `#` comment is NOT a string delimiter. The old regex
    # paired two comment `"""` and blanked the real code between them (a silent false negative in
    # every guard that scans the result). The ast-based blanker must leave that code intact.
    src = (
        'a = 1                       # opener: """ in a comment\n'
        "exec(request.body)          # a real code-injection sink\n"
        'b = 2                       # closer: """ in a comment\n'
    )
    out = strip_python_strings(src)
    assert "exec(request.body)" in out   # the sink survives — guards can still see it


def test_strip_does_not_mispair_triple_quote_inside_single_line_strings() -> None:
    # A triple-quote sequence appearing inside ordinary single-line string literals must not open a
    # docstring. The old regex paired the two below and blanked the code between; ast sees two
    # single-line Constants and leaves everything intact.
    src = (
        "a = 'x\"\"\"y'\n"      # single-line string containing a """ sequence
        "exec(danger)\n"
        "b = 'p\"\"\"q'\n"      # another one
    )
    out = strip_python_strings(src)
    assert "exec(danger)" in out


def test_strip_blanks_triple_quoted_fstring_content() -> None:
    # Regression (#366): a triple-quoted f-string (`f"""..."""`, common as a multi-line prompt
    # template in LLM apps) must have its content blanked too — else an anti-pattern example inside
    # it leaks as a false positive. In 3.12+ these tokenize as FSTRING_*, not STRING, so a naive
    # tokenize/STRING pass would miss them; the ast JoinedStr branch handles them.
    src = (
        'PROMPT = f"""\n'
        "Example: exec(user_input)  # illustrative only\n"
        "User says: {msg}\n"
        '"""\n'
        "exec(real_sink)\n"
    )
    out = strip_python_strings(src)
    assert "exec(user_input)" not in out   # inside the template: blanked
    assert "exec(real_sink)" in out         # outside: kept


def test_strip_blanks_two_char_prefixed_triple_fstrings() -> None:
    # Regression (#369 review): the prefix window was too narrow, so 2-char-prefixed triple-quoted
    # f-strings (`rf"""`, `fr"""`, ...) passed through unblanked — an anti-pattern inside a raw prompt
    # template would leak. All prefix variants (0-2 chars, any case) must be recognized and blanked.
    for prefix in ("", "r", "f", "u", "b", "rf", "fr", "rb", "br", "Rf", "fR"):
        src = f'T = {prefix}"""\nexec(SECRET_INSIDE)\n"""\nexec(outside)\n'
        out = strip_python_strings(src)
        assert "SECRET_INSIDE" not in out, f"prefix {prefix!r} left the template unblanked"
        assert "exec(outside)" in out, prefix


def test_strip_blanks_bytes_triple_quoted_literal() -> None:
    # Regression (#369 review): a `b"""..."""` bytes triple-quote is blanked too (parity with the old
    # prefix-agnostic regex), not silently skipped as a non-str constant.
    assert "SECRET_BYTES" not in strip_python_strings('B = b"""\nSECRET_BYTES\n"""\n')


def test_strip_stays_total_on_deeply_nested_expression() -> None:
    # Regression (#369 review): ast.parse raises MemoryError/RecursionError ("parser stack
    # overflowed") on deeply nested but parseable input. strip_python_strings must catch it and fall
    # back, not escape and crash the 16 guards that call it. Same class as #367/#368.
    result = strip_python_strings("x = " + "-" * 7000 + "1\n")
    assert isinstance(result, str)


def test_strip_falls_back_gracefully_on_unparseable_input() -> None:
    # The helper must stay total (guards never crash). A file that doesn't parse falls back to the
    # regex path and returns a string, never raises.
    bad = "def broken(:\n    x = 1\n"
    result = strip_python_strings(bad)
    assert isinstance(result, str)


def test_strip_empty_and_no_strings() -> None:
    assert strip_python_strings("") == ""
    assert strip_python_strings("x = 1\ny = 2\n") == "x = 1\ny = 2\n"


# --- #568 (Dean's review): ast col_offset is a UTF-8 BYTE offset, not a code-point index --------


def test_strip_non_ascii_inside_docstring_does_not_corrupt_trailing_code_on_the_same_line() -> None:
    # #568: `ast` reports col_offset/end_col_offset as UTF-8 byte offsets. Using one directly as a
    # `str` slice index overshoots by however many extra bytes a multi-byte character earlier on
    # the line costs, extending the blank window past the real closing `"""` into a sink call
    # sitting on the same physical line right after the string.
    #
    # The drift has to EXCEED the 3 characters of the closing `"""` or this test cannot
    # discriminate: at exactly 3 bytes of drift the over-run consumes the delimiter and stops
    # there, the sink survives intact, and every assertion below passes against the unfixed code
    # (#569 review — the original three 2-byte accents drifted by exactly 3). Three 2-byte accents
    # plus three 3-byte arrows drift by 9 bytes, landing 6 characters past the delimiter.
    src = 'DOC = """café naïve résumé → → →"""; exec(real_sink_after)\n'
    out = strip_python_strings(src)
    assert "café" not in out and "naïve" not in out and "résumé" not in out   # docstring blanked
    assert '"""; exec(real_sink_after)' in out     # closing delimiter AND the real code survive
    assert out.count("\n") == src.count("\n")


def test_strip_docstring_preceded_by_non_ascii_on_the_same_line_is_still_blanked() -> None:
    # #568, the other direction: a non-ASCII single-line string EARLIER on the same physical line
    # inflates the byte offset the triple-quoted docstring that follows it starts at. Using that
    # byte number directly as a character index landed inside the opening `"""` itself, so
    # `_is_triple_quoted` misread the prefix and the docstring was never recognized as one at all
    # — a silent false negative (its content leaks through unblanked).
    src = 'x = "café"; y = """exec(should_be_blanked)"""\n'
    out = strip_python_strings(src)
    assert "exec(should_be_blanked)" not in out
    assert 'x = "café"' in out   # the preceding single-line string is untouched (contract: single-line strings survive)


def test_strip_keeps_fstring_interpolation_after_non_ascii_content() -> None:
    # #568: `_keep_spans`' own FormattedValue positions are byte offsets too. A non-ASCII run
    # inside the f-string before the `{expr}` interpolation drifted the recorded keep-span past
    # the real interpolation, so `_protected()` no longer recognized it and blanked it along with
    # the surrounding template content — the exact #439 regression this span-tracking exists to
    # prevent, reintroduced via a different offset bug.
    src = 'PROMPT = f"""café naïve {user_input} exec(illustrative_only)"""\n'
    out = strip_python_strings(src)
    assert "{user_input}" in out          # the dynamic interpolation must survive, unblanked
    assert "café" not in out and "naïve" not in out and "illustrative_only" not in out


# --- #776: implicit string concatenation folds many literals into ONE ast node -----------------


def test_strip_implicit_concat_triple_first_stays_lexically_valid() -> None:
    # Regression (#776): CPython folds implicitly concatenated adjacent literals into a single
    # Constant node. The blanker assumed node span == one literal (opening delimiter at the node
    # start, closing delimiter in its last 3 chars), so a concatenation OPENING with a
    # triple-quoted literal had that literal's closing `"""` and every interior quote blanked
    # away: one unmatched opener, and every later `"""` in the file flips string/code roles —
    # the blanking is misaligned from there to EOF, an FP *and* FN machine that nothing detected
    # because no consumer re-parses the output. The shape below is agentsec's own `_TOOL_CONTEXT`
    # regex in guards/llm_tool_result_leak.py, the in-repo trigger.
    src = (
        "P = re.compile(\n"
        '    r"""["\']type["\']\\s*:\\s*["\']function["\']"""   # schema dict, quotes inside\n'
        '    r"|tools\\s*=\\s*\\["                              # second fragment\n'
        ")\n"
        "exec(after_the_concat)\n"
    )
    out = strip_python_strings(src)
    ast.parse(out)                                   # output must stay lexically valid Python
    assert "type" not in out                         # triple-quoted content: blanked
    assert 'r"""' in out and out.count('"""') == 2   # BOTH its delimiters survive
    assert 'r"|tools\\s*=\\s*\\["' in out            # single-quoted constituent: intact (contract)
    assert "# second fragment" in out                # interstitial comment: not string content
    assert "exec(after_the_concat)" in out           # code after the construct: never swallowed
    assert out.count("\n") == src.count("\n")


def test_strip_implicit_concat_blanks_a_triple_quoted_literal_that_is_not_first() -> None:
    # #776 facet: the triple-or-not gate looked only at the NODE head, so a concatenation opening
    # with a single-quoted literal was skipped wholesale and a triple-quoted literal later in it
    # was never blanked — the exact docstring-example FP leak #366 exists to prevent. This facet
    # keeps the output lexically valid either way, so the parseable-output gate below can never
    # catch it; it needs this direct assertion.
    src = (
        "MSG = (\n"
        '    "prefix: "\n'
        '    """example: exec(user_input)  # illustrative"""\n'
        ")\n"
    )
    out = strip_python_strings(src)
    ast.parse(out)
    assert "exec(user_input)" not in out     # later triple-quoted constituent: blanked now
    assert '"prefix: "' in out               # single-quoted constituent: intact


def test_strip_implicit_concat_with_triple_fstring_keeps_interpolations() -> None:
    # #776 facet: an f-string anywhere in the concatenation folds the whole thing into one
    # JoinedStr node, which broke identically (unterminated f-string) — and the #439 contract
    # still binds inside a concatenation: `{expr}` interpolations are code, not string content.
    for src in (
        'Q = f"""example: exec(bad_example) {user}"""  "tail"\nexec(real)\n',
        'Q = "head"  f"""example: exec(bad_example) {user}"""\nexec(real)\n',
    ):
        out = strip_python_strings(src)
        ast.parse(out)
        assert "bad_example" not in out, src     # f-string template content: blanked
        assert "{user}" in out, src              # interpolation: survives, unblanked
        assert "exec(real)" in out, src          # code after: intact
        assert ('"tail"' in src) == ('"tail"' in out)   # plain constituents: intact
        assert ('"head"' in src) == ('"head"' in out)


def test_strip_pins_the_tokenize_fallback_degradation(monkeypatch: pytest.MonkeyPatch) -> None:
    # #776 review (PR #818): when `_python_string_literal_spans` returns None (tokenize failed),
    # the blanker DELIBERATELY keeps the single-literal-per-node behavior — for a multi-literal
    # concatenation that is the known pre-#776 degradation (the output can stop lexing as
    # Python). Accepted residual, not an oversight: on 3.12 `ast` and `tokenize` share one
    # tokenizer (PEP 701), so no input that parses-but-does-not-tokenize could be constructed,
    # and the worst case equals pre-fix main for that one file. This test pins the decision so
    # the branch cannot drift silently: it fails if the fallback stops engaging OR if someone
    # improves it — improve it consciously and update this pin (note the regex fallback is NOT
    # a drop-in: it mangles this same shape, per the RCA). The totality floor holds regardless.
    monkeypatch.setattr(base_module, "_python_string_literal_spans", lambda _text: None)
    src = 'x = (\n    """["\']a["\']"""   # c\n    "|b"\n)\ny = 1\n'
    out = strip_python_strings(src)
    assert isinstance(out, str)                  # total, even degraded
    assert out.count("\n") == src.count("\n")    # line numbers preserved, even degraded
    with pytest.raises(SyntaxError):
        ast.parse(out)                           # the accepted degradation, pinned on purpose


@pytest.mark.slow
def test_strip_output_stays_parseable_for_every_repo_file() -> None:
    # #776's gate: the stripped text feeds ~20 guards as line-oriented text plus the
    # `iter_functions`/`enclosing_function_span` internals, and nothing ever re-parses it, so a
    # lexically broken output was invisible by construction — a failure that presents as success.
    # Assert the invariant wholesale over this repo's own code: every file the suite can parse
    # must still parse after stripping. (The one facet this cannot catch is a skipped-but-should-
    # blank literal — the not-first test above covers that direction.)
    repo = Path(__file__).resolve().parents[2]
    checked = 0
    for tree in ("agentsec", "scripts"):
        for f in sorted((repo / tree).rglob("*.py")):
            text = f.read_text(encoding="utf-8")
            try:
                ast.parse(text)
            except SyntaxError:
                continue                         # a file WE cannot parse is not the blanker's problem
            try:
                ast.parse(strip_python_strings(text))
            except SyntaxError as exc:
                pytest.fail(
                    f"strip_python_strings broke {f.relative_to(repo)}: {exc.msg} (line {exc.lineno})"
                )
            checked += 1
    assert checked > 300                         # the sweep actually swept (agentsec/ alone is ~370 files)


# --- strip_hash_comments (#362): YAML/shell `#`-comment stripper -------------------------------

def test_strip_hash_strips_trailing_comment() -> None:
    assert strip_hash_comments("PORT: 6379   # the redis port").strip() == "PORT: 6379"


def test_strip_hash_preserves_hash_inside_a_quoted_value() -> None:
    # #362 (the #358/#360 FP class): a `#` inside a value is NOT a comment — naive split("#")
    # would clip the password to `"a`.
    assert strip_hash_comments('REDIS_PASSWORD: "a#b"').strip() == 'REDIS_PASSWORD: "a#b"'
    assert strip_hash_comments('  --requirepass "p#ss"').strip() == '--requirepass "p#ss"'


def test_strip_hash_full_line_comment_becomes_empty() -> None:
    assert strip_hash_comments("# fully commented").strip() == ""


def test_strip_hash_per_line_and_empty() -> None:
    assert strip_hash_comments("") == ""
    # one space before `#` -> clean strip; a full-line comment -> empty; no-comment lines untouched.
    assert strip_hash_comments("a: 1 # c\nb: 2\n# d\nc: 3") == "a: 1\nb: 2\n\nc: 3"


def test_strip_hash_preserves_space_hash_inside_quotes() -> None:
    # Issue #418 (was the "~90% caveat" lock, now inverted): a space-before-`#` INSIDE a quoted
    # span is string content, not a comment, so the whole value survives. This is the FN-fix:
    # a quote-unaware strip used to clip to `x = "a`, dropping whatever a guard matched after it.
    assert strip_hash_comments('x = "a #b"') == 'x = "a #b"'
    # Single quotes clip the same way pre-fix — now preserved too.
    assert strip_hash_comments("password: 'p #ss'") == "password: 'p #ss'"


def test_strip_hash_preserves_408_credential_msg() -> None:
    # The exact PR #408 Critical #1 line: a quoted `#` before an interpolated credential must NOT
    # truncate the value (else the ansible credential-echo guard silently misses the leak).
    line = 'msg: "Info #1: password is {{ ansible_become_password }}"'
    assert strip_hash_comments(line) == line


def test_strip_hash_strips_trailing_comment_after_closed_quote() -> None:
    # A genuine trailing comment AFTER a closed quoted value is still stripped (the `#` is outside
    # the quotes on the masked copy).
    assert strip_hash_comments('a: "v" # tail').rstrip() == 'a: "v"'


def test_strip_hash_unterminated_quote_still_clips() -> None:
    # An UNTERMINATED quote never pairs, so nothing is masked and the `#` strips exactly as before
    # (unchanged behavior — not a regression).
    assert strip_hash_comments('msg: "unclosed # rest').rstrip() == 'msg: "unclosed'


def test_strip_hash_unpaired_quote_caveat() -> None:
    # Documented fix caveat: two apostrophes (an unpaired `'` before the comment + a `'` inside it)
    # span the `#`, masking a REAL comment so it survives. This is the inverse, FP-direction miss —
    # strictly safer than the FN it replaces. Locked so it isn't mistaken for a regression.
    assert strip_hash_comments("msg: don't fail # it's fine") == "msg: don't fail # it's fine"


# --- strip_python_line_comment (#376): the Python-context `#`-stripper (string-aware) ----------

def test_strip_python_line_comment_strips_trailing_comment() -> None:
    assert strip_python_line_comment("handle(event)  # no event.id check") == "handle(event)  "


def test_strip_python_line_comment_keeps_hash_inside_a_string() -> None:
    # The #376 FP class: a `#` inside a string literal is NOT a comment — a naive split("#")
    # would clip the line and drop the real code (`event.id`) after it.
    assert strip_python_line_comment('logger.info("tag #%s", event.id)') == 'logger.info("tag #%s", event.id)'


def test_strip_python_line_comment_masks_not_strips_strings() -> None:
    # MASK (not strip): string CONTENT after the `#`-in-string is preserved, so a `event["id"]`
    # subscript on such a line survives for the caller to match.
    line = 'logger.warning("dupe? #tag", event["id"])'
    assert strip_python_line_comment(line) == line


def test_strip_python_line_comment_real_comment_after_a_string() -> None:
    # A `#` in a string, THEN a real trailing comment: keep the string, drop the comment.
    assert strip_python_line_comment('x = "a#b"  # real') == 'x = "a#b"  '


def test_strip_python_line_comment_no_comment_and_full_line() -> None:
    assert strip_python_line_comment("x = 1") == "x = 1"
    assert strip_python_line_comment("    # full-line comment") == "    "


# --- the #419 linear SQL-scan helpers: direct contracts (PR #430 review, Medium #1) ---------
# Each test pins the helper against the exact lazy-regex form it replaced, so a future edit
# (an off-by-one in the semi == -1 path, a broken resume position) fails HERE, not just in
# whichever guard's pattern-shape happens to exercise it.


def test_iter_statement_spans_equivalent_to_lazy_regex() -> None:
    import re

    head = re.compile(r"create\s+policy\b", re.I)
    legacy = re.compile(r"create\s+policy\b.*?;", re.I | re.S)
    for sql in (
        "create policy a on t using (true); junk; create policy b on t2 using (true);",
        "create policy a on t; create policy b on t",     # unterminated tail statement
        "noise; create Policy x\n  on t\n  using (true);",  # multiline + mixed case
        "create policy;",                                   # zero-content statement
        "no heads here; at all;",
        "",
    ):
        spans = list(iter_statement_spans(sql, head))
        assert spans == [m.span() for m in legacy.finditer(sql)], sql


def test_iter_statement_spans_head_without_terminator_yields_nothing() -> None:
    import re

    head = re.compile(r"create\s+policy\b", re.I)
    assert list(iter_statement_spans("create policy p on t using (true)", head)) == []


# --- issue #559: the terminator search is quote-aware --------------------------------------
# `find_statement_end` is the ONE place `iter_statement_spans` / `iter_bounded_matches` diverge
# from the lazy regex they replaced: the regex stopped at the first `;` regardless of quotes, so
# `CREATE POLICY "grant; select" ON …` carved down to `CREATE POLICY "grant;`. The equivalence
# tests above still hold because their corpus has no quoted `;`; these pin the divergence, the
# degrade paths that keep malformed SQL at today's carve, and the linear bound.


def _policy_spans(sql: str) -> list[str]:
    import re

    head = re.compile(r"create\s+policy\b", re.I)
    return [sql[s:e] for s, e in iter_statement_spans(sql, head)]


def test_find_statement_end_quoted_semicolon_is_content() -> None:
    # The #559 shape and its single-quoted / doubled-delimiter / E'…' siblings: every `;` inside
    # a one-line quoted span is skipped and the real terminator ends the statement.
    for sql in (
        'create policy "grant; select" on d for insert to authenticated using (x);',
        "create policy p on t using (x = 'a;b');",
        "create policy p on t using (x = 'it''s; ok');",
        'create policy "a""b; c" on t using (true);',
        "create policy p on t using (x = E'a\\'; b');",
    ):
        assert find_statement_end(sql, 0) == len(sql) - 1, sql
        assert _policy_spans(sql) == [sql], sql


def test_iter_statement_spans_issue_559_two_policies_with_semicolon_names() -> None:
    # The issue's own measurement: main yielded ['CREATE POLICY "grant;', 'CREATE POLICY "another;'].
    sql = (
        'CREATE POLICY "grant; select" ON documents FOR INSERT TO authenticated USING (x);\n'
        'CREATE POLICY "another; one" ON documents FOR INSERT TO authenticated USING (y);'
    )
    assert _policy_spans(sql) == sql.split("\n")


def test_find_statement_end_unterminated_quote_degrades_to_bare_find() -> None:
    # #435's invariant, kept: a quote with no partner anywhere ahead must not swallow the file.
    sql = "create policy p on t using (x = 'abc);\ncreate policy q on t using (true);"
    assert _policy_spans(sql) == sql.split("\n")
    assert find_statement_end("create policy p on t using (x = 'a;b')", 0) == -1
    assert find_statement_end("", 0) == -1


def test_find_statement_end_quote_closing_past_a_newline_is_stray() -> None:
    # The #528 shape: the stray quote in `p` WOULD pair with `q`'s literal. Honouring that pair
    # merges `p` and `q` into one span and loses `q` (measured on the unbounded prototype). The
    # single-line bound makes it degrade to the pre-#559 carve instead: three statements.
    sql = (
        "create policy p on t using (x = 'abc);\n"
        "create policy q on t using (y = 'z');\n"
        "create policy r on t using (true);"
    )
    assert _policy_spans(sql) == sql.split("\n")


def test_find_statement_end_head_inside_execute_literal_does_not_frame_shift() -> None:
    # A `create policy` matched INSIDE an `EXECUTE format('…')` literal starts in string context
    # the scanner cannot know about, so the literal's CLOSING quote reads as an opener. Unbounded,
    # that opener pairs into `q`'s literal on the next line and swallows `q` (measured). Bounded,
    # the carve is exactly today's: the `DO` body's statement, then `q`, then `r`.
    sql = (
        "do $$ begin execute format('create policy %I on %I using (true)', 'n', 't'); end $$;\n"
        "create policy q on t using (y = 'z');\n"
        "create policy r on t using (true);"
    )
    got = _policy_spans(sql)
    assert got[0] == "create policy %I on %I using (true)', 'n', 't');"
    assert got[1:] == sql.split("\n")[1:]


def test_find_statement_end_multiline_statement_with_single_line_quotes() -> None:
    # The bound is per QUOTED SPAN, not per statement: a multi-line policy whose quoted `;`s each
    # sit on one line still carves whole.
    sql = 'create policy "a; b"\n  on t\n  for select\n  using (x = \'c;d\');\ncreate policy q on t using (true);'
    assert _policy_spans(sql) == [sql.split("\ncreate policy q")[0], "create policy q on t using (true);"]


def test_iter_bounded_matches_quoted_semicolon_is_content() -> None:
    import re

    head = re.compile(r"create\s+policy\b", re.I)
    on = re.compile(r"\bon\s+(\w+)", re.I)
    sql = (
        'create policy "grant; select" on documents using (true); '
        'create policy "b; c" on t2 using (x = \'y;z\');'
    )
    # main: [] — both bounds landed inside the names, neither `on` tail was inside its bound.
    assert [m.group(1) for (m,) in iter_bounded_matches(sql, head, on)] == ["documents", "t2"]


@pytest.mark.slow
def test_find_statement_end_hostile_quotes_stay_linear() -> None:
    # #559 must not reintroduce the #419 class. Two growth assertions, one per code path, rather
    # than a bare wall-clock budget: a budget needs a measured healthy AND a measured broken value
    # (tests/test_timing_budgets.py), and the broken value here would be a hypothetical quadratic
    # search nobody has written. Growth is machine-speed independent and needs neither. Four
    # sizes each, per `assert_growth`'s own rule.
    import re

    head = re.compile(r"create\s+policy\b", re.I)

    # One head, then a wall of alternating quotes with no `;`: every pairing scan is two chars
    # long and the `[;'"]` search dominates. Linear because scans of one kind tile the input.
    walls = {n: "create policy x on t using (" + "'\"" * n for n in (10_000, 40_000, 160_000, 640_000)}

    def scan_wall(n: int) -> None:
        assert list(iter_statement_spans(walls[n], head)) == []

    assert_growth(scan_wall, [10_000, 40_000, 160_000, 640_000], expected="linear")

    # n statements that each open a `'` they never close: each pair crosses a newline, so every
    # statement takes the degrade path (pair scan, newline check, bare find) and is still carved.
    strays = {n: "create policy x on t using (x = 'a);\n" * n for n in (1_000, 4_000, 16_000, 64_000)}

    def scan_strays(n: int) -> None:
        assert len(list(iter_statement_spans(strays[n], head))) == n

    assert_growth(scan_strays, [1_000, 4_000, 16_000, 64_000], expected="linear")

    # The remaining quote-heavy shapes are correctness-only here: doubled delimiters and `E'…'`
    # escapes are the same two-char pairing scan the first growth assertion times.
    assert list(iter_statement_spans("create policy x on t using (" + "''" * 500_000, head)) == []
    assert list(iter_statement_spans("create policy x on t using (" + "E'\\'" * 250_000, head)) == []
    assert list(iter_statement_spans("create policy x on t using (x = 'a)\n" * 30_000, head)) == []


def test_find_statement_end_end_bound_reads_nothing_past_it() -> None:
    # `end` works like `str.find(sub, start, end)`: a `;` at or past it is not found, a quoted
    # `;` before it is still content, and a quote whose close lies past it is stray WITHIN the
    # bound (the search degrades to the bare find, still bounded).
    assert find_statement_end("a; b", 0, 1) == -1
    assert find_statement_end("'x;y' ; z", 0, 6) == -1
    assert find_statement_end("'x;y' ; z", 0, 7) == 6
    assert find_statement_end("'a;b' ;", 0, 3) == 2
    assert find_statement_end("a; b", 0, 99) == 1


def test_blank_policy_names_masks_only_the_quoted_name() -> None:
    sql = 'create policy "foo; on bar" on documents using (x = \'a\');\ncreate policy p2 on "s"."t";'
    out = blank_policy_names(sql)
    assert len(out) == len(sql) and out.count("\n") == sql.count("\n")
    assert out.startswith("create policy " + " " * len('"foo; on bar"') + " on documents")
    assert out.endswith('create policy p2 on "s"."t";')          # an unquoted name is untouched
    # Doubled quotes stay inside the name; a stray quote is left alone (single-line bound), so it
    # cannot pair with a later statement's `"s"."t"` and blank the head between.
    assert blank_policy_names('create policy "a""b" on t;') == 'create policy ' + " " * 6 + ' on t;'
    stray = 'create policy "oops on t;\ncreate policy p on "s"."t";'
    assert blank_policy_names(stray) == stray


def test_iter_bounded_matches_equivalent_to_chained_lazy_regex() -> None:
    import re

    head = re.compile(r"revoke\b", re.I)
    t1 = re.compile(r"\bon\s+(\w+)", re.I)
    t2 = re.compile(r"\bfrom\b", re.I)
    legacy = re.compile(r"revoke\b[^;]*?\bon\s+(\w+)[^;]*?\bfrom\b", re.I)
    for sql in (
        "revoke update on t1 from public; revoke x; revoke select on t2 from anon;",
        "revoke on t1;",                       # inner tail chain fails (no `from`)
        "revoke update on t1 from public",     # no terminator at all — tails don't require one
        "revoke from on;",                     # tails out of order — must not match
        "",
    ):
        got = [m1.group(1) for m1, _t in iter_bounded_matches(sql, head, t1, t2)]
        assert got == [m.group(1) for m in legacy.finditer(sql)], sql


def test_iter_bounded_matches_monotone_skip_neither_loses_nor_invents_matches() -> None:
    import re

    head = re.compile(r"create\s+policy\b", re.I)
    on = re.compile(r"\bon\s+(\w+)", re.I)
    legacy = re.compile(r"create\s+policy\b[^;]*?\bon\s+(\w+)", re.I)
    # first head's lazy scan crosses the second head to reach `on` (both forms match from head 1);
    # a failed statement is skipped whole; a head after the `;` still matches.
    for sql in (
        "create policy x create policy y on t;",
        "create policy a; create policy b on t;",
        "create policy a nothing here; create policy b on t2; create policy c;",
    ):
        got = [m.group(1) for (m,) in iter_bounded_matches(sql, head, on)]
        assert got == [m.group(1) for m in legacy.finditer(sql)], sql


def test_iter_bounded_matches_three_tail_inner_failure_skips_statement() -> None:
    import re

    head = re.compile(r"revoke\b", re.I)
    tails = (re.compile(r"\bon\s+(\w+)", re.I), re.compile(r"\bfrom\b", re.I),
             re.compile(r"\b(?:authenticated|public)\b", re.I))
    sql = "revoke all on t1 from service_role; revoke all on t2 from public;"
    got = [(m1.group(1)) for m1, _f, _r in iter_bounded_matches(sql, head, *tails)]
    assert got == ["t2"]  # first statement fails the ROLE tail; second still found


# --- is_llm_framework_repo (issue #389) --------------------------------------------------------
# The LLM-framework self-exclusion was a ~30-line helper duplicated across
# `ai/lethal_trifecta.py`, `guards/system_prompt_exposure.py`, and
# `guards/mcp_tool_unverified.py`. The copies drifted: only the canonical one was made total,
# so the two private copies raised `AttributeError` on a malformed pyproject. #389 consolidated
# all four call sites onto this single definition in `base.py`. These lock its behavior.


def _fw(root: Path) -> StackProfile:
    return mkprofile(root, llm_framework="langchain")


def test_is_llm_framework_repo_true_for_framework_at_root(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "langchain"\n', encoding="utf-8")
    assert is_llm_framework_repo(tmp_path, _fw(tmp_path)) is True


def test_is_llm_framework_repo_true_for_monorepo_subpackage(tmp_path: Path) -> None:
    # langchain keeps its package at libs/langchain/pyproject.toml, not the workspace root.
    sub = tmp_path / "libs" / "langchain"
    sub.mkdir(parents=True)
    (sub / "pyproject.toml").write_text('[project]\nname = "langchain-core"\n', encoding="utf-8")
    assert is_llm_framework_repo(tmp_path, _fw(tmp_path)) is True


def test_is_llm_framework_repo_false_for_app_repo(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "my-agent-app"\n', encoding="utf-8")
    assert is_llm_framework_repo(tmp_path, _fw(tmp_path)) is False


def test_is_llm_framework_repo_false_without_detected_framework(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "langchain"\n', encoding="utf-8")
    assert is_llm_framework_repo(tmp_path, mkprofile(tmp_path)) is False  # llm_framework is None


@pytest.mark.parametrize(
    "pyproject",
    [
        'project = "x"\n',        # [project] is not a table  -> old copies: 'str' has no 'get'
        "[project]\nname = 123\n",  # name is not a string     -> old copies: 'int' has no 'lower'
    ],
)
def test_is_llm_framework_repo_total_on_malformed_pyproject(tmp_path: Path, pyproject: str) -> None:
    # The #389 regression guard: the canonical helper must return False, never raise, on a
    # crafted/odd pyproject.toml (the two former private copies raised AttributeError here).
    (tmp_path / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    assert is_llm_framework_repo(tmp_path, _fw(tmp_path)) is False


def test_strip_js_apostrophe_after_identifier_is_not_a_string_opener() -> None:
    # Regression (#440 review): a `'` directly after an identifier character is an apostrophe in
    # JSX TEXT (`<p>It's fine</p>`), not a string opener — `x'` is not valid JS. Treating it as
    # one paired it with the next quote on the line and blanked everything between, which under
    # `strip_strings=True` DELETED a CRITICAL DOM-XSS sink sitting on the same line.
    src = "  return <p>It's fine</p>; document.getElementById('x').innerHTML = html;"
    assert "innerHTML" in strip_js_comments(src, strip_strings=True)


def test_strip_js_real_strings_are_still_blanked() -> None:
    # FP-bait: the rule must not stop real string literals being blanked, and a tagged template
    # literal legitimately DOES follow an identifier, so backticks are excluded from it.
    out = strip_js_comments("const s = 'req.count'; const q = req.query.x;", strip_strings=True)
    assert "req.count" not in out and "req.query.x" in out
    assert "http://x" not in strip_js_comments('const u = "http://x"; a();', strip_strings=True)
    assert "foo();" in strip_js_comments("const t = tag`hi ${x}`; foo();", strip_strings=True)


@pytest.mark.parametrize("strip_strings", [False, True])
@pytest.mark.parametrize(
    ("src", "sink"),
    [
        # A keyword may legally abut a string literal with no space — ubiquitous in minified JS.
        ("if(a)return'foo//bar';document.getElementById('x').innerHTML=html;", "innerHTML"),
        ("throw'err//not really a comment';document.write(html);", "document.write"),
        ("return'foo//bar';document.write(x);", "document.write"),
        ("switch(k){case'a//b': el.innerHTML=html; break;}", "innerHTML"),
        ("for(const c of'a//b'){} el.innerHTML=html;", "innerHTML"),
        ("const t=typeof'a//b'; el.innerHTML=html;", "innerHTML"),
        ("delete o['k//x']; el.innerHTML=html;", "innerHTML"),
        ("const e=new'x//y'; el.innerHTML=html;", "innerHTML"),
    ],
)
def test_strip_js_keyword_abutting_string_is_a_real_opener(
    src: str, sink: str, strip_strings: bool
) -> None:
    # Regression: the JSX-apostrophe rule (#440) originally looked at the single character before
    # the quote, which cannot tell `It's` from `return'x'`. Missing the opener left the scan in
    # "code" mode INSIDE the string, so the `//` in the string body was read as a real line comment
    # and the rest of the line was blanked — DELETING the sink that followed. Quote tracking drives
    # comment detection regardless of `strip_strings`, so this must hold at BOTH settings.
    assert sink in strip_js_comments(src, strip_strings=strip_strings)


@pytest.mark.parametrize("strip_strings", [False, True])
def test_strip_js_apostrophe_rule_survives_the_keyword_fix(strip_strings: bool) -> None:
    # The other direction: gating on the preceding WORD must NOT regress the case #440 fixed —
    # `It's` / `don't` in JSX text are still not string openers, so the same-line sink survives.
    src = "  return <p>It's fine, don't worry</p>; document.getElementById('x').innerHTML = html;"
    assert "innerHTML" in strip_js_comments(src, strip_strings=strip_strings)


def test_strip_js_keyword_abutting_string_content_is_still_blanked() -> None:
    # FP-bait for the fix: recognising `return'…'` as a real opener must also mean its CONTENT is
    # blanked under strip_strings — else a pattern appearing only inside that string would match.
    out = strip_js_comments("if(a)return'req.count'; const q = req.query.x;", strip_strings=True)
    assert "req.count" not in out and "req.query.x" in out


# --------------------------------------------------------------------------------------------
# `_quote_is_jsx_apostrophe`: the string-opener decision, over the WHOLE keyword vocabulary.
#
# THE INVARIANT UNDER TEST: a `'`/`"` abutting a word W opens a string iff `W'...'` is legal JS.
#
# The first fix for this (commit 34442202) gated on `_REGEX_PRECEDING_KEYWORDS` — the answer to a
# DIFFERENT question (which tokens may precede a REGEX rather than a division). That set contains
# `return`/`throw`/`case`/`typeof`, so those looked fixed, while `from`/`default`/`extends`/`as`/
# `static` kept silently deleting sinks: `import t from"https://cdn/x.js";<sink>` — plain esbuild
# output — read the `//` in the URL as a line comment and blanked the rest of the line. The tables
# below are driven by the KEYWORD SET, not by a sample, and a drift gate ties them together.
# --------------------------------------------------------------------------------------------

# Every keyword after which a string may legally begin, each with a minimal real construct. Verified
# legal against the V8 parser (`node`, ES2024); the `//` inside each string is the payload that gets
# misread as a line comment when the opener is missed.
_ABUTTING_CONSTRUCTS: list[tuple[str, str]] = [
    ("return", "function f(){return'foo//bar';}"),
    ("throw", "throw'foo//bar';"),
    ("typeof", "const t=typeof'foo//bar';"),
    ("void", "const t=void'foo//bar';"),
    ("delete", "delete o['foo//bar'];"),
    ("new", "const e=new'foo//bar';"),
    ("await", "async function f(){await'foo//bar';}"),
    ("yield", "function*g(){yield'foo//bar';}"),
    ("in", "if(k in'foo//bar'){}"),
    ("instanceof", "if(k instanceof'foo//bar'){}"),
    ("of", "for(const c of'foo//bar'){}"),
    ("case", "switch(k){case'foo//bar': break;}"),
    ("do", "do'foo//bar';while(0);"),
    ("else", "if(a)b();else'foo//bar';"),
    ("import", 'import"https://cdn.example.com/lib.js";'),
    ("from", 'import t from"https://cdn.example.com/lib.js";'),
    ("default", "export default'foo//bar';"),
    ("extends", "class A extends'foo//bar'{}"),
    ("as", "export {a as'foo//bar'};"),
    ("static", "class A{static'foo//bar'(){}}"),
    ("get", "const o={get'foo//bar'(){}};"),
    ("set", "const o={set'foo//bar'(v){}};"),
    ("async", "const o={async'foo//bar'(){}};"),
]


def test_string_abutting_keyword_table_covers_the_whole_set() -> None:
    # Drift gate: the table above must stay in lockstep with the set the code consults, so a keyword
    # added to `_STRING_ABUTTING_KEYWORDS` without a construct proving it (or vice versa) fails here
    # rather than shipping untested. This is the guard against re-deriving the set from a sample.
    assert {kw for kw, _ in _ABUTTING_CONSTRUCTS} == set(_STRING_ABUTTING_KEYWORDS)


@pytest.mark.parametrize("strip_strings", [False, True])
@pytest.mark.parametrize(("keyword", "construct"), _ABUTTING_CONSTRUCTS, ids=[k for k, _ in _ABUTTING_CONSTRUCTS])
def test_every_string_abutting_keyword_opens_a_string(
    keyword: str, construct: str, strip_strings: bool
) -> None:
    # THE DECISION: the `//` inside the abutting string must not be read as a line comment, so a sink
    # on the same line SURVIVES. Quote tracking drives comment detection regardless of `strip_strings`
    # (that is why the original bug bit at the DEFAULT setting too), so this must hold at both.
    out = strip_js_comments(f"{construct}document.write(location.hash);", strip_strings=strip_strings)
    assert "document.write(location.hash);" in out, keyword


# Operators and punctuation that can abut a string opener. None reaches the keyword rule at all (the
# rule only fires after an identifier CHARACTER), so these lock in that the rule's entry condition
# stayed narrow — a widened one would suppress openers after `,` `=` `(` and delete sinks wholesale.
_ABUTTING_OPERATORS = [",", "=", "(", "[", "{", ":", "?", "+", "-", "!", "&&", "||", "??", "=>", "...", ";"]


@pytest.mark.parametrize("strip_strings", [False, True])
@pytest.mark.parametrize("op", _ABUTTING_OPERATORS)
def test_operator_abutting_string_always_opens(op: str, strip_strings: bool) -> None:
    out = strip_js_comments(f"x{op}'foo//bar';document.write(location.hash);", strip_strings=strip_strings)
    assert "document.write(location.hash);" in out, op


# The other side of the invariant: for these words `W'...'` does NOT parse as JS, so the quote can
# only be JSX text. Includes the keywords that need an identifier/paren/block next (`let`, `class`,
# `function`, `const`, `var`, `try`, `export`, `enum`) and the VALUE keywords (`this`, `true`) — this
# is exactly what keeps `<p>Let's go</p>` and `<p>the class's name</p>` reading as apostrophes, and
# what a naive "all keywords are openers" fix would have broken.
_NON_OPENING_WORDS = [
    "It", "don", "we", "said", "user", "Let", "let", "class", "function", "const",
    "var", "try", "export", "enum", "this", "true", "null", "super", "if", "for",
]


@pytest.mark.parametrize("strip_strings", [False, True])
@pytest.mark.parametrize("word", _NON_OPENING_WORDS)
def test_non_abutting_word_leaves_a_jsx_apostrophe(word: str, strip_strings: bool) -> None:
    src = f"return <p>the {word}'s value</p>; document.write(location.hash);"
    assert "document.write(location.hash);" in strip_js_comments(src, strip_strings=strip_strings), word


@pytest.mark.parametrize("strip_strings", [False, True])
def test_member_access_before_quote_is_an_apostrophe_not_an_opener(strip_strings: bool) -> None:
    # A reserved word used as a PROPERTY name is a value, and `obj.default'x'` is a syntax error
    # (`node --check` confirms) — so the quote cannot be an opener and the member-access branch is
    # load-bearing, not dead. NB the `/`-site mirrors the same check for a different reason there
    # (`obj.default / 2` IS legal division); the analogy does not carry, only the conclusion does.
    src = "return <p>{u.default}'s and {u.get}'s</p>; document.write(location.hash);"
    assert "document.write(location.hash);" in strip_js_comments(src, strip_strings=strip_strings)


@pytest.mark.parametrize("strip_strings", [False, True])
def test_unterminated_quote_is_closed_at_the_line_boundary(strip_strings: bool) -> None:
    # BLAST-RADIUS CAP. The opener decision is a heuristic, so it can err in both directions; JSX
    # prose whose word happens to be a keyword (`<p>the new's angle</p>`) is the residual. A raw
    # newline cannot appear inside a `'`/`"` literal, so the scanner closes it at the line boundary —
    # confining any such error to ONE line instead of desyncing (and, under strip_strings, blanking)
    # every line to EOF. `new` is deliberately a word the PREVIOUS code already opened on, so this
    # test isolates the cap: before it, this whole file went dark from line 2 onward.
    src = "const a = 1;\n<p>the new's angle</p>\ndocument.write(location.hash);\n"
    out = strip_js_comments(src, strip_strings=strip_strings)
    assert "document.write(location.hash);" in out
    assert "const a = 1;" in out


def test_template_literal_still_spans_lines_after_the_cap() -> None:
    # FP-bait for the cap: backticks legitimately span lines, so the line-boundary close must be
    # scoped to `'`/`"` only — else multi-line template content would leak past `strip_strings`.
    out = strip_js_comments("const t = `line1\nreq.count\nline3`; const q = req.query.x;", strip_strings=True)
    assert "req.count" not in out and "req.query.x" in out


@pytest.mark.parametrize("strip_strings", [False, True])
def test_leading_apostrophe_jsx_no_longer_blanks_its_line(strip_strings: bool) -> None:
    # WAS a documented pre-existing gap: a quote at the START of a JSX word (`<p>'Tis</p>`) has no
    # identifier before it, so the word rule never fires and it read as an opener — blanking the rest
    # of the line under strip_strings. The prospective close-on-this-line test closes it for free, at
    # BOTH settings: a lone `'` with no unescaped partner before the line boundary cannot open a string
    # literal, whatever precedes it. Kept parametrized so a future change cannot re-split the two.
    out = strip_js_comments("<p>'Tis</p>;document.write(location.hash);", strip_strings=strip_strings)
    assert "document.write(location.hash);" in out


@pytest.mark.parametrize("strip_strings", [False, True])
def test_quote_with_no_partner_on_its_line_never_opens_a_string(strip_strings: bool) -> None:
    # The #440 CRITICAL, in the direction the fix was written for. A JSX apostrophe on one of the
    # keywords that CAN legally precede a string (`default`, `import`, `from`, `as`, …) used to open a
    # string that swallowed the rest of its own line, deleting a real sink after it.
    src = "const I = () => <p>the default's notes</p>; setTimeout(\"el.innerHTML=\" + u, 100);"
    out = strip_js_comments(src, strip_strings=strip_strings)
    assert "setTimeout(" in out


def test_quote_with_no_partner_does_not_hide_a_real_line_comment() -> None:
    # The #440 HIGH, the reverse direction of the same defect: with the scanner wrongly "inside a
    # string", a real `//` was not recognised as a comment, so a commented-out sink FIRED.
    out = strip_js_comments("<p>read the default's docs // el.innerHTML = u; do not copy</p>")
    assert "el.innerHTML" not in out


@pytest.mark.parametrize("strip_strings", [False, True])
def test_a_string_that_closes_on_its_line_still_opens(strip_strings: bool) -> None:
    # THE TRADED-AGAINST DIRECTION. The fix NARROWS what counts as an opener, so its risk is a missed
    # real string: string body then reads as code, and a `//` inside it would blank the rest of the
    # line. A `'...'`/`"..."` that closes on its own line must still open — `"https://x"` is the case
    # that matters, since its `//` is inside the string.
    out = strip_js_comments('const u = "https://x.example/a"; el.innerHTML = userInput;', strip_strings=strip_strings)
    assert "el.innerHTML = userInput;" in out
    assert ("https://x.example/a" in out) is (strip_strings is False)


def test_escaped_closing_quote_does_not_count_as_the_partner() -> None:
    # Backslash parity in the lookahead: the only other `'` is escaped, so it cannot close the literal
    # and the leading quote is correctly not an opener. Guards the `_last_unescaped_quotes` parity walk.
    out = strip_js_comments("<p>it\\'s</p>;document.write(location.hash);")
    assert "document.write(location.hash);" in out


# --- pinning #440's opener decision, and its one real interaction with #542 -------------------
#
# Why these exist, and why the first version of them was wrong. The merge review
# (`pr-440-rescope-merge-review-2026-08-09.md`, finding 3) recorded that the #440/#542
# reconciliation added zero tests, so the merged set was exactly the union of both parents. The first
# attempt to close that gap tested "a #440 construct INSIDE a #542 template frame" and the gate on it
# found the premise wrong in three ways, all of them measured:
#
#   1. An apostrophe inside a `${…}` substitution behaves IDENTICALLY on `main` and here (0 of 32
#      arms differ, across 1-deep, 2-deep, brace-in-substitution, sink-on-the-same-line, and a
#      substitution spanning lines). A substitution quote never reaches the top-level opener
#      decision, so the two mechanisms simply do not meet there.
#   2. "The seam is an apostrophe followed by a template" was a property of the sample, not the code.
#      A fixture with NO template at all differs between the trees, and so does one with the template
#      BEFORE the apostrophe. The discriminating axis is just #440's opener decision under
#      `strip_strings=True`; templates are incidental to almost all of it.
#   3. The fixtures used a closing JSX tag (`</p>`), whose `/` opens a REGEX-literal scan that runs
#      to end of line — so the template in those fixtures was never lexed at all, and a test comment
#      claiming "#542's pushdown must still see the backtick" described something that never happened.
#
# So this block no longer claims to be a seam battery. It pins what is actually pinnable: the opener
# predicate (which nothing else in the suite covers — see below), and the ONE assertion that genuinely
# constrains the #542 side.
#
# THE COVERAGE HOLE THIS EXISTS FOR. Before `test_jsx_apostrophe_predicate_is_load_bearing`, deleting
# `_quote_is_jsx_apostrophe` from the opener gate left the ENTIRE suite green — the predicate #440 is
# named for, and the fix for its critical detection loss, was pinned by nothing. That mutation now
# fails here. Asserting on a surviving SINK does not achieve this: in every fixture below the sink
# survives on both trees and under the mutation, so the assertion has to be on the blanked span
# itself.
#
# Each test also asserts the two structural invariants from the review's 44-case probe — output
# length and `splitlines()` count unchanged — because callers report `file:line`, so a blanking bug
# that shifts either desyncs every finding location in the file.


def _assert_layout_preserved(src: str, out: str) -> None:
    assert len(out) == len(src), "blanking must preserve length — callers report file:line"
    assert len(out.splitlines()) == len(src.splitlines()), "line count must survive blanking"


@pytest.mark.parametrize("strip_strings", [False, True])
def test_jsx_apostrophe_predicate_is_load_bearing(strip_strings: bool) -> None:
    # THE MECHANISM TEST. Two apostrophes on the line, so the `last_quote[c] > i` lookahead DOES find
    # a partner and admits the quote — which makes `_quote_is_jsx_apostrophe` the only thing left that
    # can reject it. That is what makes this shape pin the predicate where a single-apostrophe line
    # cannot (there the lookahead rejects first and the predicate is never consulted).
    #
    # Verified by mutation, not assumed: with `_quote_is_jsx_apostrophe` removed from the opener gate
    # this line becomes `const a = <p>don'          's here</p>;` and this test fails. Before it, that
    # same mutation left all 5317 tests passing.
    src = "const a = <p>don't stop, it's here</p>;\nel.innerHTML = user;\n"
    out = strip_js_comments(src, strip_strings=strip_strings)
    _assert_layout_preserved(src, out)
    assert out == src, "JSX prose with two apostrophes must be left entirely alone"


@pytest.mark.parametrize("strip_strings", [False, True])
def test_a_real_string_on_the_line_still_opens(strip_strings: bool) -> None:
    # THE TRADED-AGAINST DIRECTION for the predicate test above. Narrowing what counts as an opener
    # risks missing a REAL string, whose body would then be scanned as code. A genuine `'...'` on a
    # line with other apostrophe-shaped punctuation must still open and still be blanked under
    # `strip_strings`. (Non-discriminating by construction — `main` passes it too. That is the point:
    # it is the FP-bait, not a regression test.)
    src = "const u = 'https://x.example/a'; el.innerHTML = user;\n"
    out = strip_js_comments(src, strip_strings=strip_strings)
    _assert_layout_preserved(src, out)
    assert "el.innerHTML = user;" in out
    assert ("https://x.example/a" in out) is (strip_strings is False)


@pytest.mark.parametrize("strip_strings", [False, True])
def test_top_level_apostrophe_does_not_swallow_a_following_template(strip_strings: bool) -> None:
    # The one shape where #440's decision genuinely hands off to #542's pushdown, with the closing
    # JSX tag REMOVED so the template is actually reached (with `</p>` present the `/` starts a regex
    # scan and the template is never lexed — the defect that sank the first version of this test).
    # On `main` the apostrophe opens a string that swallows the rest of the line including the
    # backtick, so the frame is never pushed and the next line is blanked too.
    src = "const a = <p>don't; const t = `v ${ q.count } w`;\ndocument.write(location.hash);\n"
    out = strip_js_comments(src, strip_strings=strip_strings)
    _assert_layout_preserved(src, out)
    assert "document.write(location.hash);" in out
    if strip_strings:
        assert "q.count" not in out, "the template WAS lexed — its substitution is blanked"


@pytest.mark.parametrize("strip_strings", [False, True])
def test_apostrophe_then_multiline_template_keeps_both_rules(strip_strings: bool) -> None:
    # The only assertion in this block that constrains the #542 side: a template must still span
    # lines. `main` fails the sink half (its apostrophe runs past its own line); an over-broad change
    # that let a line terminator close template frames would fail the `"l2" not in out` half. Both
    # directions in one fixture.
    src = "const a = <p>don't;\nconst t = `l1\nl2\nl3`;\ndocument.write(location.hash);\n"
    out = strip_js_comments(src, strip_strings=strip_strings)
    _assert_layout_preserved(src, out)
    assert "document.write(location.hash);" in out
    if strip_strings:
        assert "l2" not in out, "the template must still span lines — its body is string content"


@pytest.mark.parametrize("strip_strings", [False, True])
def test_substitution_quotes_do_not_reach_the_top_level_opener_gate(strip_strings: bool) -> None:
    # FP-BAIT, and explicitly NOT discriminating: `main` passes it too. It pins finding 1 above — that
    # a substitution quote is decided by the sub-lexer, not by the top-level gate. The fixture is the
    # one verified to be sensitive to that change: routing substitution quotes through the top-level
    # gate leaves it unchanged on both trees today and alters it under the change, whereas the
    # obvious `<p>it's</p>` fixture is insensitive because both predicates agree on `it's`.
    src = "const t = `x ${ <p>don't } stop` + it's + `here</p> } w`; el.innerHTML = u;\n"
    out = strip_js_comments(src, strip_strings=strip_strings)
    _assert_layout_preserved(src, out)
    assert out == src, "unchanged today on both trees; changes if substitution quotes are re-routed"


# --- end-to-end: the same defect, through three of the ~18 guards fed by strip_js_comments ---

_E2E_FEATURES = {"javascript", "typescript", "react", "frontend", "node", "express"}


@pytest.mark.parametrize(
    ("guard", "filename", "source"),
    [
        (
            DomXssSinksGuard(),
            "app.js",
            'import t from"https://cdn.example.com/lib.js";document.write(location.hash);\n',
        ),
        (
            DomXssSinksGuard(),
            "app.js",
            "export default'foo//bar';document.write(location.hash);\n",
        ),
        (
            DomXssSinksGuard(),
            "app.js",
            "export {a as'foo//bar'};document.write(location.hash);\n",
        ),
        (
            DomXssSinksGuard(),
            "app.js",
            "class A extends'foo//bar'{};document.write(location.hash);\n",
        ),
        (
            JsCommandInjectionGuard(),
            "srv.js",
            'const {exec} = require("child_process");\n'
            'import cp from"https://cdn.example.com/x.js";exec(`ls ${req.query.dir}`);\n',
        ),
        (
            PostmessageOriginGuard(),
            "pm.js",
            'import t from"https://cdn.example.com/x.js";'
            'window.addEventListener("message", (e) => { render(e.data); });\n',
        ),
    ],
    ids=["domxss-from", "domxss-default", "domxss-as", "domxss-extends", "cmdinject-from", "postmessage-from"],
)
def test_keyword_abutting_string_does_not_delete_a_real_finding(
    tmp_path: Path, guard: object, filename: str, source: str
) -> None:
    # The end-to-end proof: with the opener missed, each of these guards returned ZERO findings on a
    # genuine same-line sink — a silently deleted CRITICAL, not a scoring change. `import x from"…"`
    # is the single most common JS construct and every bundler emits it with no space.
    (tmp_path / filename).write_text(source, encoding="utf-8")
    profile = mkprofile(tmp_path, features=set(_E2E_FEATURES))
    assert guard.applies(profile)  # type: ignore[attr-defined]
    assert guard.run(tmp_path, profile)  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("label", "ch"),
    [("VT", "\x0b"), ("FF", "\x0c"), ("FS", "\x1c"), ("GS", "\x1d"), ("RS", "\x1e"), ("NEL", "\x85")],
)
def test_string_may_contain_a_non_terminator_control_char(label: str, ch: str) -> None:
    # The #440 re-gate's CRITICAL, and a lesson about which of three nearly-identical constants to
    # reach for. The prospective opener test capped its lookahead with `_JS_LINE_BOUNDARIES` --
    # Python's `str.splitlines()` set, which also holds VT, FF, FS, GS, RS and NEL. None of those
    # ends a JS line, so a LEGAL string containing one was refused an opener, its body read as CODE,
    # and the `//` inside it blanked a real sink. `_JS_LINE_TERMINATORS` is wrong here too (it holds
    # NEL); only the ES LineTerminator set is right.
    src = f'const label = "a{ch}b//fake"; element.innerHTML = userInput;\n'
    assert "element.innerHTML = userInput;" in strip_js_comments(src), label
    # Both settings: quote tracking governs comment detection regardless of `strip_strings`, so a
    # default-only assertion leaves half the blast radius unmeasured (#440 gate F3).
    assert "element.innerHTML = userInput;" in strip_js_comments(src, strip_strings=True), label


@pytest.mark.parametrize("terminator", ["\n", " ", " "])
def test_unclosed_quote_is_still_capped_at_a_real_line_terminator(terminator: str) -> None:
    # The other half: narrowing the stop set must not lose the cap itself. At a REAL ES
    # LineTerminator an unclosed quote is still not an opener, so the JSX apostrophe case stays
    # fixed for all three (LF, LS, PS) rather than only for LF.
    src = f"<p>the default's notes</p>{terminator}document.write(location.hash);"
    assert "document.write(location.hash);" in strip_js_comments(src)


# --------------------------------------------------------------------------------------------
# #440 gate (2026-08-03): the opener window is the LOGICAL JS line, and a `//` comment ends only
# at an ES LineTerminator. See the invariant block above `_JS_LINE_BOUNDARIES` in
# `agentsec/guards/base.py`: every GRAMMAR question uses `_JS_STRING_TERMINATORS`; only the
# "may blank() overwrite this char?" question uses Python's `str.splitlines()` set.
# --------------------------------------------------------------------------------------------


def test_string_line_continuation_carries_the_literal_onto_the_next_line() -> None:
    # F2, CRITICAL. ES2023 12.9.4.1: a `\` immediately followed by a LineTerminator is a
    # LineContinuation, legal inside a `'..'`/`".."` literal, and it carries the literal onto the
    # next PHYSICAL line. The previous round wrote the opposite into the source as settled -- "one
    # that does not close on its line is not valid JS" -- and refused the opener, so the body was
    # scanned as CODE, the `//` in it read as a real comment, and the rest of that line was blanked.
    src = 'const a = "abc\\\n//fake"; element.innerHTML = userInput;\n'
    assert "element.innerHTML = userInput;" in strip_js_comments(src)
    assert "element.innerHTML = userInput;" in strip_js_comments(src, strip_strings=True)


def test_url_inside_a_continued_string_is_not_read_as_a_comment() -> None:
    # The realistic shape of F2: a long message split with a continuation, containing a URL. The
    # `https://`-is-not-a-comment case is one `strip_js_comments` was explicitly built to handle,
    # and the continuation reopened it.
    src = ('const help = "See https://example.com/docs, \\\n'
           'or run //setup manually."; element.innerHTML = userInput;\n')
    assert "element.innerHTML = userInput;" in strip_js_comments(src)
    assert "element.innerHTML = userInput;" in strip_js_comments(src, strip_strings=True)


def test_crlf_line_continuation_is_one_terminator_sequence() -> None:
    # `\<CR><LF>` is a SINGLE LineTerminatorSequence, so the continuation covers all three chars.
    # Widening only the lookahead window (and still consuming two chars in the escape branch) leaves
    # the scan sitting on the LF, where the end-of-line cap closes a literal the grammar says is
    # still open -- F2 again, CRLF-only. Asserted at the helper, not through a guard: `read()` uses
    # `Path.read_text`, whose universal-newline translation means a guard never sees a raw CRLF.
    src = 'const a = "abc\\\r\n//fake"; element.innerHTML = userInput;\r\n'
    assert "element.innerHTML = userInput;" in strip_js_comments(src)
    assert "element.innerHTML = userInput;" in strip_js_comments(src, strip_strings=True)


@pytest.mark.parametrize(
    ("guard", "filename", "source"),
    [
        (
            DomXssSinksGuard(),
            "app.js",
            'const a = "abc\\\n//fake"; document.write(location.hash);\n',
        ),
        (
            JsCommandInjectionGuard(),
            "srv.js",
            'const {exec} = require("child_process");\n'
            'const a = "abc\\\n//fake"; exec(`ls ${req.query.dir}`);\n',
        ),
        (
            PostmessageOriginGuard(),
            "pm.js",
            'const a = "abc\\\n//fake"; '
            'window.addEventListener("message", (e) => { render(e.data); });\n',
        ),
    ],
    ids=["domxss", "cmdinject", "postmessage"],
)
def test_line_continuation_does_not_delete_a_real_finding(
    tmp_path: Path, guard: object, filename: str, source: str
) -> None:
    # The end-to-end half, matching the bar `test_keyword_abutting_string_does_not_delete_a_real_
    # finding` set: with the opener refused, each guard returned ZERO findings on a genuine same-line
    # sink -- a silently deleted CRITICAL, not a scoring change.
    (tmp_path / filename).write_text(source, encoding="utf-8")
    profile = mkprofile(tmp_path, features=set(_E2E_FEATURES))
    assert guard.applies(profile)  # type: ignore[attr-defined]
    assert guard.run(tmp_path, profile)  # type: ignore[attr-defined]


def test_an_even_backslash_run_before_the_newline_is_not_a_continuation() -> None:
    # FP-bait for the widening, and a REGRESSION LOCK rather than a discriminating test (it passes
    # before the fix too): `\\` is an escaped backslash, so the line really ends there and the JSX
    # apostrophe cap must still refuse the opener. Parity, not "is there a backslash".
    src = "<p>the default's notes</p>\\\\\ndocument.write(location.hash);\n"
    assert "document.write(location.hash);" in strip_js_comments(src)
    assert "document.write(location.hash);" in strip_js_comments(src, strip_strings=True)


def test_a_line_continuation_lets_a_mis_opened_quote_reach_the_next_line() -> None:
    # THE TRADED-AGAINST TEST for F2, and it FAILS against the pre-fix code. Widening the window to
    # the logical line is what the grammar requires; the price is paid by
    # `_quote_is_jsx_apostrophe`'s misclassifications: JSX prose whose word is a keyword, on a line
    # ending in an ODD backslash run, now reads as a string opener that reaches onto the next
    # physical line and blanks it. Asserting the COST is what keeps the residual tracked rather than
    # invisible. The real defect is `_quote_is_jsx_apostrophe`, out of scope here; measured exposure
    # is 6 losses against 248 recoveries over a 60k-input sink-survival fuzz, every one of the 6
    # requiring a `\`+LineTerminator in the source.
    src = "<p>the default's notes</p>\\\ndocument.write(location.hash); const z='q';\n"
    assert "document.write(location.hash);" not in strip_js_comments(src, strip_strings=True)


_RESIDUAL_SRC = ("<p>the default's notes</p> \\\n"
                 "const u = 'https://example.com'; document.write(location.hash);\n")


def test_continuation_residual_also_costs_the_default_path() -> None:
    # KNOWN RESIDUAL (#440 re-gate M1), and the half the test above does NOT cover. The widening's
    # cost is not confined to `strip_strings=True`: quote tracking governs comment detection at BOTH
    # settings -- which is exactly why the F2 BENEFIT is asserted at both, 80 lines above. The cost
    # was given only one setting, and the un-asserted one is the DEFAULT path, the one all 19 JS/TS
    # consumers of this helper actually run on.
    #
    # Mechanism: `_logical_line_end` correctly extends the opener window across the odd backslash
    # run, so the `_quote_is_jsx_apostrophe`-misclassified `'` in `default's` finds a partner -- the
    # `'` opening `'https://...'` on the NEXT physical line. The "string" closes there, the scan is
    # in CODE mode when it reaches the `//` of the URL, and the rest of the line is blanked.
    assert "document.write(location.hash);" not in strip_js_comments(_RESIDUAL_SRC)
    assert "document.write(location.hash);" not in strip_js_comments(_RESIDUAL_SRC,
                                                                    strip_strings=True)


def test_continuation_residual_is_guard_visible(tmp_path: Path) -> None:
    # ...and it is a guard-visible DELETION, not a helper curiosity: measured 1 -> 0 for
    # dom-xss-sinks against both the parent AND `main`, so this PR lands the loss. Pinned, not
    # fixed: the real defect is `_quote_is_jsx_apostrophe`, and reverting the widening would
    # reinstate the worse CRITICAL this PR closed. Realistic exposure is 0 of 40 000 real files on
    # the default path, which is why it is tracked here rather than blocking.
    (tmp_path / "app.js").write_text(_RESIDUAL_SRC, encoding="utf-8")
    profile = mkprofile(tmp_path, features=set(_E2E_FEATURES))
    assert DomXssSinksGuard().run(tmp_path, profile) == []


@pytest.mark.parametrize(
    ("label", "ch"),
    [("VT", "\x0b"), ("FF", "\x0c"), ("FS", "\x1c"), ("GS", "\x1d"), ("RS", "\x1e"), ("NEL", "\x85")],
)
def test_a_control_char_widens_the_opener_window_beyond_one_physical_line(
    label: str, ch: str
) -> None:
    # KNOWN RESIDUAL (#440 gate F1), pinned deliberately -- this passes before the fix too. VT / FF /
    # FS / GS / RS / NEL are `splitlines()` boundaries but not ES LineTerminators, so the opener
    # lookahead spans them: correct per the grammar, but it means a `_quote_is_jsx_apostrophe`
    # misclassification is no longer confined to one PHYSICAL line. Reverting the stop set would
    # reinstate the CRITICAL this PR closed, so the residual is made visible instead of "fixed".
    #
    # The trailing `const x = 'y';` is load-bearing and is why the gate's own suggested snippet for
    # this test (marked UNTESTED there) did not reproduce: the prospective opener test needs an
    # unescaped PARTNER quote in the window, so with no second `'` nothing opens and nothing is
    # blanked. A pin that pins nothing is worse than no pin.
    src = f"<p>the default's notes</p>{ch}const re = new RegExp(req.query.q); const x = 'y';\n"
    assert "new RegExp(req.query.q)" not in strip_js_comments(src, strip_strings=True), label
    # ...and the control: with a real LF instead, the cap confines it and the sink survives.
    lf = "<p>the default's notes</p>\nconst re = new RegExp(req.query.q); const x = 'y';\n"
    assert "new RegExp(req.query.q)" in strip_js_comments(lf, strip_strings=True), label


# #558: the opener lookahead's partner test is FLAT. `_last_unescaped_quotes` counts every unescaped
# quote on the logical line, so a quote that is not really an opener (invalid JS here; a
# `_quote_is_jsx_apostrophe` miss in JSX) pairs with a quote that lives inside a later construct.
# Pinned, not fixed: a frame-aware lookahead is circular (which spans are templates depends on whether
# THIS quote opens a string), every candidate fix measured regressed valid code, and a TypeScript-
# parser oracle found 0 instances in 522,733 openers over 9,517 real files. RCA: issue #558.
_FLAT_PARTNER_SINK = "el.innerHTML = user;"
_FLAT_PARTNER_CONTEXTS = {
    "template": "const t = `it's`;",
    "dq-string": "const t = \"it's\";",
    "line-comment": "// it's",
    "block-comment": "/* it's */",
    "regex": "x.replace(/'/g, z);",
}


@pytest.mark.parametrize("tail", list(_FLAT_PARTNER_CONTEXTS.values()), ids=list(_FLAT_PARTNER_CONTEXTS))
def test_a_false_opener_pairs_with_a_quote_in_another_construct_accepted_residual(tail: str) -> None:
    # KNOWN RESIDUAL (#558). The stray `'` finds its "partner" inside `tail`, opens, and the string
    # swallows the sink under `strip_strings`. The issue named only templates; all five constructs
    # share the mechanism. The control (the same line with no stray quote) proves the loss is the
    # false opener's doing and not the fixture's.
    src = f"return 'oops; {_FLAT_PARTNER_SINK} {tail}\n"
    out = strip_js_comments(src, strip_strings=True)
    _assert_layout_preserved(src, out)
    assert _FLAT_PARTNER_SINK not in out
    control = f"return 0; {_FLAT_PARTNER_SINK} {tail}\n"
    assert _FLAT_PARTNER_SINK in strip_js_comments(control, strip_strings=True)


def test_a_false_opener_hides_a_real_comment_on_the_default_path_accepted_residual() -> None:
    # The default-path cost of the same residual, in the opposite direction: the swallowed span holds
    # a real `//`, so the commented-out sink is handed to the guards as live code (an FP). Control:
    # with no partner (`its`), the quote never opens and the comment is stripped.
    src = "f('oops); ok(); // el.innerHTML = user; it's\n"
    assert _FLAT_PARTNER_SINK in strip_js_comments(src)
    assert _FLAT_PARTNER_SINK not in strip_js_comments(src.replace("it's", "its"))


_FLAT_PARTNER_LATER = {
    "eof-cap": "document.write(location.hash);\n",
    "parity-cap": "const u = `a`;\ndocument.write(location.hash);\nconst w = `b`;\n",
}


@pytest.mark.parametrize("later", list(_FLAT_PARTNER_LATER.values()), ids=list(_FLAT_PARTNER_LATER))
@pytest.mark.parametrize("tail", list(_FLAT_PARTNER_CONTEXTS.values()), ids=list(_FLAT_PARTNER_CONTEXTS))
def test_a_false_opener_leaves_later_code_intact(tail: str, later: str) -> None:
    # The BOUND on the sink-deleting (FN) direction: it stays on the false opener's logical line. Two
    # mechanisms, by context. The four non-template contexts swallow no backtick: the false string
    # closes on its partner, so the later lines lex exactly as they would with no first line at all.
    # The template context swallows one backtick, so the stray one after the partner opens a
    # template: with nothing after it the EOF cap restores it, and when it pairs with a later
    # template's opener the odd delimiter count trips the parity cap (#910), which restores every
    # closed span, so the later lines come back verbatim (later template text included: the parity
    # cap's own pinned trade). NOT a bound on the comment (FP) direction: see the test below.
    src = f"return 'oops; {_FLAT_PARTNER_SINK} {tail}\n" + later
    out = strip_js_comments(src, strip_strings=True)
    _assert_layout_preserved(src, out)
    assert "document.write(location.hash);" in out
    if tail == _FLAT_PARTNER_CONTEXTS["template"]:
        assert out.splitlines()[1:] == src.splitlines()[1:]
    else:
        assert out.splitlines()[1:] == strip_js_comments(later, strip_strings=True).splitlines()


@pytest.mark.parametrize("later", list(_FLAT_PARTNER_LATER.values()), ids=list(_FLAT_PARTNER_LATER))
@pytest.mark.parametrize("strip_strings", [False, True])
def test_a_false_opener_in_a_template_exposes_later_comments_accepted_residual(
    strip_strings: bool, later: str
) -> None:
    # KNOWN RESIDUAL (#558), the cost the bound above does NOT cover. The caps that save later code
    # restore SOURCE, so in the template context a commented-out sink on any later line, to EOF, is
    # handed to the guards as live code (the EOF cap's documented "a revived comment is visible"
    # trade, reached here through the stray backtick). Template-only: with the partner in a
    # double-quoted string nothing is swallowed and the comment is still stripped. The control (no
    # stray quote) strips it too, so the exposure is the false opener's doing.
    comment = "// el.innerHTML = c;\n"
    src = f"return 'oops; {_FLAT_PARTNER_SINK} {_FLAT_PARTNER_CONTEXTS['template']}\n" + comment + later
    assert "el.innerHTML = c;" in strip_js_comments(src, strip_strings=strip_strings)
    control = src.replace("'oops;", "0;", 1)
    assert "el.innerHTML = c;" not in strip_js_comments(control, strip_strings=strip_strings)
    dq = src.replace(_FLAT_PARTNER_CONTEXTS["template"], _FLAT_PARTNER_CONTEXTS["dq-string"], 1)
    assert "el.innerHTML = c;" not in strip_js_comments(dq, strip_strings=strip_strings)


@pytest.mark.parametrize(
    ("src", "body"),
    [
        ("const a = 'it`s'; el.innerHTML = x; const t = `ok`;\n", "it`s"),
        ('const f = "```ts"; el.innerHTML = x; const t = `ok`;\n', "```ts"),
    ],
    ids=["backtick-in-string", "markdown-fence"],
)
def test_a_real_string_holding_a_backtick_still_opens(src: str, body: str) -> None:
    # FP-BAIT for any future #558 fix: the valid neighbour of the residual above. Up to its partner
    # this line is lexically identical to the #558 repro, but here the quote IS an opener and the
    # backtick is string content. The issue's suggested fix (skip quotes between backtick toggles when
    # computing partners) fails both cases: the string is refused and its body read as template/code.
    # Measured on 9,517 real files, that change altered 42 under `strip_strings`, every one of which
    # parses with zero TypeScript syntax diagnostics (``` fences, 'Run `git add').
    out = strip_js_comments(src, strip_strings=True)
    _assert_layout_preserved(src, out)
    assert body not in out, "the string opened, so its body is blanked"
    assert "el.innerHTML = x;" in out


@pytest.mark.parametrize(
    ("guard", "source", "control"),
    [
        (
            JsCommandInjectionGuard(),
            "const { exec } = require('child_process');\n"
            "if (a) log('oops); exec(`convert ${req.query.file} out.png`); const t = `it's`;\n",
            "log('oops);",
        ),
        (
            PostmessageOriginGuard(),
            "window.addEventListener('message', (e) => { log('oops); "
            "if (e.origin !== TRUSTED) return; const t = `it's`; run(e.data); });\n",
            "log('oops);",
        ),
    ],
    ids=["cmdinject-fn", "postmessage-fp"],
)
def test_flat_partner_residual_is_guard_visible(
    tmp_path: Path, guard: object, source: str, control: str
) -> None:
    # ...and it reaches guards through their `strip_strings=True` views, in both directions:
    # js-command-injection loses a real tainted exec (FN) and postmessage-origin loses the origin check
    # it needs as evidence (FP). Each control drops only the stray quote and flips the outcome, so the
    # pin is the residual and not the fixture. Realistic exposure is 0 in real code (see above).
    profile = mkprofile(tmp_path, features=set(_E2E_FEATURES))
    assert guard.applies(profile)  # type: ignore[attr-defined]
    (tmp_path / "app.js").write_text(source, encoding="utf-8")
    pinned = guard.run(tmp_path, profile)  # type: ignore[attr-defined]
    (tmp_path / "app.js").write_text(source.replace(control, "log(0);"), encoding="utf-8")
    clean = guard.run(tmp_path, profile)  # type: ignore[attr-defined]
    if isinstance(guard, JsCommandInjectionGuard):
        assert pinned == [] and clean, "FN: the stray quote swallows the exec"
    else:
        assert pinned and clean == [], "FP: the stray quote swallows the origin check"


@pytest.mark.parametrize(
    ("label", "ch"),
    [("VT", "\x0b"), ("FF", "\x0c"), ("FS", "\x1c"), ("GS", "\x1d"), ("RS", "\x1e"), ("NEL", "\x85")],
)
def test_line_comment_runs_through_a_non_terminator_control_char(label: str, ch: str) -> None:
    # F5: the mirror image of the opener defect, in the same function. ES2023 12.4: a
    # SingleLineComment runs to the next LineTerminator -- and a VT/FF/FS/GS/RS/NEL is not one. The
    # `//` scan stopped at `_JS_LINE_BOUNDARIES`, so the comment ended early and the COMMENTED-OUT
    # remainder was handed to the guards as live code: a false positive live at every commit in this
    # PR, and the exact class #424 opened this branch to close.
    src = f"// note{ch}element.innerHTML = userInput;\n"
    assert "element.innerHTML = userInput;" not in strip_js_comments(src), label
    assert "element.innerHTML = userInput;" not in strip_js_comments(src, strip_strings=True), label


@pytest.mark.parametrize("terminator", ["\n", "\r", " ", " "])
def test_line_comment_still_ends_at_a_real_line_terminator(terminator: str) -> None:
    # FP-bait / traded-against for F5 (a REGRESSION LOCK -- it passes before the fix too): widening
    # what a `//` comment swallows must not swallow the next REAL line. LF, CR, LS and PS all end it.
    src = f"// note{terminator}element.innerHTML = userInput;\n"
    assert "element.innerHTML = userInput;" in strip_js_comments(src)


@pytest.mark.parametrize(
    ("label", "ch"),
    [("VT", "\x0b"), ("FF", "\x0c"), ("FS", "\x1c"), ("GS", "\x1d"), ("RS", "\x1e"), ("NEL", "\x85")],
)
def test_line_comment_widening_is_bounded_by_the_next_real_terminator(label: str, ch: str) -> None:
    # THE BOUND on F5's cost, and the answer to "does a `//` now blank the rest of the file?". No:
    # it blanks to the next ES LineTerminator, so in any file that uses LF at all the extra reach is
    # the remainder of the CURRENT physical line -- which really is commented out. The unbounded
    # shape (a control char as a file's ONLY separator: 40/40 sinks blanked, measured) needs a file
    # with no LF anywhere -- and there the `//` did NOT already blank to EOF before this change: the
    # old stop set ended the comment at the first VT. That shape is a real widening and it is
    # covered by its own test below, not by this one (this file contains LFs). #440 re-gate L1.
    src = f"// note{ch}element.innerHTML = a;\nel.innerHTML = b;\nel.innerHTML = c;\n"
    out = strip_js_comments(src)
    assert "element.innerHTML = a;" not in out, label   # same physical line: really commented out
    assert "el.innerHTML = b;" in out, label            # the LF ended it
    assert "el.innerHTML = c;" in out, label


def test_line_comment_in_a_file_with_no_line_terminator_reaches_EOF() -> None:
    # The UNBOUNDED shape the test above deliberately does not exercise, and the one the docstring
    # there used to wave away as "already true before this change". It was not: the old stop set
    # held VT, so in a VT-separated file with no LF the comment ended at the first VT and everything
    # after it survived (measured: 40 dom-xss-sinks findings at the parent, 0 here).
    #
    # The new behaviour is grammatically CORRECT -- ES2023 12.4: a SingleLineComment ends only at a
    # LineTerminator, so in a file containing none, the rest of the file really is commented out --
    # but it is a widening, and nothing in the suite covered it. Exposure: 0 of 40 000 real files.
    src = "// c\x0b" + ("el.innerHTML = a;\x0b" * 40)
    assert "el.innerHTML = a;" not in strip_js_comments(src)
    src_lf = "// c\n" + ("el.innerHTML = a;\n" * 40)   # control: one real LF bounds it
    assert "el.innerHTML = a;" in strip_js_comments(src_lf)


def test_line_comment_control_char_false_positive_is_gone(tmp_path: Path) -> None:
    # F5 end-to-end: the guard-visible consequence, a live false positive on commented-out code.
    (tmp_path / "app.js").write_text(
        "// element.innerHTML = userInput;\x0bdocument.write(location.hash);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features=set(_E2E_FEATURES))
    assert DomXssSinksGuard().run(tmp_path, profile) == []


def test_quote_parity_is_counted_to_the_true_run_start() -> None:
    # #440 re-gate L2. `_logical_line_end` counts a backslash run back to its TRUE start because
    # escape status is a property of the text, not of where the window began -- but
    # `_last_unescaped_quotes`, whose result that window feeds, kept the window-relative count. This
    # is the unit-level difference: with the run straddling `start`, the old code called an ESCAPED
    # quote unescaped.
    text = "\\'x"                                                   # the `'` is escaped by the `\`
    assert _last_unescaped_quotes(text, 1, len(text))["'"] == -1     # old code answered 1
    assert _last_unescaped_quotes(text, 0, len(text))["'"] == -1     # whole-text view always agreed


def test_the_parity_correction_changes_no_strip_js_comments_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ...and the other half: the correction is INERT at the caller, so it is a consistency fix and
    # not a behaviour change. `strip_js_comments` only ever starts a window at a raw LineTerminator
    # or at index 0, so no backslash run can straddle `start` in practice.
    #
    # Proven rather than asserted: exhaustively over every string of length 1-5 on the
    # grammar-relevant alphabet, at BOTH `strip_strings` settings, the old and new implementations
    # produce byte-identical output. (The same sweep extended to length 6 -- 299 592 strings -- also
    # shows 0 differences; it is bounded at 5 here to keep the suite fast.)
    def old_window_relative(text: str, start: int, end: int) -> dict[str, int]:
        last = {"'": -1, '"': -1}
        j, backslashes = start, 0
        while j < end:
            ch = text[j]
            if ch == "\\":
                backslashes += 1
            else:
                if ch in last and backslashes % 2 == 0:
                    last[ch] = j
                backslashes = 0
            j += 1
        return last

    alphabet = "\\\n'\"/x\r\x0b"
    corpus = ["".join(t) for n in range(1, 6) for t in itertools.product(alphabet, repeat=n)]
    assert len(corpus) == sum(len(alphabet) ** n for n in range(1, 6))  # 37 448

    def strip_both(src: str) -> tuple[str, str]:
        return strip_js_comments(src), strip_js_comments(src, strip_strings=True)

    new_out = [strip_both(s) for s in corpus]
    monkeypatch.setattr(base_module, "_last_unescaped_quotes", old_window_relative)
    old_out = [strip_both(s) for s in corpus]

    differing = [s for s, a, b in zip(corpus, new_out, old_out, strict=True) if a != b]
    assert differing == [], f"{len(differing)} inputs differ, first: {differing[:3]!r}"


def test_blanking_never_overwrites_a_splitlines_boundary() -> None:
    # The one NON-grammar question in the function: a `//` comment now runs through a VT, but the
    # blanking must still leave every `str.splitlines()` boundary intact or every downstream line
    # number shifts. Length and line count are the contract the guards' line numbers rest on.
    src = "// a\x0bb\x0cc\x1cd\x1de\x1ef\x85g\nelement.innerHTML = userInput;\n"
    for out in (strip_js_comments(src), strip_js_comments(src, strip_strings=True)):
        assert len(out) == len(src)
        assert len(out.splitlines()) == len(src.splitlines())
        assert out.splitlines()[-1] == "element.innerHTML = userInput;"
@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("post = router.post\n", {"post"}),
        ("get = app.get\n", {"get"}),
        ("    post = self.router.post\n", {"post"}),
        # A trailing `#` comment is part of no statement — anchoring `[ \t]*$` straight after the
        # verb meant two spaces and a `#` silently dropped the alias, restoring the CRITICAL false
        # negative the rule exists to fix (#452 gate, finding 3).
        ("post = router.post  # shorthand\n", {"post"}),
        ("post = router.post   \n", {"post"}),
        ("post = router.post\r\n", {"post"}),                 # CRLF source
        ("post = router.post  # shorthand\r\n", {"post"}),
        # NOT a route alias: the binding must be a bare `<receiver>.<verb>`.
        ("post = compute_something()\n", set()),
        ("post = router.post_process\n", set()),
        # NOT a route alias: the receiver is a MOCK PATCHER. Without this the ordinary
        # `patch = mock.patch` re-admitted the bare `@patch(...)` form through the alias door —
        # the very shape `_REGISTRATION_DECORATOR`'s receiver requirement rejects (#452 gate, #2).
        ("patch = mock.patch\n", set()),
        ("patch = unittest.mock.patch\n", set()),
        ("patch = webmock.patch\n", set()),
        # KNOWN RESIDUALS, pinned so a future widening is a deliberate flip, not a surprise. Both
        # lose a route rather than invent one (the safe direction) — see `_ROUTE_ALIAS_BINDING`.
        ("post: Any = router.post\n", set()),          # annotated assignment
        ("post = get_router().post\n", set()),         # call receiver
    ],
)
def test_route_decorator_aliases_are_binding_based_not_name_based(source: str, expected: set[str]) -> None:
    # A bare `@post(...)` counts as a registration only when `post` is actually bound to a route
    # method in the same module, so an ordinary local named `post` never promotes a helper.
    assert set(route_decorator_aliases(source)) == expected


def test_alias_rule_ast_line_walker_parity() -> None:
    # The alias rule is the newest widening of `include_closures=False`, and it shipped with NO
    # parity coverage: the ast path read RAW text while the line walker read string-blanked text,
    # so the two disagreed (measured 3 blocks vs 2) on any module with a binding in a docstring.
    # Parity is not cosmetic — it decides whether a file is analysed differently depending on
    # whether it happens to parse (#452 gate, finding 1).
    from agentsec.guards.base import _iter_functions_lines

    shapes = [
        # binding in a MODULE docstring — prose, not a binding
        '"""Doc.\n\n    post = router.post\n"""\n\n\ndef factory(router):\n'
        "    @post\n    def inner(x):\n        return x\n    return inner\n",
        # binding in a FUNCTION docstring
        "def factory(router):\n    \"\"\"Doc.\n\n    post = router.post\n    \"\"\"\n"
        "    @post\n    def inner(x):\n        return x\n    return inner\n",
        # the real thing: a live binding promotes the bare-decorated nested def in BOTH walkers
        "def factory(router):\n    post = router.post\n\n    @post('/x')\n"
        "    def handler(x):\n        return x\n    return handler\n",
        # ...and with a trailing comment on the binding line
        "def factory(router):\n    post = router.post  # shorthand\n\n    @post('/x')\n"
        "    def handler(x):\n        return x\n    return handler\n",
        # a mock alias promotes nothing in either walker
        "patch = mock.patch\n\n\ndef factory(router):\n    @patch('svc.store')\n"
        "    def inner(x):\n        return x\n    return inner\n",
    ]
    for shape in shapes:
        for src in (shape, shape.replace("\n", "\r\n")):
            for flag in (True, False):
                assert [ln for ln, _ in iter_functions(src, include_closures=flag)] == [
                    ln for ln, _ in _iter_functions_lines(src, include_closures=flag)
                ], f"walkers disagree with include_closures={flag} on {src!r}"
    # ...and the alias rule must survive CRLF outright, not merely fail symmetrically: a
    # `$`-anchored tail that dies on `\r\n` would silently restore the CRITICAL false negative on
    # a Windows checkout. The live-binding shape is `shapes[2]`; its route is the nested `def`.
    crlf = shapes[2].replace("\n", "\r\n")
    assert [ln for ln, _ in iter_functions(crlf, include_closures=False)] == [
        ln for ln, _ in iter_functions(shapes[2], include_closures=False)
    ]


@pytest.mark.parametrize(
    ("decorator", "is_registration"),
    [
        ("@mock.patch('x')", False),           # the unittest patcher, not the HTTP verb
        ("@unittest.mock.patch('x')", False),  # dotted, last segment is still `mock`
        # A receiver merely ENDING in "mock" is a mock patcher too, by every reading of its name —
        # not an HTTP PATCH route. Segment EQUALITY re-admitted all three as routes, a measured
        # 0 -> 1 false positive against the parent commit (#452 gate, finding 5).
        ("@webmock.patch('/x')", False),
        ("@apimock.patch('/x')", False),
        ("@redis_mock.patch('/x')", False),
        # ...while the test stays segment-SCOPED, so an ordinary route receiver is untouched.
        ("@app.patch('/x')", True),
        ("@router.patch('/x')", True),
        ("@mocking_bird.patch('/x')", True),   # "mock" inside, but the segment does not end in it
        ("@functools.lru_cache", False),
    ],
)
def test_is_registration_rejects_mock_patchers_by_receiver_suffix(decorator: str, is_registration: bool) -> None:
    assert _is_registration([decorator]) is is_registration
# --- #483 review: credential guards must keep scanning deployment trees ------------------------

def test_credential_scan_keeps_deployment_trees_in_scope() -> None:
    # Adding `alembic` to the shared non-product list silently dropped FIVE credential guards on
    # that tree — a hardcoded DB password in `alembic/env.py` went from reported to unreported,
    # while the merged plan doc claimed those guards "don't call is_nonproduct_path, so they still
    # scan it — safe" (#483 review). A deployment tree holds REAL committed credentials.
    for path in ("alembic/env.py", "alembic/versions/abc123.py", "migrations/0001_init.py"):
        assert is_nonproduct_path(path) is True, path                      # still non-product
        assert is_nonproduct_path(path, credential_scan=True) is False, path  # ...but credential-scanned


def test_credential_scan_still_skips_fake_secret_trees() -> None:
    # The other direction: `tests/`/`fixtures/`/`examples/` credentials are deliberately fake, so
    # the carve-out must not reopen that noise — including when a deployment segment is nested
    # inside one of them.
    for path in (
        "tests/test_config.py",
        "tests/fixtures/settings.py",
        "examples/demo.py",
        "tests/alembic/env.py",
        "examples/alembic/env.py",
    ):
        assert is_nonproduct_path(path, credential_scan=True) is True, path


def test_credential_scan_does_not_affect_ordinary_product_paths() -> None:
    assert is_nonproduct_path("app/config.py", credential_scan=True) is False
    assert is_nonproduct_path("app/config.py") is False


def test_credential_scan_strips_adjacent_deployment_segments(tmp_path: Path) -> None:
    # A single `re.sub` is non-overlapping, so the second of two ADJACENT deployment segments
    # survived and the path still read as non-product — `migrations/alembic/env.py` and
    # `src/migrations/alembic/env.py` were wrongly skipped by the five credential guards, which is
    # the exact layout `credential_scan` exists to keep in scope (#483 review, second pass).
    for path in (
        "migrations/alembic/env.py",
        "alembic/migrations/env.py",
        "src/migrations/alembic/env.py",
        "migrations/foo/alembic/x.py",
    ):
        assert is_nonproduct_path(path) is True, path
        assert is_nonproduct_path(path, credential_scan=True) is False, path
    # ...and the FILENAME still counts, so a test file under a deployment tree stays skipped.
    for path in ("migrations/conftest.py", "alembic/test_env.py", "alembic/versions/x.spec.py"):
        assert is_nonproduct_path(path, credential_scan=True) is True, path

def test_credential_scan_is_case_insensitive_end_to_end() -> None:
    # The regression test that was MISSING, which is the whole reason `_DEPLOYMENT_NONPROD`'s
    # `re.IGNORECASE` was reported as inert (#483 second-pass review, B22). That report is wrong:
    # `_NONPROD_PATH` is itself compiled with `re.IGNORECASE`, so a capitalized deployment tree DOES
    # reach the `credential_scan` branch, and the flag on the deployment patterns is what keeps the
    # exemption working once it gets there.
    #
    # Every other case in this section is lowercase, so nothing pinned the capitalized path and the
    # flag looked decorative. Measured: drop `re.IGNORECASE` from the deployment patterns and these
    # paths flip from scanned to SKIPPED, silently dropping the credential guards on a capitalized
    # `Migrations/` or `Alembic/` tree — exactly the "hardcoded DB password in alembic/env.py goes
    # from reported to unreported" regression this flag exists to prevent.
    for path in (
        "Migrations/env.py",
        "Alembic/env.py",
        "ALEMBIC/env.py",
        "Alembic/versions/abc123.py",
        "src/Migrations/Alembic/env.py",   # capitalized AND adjacent, so both patterns must ignore case
    ):
        assert is_nonproduct_path(path) is True, path
        assert is_nonproduct_path(path, credential_scan=True) is False, path
    # The other direction: case-insensitivity must not leak the fake-secret skip.
    for path in ("Tests/test_config.py", "Examples/Alembic/env.py"):
        assert is_nonproduct_path(path, credential_scan=True) is True, path


def test_credential_scan_still_honors_an_opted_in_archive_tree() -> None:
    # The untested COMBINATION (#483 re-gate): `credential_scan` returned False straight out of the
    # deployment-strip branch, so it never reached the `archive_segments` check and the answer for
    # `old/alembic/env.py` depended on the flag — while the docstring promises an opted-in tree is
    # non-product either way. `audit()`'s universal archive DROP masked it in the report, so this
    # pins the HELPER's contract, which is the thing a future caller reads.
    ARCH = frozenset({"old", "legacy"})
    for path in ("old/alembic/env.py", "legacy/migrations/0001.py", "old/x/alembic/env.py"):
        assert is_nonproduct_path(path, ARCH) is True, path
        assert is_nonproduct_path(path, ARCH, credential_scan=True) is True, path
    # ...and an archive segment is still required: the same deployment paths NOT under an opted-in
    # tree stay credential-scanned, so the fall-through can't quietly re-suppress the whole carve-out.
    for path in ("alembic/env.py", "src/migrations/0001.py"):
        assert is_nonproduct_path(path, ARCH, credential_scan=True) is False, path
    # A FILE merely named `old` is not an `old/` tree (directory segments only, both paths).
    assert is_nonproduct_path("alembic/old", ARCH, credential_scan=True) is False


# --- #565 review: shared non-product path missed Go's own conventions --------------------------

def test_is_nonproduct_path_skips_go_test_suffix() -> None:
    # #565 review, Dean: `_NONPROD_PATH` had a `_test\.py$` arm but no `_test\.go$` one, so Go's
    # own alongside-the-source test convention (`foo_test.go`, never under a `tests/` dir) still
    # fired on every guard using this shared gate.
    for path in ("handler_test.go", "internal/auth/token_test.go", "cmd/server_test.go"):
        assert is_nonproduct_path(path) is True, path
    # ...while ordinary Go source, including a name that merely CONTAINS "test", stays in scope.
    for path in ("handler.go", "internal/contest/service.go", "testrunner.go"):
        assert is_nonproduct_path(path) is False, path


def test_is_nonproduct_path_skips_go_testdata_dir() -> None:
    # Same review: Go's conventional fixture directory (`testdata/`, never scanned by `go build`,
    # analogous to `fixtures/` for other languages) was not in the shared `NONPRODUCT_DIR_ALT`.
    for path in ("testdata/malicious.go", "internal/auth/testdata/fixture.go"):
        assert is_nonproduct_path(path) is True, path
    # A file merely named `testdata` (not a directory segment) is not the same thing.
    assert is_nonproduct_path("cmd/testdata.go") is False


# --- #484 review: shared guard-relative file conventions ---------------------------------------

def test_is_reference_sql_path_keeps_deployed_schema_in_scope() -> None:
    # The CRITICAL false negative this helper exists to fix (#484 review): `migrations` is in the
    # shared `NONPRODUCT_DIR_ALT`, and `detect()` resolves `sql_dir` to `supabase/migrations`, so
    # `is_nonproduct_path` filtered the ENTIRE scan root and the SQL guards went silent on the
    # canonical Supabase layout. For SQL, `migrations/` IS the deployed schema.
    for path in (
        "supabase/migrations/0001_init.sql", "migrations/0002.sql", "alembic/versions/abc.sql",
        "db/schema.sql",
    ):
        assert is_reference_sql_path(path) is False, path
    # ...while genuine REFERENCE schema is still skipped, on any of the four conventions.
    for path in (
        "examples/schema.sql", "sample/schema.sql", "tests/fixtures/seed.sql",
        "__mocks__/db.sql", "docs/Examples/schema.sql",
    ):
        assert is_reference_sql_path(path) is True, path
    # Whole path segments only — a substring test would swallow real schema directories.
    for path in ("attestation/schema.sql", "unit-tests/x.sql", "sampler/schema.sql"):
        assert is_reference_sql_path(path) is False, path


def test_is_dev_compose_file_covers_dot_and_hyphen_spellings() -> None:
    # The dot-only pattern missed `docker-compose-dev.yml` entirely (#484 review).
    for name in (
        "docker-compose.dev.yml", "docker-compose.dev.yaml", "docker-compose.local.yml",
        "docker-compose-dev.yml", "compose-local.yaml", "docker-compose.DEV.yml",
        "compose.development.yml",
    ):
        assert is_dev_compose_file(name) is True, name
    for name in ("docker-compose.yml", "docker-compose.prod.yml", "compose.yaml", "devfile.yml"):
        assert is_dev_compose_file(name) is False, name


def test_is_example_template_file_is_case_insensitive() -> None:
    # `str.endswith(".example")` missed `Dockerfile.EXAMPLE`, while the dev-compose pattern beside
    # it was already case-insensitive — the inconsistency the review flagged (#484).
    for name in ("Dockerfile.example", "Dockerfile.EXAMPLE", "Dockerfile.user.example",
                 "compose.yml.Example"):
        assert is_example_template_file(name) is True, name
    for name in ("Dockerfile", "example.Dockerfile", "notes.exampleish"):
        assert is_example_template_file(name) is False, name


def test_is_dev_compose_file_requires_a_whole_trailing_token() -> None:
    # A `[.\-](dev|local)\.ya?ml$` SUBSTRING test matched `production-local.yml` and
    # `docker-compose.non-local.yml` — and the latter is reachable through the callers' own
    # `docker-compose*.yml` glob, so it was a live false negative, not a latent one (#484
    # second-pass review). The qualifier must be the file's own trailing token.
    for name in ("docker-compose.dev.yml", "docker-compose-dev.yml", "compose.local.yaml",
                 "compose-local.yml", "compose.development.yml", "dev.yml", "local.yaml"):
        assert is_dev_compose_file(name) is True, name
    for name in ("production-local.yml", "docker-compose.non-local.yml", "docker-compose.yml",
                 "docker-compose.prod.yml", "devfile.yml", "app.dev.json"):
        assert is_dev_compose_file(name) is False, name


# --- strip_sql_comments (#427): SQL comment stripper, quote-aware ------------------------------

def test_strip_sql_quoted_dash_dash_is_not_a_comment() -> None:
    # The #427 FN class: a `--` inside a `'...'` literal is string content, not a comment. A
    # quote-unaware strip truncated the literal at the `--`, so a guard matching SQL after it never
    # saw it (a silent false negative). The literal and its tail must survive intact.
    assert strip_sql_comments("SELECT '--not a comment' AS note") == "SELECT '--not a comment' AS note"
    assert strip_sql_comments("INSERT INTO t VALUES ('a -- b');") == "INSERT INTO t VALUES ('a -- b');"


def test_strip_sql_quoted_block_open_is_not_a_comment() -> None:
    # The block-comment half of the same class: a `/*` inside a literal must not open a comment.
    assert strip_sql_comments("SELECT '/* not */ x'") == "SELECT '/* not */ x'"


def test_strip_sql_real_comments_are_still_stripped() -> None:
    # Control: real `--` and `/* */` comments (outside any literal) strip exactly as before.
    assert strip_sql_comments("SELECT 1 -- real comment") == "SELECT 1 "
    assert strip_sql_comments("SELECT 1 /* c */ , 2") == "SELECT 1  , 2"
    assert strip_sql_comments("A/* x\ny */B") == "AB"


def test_strip_sql_doubled_quote_escape_is_handled() -> None:
    # SQL escapes an inner quote by DOUBLING it (`'it''s'`), not with a backslash. The whole literal
    # (including its inner `--`) must be recognized as one span and survive.
    assert strip_sql_comments("SELECT 'it''s -- ok' AS n") == "SELECT 'it''s -- ok' AS n"


def test_strip_sql_quoted_identifier_dash_dash_survives() -> None:
    # A `--` inside a double-quoted identifier (`"weird--col"`) is content, not a comment.
    assert strip_sql_comments('SELECT "weird--col" FROM t') == 'SELECT "weird--col" FROM t'


def test_strip_sql_newline_spanning_literal_preserves_line_count() -> None:
    # A `'...'` literal can span newlines. Masking must keep those newlines so consumers that map a
    # match offset back to a line number (pg_function_search_path counts "\n"; pg_anon_grant uses
    # splitlines()) stay aligned. The inner `--` survives; the trailing real `--` is stripped.
    src = "SELECT 'a\n-- inside' , 1 -- real\nSELECT 2"
    out = strip_sql_comments(src)
    assert out == "SELECT 'a\n-- inside' , 1 \nSELECT 2"
    assert out.count("\n") == src.count("\n")
    assert len(out.splitlines()) == len(src.splitlines())


def test_strip_sql_dollar_body_dash_dash_unchanged_from_historical_behavior() -> None:
    # A dollar-quoted body is NOT a string context here (the definer guards mask those themselves):
    # a `--` inside a `$$` body strips exactly as it always did. #442 made the body a bounded scope,
    # which changes only where such a comment may END (see the #442 section below), not this.
    src = "CREATE FUNCTION f() AS $$ SELECT 1 -- inner\n SELECT 2 $$ LANGUAGE sql"
    assert strip_sql_comments(src) == "CREATE FUNCTION f() AS $$ SELECT 1 \n SELECT 2 $$ LANGUAGE sql"


def test_strip_sql_comment_apostrophe_does_not_delete_real_sql() -> None:
    # The #435-review Critical, now a regression lock: an apostrophe INSIDE a real `--` comment
    # (`don't`) is prose, not a string delimiter. The earlier regex-masking approach paired it with
    # the opening quote of an unrelated literal on a later line, exposing that literal's own inner
    # `--` as a comment and DELETING real SQL after it — the exact FN class #427 exists to kill.
    # The stateful scan knows the apostrophe is inside a comment, so nothing downstream is corrupted.
    src = "-- don't grant to anon directly\nSELECT 'safe -- literal, must survive' AS note;\n"
    assert strip_sql_comments(src) == "\nSELECT 'safe -- literal, must survive' AS note;\n"


def test_strip_sql_quote_inside_block_comment_does_not_leak() -> None:
    # Sibling of the above for block comments: a stray `'` inside a real `/* */` comment must not
    # pair with a later literal's delimiter. The comment is stripped; the real literal is kept whole.
    src = "/* 'unterminated string inside comment */ SELECT 'real -- str'"
    assert strip_sql_comments(src) == " SELECT 'real -- str'"


def test_strip_sql_never_deletes_code_on_malformed_input() -> None:
    # Safety property (unchanged): the scan only drops chars it positively identifies as comment
    # content — it never deletes real code.
    #
    # UPDATED for the #435 review. This test previously asserted that an unterminated literal
    # swallows the rest of the input as string CONTENT, on the reasoning that a comment left
    # unstripped is a "mild FP-direction miss". That reasoning is wrong for roughly half the
    # consumers: `public_table_rls`, `pg_rls_no_policy`, `policy_exists_rls_disabled` and
    # `pg_function_search_path` all check that a hardening statement is PRESENT, so a surviving
    # commented-out `ALTER TABLE … ENABLE ROW LEVEL SECURITY` satisfies the check and the guard
    # goes silent on unprotected SQL. One apostrophe in a `pg_dump` COPY block (`don't`) was
    # enough — no malformed SQL required. A quote with no partner is now treated as a stray
    # character rather than an opening delimiter.
    assert strip_sql_comments("SELECT 'unclosed -- rest") == "SELECT 'unclosed "
    # Two stray apostrophes that DO pair, with NO statement boundary between them, still confer
    # comment-immunity, so that comment survives. Locked as the documented residual — a lone `'` is
    # genuinely ambiguous in SQL. It now needs a matching pair *within one statement*: the blast
    # radius is one statement, not the file tail (see the statement-locality tests below).
    assert strip_sql_comments("SELECT can't go -- it's broken") == "SELECT can't go -- it's broken"
    # The property that matters either way: every non-comment character is preserved.
    assert "unclosed" in strip_sql_comments("SELECT 'unclosed -- rest")


def test_strip_sql_line_comment_takes_precedence_over_later_block_open() -> None:
    # Correct left-to-right lexing: a `/*` that opens INSIDE a `--` line comment is comment content,
    # so its `*/` on a later line does NOT close a block — the later line's real code survives. (The
    # old block-first regex deleted across the newline here, a latent FN this scan removes.)
    assert strip_sql_comments("-- a /* b\nREAL */ c") == "\nREAL */ c"


def test_strip_sql_unterminated_block_comment_left_intact() -> None:
    # An unterminated `/*` is not a comment (the old `/\\*.*?\\*/` regex required a closing `*/`).
    assert strip_sql_comments("SELECT 1 /* unterminated") == "SELECT 1 /* unterminated"
    # Closed blocks BEFORE an unterminated one still strip (the `block_close_absent` O(n) cache only
    # engages after the first `*/`-less `/*`, so earlier real blocks are unaffected).
    assert strip_sql_comments("/*a*/Q/*b*/R/*c") == "QR/*c"


def test_strip_sql_pathological_unterminated_blocks_are_linear() -> None:
    # Regression for the O(n^2) the `block_close_absent` cache prevents: many `*/`-less `/*` must not
    # each re-scan the tail. A failed `find("*/")` guarantees failure for every later `/*`, so the
    # miss is cached; without that, a `"/* "*N` input re-scans the whole tail at each `/*` — an O(n^2)
    # DoS on untrusted target-repo source. Mirrors the JS sibling test: N large enough that a
    # reintroduced quadratic blows the 3.0s bound (the pre-cache impl took seconds here). ~600 KB.
    import time

    src = "/* " * 200_000  # no closing */ anywhere
    start = time.monotonic()
    out = strip_sql_comments(src)
    elapsed = time.monotonic() - start
    assert out == src                           # unterminated `/*` left intact
    assert elapsed < 3.0, f"took {elapsed:.2f}s — quadratic re-scan reintroduced"  # actual ~0.06s


def test_strip_sql_empty_and_passthrough() -> None:
    assert strip_sql_comments("") == ""
    assert strip_sql_comments("SELECT 1") == "SELECT 1"


def test_strip_sql_stray_apostrophe_does_not_swallow_the_file() -> None:
    # Regression (#435 review, HIGH): an unterminated `'` consumed to EOF, so ONE apostrophe in an
    # ordinary `pg_dump` COPY block put the whole rest of the file into string context and real
    # `--` comments after it stopped being stripped. `dont panic` gave a finding; `don't panic`
    # gave none. No malformed SQL involved — this is what pg_dump output looks like.
    src = (
        "create table public.notes (id int, body text);\n"
        "COPY public.notes (id, body) FROM stdin;\n"
        "1\t{payload}\n"
        "\\.\n"
        "-- ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
    )
    for payload in ("dont panic", "don't panic", "it's fine and it's ok", r"E'don\'t panic'"):
        out = strip_sql_comments(src.format(payload=payload))
        assert "ENABLE ROW LEVEL SECURITY" not in out, f"comment survived for {payload!r}"


def test_strip_sql_stray_quote_scan_stays_linear() -> None:
    # The closing-quote lookahead must cache its miss per delimiter, or a file of stray
    # apostrophes re-scans the tail once per quote — an O(n^2) DoS on untrusted repo SQL, the
    # same shape the `*/` search already guards against.
    import time

    start = time.monotonic()
    strip_sql_comments("'" * 40_000)
    assert time.monotonic() - start < 1.0, "the quote-close miss cache was removed"


# --- statement-local comment-immunity (#435 re-review Critical) --------------------------------
#
# The previous round narrowed the stray-apostrophe class without closing it, and said it had closed
# it. A stray `'` with NO partner became a stray character — but a stray `'` that DID find a partner
# still paired, and its partner is routinely the OPENING delimiter of an unrelated, well-formed
# literal later in the file. Everything between then survived verbatim as "string content",
# including a commented-out hardening statement, and the four presence-checking guards went silent.
# Every payload in `test_strip_sql_stray_apostrophe_does_not_swallow_the_file` has a zero or
# self-balancing quote count and no second literal later in the file, so none of them tripped it.


def test_strip_sql_stray_apostrophe_cannot_preserve_another_statements_comment() -> None:
    # THE TRIGGER THE PREVIOUS ROUND MISSED: a stray apostrophe, THEN a commented-out hardening
    # statement, THEN an unrelated well-formed literal. The order is load-bearing — the comment must
    # sit between the two quotes, or the mis-pairing has nothing to protect. (The stray is a
    # bare data line: since issue #528 a TERMINATED COPY payload is opaque and cannot supply it,
    # but any other stray quote still can — this pins the pairing + revocation machinery itself.)
    src = (
        "CREATE TABLE public.notes (id serial primary key, body text);\n"
        "don't panic\n"
        "-- ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
        "COMMENT ON TABLE public.notes IS 'ok';\n"
    )
    out = strip_sql_comments(src)
    assert "ENABLE ROW LEVEL SECURITY" not in out, "a commented-out ALTER survived the strip"
    # The unrelated literal is untouched: revoking immunity must not damage real SQL.
    assert "COMMENT ON TABLE public.notes IS 'ok';" in out


def test_strip_sql_statement_locality_holds_for_every_partner_shape() -> None:
    # The partner is whatever literal the next statement happens to carry. Each of these paired with
    # the stray apostrophe before the fix and preserved the commented-out ALTER between them.
    head = (
        "CREATE TABLE public.notes (id serial primary key, body text);\n"
        "don't panic\n"
        "-- ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY{semi}\n"
    )
    partners = (
        "COMMENT ON TABLE public.notes IS 'ok';",
        "ALTER TABLE public.notes ALTER COLUMN body SET DEFAULT 'x';",
        "CREATE POLICY p ON public.notes USING (body = 'x');",
        "ALTER TABLE public.notes OWNER TO 'postgres';",
    )
    # `semi` toggles whether the commented-out statement kept its `;` — a `;`-only bound would pass
    # the first column and fail the second, so both are locked.
    for semi in (";", ""):
        for partner in partners:
            out = strip_sql_comments(head.format(semi=semi) + partner + "\n")
            assert "ENABLE ROW LEVEL SECURITY" not in out, f"survived for {semi!r} + {partner!r}"


def test_strip_sql_backslash_escape_apostrophe_is_also_bounded() -> None:
    # A second source of the same parity break, unrelated to COPY data: this scanner does not model
    # backslash escapes, so `E'don\'t panic'` leaves an unbalanced `'` behind. It must not be able to
    # reach the next statement's comment either.
    src = (
        "CREATE TABLE public.notes (id serial primary key, body text);\n"
        "INSERT INTO public.notes VALUES (E'don\\'t panic');\n"
        "-- ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
        "COMMENT ON TABLE public.notes IS 'ok';\n"
    )
    assert "ENABLE ROW LEVEL SECURITY" not in strip_sql_comments(src)


def test_strip_sql_revoking_immunity_never_changes_the_pairing() -> None:
    # The design constraint that makes this safe, and the bug the first attempt at this fix had.
    # REFUSING to pair (treating the opener as data) looks equivalent to revoking immunity and is
    # not: it turns the span's CLOSING delimiter into an opening one and re-lexes the whole tail —
    # reintroducing the same bug one statement further down. Caught on real SQL of this exact shape:
    # a long `INSERT … VALUES ('<prompt>')` whose prose contains a `;`, followed by `--` comments.
    src = (
        "INSERT INTO agents (prompt, is_default) VALUES (\n"
        "    'Use the conversation''s primary language; default to English.\n"
        "     Do not include markdown.',\n"
        "    FALSE,  -- not the default agent\n"
        "    TRUE    -- active\n"
        ");\n"
        "-- ALTER TABLE public.agents ENABLE ROW LEVEL SECURITY;\n"
    )
    out = strip_sql_comments(src)
    # The literal spans a `;` so its immunity is revoked — but it contains no comment, so it is
    # emitted byte-for-byte, and the trailing `--` comments outside it still strip normally.
    assert "Use the conversation''s primary language; default to English." in out
    assert "not the default agent" not in out
    assert "active" not in out
    assert "ENABLE ROW LEVEL SECURITY" not in out


def test_strip_sql_revoked_span_keeps_its_delimiters_and_non_comment_content() -> None:
    # The documented price of statement-locality, pinned precisely so a future reader knows its
    # exact shape: a GENUINE literal spanning a statement boundary has a `--`/`/*` inside it
    # replaced by the U+FFFD sentinel (issue #528: deleting it outright welded the neighbours
    # into a `\\s+`-matchable phrase) — and nothing else. Both delimiters, every other character,
    # and the line count survive.
    src = "CREATE POLICY p ON t USING (note = 'a; -- b');"
    out = strip_sql_comments(src)
    assert out == "CREATE POLICY p ON t USING (note = 'a; \ufffd');"
    assert out.count("'") == src.count("'"), "a delimiter was consumed — parity was changed"
    # A multi-line literal whose continuation line begins a new statement, same story.
    multi = "INSERT INTO m (body) VALUES ('BEGIN;\nUPDATE t SET x = 1; -- note\nCOMMIT;');"
    out = strip_sql_comments(multi)
    assert out == "INSERT INTO m (body) VALUES ('BEGIN;\nUPDATE t SET x = 1; \ufffd\nCOMMIT;');"
    assert len(out.splitlines()) == len(multi.splitlines())
    # ...and a multi-line literal that crosses NO boundary keeps its `--` opaquely (the #427 fix).
    keep = "INSERT INTO m (body) VALUES ('line one\n   plain -- keep me\n   tail')"
    assert strip_sql_comments(keep) == keep


def test_strip_sql_statement_locality_stays_linear() -> None:
    # Revoking immunity re-scans a span's interior once and then jumps past it, so every character
    # is visited a bounded number of times. These shapes each broke a bounded-search design that
    # could not cache its misses; they must all stay linear.
    import time

    for src in (
        "''" * 20_000 + "\nSELECT 'x'",        # doubled-quote run then a real literal
        ("'" + "x" * 20) * 20_000,             # many short literals
        "'" * 20_000 + "\nSELECT 'a'",
        "; " * 200_000,                        # a boundary at every other character
        "SELECT 'a';\n" * 100_000,             # a statement boundary on every line
        "COPY t FROM stdin;\nx\n\\.\n" * 50_000,  # many opaque COPY payload spans (issue #528)
    ):
        start = time.monotonic()
        strip_sql_comments(src)
        elapsed = time.monotonic() - start
        assert elapsed < 3.0, f"took {elapsed:.2f}s on {len(src)} chars — quadratic reintroduced"


# --- issue #528: opaque COPY payloads + the revoked-interior sentinel -------------------------
#
# Two defects, one pairing mechanism (issue #528). (1) A stray quote in ordinary `pg_dump` COPY
# payload paired with the OPENING delimiter of a later well-formed literal; the scan then resumed
# normal-mode lexing INSIDE that literal, so a `--`/`/*` in its ordinary string data read as a
# real comment opener and deleted live SQL after it (to end-of-line, or to a `*/` statements
# away). Closed at the source: a TERMINATED `COPY … FROM stdin;` data section is opaque — blanked,
# never lexed. (2) DELETING a comment from a revoked-immunity span welded the tokens either side
# into one phrase a consumer's `\s+` matched as real SQL; the interior stripper now substitutes a
# non-SQL sentinel (U+FFFD) instead, so nothing can weld.


def test_strip_sql_copy_payload_apostrophe_cannot_steal_a_later_literals_opener() -> None:
    # Issue #528 repro 1 (line-comment form), verbatim. The apostrophe in `don't` paired with the
    # opening quote of `'note -- …'`, and everything from that literal's own `--` onward was
    # deleted — including the real, uncommented ALTER TABLE that enables RLS.
    src = (
        "CREATE TABLE public.notes (id serial primary key, body text);\n"
        "COPY public.notes (body) FROM stdin;\n"
        "don't panic\n"
        "\\.\n"
        "SELECT 'note -- not a real comment, just data' AS x; "
        "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
    )
    out = strip_sql_comments(src)
    assert "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;" in out
    # The payload is opaque, not merely quote-neutralized: its text must not reach a consumer.
    assert "panic" not in out
    # The head line is real SQL and survives verbatim; the line count is unchanged.
    assert "COPY public.notes (body) FROM stdin;" in out
    assert out.count("\n") == src.count("\n")


def test_strip_sql_copy_payload_block_comment_variant_stays_bounded() -> None:
    # Repro 1's block-comment form was unbounded: deletion ran from the `/*` inside the stolen
    # literal to a stray `*/` in a real comment two statements later, taking the ALTER with it.
    src = (
        "CREATE TABLE public.notes (id serial primary key, body text);\n"
        "COPY public.notes (body) FROM stdin;\ndon't panic\n\\.\n"
        "SELECT 'note /* not a real comment, just data' AS x;\n"
        "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
        "-- some other real comment with a stray */ marker below, unrelated\n"
        "CREATE POLICY p ON public.notes USING (true);\n"
    )
    out = strip_sql_comments(src)
    assert "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;" in out
    assert "CREATE POLICY p ON public.notes USING (true);" in out


def test_strip_sql_copy_payload_is_data_not_live_sql() -> None:
    # FP-bait for the widening: payload DATA that happens to look like a hardening statement must
    # not satisfy a presence-check consumer. Before the payload was opaque, this fabricated an
    # `ENABLE ROW LEVEL SECURITY` for a table the schema never hardens.
    src = (
        "CREATE TABLE public.notes (id serial primary key, body text);\n"
        "COPY public.notes (body) FROM stdin;\n"
        "ALTER TABLE public.evil ENABLE ROW LEVEL SECURITY;\n"
        "\\.\n"
    )
    out = strip_sql_comments(src)
    assert "ENABLE ROW LEVEL SECURITY" not in out
    assert out.count("\n") == src.count("\n")
    # blank mode blanks the same span and keeps its length contract.
    outb = strip_sql_comments(src, blank=True)
    assert len(outb) == len(src)
    assert "ENABLE ROW LEVEL SECURITY" not in outb


def test_strip_sql_unterminated_copy_body_degrades_to_the_old_lexing() -> None:
    # The #602 honesty rule, applied here: a COPY body with no `\.` terminator before EOF gets no
    # opaqueness — it is lexed as code exactly as before, and the #528 steal can still happen in
    # it. Pinned so the residual stays a documented choice, not an accident.
    src = (
        "COPY public.notes (body) FROM stdin;\n"
        "don't panic\n"
        "SELECT 'note -- data' AS x; ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
    )
    out = strip_sql_comments(src)
    assert "don't panic" in out                       # not blanked
    assert "ENABLE ROW LEVEL SECURITY" not in out     # the pre-existing steal, unchanged


def test_strip_sql_copy_head_inside_a_literal_is_not_a_payload() -> None:
    # FP-bait for the head detection, NARROW by design (#826 review Minor 1): this checks only
    # that a fake head inside a literal does not blank anything BY ITSELF when the nearest `\.`
    # follows the literal directly. The adversarial case where a later, genuine COPY block sits in
    # the would-be-swallowed region is its own test:
    # `test_strip_sql_fake_copy_head_cannot_swallow_a_later_real_blocks_terminator`.
    src = (
        "INSERT INTO docs (body) VALUES ('transcript:\n"
        "COPY t FROM stdin;\n"
        "row one\n"
        "');\n"
        "\\.\n"
        "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
    )
    out = strip_sql_comments(src)
    assert "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;" in out
    assert "row one" in out


def test_strip_sql_fake_copy_head_cannot_swallow_a_later_real_blocks_terminator() -> None:
    # PR #826 review Critical 1. The first cut of the COPY opacity pre-scanned heads over RAW
    # text: a head-shaped line inside an earlier literal paired with the NEXT bare `\\.` line
    # anywhere ahead, folding a later, genuine, well-formed COPY block into a phantom span the
    # walk never processed. That real block then lost the very opacity Part A exists to provide,
    # and the #528 steal reopened inside it. Heads are now recognized INLINE, only at the lexer's
    # own top-level cursor, so an embedded fake head is structurally invisible: it cannot open a
    # span of its own and it cannot swallow a later real block's terminator either.
    src = (
        "CREATE TABLE t (a int);\n"
        "INSERT INTO docs(body) VALUES ('example:\n"
        "COPY x FROM stdin;\n"
        "sample row\n"
        "end');\n"
        "COPY real FROM stdin;\n"
        "don't panic\n"
        "\\.\n"
        "SELECT 'steal -- comment' AS z; ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
    )
    out = strip_sql_comments(src)
    assert "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;" in out
    assert "panic" not in out       # the REAL block's payload is opaque, its apostrophe inert
    assert "sample row" in out      # the literal's own content is untouched


# The window is wide (0.09s healthy against 5.17s with the quadratic head probe restored), which
# is the case an absolute TimingBudget is for rather than a growth ratio (tests/_timing.py).
_C826_HEAD_PROBE_BUDGET = register(
    TimingBudget(
        name="strip-sql/copy-head-probe-backtracking",
        seconds=2.0,
        measured=0.0906,
        regression=5.17,
        why="the two-lazy-segment head regex was restored, so the O(n^2) is back (#826 Major 1)",
    )
)


def test_strip_sql_copy_head_probe_stays_linear_on_a_repeated_from_stdin_line() -> None:
    # PR #826 round-2 review Major 1. `_COPY_FROM_STDIN` paired two independent lazy segments
    # (`[^\n]*?\bFROM\s+stdin\b[^\n]*?;[ \t\r]*$`). On a head-shaped line carrying many
    # `FROM stdin` tokens and NO line-final `;`, the second segment scanned to end-of-line for a
    # `;` that never comes, backtracked, and retried at the next `FROM stdin` — O(occurrences x
    # line length) per line, measured cleanly quadratic (44 KB line: 0.65s; 88 KB: 2.5s).
    #
    # `copy_terminator_absent` does NOT bound it: that latch only engages once a head FULLY
    # matches, and these lines never match at all, so every such line pays the cost again. The
    # existing linearity tests all miss this shape — they stress many unterminated `/*`, many bare
    # `'`, or many WELL-FORMED small COPY blocks, none of which defeat the head regex's own
    # backtracking. Reachable: `strip_sql_comments` runs over target-repo `.sql` from 15 guards
    # with no caching between them, and `read()` has no size cap.
    import time

    # 32 head-shaped lines, each ~22 KB of repeated `FROM stdin` with no terminating `;`.
    src = "".join("COPY x " + ("FROM stdin " * 2_000) + "no_semicolon\n" for _ in range(32))
    start = time.monotonic()
    out = strip_sql_comments(src)
    elapsed = time.monotonic() - start
    assert out == src                        # no head matches, so nothing is blanked
    assert_within(elapsed, _C826_HEAD_PROBE_BUDGET)


def test_strip_sql_real_copy_heads_still_match_after_the_linearity_fix() -> None:
    # The fires-still direction for the narrowing above (project rule 1). Making the head probe
    # atomic commits it to the LEFTMOST `FROM stdin` on the head line, so every shape a real
    # `pg_dump` (or hand-written) head can take must still be recognized — otherwise the payload
    # is lexed as code again and the whole #528 steal reopens.
    heads = [
        "COPY t FROM stdin;",
        "   \tCOPY public.notes (id, body) FROM stdin;",
        "copy T from STDIN;",
        "COPY t FROM stdin;  \t\r",
        "COPY t FROM stdin WITH (FORMAT csv);",
        "COPY t FROM\nstdin;",          # SQL is whitespace-insensitive: a wrapped head still counts
        "COPY t FROM \n  stdin;",
    ]
    for head in heads:
        src = head + "\n1\tdon't panic\n\\.\n-- ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
        out = strip_sql_comments(src)
        assert "panic" not in out, f"payload not blanked — head unrecognized: {head!r}"
        assert "ENABLE ROW LEVEL SECURITY" not in out, f"steal reopened for {head!r}"
    # And the non-head shapes stay non-heads (the FP-bait direction).
    for miss in ("COPY t FROM stdin", "COPY t FROM stdin; -- note", "COPYING t FROM stdin;",
                 "COPY t FROMstdin;", "x COPY t FROM stdin;"):
        src = miss + "\ndata row\n\\.\n"
        assert "data row" in strip_sql_comments(src), f"non-head wrongly honored: {miss!r}"


def test_strip_sql_revoked_interior_comment_cannot_weld_a_fabricated_match() -> None:
    # Issue #528 repro 2, verbatim: documentation-style prose inside a data literal. The literal
    # spans the `;` it contains, so its immunity is revoked and the `/* … */` is stripped — but
    # DELETING it welded `ALTER TABLE foo` onto `ENABLE ROW LEVEL SECURITY`, and a consumer's
    # `\s+` then read a hardening statement for a table that exists nowhere in the schema.
    src = (
        "CREATE TABLE public.docs (id serial primary key, body text);\n"
        "INSERT INTO public.docs (body) VALUES "
        "('Example: ALTER TABLE foo /* run this in staging */ ENABLE ROW LEVEL SECURITY; end of note');\n"
    )
    weld = re.compile(r"alter\s+table\s+(?:only\s+)?foo\s+enable\s+row\s+level\s+security", re.I)
    out = strip_sql_comments(src)
    assert weld.search(out) is None, "a stripped comment welded prose into a fabricated statement"
    assert "run this in staging" not in out   # the comment text itself still goes
    # Same contract in blank mode, which must also keep its length invariant.
    outb = strip_sql_comments(src, blank=True)
    assert len(outb) == len(src)
    assert weld.search(outb) is None


def test_strip_sql_ordinary_comment_stripping_is_untouched_by_the_sentinel() -> None:
    # The fires-still direction for the sentinel: OUTSIDE a revoked span, comment handling is
    # unchanged — a genuine mid-statement comment strips clean, the statement's tokens still read
    # as one `\s+`-separated phrase, and no sentinel appears anywhere.
    src = "ALTER TABLE foo /* staging note */ ENABLE ROW LEVEL SECURITY;\n"
    out = strip_sql_comments(src)
    assert re.search(r"alter\s+table\s+foo\s+enable\s+row\s+level\s+security", out, re.I)
    assert "\ufffd" not in out


def test_strip_sql_comments_blank_mode_preserves_length_and_newlines() -> None:
    # fix-round review Critical: `blank=True` exists so a per-line caller (e.g.
    # `policy_no_role_scope.py`) can map a match offset in the stripped text back to the same
    # line in the raw file — unlike the default deleting mode, whose block-comment path drops
    # embedded newlines and desyncs the line count.
    src = "SELECT 1; /* a\nb\nc */ SELECT 2; -- trailing\n"
    out = strip_sql_comments(src, blank=True)
    assert len(out) == len(src)
    assert out.count("\n") == src.count("\n")
    assert out.splitlines()[0].startswith("SELECT 1;")
    assert set(out.splitlines()[0][len("SELECT 1;"):]) <= {" "}
    assert "a" not in out and "b" not in out and "c" not in out
    assert "trailing" not in out
    # Default (deleting) mode is unaffected by the new parameter.
    assert strip_sql_comments(src) == "SELECT 1;  SELECT 2; \n"


def test_strip_sql_comments_blank_mode_stays_quote_aware() -> None:
    # The exact reachable shape from the #693 review: a `--` inside a string literal on one
    # statement must not be read as a comment (which would eat the statement's own terminating
    # `;` and merge its span with the next statement) — `blank=True` must inherit the same
    # quote-tracking as the default mode, not fall back to a naive line-comment regex.
    src = "CREATE POLICY p1 ON t USING (x = 'a--b');\nCREATE POLICY p2 ON t TO authenticated USING (y = 1);\n"
    out = strip_sql_comments(src, blank=True)
    assert len(out) == len(src)
    assert out.count("\n") == src.count("\n")
    assert "'a--b'" in out  # the literal, `--` and all, survives untouched
    assert out.count(";") == src.count(";")  # neither statement's terminator was swallowed


def test_strip_sql_comments_blank_mode_matches_deleting_mode_minus_the_comment_chars() -> None:
    # blank=True must change WHAT a comment character becomes, never WHICH characters are
    # classified as comment content — same lexing, same decisions, only the emission step differs.
    src = "SELECT 'a--b' AS x; -- real comment\nSELECT 2; /* block\nspans lines */ SELECT 3;"
    blanked = strip_sql_comments(src, blank=True)
    deleted = strip_sql_comments(src)
    # Stripping all whitespace from the blanked output should collapse it onto the deleted one,
    # since blanking only ever substitutes comment characters with spaces (newlines excepted).
    assert "".join(blanked.split()) == "".join(deleted.split())
    # A REVOKED span goes through the sentinel path in both modes (issue #528); the equivalence
    # must hold there too — delete emits the bare sentinel, blank pads it to the comment's length.
    src = "SELECT 'a; -- b' AS x;"
    assert "".join(strip_sql_comments(src, blank=True).split()) == "".join(strip_sql_comments(src).split())


# --- issue #442: a dollar-quoted body is a BOUNDED comment scope -------------------------------
#
# A comment opener inside `$$…$$` used to be lexed as if the body were top-level code, so the `/*`
# of `$$See docs/*.md$$` opened a comment that ran to the next `*/` ANYWHERE in the file and blanked
# the live SQL between them (six guards silent on a real violation, three of them since #1006).
# The body is now a scope: comments inside it are still comments (the in-body contract the DO-block
# detections and presence checks rely on), but nothing opened inside it can end outside it.

_I442_LIVE = "CREATE POLICY p ON t USING (true);"


def _both_modes(src: str) -> list[str]:
    """`strip_sql_comments(src)` in deleting and blank mode, asserting blank mode's layout contract."""
    blanked = strip_sql_comments(src, blank=True)
    assert len(blanked) == len(src)
    assert [k for k, c in enumerate(blanked) if c == "\n"] == [k for k, c in enumerate(src) if c == "\n"]
    return [strip_sql_comments(src), blanked]


@pytest.mark.parametrize("body", ["$$See docs/*.md$$", "$sh$cp -r /opt/app/* /srv$sh$"], ids=["bare", "tagged"])
def test_strip_sql_comment_opener_in_a_dollar_body_cannot_close_outside_it(body: str) -> None:
    # The #602 sandwich, at the lexer: the body's `/*` has no `*/` inside the body, so it is data.
    src = f"COMMENT ON FUNCTION f() IS {body};\n{_I442_LIVE}\n/* note */\n"
    for out in _both_modes(src):
        assert _I442_LIVE in out, f"live SQL after the body was blanked: {out!r}"
        assert body in out, "the body itself is data, kept verbatim"
        assert "note" not in out, "the genuine trailing comment still strips"


@pytest.mark.parametrize(
    "src",
    [
        f"DO $$ BEGIN /* {_I442_LIVE} */ NULL; END $$;\n",
        f"DO $$\nBEGIN\n  -- {_I442_LIVE}\n  NULL;\nEND $$;\n",
        f"DO $body$ BEGIN /*\n{_I442_LIVE}\n*/ NULL; END $body$;\n",
    ],
    ids=["block", "line", "multi-line-block-tagged"],
)
def test_strip_sql_comments_inside_a_dollar_body_are_still_comments(src: str) -> None:
    # The traded direction (Rule 1): the scope bounds in-body comments, it never makes them data.
    # A commented-out statement inside a function or DO body stays commented out.
    for out in _both_modes(src):
        assert "CREATE POLICY" not in out, f"an in-body comment survived: {out!r}"
        assert "NULL;" in out and out.count("$") == src.count("$"), "the body's code and tags survive"


def test_strip_sql_line_comment_in_a_dollar_body_ends_at_the_close() -> None:
    # One line: the in-body `--` used to run to end-of-line, through the body's close, and take
    # the live policy with it.
    deleted, blanked = _both_modes(f"SELECT $$a--b$$; {_I442_LIVE}\n")
    assert deleted == f"SELECT $$a$$; {_I442_LIVE}\n"
    assert blanked == f"SELECT $$a   $$; {_I442_LIVE}\n"
    # ... and a genuine comment after the body on the same line still strips to end-of-line.
    deleted, _ = _both_modes(f"SELECT $$a--b$$; -- {_I442_LIVE}\n")
    assert deleted == "SELECT $$a$$; \n"


def test_strip_sql_block_comment_inside_a_dollar_body_still_strips_when_it_closes_there() -> None:
    deleted, blanked = _both_modes("SELECT $$ a /* in */ b $$ /* out */;")
    assert deleted == "SELECT $$ a  b $$ ;"
    assert blanked == "SELECT $$ a          b $$          ;"


def test_strip_sql_quote_in_a_dollar_body_pairs_only_inside_it() -> None:
    # Parity is scoped too. The apostrophe in `$$it's$$` used to pair with the next quote AFTER the
    # body (here the one in `don't`), and with no statement boundary between them that span kept
    # its comment-immunity, so the real `--` comment inside it survived as "string content".
    src = "SELECT $$it's$$ AS note -- don't ENABLE ROW LEVEL SECURITY here\n"
    for out in _both_modes(src):
        assert "ENABLE ROW LEVEL SECURITY" not in out, f"a real comment survived: {out!r}"
        assert "$$it's$$ AS note" in out
    # A literal that pairs INSIDE the body keeps its `--` opaque, as any literal does.
    for out in _both_modes("DO $$ BEGIN RAISE NOTICE 'a -- b'; END $$;"):
        assert "'a -- b'" in out


def test_strip_sql_unterminated_dollar_tag_degrades_to_the_old_lexing() -> None:
    # No partner before EOF: no scope, the `$` is plain text — exactly the pre-#442 lexing, so the
    # bare `/*` still pairs with a genuine later `*/` (the #602 no-partner cap; an unclosed `$tag$`
    # is a syntax error, and malformed input gets the caps, not a completeness guarantee).
    src = f"SELECT $body$ opener /* \n{_I442_LIVE}\n*/ tail\n"
    deleted, blanked = _both_modes(src)
    assert deleted == "SELECT $body$ opener  tail\n"
    assert "CREATE POLICY" not in blanked


@pytest.mark.parametrize(
    "src",
    [
        "SELECT x$$ -- c $$ tail\n",               # glued to an identifier: `x$$` is one identifier
        "SELECT $1$$ -- c $$ tail\n",              # `$1` is a parameter, and the `$$` after it is glued
        "SELECT '$$' -- c $$ tail\n",              # inside a literal
        'SELECT "$$" -- c $$ tail\n',              # inside a quoted identifier
        "-- $$\nSELECT 1 -- c $$ tail\n",          # inside a line comment
        "/* $$ */ SELECT 1 -- c $$ tail\n",        # inside a block comment
    ],
    ids=["glued", "param", "literal", "identifier", "line-comment", "block-comment"],
)
def test_strip_sql_dollar_opener_only_at_top_level_and_unglued(src: str) -> None:
    # A phantom opener would close at the `$$` inside the trailing comment and END that comment
    # there, leaving `tail` live. Each is not an opener, so the comment runs to end-of-line.
    for out in _both_modes(src):
        assert "tail" not in out, f"a phantom dollar opener bounded a real comment: {out!r}"


def test_strip_sql_nested_dollar_tag_inside_a_body_is_plain_text() -> None:
    # The nested-tag decision (#442): no recursion. Inside `$fn$`, the inner `$q$` is plain text, so
    # its comments are still comments and a `/*` inside it can blank at most within the OUTER body.
    src = f"CREATE FUNCTION f() AS $fn$ EXECUTE $q$ docs/*.md $q$; /* x */ $fn$;\n{_I442_LIVE}\n/* z */\n"
    for out in _both_modes(src):
        assert _I442_LIVE in out and "z" not in out
        assert "EXECUTE $q$ docs" in out and "md $q$" not in out  # blanked from `/*` to `*/` ...
        assert "$fn$;" in out                                      # ... and the outer close survives
    # A `$$` inside a `$tag$` body belongs to that body: Postgres closes only on the same tag.
    for out in _both_modes(f"SELECT $fn$ a $$ /* in */ $$ b $fn$ /* out */;\n{_I442_LIVE}\n"):
        assert "/* in */" not in out and "out" not in out and _I442_LIVE in out
        assert out.count("$$") == 2 and out.count("$fn$") == 2


def test_strip_sql_a_miss_inside_a_dollar_body_does_not_leak_to_the_tail() -> None:
    # A body has its own miss caches. Its `/*` finds no `*/` before the close and its `'` no
    # partner, and neither says anything about the file's tail: once the scan leaves the body, a
    # real block comment and a real literal after it must lex as they would without the body.
    for out in _both_modes("SELECT $$ /* $$ ;\n/* real */ SELECT 1;"):
        assert "real" not in out and "$$ /* $$" in out
    for out in _both_modes("SELECT $$ ' $$, 'a -- b';"):
        assert "'a -- b'" in out


def test_strip_sql_copy_head_inside_a_dollar_body_is_not_a_payload() -> None:
    # The COPY probe is off inside a body: a COPY-shaped line in a function body is code, and its
    # "rows" are lexed, so a comment among them still strips (blanking them as payload would not).
    src = "DO $$\nCOPY t FROM stdin;\n-- note\n\\.\n$$;\n"
    for out in _both_modes(src):
        assert "note" not in out and "COPY t FROM stdin;" in out and "\\." in out


def test_strip_sql_dollar_scope_keeps_blank_mode_layout_under_fuzz() -> None:
    # Blank mode's contract (same length, every `\n` at its offset) must hold on `$`-dense input,
    # and blanking may only turn characters into spaces — never move or invent one.
    rng = random.Random(442)
    alphabet = ["$$", "$t$", "$", "x$$", "$1", "'", '"', "--", "/*", "*/", "\n", ";", "a", " ", "E'", "\\"]
    sentinel = base_module._REVOKED_COMMENT_SENTINEL  # a revoked-span comment's first character (#528)
    for _ in range(3000):
        src = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        out = strip_sql_comments(src, blank=True)
        assert len(out) == len(src), repr(src)
        assert all(o in (s, " ", sentinel) for o, s in zip(out, src, strict=True)), repr(src)
        assert [k for k, c in enumerate(out) if c == "\n"] == [k for k, c in enumerate(src) if c == "\n"]


@pytest.mark.slow
def test_strip_sql_dollar_scope_is_linear() -> None:
    """The #419 class for the new `$` probe. Each shape breaks one bounded-search design:

    distinct unterminated tags (a per-opener close `find` walks to EOF each time, the #602 shape);
    many bodies each holding an unterminated `/*` or `'` (a body-local miss that consulted, or
    poisoned, the file-tail cache would rescan, or mis-answer, per body); and one deep nest of
    distinct tags (recursing into nested bodies would be O(n x depth)). Growth ratio, not a
    wall-clock budget: machine speed cancels out of a ratio (tests/_timing.py)."""
    # Four sizes: `classify` only drops an outlier from three ratios. Halved from (1000..64000) on
    # 2026-10-23: the per-opener `find` and the unbounded body-local `*/` mutants still read quadratic
    # with margin (ratios ~9/19/13 and ~9/13/15 per x4 step, against the ~8x linear edge).
    sizes = (500, 2000, 8000, 32000)
    shapes: dict[str, Callable[[int], str]] = {
        "unterminated-tags": lambda n: "".join(f"select $t{i}$ " for i in range(n)) + "\n/* z */\n",
        "bodies-with-block-openers": lambda n: "$$ /* $$ " * n + "\n/* z */\n",
        "bodies-with-stray-quotes": lambda n: "$$ ' $$ " * n + "\n/* z */\n",
        "deep-nest": lambda n: "".join(f"$t{i}$" for i in range(n)) + "/* x */"
        + "".join(f"$t{i}$" for i in reversed(range(n))) + "\n/* z */\n",
    }
    for name, build in shapes.items():
        texts = {n: build(n) for n in sizes}
        outs: dict[int, str] = {}

        def scan(n: int, texts: dict[int, str] = texts, outs: dict[int, str] = outs) -> None:
            outs[n] = strip_sql_comments(texts[n], blank=True)

        assert_growth(scan, sizes, expected="linear")
        # A scan that stopped recognising comments would also be fast: the trailing one still strips.
        for n in sizes:
            assert "z" not in outs[n] and len(outs[n]) == len(texts[n]), name


def _mainpy(text: str) -> list[tuple[Path, str]]:
    return [(Path("main.py"), text)]

def test_cross_file_include_with_inline_deps_protects_that_router() -> None:
    files = _mainpy(
        "from routes import admin\n"
        "app.include_router(admin.router, prefix='/api', dependencies=[Depends(get_current_admin)])\n"
    )
    assert cross_file_authed_routers(files) == {"admin": {"router"}}

def test_cross_file_include_with_variable_deps_protects_that_router() -> None:
    # `_admin = [Depends(...)]` referenced as `dependencies=_admin` (variable, not inline list).
    files = _mainpy(
        "_admin = [Depends(get_current_admin)]\n"
        "app.include_router(admin.router, dependencies=_admin)\n"
    )
    assert cross_file_authed_routers(files) == {"admin": {"router"}}

def test_cross_file_multi_dot_ref_maps_to_module_before_router() -> None:
    # `app.routes.admin.router` -> the module is the segment before `.router`, i.e. "admin".
    files = _mainpy(
        "app.include_router(app.routes.admin.router, dependencies=[Security(scope)])\n"
    )
    assert cross_file_authed_routers(files) == {"admin": {"router"}}

@pytest.mark.parametrize(
    "call",
    [
        "app.include_router(admin.router, summary='''the team's api''', dependencies=[Depends(a)])\n",
        # The bare twin: the dual-mount defense has to SEE a bare mount to flip it to unprotected.
        "app.include_router(admin.router, summary='''the team's api''')\n",
    ],
)
def test_include_router_ref_reads_past_a_triple_quoted_kwarg(call: str) -> None:
    # #613: an apostrophe inside a triple-quoted kwarg desynced the default-mode split to None, and
    # "no ref" made the mount invisible. The helper splits in Python mode, so the ref is read.
    assert split_call_args(call, call.index("(")) is None  # the default mode's answer
    assert include_router_ref(call, 0) == "admin.router"


def test_cross_file_include_without_deps_does_not_protect() -> None:
    files = _mainpy("app.include_router(admin.router, prefix='/api')\n")
    assert cross_file_authed_routers(files) == {}

def test_cross_file_include_with_non_auth_variable_deps_does_not_protect() -> None:
    # A bare identifier that is NOT a known auth-dep list variable does not protect (it could be a
    # non-auth dependency list); only a variable bound to a `[Depends(...)/Security(...)]` list does.
    files = _mainpy(
        "_pagination = [Depends(get_pagination)]\n"  # bound, but reference below is a DIFFERENT name
        "app.include_router(admin.router, dependencies=_unknown)\n"
    )
    assert cross_file_authed_routers(files) == {}

def test_cross_file_nested_bracket_before_depends_is_not_truncated() -> None:
    # A nested `[...]` before the Depends(...) must not truncate the balance-scan (the #464 ReDoS/
    # nested-bracket fix): the list still carries auth.
    files = _mainpy(
        "app.include_router(admin.router, dependencies=[limiter(times=[5]), Depends(get_user)])\n"
    )
    assert cross_file_authed_routers(files) == {"admin": {"router"}}

def test_cross_file_bare_var_include_is_not_a_cross_file_router() -> None:
    # A bare-var include (`include_router(router, ...)`) is SAME-file, so it contributes no stem.
    files = _mainpy("app.include_router(router, dependencies=[Depends(get_user)])\n")
    assert cross_file_authed_routers(files) == {}

def test_same_file_authed_routers_construct_with_inline_deps() -> None:
    text = "router = APIRouter(dependencies=[Depends(get_current_user)])\n"
    assert same_file_authed_routers(text) == {"router"}

def test_same_file_authed_routers_construct_with_variable_deps() -> None:
    text = (
        "_auth = [Depends(get_current_user)]\n"
        "router = APIRouter(dependencies=_auth)\n"
    )
    assert same_file_authed_routers(text) == {"router"}

def test_same_file_authed_routers_bare_var_include() -> None:
    text = "app.include_router(admin_router, dependencies=[Depends(require_admin)])\n"
    assert same_file_authed_routers(text) == {"admin_router"}

def test_same_file_authed_routers_construct_without_deps_is_empty() -> None:
    assert same_file_authed_routers("router = APIRouter()\n") == set()

def test_router_auth_resolvers_total_on_garbage() -> None:
    # Never raise on odd/empty input.
    assert cross_file_authed_routers([(Path("x.py"), "")]) == {}
    assert cross_file_authed_routers([]) == {}
    assert same_file_authed_routers("") == set()
    assert same_file_authed_routers("def f(: syntax( error]]]\n") == set()

def test_auth_call_named_rejects_bare_db_dependency() -> None:
    # AUTH_CALL_NAMED (the stricter guards' policy): a bare `Depends(get_db)` is NOT auth, so the
    # router is not treated as authed (issue #307 applied at the router level).
    text = "router = APIRouter(dependencies=[Depends(get_db)])\n"
    assert same_file_authed_routers(text, auth_call=AUTH_CALL_NAMED) == set()
    # ...while the default loose policy DOES treat any Depends() as auth (auth-dependency semantics).
    assert same_file_authed_routers(text, auth_call=AUTH_CALL_ANY) == {"router"}

def test_auth_call_named_accepts_auth_named_and_security() -> None:
    for dep in ("Depends(require_admin)", "Depends(get_current_user)", "Security(scopes)"):
        text = f"router = APIRouter(dependencies=[{dep}])\n"
        assert same_file_authed_routers(text, auth_call=AUTH_CALL_NAMED) == {"router"}, dep

def test_auth_call_named_variable_deps_respect_strictness() -> None:
    # A variable bound to a non-auth list is not protective under NAMED, but is under ANY.
    text = (
        "_deps = [Depends(get_db)]\n"
        "router = APIRouter(dependencies=_deps)\n"
    )
    assert same_file_authed_routers(text, auth_call=AUTH_CALL_NAMED) == set()
    assert same_file_authed_routers(text, auth_call=AUTH_CALL_ANY) == {"router"}

def test_cross_file_authed_routers_named_rejects_db_dependency() -> None:
    files = [(Path("main.py"), "app.include_router(admin.router, dependencies=[Depends(get_db)])\n")]
    assert cross_file_authed_routers(files, auth_call=AUTH_CALL_NAMED) == {}
    assert cross_file_authed_routers(files, auth_call=AUTH_CALL_ANY) == {"admin": {"router"}}


# --- #872: the shared per-route `dependencies=[<bare factory()>]` reader ----------------------------
# Moved out of `auth_dependency_not_applied.py` so the three per-route sibling guards share it. These
# pin the helper's own contract; each guard's suite pins its wiring.


def test_route_deps_carry_auth_reads_the_whole_list_and_respects_the_matcher() -> None:
    """The positive case, with a nested bracket ahead of the factory: the list is balance-scanned in
    full. The SAME text answers differently per matcher, which is the per-call-site strictness the
    move made a parameter."""
    block = "@router.post('/x', dependencies=[limiter(times=[5]), requires_authenticated()])\ndef x(): ..."
    view = blank_line_comments(block)
    open_idx = block.index("(")
    assert route_deps_carry_auth(view, open_idx, PER_ROUTE_AUTH_FACTORY) is True
    # Authentication is not privilege: the privilege matcher must not credit it.
    assert route_deps_carry_auth(view, open_idx, PER_ROUTE_PRIV_FACTORY) is False
    priv = blank_line_comments(block.replace("requires_authenticated", "requires_system_write_role"))
    assert route_deps_carry_auth(priv, open_idx, PER_ROUTE_PRIV_FACTORY) is True


def test_route_deps_carry_auth_clips_an_unterminated_list_to_the_decorator() -> None:
    """The move's one behaviour change (#872), a narrowing of what suppresses: an unterminated `[`
    inside a BALANCED decorator used to be scanned to the end of the text, so a factory CALLED in the
    handler body (never applied as a dependency) faked protection. The scan now stops at the
    decorator's own `)`."""
    block = (
        "@router.post('/x', dependencies=[get_db())\n"
        "def x():\n"
        "    requires_authenticated()\n"
    )
    view = blank_line_comments(block)
    assert route_deps_carry_auth(view, block.index("("), PER_ROUTE_AUTH_FACTORY) is False


def test_route_deps_carry_auth_is_total_on_a_bad_offset() -> None:
    """Total: an `open_idx` that is out of range, or that lands on anything but a `(` in the view
    (a decorator the blanking turned into spaces), returns False rather than reading some later
    paren pair's list. Here the next pair is a DIFFERENT, authed decorator: walking on from the
    blanked offset would balance on its `)` and credit its list to the commented-out one."""
    block = (
        "# @router.post('/x')\n"
        "@router.post('/y', dependencies=[requires_authenticated()])\n"
        "def y(): ...\n"
    )
    view = blank_line_comments(block)
    assert route_deps_carry_auth(view, block.index("("), PER_ROUTE_AUTH_FACTORY) is False
    # The live decorator itself is still read.
    assert route_deps_carry_auth(view, block.index("(", block.index("\n")), PER_ROUTE_AUTH_FACTORY)
    assert route_deps_carry_auth(view, len(view), PER_ROUTE_AUTH_FACTORY) is False
    assert route_deps_carry_auth(view, -1, PER_ROUTE_AUTH_FACTORY) is False


def test_blank_line_comments_preserves_every_offset() -> None:
    """Length- and offset-preserving even across a non-`\\n` line boundary (`\\x0c`), and a `#`
    inside a string is not a comment."""
    src = "a = '#x'  # gone\n\x0c\n@r.post('/y')  # (stray\n"
    out = blank_line_comments(src)
    assert len(out) == len(src)
    assert out.index("@r.post(") == src.index("@r.post(")
    assert "gone" not in out and "stray" not in out and "'#x'" in out


@pytest.mark.slow
def test_per_route_priv_factory_is_linear_on_a_stem_dense_identifier() -> None:
    """#1041 round 1 (R1-M1): the guard-shaped `PER_ROUTE_PRIV_FACTORY` commits to the FIRST
    privilege stem through an atomic group. Without it, a guard verb followed by a long run of stems
    and no call paren backtracks through every stem: measured 1.5s at 2,000 stems and 22s at 8,000
    (x4 per doubling), against 0.003s and 0.011s with the group. Growth CLASS is the assertion."""
    sizes = [16_000, 32_000, 64_000, 128_000]
    texts = {n: "requires" + "_admin" * n for n in sizes}
    found: dict[int, bool] = {}

    def scan(n: int) -> None:
        found[n] = PER_ROUTE_PRIV_FACTORY.search(texts[n]) is not None

    assert_growth(scan, sizes, expected="linear")
    # No call paren, so no match; and the same identifier closed as a call still matches, so a
    # matcher that stopped matching cannot pass as "fast".
    assert found == dict.fromkeys(sizes, False), found
    assert PER_ROUTE_PRIV_FACTORY.search(texts[sizes[0]] + "()") is not None


# --- FastAPI security-scheme class names as an auth signal --------------------

def test_auth_call_named_accepts_inline_security_scheme_class() -> None:
    # No `_AUTH_NAME` stem is a substring of `HTTPBearer`/`JWTBearer` — confirmed by reading
    # `_AUTH_SEGMENT_STEMS`/`_AUTH_PREFIX_STEMS` directly. Closed with a conservative allowlist of
    # FastAPI's own security-scheme class names, not a stem widening.
    for cls in ("HTTPBearer", "JWTBearer", "OAuth2PasswordBearer", "APIKeyHeader"):
        text = f"router = APIRouter(dependencies=[Depends({cls}())])\n"
        assert same_file_authed_routers(text, auth_call=AUTH_CALL_NAMED) == {"router"}, cls

def test_security_scheme_var_names_finds_module_level_bindings() -> None:
    text = (
        "bearer_scheme = HTTPBearer()\n"
        "api_key_scheme: APIKeyHeader = APIKeyHeader(name='X-API-Key')\n"
        "not_a_scheme = get_db()\n"
    )
    assert security_scheme_var_names(text) == {"bearer_scheme", "api_key_scheme"}

def test_security_scheme_var_names_empty_on_no_bindings() -> None:
    assert security_scheme_var_names("") == frozenset()
    assert security_scheme_var_names("x = 1\n") == frozenset()

def test_auth_call_named_with_aliases_falls_back_when_no_bindings() -> None:
    # No security-scheme variable anywhere in this run -> identical to the shared singleton
    # (no per-run compile needed, the overwhelming common case).
    assert auth_call_named_with_aliases("router = APIRouter()\n") is AUTH_CALL_NAMED

def test_auth_call_named_with_aliases_resolves_module_level_variable() -> None:
    # the 2nd confirmed FN shape: the class is instantiated once, at module level, and
    # referenced by variable name at the Depends() call site.
    text = (
        "bearer_scheme = HTTPBearer()\n"
        "router = APIRouter(dependencies=[Depends(bearer_scheme)])\n"
    )
    auth_call = auth_call_named_with_aliases(text)
    assert same_file_authed_routers(text, auth_call=auth_call) == {"router"}
    # A plain AUTH_CALL_NAMED (no alias resolution) does NOT recognize the bare variable —
    # proves the extension, not the base pattern, is what closes this.
    assert same_file_authed_routers(text, auth_call=AUTH_CALL_NAMED) == set()

def test_auth_call_named_with_aliases_ignores_non_security_scheme_var() -> None:
    # FP-bait: a variable bound to something that is NOT a security-scheme class must not be
    # mistaken for one just because its name sounds plausible.
    text = (
        "bearer_scheme = get_db()\n"
        "router = APIRouter(dependencies=[Depends(bearer_scheme)])\n"
    )
    auth_call = auth_call_named_with_aliases(text)
    assert same_file_authed_routers(text, auth_call=auth_call) == set()


# --- the fix-round review (piv-review-pr): 2 Criticals -------------------------------------

def test_security_scheme_var_names_last_assignment_wins() -> None:
    # Critical 1 shape (b): a name FIRST bound to a security-scheme class, then REBOUND to
    # something else before use, must not still read as an auth scheme -- the whole point of a
    # reassignment is that the old value no longer applies.
    text = "bearer_scheme = HTTPBearer()\nbearer_scheme = get_db()\n"
    assert security_scheme_var_names(text) == frozenset()

def test_security_scheme_var_names_last_assignment_wins_other_direction() -> None:
    # The FP-bait control: rebinding a NON-scheme name TO a scheme class must correctly start
    # counting it -- last-assignment-wins cuts both ways, not just toward exclusion.
    text = "bearer_scheme = get_db()\nbearer_scheme = HTTPBearer()\n"
    assert security_scheme_var_names(text) == {"bearer_scheme"}

def test_security_scheme_var_names_excludes_function_local_binding() -> None:
    # Critical 1 shape (c): a binding inside a function body is local to that function, not a
    # module-level name any `Depends(name)` elsewhere in the file could legitimately mean.
    text = "def f():\n    bearer_scheme = HTTPBearer()\n    return bearer_scheme\n"
    assert security_scheme_var_names(text) == frozenset()

def test_security_scheme_var_names_excludes_auto_error_false() -> None:
    # Critical 2: `auto_error=False` is FastAPI's own idiom for "this scheme does not enforce" --
    # the dependency returns None instead of raising, so the route stays unauthenticated. A
    # variable bound to a non-enforcing scheme must not read as an auth signal.
    #
    # the exclusion moved OUT of security_scheme_var_names itself and into
    # blank_disabled_security_schemes, which every real caller applies to a file's text before
    # this function ever sees it -- so this test now applies that same preprocessing, matching
    # actual usage (websocket_no_auth.py / auth_dependency_not_applied.py / read-time).
    for value in ("False", "None", "0"):
        text = f"bearer_scheme = HTTPBearer(auto_error={value})\n"
        assert security_scheme_var_names(blank_disabled_security_schemes(text)) == frozenset(), value


def test_security_scheme_var_names_excludes_auto_error_false_multiline() -> None:
    # the bug the old bounded-lookahead exclusion could not close -- auto_error on a
    # LATER line than the class's own opening paren. Verified against `main` before this fix:
    # this exact case reads as an auth signal (a false negative on the false-negative check).
    text = "bearer_scheme = HTTPBearer(\n    auto_error=False,\n)\n"
    assert security_scheme_var_names(blank_disabled_security_schemes(text)) == frozenset()


def test_security_scheme_var_names_excludes_auto_error_false_nested_paren() -> None:
    # the OTHER bug shape -- a nested paren (a keyword's own call) appearing BEFORE
    # auto_error on the same line, which the old lookahead's `[^)\n]` class could not see past
    # either (the nested call's own closing `)` ended the lookahead's window early).
    text = 'bearer_scheme = HTTPBearer(scheme_name=str("x"), auto_error=False)\n'
    assert security_scheme_var_names(blank_disabled_security_schemes(text)) == frozenset()

def test_security_scheme_var_names_keeps_enforcing_default() -> None:
    # Control for the test above: omitting auto_error (or an explicit auto_error=True) is the
    # default, enforcing case and must still be recognized.
    assert security_scheme_var_names("bearer_scheme = HTTPBearer()\n") == {"bearer_scheme"}
    assert security_scheme_var_names("bearer_scheme = HTTPBearer(auto_error=True)\n") == {
        "bearer_scheme"
    }

def test_auth_call_named_with_aliases_excludes_auto_error_false_inline() -> None:
    # Critical 2, inline shape: `Depends(HTTPBearer(auto_error=False))` at the call site itself.
    # same relocation as the var-names test above -- blank first, matching real usage.
    auth_call = auth_call_named_with_aliases("")
    assert auth_call.search(blank_disabled_security_schemes("Depends(HTTPBearer(auto_error=False))")) is None
    assert auth_call.search(blank_disabled_security_schemes("Depends(HTTPBearer(auto_error=None))")) is None
    # Control: the enforcing default still fires.
    assert auth_call.search(blank_disabled_security_schemes("Depends(HTTPBearer())")) is not None


def test_auth_call_named_with_aliases_excludes_auto_error_false_inline_multiline() -> None:
    # the exact bypass Dean reproduced -- auto_error on its own line, inside a
    # multi-line Depends(HTTPBearer(...)) call. A bounded single-line lookahead cannot see past
    # the newline; blank_disabled_security_schemes scans the real balanced-paren span instead.
    auth_call = auth_call_named_with_aliases("")
    text = "Depends(HTTPBearer(\n    auto_error=False,\n))"
    assert auth_call.search(blank_disabled_security_schemes(text)) is None


def test_blank_disabled_security_schemes_preserves_offsets() -> None:
    # The blanking must not shift any line/column position -- same length, same newline count,
    # same content everywhere OUTSIDE the blanked span (which starts at the CLASS NAME, not the
    # assignment's own `name = ` prefix); only the disabled call's own characters (never its
    # newlines) become spaces.
    text = "x = 1\nbearer_scheme = HTTPBearer(\n    auto_error=False,\n)\ny = 2\n"
    blanked = blank_disabled_security_schemes(text)
    assert len(blanked) == len(text)
    assert blanked.count("\n") == text.count("\n")
    assert "auto_error" not in blanked
    assert "HTTPBearer" not in blanked
    lines = blanked.splitlines()
    assert lines[0] == "x = 1"
    assert lines[1].startswith("bearer_scheme = ")  # the assignment prefix survives
    assert not lines[1][len("bearer_scheme = ") :].strip()  # only "HTTPBearer(" is blanked
    assert not lines[2].strip()  # "    auto_error=False," is fully inside the blanked span
    assert not lines[3].strip()  # the lone ")" is the call's own closing paren
    assert lines[4] == "y = 2"


def test_blank_disabled_security_schemes_leaves_enforcing_scheme_untouched() -> None:
    # FP-bait: no auto_error at all -- must be byte-identical, not just "still matches".
    text = "bearer_scheme = HTTPBearer()\nother = 1\n"
    assert blank_disabled_security_schemes(text) == text


def test_blank_disabled_security_schemes_unresolvable_call_blanks_the_token_only() -> None:
    # An UNRESOLVABLE span blanks the constructor TOKEN (`HTTPBearer(`) and nothing else. Two
    # separate wrong answers are being ruled out here (#761 re-review):
    #
    #   1. blanking a GUESSED span (the original `len(text)` fallback) erased every later route,
    #      auth signal and inline pragma to EOF, silently;
    #   2. skipping entirely asserts the scheme enforces, because nothing downstream re-examines
    #      it and neither `_TOP_LEVEL_ASSIGN` nor `security_scheme_var_names` knows about
    #      `auto_error` -- so a DISABLED scheme would read as auth and its route would go silent.
    #
    # The apostrophe in the call's own comment desyncs the quote tracking `matching_close_paren`
    # shares with `split_call_args`: neither walker knows `#`, so it opens a string that no later
    # quote balances and the span is unresolvable.
    #
    # #764: that desync alone no longer reaches this arm. A constructor in tokenizable code is
    # resolved on the code view, where comments are blanked, so the same call now resolves. The
    # raw path still runs when the file has no token stream, so the unclosed `legacy_cfg = (` on
    # the last line makes the file untokenizable, and the preconditions below pin that this test is
    # on the raw path, in the walk's Python mode, rather than passing for some other reason.
    #
    # #613: this test used an odd quote inside a triple-quoted description as its trigger. The raw
    # walk now reads that description as one span, so it resolves (see
    # `test_blank_disabled_security_schemes_raw_path_reads_a_triple_quoted_description_as_one_span`).
    text = (
        "required_auth = HTTPBearer(  # the client's bearer token\n"
        '    description="""Bearer token. Press Authorize to continue.""",\n'
        ")\n"
        "\n"
        '@router.post("/admin/wipe")\n'
        "def wipe_everything():\n"
        "    return db.wipe()\n"
        "\n"
        "public_probe = HTTPBearer(auto_error=False)\n"
        "legacy_cfg = (\n"
    )
    assert base_module._python_code_chars(text, strip_python_strings(text), keep_strings=False) is None
    assert matching_close_paren(text, text.index("HTTPBearer(") + len("HTTPBearer"), python=True) is None
    blanked = blank_disabled_security_schemes(text)
    # The token is gone, so the scheme can no longer be mistaken for a proven auth signal.
    assert "required_auth = HTTPBearer(" not in blanked
    # ...and NOTHING past the token is touched. This is the half that the EOF fallback got wrong.
    assert "Authorize to continue" in blanked
    assert "def wipe_everything" in blanked
    assert '@router.post("/admin/wipe")' in blanked
    # The last line is a different, genuinely disabled scheme whose span resolves cleanly, so its
    # whole call is blanked as usual.
    assert "HTTPBearer(auto_error=False)" not in blanked
    assert len(blanked) == len(text) and blanked.count("\n") == text.count("\n")


def test_blank_disabled_security_schemes_still_blanks_when_the_span_resolves() -> None:
    # The direction traded against: making the unresolvable case a no-op must NOT weaken the
    # resolvable one. A disabled scheme whose span DOES resolve still has to disappear, or
    # the own fix is gone.
    text = (
        "optional_auth = HTTPBearer(\n"
        '    description="""Bearer token. Press Authorize to continue.""",\n'
        "    auto_error=False,\n"
        ")\n"
        '@router.post("/admin/wipe")\n'
        "def wipe_everything():\n"
        "    return db.wipe()\n"
    )
    assert matching_close_paren(text, text.index("HTTPBearer(") + len("HTTPBearer")) is not None
    blanked = blank_disabled_security_schemes(text)
    assert "HTTPBearer" not in blanked
    assert "auto_error" not in blanked
    assert len(blanked) == len(text) and blanked.count("\n") == text.count("\n")
    assert "def wipe_everything" in blanked  # only the call is blanked, never past its own span


# #764 FP-bait: an ENFORCING scheme whose span merely MENTIONS the flag. Before #764 the raw-span
# search blanked every one of these, so all three consuming guards fired on an authenticated route.
# The last two have no `auto_error` match at all: a quote inside a comment, or #613's odd quote
# count in a triple-quoted description, left the raw span unresolvable and the token-only arm
# blanked the scheme anyway.
_ENFORCING_SCHEMES_MENTIONING_THE_FLAG = {
    "nested-call-kwarg": "bearer_scheme = HTTPBearer(scheme_name=describe(auto_error=False))\n",
    "string-literal": 'bearer_scheme = HTTPBearer(description="set auto_error=False for optional auth")\n',
    "f-string": 'bearer_scheme = HTTPBearer(description=f"{name}: auto_error=False")\n',
    "comment": "bearer_scheme = HTTPBearer(  # do NOT set auto_error=False here\n)\n",
    "apostrophe-comment": "bearer_scheme = HTTPBearer(  # don't set auto_error=False here\n)\n",
    "613-description": (
        'bearer_scheme = HTTPBearer(\n    description="""Bearer. Press "Authorize to go.""",\n)\n'
    ),
}


@pytest.mark.parametrize(
    "text",
    list(_ENFORCING_SCHEMES_MENTIONING_THE_FLAG.values()),
    ids=list(_ENFORCING_SCHEMES_MENTIONING_THE_FLAG),
)
def test_blank_disabled_security_schemes_ignores_the_flag_outside_its_own_arguments(text: str) -> None:
    assert blank_disabled_security_schemes(text) == text
    assert security_scheme_var_names(blank_disabled_security_schemes(text)) == {"bearer_scheme"}


# #764, the direction traded against (a narrowing, so Rule 1): every genuinely disabled shape must
# still be blanked. The leading-comment and apostrophe-comment rows are the ones the raw-text
# `split_call_args` fix proposed on the issue would have broken: the comment lands in the same
# argument as the kwarg (a silent false negative), or its quote leaves the call unresolvable.
_DISABLED_SCHEMES = {
    "false": "bearer_scheme = HTTPBearer(auto_error=False)\n",
    "none": "bearer_scheme = OAuth2PasswordBearer(tokenUrl='token', auto_error=None)\n",
    "zero": "bearer_scheme = APIKeyHeader(name='X-Key', auto_error=0)\n",
    "spaced": "bearer_scheme = HTTPBearer(auto_error = False)\n",
    "conditional": "bearer_scheme = HTTPBearer(auto_error=False if DEV else True)\n",
    "trailing-comment": "bearer_scheme = HTTPBearer(\n    auto_error=False,  # optional\n)\n",
    "leading-comment": (
        "bearer_scheme = HTTPBearer(\n    # optional auth for the public feed\n    auto_error=False,\n)\n"
    ),
    "apostrophe-comment": "bearer_scheme = HTTPBearer(  # don't require a token\n    auto_error=False)\n",
    "nested-paren-first": 'bearer_scheme = HTTPBearer(scheme_name=str("x"), auto_error=False)\n',
    "613-description": (
        'bearer_scheme = HTTPBearer(description="""Press "Authorize.""", auto_error=False)\n'
    ),
    "crlf": "import os\r\nbearer_scheme = HTTPBearer(\r\n    # optional\r\n    auto_error=False,\r\n)\r\n",
}


@pytest.mark.parametrize(
    "text", list(_DISABLED_SCHEMES.values()), ids=list(_DISABLED_SCHEMES)
)
def test_blank_disabled_security_schemes_still_blanks_every_disabled_shape(text: str) -> None:
    blanked = blank_disabled_security_schemes(text)
    assert "auto_error" not in blanked
    assert security_scheme_var_names(blanked) == frozenset()
    assert len(blanked) == len(text) and blanked.count("\n") == text.count("\n")


def test_blank_disabled_security_schemes_still_blanks_the_inline_depends_shape() -> None:
    # #764 Rule 1, inline shape: the code-view path must reach a constructor nested in `Depends(`.
    auth_call = auth_call_named_with_aliases("")
    text = "def r(creds=Depends(HTTPBearer(\n    # optional\n    auto_error=False,\n))): ...\n"
    assert auth_call.search(blank_disabled_security_schemes(text)) is None
    enforcing = "def r(creds=Depends(HTTPBearer(  # do NOT set auto_error=False\n))): ...\n"
    assert auth_call.search(blank_disabled_security_schemes(enforcing)) is not None


def test_blank_disabled_security_schemes_keeps_the_raw_path_inside_a_docstring() -> None:
    # A constructor that is NOT code (here, an example inside a module docstring) keeps the
    # pre-#764 raw-span search. Skipping it instead would leave `bearer = HTTPBearer(...)` at
    # column 0 for `_TOP_LEVEL_ASSIGN`, which would mint `bearer` as an auth alias from a
    # docstring, a new false negative for any route using a real `bearer` of that name.
    text = '"""Usage:\nbearer = HTTPBearer(auto_error=False)\n"""\n'
    assert security_scheme_var_names(blank_disabled_security_schemes(text)) == frozenset()


def test_python_code_chars_is_index_aligned_with_the_source() -> None:
    # The #764 view must be exactly `len(text)` long, CRLF included, so a position found in it is
    # the same position in `text`; the router views normalise rows and are not index-aligned.
    text = "a = f(x)  # note (\r\nb = g('it''s (')\r\nc = h(\"\"\"x)\"\"\")\r\n"
    view = base_module._python_code_chars(text, strip_python_strings(text), keep_strings=False)
    assert view is not None and len(view) == len(text)
    # Only the six CODE parens survive, at their source indices: the `(` in the comment, in `'s ('`
    # and the `)` inside the triple-quoted string are blanked, and each `\r\n` still counts as 2.
    assert [i for i, c in enumerate(view) if c in "()"] == [5, 7, 25, 35, 43, 52]
    assert "note" not in view and "it" not in view and view.count("\r\n") == 3
    assert base_module._python_code_chars("x = (\n", "x = (\n", keep_strings=False) is None


def test_blank_disabled_security_schemes_raw_path_reads_a_triple_quoted_description_as_one_span() -> None:
    # #613 on the raw path (a file the tokenizer rejects, so there is no code view). The odd quote
    # in the description used to desync the walk, which resynced on the later string's quotes and
    # resolved the DISABLED call to a wrong `)` past `def other():`. The whole range was blanked,
    # so an unrelated function and the user's own pragma vanished from the auth guards' view.
    text = (
        'x = HTTPBearer(description="""ab"cd""", auto_error=False)\n'
        "def other():  # security: allow-unauthenticated-route\n"
        '    y = "literal string with paren) inside"\n'
        "    return foo(bar)\n"
        "def broken(:\n"
    )
    assert base_module._python_code_chars(text, strip_python_strings(text), keep_strings=False) is None
    # Precondition: the default-mode walk resolves past the call, into `def other():`'s body.
    wrong_close = matching_close_paren(text, text.index("("))
    assert wrong_close is not None and wrong_close > text.index("def other")
    blanked = blank_disabled_security_schemes(text)
    assert "auto_error" not in blanked  # the disabled scheme itself is still blanked
    assert "def other():  # security: allow-unauthenticated-route" in blanked
    assert '"literal string with paren) inside"' in blanked
    assert len(blanked) == len(text) and blanked.count("\n") == text.count("\n")


def test_matching_close_paren_triple_quoted_string_resolves_in_python_mode() -> None:
    # #613. The DEFAULT traversal tracks `'`/`"` as single-character delimiters, so `"""` reads as
    # an open-then-close pair plus a third opening quote, and an odd number of embedded quotes
    # strands it in string mode. That stays the default on purpose, because SQL callers depend on
    # it (see the SQL pins below), so the default-mode answer is still None. Python callers pass
    # `python=True`, which reads the tripled quote as one delimiter, and the same call resolves.
    assert matching_close_paren('("""abc""")', 0) == 10  # even count: resolves in both modes
    assert matching_close_paren('("""abc""")', 0, python=True) == 10
    assert matching_close_paren('("""a"b""")', 0) is None  # odd count: default mode desyncs
    assert matching_close_paren('("""a"b""")', 0, python=True) == 10


# --- #473 review §2: the resolver's fail-open holes ---------------------------------------------

def test_cross_file_dual_mount_defeats_protection() -> None:
    # Mounted once with auth and once bare — the bare mount leaves every route reachable.
    files = _mainpy(
        "app.include_router(admin.router, dependencies=[Depends(require_admin)])\n"
        "app.include_router(admin.router, prefix='/public')\n"
    )
    assert cross_file_authed_routers(files) == {}

def test_cross_file_conditional_mount_is_not_protection() -> None:
    files = _mainpy(
        "if settings.ENABLE_AUTH:\n"
        "    app.include_router(admin.router, dependencies=[Depends(require_admin)])\n"
    )
    assert cross_file_authed_routers(files) == {}

def test_cross_file_stem_collision_drops_the_ambiguous_module() -> None:
    # Two product files named admin.py: the stem can't identify which one is mounted.
    body = "router = APIRouter()\n"
    files = [
        (Path("routes/admin.py"), body),
        (Path("v2/admin.py"), body),
        (Path("main.py"), "app.include_router(admin.router, dependencies=[Depends(require_admin)])\n"),
    ]
    assert cross_file_authed_routers(files) == {}

def test_cross_file_commented_out_include_is_not_protection() -> None:
    files = _mainpy(
        "# TODO re-enable auth before launch:\n"
        "# app.include_router(admin.router, dependencies=[Depends(require_admin)])\n"
        "app.include_router(admin.router)\n"
    )
    assert cross_file_authed_routers(files) == {}

def test_cross_file_docstring_include_is_not_protection() -> None:
    files = _mainpy(
        '"""Example wiring:\n'
        "app.include_router(admin.router, dependencies=[Depends(require_admin)])\n"
        '"""\n'
    )
    assert cross_file_authed_routers(files) == {}

def test_same_file_dual_mount_defeats_include_derived_protection() -> None:
    text = (
        "app.include_router(admin_router, dependencies=[Depends(require_admin)])\n"
        "app.include_router(admin_router, prefix='/public')\n"
    )
    assert same_file_authed_routers(text) == set()

def test_same_file_constructor_deps_survive_a_later_bare_include() -> None:
    # Constructor deps are authoritative — FastAPI applies them on EVERY mount, so a later bare
    # include cannot undo them (unlike include-derived auth above).
    text = (
        "router = APIRouter(dependencies=[Depends(require_admin)])\n"
        "app.include_router(router)\n"
    )
    assert same_file_authed_routers(text) == {"router"}

def test_same_file_conditional_construction_is_not_protection() -> None:
    # The constructor half of "protection must be UNCONDITIONAL" (#473 full gate). A router built
    # under a feature flag, with the else-branch rebinding the same name to a bare router, is not
    # protection: with the flag off every route on it is reachable unauthenticated. The include
    # form of exactly this was already closed; the construction form read as protected, and
    # silenced a CRITICAL privileged-field write end to end (see the guard-level test).
    text = (
        "if settings.ENABLE_AUTH:\n"
        "    router = APIRouter(dependencies=[Depends(require_admin)])\n"
        "else:\n"
        "    router = APIRouter()\n"
    )
    assert same_file_authed_routers(text) == set()

def test_same_file_unconditional_construction_still_protects() -> None:
    # THE DIRECTION TRADED AGAINST. The conditional test above is a narrowing, so the ordinary
    # module-level construction — by far the common case — must still authenticate its routes.
    # Without this, "no router is ever protected by its constructor" would pass the test above.
    assert same_file_authed_routers(
        "router = APIRouter(dependencies=[Depends(require_admin)])\n"
    ) == {"router"}

def test_same_file_construction_in_a_factory_or_try_is_still_protection() -> None:
    # The narrowing is scoped to `if`/`else` bodies, not to "indented" or "not at module level".
    # An app-factory function body and a try/except are both unconditional in the sense that
    # matters: the construction that runs is the one carrying the dependency.
    factory = (
        "def create_app():\n"
        "    router = APIRouter(dependencies=[Depends(require_admin)])\n"
        "    return router\n"
    )
    guarded_import = (
        "try:\n"
        "    router = APIRouter(dependencies=[Depends(require_admin)])\n"
        "except ImportError:\n"
        "    pass\n"
    )
    assert same_file_authed_routers(factory) == {"router"}
    assert same_file_authed_routers(guarded_import) == {"router"}

def test_auth_call_privileged_rejects_authentication_only_dependency() -> None:
    # `privileged-field-assignment`'s strictness: logged-in is not privileged.
    files = _mainpy("app.include_router(admin.router, dependencies=[Depends(get_current_user)])\n")
    assert cross_file_authed_routers(files, auth_call=AUTH_CALL_PRIVILEGED) == {}
    assert cross_file_authed_routers(files, auth_call=AUTH_CALL_NAMED) == {"admin": {"router"}}

def test_auth_call_privileged_accepts_a_privilege_check() -> None:
    for dep in ("Depends(require_admin)", "Depends(get_current_admin)", "Security(oauth, scopes=['admin'])"):
        files = _mainpy(f"app.include_router(admin.router, dependencies=[{dep}])\n")
        assert cross_file_authed_routers(files, auth_call=AUTH_CALL_PRIVILEGED) == {"admin": {"router"}}, dep

def test_route_receiver_returns_the_last_dotted_segment() -> None:
    assert route_receiver("@public_router.post('/x')\ndef f(): ...\n") == "public_router"
    assert route_receiver("@api.v1.admin.get('/x')\ndef f(): ...\n") == "admin"
    assert route_receiver("def f(): ...\n") is None

def test_auth_call_privileged_stems_are_boundaried() -> None:
    # `_PRIV_NAME` was a raw alternation, so `scope` matched inside `telescope` and `role` inside
    # `payroll` — `Depends(get_telescope_status)` read as a privilege check and a genuine
    # unauthenticated `user.role = body.role` returned ZERO findings. That is the same
    # substring-bleed class `boundaried_stems` exists to prevent (#307/#345), reappearing inside the
    # fix for it (#473 second-pass review).
    for dep in (
        "Depends(require_admin)", "Depends(get_current_admin)", "Depends(verify_role)",
        "Depends(check_permissions)", "Depends(admin_required)", "Depends(has_scope)",
        "Depends(is_staff)", "Security(oauth, scopes=['admin'])", "AdminReadDep",
        "Depends(require_superuser)",
    ):
        assert AUTH_CALL_PRIVILEGED.search(dep) is not None, dep
    for dep in (
        "Depends(get_telescope_status)", "Depends(get_payroll)", "Depends(get_db)",
        "Depends(get_current_user)", "Depends(get_session)", "DbDep",
    ):
        assert AUTH_CALL_PRIVILEGED.search(dep) is None, dep


def test_rate_limit_call_matches_rate_limit_dependencies_only() -> None:
    # #472: the rate-limit predicate the two rate-limit-absence guards hand the router resolvers.
    for dep in (
        "Depends(RateLimiter(times=5, seconds=60))", "Depends(RedisRateLimiter(times=5))",
        "Depends(rate_limit)", "Depends(deps.check_rate_limit)", "Depends(rate_limiter(10, 60))",
        "Depends(ratelimit, use_cache=False)", "Depends(getRateLimiter())",
    ):
        assert RATE_LIMIT_CALL.search(dep) is not None, dep
    for dep in (
        "Depends(get_current_user)", "Depends(get_db)", "Depends(moderate_limit)",
        "Depends(accurate_limits)", "Depends(rate_limits.get_db)", "Depends(limiter)", "rate_limit",
    ):
        assert RATE_LIMIT_CALL.search(dep) is None, dep


def test_rate_limit_call_reuses_the_router_resolvers() -> None:
    # Nothing in the #473 resolvers is auth-specific, so the rate-limit predicate inherits the
    # dual-mount rule with no change to them.
    rl = "[Depends(RateLimiter(times=5, seconds=60))]"
    files = _mainpy(f"app.include_router(auth.router, dependencies={rl})\n")
    assert cross_file_authed_routers(files, auth_call=RATE_LIMIT_CALL) == {"auth": {"router"}}
    dual = _mainpy(f"app.include_router(auth.router, dependencies={rl})\napp.include_router(auth.router)\n")
    assert cross_file_authed_routers(dual, auth_call=RATE_LIMIT_CALL) == {}
    assert same_file_authed_routers(f"router = APIRouter(dependencies={rl})\n", auth_call=RATE_LIMIT_CALL) == {
        "router"
    }


# --- #472: app-wide rate-limit wiring --------------------------------------------------------------

def _wiring(root: Path, files: dict[str, str]) -> RateLimitWiring:
    pairs = []
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        pairs.append((p, body))
    return rate_limit_wiring(root, pairs)


def test_rate_limit_wiring_scopes_follow_the_top_level_directory(tmp_path: Path) -> None:
    limits = "limiter = Limiter(key_func=k, default_limits=['1/second'])\n"
    mw = "app = FastAPI()\napp.add_middleware(SlowAPIMiddleware)\n"
    assert _wiring(tmp_path / "a", {"main.py": limits + mw}).slowapi_scopes == {""}
    assert _wiring(tmp_path / "b", {"backend/main.py": limits + mw}).slowapi_scopes == {"backend"}
    # The two halves must share a top-level directory.
    split = {"svc_a/limiter.py": limits, "svc_b/main.py": mw}
    assert _wiring(tmp_path / "c", split).slowapi_scopes == frozenset()
    dep = "app = FastAPI(dependencies=[Depends(RateLimiter(times=1, seconds=1))])\n"
    assert _wiring(tmp_path / "d", {"api/main.py": dep}).dependency_scopes == {"api"}


@pytest.mark.parametrize(
    "limiter",
    [
        "Limiter(key_func=k)",
        "Limiter(key_func=k, default_limits=[])",
        "Limiter(key_func=k, default_limits=None, application_limits=())",
        "Limiter(key_func=k, default_limits=['1/s'], enabled=False)",
        "Limiter(key_func=k, default_limits=['1/s'], enabled=settings.ON)",
        "Limiter(key_func=k, default_limits=['1/s'], auto_check=False)",
        "MyLimiter(key_func=k, default_limits=['1/s'])",
    ],
)
def test_rate_limit_wiring_needs_a_limiter_that_enforces_something(tmp_path: Path, limiter: str) -> None:
    main = f"limiter = {limiter}\napp = FastAPI()\napp.add_middleware(SlowAPIMiddleware)\n"
    assert _wiring(tmp_path, {"main.py": main}).slowapi_scopes == frozenset()


def test_rate_limit_wiring_credits_a_limits_expression_it_cannot_resolve(tmp_path: Path) -> None:
    # A settings attribute cannot be resolved statically, and is a configured limit in practice.
    main = (
        "limiter = Limiter(key_func=k, default_limits=settings.LIMITS, enabled=True)\n"
        "app = FastAPI()\napp.add_middleware(SlowAPIMiddleware)\n"
    )
    assert _wiring(tmp_path, {"main.py": main}).slowapi_scopes == {""}


def test_rate_limited_routes_exempt_route_withdraws_the_slowapi_credit(tmp_path: Path) -> None:
    wiring = RateLimitWiring({}, frozenset({""}), frozenset())
    route = tmp_path / "routes" / "auth.py"
    plain = "@router.post('/login')\ndef login(): ...\n"
    assert rate_limited_routes(tmp_path, route, plain, wiring).whole_file is True
    exempt = "@router.post('/health')\n@lim.exempt\ndef health(): ...\n" + plain
    assert rate_limited_routes(tmp_path, route, exempt, wiring).whole_file is False
    # An app-level dependency still covers an exempt route: `exempt` is slowapi-only.
    dep_wiring = RateLimitWiring({}, frozenset(), frozenset({"routes"}))
    assert rate_limited_routes(tmp_path, route, exempt, dep_wiring).whole_file is True


def test_middleware_scope_and_conditional_nodes() -> None:
    root = Path("/repo")
    assert middleware_scope(root, root / "main.py") == ""
    assert middleware_scope(root, root / "backend" / "app" / "main.py") == "backend"
    tree = ast.parse("a()\nif x:\n    b()\nelse:\n    c()\n")
    calls = {n.func.id: id(n) for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    inside = conditional_nodes(tree)
    assert calls["a"] not in inside
    assert calls["b"] in inside and calls["c"] in inside


def _call(src: str) -> ast.Call:
    node = ast.parse(src, mode="eval").body
    assert isinstance(node, ast.Call)
    return node


def test_registered_names_reads_every_registration_form() -> None:
    # Moved from no_cache_on_sensitive.py (#472): its multi-file tests remain the behavioural oracle.
    assert registered_names(_call("app.add_middleware(mw.SecurityHeaders, dispatch=add_no_store)")) == [
        "SecurityHeaders", "add_no_store",
    ]
    assert registered_names(_call("Middleware(GZipMiddleware, minimum_size=500)")) == ["GZipMiddleware"]
    assert registered_names(_call("app.middleware('http')(add_no_store)")) == ["add_no_store"]
    assert registered_names(_call("app.middleware('websocket')(on_socket)")) == []
    assert registered_names(_call("app.include_router(router)")) == []
    assert is_http_middleware(_call("app.middleware(b'http')"))
    assert not is_http_middleware(_call("app.middleware(kind)"))


def test_registered_names_reads_the_keyword_forms_of_the_class_argument() -> None:
    # #1016 review M1: Starlette names the class parameter `middleware_class` on `add_middleware`
    # and `cls` on `Middleware`, so the keyword spelling is the same registration as the
    # positional one. Each keyword counts only on the call that defines it.
    assert registered_names(_call("app.add_middleware(middleware_class=ContentSizeLimitMiddleware)")) == [
        "ContentSizeLimitMiddleware",
    ]
    assert registered_names(_call("Middleware(cls=mw.NoStoreHeaders, max_age=0)")) == ["NoStoreHeaders"]
    assert registered_names(_call("app.add_middleware(cls=ContentSizeLimitMiddleware)")) == []
    assert registered_names(_call("Middleware(middleware_class=ContentSizeLimitMiddleware)")) == []


def test_registered_names_does_not_read_a_bare_constructor_call() -> None:
    # The direction M1 must not trade away: `no-cache-on-sensitive` proves coverage from the body
    # of every name this returns, so reading any `X(...)` call as a registration would let a
    # `NoStoreResponse(content)` (a response class, not a middleware) cover every route. Direct
    # ASGI wrapping is credited only by `registered_middleware_scopes`, against the caller's names.
    assert registered_names(_call("NoStoreResponse(content)")) == []
    assert registered_names(_call("ContentSizeLimitMiddleware(app, max_content_size=1)")) == []


_SIZE_MIDDLEWARE = re.compile(r"ContentSizeLimitMiddleware|MaxBytesMiddleware", re.IGNORECASE)


@pytest.mark.parametrize(
    ("files", "want"),
    [
        ({"main.py": "app.add_middleware(ContentSizeLimitMiddleware, max_content_size=1)\n"}, {""}),
        ({"main.py": "app = make(middleware=[Middleware(MaxBytesMiddleware, max_bytes=1)])\n"}, {""}),
        ({"backend/app/main.py": "app.add_middleware(ContentSizeLimitMiddleware)\n"}, {"backend"}),
        ({"main.py": "# app.add_middleware(ContentSizeLimitMiddleware)\n"}, set()),
        ({"main.py": "from mw import ContentSizeLimitMiddleware\n"}, set()),
        ({"main.py": "class ContentSizeLimitMiddleware:\n    pass\n"}, set()),
        ({"main.py": "if s.LIMIT:\n    app.add_middleware(ContentSizeLimitMiddleware)\n"}, set()),
        ({"main.py": "app.add_middleware(CORSMiddleware)\n"}, set()),
        ({"main.py": "app.add_middleware(ContentSizeLimitMiddleware\n"}, set()),
        (
            {
                "a/main.py": "app.add_middleware(MaxBytesMiddleware)\n",
                "b/main.py": "app.add_middleware(CORSMiddleware)\n",
            },
            {"a"},
        ),
        # #1016 review M1: the keyword spellings and direct ASGI wrapping register too.
        ({"main.py": "app.add_middleware(middleware_class=ContentSizeLimitMiddleware)\n"}, {""}),
        ({"main.py": "app = make(middleware=[Middleware(cls=MaxBytesMiddleware, max_bytes=1)])\n"}, {""}),
        ({"main.py": "app = ContentSizeLimitMiddleware(app, max_content_size=1)\n"}, {""}),
        ({"main.py": "asgi = mw.MaxBytesMiddleware(app=app, max_bytes=1)\n"}, {""}),
        # ...and the directions that trades against: a wrap is proof only unconditionally, around
        # an app, and of a matching middleware.
        ({"main.py": "if s.LIMIT:\n    app = ContentSizeLimitMiddleware(app)\n"}, set()),
        ({"main.py": "mw = ContentSizeLimitMiddleware()\n"}, set()),
        ({"main.py": "mw = ContentSizeLimitMiddleware\n"}, set()),
        ({"main.py": "app = GZipMiddleware(app, minimum_size=500)\n"}, set()),
        # #1016 round-2 M1: a wrap needs a class whose name ENDS in `middleware` (not an exception or
        # config class that merely contains one) and an argument that can denote an app.
        ({"main.py": "raise ContentSizeLimitMiddlewareError('too big')\n"}, set()),
        ({"main.py": "c = ContentSizeLimitMiddlewareConfig(1000)\n"}, set()),
        ({"main.py": "m = ContentSizeLimitMiddleware('x')\n"}, set()),
        ({"main.py": "m = ContentSizeLimitMiddleware(app=None)\n"}, set()),
        ({"main.py": "m = ContentSizeLimitMiddleware(*a)\n"}, set()),
        # ...and the direction that trades against: an app built by a call or read off an object
        # is still an app.
        ({"main.py": "app = ContentSizeLimitMiddleware(create_app(), max_content_size=1)\n"}, {""}),
        ({"main.py": "asgi = ContentSizeLimitMiddleware(server.app)\n"}, {""}),
    ],
    ids=[
        "add-middleware", "middleware-list", "nested-scope", "comment", "import", "class-definition",
        "under-if", "other-name", "unparseable", "per-directory",
        "keyword-middleware-class", "keyword-cls", "asgi-wrap", "asgi-wrap-app-keyword",
        "asgi-wrap-under-if", "constructed-without-app", "bare-reference", "other-name-wrap",
        "exception-class", "config-class", "literal-argument", "none-app-keyword", "starred-argument",
        "call-argument", "attribute-argument",
    ],
)
def test_registered_middleware_scopes(tmp_path: Path, files: dict[str, str], want: set[str]) -> None:
    # #472: the RCA's prototyped table, run against the shared helper.
    sources = [(tmp_path / name, text) for name, text in files.items()]
    assert registered_middleware_scopes(tmp_path, sources, _SIZE_MIDDLEWARE) == want


def test_registered_middleware_scopes_credits_a_wrap_only_when_the_callee_is_named_a_middleware(
    tmp_path: Path,
) -> None:
    # A caller's pattern may be looser than the size guard's exact class names. A direct wrap is
    # credited only when the callee's own name says `middleware`, so `SizeCap(app)` or a helper
    # like `limit(app)` stays no proof whatever the pattern matches.
    loose = re.compile(r"SizeCap|limit", re.IGNORECASE)
    for text in ("# middleware\napp = SizeCap(app)\n", "# middleware\napp = rate_limit(app)\n"):
        assert registered_middleware_scopes(tmp_path, [(tmp_path / "main.py", text)], loose) == set()
    named = "app = SizeCapMiddleware(app)\n"
    assert registered_middleware_scopes(tmp_path, [(tmp_path / "main.py", named)], loose) == {""}


@pytest.mark.parametrize(
    "argument", ["settings", "settings.app", "Settings()"], ids=["variable", "attribute", "call"],
)
def test_registered_middleware_scopes_wrap_around_a_non_app_argument_is_a_known_accepted_gap(
    tmp_path: Path, argument: str
) -> None:
    # KNOWN ACCEPTED GAP (#1016 round-2 review; widened by the round-3 review): an argument cannot be
    # told from an app without type information, so a middleware-named class constructed around a
    # variable, an attribute or a call that is not an app credits the scope. A middleware's first
    # parameter IS the app it wraps, so this shape is a bug in the scanned code rather than an
    # idiom, and a call cannot simply be rejected: `X(create_app())` is a real wrap. Pinned per
    # argument shape so a change to any of them shows up in a test diff.
    files = [(tmp_path / "main.py", f"cfg = ContentSizeLimitMiddleware({argument})\n")]
    assert registered_middleware_scopes(tmp_path, files, _SIZE_MIDDLEWARE) == {""}


@pytest.mark.parametrize(
    "text",
    [
        "async def make():\n    return ContentSizeLimitMiddleware(await build())\n",
        "app = ContentSizeLimitMiddleware(apps['main'])\n",
        "app = ContentSizeLimitMiddleware(primary if ok else fallback)\n",
        "app = ContentSizeLimitMiddlewareV2(app)\n",
        "app = ContentSizeLimitMiddleware(application=app)\n",
    ],
    ids=["await-argument", "subscript-argument", "conditional-argument", "suffixed-class", "other-keyword"],
)
def test_registered_middleware_scopes_rare_wrap_shapes_fail_closed(tmp_path: Path, text: str) -> None:
    # ACCEPTED FAIL-CLOSED TRADE-OFF (#1016 round-3 review L2): the wrap credit reads only a class
    # name ending in `middleware` and an app argument that is a name, attribute or call. These rare
    # real wraps therefore get no credit and the route fires, the safe direction. Pinned so a later
    # widening of the wrap rule shows up in a test diff.
    assert registered_middleware_scopes(tmp_path, [(tmp_path / "main.py", text)], _SIZE_MIDDLEWARE) == set()


def test_add_middleware_credits_the_class_a_rare_wrap_shape_does_not(tmp_path: Path) -> None:
    # The mitigation the wiki gives for the shapes above: the `add_middleware` spelling of the same
    # class still credits, because `registered_names` applies no end-of-name rule.
    files = [(tmp_path / "main.py", "app.add_middleware(ContentSizeLimitMiddlewareV2)\n")]
    assert registered_middleware_scopes(tmp_path, files, _SIZE_MIDDLEWARE) == {""}


# --- #473 review (B6): the router argument passed by KEYWORD -------------------------------------

def test_include_router_keyword_form_binds_the_value_not_the_keyword() -> None:
    # `include_router(router=admin_router, ...)` is ordinary Python, and FastAPI's first parameter
    # is literally named `router`. The ref capture took the KEYWORD NAME, so this mount was recorded
    # against a router called `router` (the most common name for one) instead of `admin_router`.
    #
    # Both directions of that are wrong: the unauthed `router`'s routes were suppressed (a false
    # NEGATIVE on route auth), and the genuinely-authed `admin_router` went unrecorded.
    text = (
        "router = APIRouter()\n"
        "admin_router = APIRouter()\n"
        "app.include_router(router=admin_router, dependencies=[Depends(get_current_admin)])\n"
    )
    assert same_file_authed_routers(text) == {"admin_router"}

def test_include_router_keyword_form_resolves_cross_file_too() -> None:
    files = _mainpy(
        "from routes import admin\n"
        "app.include_router(router=admin.router, dependencies=[Depends(get_current_admin)])\n"
    )
    assert cross_file_authed_routers(files) == {"admin": {"router"}}

def test_include_router_positional_form_is_unchanged() -> None:
    # The other direction (F4): consuming an optional `router=` must not disturb the positional
    # form, which is the overwhelmingly common spelling.
    text = "app.include_router(admin_router, dependencies=[Depends(get_current_admin)])\n"
    assert same_file_authed_routers(text) == {"admin_router"}
    files = _mainpy("app.include_router(admin.router, dependencies=[Depends(x)])\n")
    assert cross_file_authed_routers(files) == {"admin": {"router"}}

def test_include_router_named_router_is_still_authed_when_it_really_is() -> None:
    # ...and a router genuinely called `router`, mounted by keyword, is still recognized. The fix
    # must not swing to never trusting the name.
    text = "router = APIRouter()\napp.include_router(router=router, dependencies=[Depends(x)])\n"
    assert same_file_authed_routers(text) == {"router"}

def test_include_router_resolves_the_ref_whatever_the_argument_order() -> None:
    # THIS TEST PREVIOUSLY ASSERTED THE OPPOSITE, and it was wrong. It pinned "a leading non-router
    # keyword records NOTHING" on the reasoning that recording no ref is a miss while recording the
    # wrong ref is a suppression, so only the latter hides a finding.
    #
    # That reasoning is true in isolation and FALSE in composition (#473 agentic gate): the
    # dual-mount defense has to SEE a bare mount in order to flip protection off, so an invisible
    # mount IS a suppression. See `test_dual_mount_defeats_protection_whatever_the_argument_order`.
    #
    # The resolver now parses the argument list instead of pattern-matching a prefix, so every
    # spelling resolves to the same ref.
    for src in (
        "app.include_router(r, dependencies=[Depends(x)])\n",
        "app.include_router(router=r, dependencies=[Depends(x)])\n",
        "app.include_router(prefix='/x', router=r, dependencies=[Depends(x)])\n",
        "app.include_router(tags=['a'], router=r, prefix='/x', dependencies=[Depends(x)])\n",
    ):
        assert same_file_authed_routers(src) == {"r"}, src

def test_dual_mount_defeats_protection_whatever_the_argument_order() -> None:
    # The CRITICAL this replaced the old assertion for: an authed mount plus a BARE second mount of
    # the same router must leave it unprotected. Before the resolver rewrite the bare mount was
    # invisible whenever its first argument was a keyword other than `router=`, so the authed mount
    # stood unchallenged and every route on that router went unreported.
    authed = "app.include_router(router=v.router, dependencies=[Depends(a)])\n"
    for bare in (
        "app.include_router(v.router)\n",
        "app.include_router(router=v.router, prefix='/l')\n",
        "app.include_router(prefix='/l', router=v.router)\n",
        "app.include_router(tags=['x'], router=v.router)\n",
    ):
        assert cross_file_authed_routers(_mainpy(authed + bare)) == {}, bare
    # ...and with no bare mount at all it IS protected, including on a reordered spelling.
    assert cross_file_authed_routers(
        _mainpy("app.include_router(prefix='/x', router=v.router, dependencies=[Depends(a)])\n")
    ) == {"v": {"router"}}


def test_split_call_args_quoted_close_paren_does_not_truncate() -> None:
    # #548 round-3 review, High 1: a `)` inside a string-literal argument used to be read as the
    # call's own closing paren, silently dropping everything after it — the exact regression class
    # `log_injection.py::_first_call_arg` was already written to fix once (#395 RM-2), on this same
    # helper, for the same reason. Repro is Dean's own from the review.
    line = "if (redirectUrl.includes('note)' + 'trusted.com')) { fetch(redirectUrl); }"
    open_idx = line.index("includes(") + len("includes")
    args = split_call_args(line, open_idx)
    assert args == ["'note)' + 'trusted.com'"]
    assert "trusted.com" in ",".join(args)


def test_split_call_args_quoted_comma_does_not_split_early() -> None:
    args = split_call_args("f('a, b', c)", 1)
    assert args == ["'a, b'", " c"]


def test_split_call_args_escaped_quote_inside_string_does_not_close_it() -> None:
    args = split_call_args(r"f('it\'s), still one arg', c)", 1)
    assert args == [r"'it\'s), still one arg'", " c"]


def test_split_call_args_double_quoted_paren_does_not_truncate() -> None:
    args = split_call_args('f("a)b", c)', 1)
    assert args == ['"a)b"', " c"]


def test_split_call_args_simple_multi_arg_unaffected() -> None:
    # Pre-existing behavior, unchanged by the quote-awareness fix.
    assert split_call_args("f(a, b, c)", 1) == ["a", " b", " c"]


def test_split_call_args_nested_call_unaffected() -> None:
    # Pre-existing behavior, unchanged by the quote-awareness fix — a nested call's own commas
    # and parens still don't leak into the top-level split.
    assert split_call_args("f(g(a, b), c)", 1) == ["g(a, b)", " c"]


def test_split_call_args_unbalanced_still_returns_none() -> None:
    assert split_call_args("f('unterminated", 1) is None


# ---------------------------------------------------------------------------
# matching_close_paren — (position-only sibling of split_call_args)
#

def test_matching_close_paren_simple() -> None:
    text = "f(a, b)"
    assert matching_close_paren(text, 1) == text.index(")")


def test_matching_close_paren_nested() -> None:
    text = "f(g(a, b), c)"
    assert matching_close_paren(text, 1) == len(text) - 1


def test_matching_close_paren_multiline() -> None:
    text = "f(\n    a,\n    b,\n)"
    assert matching_close_paren(text, 1) == len(text) - 1


def test_matching_close_paren_quoted_close_paren_does_not_truncate() -> None:
    line = "f('note)' + 'trusted.com')"
    assert matching_close_paren(line, 1) == len(line) - 1


def test_matching_close_paren_escaped_quote_does_not_close_string() -> None:
    text = r"f('it\'s still one arg')"
    assert matching_close_paren(text, 1) == len(text) - 1


def test_matching_close_paren_unbalanced_returns_none() -> None:
    assert matching_close_paren("f('unterminated", 1) is None


# ---------------------------------------------------------------------------
# close_paren_map — PR #1093 round 2 (one-pass sibling of matching_close_paren)
#

def test_close_paren_map_agrees_with_matching_close_paren_on_code_parens() -> None:
    text = "a = f(g(x, 'note)'), h(\n    r'it\\'s', y,\n))\nk(z)\n"
    pairs = close_paren_map(text)
    opens = [i for i, ch in enumerate(text) if ch == "("]  # none of them is inside a string
    assert len(opens) == 4 and all(pairs.get(i) == matching_close_paren(text, i) for i in opens)


def test_close_paren_map_skips_strings_unclosed_calls_and_stray_quotes() -> None:
    text = "log('call(') ; f(\n" + "x = 'unterminated (\n" + "g(1)\n"
    pairs = close_paren_map(text)
    # a `(` inside a string literal is not a call
    assert text.index("call(") + 4 not in pairs
    # the outer f( never closes, so it has no entry (the never-guess contract) ...
    assert text.index("f(") + 1 not in pairs
    # ... and a stray quote poisons only its own line: g(1) on the next line still pairs
    assert pairs[text.index("\ng(") + 2] == text.index("\ng(1)") + 4


def test_close_paren_map_pairs_across_a_blanked_multiline_triple_quoted_argument() -> None:
    # PR #1093 round-3 H1: strip_python_strings blanks a triple-quoted string's CONTENT but keeps
    # its `"""` delimiters, so the closing line starts with an odd count of quote characters. Read
    # as three single-quote toggles, the line stayed "inside a string" and swallowed its `)`, so the
    # enclosing call went unpaired. A run of three identical quotes is a delimiter, not a toggle.
    src = 'x = foo("""\ntext (with a paren\n""", bar(1))\nk(z)\n' + "y = g('''\nz\n''')\n"
    text = strip_python_strings(src)
    pairs = close_paren_map(text)
    foo, bar = text.index("foo(") + 3, text.index("bar(") + 3
    assert pairs[foo] == text.index("bar(1))") + 6
    assert pairs[bar] == text.index("bar(1))") + 5
    assert pairs[text.index("k(z)") + 1] == text.index("k(z)") + 3
    assert pairs[text.index("g(") + 1] == text.rindex(")")


@pytest.mark.slow
def test_close_paren_map_is_linear_on_unclosed_calls() -> None:
    # The reason it exists: N unclosed calls each walked to EOF by matching_close_paren is O(N^2).
    sizes = (2000, 4000, 8000, 16000)
    texts = {n: "requests.post(\n" * n + "f(x)\n" for n in sizes}
    out: dict[int, dict[int, int]] = {}

    def scan(n: int) -> None:
        out[n] = close_paren_map(texts[n])

    assert_growth(scan, sizes, expected="linear")
    for n in sizes:
        assert out[n] == {len(texts[n]) - 4: len(texts[n]) - 2}  # only the closed f(x)


# ---------------------------------------------------------------------------
# #613: `python=True` on both walkers reads a tripled quote as ONE delimiter
#
# (text, its split in Python mode). The default mode gets every one of these wrong: it truncates
# at a `)` inside the literal, or it is still "inside a string" at the end and returns None.
_PY_TRIPLE_QUOTED_CALLS = {
    "issue-repro": ("f('''it's a note) val''', c)", ["'''it's a note) val'''", " c"]),
    "odd-dquote": ('f("""a"b""")', ['"""a"b"""']),
    "multi-line": ("f('''line one\nit's two\n''', x)", ["'''line one\nit's two\n'''", " x"]),
    "fstring-field": ("f(f'''{d[\"it's\"]}''')", ["f'''{d[\"it's\"]}'''"]),
    "raw-and-bytes-prefix": ("f(r'''a\\'b''', rb\"\"\"x\"y\"\"\")", ["r'''a\\'b'''", ' rb"""x"y"""']),
    "empty-beside-triple": ("f('', '''it's''', \"\")", ["''", " '''it's'''", ' ""']),
}

# (text, its split in the DEFAULT mode, today). SQL callers pass literal-intact text, where `''''`
# is a one-quote literal and `'it''s'` doubles its quote. The per-character toggle balances those,
# and these pins hold the default mode to it.
_SQL_DEFAULT_MODE_PINS = {
    "quote-literal": ("f('''', b)", ["''''", " b"]),
    "doubled-quote": ("f('it''s', b)", ["'it''s'", " b"]),
    "trailing-doubled": ("f('a''', b)", ["'a'''", " b"]),
    "tripled-sql": ("f('''x''', b)", ["'''x'''", " b"]),
    "dquote-literal": ('f("""", b)', ['""""', " b"]),
    "trailing-dquote": ('f("a""", b)', ['"a"""', " b"]),
}


@pytest.mark.parametrize(
    ("text", "expected"), list(_PY_TRIPLE_QUOTED_CALLS.values()), ids=list(_PY_TRIPLE_QUOTED_CALLS)
)
def test_split_call_args_python_mode_reads_a_triple_quoted_argument_as_one_span(
    text: str, expected: list[str]
) -> None:
    assert split_call_args(text, 1, python=True) == expected
    assert matching_close_paren(text, 1, python=True) == len(text) - 1
    # Load-bearing: the default mode gets the same call wrong, so the flag is what fixes it.
    assert split_call_args(text, 1) != expected


@pytest.mark.parametrize(
    ("text", "expected"), list(_SQL_DEFAULT_MODE_PINS.values()), ids=list(_SQL_DEFAULT_MODE_PINS)
)
def test_split_call_args_default_mode_is_unchanged_on_sql_quote_doubling(
    text: str, expected: list[str]
) -> None:
    assert split_call_args(text, 1) == expected
    assert matching_close_paren(text, 1) == len(text) - 1


def test_split_call_args_python_mode_is_wrong_for_sql_so_it_stays_opt_in() -> None:
    # Why `python` is a flag and not the new default: Python's reading of `''''` opens a
    # triple-quoted string that never closes, while SQL reads it as one quote character.
    assert split_call_args("f('''', b)", 1, python=True) is None
    assert matching_close_paren("f('''', b)", 1, python=True) is None


def test_matching_close_paren_python_mode_does_not_resync_past_the_call() -> None:
    # The issue comment's wrong-index case: the default walk desyncs on `"""ab"cd"""`, resyncs on
    # the later string's quotes and reports a `)` inside that string, far past the call's end.
    # A caller can guard against None but not against a plausible wrong integer.
    text = (
        'x = HTTPBearer(description="""ab"cd""", auto_error=False)\n'
        "def other():\n"
        '    y = "literal string with paren) inside"\n'
        "    return foo(bar)\n"
    )
    open_idx = text.index("(")
    assert matching_close_paren(text, open_idx) == 105  # the default mode's wrong answer
    assert matching_close_paren(text, open_idx, python=True) == text.index(")\n") == 56


_WALKER_MIRROR_CASES = [
    *(t for t, _ in _PY_TRIPLE_QUOTED_CALLS.values()),
    *(t for t, _ in _SQL_DEFAULT_MODE_PINS.values()),
    "f(a, g(b, c), 'x)', \"y,\")",
    "f(r'''a\\'''' , b)",
    "f('unterminated",
]


def _assert_walkers_agree(text: str, python: bool) -> None:
    args = split_call_args(text, 1, python=python)
    close = matching_close_paren(text, 1, python=python)
    if args is None:
        assert close is None, (text, python, close)
    else:
        # Everything between the parens is the arguments plus their top-level commas, so the
        # close index is implied by the split exactly.
        assert close is not None and text[2:close] == ",".join(args), (text, python, args, close)


@pytest.mark.parametrize("python", [False, True])
@pytest.mark.parametrize("text", _WALKER_MIRROR_CASES)
def test_split_call_args_and_matching_close_paren_agree(text: str, python: bool) -> None:
    # Both docstrings say the walkers mirror each other; #613 showed how easily that drifts, so it
    # is asserted here rather than promised.
    _assert_walkers_agree(text, python)


def test_split_call_args_and_matching_close_paren_agree_on_random_quote_soup() -> None:
    # The same contract over seeded random text built from every character either walker reacts
    # to, so a future edit to one walker's quote handling cannot pass on the curated cases alone.
    rng = random.Random(613)
    alphabet = "'\"\\(),a #\n"
    for _ in range(4000):
        text = "f(" + "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 14)))
        for python in (False, True):
            _assert_walkers_agree(text, python)


# ---------------------------------------------------------------------------
# join_dockerfile_continuations — #697
#
# The joiner emits one blank line per folded continuation to keep line numbers stable, which is
# what manufactures the blank-line runs the `^\s*` anchor class re-scans. Separately from that,
# the joiner's OWN accumulation was quadratic: the previous `cur = cur.rstrip()[:-1] + " " + next`
# rebuilt the whole logical line on every fold, so cost grew with folds x line length. Measured
# before the fix, at 8,000 continuations: 0.0057s on 2-char lines (the shape the #696 regression
# test happened to use, which is why it read as linear there), 0.038s on ordinary 20-char lines,
# and 0.32s on 60-char lines. It is regex-independent, so it hit every caller, including the two
# that split per line and have no vulnerable pattern at all.
#
# The rewrite is only worth having if it is byte-identical, so the sweep below is the real test
# and the reference implementation is kept verbatim to compare against. A naive rewrite failed it
# on 938 of 4,000 inputs, in both of the ways `_reference_join` shows: the trailing `\` on the
# file's last line survives, and the `#` guard re-reads the accumulated string.
# ---------------------------------------------------------------------------


def _reference_join(text: str) -> str:
    """The pre-#697 implementation, verbatim. Slow but definitionally correct."""
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        cur = lines[i]
        blanks = 0
        while (
            cur.rstrip().endswith("\\")
            and not cur.lstrip().startswith("#")
            and i + 1 < len(lines)
        ):
            cur = cur.rstrip()[:-1] + " " + lines[i + 1]
            i += 1
            blanks += 1
        out.append(cur)
        out.extend([""] * blanks)
        i += 1
    return "\n".join(out)


# Deliberately includes the shapes the naive rewrite got wrong: a bare `\`, a whitespace-only
# line carrying a `\`, a comment line carrying a `\`, and an indented comment.
_JOIN_ATOMS = (
    "FROM alpine", "RUN apt-get update \\", "  && echo hi \\", "  && true", "# a comment \\",
    "USER root", "", "   ", "COPY . /app \\", "ARG X=1", "\tRUN x \\", "LABEL a=b",
    "RUN one \\", "trailing \\", "\\", " \\", "#\\", "  # indented comment \\", "a\\\\", "\t\\",
)


def test_join_dockerfile_continuations_matches_reference_implementation() -> None:
    """Exhaustive-ish equivalence sweep against the pre-#697 implementation.

    Seeded, so a failure is reproducible rather than a flake."""
    rng = random.Random(20260823)
    for _ in range(20000):
        text = "\n".join(rng.choice(_JOIN_ATOMS) for _ in range(rng.randint(1, 16)))
        if rng.random() < 0.5:
            text += "\n"
        assert join_dockerfile_continuations(text) == _reference_join(text), repr(text)


def test_join_dockerfile_continuations_keeps_trailing_backslash_on_last_line() -> None:
    """A `\\` on the file's LAST line is not a continuation (nothing follows it to join), and the
    old loop left it in place because its `i + 1 < len(lines)` guard failed before the strip.
    The eager-strip rewrite silently ate it."""
    assert join_dockerfile_continuations("RUN x \\") == "RUN x \\"
    assert join_dockerfile_continuations("FROM a\nRUN x \\") == "FROM a\nRUN x \\"


def test_join_dockerfile_continuations_comment_guard_reads_the_folded_line() -> None:
    """The `#` guard tests the ACCUMULATED string, not the first physical line, and a fold can
    change the answer: a whitespace-only line ending in `\\` folds the following comment line in,
    after which the accumulation starts with `#` and folding must stop."""
    text = "   \\\n# c \\\nx\n"
    assert join_dockerfile_continuations(text) == _reference_join(text)
    # ...and the `x` line is NOT absorbed, because the fold stopped at the comment.
    assert join_dockerfile_continuations(text).splitlines()[-1] == "x"


def test_join_dockerfile_continuations_still_folds_an_ordinary_multiline_run() -> None:
    """Rule 1, the direction traded against: the fold itself still works, and line numbers are
    still preserved by the blank-line padding."""
    out = join_dockerfile_continuations("FROM alpine\nRUN apt-get update \\\n  && sudo x\nUSER me\n")
    lines = out.split("\n")
    # 4 spaces: the one before the `\` survives rstrip(), plus the joiner's own, plus the
    # continuation line's 2-space indent.
    assert lines[1] == "RUN apt-get update    && sudo x"  # folded onto its original line
    assert lines[2] == ""  # consumed continuation replaced by a blank, so...
    assert lines[3] == "USER me"  # ...USER is still on physical line 4.


@pytest.mark.slow
def test_join_dockerfile_continuations_is_linear_in_continuation_count() -> None:
    """Growth class, not wall clock, because the constant is machine-dependent but the exponent
    is not. Uses ORDINARY 20-char continuation lines: the 2-char line the #696 regression test
    used keeps the joined line short enough to mask this entirely."""
    def build(n: int) -> str:
        body = "".join(f"  && echo step{i} \\\n" for i in range(n))
        return "RUN apt-get update \\\n" + body + "  && true\n"

    # Four sizes, not three: `classify`'s median only discards an outlier from THREE ratios up
    # (at two it is their mean, which is #758). The fourth size extends the TOP, where this
    # workload is cheap enough that the extra step costs single-digit milliseconds.
    texts = {n: build(n) for n in (500, 2000, 8000, 32000)}
    joined: dict[int, str] = {}

    def scan(n: int) -> None:
        joined[n] = join_dockerfile_continuations(texts[n])

    assert_growth(scan, [500, 2000, 8000, 32000], expected="linear")
    # A joiner that stopped folding would also be fast, so assert it still did the work.
    for n in texts:
        assert f"&& echo step{n - 1}" in joined[n].split("\n")[0]


@pytest.mark.slow
def test_join_dockerfile_continuations_is_linear_on_whitespace_only_continuations() -> None:
    """The husk path, which the ordinary-continuation growth test above does NOT reach.

    A line that is only indentation plus `\\` strips down to a whitespace-only "husk" part that the
    fold never removes, so husks accumulate (1,001 of them on 1,000 such lines). That is exactly the
    input that makes the backward scan in the fold walk far, so it is the shape a naive reading of
    the loop would expect to be quadratic. It is not, for the reason the comment on that scan gives,
    and this pins it. Found by the #702 review, which showed the original comment's "at most one
    husk" claim was false even though its linear conclusion held."""
    def build(n: int) -> str:
        return "  \\\n" * n + "\necho done\n"

    # Four sizes, not three: `classify`'s median only discards an outlier from THREE ratios up
    # (at two it is their mean, which is #758). The fourth size extends the TOP, where this
    # workload is cheap enough that the extra step costs single-digit milliseconds.
    texts = {n: build(n) for n in (1000, 4000, 16000, 64000)}
    joined: dict[int, str] = {}

    def scan(n: int) -> None:
        joined[n] = join_dockerfile_continuations(texts[n])

    assert_growth(scan, [1000, 4000, 16000, 64000], expected="linear")
    # ...and it still produced the same thing the reference implementation would.
    #
    # Every size EXCEPT the largest. `_reference_join` is the pre-#697 implementation and is itself
    # quadratic (measured: 248ms at n=16000, 3.9s at n=64000), so comparing at the top size would
    # spend ~4s of the slow tier — an order of magnitude more than the thing under test — to re-check
    # a property that does not vary with n. The growth assertion above needs the top size; this
    # equivalence assertion does not, and the byte-identical guarantee is pinned separately at small
    # n by `test_join_dockerfile_continuations_husks_do_not_change_the_output`.
    for n in sorted(texts)[:-1]:
        assert joined[n] == _reference_join(texts[n])


def test_join_dockerfile_continuations_husks_do_not_change_the_output() -> None:
    """The husk mechanic is an implementation detail of the fold; the folded text must be
    byte-identical to the previous implementation's regardless of how many husks piled up."""
    for n in (1, 2, 5, 50):
        text = "  \\\n" * n + "\necho done\n"
        assert join_dockerfile_continuations(text) == _reference_join(text), n


# --- python_scan_dirs / go_scan_dirs overlap dedup (#701) -------------------------------------
# `python_dirs`/`go_dirs` can resolve to BOTH a directory and one of its own subdirectories (root
# "." plus a specific subdir, e.g. detected because both hold recognizable source). `iter_files`
# recurses, so scanning both means every file under the subdirectory is scanned twice — and any
# guard using `for d in python_scan_dirs(...): for f in iter_files(d, ...)` (the majority) then
# emits a duplicate Finding for every match in the overlap. Caught live via agentsec's own
# self-audit: `llm-json-output-unvalidated` fired twice on one line once `guards/` was itself one
# of the overlapping dirs.

def test_python_scan_dirs_drops_root_when_subdir_also_present(tmp_path: Path) -> None:
    (tmp_path / "guards").mkdir()
    (tmp_path / "guards" / "x.py").write_text("x = 1\n", encoding="utf-8")
    prof = StackProfile(root=tmp_path, python_dirs=[".", "guards"])
    dirs = python_scan_dirs(tmp_path, prof)
    # Root recursively covers "guards" already -- only root should survive.
    assert dirs == [tmp_path]


def test_python_scan_dirs_drops_subdir_when_root_also_present_regardless_of_order(
    tmp_path: Path,
) -> None:
    (tmp_path / "guards").mkdir()
    prof = StackProfile(root=tmp_path, python_dirs=["guards", "."])
    dirs = python_scan_dirs(tmp_path, prof)
    assert dirs == [tmp_path]


def test_python_scan_dirs_keeps_sibling_dirs_unrelated_to_each_other(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "lib").mkdir()
    prof = StackProfile(root=tmp_path, python_dirs=["app", "lib"])
    dirs = python_scan_dirs(tmp_path, prof)
    assert sorted(dirs) == sorted([tmp_path / "app", tmp_path / "lib"])


def test_python_scan_dirs_keeps_nonoverlapping_dirs_when_no_root_present(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "sub").mkdir()
    (tmp_path / "lib").mkdir()
    # "app/sub" is a real subdirectory of "app" -- also gets deduped, same as the root case.
    prof = StackProfile(root=tmp_path, python_dirs=["app", "app/sub", "lib"])
    dirs = python_scan_dirs(tmp_path, prof)
    assert sorted(dirs) == sorted([tmp_path / "app", tmp_path / "lib"])


# --- bounded reads: file_contains_bytes / iter_lines_bounded (#443) ------------------------------
# The two helpers a guard with an UNFILTERED walk uses so a multi-GB committed binary costs one
# chunk of memory. `iter_lines_bounded` must number lines exactly as `read(p).splitlines()` does,
# because the guard switches between the two by file size and a finding's line must not move.


def test_file_contains_bytes_finds_needle_straddling_every_chunk_boundary(tmp_path: Path) -> None:
    p = tmp_path / "blob.bin"
    needle = b"-----BEGIN"
    for offset in range(len(needle) + 2):
        # With 16-byte chunks, the needle starts `offset` bytes before the first boundary.
        p.write_bytes(b"\x00" * (16 - offset) + needle + b"\xff" * 40)
        assert base_module.file_contains_bytes(p, needle, chunk_bytes=16)


def test_file_contains_bytes_edges(tmp_path: Path) -> None:
    p = tmp_path / "blob.bin"
    p.write_bytes(b"\x00" * 100 + b"-----BEGIN")  # needle ends at the very last byte
    assert base_module.file_contains_bytes(p, b"-----BEGIN", chunk_bytes=7)
    p.write_bytes(b"-----BEGI" + b"\x00" * 100)  # a prefix of the needle is not the needle
    assert not base_module.file_contains_bytes(p, b"-----BEGIN", chunk_bytes=7)
    p.write_bytes(b"")
    assert not base_module.file_contains_bytes(p, b"-----BEGIN")
    assert not base_module.file_contains_bytes(tmp_path / "missing", b"-----BEGIN")  # OSError path
    p.write_bytes(b"a")
    assert base_module.file_contains_bytes(p, b"a", chunk_bytes=1)  # 1-byte needle, no overlap
    with pytest.raises(ValueError):
        base_module.file_contains_bytes(p, b"")


def test_read_bytes_prefix_reports_whether_more_bytes_exist(tmp_path: Path) -> None:
    p = tmp_path / "blob.bin"
    p.write_bytes(b"abcdef")
    assert base_module.read_bytes_prefix(p, 6) == (b"abcdef", False)  # exactly the cap: not more
    assert base_module.read_bytes_prefix(p, 4) == (b"abcd", True)
    assert base_module.read_bytes_prefix(p, 100) == (b"abcdef", False)
    with pytest.raises(OSError):
        base_module.read_bytes_prefix(tmp_path / "missing", 4)


def test_zip_member_prefix_streams_only_the_cap(tmp_path: Path) -> None:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("stored", b"x" * 10, compress_type=zipfile.ZIP_STORED)
        zf.writestr("deflated", b"y" * 100_000, compress_type=zipfile.ZIP_DEFLATED)
        zf.writestr("bz2", b"z" * 10, compress_type=zipfile.ZIP_BZIP2)
    with zipfile.ZipFile(buf) as zf:
        assert base_module.zip_member_prefix(zf, "stored", 10) == (b"x" * 10, False)
        assert base_module.zip_member_prefix(zf, "deflated", 16) == (b"y" * 16, True)
        # A method whose inflate cannot be bounded is reported as NOT read, never as clean.
        assert base_module.zip_member_prefix(zf, "bz2", 100) == (b"", True)


def test_zip_central_directory_size_reads_the_tail_record(tmp_path: Path) -> None:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a/data.pkl", b"x")
        zf.writestr("a/version", b"3")
    p = tmp_path / "m.pt"
    p.write_bytes(buf.getvalue())
    with zipfile.ZipFile(p) as zf:
        expected = sum(46 + len(i.filename) + len(i.extra) + len(i.comment) for i in zf.infolist())
    assert base_module.zip_central_directory_size(p) == expected
    # (zip64 end records: test_zip_central_directory_size_prefers_the_zip64_record)
    p.write_bytes(b"not a zip at all")
    assert base_module.zip_central_directory_size(p) is None


def _with_zip64_end_records(zipped: bytes, plain_directory_size: int) -> bytes:
    """Rewrite a small zip's tail as zipfile reads a zip64 archive: a zip64 end-of-central-
    directory record and locator before the classic record, whose own size field is set to
    `plain_directory_size`. zipfile takes the directory size from the zip64 record whenever the
    locator is present, and ignores the classic field. (Python's own force_zip64 writes no zip64
    end record, so it cannot exercise this.)"""
    import struct

    entries, size, offset = struct.unpack("<HII", zipped[-12:-2])
    record_at = len(zipped) - 22
    record = b"PK\x06\x06" + struct.pack("<QHHIIQQQQ", 44, 45, 45, 0, 0, entries, entries, size, offset)
    locator = b"PK\x06\x07" + struct.pack("<IQI", 0, record_at, 1)
    classic = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, entries, entries, plain_directory_size, offset, 0)
    return zipped[:-22] + record + locator + classic


def test_zip_central_directory_size_prefers_the_zip64_record(tmp_path: Path) -> None:
    """Re-review round 2, H4: the zip64 record was followed only when the classic size field was
    0xFFFFFFFF, but zipfile uses it whenever the locator is present. A file whose classic field
    says 46 while its zip64 record declares a 37 MB directory passed the budget."""
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a/data.pkl", b"x")
        zf.writestr("a/version", b"3")
    plain = buf.getvalue()
    real = int.from_bytes(plain[-10:-6], "little")
    p = tmp_path / "m.pt"
    for classic in (46, 0xFFFFFFFF, real):  # a lie, the genuine zip64 marker, the truth
        p.write_bytes(_with_zip64_end_records(plain, classic))
        with zipfile.ZipFile(p) as zf:  # zipfile itself accepts the file and reads every entry
            assert [i.filename for i in zf.infolist()] == ["a/data.pkl", "a/version"]
        assert base_module.zip_central_directory_size(p) == real


_LFS_POINTER = (
    b"version https://git-lfs.github.com/spec/v1\n"
    b"oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n"
    b"size 12345\n"
)


def test_is_git_lfs_pointer_accepts_only_a_whole_pointer_file(tmp_path: Path) -> None:
    p = tmp_path / "model.pt"
    p.write_bytes(_LFS_POINTER)
    assert base_module.is_git_lfs_pointer(p)
    p.write_bytes(_LFS_POINTER.replace(b"\n", b"\r\n"))
    assert base_module.is_git_lfs_pointer(p)
    # A loadable binary that merely STARTS with the version line is not a pointer: an HDF5 file
    # may carry a user block before its superblock, so the prefix alone proves nothing.
    p.write_bytes(_LFS_POINTER + b"\x89HDF\r\n\x1a\n" + b"\x00" * 64)
    assert not base_module.is_git_lfs_pointer(p)
    p.write_bytes(_LFS_POINTER + b"cos\nsystem\n.")  # a non `key value` line
    assert not base_module.is_git_lfs_pointer(p)
    p.write_bytes(_LFS_POINTER + b"x" * 1024)  # over the pointer size limit
    assert not base_module.is_git_lfs_pointer(p)
    p.write_bytes(b"version https://git-lfs.github.com/spec/v1\nsize 1\n")  # no oid
    assert not base_module.is_git_lfs_pointer(p)
    assert not base_module.is_git_lfs_pointer(tmp_path / "missing")


_LINE_ALPHABET = [
    b"a", b"b", b" ", b"-", b"\n", b"\r", b"\r\n", b"\x0b", b"\x0c", b"\x1c", b"\x1d", b"\x1e",
    b"\xc2\x85", b"\xe2\x80\xa8", b"\xe2\x80\xa9", b"\xe2\x80", b"\xc2", b"\x85", b"\xff",
    "é".encode(), "€".encode(),
]


@pytest.mark.parametrize("seed", range(40))
def test_iter_lines_bounded_matches_splitlines(tmp_path: Path, seed: int) -> None:
    # Parity with `read(p).splitlines()`: every boundary splitlines() honours (CRLF, bare CR, VT, FF,
    # FS/GS/RS, NEL, LS, PS), invalid and truncated UTF-8 around them, and tiny chunks so a `\r\n`
    # or a multi-byte boundary is regularly cut in half by a chunk edge.
    rng = random.Random(seed)
    data = b"".join(rng.choice(_LINE_ALPHABET) for _ in range(rng.randint(0, 300)))
    p = tmp_path / "f.txt"
    p.write_bytes(data)
    expected = list(enumerate(base_module.read(p).splitlines(), start=1))
    for chunk in (1, 2, 3, 7, 64):
        got = list(base_module.iter_lines_bounded(
            p, max_line_chars=1 << 20, overlap_chars=16, chunk_bytes=chunk
        ))
        assert got == expected, (seed, chunk)


def test_iter_lines_bounded_crlf_split_across_chunks_is_one_break(tmp_path: Path) -> None:
    p = tmp_path / "f.txt"
    p.write_bytes(b"abc\r\ndef\r\n\r\nx")
    for chunk in range(1, 12):
        got = list(base_module.iter_lines_bounded(
            p, max_line_chars=64, overlap_chars=8, chunk_bytes=chunk
        ))
        assert got == [(1, "abc"), (2, "def"), (3, ""), (4, "x")], chunk


@pytest.mark.parametrize("chunk", [3, 10, 1 << 20])
def test_iter_lines_bounded_splits_overlong_line_into_overlapping_pieces(
    tmp_path: Path, chunk: int
) -> None:
    # A line longer than max_line_chars comes back as pieces sharing its number, none longer than
    # the cap, overlapping so any window up to overlap+1 bytes lies whole inside one piece. Covered
    # whether the line is cut while still being read (small chunks) or once it is complete.
    line = "".join(chr(ord("A") + i % 26) for i in range(95))
    p = tmp_path / "f.txt"
    p.write_bytes(b"first\n" + line.encode() + b"\nlast")
    got = list(base_module.iter_lines_bounded(
        p, max_line_chars=10, overlap_chars=4, chunk_bytes=chunk
    ))
    assert got[0] == (1, "first") and got[-1] == (3, "last")
    pieces = [text for n, text in got if n == 2]
    assert len(pieces) > 1 and all(len(t) <= 10 for t in pieces)
    for start in range(len(line) - 5 + 1):
        assert any(line[start : start + 5] in t for t in pieces), start


def test_iter_lines_bounded_memory_stays_bounded_on_one_huge_line(tmp_path: Path) -> None:
    p = tmp_path / "f.bin"
    p.write_bytes(b"z" * (3 << 20))  # 3 MiB, no line break at all
    sizes = [len(t) for _, t in base_module.iter_lines_bounded(
        p, max_line_chars=1 << 16, overlap_chars=64, chunk_bytes=1 << 16
    )]
    assert sizes and max(sizes) <= 1 << 16


def test_iter_lines_bounded_edges(tmp_path: Path) -> None:
    assert list(base_module.iter_lines_bounded(
        tmp_path / "missing", max_line_chars=10, overlap_chars=1
    )) == []  # OSError path yields nothing, like read() returning ""
    p = tmp_path / "empty"
    p.write_bytes(b"")
    assert list(base_module.iter_lines_bounded(p, max_line_chars=10, overlap_chars=1)) == []
    with pytest.raises(ValueError):
        list(base_module.iter_lines_bounded(p, max_line_chars=10, overlap_chars=10))


def test_splitlines_break_set_is_exactly_what_splitlines_honours() -> None:
    # iter_lines_bounded decides "is the last line complete?" from this set, so a missing entry
    # would silently merge two lines on the large-file path and shift every later line number.
    honoured = {c for c in map(chr, range(0x110000)) if len(("a" + c + "b").splitlines()) == 2}
    assert honoured == base_module._SPLITLINES_BREAKS


# --- #538: the router views locate comments by TOKEN and can blank one-line strings ------------------
# `router_resolver_view` keeps single-line strings (a router `prefix="/auth"` is a value the prefix map
# needs); `router_code_view` blanks their content too, and is what the router-auth resolvers read.

_CLOSING_LINE = (
    "widgets = APIRouter()\n"
    'DOC = """\n'
    "Widget routes.\n"
    '"""  # TODO restore the "admin" gate: widgets = APIRouter(dependencies=[Depends(admin)])\n'
)


def test_router_resolver_view_blanks_a_comment_on_a_triple_quote_closing_line() -> None:
    # The per-line masker paired the leftover `"` of the delimiter with the comment's first `"` and
    # hid the `#`, so the dead `dependencies=` survived into the view.
    row = router_resolver_view(_CLOSING_LINE).splitlines()[3]
    assert row.rstrip() == '"""'
    assert same_file_authed_routers(_CLOSING_LINE) == set()


def test_router_code_view_blanks_one_line_string_content_but_keeps_the_quotes() -> None:
    text = 'HINT = "router = APIRouter(dependencies=[Depends(get_current_user)])"\nx = f\'{a}b\'\n'
    resolver, code = router_resolver_view(text).splitlines(), router_code_view(text).splitlines()
    assert resolver[0] == text.splitlines()[0]          # the value view keeps the string
    assert code[0] == 'HINT = "' + " " * (len(resolver[0]) - 9) + '"'
    assert code[1] == "x = f'{a} '"                   # a replacement field is code, its text is not
    assert same_file_authed_routers(text) == set()


def test_router_code_view_keeps_a_multirow_fstring_field_and_blanks_its_text() -> None:
    # #1017 review, High 1: a single-quoted f-string whose field spans rows used to be kept WHOLE
    # (blanking the in-field row break would leave a raw newline in a single-quoted literal), so the
    # text around the field survived and minted the auth map. Now only the text is blanked; the
    # field, a nested f-string's own fields and `{{` escapes are told apart at token level.
    text = (
        'HINT = f"router = APIRouter(dependencies=[Depends(admin)]) {\n'
        "    f'in {name}'\n"
        '} {{x}} tail"\n'
    )
    rows = router_code_view(text).splitlines()
    assert rows[0] == 'HINT = f"' + " " * len("router = APIRouter(dependencies=[Depends(admin)]) ") + "{"
    assert rows[1] == "    f'   {name}'"
    assert rows[2] == "}" + " " * len(" {{x}} tail") + '"'
    assert same_file_authed_routers(text) == set()
    ast.parse("\n".join(rows))


@pytest.mark.parametrize(
    "text",
    [
        _CLOSING_LINE,
        'a = "x#y"  # c "q"\nb = 1\r\nc = 2\n\x0cd = 3\n',
        'A = "first \\\nsecond"\nB = 2\n',
        'B = f"{len(\n[1])} and {{x}} and {y!r:>10}"\n',
        "C = rb'\\x00' + u'\\u00e9' + 'it\\'s'  # trailing\n",
        "D = '''\n# not a comment\n'''  # a comment\n",
        "E = f\"text {\n    f'{a!r:>{len(b)}}'  # why\n} more \\\nrun\"\n",
    ],
    ids=["closing-line", "hash-and-boundaries", "backslash-continued", "multirow-fstring",
         "prefixes-escapes", "hash-in-triple", "multirow-field-with-text"],
)
def test_router_views_are_row_aligned_and_the_code_view_still_parses(text: str) -> None:
    # The prefix map matches structure on one view and reads the value from the other, so the two
    # must agree row for row and column for column. And `_conditional_lines` parses the view: a code
    # view that stopped parsing would silently count a mount under an `if` as protection.
    resolver, code = router_resolver_view(text), router_code_view(text)
    assert [len(r) for r in resolver.splitlines()] == [len(r) for r in code.splitlines()]
    assert len(resolver.splitlines()) == len("\n".join(text.splitlines()).splitlines())
    ast.parse(text)
    ast.parse(code)


def test_router_views_fall_back_to_the_line_pass_without_a_token_stream() -> None:
    # An unterminated triple-quoted string defeats both the tokenizer and the AST, so no offset can
    # be trusted: the view is the pre-#538 per-line pass, and it still never raises.
    text = 'router = APIRouter()  # dependencies=[Depends(x)]\nDOC = """\nunterminated\n'
    expected = "\n".join(strip_python_line_comment(ln) for ln in strip_python_strings(text).splitlines())
    assert router_resolver_view(text) == expected
    assert router_code_view(text) == expected
    assert same_file_authed_routers(text) == set()


@pytest.mark.parametrize("ending", ["\n", ""], ids=["final-newline", "no-final-newline"])
@pytest.mark.parametrize(
    "dead",
    [
        'HINT = "router = APIRouter(dependencies=[Depends(admin)])"',
        'DOC = """\nx\n"""  # the "admin" gate: router = APIRouter(dependencies=[Depends(admin)])',
        'HINT = f"router = APIRouter(dependencies=[Depends(admin)]) {\n    name\n} tail"',
        # ends inside an indented block, so the stream closes with DEDENTs past the last row
        'def hint():\n    return "router = APIRouter(dependencies=[Depends(admin)])"',
    ],
    ids=["one-line-string", "closing-line-comment", "multirow-fstring", "ends-in-a-block"],
)
def test_dead_text_mints_no_auth_whether_or_not_the_file_ends_in_a_newline(
    dead: str, ending: str
) -> None:
    # #1017 re-review, Critical 1: with no final newline the tokenizer still places its closing
    # NEWLINE/DEDENT/ENDMARKER on the row past the last one, which a row table built from the text
    # does not have. Indexing it raised, the broad `except` turned that into "no token stream", and
    # the view fell back to the pre-#538 per-line pass for every such file, so A and B reopened.
    text = "router = APIRouter()\n" + dead + ending
    assert same_file_authed_routers(text) == set()


@pytest.mark.parametrize("ending", ["\n", ""], ids=["final-newline", "no-final-newline"])
def test_cross_file_mount_quoted_in_a_string_mints_nothing_without_a_final_newline(ending: str) -> None:
    files = [(Path("main.py"),
              'HINT = "app.include_router(admin.router, dependencies=[Depends(admin)])"' + ending)]
    assert cross_file_authed_routers(files) == {}


def test_resolvers_ignore_a_mount_quoted_in_a_one_line_string() -> None:
    assert same_file_authed_routers(
        'router = APIRouter()\nHINT = "app.include_router(router, dependencies=[Depends(get_user)])"\n'
    ) == set()
    files = [(Path("main.py"),
              'HINT = "app.include_router(admin.router, dependencies=[Depends(get_user)])"\n')]
    assert cross_file_authed_routers(files) == {}


def test_resolvers_still_see_live_auth_beside_a_string_that_spells_one() -> None:
    # FP bait for the code view: blanking the string must not take the live kwarg with it.
    text = (
        'router = APIRouter(description="dependencies=[] opens it",'
        " dependencies=[Depends(get_current_user)])\n"
    )
    assert same_file_authed_routers(text) == {"router"}
    files = [(Path("main.py"),
              'app.include_router(admin.router, tags=["#x"], dependencies=[Depends(get_user)])\n')]
    assert cross_file_authed_routers(files) == {"admin": {"router"}}


def test_router_view_memo_is_scoped_to_a_derived_state_run() -> None:
    base_module._router_view_cache.clear()
    router_code_view("x = 1\n")
    assert base_module._router_view_cache == {}, "memo populated outside a derived_state_run scope"
    with base_module.derived_state_run():
        router_code_view("x = 1\n")
        router_resolver_view("x = 1\n")
        assert set(base_module._router_view_cache) == {("x = 1\n", False), ("x = 1\n", True)}
    assert base_module._router_view_cache == {}, "leaving the outermost scope clears the table"


# --------------------------------------------------------------------------- #
# LLM_CALL: the shared LLM call-site matcher (#726)
# --------------------------------------------------------------------------- #

# A runner exclusion written as a lookbehind, with or without its leading `\b`: the shape every hand
# copy of the LLM-call pattern carried. Matched as TEXT, so a copy is caught however it is composed.
_RUNNER_LOOKBEHIND = re.compile(
    r"\(\?<!(?:\\b)?(?:asyncio|subprocess|trio|anyio|uvicorn|gunicorn|unittest|pytest|nox|tox)\)"
)


def test_llm_call_has_one_definition_and_its_consumers_import_it() -> None:
    # The pattern lived in three guards, kept "identical" by a comment, and drifted apart twice (found
    # in #717 and #726). The #717 parity test compared two of the copies, and the third drifted
    # unseen. So this pins the root cause instead: no guard module except base.py may spell a runner
    # exclusion of its own.
    base_path = Path(base_module.__file__)
    # The scan must be live before its silence means anything: base.py's own definition must match.
    assert _RUNNER_LOOKBEHIND.search(base_path.read_text(encoding="utf-8"))
    copies = sorted(
        p.name
        for p in base_path.parent.glob("*.py")
        if p != base_path and _RUNNER_LOOKBEHIND.search(p.read_text(encoding="utf-8"))
    )
    assert not copies, (
        f"guard modules carrying their own runner-excluding LLM-call pattern: {copies} - import "
        "LLM_CALL from agentsec.guards.base, and OR any guard-specific arm in locally (the shape "
        "of prompt_string_interp._calls_llm)"
    )

    from agentsec.guards import input_delimiters, prompt_string_interp, rag_trust_boundary

    for mod in (input_delimiters, prompt_string_interp, rag_trust_boundary):
        assert mod.LLM_CALL is LLM_CALL, mod.__name__


@pytest.mark.parametrize(
    ("call", "is_llm"),
    [
        ("agent.run(prompt)", True),
        ("title_agent.run(prompt)", True),
        ("research_trio.run(prompt)", True),  # ENDS in a runner name, is not one (#725 review)
        ("detox.run(prompt)", True),
        ("agent.run_sync(prompt)", True),
        ("client.chat.completions.create(model='m')", True),
        ("chain.invoke(x)", True),
        ("asyncio.run(main())", False),
        ("sys.exit(asyncio.run(main()))", False),
        ("uvicorn.run(app, port=8001)", False),
        ("gunicorn.run(app)", False),
        ("client.messages.create(body=x)", False),  # the Anthropic arm is prompt-string-interp's own
        # The accepted residuals named in the comment on LLM_CALL, pinned so a change is deliberate.
        ("self.subprocess.run(cmd)", False),
        ("asyncio\n.run(main())", True),
        ('session.run("pytest")', True),
    ],
)
def test_llm_call_receiver_scoping(call: str, is_llm: bool) -> None:
    assert bool(LLM_CALL.search(call)) is is_llm


# --- neutralize_interpolations / iter_policy_key_values (PR #1051 final review F2) ---------------


def test_neutralize_interpolations_counts_nested_braces() -> None:
    from agentsec.guards.base import neutralize_interpolations

    assert neutralize_interpolations('x ${lookup({a="b"}, v)} y') == 'x $(lookup(_a=_b__, v)) y'


def test_neutralize_interpolations_blanks_brackets_and_quotes_inside() -> None:
    from agentsec.guards.base import neutralize_interpolations

    assert neutralize_interpolations('"${m["k"]}"') == '"$(m__k__)"'


def test_neutralize_interpolations_unterminated_runs_to_the_end() -> None:
    from agentsec.guards.base import neutralize_interpolations

    assert neutralize_interpolations('a ${ b "c" ]') == 'a $( b _c_ _'


def test_iter_policy_key_values_skips_a_head_inside_the_previous_value() -> None:
    from agentsec.guards.agent_iam_killchain_combination import _ACTION_HEAD
    from agentsec.guards.base import iter_policy_key_values

    values = list(iter_policy_key_values('Action = ["x", Action = ["b"]]', _ACTION_HEAD))
    assert len(values) == 1
    assert values[0][1] == '["x", Action = ["b"]'


def test_iter_policy_key_values_is_linear_on_a_long_unterminated_run() -> None:
    # The `unclosed` memo is what keeps a run of `[` with no `]` linear: without it every head
    # re-scans to the end of the text. The guard-level 16k-repeat tests are too short to see that
    # (the find is a fast C scan); 80k repeats is where the mutant measured x3.7 per doubling.
    from agentsec.guards.agent_iam_killchain_combination import _ACTION_HEAD
    from agentsec.guards.base import iter_policy_key_values

    sizes = [10000, 20000, 40000, 80000]
    texts = {n: "Action = [" * n for n in sizes}

    def scan(n: int) -> None:
        for _ in iter_policy_key_values(texts[n], _ACTION_HEAD):
            pass

    assert_growth(scan, sizes, expected="linear")
# --------------------------------------------------------------------------- #
# LLM_SDK_CREATE + is_llm_sdk_create_call: the SDK `create` shape and its argument gate (#561)
# --------------------------------------------------------------------------- #

# A create-shape regex spelled as TEXT (`responses\.create`, or an alternation ending
# `messages)\.create`): what each guard's own hand-kept enumeration looked like.
_SDK_CREATE_COPY = re.compile(r"(?:responses|messages|completions)\)?\\\.create")


def test_llm_sdk_create_has_one_definition_and_its_consumers_import_it() -> None:
    # guardrail-architecture Rule 3 and llm-input-size-cap each kept their own enumeration of the SDK
    # create paths, and the two disagreed in membership (3 arms vs 4) and in prefix (#561). So both
    # import the one in base.py, and neither consumer may spell one of its own.
    # Scoped to Rule 3's regex rather than the whole guardrail module: Rule 1's Llama Guard signal
    # (`_LLAMA_GUARD_LOADED`) keeps its own call shapes, in a different role (a line that also names
    # the Llama Guard model), so the receiver FP class of #561 does not reach it.
    from agentsec.guards import guardrail_architecture, llm_input_size_cap

    # The scan must be live before its silence means anything: base.py's own definition must match.
    assert _SDK_CREATE_COPY.search(Path(base_module.__file__).read_text(encoding="utf-8"))
    for mod in (guardrail_architecture, llm_input_size_cap):
        assert mod.LLM_SDK_CREATE is LLM_SDK_CREATE, mod.__name__
    size_cap_src = Path(llm_input_size_cap.__file__ or "").read_text(encoding="utf-8")
    assert not _SDK_CREATE_COPY.search(size_cap_src), "llm_input_size_cap spells its own SDK create shape"
    # Rule 3's assignment regex takes any `.create(` and leaves the SDK shape to the shared one.
    rule3 = guardrail_architecture._LLM_RESULT_VAR.pattern
    assert not _SDK_CREATE_COPY.search(rule3), rule3


def _gate(src: str) -> bool:
    m = LLM_SDK_CREATE.search(src)
    assert m, src
    return is_llm_sdk_create_call(src, m.end() - 1)


@pytest.mark.parametrize(
    "src",
    [
        "client.chat.completions.create(model='m', messages=[])",
        "client.completions.create(model='m', prompt=q)",
        "client.responses.create(model='gpt-4o', input=q)",
        "anthropic.messages.create(model='c', max_tokens=1, messages=m)",
        "client.chat.completions.create(**params)",
        "client.chat.completions.create(messages=m, **cfg)",
        # instructor `from_provider(...)`: the model lives in the provider string, `messages=` remains.
        "client.chat.completions.create(response_model=User, messages=m)",
        # responses.create's two model-less forms: a stored prompt, an Azure AI Foundry agent reference.
        "client.responses.create(prompt={'id': 'pmpt_1'}, input=q)",
        "client.responses.create(input=q, extra_body={'agent': a})",
        "client.messages.create(\n    max_tokens=1,\n    model='c',\n    messages=m,\n)",
        "client.messages.create(model = 'c', messages=m)",
        # Fail-open: an argument list that never closes is not guessed at.
        "client.messages.create(body=q",
        # The accepted residuals named in the docstring, both erring towards firing.
        "survey.responses.create(answers={'q': a, **rest})",
        "x.messages.create(key=lambda a, model=None: a)",
        # #613: a triple-quoted argument with an apostrophe splits, and its `model=` still confirms.
        "client.messages.create(system='''the user's notes''', model='c', messages=m)",
    ],
)
def test_llm_sdk_create_gate_confirms(src: str) -> None:
    assert _gate(src) is True


@pytest.mark.parametrize(
    "src",
    [
        "survey.responses.create(answer=q)",  # a Django reverse relation
        "self.survey.responses.create(answer=q)",
        "db.completions.create(body=q)",
        "client.messages.create(body=q, from_=a, to=n)",  # Twilio SMS
        "api.messages.create(room_id, text=t)",  # Webex
        "client.responses.create(data={'model': m})",  # `model` only as a dict key
        "client.responses.create('model=x')",  # only as string content
        "client.responses.create(model == m)",  # a comparison, not a keyword
        "client.messages.create(*args)",  # a keyword-only create rejects a bare positional spread
        "client.responses.create(input=q)",  # `input=` is an ORM-plausible field name: not accepted
        "client.messages.create()",
        # The Assistants API adds a message to a thread and generates nothing: the model call there is
        # `runs.create`, which is not an SDK create shape. OpenAI has deprecated that API.
        "client.beta.threads.messages.create(thread_id=t, role='user', content=q)",
        # #613: the Twilio shape with a triple-quoted body. It used to split to None and fail open.
        "client.messages.create(body='''it's late''', from_=a, to=n)",
    ],
)
def test_llm_sdk_create_gate_rejects(src: str) -> None:
    assert _gate(src) is False


def test_llm_sdk_create_gate_fails_open_off_a_paren() -> None:
    # A caller that hands over the wrong index gets today's answer, never a silent miss.
    assert is_llm_sdk_create_call("survey.responses.create(answer=q)", 0) is True
    assert is_llm_sdk_create_call("", 3) is True


@pytest.mark.parametrize(
    ("src", "is_candidate"),
    [
        ("client.chat.completions.create(", True),
        ("client.completions.create(", True),
        ("client.responses.create (", True),
        ("client.messages.create(", True),
        ("get_client().messages.create(", True),  # no receiver name is required
        ("Order.objects.create(", False),
        ("stripe.PaymentIntent.create(", False),
        ("client.beta.threads.runs.create(", False),
        ("responses.create(", False),  # the shape starts at the dot
    ],
)
def test_llm_sdk_create_shape(src: str, is_candidate: bool) -> None:
    assert bool(LLM_SDK_CREATE.search(src)) is is_candidate


def test_js_in_identifier_literal_credits_a_key_and_not_prose() -> None:
    # #1055: a header name or env key is a string by nature and credits; the same word in prose does
    # not, and neither does a template literal split by a `${...}` substitution.
    def at(src: str, word: str) -> bool:
        return js_in_identifier_literal(src, _anchor_mask(src), src.index(word))

    assert at("h = req.headers['mcp-method'];", "mcp-method")
    assert at('n = process.env[" MAX_TOOLS "];', "MAX_TOOLS")
    assert at("o = { 'limit': 50 };", "limit")
    assert not at("log('no limit configured');", "limit")
    assert not at("log(`limit ${n}`);", "limit")
    assert not at("t = `${n} limit`;", "limit")
    assert not at("log('use 'limit' here');", "here")  # the quote ending the run is not a real delimiter pair


def test_js_in_identifier_literal_fails_closed() -> None:
    # It widens a credit, so the inverse of js_anchor_is_code's contract: misaligned views, an
    # out-of-range position, and an anchor in live code all answer False.
    src = "x = 'limit';"
    mask = _anchor_mask(src)
    pos = src.index("limit")
    assert js_in_identifier_literal(src, mask, pos)
    assert not js_in_identifier_literal(src, mask[:-1], pos)
    assert not js_in_identifier_literal(src, mask, 99)
    assert not js_in_identifier_literal(src, mask, -1)
    assert not js_in_identifier_literal(src, mask, 0)  # `x` is code, not a literal


def test_js_code_matches_a_dropped_match_does_not_swallow_a_real_one() -> None:
    # #1055 batch 2a: a long-span pattern's quoted copy runs over the real match below it. Under plain
    # `finditer` the dropped copy consumed that span, so the real call was never visited (found on
    # js-cors-wildcard's `_HEADER_OBJECT_WILDCARD`, which spans ~280 characters across lines).
    src = "log('.set(x');\nres.set({ a: '*' });\n"
    pattern = re.compile(r"\.set\([\s\S]{0,40}?\*")
    found = list(js_code_matches(pattern, src, _anchor_mask(src), anchor=lambda m: m.start() + 4))
    assert [m.start() for m in found] == [src.index("res.set(") + 3]


def test_js_code_matches_literal_ok_accepts_an_identifier_literal_and_resumes_after_a_drop() -> None:
    # PR #1131 round-1 M1: `literal_ok=True` also yields a match anchored in a one-identifier string
    # literal (a header name), never one anchored in prose, and a dropped prose match that runs over a
    # real one does not consume it.
    src = "log('hdr x key'); h['key'];"
    pattern = re.compile(r"\b(?:hdr[^\n]{0,20}key|key)\b")
    plain = list(js_code_matches(pattern, src, _anchor_mask(src), anchor=lambda m: m.start()))
    lit = list(js_code_matches(pattern, src, _anchor_mask(src), anchor=lambda m: m.start(), literal_ok=True))
    assert plain == []
    assert [m.start() for m in lit] == [src.index("['key']") + 2]


# --- literal_bool_state / terraform_code_view (PR #1162 round-3 fix pass) ---------------------


def test_literal_bool_state_quoted_value_counts_only_as_a_bool_or_interpolation() -> None:
    from agentsec.guards.base import literal_bool_state

    assert literal_bool_state("encrypted", "encrypted = true") == "true"
    assert literal_bool_state("encrypted", 'encrypted = "true"') == "true"
    assert literal_bool_state("encrypted", 'encrypted = "false"') == "false"
    assert literal_bool_state("encrypted", "encrypted = var.e") == "nonliteral"
    assert literal_bool_state("encrypted", 'encrypted = "${var.e}"') == "nonliteral"
    # The `"$(...)"` that terraform_code_view leaves behind is non-literal too.
    assert literal_bool_state("encrypted", 'encrypted = "$(var.e)"') == "nonliteral"
    # Round-3 L-1: a quoted non-bool word (a tag VALUE under a key that shares the attribute's
    # name) is not the attribute, so it must not read as "nonliteral" and silence the caller.
    assert literal_bool_state("encrypted", 'tags = { encrypted = "no" }') == "absent"
    # ...and the search moves past it to the real attribute.
    assert literal_bool_state("encrypted", 'tags = { encrypted = "no" }\nencrypted = false') == "false"


def test_terraform_code_view_blanks_comments_and_neutralises_interpolation() -> None:
    from agentsec.guards.base import terraform_code_view

    text = (
        'a = "${var.x}"  # was {\n'
        "// retention_in_days = 1\n"
        'b = "http://h/#frag"\n'
        "script = <<EOT\n"
        "  echo {\n"
        "EOT\n"
    )
    view = terraform_code_view(text)
    # Length- and newline-preserving, so offsets and line numbers still index the original.
    assert len(view) == len(text)
    assert view.count("\n") == text.count("\n")
    lines = view.split("\n")
    assert lines[0].rstrip() == 'a = "$(var.x)"'
    assert lines[1].strip() == ""
    # A `#` or `//` inside a string is not a comment.
    assert lines[2] == 'b = "http://h/#frag"'
    # A non-policy heredoc body is blanked, so its `{` cannot unbalance a block regex.
    assert lines[4].strip() == ""
    assert "{" not in view and "}" not in view


def test_top_level_attribute_text_ignores_braces_in_comments_strings_and_heredocs() -> None:
    # PR #1162 round-3 L-3: the H-3 fix (brace depth via _tf_line_scan) was pinned only for a
    # `#` comment. Each shape below used to close the top-level scope early and drop
    # `protocol = "HTTP"` (a silent false negative for the listener guards).
    from agentsec.guards.base import top_level_attribute_text

    head = 'resource "aws_lb_listener" "l" {\n'
    tail = '  protocol = "HTTP"\n  default_action {\n    type = "forward"\n  }\n'
    for noise in (
        "  # was {\n",
        "  // was {\n",
        '  description = "{"\n',
        '  tags = { note = "x{" }\n',
        "  description = <<EOT\n  {\nEOT\n",
    ):
        top = top_level_attribute_text(head + noise + tail)
        assert 'protocol = "HTTP"' in top, noise
        # The nested block's own content is still excluded.
        assert 'type = "forward"' not in top, noise


def test_top_level_attribute_text_reads_a_one_line_resources_own_attribute() -> None:
    # PR #1162 round-5 M1: a one-line resource is a body of its opening line alone, which the
    # helper used to drop, so `{ encrypted = true }` read as no attribute at all. The attribute
    # comes back on its own line, without the closing `}`, and a brace inside a string or a
    # trailing comment is not taken for the block's own.
    from agentsec.guards.base import iter_terraform_resources, top_level_attribute_text

    def top(text: str) -> list[str]:
        ((_, _, _, body),) = iter_terraform_resources(text)
        return [line.strip() for line in top_level_attribute_text("\n".join(t for _, t in body)).splitlines()]

    assert top('resource "aws_efs_file_system" "x" { encrypted = true }\n') == ["encrypted = true"]
    assert top('resource "t" "x" { tags = { a = "}" } }\n') == ['tags = { a = "}" }']
    assert top('resource "t" "x" { url = "http://h/#frag" } # note }\n') == ['url = "http://h/#frag"']
    assert top('resource "t" "x" { snapshot_identifier = "" }\n') == ['snapshot_identifier = ""']
    assert top('resource "t" "x" {}\n') == []
    # The multi-line form is unchanged: its opening line carries nothing, and a nested block
    # contributes only its own opener line, never its content.
    assert top('resource "t" "x" {\n  encrypted = true\n  b {\n    c = 1\n  }\n}\n') == [
        "encrypted = true",
        "b {",
    ]
