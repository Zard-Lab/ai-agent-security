from __future__ import annotations

import itertools
import random

import pytest

import agentsec.guards.base as base
from agentsec.guards.base import (
    _QUOTED_SPAN,
    _mask_quoted_spans,
    comment_view,
    strip_hash_comments,
    strip_js_comments,
)
from tests._timing import assert_growth

# --- the quote mask behind strip_hash_comments: exact and linear, no cap (issue #508) ------------


def _regex_mask(s: str) -> str:
    """The spec `_mask_quoted_spans` must reproduce: the regex `.sub()` it replaced."""
    return _QUOTED_SPAN.sub(lambda m: "x" * len(m.group()), s)


def test_mask_quoted_spans_is_byte_identical_to_the_regex_spec() -> None:
    """The equivalence the whole #508 fix rests on: the linear masker answers exactly what the
    quadratic regex answered, on every input, so removing the 1 KB cap changes no short line.

    Random lines over the characters the two quote grammars care about, newlines included, since
    the masker's one piece of state (the dead-dquote index) must expire at each `\\n`. That is
    the bug this test exists to catch: a mutant whose dead index never expires mismatched 57,998
    of 400,000 lines from this generator (~14%), so the 20,000 here miss it with probability ~0."""
    rng = random.Random(508)
    alphabets = (
        ["\n", '"', "'", "\\", "#", " ", "a", "x"],
        ['"', "\\", "\n", "'"],
        ['"', "\\", "a"],
        ["'", '"', "\\"],
        ['"', "\\", "\\", "'", "#", " "],
    )
    for _ in range(20_000):
        alphabet = rng.choice(alphabets)
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, rng.choice((12, 40, 200)))))
        assert _mask_quoted_spans(s) == _regex_mask(s), f"diverged from the regex spec on {s!r}"
    realistic = [
        'msg: "Info #1: {{ secret }}"',
        "msg: don't fail # it's fine",
        'msg: "unclosed # rest',
        r'a: "x\"y" # c',
        "k: 'a''b' # c",
        r'"\\" # c',
        'x \\"' * 50,
        '- "5432:5432"  # dev only',
        "--requirepass 'p#ss' # note",
    ]
    for s in realistic:
        assert _mask_quoted_spans(s) == _regex_mask(s), f"diverged from the regex spec on {s!r}"


def test_strip_hash_comments_is_linear_on_hostile_line() -> None:
    """A run of `\\"` pairs with no terminating bare quote is the input the regex mask was
    quadratic on (issue #418 residue): 920 ms at 16 KB, x4.0 per doubling, which is why a 1 KB cap
    once skipped masking long lines (#508). The masker remembers a failed `"` instead of retrying
    every later one, so cost is linear and needs no cap.

    The line ends in a real comment, and it has to: `_hash_comment_start` returns early on a line
    with no `#`, so a `#`-free hostile line would never reach the mask and pass vacuously."""
    sizes = [8000, 16000, 32000, 64000]
    lines = {n: ('"' + chr(92)) * n + " # c" for n in sizes}

    def scan(n: int) -> None:
        strip_hash_comments(lines[n])

    assert_growth(scan, sizes, expected="linear")
    # The behavioural half: the comment is stripped, which the old capped path did not do.
    assert strip_hash_comments(lines[64000]) == lines[64000][: -len(" # c")]


def test_yaml_comment_view_is_linear_on_hostile_line_without_a_hash() -> None:
    """The yaml view masks once more, in `_yaml_block_scalar_parent`, and it does so on every line,
    `#` or not. The 1 KB cap used to skip that call on a long line along with the comment search,
    so removing the cap made it reachable: it has to use the linear masker too, or a `#`-free
    hostile line in a YAML file costs O(n^2) in every pragma check."""
    sizes = [8000, 16000, 32000, 64000]
    texts = {n: ('"' + chr(92)) * n + "\n" for n in sizes}

    def scan(n: int) -> None:
        comment_view(texts[n], "yaml")

    assert_growth(scan, sizes, expected="linear")


@pytest.mark.parametrize(
    "unit",
    ["' ", '" ', "$a$ ", "$$ ' ", "$x$ '", "E'" + chr(92) + "' "],
    ids=["apostrophe", "double-quote", "tag", "body-apostrophe", "tagged-body-apostrophe", "e-string"],
)
def test_sql_comment_view_is_linear_on_hostile_quotes_and_dollar_tags(unit: str) -> None:
    """The SQL view's take-back walk (`_sql_view_literals`, #1040 T2) is linear on hostile quote and
    dollar-tag repeats (#1125 round 1, L1). Measured what this pins: rebuilding the
    `_index_dollar_delims` table per tag instead of once fails the three dollar-tag cases. Dropping
    the per-kind quote latch does NOT fail any case, nor any repeat of up to four tokens from
    `' " E' \\ space $$ $a$ x` (the walk stayed linear without it on every one), so the latch is a
    backstop this test cannot see."""
    sizes = [4000, 8000, 16000, 32000]
    texts = {n: unit * n + "\n" for n in sizes}

    def scan(n: int) -> None:
        comment_view(texts[n], "sql")

    assert_growth(scan, sizes, expected="linear")


def test_sql_comment_view_is_linear_on_an_unterminated_body() -> None:
    sizes = [4000, 8000, 16000, 32000]
    texts = {n: "$u$ " + "x ' " * n + "\n" for n in sizes}

    def scan(n: int) -> None:
        comment_view(texts[n], "sql")

    assert_growth(scan, sizes, expected="linear")


def test_strip_js_comments_failed_regex_starts_in_a_substitution_are_linear() -> None:
    """A `/[` never closes on its line: the `[` opens a class, so every later `/` is class content.
    The `${…}` sub-lexer (#543) used to retry a regex start at each such `/` and rescan to the line
    end, which made one long line quadratic (5.3 s at 16 KB, #1124 round 1, H1). A failed scan now
    marks where it bailed, and no `/` before that point is retried as a regex opener."""
    sizes = [8000, 16000, 32000, 64000]
    texts = {n: "x = `${ " + "/[" * n for n in sizes}

    def scan(n: int) -> None:
        strip_js_comments(texts[n], strip_strings=True)

    assert_growth(scan, sizes, expected="linear")
    # The behavioural half: a regex that does close is still consumed after the failed-start run
    # ends at the line terminator, so its `}` cannot end the substitution early.
    src = "x = `${ f(/[\n, /}/.test(b)) }`;\n// SINK()\n"
    assert "SINK" not in strip_js_comments(src, strip_strings=True)


def test_strip_hash_comments_strips_a_line_of_any_length() -> None:
    """Past 1 KB the comment is stripped like on any other line (#508; the old cap returned such a
    line verbatim, so a mitigation written in its comment still counted). Both directions: the
    trailing comment goes, and a `#` inside a long quoted value survives, which is what stripping
    WITHOUT the mask would get wrong (the #418 bug)."""
    pad = "x" * 2000
    assert strip_hash_comments(f'key: "{pad}"  # trailing comment').rstrip() == f'key: "{pad}"'
    quoted = f'key: "{pad} #not-a-comment"'
    assert strip_hash_comments(quoted) == quoted


def test_strip_hash_comments_ordinary_lines_still_strip() -> None:
    """Ordinary short lines strip as they always did."""
    assert strip_hash_comments('key: value  # c').rstrip() == 'key: value'
    assert strip_hash_comments('key: "has # inside"  # real').rstrip() == 'key: "has # inside"'
    assert strip_hash_comments("key: 'has # inside'").rstrip() == "key: 'has # inside'"


# --- run-scoped derived-state memo (issue #544) ------------------------------------------------


def test_derived_memo_returns_identical_output_to_the_uncached_path() -> None:
    """The memo must be a pure speedup: for every text, cached output == uncached output.

    This is the assertion that makes the optimization safe. The memo sits on the analysis path
    shared by a large share of the guard set, so a divergence here is a silent, repo-wide change
    in what they see."""
    samples = [
        'x = 1\n"""a docstring with exec( inside"""\ny = 2\n',
        "def f():\n    '''triple single'''\n    return 1\n",
        'f = f"""prefix {a + b} suffix"""\n',                       # f-string: interpolations are code
        "s = 'single line stays intact'  # eval(\n",
        "this is not python at all ((( \n",                          # parse failure -> regex fallback
        "",                                                          # degenerate
        'r"""raw"""\nb"""bytes"""\n',                                # string prefixes
    ]
    with base.derived_state_run():
        for text in samples:
            first = base.strip_python_strings(text)
            second = base.strip_python_strings(text)               # served from the memo
            assert first == base._strip_python_strings_uncached(text), f"memo diverged for {text!r}"
            assert second is first, "second call should be the memoised object"


def test_derived_memo_is_inactive_outside_a_run_scope() -> None:
    """Outside a scope nothing is cached, so a direct call (a unit test, a single guard, a
    long-lived process between audits) can never be served a stale or foreign result."""
    base._strip_python_strings_cache.clear()
    base.strip_python_strings("x = 1\n")
    assert base._strip_python_strings_cache == {}, "memo populated outside a derived_state_run scope"
    assert base._derived_depth == 0


def test_derived_memo_is_cleared_between_runs_and_is_reentrant() -> None:
    """Run-scoped, not process-global: a process auditing two different targets must not serve
    one target's derived state from the other's run. Nested scopes share one table (mirrors
    `walk_run`), and the outermost exit clears it."""
    with base.derived_state_run():
        base.strip_python_strings("x = 1\n")
        assert base._strip_python_strings_cache, "memo should be populated inside a scope"
        with base.derived_state_run():                              # re-entrant
            assert base._derived_depth == 2
            base.strip_python_strings("y = 2\n")
        assert base._derived_depth == 1, "inner exit must not tear down the shared table"
        assert base._strip_python_strings_cache, "inner exit must not clear the outer scope's memo"
    assert base._strip_python_strings_cache == {}, "outermost exit must clear the memo"
    assert base._derived_depth == 0

    with base.derived_state_run():                                  # a second, independent run
        assert base._strip_python_strings_cache == {}, "a new run must start from an empty table"


JS_SAMPLES = [
    "const a = 1;  // a trailing comment\nel.innerHTML = data;\n",
    "/* block\n   comment */\nconst re = /^\\/api\\//;\n",
    "const url = `${base}/x?q=${encodeURIComponent(n)}`;  // template\n",
    "<p>Don't forget the class's name</p>\n",                       # JSX apostrophes
    'import t from"https://cdn/x.js";\nel.innerHTML = d;\n',        # keyword-abutting string
    "const s = 'unterminated\nconst t = 2;\n",                      # unterminated literal
    "",                                                             # degenerate
]


def test_js_derived_memo_returns_identical_output_to_the_uncached_path() -> None:
    """The JS memo must be a pure speedup at EVERY `strip_strings` / `strip_regex` /
    `keep_substitutions` setting.

    Same assertion as the Python table above, and for the same reason: `strip_js_comments` feeds 21
    guard modules, so a divergence here is a silent, repo-wide change in what they see."""
    with base.derived_state_run():
        for text in JS_SAMPLES:
            for strings, regex, keep in itertools.product((False, True), repeat=3):
                first = base.strip_js_comments(
                    text, strip_strings=strings, strip_regex=regex, keep_substitutions=keep
                )
                second = base.strip_js_comments(  # memo
                    text, strip_strings=strings, strip_regex=regex, keep_substitutions=keep
                )
                direct = base._strip_js_comments_uncached(
                    text, strip_strings=strings, strip_regex=regex, keep_substitutions=keep
                )
                assert first == direct, (
                    f"memo diverged for {text!r} at strip_strings={strings}, strip_regex={regex}, "
                    f"keep_substitutions={keep}"
                )
                assert second is first, "second call should be the memoised object"


def test_js_derived_memo_keys_on_the_strip_regex_flag() -> None:
    """The `strip_strings` key test below, for the second flag (#909). A key that forgot
    `strip_regex` would hand the timer scan an un-blanked regex body, or hand a plain
    `strip_strings` consumer a blanked one, depending only on which guard ran first."""
    text = 'x = s.replace(/}\'/g, "");  // note\n'
    off_direct = base._strip_js_comments_uncached(text, strip_strings=True)
    on_direct = base._strip_js_comments_uncached(text, strip_strings=True, strip_regex=True)
    assert off_direct != on_direct, "fixture does not discriminate — the test would be vacuous"

    for first_flag in (False, True):                 # whichever variant warms the cache first
        with base.derived_state_run():
            base.strip_js_comments(text, strip_strings=True, strip_regex=first_flag)
            assert base.strip_js_comments(text, strip_strings=True) == off_direct
            assert base.strip_js_comments(text, strip_strings=True, strip_regex=True) == on_direct


def test_js_derived_memo_keys_on_the_strip_strings_flag() -> None:
    """The failure mode this function has and `strip_python_strings` does not: ONE input, TWO valid
    outputs. A text-only key would serve whichever variant was computed first to every later caller,
    so a guard asking for `strip_strings=True` could receive un-blanked string contents — a
    correctness bug, and one that would look like a guard FP rather than a cache defect.

    Uses a text where the two settings genuinely differ, and asserts that both directions are served
    correctly regardless of which is computed first."""
    text = 'const secret = "sk-live-abcdefghijklmnop";  // note\n'
    off_direct = base._strip_js_comments_uncached(text, strip_strings=False)
    on_direct = base._strip_js_comments_uncached(text, strip_strings=True)
    assert off_direct != on_direct, "fixture does not discriminate — the test would be vacuous"

    for first_flag in (False, True):                 # whichever variant warms the cache first
        with base.derived_state_run():
            base.strip_js_comments(text, strip_strings=first_flag)
            assert base.strip_js_comments(text, strip_strings=False) == off_direct
            assert base.strip_js_comments(text, strip_strings=True) == on_direct


def test_js_derived_memo_keys_on_the_keep_substitutions_flag() -> None:
    """The third variant (#749): `keep_substitutions=True` differs from plain `strip_strings=True`
    exactly inside a `${...}`, so a two-field key would hand the anchor mask a string-blanked view
    (silently dropping every substitution-nested sink a guard filters with it) or the reverse.

    Same shape as the test above: a discriminating text, and every variant served correctly
    whichever one warms the cache first."""
    text = "res.send(`out: ${execSync(cmd)}`);  // note\n"
    variants = ((False, False), (True, False), (True, True))
    direct = {
        v: base._strip_js_comments_uncached(text, strip_strings=v[0], keep_substitutions=v[1])
        for v in variants
    }
    assert len(set(direct.values())) == 3, "fixture does not discriminate — the test would be vacuous"

    for first in variants:
        with base.derived_state_run():
            base.strip_js_comments(text, strip_strings=first[0], keep_substitutions=first[1])
            for v in variants:
                assert base.strip_js_comments(text, strip_strings=v[0], keep_substitutions=v[1]) == direct[v]


def test_js_derived_memo_is_inactive_outside_a_run_scope() -> None:
    """Outside a scope nothing is cached, so a direct call (a unit test, a single guard, a
    long-lived process between audits) can never be served a stale or foreign result."""
    base._strip_js_comments_cache.clear()
    base.strip_js_comments("const a = 1;  // c\n")
    assert base._strip_js_comments_cache == {}, "memo populated outside a derived_state_run scope"
    assert base._derived_depth == 0


def test_js_derived_memo_is_cleared_between_runs() -> None:
    """Run-scoped, not process-global: a process auditing two targets in sequence (corpus-scan does
    exactly this) must not serve one target's derived state from the other's run."""
    with base.derived_state_run():
        base.strip_js_comments("const a = 1;  // c\n")
        assert base._strip_js_comments_cache, "memo should be populated inside a scope"
    assert base._strip_js_comments_cache == {}, "outermost exit must clear the JS memo"

    with base.derived_state_run():
        assert base._strip_js_comments_cache == {}, "a new run must start from an empty table"


def test_js_derived_memo_respects_its_entry_bound() -> None:
    """Past the bound the JS memo stops growing and recomputes — slower, never wrong."""
    original = base._MAX_DERIVED_ENTRIES
    try:
        base._MAX_DERIVED_ENTRIES = 2
        with base.derived_state_run():
            for i in range(5):
                text = f"const a = {i};  // c\n"
                assert base.strip_js_comments(text) == base._strip_js_comments_uncached(text)
            assert len(base._strip_js_comments_cache) == 2, "entry bound not enforced"
    finally:
        base._MAX_DERIVED_ENTRIES = original


def test_derived_memo_respects_its_entry_bound() -> None:
    """Past the bound the memo stops growing and simply recomputes — slower, never wrong. Guards a
    pathological target (thousands of large files) from ballooning memory."""
    original = base._MAX_DERIVED_ENTRIES
    try:
        base._MAX_DERIVED_ENTRIES = 2
        with base.derived_state_run():
            for i in range(5):
                text = f"x = {i}\n"
                assert base.strip_python_strings(text) == base._strip_python_strings_uncached(text)
            assert len(base._strip_python_strings_cache) == 2, "entry bound not enforced"
    finally:
        base._MAX_DERIVED_ENTRIES = original
