from __future__ import annotations

import textwrap

import pytest

from agentsec.guards.redos import _DISJOINT_SAFE, _NESTED, RedosGuard
from tests.guards._common import *  # noqa: F401,F403


def test_redos_flags_nested_quantifier(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text("import re\nP = re.compile(r'(a+)+$')\n", encoding="utf-8")
    findings = RedosGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "redos/nested-quantifier" and findings[0].severity == "medium"

def test_redos_flags_star_star(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text("import re\ndef m(s):\n    return re.match(r'(.*)*x', s)\n", encoding="utf-8")
    assert len(RedosGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_redos_passes_safe_regex(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text("import re\nP = re.compile(r'[a-z]+@[a-z]+\\.[a-z]+')\n", encoding="utf-8")
    assert RedosGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_redos_passes_separator_anchored_disjoint(tmp_path: Path) -> None:
    # T3 precision: a repeated group anchored by a REQUIRED literal separator (`\.`, `\s+`) is
    # linear, not catastrophic — iterations can't overlap. Was a false positive on semver/name regexes.
    (tmp_path / "v.py").write_text(
        "import re\n"
        "SEMVER = re.compile(r'^\\d+(?:\\.\\d+)*')\n"
        "NAME = re.compile(r'\\b([A-Z][a-z]+(?:\\s+[A-Z][a-z]+)+)\\b')\n", encoding="utf-8"
    )
    assert RedosGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_redos_still_flags_catastrophic_after_narrowing(tmp_path: Path) -> None:
    # ...the narrowing MUST NOT create a false negative — genuine catastrophic shapes still fire.
    (tmp_path / "v.py").write_text(
        "import re\n"
        "A = re.compile(r'(a+)+$')\n"          # same-class nested
        "B = re.compile(r'(\\w+)+!')\n"        # \\w+ re-quantified
        "C = re.compile(r'(.+)+z')\n"          # wildcard (bare . is NOT a separator)
        "D = re.compile(r'(\\s*\\w+)+')\n", encoding="utf-8"     # OPTIONAL separator -> can still overlap
    )
    assert len(RedosGuard().run(tmp_path, _pyprof(tmp_path))) == 4

def test_redos_passes_nested_outside_re_call(tmp_path: Path) -> None:
    # the nested-quantifier text is not in a re.* call -> not flagged
    (tmp_path / "v.py").write_text("DOC = 'the pattern (a+)+ is dangerous'\n", encoding="utf-8")
    assert RedosGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_redos_passes_group_final_only_false_positive(tmp_path: Path) -> None:
    # #424: a quantifier that is NOT at an overlap boundary (`(foo+bar)*`, required literals
    # follow) is a benign, linear pattern — the inner unit can't overlap ambiguously — so it must
    # NOT fire. Requires the boundary narrowing of _NESTED.
    (tmp_path / "v.py").write_text("import re\nP = re.compile(r'(foo+bar)*')\n", encoding="utf-8")
    assert RedosGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_redos_flags_alternation_branch_quantifier(tmp_path: Path) -> None:
    # Regression (#439 review, Critical): the narrowing must STILL flag a catastrophic regex whose
    # quantifier ends an ALTERNATE branch, e.g. `(a+|b)+` — a genuine exponential-backtracking
    # pattern (verified to hang) that a naive group-final-only narrowing silently dropped.
    (tmp_path / "v.py").write_text("import re\nP = re.compile(r'(a+|b)+$')\n", encoding="utf-8")
    findings = RedosGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "redos/nested-quantifier"

def test_redos_passes_docstring_example(tmp_path: Path) -> None:
    # FP-bait (#424): a `re.compile(r"(a+)+")` EXAMPLE inside a docstring must not fire.
    (tmp_path / "v.py").write_text(
        '"""Never write a nested quantifier like re.compile(r"(a+)+"):\n'
        "it backtracks exponentially.\n"
        '"""\n'
        "import re\n",
        encoding="utf-8",
    )
    assert RedosGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_redos_pragma(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text("import re\nP = re.compile(r'(a+)+')  # security: allow-redos\n", encoding="utf-8")
    assert RedosGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_redos_na_without_python() -> None:
    assert RedosGuard().applies(mkprofile(Path("/tmp"), features={"frontend"})) is False

def test_regex_injection_flags_fstring_pattern(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text("import re\ndef m(u):\n    return re.compile(f'^{u}$')\n", encoding="utf-8")
    findings = RedosGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "redos/regex-injection" and findings[0].severity == "medium"

def test_regex_injection_flags_concatenation(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text('import re\ndef m(u):\n    return re.match("^" + u + "$", "x")\n', encoding="utf-8")
    assert len(RedosGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_regex_injection_flags_format_call(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text('import re\ndef m(u):\n    return re.search("^{}$".format(u), "x")\n', encoding="utf-8")
    assert len(RedosGuard().run(tmp_path, _pyprof(tmp_path))) == 1

def test_regex_injection_passes_when_escaped(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text("import re\ndef m(u):\n    return re.compile(f'^{re.escape(u)}$')\n", encoding="utf-8")
    assert RedosGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_regex_injection_passes_static_pattern(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text("import re\nP = re.compile(r'^\\d{3}-\\d{4}$')\n", encoding="utf-8")
    assert RedosGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_regex_injection_pragma(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text(
        "import re\ndef m(u):\n    return re.compile(f'^{u}$')  # security: allow-redos\n", encoding="utf-8"
    )
    assert RedosGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_regex_injection_passes_constant_concatenation(tmp_path: Path) -> None:
    # #395 H2: config-driven composition from an ALL_CAPS module constant is not tainted.
    (tmp_path / "v.py").write_text(
        "import re\nBASE_PATTERN = r'[a-z]+'\nP = re.compile(BASE_PATTERN + '$')\n",
        encoding="utf-8",
    )
    assert RedosGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_regex_injection_passes_constant_fstring_bound(tmp_path: Path) -> None:
    # #395 H2: an f-string interpolating a config int constant is not tainted.
    (tmp_path / "v.py").write_text(
        "import re\nMAX_LEN = 64\nP = re.compile(f'^.{{1,{MAX_LEN}}}$')\n",
        encoding="utf-8",
    )
    assert RedosGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_regex_injection_trailing_comment_does_not_taint(tmp_path: Path) -> None:
    # #395 RM-1: a lowercase word in a TRAILING comment must not defeat the constant-exclusion —
    # the taint scan is bounded to the call's own arguments.
    (tmp_path / "v.py").write_text(
        "import re\nBASE_PATTERN = r'[a-z]+'\n"
        "p = re.compile(BASE_PATTERN + '$')  # legacy: previously validated user_input here\n",
        encoding="utf-8",
    )
    assert RedosGuard().run(tmp_path, _pyprof(tmp_path)) == []



def test_redos_flags_bounded_quantifier_before_alternation(tmp_path: Path) -> None:
    # Regression (#439 review): `_NESTED` gained the `[+*]`-before-alternation case but not
    # the bounded-quantifier one, so `(a{2,}|b)+` regressed OUT of detection while the
    # group-final `(a{2,})+` stayed in. Catastrophic backtracking confirmed on the missed
    # form — measured ~2.5x per two added characters.
    (tmp_path / "v.py").write_text("import re\nP = re.compile(r'(a{2,}|b)+$')\n", encoding="utf-8")
    findings = RedosGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1 and findings[0].rule == "redos/nested-quantifier"


def test_redos_scans_triple_quoted_verbose_pattern(tmp_path: Path) -> None:
    # Regression (#439 review): a `re.VERBOSE` pattern is triple-quoted by convention and is
    # real code, but the docstring-blanking pass erased it, so it stopped being scanned at
    # all. Resolved on the AST — a pattern passed to an `re.` call is code, wherever it sits.
    (tmp_path / "v.py").write_text(
        'import re\n'
        'PAT = re.compile(r"""\n'
        '    (a+)+          # nested quantifier\n'
        '""", re.VERBOSE)\n',
        encoding="utf-8",
    )
    findings = RedosGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1 and findings[0].rule == "redos/nested-quantifier"


def test_redos_silent_on_docstring_example_pattern(tmp_path: Path) -> None:
    # FP-bait for the above: an anti-pattern quoted in PROSE is not a compiled pattern.
    (tmp_path / "v.py").write_text(
        'def f():\n    """Never write re.compile(r"(a+)+") like this."""\n    return 1\n',
        encoding="utf-8",
    )
    assert RedosGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_redos_verbose_pattern_is_reported_once(tmp_path: Path) -> None:
    # The AST pass and the line scan must not both report the same single-line pattern.
    (tmp_path / "v.py").write_text("import re\nP = re.compile(r'(a+)+$')\n", encoding="utf-8")
    assert len(RedosGuard().run(tmp_path, _pyprof(tmp_path))) == 1


# --- #439 re-review: the linear-safe anchor does not have to be the group's FIRST element ---
# `(?:\s*\.\s*\w+)*` was flagged catastrophic because `_DISJOINT_SAFE` required the required
# separator at position 1, and this shape leads with an OPTIONAL `\s*`. Measured, it is flat
# linear (415 -> 6415 chars costs 0.145 -> 0.963 ms) where `(a+)+$` doubles per added character.
# The `-` in the separator class also appears inside ordinary classes like `[a-z]`, so the
# prefix rule admits only *-/?-quantified atoms; a generic prefix would exempt `([a-z]+)+`.


@pytest.mark.parametrize("pattern", [
    r"(?:\s*\.\s*[A-Za-z_$][\w$]*)*",   # the postmessage-origin shape that prompted this
    r"(?:\s*\.\d+)*",
    r"(?:[\d]?\.\w+)+",
])
def test_redos_optional_prefix_before_a_required_anchor_is_linear_safe(pattern: str) -> None:
    assert _NESTED.search(pattern), "precondition: the shape must look nested"
    assert _DISJOINT_SAFE.search(pattern), f"{pattern} is linear-safe and must be exempt"


@pytest.mark.parametrize("pattern", [
    r"([a-z]+)+",        # the '-' inside [a-z] must NOT buy an exemption
    r"([a-z0-9-]+)+",
    r"([\w-]+)*",
    r"(\s*\w+)+",        # an OPTIONAL separator cannot anchor iterations
    r"([\d]*\w+)+",
    r"(a+)+",
])
def test_redos_catastrophic_shapes_still_fire(pattern: str) -> None:
    assert _NESTED.search(pattern) and not _DISJOINT_SAFE.search(pattern), \
        f"{pattern} is catastrophic and must still be flagged"


# --- #688 / #689: regex-injection taint is resolved from BINDINGS, not from name case ---------
# Before #688 the taint test was a one-line identifier scan. A lowercase literal (`date_expr`) and a
# class literal read through `self.` (celery) both looked like input, an `re.escape` on the line
# above was invisible (#689), and the SUBJECT argument tainted every multi-argument call, so even
# `re.match(BASE + "$", value)` fired. It is a narrowing, so every SILENT case below has traded-
# direction twins in the STILL-FIRES table (review-doctrine Rule 1). A sink line that must fire is
# marked `# FIRES` in its fixture, so the expected lines can't drift from the source.


def _injection_lines(tmp_path: Path, src: str) -> list[int]:
    (tmp_path / "v.py").write_text(textwrap.dedent(src).lstrip("\n"), encoding="utf-8")
    findings = RedosGuard().run(tmp_path, _pyprof(tmp_path))
    return sorted(int(f.location.rsplit(":", 1)[1]) for f in findings if f.rule == "redos/regex-injection")


def _marked_lines(src: str) -> list[int]:
    lines = textwrap.dedent(src).lstrip("\n").splitlines()
    return [i for i, line in enumerate(lines, start=1) if line.endswith("# FIRES")]


_SILENT = {
    # celery/schedules.py:262-265: class-body literals read through `self.`
    "class-literal-via-self": r"""
        import re
        class crontab_parser:
            _range = r'(\w+?)-(\w+)'
            _steps = r'/(\w+)?'
            _star = r'\*'
            def __init__(self):
                self.pats = (
                    (re.compile(self._range + self._steps), self._range_steps),
                    (re.compile(self._range), self._expand_range),
                    (re.compile(self._star + self._steps), self._star_steps),
                    (re.compile('^' + self._star + '$'), self._expand_star),
                )
    """,
    # openai/_utils/_datetime_parse.py:21-22: lowercase module literals, one an implicit concat
    "module-literal-in-fstring": r"""
        import re
        date_expr = r"(?P<year>\d{4})-(?P<month>\d{1,2})-(?P<day>\d{1,2})"
        time_expr = (
            r"(?P<hour>\d{1,2}):(?P<minute>\d{1,2})"
            r"(?P<tzinfo>Z|[+-]\d{2}(?::?\d{2})?)?$"
        )
        date_re = re.compile(f"{date_expr}$")
        datetime_re = re.compile(f"{date_expr}[T ]{time_expr}")
    """,
    # #689, openai/tests/respx2/patterns.py:734,738: escaped on the line ABOVE, bound twice
    "escaped-on-previous-line": r"""
        import re
        def host_pattern(url):
            if url.host.startswith("*."):
                domain = re.escape(url.host[2:])
                return re.compile(f"^.+\\.{domain}$")
            domain = re.escape(url.host[1:])
            return re.compile(f"^(.+\\.)?{domain}$")
    """,
    # root cause 3: a constant pattern with a variable SUBJECT (or other trailing argument)
    "constant-pattern-variable-subject": r"""
        import re
        BASE = r"[a-z]+"
        def one(value):
            return re.match(BASE + "$", value)
        def two(text):
            return re.sub(f"^{BASE}", "", text)
        def three(parts, s):
            return re.split(BASE + ",", s, maxsplit=len(parts))
    """,
    # a literal composed from literals, and an int literal in a quantifier bound
    "composed-literal-chain": r"""
        import re
        a = r"[a-z]+"
        b = a + "-x"
        width = 3
        P = re.compile(f"{b}$")
        Q = re.compile(f"^\\d{{{width}}}$")
    """,
    # FP-bait for the per-call check (#1020 H1): two clean dynamic patterns on one line stay silent
    "two-clean-calls-on-a-line": r"""
        import re
        BASE = r"\d+"
        suffix = "$"
        def m(s):
            return re.match(BASE, s) and re.match(f"{BASE}{suffix}", s)
    """,
    # FP-bait for the quote-aware literals (#1020 M1): a quoted key on an ALL_CAPS receiver is a
    # constant read in an f-string field exactly as in a `+` operand, which was already silent
    "quoted-key-on-a-constant-receiver": """
        import re
        CONFIG = {"date": "[0-9-]+", "KEY": "x"}
        P = re.compile(f"^{CONFIG['date']}$")
        Q = re.compile("^" + CONFIG["date"] + "$")
        R = re.compile(f"{CONFIG['KEY']}-{CONFIG['date']}")
    """,
    # FP-bait for the field scanner (#1020 R2-M1): `{{`/`}}` escapes are literal text, not a field
    # (main read `{{literal}}` as a name), and a nested spec of constants or a quoted brace is clean
    "escaped-braces-are-not-fields": """
        import re
        BASE = "a"
        WIDTH = 3
        P = re.compile(f"{{literal}}{BASE}")
        Q = re.compile(f"^{{{BASE}}}$")
        R = re.compile(f"{BASE:{WIDTH}}")
        S = re.compile(f"{BASE + '}'}")
    """,
    # #1020 R2-L1: a `re.` call written in a trailing comment is not code
    "dynamic-call-in-a-trailing-comment": r"""
        import re
        BASE = r"\d+"
        def m(s):
            return re.match(BASE + "x", s)  # was: re.match(f"{u}", s)
    """,
    # #1020 R2-L2: a bare-variable pattern is never inspected (the documented call-site-only limit),
    # and sharing a line with a clean dynamic call does not change that
    "bare-variable-pattern-beside-a-dynamic-call": r"""
        import re
        BASE = r"\d+"
        def m(u, s):
            return re.match(u, s) and re.match(f"{BASE}", s)
    """,
    # FP-bait twin of the `apostrophe-in-literal-operand` widening below: a literal stays silent
    "apostrophe-in-literal-operand": """
        import re
        suffix = "x"
        def m():
            return re.match("A" + "B'C" + suffix, "Q")
    """,
}


@pytest.mark.parametrize("src", list(_SILENT.values()), ids=list(_SILENT))
def test_regex_injection_silent_on_literal_bindings(tmp_path: Path, src: str) -> None:
    assert _injection_lines(tmp_path, src) == []


_STILL_FIRES = {
    # the measured true positives (litellm factory.py:2794, langchain character.py:71) + the canary
    "parameter-interpolated": """
        import re
        def tags(tag, string):
            return re.findall(f"<{tag}>(.+?)</{tag}>", string, re.DOTALL)  # FIRES
        def split(separator, text):
            return re.split(f"({separator})", text)  # FIRES
        def build_matcher(user_input):
            return re.compile(f"^{user_input}$")  # FIRES
    """,
    # ag2 mcp/resources.py:84: unescaped group names appended to a list, then joined
    "joined-list-of-parts": """
        import re
        def compile_template(names):
            parts: list[str] = []
            for name in names:
                parts.append(f"(?P<{name}>[^/]+)")
            return re.compile("^" + "".join(parts) + "$")  # FIRES
    """,
    "literal-mixed-with-parameter": r"""
        import re
        suffix = r"\.txt"
        def m(u, s):
            return re.match(f"^{suffix}{u}$", s)  # FIRES
    """,
    # The one WIDENING (a true positive). Before #688 the quote-naive literal regex paired the
    # apostrophe with the subject's opening quote and swallowed `+ x,`. Scoping to the pattern
    # argument leaves no subject to pair with, and a literal now closes on its own quote char, so
    # `x` is seen.
    "apostrophe-in-literal-operand": """
        import re
        def m(x):
            return re.match("A" + "B'C" + x, "Q")  # FIRES
    """,
    "pattern-parameter-constant-subject": """
        import re
        def m(u):
            return re.match(u + "$", "fixed")  # FIRES
    """,
    "module-literal-rebound-via-global": """
        import re
        prefix = r"[a-z]+"
        def configure(p):
            global prefix
            prefix = p
        def m(s):
            return re.match(prefix + "$", s)  # FIRES
    """,
    # bindings are unioned module-wide, so the literal use ALSO fires: an accepted, fail-closed FP
    "name-is-literal-and-parameter": """
        import re
        tag = "b"
        def literal_use(s):
            return re.findall(f"<{tag}>", s)  # FIRES
        def param_use(tag, s):
            return re.findall(f"<{tag}>", s)  # FIRES
    """,
    "partial-escape": """
        import re
        def p(tag, s):
            t = re.escape(tag) + tag
            return re.findall(f"<{t}>", s)  # FIRES
    """,
    "escape-then-augassign": """
        import re
        def q(tag, s):
            t = re.escape(tag)
            t += tag
            return re.findall(f"<{t}>", s)  # FIRES
    """,
    "loop-target": """
        import re
        def m(user_patterns, s):
            for pat in user_patterns:
                re.match(pat + "$", s)  # FIRES
    """,
    "walrus-from-parameter": """
        import re
        def m(p, s):
            if (pat := p):
                return re.match(pat + "$", s)  # FIRES
    """,
    "tainted-format-spec": """
        import re
        A = "x"
        def m(fill, s):
            p = f"{A:{fill}>4}"
            return re.match(f"^{p}$", s)  # FIRES
    """,
    "imported-name": """
        import re
        from patterns import date_expr
        date_re = re.compile(f"{date_expr}$")  # FIRES
    """,
    "star-import-may-rebind": r"""
        import re
        date_expr = r"\d+"
        from config import *
        date_re = re.compile(f"{date_expr}$")  # FIRES
    """,
    "exec-may-rebind": r"""
        import re
        date_expr = r"\d+"
        exec(load_overrides())
        date_re = re.compile(f"{date_expr}$")  # FIRES
    """,
    "bare-escape-import-unrecognised": """
        import re
        from re import escape
        def m(host):
            domain = escape(host)
            return re.compile(f"^{domain}$")  # FIRES
    """,
    "dataclass-field-default": r"""
        import re
        from dataclasses import dataclass
        @dataclass
        class M:
            field_pat: str = r"\d+"
            def m(self, s):
                return re.match(self.field_pat + "$", s)  # FIRES
    """,
    # the inherited dataclass __init__ still sets `self.pat` from a constructor argument
    "plain-override-of-dataclass-field": r"""
        import re
        from dataclasses import dataclass
        @dataclass
        class Base:
            pat: str = r"\d+"
        class Sub(Base):
            pat = r"[a-z]+"
            def m(self, s):
                return re.match(self.pat + "$", s)  # FIRES
    """,
    "class-literal-overridden-in-init": r"""
        import re
        class A:
            pat = r"\d+"
            def __init__(self, p):
                self.pat = p
            def m(self, s):
                return re.match(self.pat + "$", s)  # FIRES
    """,
    "class-literal-overridden-externally": r"""
        import re
        class B:
            pat = r"\d+"
            def m(self, s):
                return re.match(self.pat + "$", s)  # FIRES
        def configure(o, v):
            o.pat = v
    """,
    "class-literal-set-via-setattr": r"""
        import re
        class Matcher:
            pat = r"\d+"
            def __init__(self, **kw):
                for k, v in kw.items():
                    setattr(self, k, v)
            def m(self, s):
                return re.match(self.pat + "$", s)  # FIRES
    """,
    "class-literal-set-via-dict-update": r"""
        import re
        class Matcher:
            pat = r"\d+"
            def __init__(self, **kw):
                self.__dict__.update(kw)
            def m(self, s):
                return re.match(self.pat + "$", s)  # FIRES
    """,
    # `self.pat` resolves against the ENCLOSING class only; a same-named literal elsewhere is no proof
    "same-attr-literal-in-another-class": r"""
        import re
        class Literal:
            pat = r"\d+"
        class Configured(ExternalBase):
            def m(self, s):
                return re.match(self.pat + "$", s)  # FIRES
    """,
    "non-self-receiver": r"""
        import re
        class C:
            pat = r"\d+"
            def m(self, other, s):
                return re.match(other.pat + "$", s)  # FIRES
        def m(obj, s):
            return re.match(obj.pat + "$", s)  # FIRES
    """,
    # #1020 H1: every dynamic `re.` call on a line is checked, not just the first one
    "second-call-on-the-line": r"""
        import re
        BASE = r"\d+"
        def m(u, s):
            return re.match(BASE, s) and re.match(f"{u}", s)  # FIRES
        def n(u, s):
            return re.match(r"^\d+$", s) or re.search("^" + u, s)  # FIRES
    """,
    # #1020 M1: a quote inside a field must not hide the receiver and leave only the key, which a
    # same-named clean literal would then clear
    "quoted-key-named-like-a-literal": """
        import re
        name = "x"
        q = "y"
        def m(data):
            return re.compile(f"^{data['name']}$")  # FIRES
        def n(request):
            return re.compile(f"^{request.args.get('q')}$")  # FIRES
        def o(config):
            return re.compile(f"^{config['date']}$")  # FIRES
    """,
    # same-quote nesting (legal since 3.12) cuts the literal short: the field is unreadable, so it fires
    "same-quote-string-inside-a-field": """
        import re
        name = "x"
        def m(data):
            return re.compile(f"^{data["name"]}$")  # FIRES
        def n(data):
            return re.compile(f"^{data["KEY"]}$")  # FIRES
    """,
    # A WIDENING (a true positive): before #1020 the quote-naive literal swallowed the receiver and
    # kept only the ALL_CAPS key, so this was silent on main too
    "quoted-constant-key-on-a-tainted-receiver": """
        import re
        def m(data):
            return re.compile(f"^{data['KEY']}$")  # FIRES
    """,
    # a quote char of the OTHER kind inside a literal operand must not pair across `+ key +`
    "other-quote-inside-a-literal-operand": """
        import re
        BASE = "a"
        def m(key, text):
            return re.search(BASE + "'" + key + "'", text)  # FIRES
    """,
    "module-locals-rebinding": """
        import re
        p = "a"
        locals()["p"] = input()
        r = re.match(p + "$", "s")  # FIRES
    """,
    "self-module-rebinding-via-sys-modules": """
        import re
        import sys
        p = "a"
        sys.modules[__name__].p = input()
        r = re.match(p + "$", "s")  # FIRES
    """,
    # #1020 R2-M1: a field holding a nested `{...}` or a brace inside a string is read whole, not
    # just its innermost clean run (`W`, `10`), and a nested f-string's own fields are read too
    "nested-or-quoted-braces-in-a-field": """
        import re
        W = 5
        def m(u, s):
            a = re.match(f"{u:{W}}", s)  # FIRES
            b = re.match(f"{u:>{10}}", s)  # FIRES
            c = re.match(f"{'}' + u}", s)  # FIRES
            d = re.match(f"{'{}'.format(u)}", s)  # FIRES
            e = re.match(f"{u!r:{W}}", s)  # FIRES
            g = re.match(f"{f'{u}'}", s)  # FIRES
    """,
    # twin of the `escaped-braces-are-not-fields` narrowing: a real field beside an escape still counts
    "escaped-braces-beside-a-tainted-field": """
        import re
        def m(u, s):
            return re.match(f"{{x}}{u}", s)  # FIRES
    """,
    # the trailing-comment cut must not clip a `#` that lives inside a string
    "hash-inside-a-string-is-not-a-comment": """
        import re
        def m(u, s):
            a = re.match("#" + u, s)  # FIRES
            b = re.match(f"#{u}", s)  # FIRES
    """,
    # #1020 R3-M1: a `#` in a same-quote nested key (3.12) fools the string mask the comment cut uses,
    # so a line holding an unreadable f-string is scanned whole rather than cut there
    "hash-in-a-same-quote-key-before-a-call": """
        import re
        def m(u, d):
            x = f"{d["#"]}" ; r = re.match(f"{u}", "s")  # FIRES
            y = f"{d["#"]}" ; t = re.match("a" + u, "s")  # FIRES
            z = f'{d['#']}' ; v = re.match("a" + u, "s")  # FIRES
    """,
    # an unparseable file keeps the line-only rule: a lowercase literal name still reads as taint
    "unparseable-file-keeps-line-rule": r"""
        import re
        date_expr = r"\d+"
        date_re = re.compile(f"{date_expr}$")  # FIRES
        def m(u):
            return re.compile(f'^{u}$')  # FIRES
        def broken(:
    """,
}


@pytest.mark.parametrize("src", list(_STILL_FIRES.values()), ids=list(_STILL_FIRES))
def test_regex_injection_still_fires_on_unresolved_bindings(tmp_path: Path, src: str) -> None:
    expected = _marked_lines(src)
    assert expected, "fixture must mark at least one sink line with `# FIRES`"
    assert _injection_lines(tmp_path, src) == expected


def test_redos_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040, all three checks: the pragma quoted in a string on the flagged line is not a comment.
    # Nested quantifier (line scan), regex injection, and a triple-quoted pattern (AST pass, which
    # the line scan cannot see once the string is blanked); neutral run = control.
    for note in ("# reviewed", "# security: allow-redos"):
        for source, rule in (
            (f"import re\nP = re.compile(r'(a+)+'); _note = \"{note}\"\n", "redos/nested-quantifier"),
            (f"import re\ndef m(u):\n    return re.compile(f'^{{u}}$'); _note = \"{note}\"\n", "redos/regex-injection"),
            (f'import re\nP = re.compile(r"""(a+)+""", re.X); _note = "{note}"\n', "redos/nested-quantifier"),
        ):
            (tmp_path / "v.py").write_text(source, encoding="utf-8")
            assert [f.rule for f in RedosGuard().run(tmp_path, _pyprof(tmp_path))] == [rule], (note, source)


def test_redos_triple_quoted_pattern_pragma_comment_on_the_call_line_still_suppresses(tmp_path: Path) -> None:
    # #1040 reach unchanged for the AST pass: a real comment on the `re.` call's first line still
    # silences a triple-quoted pattern opened there.
    for tail, n in (("", 1), ("  # security: allow-redos", 0)):
        (tmp_path / "v.py").write_text(
            f'import re\nP = re.compile({tail}\n    r"""\n    (a+)+\n    """,\n    re.X,\n)\n', encoding="utf-8"
        )
        assert len(RedosGuard().run(tmp_path, _pyprof(tmp_path))) == n, tail


# A form feed is a line break to `str.splitlines()` but not to Python or `ast`; inside a docstring
# the stripper blanks it, so a pragma set numbered on the raw text lands one line low (#1132).
_FF_DOCSTRING = f'"""doc{chr(12)}x\nmore"""\n'


def test_redos_pragma_comment_after_a_form_feed_docstring_stays_on_its_own_line(tmp_path: Path) -> None:
    # #1132 review (round 2, M1): the AST pass numbers by `ast`, so its pragma set must be the
    # stripped text's, like the line scan's. Both directions, on both passes.
    def count(above: str, call_tail: str, verbose: bool) -> int:
        call = (
            f'P = re.compile({call_tail}\n    r"""\n    (a+)+\n    """,\n    re.X,\n)\n' if verbose
            else f"P = re.compile(r'(a+)+'){call_tail}\n"
        )
        (tmp_path / "v.py").write_text(f"{_FF_DOCSTRING}import re\nX = 1{above}\n{call}", encoding="utf-8")
        return len(RedosGuard().run(tmp_path, _pyprof(tmp_path)))

    pragma = "  # security: allow-redos"
    for verbose in (False, True):
        assert count("", "", verbose) == 1, verbose  # control
        assert count("", pragma, verbose) == 0, verbose
        # The pragma on the line ABOVE the call must not silence it.
        assert count(pragma, "", verbose) == 1, verbose
