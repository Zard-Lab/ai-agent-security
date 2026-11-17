from __future__ import annotations

import struct
import tracemalloc
from pathlib import Path

import pytest

import agentsec.guards.ml_gguf_template_injection as gguf_guard
from agentsec.guards.ml_gguf_template_injection import (
    MlGgufTemplateInjectionGuard,
    jinja_threats_are_critical,
    scan_gguf_bytes,
    scan_jinja_template,
)
from tests._timing import assert_growth
from tests.conftest import mkprofile


def _gguf_string(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack("<Q", len(b)) + b


def _make_gguf(templates: dict[str, str], *, truncate_to: int | None = None) -> bytes:
    body = b"GGUF"
    body += struct.pack("<I", 3)              # version
    body += struct.pack("<Q", 0)               # tensor count
    body += struct.pack("<Q", len(templates))  # kv count
    for key, value in templates.items():
        body += _gguf_string(key)
        body += struct.pack("<I", 8)           # GGUF_TYPE_STRING
        body += _gguf_string(value)
    if truncate_to is not None:
        body = body[:truncate_to]
    return body


def test_scan_jinja_template_finds_sandbox_escape() -> None:
    threats = scan_jinja_template("{{ ''.__class__.__mro__[1].__subclasses__() }}")
    assert jinja_threats_are_critical(threats)


def test_scan_jinja_template_role_comparison_stays_silent() -> None:
    """'system' as a role-string comparison is not a call to os.system."""
    threats = scan_jinja_template("{% if message['role'] == 'system' %}{{ message['content'] }}{% endif %}")
    assert not jinja_threats_are_critical(threats)


def test_scan_gguf_bytes_finds_sandbox_escape() -> None:
    data = _make_gguf({"tokenizer.chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}"})
    threats, truncated = scan_gguf_bytes(data)
    assert jinja_threats_are_critical(threats)
    assert truncated is False


def test_scan_gguf_bytes_ordinary_template_stays_silent() -> None:
    data = _make_gguf({"tokenizer.chat_template": "{% for m in messages %}{{ m.content }}{% endfor %}"})
    threats, truncated = scan_gguf_bytes(data)
    assert threats == []
    assert truncated is False


def test_scan_gguf_bytes_non_gguf_stays_silent() -> None:
    threats, truncated = scan_gguf_bytes(b"not a gguf file at all")
    assert threats == []
    assert truncated is False


def test_scan_gguf_bytes_named_template_variant() -> None:
    """A model shipping more than one template variant gets each threat tagged
    with the key it came from -- a single template is reported untagged."""
    data = _make_gguf({
        "tokenizer.chat_template.default": "{% for m in messages %}{{ m.content }}{% endfor %}",
        "tokenizer.chat_template.tool_use": "{{ ''.__class__ }}",
    })
    threats, _ = scan_gguf_bytes(data)
    assert any("[tokenizer.chat_template.tool_use]" in t for t in threats)


def test_scan_gguf_bytes_truncated_metadata_reports_incomplete() -> None:
    full = _make_gguf({"tokenizer.chat_template": "{% for m in messages %}{{ m.content }}{% endfor %}"})
    data = full[: len(full) - 5]  # cut off mid-string
    threats, truncated = scan_gguf_bytes(data)
    assert threats == []
    assert truncated is True


def test_committed_gguf_sandbox_escape_fires_end_to_end(tmp_path: Path) -> None:
    data = _make_gguf({"tokenizer.chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}"})
    (tmp_path / "model.gguf").write_bytes(data)
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlGgufTemplateInjectionGuard().run(tmp_path, profile)
    assert any(f.rule == "ml-gguf-template-injection/sandbox-escape" for f in findings)


def test_ordinary_gguf_stays_silent_end_to_end(tmp_path: Path) -> None:
    data = _make_gguf({"tokenizer.chat_template": "{% for m in messages %}{{ m.content }}{% endfor %}"})
    (tmp_path / "model.gguf").write_bytes(data)
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlGgufTemplateInjectionGuard().run(tmp_path, profile)
    assert findings == []


def test_truncated_gguf_fires_incomplete_high_end_to_end(tmp_path: Path) -> None:
    full = _make_gguf({"tokenizer.chat_template": "{% for m in messages %}{{ m.content }}{% endfor %}"})
    (tmp_path / "model.gguf").write_bytes(full[: len(full) - 5])
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlGgufTemplateInjectionGuard().run(tmp_path, profile)
    assert any(f.rule == "ml-gguf-template-injection/metadata-incomplete" for f in findings)
    assert all(f.severity == "high" for f in findings)


def test_in_file_pragma_bytes_do_not_suppress(tmp_path: Path) -> None:
    """H3 (PR #1049 review): the artifact is the untrusted thing being judged, so a marker
    INSIDE it is attacker-controlled; a malicious model carried its own opt-out. Only the
    owner-side opt-outs (the exceptions file, `.agentsec/config.json` paths) suppress now."""
    data = _make_gguf({
        "tokenizer.chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}",
        "general.description": "security: allow-ml-gguf-template-injection",  # string metadata
    })
    (tmp_path / "model.gguf").write_bytes(data)
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlGgufTemplateInjectionGuard().run(tmp_path, profile)
    assert [(f.rule, f.severity) for f in findings] == [
        ("ml-gguf-template-injection/sandbox-escape", "critical")
    ]


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    data = _make_gguf({"tokenizer.chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}"})
    (fixtures / "sample.gguf").write_bytes(data)
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlGgufTemplateInjectionGuard().run(tmp_path, profile)
    assert findings == []


def test_does_not_apply_without_llm_feature(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features=set())
    assert MlGgufTemplateInjectionGuard().applies(profile) is False


def test_garbage_file_does_not_raise(tmp_path: Path) -> None:
    """Garbage GGUF-magic bytes with a bogus (huge) kv_count never crash the
    scan -- and correctly report MEDIUM "incomplete", not a false "clean"."""
    (tmp_path / "garbage.gguf").write_bytes(b"GGUF" + b"\xff" * 20)
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlGgufTemplateInjectionGuard().run(tmp_path, profile)
    assert all(f.rule == "ml-gguf-template-injection/metadata-incomplete" for f in findings)


def test_template_comment_and_literal_strip_is_linear() -> None:
    """H1 (PR #1049 review): `{#.*?#}` (DOTALL) and the backslash-alternation string-literal
    regex re-scanned to the end of the template from every unterminated opener, so a ~100 KB
    template stalled the guard for minutes (measured 143 s at `"{#" * 100_000`). Both shapes
    must now grow linearly; the absolute times are not asserted, only the growth class."""
    sizes = [4000, 8000, 16000, 32000]

    def comment_openers(n: int) -> None:
        scan_jinja_template("{#" * n)

    def escaped_literal_openers(n: int) -> None:
        scan_jinja_template("{{ " + "'a\\" * n)

    assert_growth(comment_openers, sizes, expected="linear")
    assert_growth(escaped_literal_openers, sizes, expected="linear")


@pytest.mark.parametrize(
    ("template", "critical"),
    [
        # A comment or a string literal hides a would-be call token: stays silent.
        ("{# eval(x) #}{{ m.content }}", False),
        ("{{ 'os.system(1)' }}", False),
        ('{{ "a \\" system(" }}', False),
        ("{{ 'it\\'s eval(' }}", False),
        ("{#a#}{# b #}{{ m['role'] == 'system' }}", False),
        # The same tokens OUTSIDE a literal/comment still fire.
        ("{# note #}{{ x.system('id') }}", True),
        ("{{ 'a' }}{{ eval('1') }}", True),
        # An unterminated comment or literal hides nothing after it.
        ("{# never closed {{ x.system('id') }}", True),
        ("{{ 'never closed }}{{ eval(1) }}", True),
        # A `"` literal after an unterminated `'` is still stripped.
        ("{{ 'open \"eval(\" }}", False),
    ],
)
def test_template_strip_keeps_literal_and_comment_semantics(template: str, critical: bool) -> None:
    assert jinja_threats_are_critical(scan_jinja_template(template)) is critical


def test_gguf_file_far_over_the_cap_is_not_loaded_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """H2 (PR #1049 review): `f.read_bytes()[:cap]` loaded a multi-GB model whole before slicing.
    The cap is patched to 64 KiB and the file is 16 MiB; tracemalloc's peak is the bound."""
    monkeypatch.setattr(gguf_guard, "_MAX_READ_BYTES", 64 * 1024)
    data = _make_gguf({"tokenizer.chat_template": "{{ ''.__class__.__mro__[1].__subclasses__() }}"})
    (tmp_path / "model.gguf").write_bytes(data + b"\x00" * (16 * 1024 * 1024))
    profile = mkprofile(tmp_path, features={"llm"})
    tracemalloc.start()
    try:
        rules = [f.rule for f in MlGgufTemplateInjectionGuard().run(tmp_path, profile)]
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert "ml-gguf-template-injection/sandbox-escape" in rules
    assert peak < 4 * 1024 * 1024, f"peak {peak} bytes: the whole file was read before the cap"


def test_an_unexpected_scanner_error_is_contained_per_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M1 (PR #1049 review), defence in depth: one file that breaks the scanner must not abort the
    run for every other file; it is reported `metadata-incomplete` instead."""
    real = gguf_guard.scan_gguf_bytes

    def flaky(blob: bytes) -> tuple[list[str], bool]:
        if b"BOOM" in blob:
            raise RecursionError("simulated")
        return real(blob)

    monkeypatch.setattr(gguf_guard, "scan_gguf_bytes", flaky)
    escape = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    (tmp_path / "a.gguf").write_bytes(_make_gguf({"tokenizer.chat_template": "BOOM"}))
    (tmp_path / "b.gguf").write_bytes(_make_gguf({"tokenizer.chat_template": escape}))
    profile = mkprofile(tmp_path, features={"llm"})
    rules = sorted(f.rule for f in MlGgufTemplateInjectionGuard().run(tmp_path, profile))
    assert rules == [
        "ml-gguf-template-injection/metadata-incomplete",
        "ml-gguf-template-injection/sandbox-escape",
    ]


# --- attribute-name false positives (PR #1049 review M3) --------------------------------------


@pytest.mark.parametrize(
    "template",
    [
        "{{ messages[0].system }}",
        "{% if message.system %}{{ message.system }}{% endif %}",
        "{% set joiner = ',' %}{{ joiner }}",
        "{{ ns.compile }}",
        "{% set pipe = joiner(' | ') %}{% for m in messages %}{{ pipe() }}{{ m.content }}{% endfor %}",
        "{% for m in messages %}{{ loop.cycle('a', 'b') }}{% endfor %}",
    ],
)
def test_benign_attribute_and_variable_names_stay_silent(template: str) -> None:
    """A field or variable named after a sink (`.system`, `.compile`, `joiner`) is not a call,
    and calling Jinja's own `joiner()` global is its designed use, not an escape."""
    assert not jinja_threats_are_critical(scan_jinja_template(template))


@pytest.mark.parametrize(
    "template",
    [
        "{{ x.__globals__ }}",
        "{{ lipsum.__globals__.os.popen('id').read() }}",
        "{{ cycler.__init__.__globals__.os.system('id') }}",
        "{{ self._TemplateReference__context.cycler }}",
        "{{ config.system('id') }}",
        "{{ x.os.popen ('id') }}",
        "{{ lipsum . os }}",
        "{{ joiner.x }}",
        "{{ subprocess.check_output(['id']) }}",
    ],
)
def test_real_escape_shapes_still_fire(template: str) -> None:
    """Still-fires for the M3 narrowing: dunder traversal, a real `.system(`/`.popen(` call, and
    attribute traversal off a context-leaking global."""
    assert jinja_threats_are_critical(scan_jinja_template(template))


# --- the whole template is scanned (re-review round 2, H5) -----------------------------------


def test_payload_past_256_kib_of_template_fires(tmp_path: Path) -> None:
    """The template was cut at 256 KiB with only a non-critical JINJA_TEMPLATE_TRUNCATED note, and
    no finding at all followed: padding the template hid the escape. The strip is linear now, so
    the whole template (bounded by the read cap) is scanned."""
    template = " " * 300_000 + "{{ ''.__class__.__mro__ }}"
    (tmp_path / "model.gguf").write_bytes(_make_gguf({"tokenizer.chat_template": template}))
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlGgufTemplateInjectionGuard().run(tmp_path, profile)
    assert [(f.rule, f.severity) for f in findings] == [("ml-gguf-template-injection/sandbox-escape", "critical")]


def test_cut_metadata_with_only_non_critical_threats_is_reported_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-critical threat (template inclusion) must not suppress the incomplete signal when the
    read cap cut the metadata: the cut part may hold the escape."""
    monkeypatch.setattr(gguf_guard, "_MAX_READ_BYTES", 64 * 1024)
    data = _make_gguf({
        "tokenizer.chat_template.a": "{% include 'other.j2' %}",
        "tokenizer.chat_template.b": " " * 100_000 + "{{ ''.__class__ }}",
    })
    (tmp_path / "model.gguf").write_bytes(data)
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlGgufTemplateInjectionGuard().run(tmp_path, profile)
    assert [(f.rule, f.severity) for f in findings] == [("ml-gguf-template-injection/metadata-incomplete", "high")]


# --- subscript and filter forms (re-review round 2, M1) --------------------------------------


@pytest.mark.parametrize(
    "template",
    [
        "{{ lipsum['__glo'~'bals__']['os']['popen']('id')['read']() }}",
        "{{ cycler['__in'~'it__'] }}",
        "{{ joiner [ 'x' ] }}",
        "{{ x['system']('id') }}",
        '{{ x["popen"] ("id") }}',
        "{{ x|attr('system') }}",
        "{{ x | attr('sys' ~ 'tem')('id') }}",
    ],
)
def test_subscript_and_filter_escape_forms_fire(template: str) -> None:
    """Still-fires for the M3 narrowing: those required an attribute DOT, and the subscript form
    (with string concatenation splitting the dunder) went silent, though 7726c6f7 fired on it."""
    assert jinja_threats_are_critical(scan_jinja_template(template))


@pytest.mark.parametrize(
    "template",
    [
        "{{ messages['system'] }}",
        "{% if message['role'] == 'system' %}{{ message['content'] }}{% endif %}",
        "{% set joiner = ',' %}{{ joiner }}",
        "{% set pipe = joiner(' | ') %}{{ pipe() }}",
        "{{ message['content'] | trim }}",
    ],
)
def test_subscript_reads_and_benign_names_stay_silent(template: str) -> None:
    """FP-bait for the widening: a subscript READ of a sink-named key is not a call."""
    assert not jinja_threats_are_critical(scan_jinja_template(template))


def test_subscript_call_pattern_lists_every_dangerous_call() -> None:
    """`_SUBSCRIPT_CALL` is written out literally (so the ReDoS linter resolves it); keep it equal
    to `_DANGEROUS_CALLS`."""
    for token in gguf_guard._DANGEROUS_CALLS:
        assert gguf_guard._SUBSCRIPT_CALL.search(f"x['{token}'](1)"), token


# --- final reviewer blockers B1 / B2 ------------------------------------------------------------
_ESCAPE_TEMPLATE = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
_BENIGN_TEMPLATE = "{% for m in messages %}{{ m.content }}{% endfor %}"


def _make_gguf_pairs(pairs: list[tuple[str, str]]) -> bytes:
    """Like `_make_gguf`, but a key may repeat (a dict cannot express that)."""
    body = b"GGUF" + struct.pack("<IQQ", 3, 0, len(pairs))
    return body + b"".join(_gguf_string(k) + struct.pack("<I", 8) + _gguf_string(v) for k, v in pairs)


def _gguf_rules(root: Path) -> list[tuple[str, str]]:
    findings = MlGgufTemplateInjectionGuard().run(root, mkprofile(root, features={"llm"}))
    return [(f.rule, f.severity) for f in findings]


_SANDBOX_ESCAPE = ("ml-gguf-template-injection/sandbox-escape", "critical")


def test_a_malicious_named_variant_next_to_a_benign_default_fires(tmp_path: Path) -> None:
    """B1: with more than one template, threats were tagged `"[key] JINJA_..."` and the critical
    check reads the PREFIX, so a malicious `tool_use` variant next to a benign default produced
    NO finding. Asserts the finding, not only the threat strings."""
    data = _make_gguf_pairs([
        ("tokenizer.chat_template", _BENIGN_TEMPLATE),
        ("tokenizer.chat_template.tool_use", _ESCAPE_TEMPLATE),
    ])
    (tmp_path / "model.gguf").write_bytes(data)
    assert _gguf_rules(tmp_path) == [_SANDBOX_ESCAPE]


def test_named_variant_tag_survives_a_key_containing_a_bracket() -> None:
    """The variant tag is a suffix, so a key containing `]` cannot break the critical check."""
    data = _make_gguf_pairs([
        ("tokenizer.chat_template", _BENIGN_TEMPLATE),
        ("tokenizer.chat_template.a] JINJA_X", _ESCAPE_TEMPLATE),
    ])
    threats, _ = scan_gguf_bytes(data)
    assert jinja_threats_are_critical(threats)


def test_benign_named_variants_stay_silent(tmp_path: Path) -> None:
    """FP-bait: several benign variants produce nothing."""
    data = _make_gguf_pairs([
        ("tokenizer.chat_template", _BENIGN_TEMPLATE),
        ("tokenizer.chat_template.tool_use", "{{ messages[0]['content'] }}"),
    ])
    (tmp_path / "model.gguf").write_bytes(data)
    assert _gguf_rules(tmp_path) == []


@pytest.mark.parametrize("evil_first", [True, False], ids=["evil_first", "evil_last"])
def test_every_duplicate_chat_template_key_is_judged(tmp_path: Path, evil_first: bool) -> None:
    """B2: a repeated `tokenizer.chat_template` key kept only the LAST value (`values[key] =`), so
    an evil FIRST copy was silent. Readers disagree on which copy wins; every copy is judged."""
    pairs = [("tokenizer.chat_template", _ESCAPE_TEMPLATE), ("tokenizer.chat_template", _BENIGN_TEMPLATE)]
    (tmp_path / "model.gguf").write_bytes(_make_gguf_pairs(pairs if evil_first else pairs[::-1]))
    assert _gguf_rules(tmp_path) == [_SANDBOX_ESCAPE]


def test_the_incomplete_finding_names_the_owner_opt_outs(tmp_path: Path) -> None:
    """F2: a fail-closed HIGH must tell the owner how to accept an audited artifact."""
    (tmp_path / "model.gguf").write_bytes(b"GGUF" + b"\xff" * 20)
    [finding] = MlGgufTemplateInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert "agentsec-exceptions.json" in finding.remediation and "nonproduct_paths" in finding.remediation


# --- re-review of the blocker pass: B-1 and F-3 -------------------------------------------------


def test_an_attr_filter_only_variant_next_to_a_benign_default_fires(tmp_path: Path) -> None:
    """B-1 (the clause B1 missed): `jinja_threats_are_critical` tested `t == "JINJA_ATTR_FILTER"`,
    so the suffix-tagged `"JINJA_ATTR_FILTER [tokenizer.chat_template.rag]"` was not critical and a
    benign default plus an attr-filter-only variant read CLEAN."""
    data = _make_gguf_pairs([
        ("tokenizer.chat_template", _BENIGN_TEMPLATE),
        ("tokenizer.chat_template.rag", "{{ x|attr(n)() }}"),
    ])
    (tmp_path / "model.gguf").write_bytes(data)
    assert _gguf_rules(tmp_path) == [_SANDBOX_ESCAPE]


@pytest.mark.parametrize(
    "template",
    ["{{ ''.__class__ }}", "{{ x|attr(n)() }}", "{{ eval(1) }}", "{{ lipsum.os }}"],
    ids=["escape", "attr_filter", "dangerous_call", "context_leak"],
)
def test_every_critical_kind_stays_critical_when_tagged(template: str) -> None:
    """Every critical threat kind, tagged with a variant key, still reads as critical."""
    threats, _ = scan_gguf_bytes(_make_gguf_pairs([
        ("tokenizer.chat_template", _BENIGN_TEMPLATE), ("tokenizer.chat_template.v", template),
    ]))
    assert threats and all(t.endswith("[tokenizer.chat_template.v]") for t in threats)
    assert jinja_threats_are_critical(threats)


def test_many_distinct_template_keys_are_merged_in_linear_time() -> None:
    """F-3: `if tagged not in threats` tested membership on a list, so n distinct
    `tokenizer.chat_template.k<i>` keys cost O(n^2) (40,000 keys: 155 s; the 8 MiB cap allows about
    8 minutes). A set beside the ordered list makes it linear."""
    from tests._timing import assert_growth

    # NOT halved (2026-10-23): at [2000..16000] the list-membership mutant read 2.88-3.88 per x2 step
    # against the 2.83 linear edge, too close to the cliff for a test whose job is to catch it (#1145
    # review). The speedup kept is `_make_gguf_pairs` no longer being quadratic itself.
    sizes = [4000, 8000, 16000, 32000]
    blobs = {n: _make_gguf_pairs([(f"tokenizer.chat_template.k{i}", "{{ __class__ }}") for i in range(n)]) for n in sizes}
    found: dict[int, int] = {}

    def scan(n: int) -> None:
        found[n] = len(scan_gguf_bytes(blobs[n])[0])

    assert_growth(scan, sizes, expected="linear")
    assert all(found[n] == n for n in sizes), found
