from __future__ import annotations

from agentsec.guards.target_blank_noopener import TargetBlankNoopenerGuard
from tests.guards._common import *  # noqa: F401,F403


def test_target_blank_noopener_flags_missing_rel(tmp_path: Path) -> None:
    (tmp_path / "page.html").write_text(
        '<a href="http://x.com" target="_blank">X</a>', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = TargetBlankNoopenerGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "target-blank-noopener/missing-rel-noopener"
    assert findings[0].severity == "medium"

def test_target_blank_noopener_flags_jsx_variant(tmp_path: Path) -> None:
    (tmp_path / "Link.tsx").write_text(
        "<a href={url} target={'_blank'}>link</a>", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = TargetBlankNoopenerGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "target-blank-noopener/missing-rel-noopener"

def test_target_blank_noopener_silent_with_noopener_noreferrer(tmp_path: Path) -> None:
    (tmp_path / "page.jsx").write_text(
        '<a href={url} target="_blank" rel="noopener noreferrer">safe</a>',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = TargetBlankNoopenerGuard().run(tmp_path, profile)
    assert findings == []

def test_target_blank_noopener_silent_with_noopener_only(tmp_path: Path) -> None:
    (tmp_path / "page.jsx").write_text(
        '<a href="x" target="_blank" rel="noopener">also safe</a>',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = TargetBlankNoopenerGuard().run(tmp_path, profile)
    assert findings == []

def test_target_blank_noopener_silent_with_noreferrer_only(tmp_path: Path) -> None:
    # backlog #4: `rel="noreferrer"` alone satisfies the control — noreferrer implies noopener in
    # every modern browser. Must be silent (was 1 FP on a RAG app).
    (tmp_path / "page.jsx").write_text(
        '<a href="x" target="_blank" rel="noreferrer">safe</a>',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert TargetBlankNoopenerGuard().run(tmp_path, profile) == []

def test_target_blank_noopener_silent_with_noreferrer_jsx_brace(tmp_path: Path) -> None:
    (tmp_path / "Link.tsx").write_text(
        "<a href={url} target=\"_blank\" rel={'noreferrer'}>safe</a>",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert TargetBlankNoopenerGuard().run(tmp_path, profile) == []

def test_target_blank_noopener_silent_with_multiline_rel(tmp_path: Path) -> None:
    # T4 precision: Prettier puts each attribute on its own line — `rel` lands on the line
    # after `target`. The enclosing-element check must see it (was a false positive).
    (tmp_path / "page.tsx").write_text(
        "<a\n"
        '  href={url}\n'
        '  target="_blank"\n'
        '  rel="noopener noreferrer"\n'
        ">\n"
        "  open\n"
        "</a>\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert TargetBlankNoopenerGuard().run(tmp_path, profile) == []

def test_target_blank_noopener_flags_multiline_without_rel(tmp_path: Path) -> None:
    # ...but a genuinely missing rel on a multiline element MUST still fire (no over-suppression).
    (tmp_path / "page.tsx").write_text(
        "<a\n"
        '  href={url}\n'
        '  target="_blank"\n'
        ">\n"
        "  open\n"
        "</a>\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = TargetBlankNoopenerGuard().run(tmp_path, profile)
    assert len(findings) == 1 and findings[0].rule == "target-blank-noopener/missing-rel-noopener"

def test_target_blank_noopener_arrow_attr_does_not_truncate(tmp_path: Path) -> None:
    # an onClick arrow before the close must not truncate the element span and hide a real miss
    (tmp_path / "page.tsx").write_text(
        '<a href={url} onClick={() => track()} target="_blank">x</a>\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert len(TargetBlankNoopenerGuard().run(tmp_path, profile)) == 1

def test_target_blank_noopener_pragma_silences(tmp_path: Path) -> None:
    content = (
        "// security: allow-target-blank\n"
        '<a href="http://x.com" target="_blank">bad</a>\n'
    )
    (tmp_path / "page.jsx").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = TargetBlankNoopenerGuard().run(tmp_path, profile)
    assert findings == []

def test_target_blank_noopener_applies_gate(tmp_path: Path) -> None:
    (tmp_path / "page.jsx").write_text(
        '<a href={url} target="_blank">link</a>', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    assert TargetBlankNoopenerGuard().applies(profile) is False


def test_target_blank_rel_token_must_be_in_the_rel_attribute(tmp_path: Path) -> None:
    # Regression (#471 review): `noreferrer`/`noopener` were searched as a SUBSTRING over the
    # whole element, so an unrelated attribute value satisfied the control — a `data-testid`, an
    # `aria-label`, even a variable name — and an anchor with NO `rel` at all was reported safe.
    (tmp_path / "a.jsx").write_text(
        '<a href="https://x.com" target="_blank" data-testid="noreferrer-link">go</a>\n',
        encoding="utf-8",
    )
    (tmp_path / "b.jsx").write_text(
        '<a href="https://x.com" target="_blank" aria-label="opens noopener docs">go</a>\n',
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"frontend"})
    assert len(TargetBlankNoopenerGuard().run(tmp_path, prof)) == 2


def test_target_blank_real_rel_spellings_all_suppress(tmp_path: Path) -> None:
    # FP-bait: the value is extracted and tested, so every ordinary React spelling still counts —
    # quoted, JSX brace, template literal, and Prettier's multi-line layout.
    for name, src in (
        ("a.jsx", '<a href="https://x.com" target="_blank" rel="noopener noreferrer">go</a>\n'),
        ("b.jsx", '<a href="https://x.com" target="_blank" rel="noreferrer">go</a>\n'),
        ("c.jsx", '<a href="https://x.com" target="_blank" rel={"noopener"}>go</a>\n'),
        ("d.jsx", '<a href="https://x.com" target="_blank" rel={`noopener noreferrer`}>go</a>\n'),
        ("e.jsx", '<a\n  href="https://x.com"\n  target="_blank"\n  rel="noopener noreferrer"\n>go</a>\n'),
    ):
        (tmp_path / name).write_text(src, encoding="utf-8")
    prof = mkprofile(tmp_path, features={"frontend"})
    assert TargetBlankNoopenerGuard().run(tmp_path, prof) == []


def test_target_blank_hyphenated_attribute_is_not_a_rel(tmp_path: Path) -> None:
    # Regression (#471 review round 2, HIGH): the attribute name was anchored with `\b`, which
    # treats `-` as a word boundary, so the pattern matched the TAIL of any hyphenated attribute.
    # `<a target="_blank" data-rel="noopener">` has no real `rel` at all and was reported safe.
    # `data-rel` is a real attribute (jQuery lightbox / gallery plugins). Same bug class the
    # value-extraction closed for `data-testid`, in the spelling that pass did not test.
    for name, src in (
        ("a.jsx", '<a href="https://x.com" target="_blank" data-rel="noopener">go</a>\n'),
        ("b.jsx", '<a href="https://x.com" target="_blank" aria-rel="noreferrer">go</a>\n'),
        ("c.jsx", '<a href="https://x.com" target="_blank" x-rel={"noopener"}>go</a>\n'),
    ):
        (tmp_path / name).write_text(src, encoding="utf-8")
    prof = mkprofile(tmp_path, features={"frontend"})
    assert len(TargetBlankNoopenerGuard().run(tmp_path, prof)) == 3


def test_target_blank_uppercase_rel_token_still_suppresses(tmp_path: Path) -> None:
    # FP-bait for the substring pre-check in `_rel_protects`. The token regex is IGNORECASE, so
    # a case-sensitive reject would silently un-suppress an uppercase `rel` that the guard has
    # always treated as safe. HTML attribute values are case-insensitive for `rel`, and shouting
    # attribute values do occur in hand-written markup. This arm fails if the `.lower()` is
    # dropped from the pre-check while the rest of the function keeps working.
    (tmp_path / "a.html").write_text(
        '<a href="https://x.com" target="_blank" rel="NOOPENER NOREFERRER">go</a>\n',
        encoding="utf-8",
    )
    (tmp_path / "b.html").write_text(
        '<a href="https://x.com" target="_blank" rel="NoReferrer">go</a>\n',
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"frontend"})
    assert TargetBlankNoopenerGuard().run(tmp_path, prof) == []


def test_target_blank_hostile_bracketless_file_is_linear(tmp_path: Path) -> None:
    # Regression (issue #419): on a hostile many-match file two per-match costs went quadratic —
    # the enclosing-element rfind/find (now bounded to a 4 KB window) AND the line-number
    # `text.count("\n", 0, m.start())` that re-scanned from offset 0 every match (now counted
    # incrementally). `rel()` is also hoisted per-file. Actual ~0.1s; quadratic takes minutes.
    import time

    (tmp_path / "hostile.html").write_text('target="_blank" ' * 30_000, encoding="utf-8")
    start = time.monotonic()
    findings = TargetBlankNoopenerGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert time.monotonic() - start < 5.0, "unbounded element-span scan reintroduced"
    assert len(findings) == 30_000  # every un-noopener'd match still fires
