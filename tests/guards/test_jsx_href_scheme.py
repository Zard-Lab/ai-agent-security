from __future__ import annotations

import pytest

from agentsec.findings import Finding
from agentsec.guards.jsx_href_scheme import JsxHrefSchemeGuard
from tests.guards._common import *  # noqa: F401,F403


def test_jsx_href_scheme_flags_href_var(tmp_path: Path) -> None:
    (tmp_path / "link.jsx").write_text("<a href={userUrl}>link</a>", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = JsxHrefSchemeGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "jsx-href-scheme/href-dynamic-no-scheme-check"
    assert findings[0].severity == "high"
    assert findings[0].standards == ["OWASP:A03", "CWE-79"]

def test_jsx_href_scheme_flags_href_not_img_src(tmp_path: Path) -> None:
    # href is a javascript:-scheme XSS vector; img/source `src` is NOT (intentional scope
    # reduction — `src={...}` on images was the dominant false positive).
    (tmp_path / "img.tsx").write_text("<img src={data.imageUrl} />", encoding="utf-8")
    (tmp_path / "link.tsx").write_text("<a href={data.url}>go</a>", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = JsxHrefSchemeGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].location.startswith("link.tsx")
    assert findings[0].rule == "jsx-href-scheme/href-dynamic-no-scheme-check"

def test_jsx_href_scheme_silent_when_validated_nearby(tmp_path: Path) -> None:
    # the scheme check is on a preceding line — the ±3-line window must see it (no FP on
    # already-sanitized code).
    (tmp_path / "safe.tsx").write_text(
        "const safeHref = /^https?:\\/\\//i.test(u) ? u : '#'\n"
        "return <a href={safeHref}>go</a>\n",
        encoding="utf-8",
    )
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []

def test_jsx_href_scheme_ignores_custom_src_prop(tmp_path: Path) -> None:
    # word-boundary: `imageSrc={...}` is a custom prop, not a DOM src attribute.
    (tmp_path / "c.tsx").write_text("<Avatar imageSrc={cropSrc} />", encoding="utf-8")
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []

def test_jsx_href_scheme_flags_action_var(tmp_path: Path) -> None:
    (tmp_path / "form.jsx").write_text("<form action={redirectUrl}>", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = JsxHrefSchemeGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "jsx-href-scheme/href-dynamic-no-scheme-check"

def test_jsx_href_scheme_silent_static_href(tmp_path: Path) -> None:
    (tmp_path / "safe.jsx").write_text('<a href="/static/page">link</a>', encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = JsxHrefSchemeGuard().run(tmp_path, profile)
    assert findings == []

def test_jsx_href_scheme_silent_screaming_case_constant(tmp_path: Path) -> None:
    # T4 precision: a SCREAMING_CASE-rooted route constant is author-defined, not attacker input.
    (tmp_path / "nav.tsx").write_text(
        "<a href={ROUTES.HOME}>home</a>\n<a href={PATHS.login}>in</a>\n<a href={API_BASE}>api</a>\n",
        encoding="utf-8",
    )
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []

def test_jsx_href_scheme_still_flags_lowercase_and_indexed(tmp_path: Path) -> None:
    # ...but a lowercase-rooted member (user input) or an indexed expr MUST still fire (no FN).
    (tmp_path / "x.tsx").write_text(
        "<a href={user.website}>site</a>\n<a href={match[3]}>m</a>\n", encoding="utf-8"
    )
    findings = JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 2

def test_jsx_href_scheme_silent_https_href(tmp_path: Path) -> None:
    (tmp_path / "external.jsx").write_text('<a href="https://example.com">external</a>', encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = JsxHrefSchemeGuard().run(tmp_path, profile)
    assert findings == []

def test_jsx_href_scheme_silent_sanitize(tmp_path: Path) -> None:
    (tmp_path / "comp.jsx").write_text("<a href={sanitizeUrl(userUrl)}>safe</a>", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = JsxHrefSchemeGuard().run(tmp_path, profile)
    assert findings == []

def test_jsx_href_scheme_pragma_silences(tmp_path: Path) -> None:
    content = "// security: allow-jsx-href-scheme\n<a href={userUrl}>link</a>\n"
    (tmp_path / "guarded.jsx").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = JsxHrefSchemeGuard().run(tmp_path, profile)
    assert findings == []

def test_jsx_href_scheme_not_applies_no_frontend(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    assert JsxHrefSchemeGuard().applies(profile) is False

def test_jsx_href_scheme_template_literal_relative_silent(tmp_path: Path) -> None:
    # Precision fix: template literals starting with / are relative paths — javascript:
    # injection is not possible; guard should not fire.
    (tmp_path / "nav.tsx").write_text(
        "export const NavLink = ({ section }: Props) => (\n"
        "  <a href={`/dashboard/${section}`}>click</a>\n"
        ");\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert JsxHrefSchemeGuard().run(tmp_path, profile) == []

def test_jsx_href_scheme_template_literal_https_silent(tmp_path: Path) -> None:
    # Template literals starting with https:// are always safe.
    (tmp_path / "link.tsx").write_text(
        'const url = `https://example.com/${id}`;\n'
        "<a href={`https://example.com/${id}`}>link</a>\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert JsxHrefSchemeGuard().run(tmp_path, profile) == []


def test_jsx_href_scheme_silent_camelcase_const_declared(tmp_path: Path) -> None:
    # corpus scan: 5/5 sampled false positives were developer-authored navigation
    # constants NOT in SCREAMING_CASE — a camelCase `const` assigned a safe-prefixed literal.
    (tmp_path / "nav.tsx").write_text(
        'const homeLink = "/home";\n<a href={homeLink}>home</a>\n', encoding="utf-8"
    )
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []

def test_jsx_href_scheme_silent_pascalcase_const_declared(tmp_path: Path) -> None:
    # Same false-positive shape, PascalCase name.
    (tmp_path / "nav.tsx").write_text(
        'const HomeRoute = "https://example.com/home";\n<a href={HomeRoute}>home</a>\n',
        encoding="utf-8",
    )
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []

def test_jsx_href_scheme_silent_typescript_annotated_const(tmp_path: Path) -> None:
    # A TypeScript `: string` annotation on the const declaration must not block recognition.
    (tmp_path / "nav.tsx").write_text(
        'const dashboardPath: string = "/dashboard";\n<a href={dashboardPath}>go</a>\n',
        encoding="utf-8",
    )
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []

# ── widening still fires on a genuinely unsafe case (FP-bait, not just noise reduction) ─────

def test_jsx_href_scheme_still_fires_non_literal_const(tmp_path: Path) -> None:
    # A `const` is only safe when it is assigned a STRING LITERAL — one assigned a function
    # call's return value is still exactly as dynamic/attacker-reachable as any other variable.
    (tmp_path / "nav.tsx").write_text(
        "const userUrl = getUserInput();\n<a href={userUrl}>go</a>\n", encoding="utf-8"
    )
    findings = JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].rule == "jsx-href-scheme/href-dynamic-no-scheme-check"

def test_jsx_href_scheme_still_fires_let_declared_binding(tmp_path: Path) -> None:
    # `let`/`var` are reassignable — even a safe-looking initial value proves nothing about what
    # flows through the binding by the time it reaches href, so these must still fire.
    (tmp_path / "nav.tsx").write_text(
        'let homeLink = "/home";\nhomeLink = attackerInput;\n<a href={homeLink}>go</a>\n',
        encoding="utf-8",
    )
    findings = JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].rule == "jsx-href-scheme/href-dynamic-no-scheme-check"

def test_jsx_href_scheme_still_fires_const_with_unsafe_scheme_literal(tmp_path: Path) -> None:
    # An author-written `const` literal that itself starts with an unsafe scheme is a real bug
    # (self-XSS / a planted backdoor constant) — the const-declaration widening must not shield
    # a `javascript:` literal just because it's assigned to a name first.
    (tmp_path / "nav.tsx").write_text(
        'const evilLink = "javascript:alert(1)";\n<a href={evilLink}>go</a>\n', encoding="utf-8"
    )
    findings = JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].rule == "jsx-href-scheme/href-dynamic-no-scheme-check"


def test_jsx_href_scheme_prop_shadowing_top_level_const_still_fires(tmp_path: Path) -> None:
    # Real false negative found by review: a caller-controlled prop shares a name with an
    # UNRELATED top-level `const` elsewhere in the file — JS scoping means the destructured prop
    # parameter shadows the outer const inside this function, so the outer declaration is not
    # actually what flows into this usage. `safe_const_names` used to be file-wide with no
    # scoping, so this silently suppressed a genuine attacker-controlled href. Must still fire.
    (tmp_path / "nav.tsx").write_text(
        'const homeLink = "/home";\n'
        "function NavLink({ homeLink }) {\n"
        "  return <a href={homeLink}>Home</a>;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].rule == "jsx-href-scheme/href-dynamic-no-scheme-check"


def test_jsx_href_scheme_prop_shadowing_control_no_top_level_const(tmp_path: Path) -> None:
    # Control for the shadowing test above: identical prop shape, but with no same-named const
    # anywhere in the file, proving the guard fires on this shape on its own — isolates that the
    # shadow-detection path (not some other change) is what the test above exercises.
    (tmp_path / "nav.tsx").write_text(
        "function NavLink({ homeLink }) {\n"
        "  return <a href={homeLink}>Home</a>;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1


def test_jsx_href_scheme_genuine_same_scope_const_use_stays_silent(tmp_path: Path) -> None:
    # Genuine safe const use, declared and used in the same function with no shadowing prop —
    # must remain silent (no FP regression from the shadow-detection fix).
    (tmp_path / "nav.tsx").write_text(
        "function NavLink() {\n"
        '  const homeLink = "/home";\n'
        "  return <a href={homeLink}>Home</a>;\n"
        "}\n",
        encoding="utf-8",
    )
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_jsx_href_scheme_cross_component_const_reference_stays_silent(tmp_path: Path) -> None:
    # A genuine cross-component reference to a module-level const (no shadowing parameter in the
    # referencing function) must stay silent — the shadow fix must not over-narrow to "same
    # function only".
    (tmp_path / "nav.tsx").write_text(
        'const homeLink = "/home";\n'
        "function Footer() {\n"
        "  return <a href={homeLink}>Home</a>;\n"
        "}\n",
        encoding="utf-8",
    )
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_jsx_href_scheme_prop_shadowing_concise_arrow_body_still_fires(tmp_path: Path) -> None:
    # Residual found by review (fix-commit round): a concise (expression-body) arrow component
    # puts its signature and its usage on the SAME line, e.g.
    # `const C = ({ homeLink }) => <a href={homeLink}>x</a>;`. The shadow-detection search used
    # to anchor at the USAGE LINE'S START, which for a same-line signature excludes it entirely
    # (the signature sits after the line start in text order, so the [0, line_start) window never
    # reaches it) -- a real false negative, this is one of the most common React component shapes.
    (tmp_path / "nav.tsx").write_text(
        'const homeLink = "/home";\n'
        "const C = ({ homeLink }) => <a href={homeLink}>x</a>;\n",
        encoding="utf-8",
    )
    findings = JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].rule == "jsx-href-scheme/href-dynamic-no-scheme-check"


def test_jsx_href_scheme_concise_arrow_no_shadow_stays_silent(tmp_path: Path) -> None:
    # Control: the same concise-arrow shape, but the prop name does NOT collide with any
    # module-level const -- must stay silent like any other genuine safe const use.
    (tmp_path / "nav.tsx").write_text(
        'const officeLink = "/office";\n'
        "const C = ({ homeLink }) => <a href={officeLink}>x</a>;\n",
        encoding="utf-8",
    )
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_jsx_href_scheme_concise_arrow_genuine_const_use_stays_silent(tmp_path: Path) -> None:
    # A concise arrow component genuinely referencing the module-level const it's named after
    # (no shadowing parameter) must still stay silent.
    (tmp_path / "nav.tsx").write_text(
        'const homeLink = "/home";\n'
        "const Footer = () => <a href={homeLink}>x</a>;\n",
        encoding="utf-8",
    )
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_jsx_href_scheme_ts_type_literal_param_not_treated_as_shadow(tmp_path: Path) -> None:
    # Real false positive found by review (fix-commit round): a plain typed parameter whose TYPE
    # is an inline object literal (`props: { homeLink: string }`) was mistaken for a destructured
    # BINDING of `homeLink`, so a genuinely safe top-level const use fired HIGH. `homeLink` there
    # is a property name inside `props`'s TYPE annotation, not a bound variable -- the only real
    # binding in that signature is `props` itself.
    (tmp_path / "nav.tsx").write_text(
        'const homeLink = "/home";\n\n'
        "const C = (props: { homeLink: string }) => <a href={homeLink}>x</a>;\n",
        encoding="utf-8",
    )
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_jsx_href_scheme_ts_type_literal_param_block_body_not_treated_as_shadow(tmp_path: Path) -> None:
    # Same false positive, block-body form (pre-dates the concise-arrow fix on the shared
    # extraction path, so this locks in the fix for both signature shapes at once).
    (tmp_path / "nav.tsx").write_text(
        'const homeLink = "/home";\n'
        "const C = (props: { homeLink: string }) => {\n"
        "  return <a href={homeLink}>x</a>;\n"
        "};\n",
        encoding="utf-8",
    )
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_jsx_href_scheme_typed_positional_param_still_shadows(tmp_path: Path) -> None:
    # Control for the type-literal fix above: a plain TYPED positional parameter (not an object
    # type literal) must still be recognized as a real binding and still shadow the outer const.
    (tmp_path / "nav.tsx").write_text(
        'const homeLink = "/home";\n'
        "function NavLink(homeLink: string) {\n"
        "  return <a href={homeLink}>Home</a>;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1


def test_jsx_href_scheme_destructured_rename_shadows_the_renamed_name(tmp_path: Path) -> None:
    # A destructured + renamed binding (`{ homeLink: hl }`) binds `hl`, not `homeLink` -- the
    # renamed name is what actually shadows a same-named outer const.
    (tmp_path / "nav.tsx").write_text(
        'const hl = "/home";\n'
        "const C = ({ homeLink: hl }) => <a href={hl}>x</a>;\n",
        encoding="utf-8",
    )
    findings = JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1


def test_jsx_href_scheme_destructured_with_trailing_type_still_shadows(tmp_path: Path) -> None:
    # A destructured binding with a trailing type annotation for the whole pattern
    # (`({ homeLink }: Props)`) must still be recognized as a real binding.
    (tmp_path / "nav.tsx").write_text(
        'const homeLink = "/home";\n'
        "interface Props { homeLink: string }\n"
        "const C = ({ homeLink }: Props) => <a href={homeLink}>x</a>;\n",
        encoding="utf-8",
    )
    findings = JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1


def test_jsx_href_scheme_silent_on_commented_example(tmp_path: Path) -> None:
    # FP-bait (#424): a commented-out dynamic href must not fire.
    (tmp_path / "link.jsx").write_text(
        "// <a href={userUrl}>link</a>\n"
        "const x = 1;\n",
        encoding="utf-8",
    )
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_jsx_href_scheme_rest_and_nested_destructure_still_shadow(tmp_path: Path) -> None:
    # Both directions on the type-literal narrowing. `_binding_names` classifies each destructured
    # entry, and a rest element (`...rest`) and a NESTED pattern (`a: { inner }`) both start with a
    # character the identifier match rejects, so they contributed no name and the parameter
    # silently stopped shadowing. That is a false negative the flat pre-narrowing scan did not
    # have: the outer const was treated as safe even though a prop of the same name shadows it.
    for name, sig in (
        ("rest.tsx", "({ ...homeLink })"),
        ("nested.tsx", "({ a: { homeLink } })"),
        ("deep.tsx", "({ a: { b: { homeLink } } })"),
    ):
        (tmp_path / name).write_text(
            'const homeLink = "/home";\n'
            f"const C = {sig} => <a href={{homeLink}}>x</a>;\n",
            encoding="utf-8",
        )
    findings = JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 3
    assert {f.rule for f in findings} == {"jsx-href-scheme/href-dynamic-no-scheme-check"}

def test_jsx_href_scheme_silent_jsx_element_action_prop(tmp_path: Path) -> None:
    # issue #806: on a CAPITALIZED custom component, `action`/`href` is an author-defined prop,
    # not an HTML form-action/anchor sink. A value that is a JSX ELEMENT (a ReactNode) can never
    # carry a `javascript:` URL, so `<ComingSoon action={<Button/>} />` must stay silent — this was
    # the dominant FP shape (12 flagship hits from one `action?: ReactNode` component).
    (tmp_path / "coming.tsx").write_text(
        "export function Page() {\n"
        '  return <ComingSoon action={<Button variant="primary">Notify</Button>} />;\n'
        "}\n",
        encoding="utf-8",
    )
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []

def test_jsx_href_scheme_silent_jsx_element_fragment_value(tmp_path: Path) -> None:
    # A JSX fragment value (`{<>…</>}`) is also a ReactNode, never a URL string — must stay silent.
    (tmp_path / "menu.tsx").write_text("<Menu action={<><Item /></>} />", encoding="utf-8")
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []

def test_jsx_href_scheme_still_fires_wrapper_component_href_var(tmp_path: Path) -> None:
    # The #806 narrowing is VALUE-shape, not element-casing: a wrapper component that forwards a URL
    # VARIABLE to a real anchor (`<NavLink href={userUrl}>`, `<Link href={url}>`) is a genuine sink
    # and MUST still fire. Skipping every capitalized component would have silenced these — the
    # false-negative class #712 warns against. The value `userUrl` is not a `<…>` element.
    (tmp_path / "nav.tsx").write_text("<NavLink href={userUrl}>go</NavLink>", encoding="utf-8")
    findings = JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].rule == "jsx-href-scheme/href-dynamic-no-scheme-check"

def test_jsx_href_scheme_silent_parenthesized_jsx_value(tmp_path: Path) -> None:
    # issue #806 follow-up (PR #814 review): a JSX-element value wrapped in ONE paren is the
    # idiomatic Prettier formatting for a multi-line JSX prop value. It is still a ReactNode, never
    # a URL, so `action={(<Button/>)}` (with or without inner whitespace) must stay silent — the
    # `\(?` in the lookahead tolerates the wrapping paren. Discriminates: fires without `\(?`.
    (tmp_path / "paren.tsx").write_text(
        "<ComingSoon action={(<Button variant=\"primary\">Notify</Button>)} />", encoding="utf-8"
    )
    (tmp_path / "parenws.tsx").write_text("<Menu action={( <Bar /> )} />", encoding="utf-8")
    assert JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []

def test_jsx_href_scheme_still_fires_parenthesized_url_var(tmp_path: Path) -> None:
    # Direction traded against (Rule 1): the paren-tolerance must NOT swallow a real paren-wrapped
    # URL VARIABLE. `href={(userUrl)}` opens with an identifier char after the paren (not `<`), so
    # it is not a JSX element and MUST still fire — otherwise the widening of the exclusion would
    # have introduced a false negative.
    (tmp_path / "nav.tsx").write_text("<a href={(userUrl)}>go</a>", encoding="utf-8")
    findings = JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].rule == "jsx-href-scheme/href-dynamic-no-scheme-check"


def test_jsx_href_scheme_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the whole-file check reads the JS comment-only view, so a string literal quoting the
    # documented `// security: …` form is content - only a real comment opts out.
    content = 'const help = "opt out with // security: allow-jsx-href-scheme";\n<a href={userUrl}>link</a>\n'
    (tmp_path / "guarded.jsx").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    assert len(JsxHrefSchemeGuard().run(tmp_path, profile)) == 1


# --- #1055: the sink and the code-shaped scheme guards count only when they are live code ---------

_RULE = "jsx-href-scheme/href-dynamic-no-scheme-check"
_SINK = "  return <a href={userUrl}>{label}</a>;\n"


def _run_nav(tmp_path: Path, body: str) -> list[Finding]:
    (tmp_path / "Nav.jsx").write_text("function Nav({ userUrl, label }) {\n" + body + "}\n", encoding="utf-8")
    return JsxHrefSchemeGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))


@pytest.mark.parametrize(
    "extra",
    [
        "  log('TODO sanitize');\n",
        "  log(`TODO: call sanitizeUrl here`);\n",
        "  console.warn(\"check url.startsWith('http') first\");\n",
    ],
)
def test_jsx_href_scheme_quoted_guard_no_longer_clears_the_finding(tmp_path: Path, extra: str) -> None:
    # The FN direction (#1055): a guard word in a log string or template text cleared a real sink.
    findings = _run_nav(tmp_path, extra + _SINK)
    assert [f.rule for f in findings] == [_RULE]
    assert findings[0].location.replace("\\", "/").endswith("Nav.jsx:3")


@pytest.mark.parametrize(
    "extra",
    [
        "  const u = sanitizeUrl(userUrl);\n",
        "  const ok = /^https?:/.test(userUrl);\n",
        # The real guard nested in a `${...}` substitution is code: the shortcut-separating case,
        # which plain `strip_strings=True` would have blanked.
        "  log(`u=${sanitizeUrl(userUrl)}`);\n",
        # A quoted copy earlier on the line must not hide the real call after it (shadowing).
        "  log('sanitize'); const u = sanitizeUrl(userUrl);\n",
        # The literal `https://` credit only ever matches inside a literal, so it is NOT anchored
        # and still clears the finding exactly as before #1055.
        "  const fallback = 'https://example.com';\n",
    ],
)
def test_jsx_href_scheme_real_guard_or_https_literal_still_clears_the_finding(tmp_path: Path, extra: str) -> None:
    assert _run_nav(tmp_path, extra + _SINK) == []


@pytest.mark.parametrize(
    "body",
    [
        "  const doc = '<a href={userUrl}>';\n  return null;\n",
        "  const doc = `<form action={userUrl}>`;\n  return null;\n",
    ],
)
def test_jsx_href_scheme_sink_spelled_in_a_string_does_not_fire(tmp_path: Path, body: str) -> None:
    # The FP direction (#1055): a docs string or template text is not a JSX attribute.
    assert _run_nav(tmp_path, body) == []


@pytest.mark.parametrize(
    "body",
    [
        # A JSX attribute in a `${...}` substitution is code: the shortcut-separating case.
        "  const s = `${render(<a href={userUrl}>x</a>)}`;\n",
        # A quoted copy first on the line must not hide the real attribute after it.
        "  const d = '<a href={x}>'; return <a href={userUrl}>u</a>;\n",
        # A constant first attribute used to hide a dynamic one after it (`.search` took the first).
        "  return <><a href={ROUTES.HOME}>h</a><a href={userUrl}>u</a></>;\n",
    ],
)
def test_jsx_href_scheme_real_sink_nested_or_after_another_attribute_still_fires(
    tmp_path: Path, body: str
) -> None:
    findings = _run_nav(tmp_path, body)
    assert [f.rule for f in findings] == [_RULE]
    assert findings[0].location.replace("\\", "/").endswith("Nav.jsx:2")


def test_jsx_href_scheme_two_constant_attributes_on_one_line_stay_silent(tmp_path: Path) -> None:
    # FP bait for the every-attribute widening: each attribute is judged on its OWN value.
    body = "  return <><a href={ROUTES.HOME}>h</a><a href={ROUTES.ABOUT}>a</a></>;\n"
    assert _run_nav(tmp_path, body) == []


def test_jsx_href_scheme_pragma_still_suppresses_a_code_anchored_sink(tmp_path: Path) -> None:
    # Both directions (PR #1131 round-1 L1): the shape fires without the pragma.
    assert len(_run_nav(tmp_path, _SINK)) == 1
    assert _run_nav(tmp_path, "  // security: allow-jsx-href-scheme\n" + _SINK) == []
