"""Guard: JSX href/src/action attribute set to an unsanitized dynamic value (§6a — Frontend Security).

In React/JSX, `href`, `src`, and `action` attributes accept dynamic expressions via
curly-brace syntax: `<a href={userUrl}>`. If `userUrl` is attacker-controlled and is
not validated to start with a safe scheme (`http://`, `https://`, `/`), an attacker
can inject `javascript:doEvil()` — a URL scheme that browsers execute as JavaScript
when the user clicks the link or when the form is submitted.

React does NOT sanitize href/src/action values for scheme safety beyond preventing
explicit string-literal `javascript:` props (it only protects static string literals,
not runtime expressions). Dynamic values escape React's built-in protection entirely.

One statically detectable pattern:

  **`href-dynamic-no-scheme-check`** (HIGH): A .jsx/.tsx line that contains a JSX
  `href={`, `src={`, or `action={` attribute where the brace value is a variable or
  expression (not a string literal starting with `http` or `/`) AND the line does not
  contain any of the safe-scheme guards:
    - `.startsWith("http")`
    - `startsWith("/")`
    - `sanitize` (a sanitizer call, e.g. sanitizeUrl())
    - `encodeURI`

**Why HIGH?** The `javascript:` URL scheme executes arbitrary JS in the user's browser
session with full access to cookies (even without HttpOnly if set on an unreachable
domain), DOM, and storage. This is a classic and actively exploited XSS vector (CWE-79).
OWASP classifies URL scheme injection under A03:2021 — Injection. The attack requires
only that an attacker controls any string variable passed to one of these attributes.

**False-negative scope:** This guard only catches same-line dynamic attribute patterns.
Multi-line attribute expressions (JSX spanning multiple lines) and variables pre-validated
elsewhere are NOT caught — they require dataflow analysis beyond the scope of static
line-level detection.

**Author-defined constant recognition (FP fix, corpus scan finding):** a value that is an
author-defined route/URL constant — never attacker input — does not fire, via either of two
signals: (1) a SCREAMING_CASE-rooted name (`ROUTES.HOME`, `API_BASE`), which also covers a
constant imported from elsewhere with no local declaration to inspect; or (2) a bare identifier
declared `const` in the same file and assigned a string/template literal starting with a safe
scheme (`homeLink`, `HomeRoute` — any casing), which a corpus scan found was the dominant
false-positive shape (5/5 sampled hits) that signal (1) alone missed. Deliberately
`const`-only, never `let`/`var`: a reassignable binding proves nothing about what flows through
it later, so the guard still fires on those.

**Author-defined constants are not immune when they carry an unsafe scheme.** A `const`
literal that itself starts with `javascript:` (or anything else not `http(s)://`/`/`) is NOT
recognized as safe by signal (2) — an author writing `const evilLink = "javascript:..."` is a
real bug (self-XSS, or a supply-chain-planted backdoor constant), and the guard still fires.

**Live code only (#1055):** the `href={`/`action={` sink and every code-shaped scheme guard
(`startsWith`, `sanitize`, `encodeURI`, `new URL(`, `.test(`, ...) count only when they are live
code, tested on the shared anchor mask (`js_code_matches`). A `log("TODO sanitize")` no longer
clears a real sink, and an `href={...}` spelled out in a docs string no longer fires. The literal
`https://` credit is the exception: it only ever matches inside a literal, so it stays a plain
text match. Every attribute on a line is tried, so a constant first attribute no longer hides a
dynamic one after it.

**Checklist items:** `6a-jsx-url-scheme-xss`

**Suppress:** `// security: allow-jsx-href-scheme` anywhere in a file silences this check
for that file. Use only when you have confirmed every dynamic URL in that file is
validated against an allowlist of safe schemes before being rendered.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    js_code_matches,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_PRAGMA = "security: allow-jsx-href-scheme"

_STANDARDS = ["OWASP:A03", "CWE-79"]

# Matches a JSX href={ or action={ with a dynamic (non-string-literal) value.
# `src` is deliberately EXCLUDED: a `javascript:` URL does not execute in img/source/
# script `src` (only `href` on anchors/areas and `action` on forms run the scheme), and
# `src={...}` on images was the dominant false positive. The leading `\b` stops the match
# from firing inside a custom prop like `imageSrc={` / `avatarHref={`.
#
# The first negative lookahead covers single-quoted, double-quoted, AND backtick template
# literals that start with a safe prefix (https?:// or /). Template literals like
# `href={\`/dashboard/${section}\`}` are relative paths — no javascript: injection possible.
#
# The second lookahead `(?!\s*\(?\s*<)` excludes a value that is a JSX ELEMENT or fragment
# (`action={<Button/>}`, `href={<>…</>}`) — a ReactNode, never a URL string, so no
# `javascript:` scheme can flow through it. This is the dominant shape on a CAPITALIZED custom
# component (`<ComingSoon action={<Button/>} />`), where `action`/`href` is an author-defined
# prop, not an HTML form-action/anchor sink (issue #806). The optional `\(?` also tolerates ONE
# wrapping paren (`action={(<Button/>)}`), the idiomatic Prettier formatting for a multi-line JSX
# value. It is a VALUE-shape signal, not an element-casing one: a wrapper component that forwards
# a URL variable to a real anchor (`<NavLink href={userUrl}>`, `<Link href={url}>`) has a non-`<`
# value and STILL fires, so no real sink is silenced — and a parenthesized *variable*
# (`href={(userUrl)}`) opens with an identifier char after the paren, so it fires too. Only what
# follows `{` on this line is inspected, so a JSX-element value that spills onto later lines is
# caught too. Residuals that still fire (both ReactNodes, both rare): a JSX element behind a
# ternary (`action={cond ? <A/> : <B/>}`) and a doubly-parenthesized element (`{((<X/>))}`).
_DYNAMIC_URL_ATTR = re.compile(
    r"\b(?:href|action)=\{(?!\s*['\"`](?:https?://|/))(?!\s*\(?\s*<)",
    re.IGNORECASE,
)

# Safe-scheme indicators. Scanned over a small WINDOW around the attribute line (not just
# the same line) because the validation is routinely on a preceding line — e.g.
# `const safeHref = /^https?:\/\//i.test(u) ? u : '#'` then `<a href={safeHref}>`.
#
# Split in two for #1055. The code-shaped guards count only when their first character is live
# code on the anchor mask, so `log("TODO sanitize")` is not a guard. The literal `https://` (or a
# regex's escaped `https:\/\/`) only ever matches inside a string, template or regex body, so
# anchoring it would drop every hit: it stays a plain text match.
_SAFE_GUARD = re.compile(
    r"startswith|sanitiz|encodeuri|new\s+url\(|\.test\(|isvalid|allowlist|safe(?:url|href|link)",
    re.IGNORECASE,
)
_SAFE_SCHEME_LITERAL = re.compile(r"https?:\\?/\\?/", re.IGNORECASE)
_SAFE_WINDOW = 3  # lines of context on each side to scan for a scheme guard

# The href/action brace VALUE, to recognize author-controlled constants. A value that is a
# SCREAMING_CASE-rooted constant reference (`ROUTES.HOME`, `PATHS.login`, `API_BASE`) is a
# route/URL constant the developer defined — never attacker input — so a `javascript:` scheme
# cannot be injected through it. (A user-controlled value like `user.website` has a lowercase
# root and is still flagged; `match[3]` has brackets and is still flagged.)
_HREF_VALUE = re.compile(r"\b(?:href|action)=\{([^}]*)\}", re.IGNORECASE)

# A `const NAME = "safe literal"` declaration, ANY identifier casing — a broader safe-pattern
# signal than the SCREAMING_CASE naming heuristic below. A corpus scan found the
# dominant false-positive shape was a developer-authored navigation constant that was NOT
# SCREAMING_CASE (`const homeLink = "/home"`, `const HomeRoute = "/dashboard"`): `_is_const_ref`
# only recognized the ALL-CAPS naming convention, so these fired as if `homeLink` were attacker
# input. Recognized here by DECLARATION SHAPE instead of name shape: `const` (never `let`/`var` —
# those are reassignable, so the name alone proves nothing about what flows through it later)
# assigned a string/template literal whose OPENING matches the same safe-prefix threshold
# `_DYNAMIC_URL_ATTR` already uses for an inline literal (`https?://` or a leading `/`). Optional
# `: string` covers a TypeScript-annotated const. Only the opening quote+prefix is matched (no
# closing-quote capture) — cheap and sufficient: the declaration is scanned for its existence,
# not its full value.
_CONST_SAFE_STRING_DECL = re.compile(
    r"(?m)^[^\S\n]*(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*(?::\s*string)?\s*="
    r"\s*['\"`](?:https?://|/)"
)


# A function/component signature start, anchored at column 0 — the near-universal formatting
# convention for a JSX file's top-level component/function declarations (the same "column-0
# top-level def" heuristic `agent_loop_circuit_breaker.py`'s `_FUNC_DEF` uses for Python). Only
# the START position matters — it bounds the parameter-list scan `_is_shadowed_locally` uses
# below to detect a prop name that shadows a same-named module-level `const`.
_JS_SIGNATURE_START = re.compile(
    r"^(?:export\s+(?:default\s+)?)?(?:async\s+)?(?:"
    r"function\b|"
    r"(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\("
    r")",
    re.MULTILINE,
)


def _signature_param_list(text: str, sig_start: int) -> str:
    """The raw text of the parameter list belonging to the signature starting at `sig_start` —
    from its first `(` through the matching `)`, paren-depth counted so a destructured-prop
    `{ ... }` or a default-value expression inside the list can't prematurely close it. "" if no
    balanced list closes within a bounded scan (malformed file, or `sig_start` wasn't really a
    parameter list)."""
    paren_start = text.find("(", sig_start)
    if paren_start == -1:
        return ""
    depth = 0
    i = paren_start
    n = min(len(text), paren_start + 2000)  # bounded: a parameter list this long is unrealistic
    while i < n:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[paren_start:i + 1]
        i += 1
    return ""


def _split_top_level(text: str, sep: str) -> list[str]:
    """Split `text` on `sep`, only at bracket/brace/paren depth 0 — so a destructuring pattern's
    or a type literal's own internal commas/colons don't fragment the split."""
    parts: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(text):
        if ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
        elif ch == sep and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return parts


def _binding_names(params_text: str) -> set[str]:
    """The BOUND identifier names in a parameter list's raw text (from `_signature_param_list`,
    parens included) — excluding a name that only appears in a TypeScript type annotation.

    Real false positive found by review (fix-commit round): a plain typed parameter whose type is
    an inline object literal (`(props: { homeLink: string }) => <a href={homeLink}>`) was treated
    as if `homeLink` were a destructured binding, because the old check just regex-searched the
    whole parameter-list text for the name. `{ homeLink: string }` there is `props`'s TYPE, not a
    destructuring pattern — the only real binding is `props` itself, and `homeLink` in the JSX
    still refers to the outer module-level const.

    Per top-level (comma-split) parameter:
      `name`                    -> {name}                 plain positional
      `name: T`                 -> {name}                 typed positional; T (whatever shape,
                                                            including `{ ... }`) is a TYPE, ignored
      `{ a, b }`                -> {a, b}                  destructured, no rename
      `{ a: renamed }`          -> {renamed}               destructured + renamed: the BOUND name
                                                            is what comes after the colon, `a` is
                                                            just the source object's key
      `{ a }: SomeType`         -> {a}                     destructured; the trailing `: SomeType`
                                                            (outside the braces) is the pattern's
                                                            own type annotation, ignored
    A default value (`= expr`) is stripped before extracting the name in every shape above."""
    inner = params_text.strip()
    if inner.startswith("(") and inner.endswith(")"):
        inner = inner[1:-1]
    names: set[str] = set()
    for raw_param in _split_top_level(inner, ","):
        p = raw_param.strip()
        if not p:
            continue
        if p.startswith("{"):
            depth = 0
            end = len(p) - 1
            for idx, ch in enumerate(p):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = idx
                        break
            for entry in _split_top_level(p[1:end], ","):
                entry = entry.strip()
                if not entry:
                    continue
                bound = entry.split(":", 1)[1] if ":" in entry else entry
                bound = bound.split("=", 1)[0].strip()
                # A rest element (`...rest`) binds the name after the dots, and a NESTED pattern
                # (`a: { inner }`) binds the names inside it, not `a`. Both start with a character
                # the identifier match below rejects, so without these two lines they contribute no
                # name at all and the parameter silently stops shadowing — a false negative the
                # flat pre-#709 scan did not have.
                if bound.startswith("..."):
                    bound = bound[3:].strip()
                if bound[:1] in ("{", "["):
                    names |= _binding_names("(" + bound + ")")
                    continue
                m = re.match(r"[A-Za-z_$][\w$]*", bound)
                if m:
                    names.add(m.group(0))
        else:
            head = p.split(":", 1)[0].split("=", 1)[0].strip()
            m = re.match(r"[A-Za-z_$][\w$]*", head)
            if m:
                names.add(m.group(0))
    return names


def _is_shadowed_locally(text: str, usage_pos: int, name: str) -> bool:
    """True if `name` is bound as a parameter or destructured-prop key in the signature of the
    function/component whose scope (nearest preceding column-0 signature start) encloses
    `usage_pos`. Closes a real false negative: a caller-controlled `href={homeLink}` prop was
    silently treated as safe because an UNRELATED top-level `const homeLink` exists elsewhere in
    the file — JS scoping means the prop parameter shadows the outer const inside this function,
    so the outer declaration is not actually what flows into this usage."""
    sig_starts = [m.start() for m in _JS_SIGNATURE_START.finditer(text, 0, usage_pos)]
    if not sig_starts:
        return False
    params = _signature_param_list(text, sig_starts[-1])
    if not params:
        return False
    return name in _binding_names(params)


def _is_const_ref(value: str, safe_const_names: frozenset[str], shadowed: bool) -> bool:
    """True for a value that is author-defined, never attacker input — so a `javascript:` scheme
    cannot be injected through it. Two independent signals, either is sufficient:

    1. A SCREAMING_CASE-rooted constant reference (`ROUTES.HOME`, `PATHS.login`, `API_BASE`) — a
       naming-convention heuristic that also covers an IMPORTED constant with no local `const`
       declaration to see. The first dotted segment must be ALL-CAPS, and the whole value is
       just identifier chars + dots (so `user.website`, `match[3]`, calls, and template literals
       are NOT treated as constants).
    2. A bare identifier that exactly matches a `const NAME = "safe literal"` declaration found
       in THIS file (`safe_const_names`, from `_CONST_SAFE_STRING_DECL`) — any casing — AND is
       not `shadowed` (a same-named parameter/destructured-prop bound in the usage's own
       enclosing function signature; see `_is_shadowed_locally`). This is the declaration-shape
       signal that closes the camelCase/PascalCase gap signal (1) misses. Signal (1) is not
       scope-checked: an ALL-CAPS prop name is not a realistic JS naming convention, so the
       cross-scope collision this guards against does not apply to it.

    Plain string ops for (1), not a regex — avoids a (linear-but-) nested-quantifier ReDoS match.
    """
    value = value.strip()
    if not value:
        return False
    if value in safe_const_names and not shadowed:
        return True
    head = value.partition(".")[0]
    if not head.isupper():  # `isupper()` is False for "user"/"Foo"/"" — requires an all-caps head
        return False
    return all(c.isalnum() or c in "_." for c in value)


def _is_author_constant(
    line: str,
    attr_m: re.Match[str],
    lineno: int,
    line_offsets: list[int],
    joined: str,
    safe_const_names: frozenset[str],
) -> bool:
    """True when the brace value of the attribute matched at `attr_m` is an author-defined
    route/URL constant (SCREAMING_CASE name, or a `const` declared with a safe-prefixed literal,
    not shadowed locally) — not attacker input. The value is read from THIS attribute, not the
    line's first one (#1055)."""
    value_m = _HREF_VALUE.match(line, attr_m.start())
    if not value_m:
        return False
    val = value_m.group(1).strip()
    # The attribute's OWN position within the line, not the line start — a concise-body arrow
    # component (`const C = ({ x }) => <a href={x}>`) puts its signature and its usage on the SAME
    # line, and the signature always precedes the usage in text order. Anchoring the backward
    # search at the line start excluded that same-line signature entirely, since it sits AFTER the
    # line start but the search window ended AT the line start (review finding).
    usage_pos = line_offsets[lineno - 1] + attr_m.start()
    shadowed = val in safe_const_names and _is_shadowed_locally(joined, usage_pos, val)
    return _is_const_ref(val, safe_const_names, shadowed)


# --- static `javascript:` literals (mined from eslint-plugin-react-security's no-javascript-urls) ---
#
# React 16.9 to 18 only logs a warning for a literal `javascript:` URL and still renders it, and
# React 19 blocks it; either way a literal in an anchor or form is a planted-backdoor / self-XSS
# smell, and the `<a href="javascript:void(0)">` placeholder is legacy debt. The value is read whole
# and normalized the way a browser does (ASCII whitespace and control characters dropped, case
# folded) so `" JavaScript:alert(1)"` and `java<TAB>script:` are caught.
_STATIC_URL_ATTR = re.compile(
    r"\b(href|action)\s*=\s*(?:(\{\s*)([\"'`])|([\"']))((?:\\.|(?!\3|\4)[^\\])*)(?:\3|\4)",
    re.DOTALL,
)
_URL_CTRL = re.compile(r"[\x00-\x20]+")
_PLACEHOLDER_PAYLOAD = re.compile(r"^(?:void\(?0\)?;?|;?|undefined;?)$")
_TAG_OPEN = re.compile(r"<([A-Za-z][\w.]*)")
_URL_SINK_TAGS = {"href": frozenset({"a", "area"}), "action": frozenset({"form"})}


def _static_javascript_urls(text: str, mask: str) -> list[tuple[int, str]]:
    """(1-based line, severity) for each live `href`/`action` on an anchor, area or form whose
    string literal value is a `javascript:` URL. `void(0)`, an empty body and `;` are the legacy
    placeholder (low); anything else runs code (medium)."""
    found: list[tuple[int, str]] = []
    for m in js_code_matches(_STATIC_URL_ATTR, text, mask, anchor=lambda m: m.start()):
        value = _URL_CTRL.sub("", m.group(5)).lower()
        if not value.startswith("javascript:"):
            continue
        tags = _TAG_OPEN.findall(text, 0, m.start())
        if not tags or tags[-1].lower() not in _URL_SINK_TAGS[m.group(1).lower()]:
            continue
        payload = value[len("javascript:"):]
        severity = "low" if _PLACEHOLDER_PAYLOAD.match(payload) else "medium"
        found.append((text.count("\n", 0, m.start()) + 1, severity))
    return found


_JSX_SUFFIXES = (".jsx", ".tsx")


class JsxHrefSchemeGuard(Guard):
    id = "jsx-href-scheme"
    title = "JSX href/action set to unsanitized dynamic URL (javascript: XSS)"
    area = "Web & browser"

    # components/NavLink.jsx: dynamic href={userUrl} without scheme check -> fires jsx-href-scheme.
    # components/NavLink.jsx: <a href={userUrl}> without scheme check ->
    # href-dynamic-no-scheme-check.
    canary_plant = CanaryPlant(
        files={
            "components/NavLink.jsx": (
                "function NavLink({ userUrl, label }) {\n"
                "    return <a href={userUrl}>{label}</a>;\n"
                "}\n"
            ),
            "components/StaticJsLink.jsx": (
                "function StaticJsLink() {\n"
                "    return <a href=\"javascript:alert(document.cookie)\">run</a>;\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "jsx-href-scheme/href-dynamic-no-scheme-check",
            "jsx-href-scheme/static-javascript-url-literal",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _JSX_SUFFIXES):
            dynamic_lines: set[int] = set()
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            # Blank `//` and `/* */` comments (line numbers preserved) so a commented-out or
            # documented `href={userValue}` EXAMPLE doesn't fire (issue #424).
            lines = strip_js_comments(text).splitlines()
            # The anchor mask (#1055): same layout, string and template text blanked, `${...}` code kept.
            mask_lines = strip_js_comments(text, strip_strings=True, keep_substitutions=True).splitlines()
            joined = "\n".join(lines)
            # `const NAME = "safe literal"` declarations anywhere in this file — scanned once per
            # file, not per line, since the widened `_is_const_ref` signal is file-scoped.
            safe_const_names = frozenset(
                m.group(1) for m in _CONST_SAFE_STRING_DECL.finditer(joined)
            )
            # Cumulative offset of the start of each line within `joined`, so a usage line's
            # scope (the function/component signature enclosing it) can be located by character
            # position — used only to check for local shadowing (below), not per-line otherwise.
            line_offsets = [0]
            for ln in lines:
                line_offsets.append(line_offsets[-1] + len(ln) + 1)
            for lineno, (line, mask_line) in enumerate(zip(lines, mask_lines, strict=True), 1):
                # Every live attribute's `{` is tried (#1055): an `href={...}` spelled out in a
                # string is not a sink, and a constant first attribute no longer hides a dynamic
                # one after it on the line (`.search` took the first).
                if not any(
                    not _is_author_constant(line, attr_m, lineno, line_offsets, joined, safe_const_names)
                    for attr_m in js_code_matches(_DYNAMIC_URL_ATTR, line, mask_line, anchor=lambda m: m.end() - 1)
                ):
                    continue
                lo, hi = max(0, lineno - 1 - _SAFE_WINDOW), lineno + _SAFE_WINDOW
                window = "\n".join(lines[lo:hi])
                window_mask = "\n".join(mask_lines[lo:hi])
                if _SAFE_SCHEME_LITERAL.search(window) or any(
                    js_code_matches(_SAFE_GUARD, window, window_mask, anchor=lambda m: m.start())
                ):
                    continue  # a scheme check / sanitizer is present in the surrounding lines
                dynamic_lines.add(lineno)
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="JSX href/action set to dynamic URL without scheme check",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "A JSX href or action attribute is set to a dynamic "
                            "expression (variable or runtime value) without a safe-scheme "
                            "guard. If the value is attacker-controlled and contains "
                            "`javascript:doEvil()`, the browser will execute that JavaScript "
                            "when the user clicks the link or submits the form. React does "
                            "not sanitize dynamic URL expressions — only static string "
                            "literals are protected."
                        ),
                        remediation=(
                            "Validate the URL before rendering: check that it starts with "
                            "`http://`, `https://`, or `/` (e.g. "
                            "`url.startsWith('http') || url.startsWith('/')`) or use a "
                            "dedicated sanitizer such as `sanitizeUrl()` from the "
                            "`@braintree/sanitize-url` package. Never pass unvalidated "
                            "user-supplied strings directly to href, src, or action. "
                            "Suppress with `// security: allow-jsx-href-scheme` only "
                            "after confirming every URL value in this file is scheme-safe."
                        ),
                        rule="jsx-href-scheme/href-dynamic-no-scheme-check",
                        standards=list(_STANDARDS),
                    )
                )
            if not is_nonproduct_path(rel(root, f), profile.archive_segments):
                full = "\n".join(lines)
                full_mask = "\n".join(mask_lines)
                for lineno, severity in _static_javascript_urls(full, full_mask):
                    if lineno in dynamic_lines:
                        continue  # the dynamic-value rule already reported this attribute (HIGH)
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="low" if severity == "low" else "medium",
                            title="JSX anchor or form uses a literal javascript: URL",
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                "A literal `javascript:` URL in an anchor `href` or form `action`. "
                                "React 16.9 to 18 only warns and still runs it, React 19 blocks it; "
                                "either way it is a script-injection sink left in the markup"
                                + (" (a `void(0)` placeholder)." if severity == "low" else ".")
                            ),
                            remediation=(
                                "Use a real URL, or a `<button type=\"button\" onClick={...}>` for an "
                                "action that is not navigation. Suppress with "
                                "`// security: allow-jsx-href-scheme` after review."
                            ),
                            rule="jsx-href-scheme/static-javascript-url-literal",
                            standards=list(_STANDARDS),
                        )
                    )
        return out
