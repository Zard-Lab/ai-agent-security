"""Guard: no SSRF from a user-controlled fetch URL (checklist §3a).

Server-Side Request Forgery — a server-side HTTP fetch whose URL is built from
user input lets an attacker point it at internal services or the cloud metadata
endpoint (`http://169.254.169.254/`), turning your backend into a proxy for
reaching things the attacker can't reach directly. OWASP:A10 / CWE-918. This
guard generalizes the LLM-only SSRF heuristic to **all** server-side fetches.

Conservative by design (SSRF is FP-prone) and **host-source-aware** (#861): the
SSRF risk lives in the *destination* — the scheme+host the request goes to — not
in interpolated *path* segments. So the guard isolates the URL's host authority
(everything between the authority prefix and the first `/`/`?`/`#` that lies
OUTSIDE an interpolation) and classifies where it comes from — considering
**every** interpolation in that span, so a config prefix cannot launder an
attacker-driven later segment (#868). The prefix is a literal `scheme://`, a
protocol-relative `//`, or an *interpolated* scheme (`f"{self.scheme}://…"`),
which is itself part of the destination and is classified along with the host
(#869); Python's `{{`/`}}` escapes are literal braces, not interpolations. The
authority is host+port+userinfo: a user-controlled *port* on a config host
(`f"{self.host}:{port}/x"`) is an attacker-influenced destination too, so it
classifies **user** — only a config port (`{self.host}:{self.port}`) stays config.

  * **request / bare-param host** — `request.`/`req.`, a name this file bound from
    request data, or a bare variable/parameter (`f"https://{host}/x"`) → fires
    **HIGH** `ssrf-general/user-controlled-url` (the attacker chooses the
    destination). Unchanged behaviour.
  * **operator-config host** — a `self.<attr>` / `settings.`/`config.`/`conf.`/
    `cfg.`/`app.` attribute or an ALL-CAPS module constant (`f"{self.api_url}/x"`,
    `BASE = "https://…"; f"{BASE}/x"`) → fires **MEDIUM**, surfacing,
    `ssrf-general/config-host-fetch`. The destination is operator-controlled, not
    directly attacker-chosen, so it does not gate CI — but it is *surfaced* (not
    suppressed) because in some deployments env/config values are themselves
    attacker-influenceable (SSRF-via-config), and a human should confirm the
    config source is not attacker-writable.
  * **literal host, path-only interpolation** — `f"https://api.example.com/{name}"`
    → **silent**. The destination is a fixed literal the attacker cannot change;
    only a path segment is interpolated, so this is not SSRF under any threat model.

A bare-variable *whole* URL (`requests.get(url)`) still does NOT fire (too noisy),
nor does a static literal. A `+`/`%` concat still keeps firing HIGH: the host component
of a concat can't be isolated reliably, so the conservative path is kept.

The host source is followed through two common indirections (#878), each a strict
DOWNGRADE that only ever removes a false positive from an already-HIGH line:

  * **a hoisted local** — a URL assigned to a local (`url = f"{self.api_url}/x"`) then
    fetched via `url.format(path=p)` — is resolved to its same-block assignment(s); the
    finding is downgraded to MEDIUM only when EVERY same-block assignment is a config host
    (a local reassigned across branches is config only if all branches are). Resolution
    only ever downgrades to config, never silences. Anything with a request signal
    anywhere in the fetch argument (including inside the peeled method's own arguments,
    `url.format(host=request.args[...])`), an unresolvable/sibling-scope local, a
    mixed-branch local whose branches disagree, or a resolved host that is not clearly
    config, keeps the conservative HIGH (taint-first).
  * **a string method over the host** — `f"{self.api_url.rstrip('/')}/v"`,
    `f"{_API_URL.rstrip('/')}/version"` — has its trailing `.rstrip`/`.strip`/`.format`/
    `.replace`/… peeled so the underlying config symbol (including a leading-underscore
    private constant like `_API_URL`) is recognized as config.

Sinks watched:

  * `requests.<verb>(...)` / `requests.request(...)`;
  * `httpx.<verb>(...)`;
  * `urllib.request.urlopen(...)` / a bare `urlopen(...)`.

The fix is an allow-list of permitted hosts/schemes plus blocking RFC-1918 /
link-local / metadata IPs (resolve then check). Suppress an audited internal
fetch with `# security: allow-ssrf`.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_line_set, python_scan_dirs, read, rel
from .path_traversal import _tainted_names  # ReDoS-safe request-taint scan (shared, #861)

_SINK = re.compile(
    r"\b(?:requests\.(?:get|post|put|delete|head|patch|options|request)|"
    r"httpx\.(?:get|post|put|delete|head|patch|options|request)|"
    r"(?:urllib\.request\.)?urlopen)\s*\("
)
_CONCAT = re.compile(r"['\"]\s*\+|\+\s*['\"]|\.format\s*\(|%\s*[\(A-Za-z_]")
_REQUEST = re.compile(r"\b(?:request|req)\.")
_PRAGMA = re.compile(r"#\s*security:\s*allow-ssrf")

# The BODY of the first f-string in the argument (between its matching quotes). Non-greedy to
# the same quote; single-line, which is all a URL literal ever is. No nested quantifier, so it
# cannot backtrack catastrophically (agentsec's own `redos` guard audits this file).
_FSTRING_BODY = re.compile(r"[rR]?[fF](['\"])(.*?)\1")
# A leading LITERAL URI scheme (`https://`, `http://`, a generic `\w+://`) on the literal prefix
# before the first interpolation — stripped so `https://{host}` reads as "host is the first interp".
# An INTERPOLATED scheme (`{self.scheme}://`) and a protocol-relative `//` are recognized by
# `_fstring_host_class` on the tokenized segments instead (#869).
_SCHEME = re.compile(r"[a-zA-Z][\w+.\-]*://")
# The closed set of host-source classifications. Typed as a Literal so both type-checkers catch a
# typo'd class string at the `cls == "user"` / `cls == "config"` branches in `_scan` (#868).
_HostClass = Literal["user", "config"]
# App-internal host ROOTS that are not request-derived: a config/instance attribute
# (`settings.X` / `config.X` / `conf.` / `cfg.` / `app.X` / `self.X`) or an ALL-CAPS module
# constant (`BASE`, and a leading-underscore private one `_API_URL`, #878). Mirrors
# `path_traversal.py::_TRUSTED_PATH_ROOT` (same vocabulary, same rationale). Blanked out of the
# host expression; if a bare identifier still survives, the host is a non-config, non-literal
# value (a param/local like `host`).
_TRUSTED_HOST_ROOT = re.compile(
    r"\b(?:settings|config|conf|cfg|app|self)\s*\.\s*\w+"
    r"|\b_*[A-Z][A-Z0-9_]*\b"
)
_BARE_IDENT = re.compile(r"[A-Za-z_]\w*")
# A single-line string literal (with its optional r/b/f/u prefix) — blanked out of a host
# expression so a literal's identifier chars aren't mistaken for a surviving bare variable.
_STR_LITERAL = re.compile(
    r'[rRbBfFuU]{0,2}(?:"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\')'
)
# String methods whose result is still the same destination host/URL, just normalized or
# templated. A trailing one is peeled off so the underlying config/local symbol can be classified
# (#878: `f"{self.api_url.rstrip('/')}/v"`, `url.format(path=path)`). `.format`/`.replace` CAN
# inject, but a request-bound argument is caught first by the taint check that runs BEFORE the peel
# result is trusted (in `_host_expr_class` and `_resolves_to_config`, both over the FULL un-peeled
# expression), so peeling here only ever downgrades an operator-config host — never launders user
# input.
_STR_METHODS = ("rstrip", "lstrip", "strip", "removesuffix", "removeprefix", "format", "replace")


def _mask_str_literals(e: str) -> str:
    """Replace string-literal spans with same-length, punctuation-free filler so a `)`/`.`/quote
    inside a method argument (`.replace(')', '/')`) cannot fool the paren scan in `_peel_str_methods`.
    Length-preserving, so indices stay aligned with the original expression."""
    return _STR_LITERAL.sub(lambda m: "_" * len(m.group(0)), e)


def _peel_str_methods(expr: str) -> str:
    """Strip trailing string-method calls (`x.rstrip('/')`, `x.format(a=b)`, ...) off a host/URL
    expression and return the underlying receiver (`x`).

    ReDoS-safe by construction: a manual right-to-left paren match (no backtracking regex), with
    string literals masked first so an in-argument paren is ignored. Only the closed
    ``_STR_METHODS`` set is peeled, so a `+`/`%` concat or a non-string method is left untouched
    (the conservative HIGH path is preserved).
    """
    e = expr.strip()
    while e.endswith(")"):
        masked = _mask_str_literals(e)
        depth = 0
        open_idx = -1
        for idx in range(len(masked) - 1, -1, -1):
            ch = masked[idx]
            if ch == ")":
                depth += 1
            elif ch == "(":
                depth -= 1
                if depth == 0:
                    open_idx = idx
                    break
        if open_idx <= 0:
            break
        prefix = masked[:open_idx].rstrip()
        for meth in _STR_METHODS:
            if prefix.endswith("." + meth):
                e = e[: len(prefix) - len(meth) - 1].strip()  # cut before the `.` (indices aligned)
                break
        else:
            break  # a `)` not closing a peelable string method — stop (keep the conservative path)
    return e


def _host_expr_class(expr: str, tainted: frozenset[str]) -> _HostClass:
    """Classify a single host interpolation expression as ``"user"`` or ``"config"``.

    ``"user"`` when the host is attacker-influenced — a name this file bound from request data
    (an ALL-CAPS `X = request.args[...]` looks exactly like a module constant, so the taint set
    overrides the spelling), or a bare variable/parameter that is not app-internal config.
    ``"config"`` when the host is operator config (a `self.`/`settings.`/… attribute or an
    ALL-CAPS module constant not bound from request data).
    """
    e = expr.strip()
    if not e:
        return "user"  # `f"{}"` — never legitimate; keep the conservative HIGH path
    # A name bound from a request source is user input however it is spelled. Checked on the FULL
    # expression (before the peel) so a tainted method ARGUMENT (`cfg.host.replace(evil, "")`)
    # cannot be peeled away and laundered — taint-first (#878).
    if any(tok in tainted for tok in _BARE_IDENT.findall(e)):
        return "user"
    # Peel a trailing string method (`.rstrip('/')`, `.format(...)`) so a config symbol carrying a
    # normalizing/templating call still reads as config (#878), then blank string literals and the
    # trusted-root vocabulary. Anything left that is still a bare identifier is a non-config,
    # non-literal host — a param/local the attacker may drive.
    blanked = _TRUSTED_HOST_ROOT.sub("", _STR_LITERAL.sub("", _peel_str_methods(e)))
    if _BARE_IDENT.search(blanked):
        return "user"
    return "config"


def _fstring_segments(body: str) -> list[tuple[bool, str]]:
    """Split an f-string body into ``(is_interp, text)`` segments, left to right (#869).

    The ONE place that decides what an interpolation is. Honours Python's brace escapes: at the
    literal level a `{{` / `}}` is a literal brace (so `{{literal}}` is text, not an interpolation
    — and `{{{x}}}` is a literal `{`, a real `{x}`, a literal `}`), a single `{` opens an
    interpolation, and braces NESTED inside it (`{d['k']}`, `{f(x={})}`) are tracked so the
    matching `}` closes it — a `/` inside an interpolation never reaches the authority walk. An
    unterminated `{` yields the remainder as one interpolation, which degrades to the conservative
    side (a bare identifier in it classifies ``"user"``). Adjacent literal text is merged into one
    segment; an interpolation's text is the expression between its braces. A plain O(n) character
    walk — no regex, so nothing new for the ReDoS gate to audit.
    """
    segs: list[tuple[bool, str]] = []
    lit: list[str] = []
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch == "{" and body.startswith("{{", i):
            lit.append("{")  # escaped literal brace
            i += 2
        elif ch == "}" and body.startswith("}}", i):
            lit.append("}")  # escaped literal brace
            i += 2
        elif ch == "{":
            if lit:
                segs.append((False, "".join(lit)))
                lit = []
            depth = 1
            j = i + 1
            while j < n and depth:
                if body[j] == "{":
                    depth += 1
                elif body[j] == "}":
                    depth -= 1
                j += 1
            # `j` is one past the closing `}` — or `n` when unterminated (the whole rest is the
            # expression, so a `/` in it cannot be mistaken for the authority terminator).
            segs.append((True, body[i + 1 : j - 1 if depth == 0 else n]))
            i = j
        else:
            lit.append(ch)  # a stray single `}` is not valid Python; keep it as literal text
            i += 1
    if lit:
        segs.append((False, "".join(lit)))
    return segs


def _fstring_host_class(body: str, tainted: frozenset[str]) -> _HostClass | None:
    """Classify the destination host of an f-string URL body, or ``None`` if it is not SSRF.

    The host is the URL *authority* — everything after the authority PREFIX up to the first
    `/`/`?`/`#` that lies OUTSIDE an interpolation. The prefix (#869) is a literal `scheme://`, a
    protocol-relative `//` (an authority MARKER, not the end of the authority), or an
    INTERPOLATED scheme (`{self.scheme}://…`): the scheme is part of the destination, so that
    interpolation is classified along with the host (a bare `{scheme}://` lets the attacker pick
    the protocol → user; a config scheme on a config host stays config). A single leading `/` is a
    relative path, not an authority. EVERY interpolation in the authority span is classified, not
    just the first (#868): if any is user-controlled the host is ``"user"`` (an attacker-driven
    segment anywhere in the authority chooses the destination); else if any is config the host is
    ``"config"``; if the authority is a fixed literal with no interpolation at all (only a later
    path/query segment is interpolated), the destination is pinned and this is not SSRF
    (``None``). A static f-string — including one whose only braces are `{{`/`}}` escapes — is
    likewise ``None``.
    """
    segs = _fstring_segments(body)
    if not any(is_interp for is_interp, _ in segs):
        return None  # static f-string (or escaped-brace-only): no interpolation at all
    # Strip the authority prefix so the walk starts ON the authority (#869).
    if not segs[0][0]:
        # A literal prefix: `scheme://` or a protocol-relative `//`.
        lit = segs[0][1]
        scheme_m = _SCHEME.match(lit)
        if scheme_m:
            lit = lit[scheme_m.end() :]
        elif lit.startswith("//"):
            lit = lit[2:]
        segs[0] = (False, lit)
    elif len(segs) > 1 and not segs[1][0] and segs[1][1].startswith("://"):
        # An interpolated scheme: `{x}://…`. Keep the interpolation (it IS part of the destination
        # — the walk below classifies it) and drop the `://` so its `/` does not end the authority.
        segs[1] = (False, segs[1][1][3:])
    # Walk the authority: classify every interpolation; stop at the first LITERAL segment carrying
    # a `/`/`?`/`#` (a separator inside an interpolation, e.g. `{build('/a')}`, is not literal text).
    classes: list[_HostClass] = []
    for is_interp, text in segs:
        if is_interp:
            classes.append(_host_expr_class(text, tainted))
        elif any(c in text for c in "/?#"):
            break
    if not classes:
        return None  # host authority is a fixed literal; only a later segment is interpolated
    return "user" if "user" in classes else "config"


def _url_host_class(arg: str, tainted: frozenset[str]) -> _HostClass | None:
    """Classify a fetch URL argument by the trust of its destination host.

    Returns ``"user"`` (attacker-influenced host → HIGH, unchanged), ``"config"`` (operator
    config host → downgraded, surfacing finding), or ``None`` (not an attacker-chosen
    destination → silent: a static literal, a bare-variable URL, or a literal host with only a
    path segment interpolated).
    """
    a = arg.strip()
    if not a:
        return None
    # A genuine request/user reference anywhere in the URL keeps firing HIGH — the direction we
    # must never silence (Review Doctrine Rule 1). Covers `urlopen(request.args['u'])` too.
    if _REQUEST.search(a):
        return "user"
    body_m = _FSTRING_BODY.search(a)
    if body_m:
        return _fstring_host_class(body_m.group(2), tainted)
    # concat / .format / % : the host component can't be isolated from the argument reliably,
    # so keep the conservative HIGH path (all reported config-host FPs are f-strings, #861).
    if _CONCAT.search(a):
        return "user"
    return None


def _first_arg(line: str, paren: int) -> str:
    # Terminate at the call's OWN closing `)` (depth 0), so trailing same-line code/comments
    # after `requests.get(url)` don't leak into the arg and trip the user-signal check (#423).
    rest = line[paren + 1 :]
    depth = 0
    for idx, ch in enumerate(rest):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return rest[:idx]
            depth -= 1
        elif ch == "," and depth == 0:
            return rest[:idx]
    return rest


# A single-target assignment `name = <rhs>` (optionally annotated `name: T = <rhs>`), NOT `==` or
# an augmented op. Used to resolve a fetch arg that is a hoisted local back to the expression it was
# assigned from (#878). Quantifier-nested-free: `[^=]+`/`\S`/`.*` are sequential single quantifiers,
# so nothing can backtrack catastrophically (this file self-audits with the `redos` guard).
_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)\s*(\S.*)$")
# A line that OPENS a new function/class scope. A `def`/`class` dedented below an assignment ends
# the assignment's enclosing scope, so a same-named local in a SIBLING method must not be borrowed
# (#881 review — a column-0-only boundary missed indented sibling methods).
_DEF_OR_CLASS = re.compile(r"\s*(?:async\s+def|def|class)\b")


def _url_assignments(lines: list[str], pragmas: frozenset[int]) -> dict[str, list[tuple[int, str]]]:
    """Map each locally-assigned name to the ``(line-index, right-hand-side)`` of every simple
    assignment to it, so a hoisted fetch URL can be resolved to its definition (#878). Attribute
    targets (`self.api_url = …`) are not locals and don't match. A line in `pragmas` (1-based
    numbers of the lines whose pragma is a real comment, #1040) is skipped."""
    out: dict[str, list[tuple[int, str]]] = {}
    for idx, line in enumerate(lines):
        if idx + 1 in pragmas:
            continue
        m = _ASSIGN.match(line)
        if m:
            out.setdefault(m.group(1), []).append((idx, m.group(2).strip()))
    return out


def _same_block(lines: list[str], assign_idx: int, sink_idx: int) -> bool:
    # The sink is in the same function/block as the assignment iff no line strictly between them
    # ends the assignment's enclosing scope: a non-blank column-0 line (we left to module level), or
    # a `def`/`class` DEDENTED below the assignment's own indent (a sibling function/method, whose
    # same-named local must not be borrowed — a class method sits at an indent > 0, so a column-0
    # check alone missed it, #881 review). A `def`/`class` at or deeper than the assignment's indent
    # is a nested helper and does NOT end the scope, so a real in-function local still resolves.
    assign_indent = len(lines[assign_idx]) - len(lines[assign_idx].lstrip())
    for k in range(assign_idx + 1, sink_idx):
        ln = lines[k]
        if not ln.strip():
            continue
        indent = len(ln) - len(ln.lstrip())
        if indent == 0:
            return False
        if indent < assign_indent and _DEF_OR_CLASS.match(ln):
            return False
    return True


def _resolves_to_config(
    arg: str,
    sink_idx: int,
    assigns: dict[str, list[tuple[int, str]]],
    tainted: frozenset[str],
    lines: list[str],
) -> bool:
    """True iff a fetch arg that is a hoisted local — a bare name, optionally with a trailing string
    method (`url`, `url.format(path=path)`) — resolves to same-block assignment(s) whose right-hand
    side(s) ALL classify as CONFIG-host URLs. That is the one case where an already-HIGH fetch may be
    downgraded to the MEDIUM `config-host-fetch` surfacing finding (#878).

    Resolution can only DOWNGRADE HIGH->MEDIUM; it never silences. Everything else keeps the
    conservative HIGH (#881 review, both directions):

    * **Taint-first over the FULL arg** — a `request.`/`req.` reference or a tainted token ANYWHERE
      in the arg, *including inside a peeled method's arguments* (`url.format(host=request.args["h"])`
      injects user input into the URL through `.format`), keeps HIGH. Checked BEFORE the peel so a
      tainted call argument cannot be discarded and laundered — the Critical regression this fix
      closes, and the equivalent of `_host_expr_class`'s taint-first ordering.
    * **Config-only downgrade** — a resolved RHS is trusted only when it classifies ``"config"``.
      A RHS that is ``"user"`` or ``None`` keeps HIGH: ``None`` may be a plain-string ``.format``
      template whose host placeholder (`"http://{host}/x".format(host=...)`) this guard's f-string-
      only host parser cannot see, so silencing it would drop a real SSRF.
    * **All-branches-config** — EVERY same-block assignment to the local must classify ``"config"``.
      A local reassigned across mutually-exclusive branches (`url = f"{host}/x"; if not host: url =
      f"{self.api_url}/x"`) is config only if all branches are; a single user/None branch keeps HIGH
      (#881 fresh-eyes review — classifying only the textually-last assignment with `max()` laundered
      the attacker-controlled branch to MEDIUM, voiding a real detection).
    """
    if _REQUEST.search(arg) or any(tok in tainted for tok in _BARE_IDENT.findall(arg)):
        return False
    name = _peel_str_methods(arg)
    if not _BARE_IDENT.fullmatch(name):
        return False
    candidates = [
        (idx, rhs)
        for idx, rhs in assigns.get(name, ())
        if idx < sink_idx and _same_block(lines, idx, sink_idx)
    ]
    if not candidates:
        return False
    # EVERY same-block assignment must classify config to downgrade. A local reassigned across
    # mutually-exclusive branches (`url = f"{host}/x"; if not host: url = f"{self.api_url}/x"`) is
    # config only if all branches are config; a single user/None/unparseable branch keeps the
    # conservative HIGH (#881 fresh-eyes review — classifying only the textually-last assignment
    # with `max()` laundered the attacker-controlled branch to MEDIUM, voiding a real detection).
    return all(_url_host_class(rhs, tainted) == "config" for _, rhs in candidates)


class SsrfGeneralGuard(Guard):
    id = "ssrf-general"
    title = "No SSRF from a user-controlled fetch URL"
    area = "Network requests"
    # Only the config-host rule is a review signal; the user-controlled-url rule is a proven
    # bug and stays gating. Per-RULE surfacing, not a flat `surfacing = True` (#861).
    surfacing_rule_prefixes = ("ssrf-general/config-host-fetch",)

    # fetch.py: requests.get on an f-string URL with a bare-param host -> ssrf-general HIGH.
    canary_plant = CanaryPlant(
        files={
            "fetch.py": ("import requests\n\n\ndef fetch(host: str):\n    return requests.get(f\"https://{host}/data\")\n"),
        },
        expects=frozenset({"ssrf-general/user-controlled-url"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        src = read(f)
        tainted = _tainted_names(src)
        lines = src.splitlines()
        # The pragma counts only as a real comment on the line, never quoted in a string there (#1040).
        pragmas = pragma_line_set(_PRAGMA, src, dialect="python")
        assigns = _url_assignments(lines, pragmas)
        for i, line in enumerate(lines, start=1):
            if line.lstrip().startswith("#") or i in pragmas:
                continue
            m = _SINK.search(line)
            if not m:
                continue
            arg = _first_arg(line, m.end() - 1)
            cls = _url_host_class(arg, tainted)
            if cls == "user" and _resolves_to_config(arg, i - 1, assigns, tainted, lines):
                # #878: the HIGH arg is a config-derived local reached through a hoist and/or a
                # trailing string method (`url = f"{self.api_url}/x"; requests.get(url.format(...))`).
                # Downgrade to the MEDIUM surfacing finding. Only reached on an already-HIGH line and
                # only when the resolved host is config, so this strictly REMOVES false positives.
                cls = "config"
            if cls == "user":
                out.append(self._user_finding(root, f, i))
            elif cls == "config":
                out.append(self._config_finding(root, f, i))
        return out

    def _user_finding(self, root: Path, f: Path, i: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title="Server-side fetch URL built from untrusted input (SSRF)",
            location=f"{rel(root, f)}:{i}",
            message=(
                "This outbound request's destination host is assembled from user/dynamic input "
                "with no allow-list — an attacker can point it at internal services or the cloud "
                "metadata endpoint (169.254.169.254) and exfiltrate credentials."
            ),
            remediation=(
                "Validate the URL against an allow-list of permitted hosts/schemes, and "
                "block RFC-1918 / link-local / metadata IPs (resolve the host, then check). "
                "Suppress an audited internal fetch with `# security: allow-ssrf`."
            ),
            rule="ssrf-general/user-controlled-url",
            standards=["OWASP:A10"],
        )

    def _config_finding(self, root: Path, f: Path, i: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title="Server-side fetch to a config-derived host (review SSRF-via-config)",
            location=f"{rel(root, f)}:{i}",
            message=(
                "This outbound request's host traces to operator configuration (an env/settings "
                "value, a `self.` attribute, or a module constant), not directly to attacker "
                "input — so it is not a gating SSRF. It is surfaced for review because in some "
                "deployments a config value is itself attacker-influenceable (SSRF-via-config); "
                "only a path segment is interpolated here."
            ),
            remediation=(
                "Confirm the host's config source is not attacker-writable. If the host can vary "
                "at runtime, validate it against an allow-list of permitted hosts/schemes and "
                "block RFC-1918 / link-local / metadata IPs (resolve, then check). Suppress an "
                "audited internal fetch with `# security: allow-ssrf`."
            ),
            rule="ssrf-general/config-host-fetch",
            standards=["OWASP:A10"],
        )
