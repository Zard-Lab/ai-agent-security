"""Guard: a raw URL's substring checked against a trusted domain — bypassable
(checklist §3a, new item, CWE-020).

Checking whether a URL "contains" or "starts with" a trusted domain string, without
first parsing the URL and comparing the actual hostname, is a classic and still-common
SSRF/open-redirect bypass:

  if (url.includes("trusted.com")) { fetch(url); }   // bypassed by:
  //   https://evil.com/trusted.com
  //   https://trusted.com.evil.com
  //   https://trusted.com@evil.com

A substring/prefix test on the RAW URL string has no concept of "this is the hostname
component" — an attacker controls every other part of the URL (path, subdomain,
userinfo) and can place the trusted string anywhere that satisfies the check while the
URL still resolves to an attacker-controlled host.

Sourced from GitHub CodeQL's `js/incomplete-url-substring-sanitization`
(`javascript/ql/src/Security/CWE-020/IncompleteUrlSubstringSanitization.ql`) — the
query's own description: "Security checks on the substrings of an unparsed URL are
often vulnerable to bypassing."

Fires HIGH per match: a `.includes(`, `.indexOf(`, or `.startsWith(` call whose receiver
is a variable that looks like a URL (`url`/`uri`/`href`/`target`/`redirect`/`link`) and
whose argument is a domain-shaped string literal (contains a dot and no `/`), with no
URL-parsing call (`new URL(`, `.hostname`) on the same line.

**Scope:** same-line only — the check and the URL-ish receiver name must appear
together; a substring check on a value already extracted via `new URL(x).hostname` is
correctly excluded (see the FP-bait test), but a check split across two statements
(`const h = url; if (h.includes(...))`) is not tracked.

The check call and the parse evidence count only when they are live code, tested on the shared
anchor mask (`js_code_matches`, #1055): a `new URL(` spelled out in a log string no longer clears a
real finding, and a check spelled out in a docs string no longer fires. Every check call on the line
is tried, so a quoted or domain-less call earlier on the line cannot hide a real one after it.

Suppress an audited case (e.g. a value already known to be a parsed hostname despite the
generic variable name) with `// security: allow-incomplete-url-substring-sanitization`
on the line.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    is_nonproduct_path,
    iter_files,
    js_code_matches,
    read,
    rel,
    split_call_args,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA_TEXT = "security: allow-incomplete-url-substring-sanitization"

# A URL-ish receiver: `.includes(`/`.indexOf(`/`.startsWith(` called on a variable whose
# name suggests a raw, unparsed URL/link value.
_URL_ISH_RECEIVER = re.compile(
    r"\b(\w*(?:url|uri|href|target|redirect|link)\w*)\s*\.\s*(?:includes|indexOf|startsWith)\s*\(",
    re.IGNORECASE,
)
# A domain-shaped string literal argument: contains a dot, no slash (a bare domain, not
# a full path/URL — a full-URL argument would itself need the same treatment, but the
# dominant real-world case is a bare trusted-domain string).
_DOMAIN_LITERAL_ARG = re.compile(r"""['"][\w.-]+\.[a-z]{2,}['"]""", re.IGNORECASE)
# Evidence the value was already parsed into a hostname before this check — excludes it.
_ALREADY_PARSED = re.compile(r"\bnew\s+URL\s*\(|\.hostname\b")


# The anchors tested on the anchor mask (#1055): the check call's `(`, and the parse evidence's first
# character (`new`, or `.hostname`'s dot). Neither is string content on purpose.
def _call_paren(m: re.Match[str]) -> int:
    return m.end() - 1


def _start(m: re.Match[str]) -> int:
    return m.start()


_STANDARDS = ["CWE-020"]


class IncompleteUrlSubstringSanitizationGuard(Guard):
    id = "incomplete-url-substring-sanitization"
    title = "Raw URL substring checked against a trusted domain — bypassable"
    area = "Network requests"

    # express_url_substring.js: raw url.includes("trusted.com") check ->
    # fires incomplete-url-substring-sanitization/raw-substring-check.
    canary_plant = CanaryPlant(
        files={
            "express_url_substring.js": (
                "function isTrustedTarget(redirectUrl) {\n"
                "  return redirectUrl.includes('trusted.com');\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "incomplete-url-substring-sanitization/raw-substring-check"
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return (
            "javascript" in profile.features
            or "express" in profile.features
            or "typescript" in profile.features
        )

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            raw = read(f)
            code = strip_js_comments(raw)
            mask = strip_js_comments(raw, strip_strings=True, keep_substitutions=True)
            out.extend(self._scan_file(root, f, code, mask, raw))
        return out

    def _scan_file(self, root: Path, f: Path, code: str, mask: str, raw: str) -> list[Finding]:
        out: list[Finding] = []
        lines = code.splitlines()
        mask_lines = mask.splitlines()
        view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
        for i, (line, mask_line) in enumerate(zip(lines, mask_lines, strict=True)):
            # Every live check call on the line is tried (#1055): `.search` took only the first, so a
            # quoted or domain-less call earlier on the line hid a real raw check after it. At most
            # one finding per line, as before.
            for m in js_code_matches(_URL_ISH_RECEIVER, line, mask_line, anchor=_call_paren):
                # Scope the "already parsed" exclusion to THIS call: only evidence that appears
                # before the call (i.e. part of building this receiver, e.g. `const h = new
                # URL(x).hostname; h.startsWith(...)`) counts. An unrelated `new URL(`/`.hostname`
                # belonging to a DIFFERENT call later on the same line must not silently suppress a
                # real finding on this one (FN).
                # The evidence must be live code too (#1055): a `log('TODO: use new URL( here')` is not one.
                before, before_mask = line[: m.start()], mask_line[: m.start()]
                if any(js_code_matches(_ALREADY_PARSED, before, before_mask, anchor=_start)):
                    continue
                # Bound the argument scan to the call's OWN arguments (shared balanced-paren
                # splitter) so an unrelated string literal elsewhere on the same line — e.g. inside
                # a sibling call — can't be swept in as if it were this call's argument (a fixed
                # FP). Falls back to end-of-line only when the call's parens are unbalanced on this
                # line (e.g. a multi-line call); this guard is documented as single-line-scoped.
                arglist = split_call_args(line, m.end() - 1)
                args = ",".join(arglist) if arglist is not None else line[m.end() - 1 :]
                if not _DOMAIN_LITERAL_ARG.search(args):
                    continue
                line_text = view_lines[i] if i < len(view_lines) else ""
                if _PRAGMA_TEXT in line_text:
                    break
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{i + 1}",
                        message=(
                            f"`{m.group(1)}` is checked against a trusted-domain string using "
                            "a raw substring/prefix test, not a parsed hostname comparison. "
                            "An attacker controls every other part of the URL (path, "
                            "subdomain, userinfo), so `evil.com/trusted.com`, "
                            "`trusted.com.evil.com`, or `trusted.com@evil.com` can all "
                            "satisfy this check while resolving to an attacker-controlled "
                            "host — a classic SSRF/open-redirect bypass."
                        ),
                        remediation=(
                            "Parse the URL and compare the actual hostname: "
                            '`new URL(url).hostname === "trusted.com"` (or `.endsWith` on a '
                            "properly dot-anchored suffix for subdomains). Suppress a "
                            "reviewed case with "
                            "`// security: allow-incomplete-url-substring-sanitization`."
                        ),
                        rule="incomplete-url-substring-sanitization/raw-substring-check",
                        standards=list(_STANDARDS),
                    )
                )
                break
        return out
