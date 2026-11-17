"""Guard: a network fetch feeds directly into an MCP stdio server spawn in the same
function (checklist §4, new item — the batch).

    config = requests.get("https://marketplace.example/manifest").json()
    StdioServerParameters(command=config["cmd"], args=config["args"])

Cloudflare's MCP-defender reframe (2026-04-25) called this out as the highest-risk
single-line bug shape in the wild: an MCP client fetches a server manifest from a
marketplace/registry over the network, then feeds the fetched content DIRECTLY into a stdio
server spawn — `command`/`args` sourced from whatever the marketplace returned. A marketplace
compromise (a hijacked registry, a DNS/TLS MITM, a poisoned CDN cache) becomes client-side
remote code execution on every consumer at the next refresh, with no further exploitation step
required — the fetch response IS the exec target.

Fires HIGH when, in the SAME function, a network fetch call is followed (later in the same
function's call sequence) by a stdio-spawn call:

  * Python — a `requests`/`httpx`/`urllib` fetch call (`.get(`/`.post(`/`.request(`/
    `urlopen(`) followed by `StdioServerParameters(...)`/`StdioClientTransport(...)`;
  * TS/JS — `await fetch(...)` followed, within a bounded lookahead window, by
    `new StdioClientTransport(...)`/`new StdioServerTransport(...)`.

Ported from `agent-audit-kit`'s real `mcp_marketplace_fetch.py` (fetched and read in full; both
language arms are verbatim, including the Python variant's per-function call-sequence walk and
the TS variant's bounded-window lookahead).

The real source's escape hatch is a bespoke `.aak-mcp-marketplace-trust.yml` file listing
trusted manifest URLs with a `justification:` field. agentsec has no equivalent convention
anywhere in this codebase (see `mcp-sampling-no-consent`'s own docstring for the same
adaptation) — this guard uses the shared inline pragma instead:

    config = requests.get(MARKETPLACE_URL).json()  # security: allow-mcp-marketplace-fetch-stdio-spawn
    StdioServerParameters(command=config["cmd"], args=config["args"])
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    _SL_STRING,
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    js_code_matches,
    pragma_present,
    read,
    rel,
    strip_js_comments,
    strip_python_line_comment,
    strip_python_strings,
)

# 2026-09-23 fix (Dean's review, agentic pre-review H-8): a `#`-anchored regex
# never matches in the JS/TS files this guard also scans (`#` is not that language's line-
# comment marker), so `// security: allow-...` silently never suppressed anything there. A
# plain substring, matching every other JS/TS guard's own pragma convention, works regardless
# of comment style/language.
_PRAGMA = "security: allow-mcp-marketplace-fetch-stdio-spawn"

_STANDARDS = ["CWE-829", "OWASP:A08", "OWASP-ASI:ASI04"]

_PY_SUFFIXES = (".py",)
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")

_PY_FETCH_NAMES = frozenset({"get", "post", "request", "urlopen"})
_PY_STDIO_TARGETS = frozenset({"StdioServerParameters", "StdioClientTransport"})

_TS_FETCH_RE = re.compile(r"await\s+fetch\s*\(")
_TS_STDIO_NEW_RE = re.compile(r"new\s+Stdio(?:ClientTransport|ServerTransport)")
_TS_LOOKAHEAD_WINDOW = 2048

# A mitigation marker matching the finding's OWN three suggested fixes: hash/signature
# verification, an explicit user-confirmation gate, or a diff against a previously-approved/
# known-good manifest. 2026-09-23 fix (Dean's review, agentic pre-review M-4):
# this guard recognized NO mitigation at all -- applying the fix the finding itself recommends
# (a hash-verified manifest) did not clear it, the same "the remediation doesn't work" failure
# class as H-3's sandboxed-eval fix elsewhere in this batch. Deliberately does NOT try to
# verify the mitigation is applied CORRECTLY (e.g. that the hash check actually gates the
# spawn) -- same disclosed-scope shape as every other marker-presence check in this codebase.
#
# 2026-09-24 fix (Dean's review, round 2 -- regression in the M-4 fix above, 30e594a2):
# checked against RAW source, so a bare "TODO: verify signature..." comment with no real
# verification code satisfied it. Both call sites now strip comments first (Python: per-line
# strip_python_line_comment; TS/JS: strip_js_comments, the M-3 model) before this regex runs.
#
# 2026-09-24 fix (PR #923 round-3 re-review, H3/M2): stripping comments was not enough, since a
# docstring (`"""Callers must verify signature..."""`) or a log string (`log.warn('add signature
# verification')`) still satisfied it. The marker is now matched against CODE, with every string
# literal blanked (`_mitigated` below). Blanking strings alone was measured unsafe on TS: real
# verification such as `createHash('sha256')` or `verifySignature(cfg, headers.get('x-signature'))`
# was recognized only through a token inside a string. So the regex gained code-level TS markers
# (`createHash`/`createHmac`/`createVerify`/`timingSafeEqual`, `.verify(`, camelCase
# `verify*Signature`), and a string literal that is a single token such as `'x-signature'` or
# `'RSA-SHA256'` still counts as evidence. Only prose strings (with whitespace) are ignored, the
# same identifier-token rule `mcp-toolgate-asymmetry` applies to its gate strings (H-7b). A
# single-token string that merely CONTAINS a marker word, such as an unrelated form-field name
# `'email-signature'` or a button id `'user-approve'`, still counts: a disclosed residual that
# was equally silent at e6f95e89 (measured in the round-4 review), not something this closes.
_MITIGATION_RE = re.compile(
    r"hashlib|sha256|sha512|\bhmac\b|verify_hash|checksum|\bsignature\b|verify\w*signature"
    r"|createHash|createHmac|createVerify|timingSafeEqual|\.verify\s*\("
    r"|\bgpg\b|\bpgp\b|\bconfirm\s*\(|\bapprove\b|\bprompt\s*\("
    r"|known_good|previously_approved|trusted_manifest",
    re.IGNORECASE,
)
# A quoted literal that is ONE token (no whitespace): a hash name, a header name, an algorithm
# id. Prose is never a single token, so a log message or TODO cannot pass as verification.
_QUOTED_TOKEN_RE = re.compile(r"""(['"`])([\w.:/+-]{1,80})\1""")


def _mitigated(code: str, with_strings: str) -> bool:
    """True if a mitigation marker appears in `code` (comments AND string literals blanked), or
    inside a single-token string literal of `with_strings` (the same span, comments blanked but
    strings kept). A quote pair mis-matched across code can only yield text that `code` already
    carries, so the literal scan never admits evidence the code view would not."""
    if _MITIGATION_RE.search(code):
        return True
    return any(_MITIGATION_RE.search(m.group(2)) for m in _QUOTED_TOKEN_RE.finditer(with_strings))


def _blank_single_line_strings(line: str) -> str:
    return _SL_STRING.sub(lambda m: " " * len(m.group()), line)


def _attr_chain(node: ast.AST) -> str:
    parts: list[str] = []
    cur: ast.AST | None = node
    while True:
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Name):
            parts.append(cur.id)
            break
        elif isinstance(cur, ast.Call):
            cur = cur.func
        else:
            break
    return ".".join(reversed(parts))


def _is_fetch_call(call: ast.Call) -> bool:
    chain = _attr_chain(call.func)
    if not chain:
        return False
    parts = chain.split(".")
    last = parts[-1]
    if last not in _PY_FETCH_NAMES:
        return False
    head = parts[0] if len(parts) > 1 else ""
    return head in {"requests", "httpx", "urllib"} or chain == "urlopen"


def _is_stdio_call(call: ast.Call) -> bool:
    chain = _attr_chain(call.func)
    return bool(chain) and chain.split(".")[-1] in _PY_STDIO_TARGETS


class McpMarketplaceFetchStdioSpawnGuard(Guard):
    id = "mcp-marketplace-fetch-stdio-spawn"
    title = "Network fetch feeds directly into an MCP stdio server spawn"
    area = "AI agent"

    # mcp_marketplace_client.py: requests.get(...).json() feeds command/args straight
    # into StdioServerParameters(...) in the same function -> fires
    # mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn.
    canary_plant = CanaryPlant(
        files={
            "mcp_marketplace_client.py": (
                "import requests\n"
                "from mcp import StdioServerParameters\n"
                "\n"
                "\n"
                "def load_server(manifest_url: str) -> StdioServerParameters:\n"
                "    config = requests.get(manifest_url).json()\n"
                "    return StdioServerParameters(command=config['cmd'], args=config['args'])\n"
            ),
        },
        expects=frozenset({
            "mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _PY_SUFFIXES + _TS_SUFFIXES):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            out.extend(self._scan(root, f, r))
        return out

    def _scan(self, root: Path, f: Path, r: str) -> list[Finding]:
        text = read(f)
        if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return []
        if f.suffix in _PY_SUFFIXES:
            return self._scan_python(text, f, r)
        return self._scan_ts(text, r)

    def _scan_python(self, text: str, f: Path, r: str) -> list[Finding]:
        tree = safe_ast_parse(text, filename=f)
        if tree is None:
            return []

        # Docstrings blanked file-wide (line-preserving), then `#` comments per line.
        no_comments = [
            strip_python_line_comment(ln)
            for ln in strip_python_strings(text, filename=f).splitlines()
        ]
        findings: list[Finding] = []
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            fn_lines = no_comments[fn.lineno - 1 : fn.end_lineno]
            fn_with_strings = "\n".join(fn_lines)
            fn_code = "\n".join(_blank_single_line_strings(ln) for ln in fn_lines)
            if _mitigated(fn_code, fn_with_strings):
                continue
            calls = sorted(
                (n for n in ast.walk(fn) if isinstance(n, ast.Call)),
                key=lambda c: (c.lineno, c.col_offset),
            )
            fetch_seen = False
            fetch_line = 0
            for call in calls:
                if not fetch_seen and _is_fetch_call(call):
                    fetch_seen = True
                    fetch_line = call.lineno
                    continue
                if fetch_seen and _is_stdio_call(call):
                    findings.append(self._finding(r, fetch_line, call.lineno))
                    return findings
        return findings

    def _scan_ts(self, text: str, r: str) -> list[Finding]:
        # Both views are layout-preserving, so a window's offsets index both alike. `code` is the
        # anchor mask (#749): string and template text blanked, `${...}` substitution code kept.
        # Plain `strip_strings=True`, used here before #1055, blanked a real verifier nested in a
        # substitution (`` `${createHash('sha256').update(body).digest('hex')}` ``) and lost the
        # credit.
        no_comments = strip_js_comments(text)
        code = strip_js_comments(text, strip_strings=True, keep_substitutions=True)
        # The fetch and the spawn are matched on the comment-blanked view, never the raw text, so a
        # commented-out pair is not a finding, and each must be live code: a `fetch(` or
        # `new StdioClientTransport` spelled out in a docs or log string is not a call (#1055). The
        # fetch anchor is its `(`, the spawn's the `n` of `new`. Every fetch is tried, so a quoted
        # one cannot hide the real one after it.
        for m in js_code_matches(_TS_FETCH_RE, no_comments, code, anchor=lambda m: m.end() - 1):
            lo, hi = m.end(), m.end() + _TS_LOOKAHEAD_WINDOW
            spawns = js_code_matches(_TS_STDIO_NEW_RE, no_comments[lo:hi], code[lo:hi], anchor=lambda m: m.start())
            if not any(spawns):
                continue
            if _mitigated(code[lo:hi], no_comments[lo:hi]):
                continue
            fetch_line = text[: m.start()].count("\n") + 1
            return [self._finding(r, fetch_line, None)]
        return []

    def _finding(self, r: str, fetch_line: int, spawn_line: int | None) -> Finding:
        location = f"{r}:{fetch_line}"
        spawn_note = f" (spawn at line {spawn_line})" if spawn_line else ""
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=location,
            message=(
                f"A network fetch at line {fetch_line} feeds directly into an MCP stdio "
                f"server spawn in the same function{spawn_note}. A marketplace/registry "
                "compromise (a hijacked registry, a DNS/TLS MITM, a poisoned CDN cache) "
                "becomes client-side remote code execution on every consumer at the next "
                "refresh — the fetch response IS the exec target, no further "
                "exploitation step required."
            ),
            remediation=(
                "Never spawn a stdio server directly from a freshly-fetched manifest. "
                "Pin the manifest to a signed/hash-verified release, require an explicit "
                "user confirmation before spawning a newly-discovered server, or cache "
                "and diff the manifest against a previously-approved version before "
                "acting on it."
            ),
            rule="mcp-marketplace-fetch-stdio-spawn/fetch-then-spawn",
            standards=list(_STANDARDS),
        )
